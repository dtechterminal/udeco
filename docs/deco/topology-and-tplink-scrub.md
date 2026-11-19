# Network topology and TP-Link state removal (measured 2026-11-18)

## Topology (LLDP from the gateway, captured on each Deco's uplink)

```
UCG "Example-Network" 192.168.0.1 (UniFi gateway, ipq5322, LLDP every 30 s, TTL 120)
 ├─ UCG port eth2 ── 192.168.0.241 (Deco eth0, 1 Gbps FDX)
 └─ UCG port eth3 ── unmanaged switch ─┬─ 192.168.0.205 (Deco eth1, 1 Gbps)
                                       └─ 192.168.0.232 (Deco eth1, 1 Gbps)
```

- A star: each Deco is a leaf on the wired LAN. No Deco sits behind another.
- On every unit the second Ethernet port has no link. .232's eth0 has past traffic, so something was plugged into
  it at some point.
- `br-lan` bridges eth0, eth1 and the client vifs. STP is off on every bridge.
- The wireless backhaul (wl01/wl11, dwds=1, hidden) is up on all three with **zero peers**: it carries nothing.
- Each unit runs TP-Link sysmode AP. The gateway MAC is learned on the wired uplink port.
- Tagged VLAN 2 frames reach both .241 and .205 (97 in 30 s), so VLAN SSIDs work through the unmanaged switch as it is.

## What "shows up natively in UniFi" needs

The real U6 Pro inform carries these, and the agent must report the same:
- `lldp_table`: one row per LLDP neighbour heard on the uplink, of the form
  `{chassis_id, chassis_id_subtype, port_id, mgmt_ips[], local_port_idx: 1, local_port_name: "eth0", is_wired: true}`.
  - Here: chassis `1c:6a:1b:c5:04:c1` (subtype local), port_id = the UCG port MAC (`…:c3` for eth2, `…:c4` for
    eth3), mgmt 192.168.0.1.
  - The agent needs a small LLDP receiver: an AF_PACKET socket for ethertype 0x88cc on the uplink.
- LLDP **transmit** from the AP, as a real U6-Lite does, so the UCG lists the AP as the neighbour on eth2/eth3.
  The frames carry: chassis = AP MAC, port = "eth0", system name = hostname, a description, capabilities
  WLAN AP + Bridge, and the management IP.
- `uplink: "eth0"`, `gateway_mac`, `gateway_ip`, `connect_request_ip`/`port`.
- `if_table` with exactly one wired port, as on a U6-Lite: the Deco's real uplink (eth0 or eth1) reported as
  `eth0`, with real speed, duplex and counters.
- Loop guard for the Deco's second port. If the gateway's LLDP chassis or the gateway MAC appears on **both**
  Ethernet ports, take the non-uplink port out of `br-lan` and log it loudly. This is cheaper than STP and adds no
  forwarding delay at link-up.
- Migration order: TP-Link satellites SSH to the master on :22, and a satellite that loses the master rebuilds
  its Wi-Fi. So take over satellites (.205, then .232) first and the master (.241) last, or all three together.

## TP-Link per-device rules must stop at takeover

How "bind device to a Deco" and "bind device to 2.4/5 GHz" are enforced:
the Deco app → `/etc/config/client_mgmt` (`link_pri_band` per client), `/etc/config/access_client` →
`nrd` (`/etc/config/nrd_blacklist`, `/tmp/nrd_link_pri.conf`, `/tmp/nrd.conf`) → **driver deny lists**:
`wl -i wl02/wl12 macmode 1` plus a MAC list.

Measured state (read-only):

| unit | wl02 (2.4 GHz SSID) | wl12 (5 GHz SSID) |
|---|---|---|
| .241 | macmode 1, 8 MACs | macmode 1, 7 MACs |
| .205 | macmode 1, 11 MACs | macmode 1, 8 MACs |

- The lists are in the driver's runtime state, so they **outlive nrd and client_mgmt being stopped**.
- No MAC-based iptables or ebtables rules exist. TP-Link's iptables firewall zones only affect the Deco's own
  traffic, since `br_netfilter` is absent.
- TP-Link runs htb on `br-lan` (root rate 317440 kbit). It only shapes the Deco's own outbound traffic, but it is
  TP-Link state and goes at takeover.

Requirements for the agent:
1. decosys stops `nrd` (and its restart loops), `client_mgmt`, `awnd` and `repacd` before bcmwifi applies.
   This is already in place.
2. At takeover TP-Link's driver MAC filters go away with its vifs: stopping TP-Link's hostapd deletes the `bss=`
   vifs (wlX2..wlX6), and the agent's hostapd creates fresh ones, which get only the controller's lists. bcmwifi
   flushes `macmode`/`mac` on what survives (the primaries and the `interface=` vif wlX1) and reports the deleted
   vifs' foreign entries.
3. bcmwifi's change detection for macmode/maclist compares against the **live driver**
   (`wl -i <vif> macmode`, `wl -i <vif> mac`), not only its saved `drv-wlN.json`. A foreign entry is removed and
   logged on the next tick.
4. Remove TP-Link's `br-lan` htb qdisc at takeover (save it for Restore).
5. Add a takeover self-check, run every few minutes, that reports any foreign state: a deny list we did not set,
   a TP-Link daemon running again, a TP-Link qdisc, or a procd trigger re-registered. Re-assert, and count it in
   the agent's log.
6. TP-Link config files stay on disk untouched (for rollback). bcmwifi only reads them: the `bssid=` lines (to
   recreate an absent vif with its MAC) and the `bss=`/`ctrl_interface=` lines (to know which vifs a stop deletes
   and to wait for a restarted TP-Link hostapd).
