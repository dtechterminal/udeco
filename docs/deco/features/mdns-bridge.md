# mDNS service bridge (fw2_caps 0x10000000)

Status: implemented 2026-11-19. Claimed (fw2_caps 0x10000000) only in takeover
with `apply` and the config key `mdns_bridge` (off by default until the live
test: the controller puts every "auto" WLAN in mDNS auto mode once the bit is
claimed, and AF_PACKET sends on the wl vifs are unverified). A start-time
cleanup removes a crashed run's chain; it runs only when the run-dir marker
`/tmp/udeco/mdns-bridge` exists, so a unit that never ran the bridge sees no
ebtables command. Code: `internal/mdnsbr`, `cmd/udeco-ap/mdnsbr.go`.

## What the controller sends

With `supportsMdnsSdBridge` (fw2_caps bit 28, 0x10000000) set, Network 10.6.109
(`com.ubnt.service.config.ubntconf.jfhrAUVHPMhBVsMer`, booleans rendered
`enabled`/`disabled`) adds an `mdns_sd` section for every WLAN whose
`mdns_proxy_mode` is not `off`:

```
mdns_sd.status=enabled
mdns_sd.ap_mode=enabled                       any applied custom entry has isolation_enabled
mdns_sd.proxy.P.status=enabled                custom mode: one per (WLAN, custom entry) naming another VLAN
mdns_sd.proxy.P.dst.1.devname=br0             the WLAN's bridge (br0 = untagged, br0.<vid>)
mdns_sd.proxy.P.src.M.devname=br0.3           the entry's networks' bridges, the WLAN's own left out
mdns_sd.filter.F.vlan=3                       1 = untagged
mdns_sd.filter.F.policy=deny                  allow | deny
mdns_sd.filter.F.dst.D.devname=ra1            the WLAN's VAP devnames
mdns_sd.filter.F.service.S.name=_airplay._tcp.local   exceptions to the policy
```

- **auto**: one filter for the WLAN's own VLAN, policy `deny`, exceptions = the
  addresses of the 25 predefined service groups (`com.ubnt.i.e.i.sITFkDkyKy`: AirPlay,
  Chromecast, printers, HomeKit, Matter, Sonos, ...). Some are written without
  `.local` (`_matterc._udp`, `_amazonecho-remote._tcp`). No proxy.
- **custom** (`mdns_proxy_custom[]`: `networkconf_ids`, `ap_scope_mode`
  all/specific/group with `ap_macs`/`ap_group_ids`, `isolation_enabled`,
  `services_mode` all/specific/none, `predefined_services`, `custom_services`):
  per entry that applies to this AP, a proxy (dst = the WLAN's bridge, src = the
  other named VLANs' bridges) and one filter per named VLAN: `all` = allow,
  `specific` = deny with the chosen services, `none` = deny. If no entry names the
  WLAN's own network, the controller adds one for it (all, or specific with the
  union of the services), so the own VLAN always gets a filter.
- VLANs that are only proxied from get `vlan.N`/`bridge.N` sections too (bridge
  with only the uplink VLAN device). bcmwifi does not build those (it builds
  bridges for SSID VLANs only); the agent reaches them with 802.1Q frames on the
  uplink instead.
- With `isolation_enabled` the controller also writes
  `iptables -t raw -A PREROUTING -i <uplink vlan dev> -p udp --dport 5353 -j DROP`:
  the U6 Pro's repeater then takes no mDNS from the wire. So `ap_mode` = only this
  AP's wireless clients take part.

On a U6 Pro the proxy is `/usr/sbin/mdns-repeater` (config `mdns.conf`) and the
filter a kernel module (`/proc/ui_multicast/mdns_filter/vaps/<vap>/vlans/<vlan>/{policy,services}`).

## What the agent does

Plan (`mdnsbr.BuildPlan`), from the `mdns_sd` section, the reading's VAP names and
`/sys/class/net/br-*/brif`:

- A filter whose VLAN is the VAP's own: the vif is **intercepted** unless the
  filter allows everything. A filter for another VLAN is a **route** (vif takes
  services from that VLAN), but only when a proxy brings that VLAN to the vif's
  bridge. The last filter for a (VAP, VLAN) wins, as with the proc files.
- Ports: every port of the bridges involved (`br-lan` = VLAN 1, `br-v<vid>`), plus,
  for a VLAN with no bridge here, the uplink as a virtual port for that VLAN's
  tagged frames (not in AP mode). Guest vifs and TP-Link's backhaul vif are never
  tapped or sent to; a filter on a guest VAP is dropped with a note.

Runtime (`mdnsbr.Service`): one AF_PACKET socket per port, with a classic BPF
filter (unfragmented UDP 5353 to 224.0.0.251 / ff02::fb, no IP options or IPv6
extension headers; untagged, or tagged with the port's VID, read from the
packet metadata). Frames are sent on ports, never into a bridge device, since a
frame sent into a bridge floods every port, guest vifs included, past the guest
chains in ebtables FORWARD. For a frame from port In (VLAN V):

1. own VLAN: each intercepted vif on V (other than In) gets it through its filter;
2. a query from a vif with routes goes to each route's VLAN: questions and known
   answers through the route's filter, QU bits cleared (the answer must come back
   as multicast), sent on every port of that VLAN (only its vifs in AP mode), an
   intercepted vif there getting it through its own filter as well;
3. a response from VLAN S goes to every vif with a route from S, through that
   route's filter (in AP mode only responses from a vif count).

So the bridge is one way (services in S are offered to the WLAN, not the other
way round), as the controller's src/dst naming says. Reflected answers go to the
WLAN's vifs only, not to the dst VLAN's wire, so several agents (or an agent and
a UniFi AP) on one wire do not multiply them.

**Service filter.** A name matches a listed type when the type is the name or a
label-aligned suffix of it (instances `TV._airplay._tcp.local`, subtypes
`_printer._sub._http._tcp`), case-insensitively, `.local` ignored. Host records
and address questions (no `_` label) pass a deny policy only for hosts that an
allowed SRV record in the same message points at, or that the host cache (SRV
records seen on that VLAN, at most their TTL and 1 h) knows to offer an allowed
service. Enumeration PTRs (`_services._dns-sd._udp`) pass only for allowed types.
A message the filter changed is rebuilt without compression; records whose RDATA
may hold compressed names the parser does not decode (NS, SOA, MX, ...) are left
out of a rebuilt message. A message with no question and no answer left is not
sent.

**Interception.** ebtables (2.0.10-4 on the X20 has `--ip-dport`/`--ip6-dport`):

```
FORWARD -o <vif> -j UDECO-MDNS                 (inserted first)
UDECO-MDNS (policy RETURN):
  -p IPv4 --ip-dst 224.0.0.251 --ip-proto udp --ip-dport 5353 -j DROP
  -p IPv6 --ip6-dst ff02::fb --ip6-proto udp --ip6-dport 5353 -j DROP
```

Only multicast mDNS towards the vif is dropped. A vif is intercepted only when
its socket and every port of its VLAN are open (else it would miss that port's
mDNS: it is then served natively, unfiltered). Each change is followed by
`fc flush --if <vif>` (best effort, R21). Stopping (drop to observe, R4 shedding,
`apply` off, empty plan, agent shutdown) removes the jumps and the chain; the
first tick of every start removes leftovers of a crashed run in either mode
(it only reads ebtables unless `UDECO-MDNS` exists).

**Loops and floods.** Only vif-originated queries go to wired ports and
wire-originated traffic only goes to vifs, so two bridges never hand a frame back
and forth. Frames from the unit's own MACs are dropped; a message (source IP +
payload) seen in the last 500 ms is not forwarded again. Token buckets: 100
frames/s (burst 200) per port, 20/s (burst 60) per source MAC (at most 1024 MACs
tracked; new MACs are refused beyond that), 400/s (burst 800) sent in total. IPv4
fragments, legacy unicast queries (source port not 5353) and frames over 1514
bytes are not bridged.

Source MAC, source IP and TTL of a bridged frame are the original sender's (as a
bridge would forward it); only the payload (and checksums) change.

## Not done / open

- `ap_mode` is read as "wireless clients only" from the controller's iptables rule;
  its UI meaning is not documented anywhere in the controller.
- An intercepted vif's own-VLAN mDNS from guest vifs on the same bridge is not
  delivered (guest frames are not tapped; the guest chains drop them anyway).
- Not tested on the unit: AF_PACKET send on a Broadcom vif and on the uplink with
  an in-band 802.1Q header, and the metadata VLAN tag in BPF on kernel 4.1.52.

## Garage (platform jio-mtk)

The same bridge with `bdg2` as the LAN bridge: its wired `eth0.<port>.1`
members and served `ra*`/`rai*` BSSes are tapped (idle slots, AP-client and WDS
netdevs are skipped), a VLAN with no local bridge is reached tagged on `eth0.4`,
and no flow cache is flushed (none on this unit). Unverified: the `--ip-dport`
matches in the Garage's ebtables and tagged sends on `eth0.4`.
