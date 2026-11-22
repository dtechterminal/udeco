# Multicast inspect, DNS assistance, mDNS service bridge, Multicast Suppressor

Status 2026-11-19: multicast inspect is implemented (takeover only). DNS
assistance and the Multicast Suppressor are not; the reasons are below. The
mDNS service bridge was not either when this was written, and has been built
since (its section below). Sources: the Network 11.1.50 controller (decompiled device
class `XCfthFC`, the AP system.cfg generator `config/XHjguBsIf`, the mDNS-SD
config factory `config/ubntconf/jfhrAUVHPMhBVsMer`, the inform-scope service
`devmgr/l/PfwtrEhZ`, the multicast stats collector `stat/f/QdjEeOBh`) and the
real U6 Pro captures in `docs/reference/u6pro/`.

## Capability bits (from the controller)

| feature | word | bit | controller method |
|---|---|---|---|
| multicast inspect | fw3_caps | 0x80 | `supportsMulticastInspect` |
| DNS assistance | fw3_caps | 0x8 | `supportsDnsAssistance` |
| mDNS service bridge | fw2_caps | 0x10000000 | `supportsMdnsSdBridge` |
| Multicast Suppressor | wifi_caps2 | 0x400000 | `supportsMulticastSuppressor` (not fw3 0x80) |

## Multicast inspect (fw3_caps 0x80): implemented, takeover only

What the controller does when the bit is set:

- system.cfg: `wireless.N.multicast.inspect=true` on every WLAN that is not a
  service WLAN (`false` otherwise, and `false` on every WLAN without the bit).
- The inform reply (`noop`) lists `"multicast"` in `include_blocks`.
- It stores each client's `sta_table[].multicast` block as STA_MULTICAST
  time series (per protocol and per mDNS service) and keeps the latest one per
  client (services, memberships, groups, mdns_rr) for its multicast views;
  `multicast_type` is 1 when the client has memberships, |2 when it has groups.

The block, in the U6 Pro's shape (`mca-dump.json`, every client row):

```
multicast: {
  types: {arp, dhcp, dhcpv6, igmp, ipv6_nd, mdns, mld, other, ssdp, stream, ubnt:
          {rx_bytes, rx_pkts, tx_bytes, tx_pkts}},       all eleven, always
  groups: [{type, group_ip, dst_port, rx_bytes?, rx_pkts?, tx_bytes?, tx_pkts?}],
  memberships: [{group_ip, age_ms}],
  services: [{name, bytes, pkts}],
  mdns_rr: {PTR: n, SRV: n, ANY: n, A: n, AAAA: n, TXT: n}  only when the client sent mDNS
}
```

On the U6 Pro rx counters are the client's own; tx counters are the VAP's and
identical on every client of the VAP (verified: all clients of `wifi1ap1`
show arp tx 764313, mdns 224.0.0.251 tx 1373954). A group row leaves out a
direction it never saw.

How the agent does it (`internal/mcinspect`, `cmd/udeco-ap/mcinspect.go`):

- `translate.MulticastInspect` reads the devnames with `multicast.inspect` on
  (disabled WLANs left out); `Snapshot.IfnamesByDevname` maps them to the
  agent's vifs (`wlX2..`).
- One AF_PACKET socket per inspected vif, bound with ETH_P_ALL (taps run
  before the bridge, and see the frames the VAP transmits as
  PACKET_OUTGOING), with a classic BPF filter that keeps only group-addressed
  frames (I/G bit of the destination MAC). Unicast never reaches the agent.
  No promiscuous mode, no membership, nothing on the unit changes.
- Classification: ARP; IPv4 IGMP; IPv6 ICMPv6 MLD (130/131/132/143, behind a
  hop-by-hop header) and ND (133-137); UDP by destination port: 5353 mdns,
  1900 ssdp, 10001 ubnt, 67/68 dhcp, 546/547 dhcpv6; any other UDP to a
  multicast group is `stream`, a broadcast is `other`; non-IP is `other`.
- Memberships come from the client's own IGMPv1/v2/v3 and MLDv1/v2 reports
  (joins, leaves, TO_IN{}); `age_ms` runs from the first report and a group
  not reported for 260 s (the U6 Pro's snooping ageing, `mcsd.conf`) goes.
- mDNS from the client is parsed (compression, loop guard, at most 64
  records): every question and record of a known type counts in `mdns_rr`;
  names whose first label starts with `_` are services (pkts, bytes).
- Bounds: 256 clients per VAP; 64 groups per client and per VAP, 64 services,
  64 memberships per client; 32 groups and 32 services per inform row.
  Clients that leave are forgotten (counters restart, as on a real AP).
- A socket that fails to open is retried after a minute (logged once). A
  drop to observe mode or R4 memory shedding stops every reader at the next
  inform and the block is no longer sent.

Bit: fw3_caps 0x80, claimed in takeover only
(`models.FW3CapMulticastInspect`, one of `models.DecoAgentTakeoverFW3Caps`).
When this was written the agent sent no `fw3_caps` word; it does now
(`inform.Profile.FW3Caps`, a uint32 like fw2_caps), and the claim follows
takeover the way RF_SCAN does.

Untested on the unit (live test plan in the integration report): whether the
Broadcom datapath (archer/fc/WFD, WMF) hands multicast to the ETH_P_ALL taps
of the `wl` vifs in both directions. If accelerated multicast bypasses the
taps, tx counters will under-count; rx from clients (mDNS, SSDP, IGMP, ARP)
takes the slow path.

## DNS assistance (fw3_caps 0x8): not implemented

What the controller sends, per WLAN with `dns_assistance_mode` auto or manual:
`wireless.N.dns_cache.status=enabled`, `wireless.N.dns_bypass.status=enabled`,
and in manual mode `wireless.N.dns_bypass.servers=a,b`. On the U6 Pro these go
to kernel modules (`/proc/ui_dns_cache`, `/proc/ui_dns_bypass`) whose bypass
trigger (failure rate, latency, consecutive timeouts, probe and recovery
timers, `trigger_mask`) is compiled in and raises DNS_BYPASS events
(BYPASS/NORMAL/ALERT) to the controller.

Why not on the Deco: intercepting a Wi-Fi client's bridged DNS needs either
br_netfilter (absent: no `/proc/sys/net/bridge`, iptables never sees bridged
frames) or an ebtables redirect/dnat target (the Deco's ebtables 2.0.10-4 has
`ip`, `ip6`, `mark`, `mark_m`, `vlan`, `time`, `ftos`; `redirect`, `dnat`,
`snat`, `log`, `nflog`, `ulog` are "not found"). A broute DROP sends the frame
to the IP stack with the gateway's destination MAC, which drops it as
PACKET_OTHERHOST. What remains is a userspace L2 DNS proxy (drop the query in
ebtables, read it from an AF_PACKET tap, answer with a spoofed reply), with
the bypass thresholds guessed, and the agent's egress fence (UDECO-OUT) drops
DNS to non-LAN servers by design. Not claimed.

## mDNS service bridge (fw2_caps 0x10000000): implemented, takeover with apply and `mdns_bridge`

Superseded: `internal/mdnsbr` runs the controller's proxies and per-VAP
service filters from userspace (AF_PACKET taps and sends, an ebtables chain
for the filtered vifs). See docs/deco/features/mdns-bridge.md.

## Multicast Suppressor (wifi_caps2 0x400000): not implemented

The controller writes `wireless.N.multicast.suppressor=enabled` when the WLAN's
`multicast_suppressor_mode` is conservative or aggressive (both give the same
key, so the AP has a single behaviour) and the AP claims wifi_caps2 0x400000.
On the U6 Pro it is `/proc/ui_multicast/mc_suppressor/enable` in a closed
kernel module; what it suppresses is not stated anywhere in the controller or
the captures. Not claimed (the agent's wifi_caps2 word, sent for the Roaming
Assistant in takeover, never has this bit); translate keeps noting
`multicast.suppressor` when it is on.

The inspector itself (`internal/mcinspect`) is platform-independent and is
claimed on the Garage (platform jio-mtk) too.
