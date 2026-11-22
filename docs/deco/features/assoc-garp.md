# Gratuitous ARP on association (2026-11-20)

## What a U6 does

- UniFi APs announce a client that (re)associates to the wired network so switches and the
  gateway move it to the new AP at once (the exact frame a U6 sends was not captured).

## What the agent does (takeover, Deco; `assoc_garp`, default on, needs `sta_snoop`)

- `cmd/udeco-ap/garp.go`: on AP-STA-CONNECTED (after authorization only, never on association),
  as the control socket delivers it (hapdmon's `OnEvent` hook queues it to a GARP goroutine; it
  used to wait for the next reading, up to an inform interval after the roam), for a station
  whose IPv4 address is known on that BSS's bridge (its DHCP ACK or its own frames seen by the
  connection-event taps within the last hour on a BSS of the same bridge; else, on br-lan only,
  the last reading's ARP table, which is the AP's own and so br-lan's). An address learnt on
  another bridge (the station was on the guest VLAN before) is never announced, so a guest
  address never goes into the LAN or the reverse. Then one gratuitous ARP
  (broadcast ARP request from the station's MAC, its address as sender and target, padded to
  60 bytes; `internal/stasnoop` GARP) is sent on each wired member of the station's bridge
  (sysfs `brport/bridge` and `brif`; never a wl port): eth1 for br-lan, eth1.20 for a VLAN bridge.
- At most once per station per 10 s; a send failure is logged once.
- `assoc_garp` false turns it off. Takeover only. On jio-mtk it is the opt-out of the Garage's own
  station GARP (garage-parity.md section 15), which does not need `sta_snoop`.

## Unverified on hardware

- That the Deco's switch/driver passes a frame with a foreign source MAC sent by AF_PACKET on
  eth1 (and on the VLAN device) unchanged.
- The effect on roam gaps with the site's switches.
- An address stays known for an hour: a station that changed address on the same bridge without
  a DHCP ACK the tap saw (a static change) would have its old one announced once.
