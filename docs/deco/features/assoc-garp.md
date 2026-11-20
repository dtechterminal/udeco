# Gratuitous ARP on association (2026-11-20)

## What a U6 does

- UniFi APs announce a client that (re)associates to the wired network so switches and the
  gateway move it to the new AP at once (the exact frame a U6 sends was not captured).

## What the agent does (takeover, Deco; `assoc_garp`, default on, needs `sta_snoop`)

- `cmd/udeco-ap/garp.go`: on AP-STA-CONNECTED (after authorization only, never on association)
  for a station whose IPv4 address is known (its DHCP ACK or its own frames seen by the
  connection-event taps within the last hour, else the reading's ARP table), one gratuitous ARP
  (broadcast ARP request from the station's MAC, its address as sender and target, padded to
  60 bytes; `internal/stasnoop` GARP) is sent on each wired member of the station's bridge
  (sysfs `brport/bridge` and `brif`; never a wl port): eth1 for br-lan, eth1.20 for a VLAN bridge.
- At most once per station per 10 s; a send failure is logged once.
- `assoc_garp` false turns it off. Takeover only; refused on jio-mtk.

## Unverified on hardware

- That the Deco's switch/driver passes a frame with a foreign source MAC sent by AF_PACKET on
  eth1 (and on the VLAN device) unchanged.
- The effect on roam gaps with the site's switches.
