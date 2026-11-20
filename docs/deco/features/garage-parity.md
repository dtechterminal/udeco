# Garage (platform jio-mtk): U6 parity

What a UniFi U6 does that the JioFiber JCOW414 ("the Garage", MT7603 on
2.4 GHz, MT7663 on 5 GHz) now does too, how, and what has not been seen on
the unit yet. Nothing here was run on hardware: every item below is built
and tested against the repository's fake driver only.

Rules the items share:

- **U6 defaults are the defaults.** What the controller toggles follows
  the controller's key.
- **One restart per radio.** Everything that is a profile key
  (`RT2860AP.dat`) is written in the same profile, so the first deploy of
  this build restarts each radio once (adopt compares the profile bytes)
  and later changes restart a radio only when the written profile differs
  (`restartKey`). Restarts go through the RestartGate.
- **Live `iwpriv` outside restarts.** What the drivers take only live
  (`iwpriv <if> set ...`) is queued and sent by the first Apply or Tick
  after a restart's settle time (`internal/mtkwifi/live.go`).
- **Hand-back restores the vendor.** The vendor profile of the boot comes
  back, and everything set live is undone first.
- **Opt-out keys only where a behaviour could cut off management.**

New agent config keys (all `platform: jio-mtk` only; an error elsewhere):
`uplink_loss`, `uplink_loss_ssid`, `bss_pinning`, `proxy_arp`, `proxy_arp_driver`, `dfs`.

## 1. Minimum RSSI

- **U6:** stamgr refuses association requests below the controller's
  minimum RSSI and disconnects a client that stays below it
  (`minrssi`, assoc status 16 in the leave).
- **Garage:** each served BSS gets `iwpriv <if> set AssocReqRssiThres=<dBm>`
  (0 = off), sent after every restart's settle time
  (`internal/mtkwifi/live.go`). `KickWeak` (`internal/mtkwifi/minrssi.go`)
  disconnects a station after 3 readings in a row at least 5 s apart below
  the threshold (`DisConnectSta`), backing off 30 s doubling to 10 min per
  station, never during a restart or its settle time. The kicked station's
  leave carries `assoc_status` 16 (`cmd/udeco-ap/staevents.go`).
- **Unverified:** that the MT7663's association path uses the threshold
  (only the setter was found); the RSSI scale the drivers compare.

## 2. WPS off

- **U6:** `wps_state=disabled` on every VAP.
- **Garage:** `WscConfMode=0` for every slot (profile, batched).
- **Unverified:** that beacons lose the WPS IE (the parser reads the key).

## 3. Group rekey and PMK cache

- **U6:** `wpa_group_rekey` from the WLAN's `group_rekey` (0 = never).
- **Garage:** per served slot `RekeyMethod=TIME` + `RekeyInterval=<s>`, or
  `DISABLE`/0 (always for an open WLAN); `PMKCachePeriod=720` (minutes, the
  U6's 12 h) on 5 GHz. Unserved slots keep the vendor values.
- **Unverified:** on-air GTK rotation interval.

## 4. 2.4 GHz automatic channel: 1/6/11 only

- **U6:** `block_acs_channel` for 2-5 and 7-10.
- **Garage:** with channel auto, `AutoChannelSkipList=2;3;4;5;7;8;9;10`.
  A fixed channel keeps the vendor value. The controller has no channel
  blacklist key in what the agent receives (`internal/translate`), so
  there is none to carry.
- **Unverified:** that the MT7603's ACS honours the list.

## 5. Band steering flag off

- **U6:** no steering at this site (ui_bandsteer off; BANDSTEER not
  claimed).
- **Garage:** `BandSteering=0` for every slot.
- **Unverified:** that the vendor flag was inert anyway.

## 6. Multicast enhancement per SSID on 5 GHz

- **U6:** `mcastenhance` per VAP from the WLAN.
- **Garage:** the MT7663's per-BSS `IgmpSnEnable` list from each WLAN's
  multicast-to-unicast. 2.4 GHz has one value per radio and stays on when
  any SSID wants it.
- **Unverified:** that the MT7663 honours the per-BSS list.

## 7. Transmit power

- **U6:** `txpower_mode` high/medium/low/custom.
- **Garage:** the controller's dBm maps to the drivers' percentage steps
  (100/75/50/25/12/6 % = 0/-1/-3/-6/-9/-12 dB from the radio's maximum);
  a power-only change goes live (`TxPower` on 2.4 GHz, `PowerDropCtrl` on
  5 GHz) without a restart; the reported power is the step's dBm, with the
  controller's mode (`mtk-txmode.json` in the run dir).
- **Unverified:** the step table on air (one U6 data point; the step
  table was not decompiled for this build).

## 8. Implicit beamforming and 20/40 coexistence

- **U6:** `implicitbf 0`, `disablecoext 1`.
- **Garage:** `ITxBfEn=0` (5 GHz), `HT_BSSCoexistence=0` (2.4 GHz), in the
  same profile batch as items 2-6 and 10.
- **Unverified:** client effect (inferred to be none at 20 MHz).

## 9. Uplink loss

- **U6:** with the uplink down, the user and guest VAPs go down
  (syswrapper `configure_vap up down down`).
- **Garage:** with no carrier on the uplink port (port 4) for 15 s, every
  SSID goes down except one management SSID (`uplink_loss_ssid`, else the
  first LAN SSID without a VLAN that is not a guest), one restart per
  radio; with carrier back for 30 s every SSID comes back. A new isolation
  waits 5 min after the last restore. With no management SSID served,
  nothing is taken down (the unit must stay reachable through the GL KVM
  side door). `uplink_loss: false` turns it off
  (`internal/mtkwifi/uplinkloss.go`, `cmd/udeco-ap/garage.go`). Events
  `UPLINK LOST`/`UPLINK BACK` go to `events.log`.
- A rollback while isolated (a failed apply, or the health check after a
  failed isolation) brings last-good back isolated, which is what Verify
  checks. It used to bring back every SSID while Verify checked the
  isolated plan, so each health check failed and rolled back again: two
  radio restarts per check for the whole outage.
- **Unverified:** the carrier reading of `jioports` during a real WAN
  cable pull; client behaviour.

## 10. Real-time station events

- **U6:** wevent/stahtd: joins and leaves at once.
- **Garage:** `WirelessEvent=1` on 5 GHz (batched); a passive rtnetlink
  listener (IWEVCUSTOM: Delete, the MBO and WAPP leaves), the Econet event
  socket (failed joins logged with their reason) and the kernel log's
  2.4 GHz `Del Sta` lines (`internal/mtkwifi/drvevents.go`). A leave is held
  1 s, a burst (more than 3 on one BSS within 1 s: a restart) is dropped,
  events during a restart or its settle time are dropped, and the same
  station's leave from two sources within 5 s is reported once. A released
  leave is the station's `sta_leave` in the next reading and wakes the
  inform loop (at most every 2 s); joins stay with the reading diff.
- **Unverified:** the MT7663's event payloads on the unit (from the
  decompile), whether the Insert/Delete events need `WirelessEvent=1`.

## 11. BSS slot pinning (`bss_pinning`, off by default)

- **U6:** one VAP per WLAN: a WLAN coming or going leaves the others alone.
- **Garage today:** SSIDs take the profile slots in the controller's order,
  so a WLAN that goes moves the later ones to other netdevs and BSSIDs.
- **With `bss_pinning`:** each WLAN keeps its slot (WLAN id -> slot per
  radio, `mtk-slots.json` in the run dir, saved after a successful apply);
  a WLAN that comes back gets its slot while it is free. Slot 0 (ra0/rai0,
  whose netdev reads the profile) always carries a WLAN, one without a
  schedule when there is one, and comes up first
  (`internal/mtkwifi/slots.go`). A slot change is still a radio restart.
- **Unverified / next step:** taking one BSS down and up without a radio
  restart. The decompile says `ifconfig <ra1-3|rai1-3> down/up` is per BSS
  while slot 0 stays up (the drivers count the open BSSes). On-unit test,
  in a quiet window more than 60 s after a restart, with a test SSID in
  slot 2: `ifconfig ra2 down`, check that the other BSSes keep their
  clients and dmesg shows no `2.4G MAIN INF DOWN`; `ifconfig ra2 up`, check
  it beacons with its BSSID. The same on rai2 (`5G virtual_if_down_handler`
  only). Until then pinning stays off.

## 12. Guest WLANs

- **U6:** guest VAPs behind ebtables GUESTIN/GUESTOUT chains, with the
  portal's authorisations.
- **Garage:** guest SSIDs are served with the Deco's own fail-closed rules
  (`bcmwifi.GuestEbtables`): chains `UDECO-GIN`/`UDECO-GOUT` (and
  `UDECO-GAUTH` with the portal) with policy DROP are built, and the guest
  vif's jumps (FORWARD in/out, INPUT in) inserted, before the guest SSID's
  netdev comes up; jumps of vifs no longer carrying a guest SSID go only
  after the radios changed. A guest SSID without a usable policy (gateway
  MAC and IP) is not served. Authorise/unauthorise add and remove the
  guest's RETURN rule (kept in the run dir for rebuilds); unauthorising
  disconnects the guest. Tick rebuilds chains something else removed; the
  hand-back removes them (`internal/mtkwifi/guest.go`).
- Rollback: last-good is saved with the Desired it came from
  (`last-good-desired.json` in the state dir), and a rollback restores
  that Desired's guest policy and ACLs before last-good comes up. It used
  to keep the failed apply's Desired, so a failed apply without a usable
  guest policy brought last-good's guest SSID back with its chains
  removed (open) until the next successful apply. A last-good from an older
  build (no saved Desired) with a guest SSID is not brought back: the
  vendor's Wi-Fi is restored instead (fail closed).
- **Unverified:** the ebtables binary's behaviour on the unit beyond the
  match list checked on 2026-11-20 (filter table; ip, ip6, arp, mark).

## 13. Proxy ARP (`proxy_arp`, on by default)

- **U6:** `proxyarp 1` on a WLAN with proxy ARP: the AP answers ARP for
  its clients, so broadcast ARP does not wake them.
- **Garage, 5 GHz (MT7663), by default:** served like 2.4 GHz below, by the
  agent (garage-final proxyarp: "do not enable the MT7663 driver flag by
  default"). The driver flag was on by default with `hs_flag=2` (bit 1
  only): the driver then learnt no station from its own ARP (bit 0, the
  RX snoop, was off), only from a DHCP ACK sent while the flag was on, and
  it drops every broadcast request toward the BSS whether or not the
  target is known. Clients that joined during the 20 s settle after a
  restart were unreachable from the LAN until their next DHCP renew.
- **Garage, 5 GHz with `proxy_arp_driver: true` (off by default):** the
  driver's proxy ARP (`iwpriv rai<N> set hs_flag=3`: bit 0 learns from the
  stations' ARP, bit 1 drops the requests) hands each request for a known
  station to a daemon as IWEVCUSTOM 0x93b; the agent's responder sends the
  reply on the BSS's bridge. The flag is set only while the rtnetlink
  listener and the responder's socket are healthy, outside restart settle
  times; it is cleared at once when either dies, at startup, after a
  restart until re-checked, and at the hand-back.
- **Garage, 2.4 GHz (MT7603):** no driver support. An AF_PACKET responder
  learns each associated station's address from its own ARP and its DHCP
  ACK (a BPF filter passes only those), answers broadcast requests the
  bridge delivers, and an ebtables rule per learnt address (`UDECO-PARP`,
  FORWARD `-o <vif>`) keeps those requests off the air. The chain's policy
  is RETURN (`-N UDECO-PARP -P RETURN`, or `-P UDECO-PARP RETURN` on a chain
  an older build left): with the default ACCEPT policy a frame no drop rule
  matched left FORWARD at the jump (FORWARD 1) and skipped the guest
  isolation chains (UDECO-GIN/GOUT) after it. Unknown addresses
  still go out (fail open, as the Linux bridge's proxy ARP). The rules
  exist only while the responder's sockets are healthy.
- `proxy_arp: false` leaves every request going out on the air, as before
  (`internal/mtkwifi/proxyarp.go`, `proxyarp_linux.go`). IPv6 neighbour
  solicitations are not proxied.
- **Unverified:** that AF_PACKET on ra<N>/rai<N> sees the frames sent to
  the station (DHCP ACKs) on these drivers. With `proxy_arp_driver`: that
  `hs_flag=3` works without `HotSpotEnable`, and the 0x93b payload on the
  unit.

## 14. DFS (`dfs`, off by default)

- **U6:** DFS channels by the country's rules; radar is reported.
- **Garage:** with `dfs`, the controller's 52-64 (the only DFS channels of
  the MT7663's IN table; 100-144 stay refused with a plan note) are served
  and the 5 GHz radio claims `has_dfs` (`has_fccdfs` stays false: IN).
  - The driver caches its channel list, so the region goes live:
    `iwpriv rai0 set CountryRegionABand=0`, then `set Channel=<52-64>`;
    going back the channel first, then the vendor's region, and only with
    no channel in its non-occupancy period. The profile is kept in step
    (`CountryRegionABand=0` with a DFS channel). A channel move into or out
    of 52-64 is not a profile restart.
  - After a move, or a restart onto 52-64, the agent stays off the driver
    for 90 s (the 65 s CAC: no SSID reads, no live settings, so no rollback
    of a silent radio); the collector refuses 5 GHz scans while on a DFS
    channel.
  - Radar is the driver's (CSA, a random new channel, 30 min NOP). The
    agent sees the radio on another channel than the one it set, reports
    `EVT_AP_RadarDetected` (radio, channel, freq) to the controller and logs
    `RADAR` in `events.log`, keeps the channel out for 31 min (all of 52-64
    at 80 MHz), writes the driver's channel into the profile meanwhile, and
    then goes back. A move the driver refused is no radar.
  - Never touched: IEEE80211H, RDRegion, DfsEnable, DfsZeroWait and the
    driver's DFS test commands (`internal/mtkwifi/dfs.go`).
- **Unverified, before turning `dfs` on:** in a quiet window on an empty
  radio, `iwpriv rai0 set CountryRegionABand=0; iwlist rai0 channel` must
  list 52-64 (a region lock refuses it), then `iwpriv rai0 set
  CountryRegionABand=10` while still on 149. Also unverified: the CAC
  length on the unit, that a NOP survives the region change back, and
  automatic channel after leaving DFS (the radio goes to 36 until the next
  restart).

## 15. Station GARP

- **U6:** a gratuitous ARP for a client that roamed in, so the LAN's
  switches and ARP caches follow it at once.
- **Garage:** a station new on a BSS whose IPv4 address is known (the
  unit's ARP table, an address seen before, or the proxy ARP responder's)
  is announced with a GARP from its MAC out of the uplink port (a VLAN
  SSID's: the uplink's VLAN device), at most every 30 s per station; not
  for the stations of the agent's first reading, nor while the radios
  restart (`internal/mtkwifi/garp.go`, `cmd/udeco-ap/garage.go`). Joins
  come from the readings, so the GARP follows within one reading.
- **Unverified:** on-air capture of the GARP; the upstream switch's MAC
  move.
