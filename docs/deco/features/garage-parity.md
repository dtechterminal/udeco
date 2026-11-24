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
`uplink_loss`, `uplink_loss_ssid`, `bss_pinning`, `proxy_arp`, `proxy_arp_driver`, `dfs`, `rate_limits`, `enterprise`, `ft`.
The login lock's keys (`login_lock`, `login_lock_failopen_s`, section 16)
apply to both platforms, as do the Deco keys this platform now takes:
`mdns_bridge` (section 19), `sta_snoop` (section 20) and `assoc_garp`
(section 15).

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
  leave carries `assoc_status` 16 (`cmd/udeco-ap/staevents.go`). It is the
  only kicker: the Deco's agent-side loop (`cmd/udeco-ap/minrssi.go`) used
  to run here too, with other timers and no settle guard, so a weak client
  was kicked twice; it is now Deco only. A controller `kick-sta` inside a
  settle time is sent after it.
- **Unverified:** that the MT7663's association path uses the threshold
  (only the setter was found); the RSSI scale the drivers compare.

## 2. WPS off

- **U6:** `wps_state=disabled` on every VAP.
- **Garage:** `WscConfMode=0` for every slot (profile, batched).
- **Unverified:** that beacons lose the WPS IE (the parser reads the key).

## 3. Group rekey and PMK cache

- **U6:** `wpa_group_rekey` from the WLAN's `group_rekey` (0 = never).
- **Garage:** per served slot `RekeyMethod=TIME` + `RekeyInterval=<s>`, or
  `DISABLE`/0 (always for an open WLAN); `PMKCachePeriod=129600` (minutes: 90 days, not the U6's 12 h) on 5 GHz.
  The MT7663 also uses it as the lifetime of its own FT key holder entries,
  and an entry that ages while its client is connected can stop the
  radio's scans until it restarts ([garage-ft](garage-ft.md#key-holder-entries-that-age-2026-11-25)).
  Unserved slots keep the vendor values.
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
- **Found (2026-11-22):** the rebuilt MT7603 module (the WPA3 build) has no
  IGMP snooping code: `IgmpSnEnable` does not occur in its strings, where
  the vendor's `mt7603eap.ko` has it. So on 2.4 GHz the written value is
  read by nothing and 2.4 GHz multicast goes out as broadcast. The 2.4 GHz
  BSSes on a VLAN still get the bridge's snooping (section 23).

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
  `UPLINK LOST`/`UPLINK BACK` go to `events.log`. The status LED blinks red
  fast meanwhile, the firmware's own "no WAN" pattern (row `102 27 2 0`),
  where a U6 blinks its LED for a lost uplink; locate (blue) and the LED off
  (dark) win over it, and the agent's stop puts green back
  (`internal/mtkwifi/led.go` uplinkLED/ReleaseLED). Not yet seen on the unit
  with a real cable pull.
- A rollback while isolated (a failed apply, or the health check after a
  failed isolation) brings last-good back isolated, which is what Verify
  checks. It used to bring back every SSID while Verify checked the
  isolated plan, so each health check failed and rolled back again: two
  radio restarts per check for the whole outage.
- **Default (owner decision 2026-11-20: on, like a U6):** on, as a U6's uplink monitor is
  (design principle a). gaps.json garage item 5 asked for off by default
  because each isolation and each restore is a restart per radio (hang
  exposure). The rollback loop that made an outage cost repeated restarts
  is fixed (above); what remains is two restarts per radio per outage of
  15 s or more. `uplink_loss: false` is the opt-out.
- **Unverified:** the carrier reading of `jioports` during a real WAN
  cable pull; client behaviour.

## 10. Real-time station events

- **U6:** wevent/stahtd: joins and leaves at once.
- **Garage:** `WirelessEvent=1` on 5 GHz (batched); a passive rtnetlink
  listener (IWEVCUSTOM: Delete, the MBO and WAPP leaves), the Econet event
  socket (failed joins logged with their reason) and the kernel log's
  2.4 GHz `Del Sta` lines (`internal/mtkwifi/drvevents.go`). A leave is held
  1 s, a burst (more than 3 on one BSS within 1 s: a restart) is dropped,
  counted over every Delete of the last seconds, released or not (counting
  only the ones still held let a burst's tail out as leaves once its head
  was dropped), the kernel log's 2.4 GHz `Del Sta` lines together with the
  2.4 GHz BSSes,
  events during a restart or its settle time are dropped, and the same
  station's leave from two sources within 5 s is reported once. A released
  leave is the station's `sta_leave` in the next reading and wakes the
  inform loop (at most every 2 s); joins stay with the reading diff. The
  station table a reading uses can be older than the reading's start (the
  collector's 5 s cache, up to 5 min around a restart), so a station a
  driver leave removed and the same reading still lists is not reported
  as associated again in that reading: a station really back shows as an
  association in the next one (it used to give leave, association, leave
  for one disconnect).
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
  disconnects the guest (inside a restart's settle time the RETURN rule
  goes at once and the disconnect, live iwpriv, waits for the first Tick
  after it; a guest authorised again meanwhile is not disconnected). Tick rebuilds chains something else removed; the
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
- At the hand-back inside a settle time no `hs_flag=0` is sent (the radio
  restarts that follow clear it).
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
    `EVT_AP_RadarDetected` (radio, radio_name: the 5 GHz radio's
    `radio_table` name, rai0 or wifi1; channel, freq) to the controller and logs
    `RADAR` in `events.log`, keeps the channel out for 31 min (all of 52-64
    at 80 MHz), writes the driver's channel into the profile meanwhile, and
    then goes back. A move the driver refused is no radar.
  - A planned profile restart (a channel and width change in one push, a
    hand-back) resets the radar follow-up: the radio comes up on the
    profile's channel, which is no radar. It used to compare against the
    DFS channel set before the restart and report a false
    `EVT_AP_RadarDetected` with a 31 min NOP on 52-64.
  - The live region and channel changes hold the RestartGate's write side
    and start their quiet time before the `iwpriv`, from Tick as from Apply,
    so no collector read (iwconfig, iwpriv show, site survey) runs while the
    driver rebuilds its channel list or restarts its BSSes (the 2026-11-19
    hang rule).
  - Never touched: IEEE80211H, RDRegion, DfsEnable, DfsZeroWait and the
    driver's DFS test commands (`internal/mtkwifi/dfs.go`).
- **Unverified, before turning `dfs` on:** in a quiet window on an empty
  radio, `iwpriv rai0 set CountryRegionABand=0; iwlist rai0 channel` must
  list 52-64 (a region lock refuses it), then `iwpriv rai0 set
  CountryRegionABand=10` while still on 149. Also unverified: the CAC
  length on the unit, that a NOP survives the region change back, and
  automatic channel after leaving DFS (the radio goes to 36 until the next
  restart). Whether a full close/open rebuilds the driver's cached channel
  list from the profile (INFERRED): if not, the hand-back leaves the live
  region at 0 until the vendor's next restart, and a first deploy onto
  52-64 gets a second, live move after the batched restart.

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
- **Opt-out:** `assoc_garp` false (the Deco's key, default true) stops
  it; the proxy ARP responder still gets the stations. Unlike the Deco it
  does not need `sta_snoop`: with `sta_snoop` on, an address the
  connection-event taps saw on the BSS's bridge is used too (section 20).
- **Unverified:** on-air capture of the GARP; the upstream switch's MAC
  move.

## 16. Login lock (`login_lock`, on with takeover and apply)

- **U6:** with the site's Device SSH Authentication off, the AP's SSH
  server listens on the loopback only.
- **Garage:** the agent drops new connections to telnetd (:23) and to :22,
  IPv4 and IPv6, while Device SSH is off and the controller answers
  (`UDECO-LOCK`, first in `INPUT`, ahead of Jio's own :23 accept;
  `/pfrm2.0/bin/iptables` without `-w`; `internal/jiosys/loginlock.go`).
  Established sessions and the loopback are let through. It opens after
  10 min without a controller reply, on Device SSH on, at the agent's
  stop and at the hand-back. `deploy/jio-start.sh` removes the lock
  first thing in each round of its supervisor loop, and `deploy/jio-ap.sh` says what to do
  when telnet does not answer. The details:
  [login-lock](login-lock.md).
- **Unverified:** `-m conntrack` and `ip6tables` on this kernel; an open
  telnet session surviving the lock. A failed rule leaves the unit open,
  and the log says why.

## 17. 802.11r, 802.11k, 802.11v on 5 GHz (`ft`, off by default)

- **U6:** FT-PSK and FT-SAE with the other APs (hostapd, `iapp_key`),
  neighbour reports, BTM requests.
- **Garage:** the MT7663 driver has 802.11r but no daemon (iappd is a
  `tf1Main` link without IAPP). `internal/mtkft` has what the agent needs
  to take the daemon's place: the driver's KDP signals and key OIDs, the
  FT key hierarchy, hostapd 2.9's RRB-OUI push and sequence frames, the
  neighbour report and BTM bodies. With `ft` the agent writes the
  FT profile keys in the Decos' mobility domains (`mtkwifi/ftplan.go`) and
  relays FT-SAE keys between the driver and the Decos' hostapd
  (`mtkwifi/roam.go`); details in [garage-ft](garage-ft.md).
- **Off by default** until the roaming test passes: the FT AKMs change
  every FT SSID's beacon (some old clients refuse them) and turning it on
  restarts the radio.
- **FT-PSK, Deco to Garage:** the agent pre-installs the keys hostapd
  derives, for each station that joined here and on a refused attempt;
  only on WLANs with FT-SAE (the Decos announce holders for no others).
- **802.11v:** band steering and the Roaming Assistant are claimed with
  `ft` (BTM requests; 5 GHz never with a disconnect timer, since
  the driver does not check the station's BTM support there).
- **802.11k:** answered by the drivers from their scan tables; the agent
  writes no lists.
- **Verified on the unit (2026-11-23):** the profile keys (MDIE of the
  Decos' 5 GHz domain, FT AKMs, R0KH-ID length 24); the KDP channel
  (`iwpriv rai0 set ft=0`); `KEY_REQ` for an FT-PSK station, whose
  PMK-R1 matched hostapd's derivation. **Open:** the FT_ASSOCIATION
  signal (none seen on an initial FT-PSK association; the agent asks on
  the 4-way completion event instead); all roams.

## 18. 802.11r/k/v and U-APSD on 2.4 GHz (driver only, `mt7603roam`)

- **U6:** FT-PSK and FT-SAE with the WLAN's fast roaming, 802.11k
  neighbour reports, 802.11v BSS transition, U-APSD.
- **Garage:** a rebuilt MT7603 module (`mt7603roam.ko`, module name
  `mt76x3_ap`) has FT-PSK by itself (hostapd `ft_psk_generate_local`
  semantics, R0KH-ID = BSSID hex, `FtMdId<N>` in hostapd's
  `mobility_domain` byte order), FT-SAE through three driver OIDs for the
  agent's RRB relay, a per-BSS neighbour list (`NrAdd`), a one-station
  BTM request (`BtmReq`), U-APSD (`APSDCapable`) and the vendor's
  `ApOffChanScan`. The keys, OIDs and commands:
  [garage-ft](garage-ft.md). With `ft` the agent writes the FT
  keys (only when the module is loaded: `FT_UDFT_GetEvents` in
  `/proc/kallsyms`) and relays FT-SAE keys through the three OIDs; the
  neighbour list, BTM and U-APSD are not used yet. The module was
  live-swapped on the unit on 2026-11-23 (not persistent).
- **Not on this unit:** FT-1X (no MSK in the driver), FT over the DS,
  RIC, Hotspot 2.0 (the padavan tree lacks the WAPP sources it needs; see
  garage-ft).
- **Unverified:** all of it on air. Open risks: the R1 table and the
  R0 cache are emptied by every radio restart; a pull must land within
  about 400 ms (mac80211's FT auth retries); BTM to a PMF station not
  checked as a protected frame.

## 19. mDNS service bridge (`mdns_bridge`, off by default)

- **U6:** mdns-bridge between the site's VLANs (the controller's fw2_caps
  mDNS).
- **Garage:** the Deco's `internal/mdnsbr`, with the LAN bridge `bdg2`
  (the agent's `br-v<vid>` bridges as on the Deco). Its wired members
  (`eth0.<port>.1`) and served BSSes are tapped; idle BSS slots, the
  AP-client and WDS netdevs are skipped. A VLAN without a local bridge is
  reached tagged on the uplink's parent `eth0.4`. The Wi-Fi interception
  is the same `UDECO-MDNS` ebtables chain; there is no Broadcom flow cache
  to flush (`cmd/udeco-ap/mdnsbr.go`, `NoFlowCache`).
- **Unverified:** ebtables `--ip-dport`/`--ip6-dport` matches in the
  Garage's ebtables build; sending tagged frames on `eth0.4`.

## 20. Connection-timing events (`sta_snoop`, on by default)

- **U6:** STA_ASSOC_TRACKER events (success, failure, soft failure, fixup)
  with the join's timing.
- **Garage:** the Deco's tracker and its read-only ARP/DHCP/DNS taps on
  each served BSS (`ra0`-`ra3`, `rai0`-`rai3`). There is no hostapd, so the
  join steps come from the drivers' events (`cmd/udeco-ap/staconn_jio.go`,
  `mtkwifi.EventsOptions.Steps`): the Insert (MAC entry made at
  authentication) starts the attempt; on 5 GHz the MT7663's system-log
  events (IWEVCUSTOM on `rai0`, `STA(<mac>) ...`: 0x200 associated,
  0x20D/0x20E key done, 0x207 MIC different, 0x20B handshake timeout) and
  the WAPP authorized event give association and authorization; ECNT
  reasons 14 (wrong passphrase) and 15 (4-way timeout) count as failures,
  once when two sources report the same step within 5 s. A key done that
  belongs to no open attempt (a group rekey) is ignored.
- **Not filled:** on 2.4 GHz the rebuilt MT7603 reports only the Insert,
  so its stations are authorized at their first frame on the tap:
  `assoc_delta` and `wpa_auth_delta` are 0 and a wrong 2.4 GHz passphrase
  is never reported as a failure. `auth_delta` and RADIUS fields stay out
  (no 802.1X here).
- **Unverified:** the MT7663 system-log flags and their netdev on the unit
  (from the mt7615 source; the texts are in the kernel's strings); that
  `WirelessEvent=1` is enough for them.

## 21. Multicast inspect

- **Garage:** the platform-independent `internal/mcinspect`, as on the
  Deco; claimed on both platforms.

## 22. Bridge group address filter (controller `bga_filter`)

- **U6:** ebtables drops of the 802.1D bridge group address on its VAPs.
- **Garage:** the Deco's filter: `UDECO-BGA` (policy RETURN), first in
  `FORWARD`, drops `01:80:c2:00:00:00` (STP BPDUs; EAPOL and LLDP pass) in
  and out of each served BSS whose WLAN does not disable it. Live ebtables
  only, built after the radios are applied and checked each Tick after the
  settle time (a deleted chain is rebuilt); the hand-back removes it
  (`internal/mtkwifi/bga.go`).
- **Unverified:** on the unit.

## 23. IGMP/MLD snooping on the VLAN bridges

- **U6:** mcsd: snooping on every bridge, no querier, `hash_max 2048`.
- **Garage:** the Deco's values on each `br-v<vid>` the agent makes, set
  through sysfs where they read otherwise, at creation and each Tick
  (`internal/mtkwifi/snoop.go`). The 3.18.21 kernel has bridge multicast
  snooping and floods a group while no querier is seen. `bdg2` is the
  vendor's and left alone.
- **Unverified:** on the unit.

## 24. Nothing to change, or not possible

- **BSS Load element:** both drivers advertise it on every BSS of a radio
  while WMM (forced on by HT) or 802.11k is on (MT7603
  `ap_qload.c` QBSS_LoadInit). A WLAN with it disabled is noted as not
  applied: the drivers have no key or command to turn it off.
- **Intelligent DHCP (DHCP broadcast to unicast):** neither driver has it
  for an AP's clients (the MT7663 `dhcp_uc` belongs to the repeater's MAC
  translation). Not served; DHCP is left alone.
- **5 GHz minimum rates:** the MT7663 forces 6, 12 and 24 Mb/s basic, so
  `min_rates` applies to 2.4 GHz only (noted).
- **Max clients:** served (`MaxStaNum`/`MbssMaxStaNum`, at most 32).
- **TWT:** 802.11ax only. The MT7603 is 802.11n and the MT7663 802.11ac,
  so `twt` stays a Deco-only key.

## 25. SNMP

- **Garage:** the same agent (`internal/snmpagent`) as on the Deco. The
  MediaTek netdevs (`ra*`, `rai*`, `apcli*`, `wds*`) report ifType
  ieee80211 by name, as their drivers may have no sysfs `wireless`
  directory. The engine boots counter is under `/flash2/udeco/session`.
- **Unverified:** that UDP 161 is free on the unit and that Jio's
  firewall lets the controller's queries in.

## 26. Speed limits (`rate_limits`, off by default)

- **U6:** a client's user group (cmd rate-update) and the WLAN's user
  group are shaped per station, both directions.
- **Garage:** the kernel has no traffic control (`CONFIG_NET_SCHED` off),
  so the agent's own module polices instead: `udeco_rl.ko`
  (`tools/udeco_rl`, built against the unit's 3.18.21 layout by
  `tools/econet-kernel/build-modules.sh`, released as
  `udeco_rl-jio-jcow414.ko.gz`, installed with `deploy/jio-ap.sh
  --rate-limit-module`), a token
  bucket per station and direction on the bridge's FORWARD hook. The
  agent loads it from `/flash2/udeco/udeco_rl.ko.gz` only when a limit is
  set and writes the whole table to `/proc/udeco_rl` in one write
  (`internal/mtkwifi/ratelimit.go`). The table merges the client's own
  entry (by MAC: any SSID, either radio) with the SSID's limit in the
  directions the entry leaves open, like bcmwifi. SSID limits follow the
  stations of each reading.
  - **Never a cut-off:** a frame is dropped only while its bucket is in
    debt. ARP, DHCP, DHCPv6 and IPv6 neighbour discovery always pass.
    Only frames forwarded to or from a Wi-Fi port (`ra*`, `rai*`) of a
    listed station are looked at; the unit's own traffic (management,
    telnet, inform) is never forwarded, so it is never policed.
  - **Hardware NAT:** Jio's `hw_nat` binds flows into the PPE, past the
    bridge. The module clears the FOE tag of each limited station's
    frames so they are never bound, and a table that adds or changes a
    limit carries `flush` (hw_nat's `PpeCleanTableHandler`) for flows
    bound before.
  - **Restarts:** the module keeps its table across agent restarts. The
    agent keeps the per-client list in `/tmp/udeco/mtk-client-rates.json`
    and the session's `state.json`, and writes the table again once. A
    reboot loses both; the startup hand-over writes it again.
  - **Hand-back:** the table is cleared and the module removed (`rmmod
    udeco_rl`). The observe-mode start and the drop to observe remove one
    an earlier run left loaded.
  - **Notes:** with `rate_limits` off, or a module that does not load or
    answers in another version, each limited SSID keeps the plan note
    "per-client rate limit ... not applied" with the reason; the module is
    tried again after 10 min. No capability bit claims limits on either
    platform (the controller sends rate-update regardless).
- **VERIFIED on the unit 2026-11-23** (the Garage live test in
  [client-rate-limit](client-rate-limit.md), steps 1-4): the kernel takes
  the module (`insmod`/`rmmod` clean, no oops); bridged Wi-Fi traffic passes
  the FORWARD hook (the `/proc/udeco_rl` counters rose); 512 down / 768 up
  held at 502/698 kbit/s on 2.4 GHz and 504/699 on 5 GHz with ping, DHCP and
  telnet unaffected; a 5 GHz flow bound in hw_nat before the limit bypasses
  FORWARD until a write with `flush`, so the agent's flush on a new or
  tighter limit is required. Still to run: the path through UniFi (user
  group, band move, agent restart, hand-back). `rate_limits` stays off by
  default until that run: it loads a kernel module. Not covered: traffic
  between two stations of the same BSS that the driver forwards itself, and
  a station's traffic to the unit itself.

## 27. WPA2/WPA3-Enterprise (`enterprise`, on by default)

- **U6:** hostapd runs 802.1X against the WLAN's RADIUS servers (RadSec
  too), with RADIUS MAC authentication, Filter-Id, accounting and
  Hotspot 2.0 where the controller sets them.
- **Garage:** the vendor's split. The driver advertises the RSNE
  (`AuthMode=WPA2`, AES), keeps each station's port closed until it has
  a PMK and passes EAPOL up the BSS netdev; Jio's
  `/userfs/bin/rtdot1xd` runs EAP with the RADIUS server and hands the
  PMK to the driver (`internal/mtkwifi/dot1x.go`). 5 GHz always; 2.4 GHz
  only with the rebuilt MT7603 module (`mt76x3_ap`): the vendor
  `mt7603eap`'s RADIUS profile format is unverified, so there the SSID is
  noted and left off.
  - The profile carries the client: `RADIUS_Server`/`RADIUS_Port` per
    slot; the secret in `RADIUS_Key1` as a ;-list of every slot on the
    MT7603 (its parser's "prev format"; the other slots get a
    placeholder, never empty), in `RADIUS_Key<n>` per slot on the MT7663;
    `NasId<n>` with the controller's NAS-Identifier (16 characters at
    most); `EAPifname`/`PreAuthifname` the distinct bridges of the
    enterprise BSSes padded with `lo` (the drivers keep entries a later
    profile drops, and rtdot1xd opens a socket per entry);
    `session_timeout_interval=0` (rtdot1xd adds no deauth timer of its
    own; the server's Session-Timeout still applies); the vendor's
    `own_ip_addr` (NAS-IP-Address; 127.0.0.1 if it is 0). A radio without
    an enterprise BSS keeps every vendor RADIUS key, so this changes
    nothing on today's WLANs. Any change is a profile change: one radio
    restart.
  - WPA3-Enterprise is WPA2 with PMF required (`PMFMFPR=1`,
    `PMFSHA256=1`): both RSNE builders then advertise AKM 00-0f-ac:5
    only. 192-bit (Suite B) is refused by translate on every platform.
  - rtdot1xd is the agent's: `sh -c 'exec /userfs/bin/rtdot1xd -p <ra|rai>
    -i <first BSS netdev> </dev/null >/dev/null 2>&1'`, one per radio with
    an enterprise BSS, started by the first Apply or Tick after the
    restart's settle time (its first ioctls are driver reads), at most
    once a minute while it keeps exiting. Each radio restart stops that
    radio's copy first (SIGTERM, SIGKILL at the next pass: what it read is
    stale and the driver never tells it); any copy the agent did not start
    (the vendor's, `rtdot1xd_AC`) is stopped; the hand-back stops the
    agent's. `rtdot1xd` is in jiosys's dumb-AP keep list (it forks to
    init). Without it the enterprise BSS beacons and admits nobody.
  - Not served (the SSID stays off, noted): RADIUS MAC authentication
    (neither driver nor rtdot1xd has it), a Filter-Id (rtdot1xd cannot
    send it, and without it the server could admit users meant to be kept
    off), a server that is not an IPv4 literal, a secret the profile cannot
    carry (empty, over 64 characters, `;`, control characters, spaces at
    either end). Noted and served: accounting servers (rtdot1xd has no
    accounting client), auth servers after the first (no failover), the
    controller's own IP, a NAS-Identifier over 16 characters, Hotspot 2.0.
  - RadSec: the agent's proxy as on the Deco (`cmd/udeco-ap/radsec.go`
    rewrites the servers to 127.0.0.1 before the plan); fw2_caps RadSec
    is claimed on the Garage only while some radio serves 802.1X
    (`Applier.ServesDot1X`). PPSK, the RADIUS filter, Hotspot 2.0 and
    RADIUS-assigned VLANs are not claimed: not possible with these
    drivers and this rtdot1xd (the feature docs' Garage sections).
  - `enterprise: false` never starts rtdot1xd and leaves the enterprise
    WLANs off, as before this item, with RadSec unclaimed.
- **Unverified:** everything on the unit. `/userfs/bin/rtdot1xd` on this
  firmware; the MT7663's EAPifname parse (it is gated by a driver flag at
  `pAd+0x111885`, read but not identified); EAPOL from a VLAN bridge;
  `lo` entries; a PEAP or EAP-TLS join on each band; WPA3-Enterprise
  (AKM 5) on each band; that rtdot1xd survives a radio restart's
  SIGTERM/SIGKILL cleanly; the RadSec path end to end.
