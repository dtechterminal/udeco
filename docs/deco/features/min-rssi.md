# Minimum RSSI for connected clients (2026-11-20)

## What a U6 does

- The controller sends a radio's minimum RSSI as `stamgr.N.minrssi.status=true` and
  `stamgr.N.minrssi.rssi=<dBm>` (per radio, with `stamgr.N.radio`). On the U6 Pro the station
  manager daemon `stamgr` acts on it (U6 Pro ubntbox strings): a client that stays below
  the minimum is disconnected, and its `sta_leave` STA_ASSOC_TRACKER event carries
  `assoc_status` 16 (KICKED_DUE_TO_MIN_RSSI). The controller reads that as
  `triggeredByMinimalRssi` on the client's roaming record.
- The exact sampling and hysteresis of `stamgr` are not known (no U6 capture of a kick).

## What the agent does (takeover, Deco)

- `translate` already reads `stamgr.N.minrssi` into `RadioIntent.MinRSSI` and bcmwifi writes
  hostapd's `rssi_reject_assoc_rssi`. That line is most likely a no-op on the X20: association runs
  in the Broadcom driver (driver SME), not through hostapd's `handle_assoc`, where the check lives.
- `cmd/udeco-ap/minrssi.go` (inform loop, every fresh reading; a stale reading does not count):
  1. a client on a band with a minimum qualifies after 3 readings in a row below it;
  2. it is asked to leave with an 802.11v BSS transition request with Disassociation Imminent
     (`bcmwifi.RoamAssist`, disassociation timer 50 beacon intervals, about 5 s), naming the other
     APs of its SSID this unit's scans heard at the minimum or better (never this unit's own BSSes);
  3. still on that BSS 20 s later, or right away when no other AP was heard or the client does not
     support BSS transition: it is kicked with a 30 s ban on that BSS (`bcmwifi.TempDeny`: the
     station goes into the vif's driver MAC filter in deny mode, which also hides the BSS from its
     probes, and it is deauthenticated from that BSS only). An allow-list SSID cannot take a ban
     (its driver filter admits listed stations): a plain kick then;
  4. the ban is lifted after 30 s; nothing more is done to the client for 2 minutes;
  5. its `sta_leave` carries `assoc_status` 16 (the leave after a Roaming Assistant request
     carries 8192, any other leave 0).
- The ban never touches the stored driver state, hostapd's ACL files or the controller's block
  list. Plan, Tick and the block-list refresh add the live bans to the vif's filter, so none of
  them reports or removes one. A ban the agent did not lift (it stopped) lapses 2 minutes after its
  end and Tick then removes it; a hand-back to TP-Link drops them all.
- No config key: the controller's minimum RSSI switch is the opt-out.

## Unverified on hardware

- That the X20 driver refuses association of a station in a deny-mode MAC filter of one BSS while
  the same station may use the unit's other BSSes (the block list relies on the same filter on
  every BSS).
- Clients' behaviour on the disassociation-imminent request with a 5 s timer.
- That hostapd's `rssi_reject_assoc_rssi` really is a no-op with driver SME.
