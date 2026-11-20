# DFS channels and the India country table

## What the U6 Pro does

- It serves the controller's DFS channel and reports `has_dfs` and
  `has_fccdfs` on both radios (mca-dump).
- It runs the channel availability check (CAC) before beaconing on a radar
  channel: about 60 s, 10 minutes on the ETSI weather channels.
- On radar it moves off the channel. The ubntbox strings show
  `DFS: Radar detected on channel %u (freq %u)` and
  `EVT_AP_RadarDetected %s: radar found on channel %u (%u MHz)`.
- At 02:00 the controller's cron job `syswrapper.sh dfs-reset` moves a radio
  back to its configured channel, unless that channel is still in the
  non-occupancy list (`radartool chknol`; syswrapper.sh 1844–1925).

## What the agent does

**Country.** India runs as `IN/288` (`internal/bcmwifi/radio.go`
countryRev). The driver's IN/0 has no 80 MHz chanspec at all (verified on
.205, 2026-11-19). If the driver refuses IN/288, the country step's
alternative `IN` runs instead (`Step.Alts`). `Applier.refused` remembers
the refusal, so later plans use IN and do not restart the radio on every
tick. `driver_country` still overrides the country, but it is no longer
recommended.

**Channel** (`internal/bcmwifi/dfs.go`, plan.go):

- A DFS chanspec gets `wl spect 1` (802.11h) before the chanspec, in the
  same radio down. `spect 1` also rides every later radio-down window on 5
  GHz ([radio-parity](radio-parity.md)).
- hostapd's conf names channel 36 for a DFS channel. wl owns the channel,
  and a radar channel in the conf would make hostapd start a CAC of its own
  over nl80211.
- The controller's channel is checked against the driver's live chanspec
  list for the country (`wl.Caps`, re-read after every apply). A channel
  the list does not hold is refused with a note, and the radio stays on
  auto.

**CAC.** While `wl dfs_status` reads PRE-ISM or Channel Availability Check:

- Verify accepts a BSS that is not up, so the health check does not roll
  back;
- Tick runs no repair and asks for no apply, because a radio down/up would
  restart the CAC.

**Radar.** When the live chanspec is not the wanted DFS one and
`wl chan_info` lists a 20 MHz channel of the wanted block as "Temporarily
Out of Service", the agent:

- keeps the driver's channel instead of moving back;
- logs the move;
- queues a `RadarEvent`, which Tick reports once and the agent sends as an
  `EVT_AP_RadarDetected` notification (`event_string`, `radio`,
  `radio_name`, `channel`, `freq`; `cmd/udeco-ap/dfs.go`);
- notes the move in every plan.

**dfs-reset.** The controller's cron job (`cron.N.job.M.cmd` containing
`dfs-reset`, schedule `M H * * *`; translate `Intent.DFSReset`) runs once a
day at its time. A reset missed while the agent was down runs at the next
check. `Applier.DFSReset` frees a radio whose channel is out of the
non-occupancy list, and the agent applies. A channel still in the list
waits for the next night. Other cron jobs are noted and not run.

**Reporting.** `has_dfs` and `has_fccdfs` are reported on the 5 GHz radio in
takeover on the Deco (`models.DecoAgentFeatures.DFS`) and cleared on a drop
to observe mode.

## Unverified on hardware

- That the X20's driver has an IN/288 table, and what it allows.
- The output formats of `wl dfs_status` and `wl chan_info`. They are taken
  from the Broadcom `wl` utility's source and have not been read on an X20.
  If either cannot be read, CAC and radar handling stay off: Verify and
  Tick behave as before.
- That `wl spect 1` needs the radio down, and that this `wl.ko` runs the CAC
  and radar detection with it (TP-Link's own radar daemon is stopped).
- That hostapd 2.9 with `ieee80211h=1` and channel 36 in its conf leaves a
  DFS chanspec set by wl alone.
- The `EVT_AP_RadarDetected` payload keys. They were chosen to match the
  quick-scan event, because the U6's own payload has not been captured.
