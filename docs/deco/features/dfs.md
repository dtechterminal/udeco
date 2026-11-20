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

Superseded by the sections below: IN/288 turned out to have low power and
no Wi-Fi 6 rates on this board, and the last section has the tables the
units run now (`driver_country_bands`).

**Channel** (`internal/bcmwifi/dfs.go`, plan.go):

- A DFS chanspec gets `wl spect 1` (802.11h) before the chanspec, in the
  same radio down. `spect 1` also rides every later radio-down window on 5
  GHz ([radio-parity](radio-parity.md)).
- hostapd's conf names channel 36 for a DFS channel. wl owns the channel,
  and a radar channel in the conf would make hostapd start a CAC of its own
  over nl80211. While a radar move is followed the conf keeps naming the
  wanted DFS channel (36), whatever channel the driver chose: a conf that
  followed the driver to 149/80 would differ from the running one, so every
  Tick would ask for a full apply (no repairs) and every provision would
  restart hostapd until the dfs-reset.
- After hostapd starts, the chanspec is set again inside the dwds/rrm radio
  down/up the reconcile makes anyway (the spec's "apply the DFS chanspec
  after hostapd is up"). This costs no extra restart; it keeps hostapd's
  START_AP from leaving the radio on the conf's 36.
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
  `radio_name` (the radio's `radio_table` name), `channel`, `freq`;
  `cmd/udeco-ap/dfs.go`, which the Garage's radar event shares);
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

## Deploying a DFS channel on a Deco

- **Drop `driver_country`.** Under the X20's US/0 the 5 GHz list is 36-48
  and 149-165, so 100/116/132 are refused ("not allowed by the driver in
  this country": the radio stays on auto). The agent logs a note when the
  override meets a DFS channel.
- **CAC on every 5 GHz restart.** Each radio down/up on a DFS channel runs
  the CAC again, during which Tick skips all repairs on both radios. 116/80
  covers 120-128, the weather channels, so its CAC is about 10 minutes
  (timed on the Hallway X20 2026-11-20 under IN/288: PRE-ISM from 10:04:30
  to In-Service Monitoring at 10:14:33). 100/80 and 132/80 took 60 s
  (Bedroom, Owner's Room). `wl chan_info` flags 120-128 only "RADAR
  Sensitive, Passive", like the rest of the band: the long CAC is not
  visible there. The owner kept Hallway on 116/80 (25 dBm) knowing every
  5 GHz restart there costs ~10 minutes of 5 GHz.

## Unverified on hardware

This list is the note's state when its sections above were written
(2026-11-20). The current status is the "DFS channels" and "Country" rows
of the [README](../../../README.md) and the dated sections below; where they
differ from this list, they are right.

- Verified: the Bedroom X20 accepts `wl country IN/288` with the radio down
  (2026-11-20, "IN (IN/288) INDIA", 80 MHz blocks 36/52/100/116/132/149,
  chanspec_txpwr_max 18 dBm on 36-64/80, 25 on 100-144/80, 18.5 on
  149-161/80). Not verified when this was written: the agent's own apply of
  it, and serving a DFS channel. DFS channels have been served since (the
  CAC timings under "Deploying a DFS channel on a Deco" above, and the
  README row).
- The output formats of `wl dfs_status` and `wl chan_info`. They are taken
  from the Broadcom `wl` utility's source and have not been read on an X20.
  If either cannot be read, CAC and radar handling stay off: Verify and
  Tick behave as before.
- That `wl spect 1` needs the radio down, and that this `wl.ko` runs the CAC
  and radar detection with it (TP-Link's own radar daemon is stopped).
- That hostapd 2.9 with `ieee80211h=1` and channel 36 in its conf leaves a
  DFS chanspec set by wl alone. The agent sets the chanspec again after
  hostapd starts in case it does not; read `wl -i wl1 chanspec` right after
  the takeover apply to see which.
- The `EVT_AP_RadarDetected` payload keys. They were chosen to match the
  quick-scan event, because the U6's own payload has not been captured.

## Power per region and the per-band override (2026-11-20)

Read with `wl -i <radio> txpwr_target_max` on the X20s:

| Region | 2.4 GHz | 5 GHz 36-48 | 5 GHz 100-144 | 5 GHz 149+ |
| --- | --- | --- | --- | --- |
| IN/288 | 14 dBm | 16.5 dBm | 23.5-25 dBm | 18.5 dBm |
| US/0 | 24 dBm | 23.5 dBm | none (no DFS) | n/a here |

IN/288 at 14 dBm on 2.4 GHz cut a Tapo camera on Bedroom from 72 Mbps with
1-3 % retries to 1-5.5 Mbps with 40-64 % retries the hour the parity build
landed. At 16.5 dBm on channels 36/40, a Galaxy S20 FE never received its
DHCP replies. Each radio keeps its own country in the driver: on Bedroom,
`wl -i wl0 down; wl -i wl0 country US; wl -i wl0 up` gave 2.4 GHz 24 dBm
while 5 GHz stayed IN/288 on 100/80 with its In-Service Monitoring
untouched, and the camera went back to 72 Mbps at once.
`"driver_country_bands": {"ng": "US"}` makes this the agent's plan
(bcmwifi `Desired.BandCountry`): full power on both bands, with DFS on 5 GHz.
Keep 5 GHz on 100-144 under IN/288: 36-48 is the low-power block there.

Superseded by the sections below (IN/288 on 5 GHz gave way to US, then to
`#a`).

## IN/288 has no Wi-Fi 6 rates: run US on both bands (2026-11-20)

`wl -i wl1 curppr` on Bedroom (IN/288, 132/80) showed every HE row as `-`
(rate disabled) at 20, 40 and 80 MHz, and VHT MCS 10-11 missing. The same
command on Hallway (US/0, 40/80) filled every HE row. The agent still turns
`wl he 1` on, so the radio advertises Wi-Fi 6 but may not send it: Wi-Fi 6
phones set up an HE link and the downlink collapses. An iPhone 17 Pro Max on
Bedroom at -65 to -70 dBm took 19,379 retries for 3,329 frames and fell to
8.6 Mbps (HE MCS0 at 20 MHz); its uploads still reached the AP at 432 Mbps.
A Wi-Fi 5 laptop on the same radio got 433 Mbps with 4 % retries. With
`wl he 0` on that radio (down, set, up), the iPhone got 585-650 Mbps with
0-17 % retries. This is also why a Galaxy S20 FE lost its downlink on 116/80.

Wi-Fi 6 matters more than DFS here, so every Deco runs US/0 on both bands
(`"driver_country_bands": {"ng": "US", "na": "US"}`). Under US/0 this board's
5 GHz has no DFS: `wl chanspecs -c US -b 5 -w 80` lists only 36-48 and
149-161 (165 at 20 MHz), with HE rows filled on 149/80 at 23.5 dBm. Plan
since 19:07 IST: Hallway 40/80; Bedroom and Owner's Room 149/80, which hear
each other at -76 dBm and so share air time; the Garage 149/80, which none
of the Decos hear. Do not set a band to IN/288 while Wi-Fi 6 is wanted.

The choice of US on 5 GHz is superseded by the last section ("5 GHz on `#a`
by the user's choice"); the measurements here stand.

Which countries have DFS and Wi-Fi 6 together (checked on Bedroom, 2026-11-20)?
None of the real ones. `wl chanspecs -c <cc> -b 5 -w 80` over all 267 codes in
the driver gives DFS at 80 MHz for 45 base tables (AU, SG, SA, DO and others;
EU, E0, GB, FR, CA, JP and CN give no DFS or no 80 MHz). Setting the radio to
AU, SG, SA, DO and IN/288 in turn and reading `curppr` showed every HE rate
disabled for all of them, on 36/80 and 149/80 as well as on 52/80, 100/80 and
132/80, so it is the country table and not the channel. Only US/0 and `#a`
fill the HE rows. `#a` is Broadcom's all-channels test table, not a country:
it gives HE at 23.5 dBm on 52/80 and 100/80, but it runs no radar detection:
on 100/80 under `#a` (Bedroom, 2026-11-20 19:16 IST) `wl dfs_status` stayed
IDLE for 80 s, with no CAC and no In-Service Monitoring, where IN/288 on the
same radio runs a 60 s CAC and then monitors. It also offers 116/80, in the
weather-radar band. Do not run DFS channels under `#a`. The cause is in the table: with the radio down,
`wl chan_info 100` reads "RADAR Sensitive, Passive" under IN/288 but only "5G
Band" under `#a` (52 and 120 likewise), and `wl spect 2` (strict 802.11h)
does not change it, so the driver's CAC and monitoring never engage; the
`dfs_preism`/`dfs_postism` overrides only act on radar-sensitive channels.

Hardware test under `#a` (Owner's Room, 2026-11-20 19:25-19:28 IST, done by
hand with a 10-minute auto-revert, then put back to US 149/80): Wi-Fi 6 does
run on a DFS channel. The GL KVM (AIC8800, one stream, links at 40 MHz only),
pinned to that AP at -25 to -30 dBm, measured with iperf3 against the UCG:

| Setup | Link | Down | Up | AP retries |
| --- | --- | --- | --- | --- |
| US/0 149/80 (shared with Bedroom) | HE-MCS 11, 40 MHz | 173 Mbps | 211 Mbps | 9,836 of 217,177 |
| `#a` 100/80 (alone) | HE-MCS 11, 40 MHz | 215 Mbps | 211 Mbps | 1,858 of 41,773 |

Internet speed test from the same KVM (Cloudflare, 4 streams each way, over
its Wi-Fi only), 19:35-19:38 IST: US/0 149/80 150.6 down / 151.1 up, `#a`
100/80 151.4 down / 156.1 up, 25 ms either way, with 785 AP retries in
248,682 frames on 100. Both hit the 150 Mbps line, not the Wi-Fi.

So the radio and driver do Wi-Fi 6 on DFS channels. Only the country data
withholds it for every real country, and `#a` gets it by dropping radar
detection, which is why it stays a test. TP-Link's data for this board carries Wi-Fi 6 only for US.

## 5 GHz on `#a` by the user's choice (2026-11-20 19:55 IST)

The user chose Wi-Fi 6 with the extra channels over radar detection and
made `#a` the 5 GHz table on all three Decos:
`"driver_country_bands": {"ng": "US", "na": "#a"}` (2.4 GHz stays US/0,
already full power with Wi-Fi 6). The agent accepts `#a` since a0873d9 and
keeps its case (`bcmwifi.NormCountry`). Because `#a` runs no radar
detection, the planner refuses any 5 GHz chanspec that covers 120-128
(5600-5650 MHz, weather radar) and keeps the live one with a note. Seen
live on Owner's Room: UniFi's 116/80 was refused twice ("116/80 covers the
weather-radar band ... keeping"), and the radio stayed on its channel.

Plan: Hallway 40/80, Owner's Room 100/80 (it does not hear the neighbour
"Kallu" on 106/80), Bedroom 132/80, Garage 149/80 (MT7603, its own table).
All Decos at 23.5 dBm with every Wi-Fi 6 rate enabled, each on its own
80 MHz block. Back to US: set "na" to "US" and restart the agent; US/0 has
no DFS, so move the channels to 36-48 or 149-161 first.

