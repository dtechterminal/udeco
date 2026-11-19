# Deco X20 spectrum measurements (device tests of spectrum-design §12)

**What this is.** Results of the §12 device tests in `spectrum-design.md`, run on one Deco X20 V2 (`192.168.0.205`, wired uplink `eth1`) on 2026-11-18, uptime about 3 400 s onward. Each section gives the command, the numbers and a verdict against what the design expected. Raw captures are in `internal/wl/testdata/spectrum/` (`t<N>_*.txt`, described in that folder's `README.md`). SSIDs are hashed (`h:` + 8 hex of md5), vendor IEs dropped, and client MACs hashed on the device (`m:` + 8 hex of md5 of the upper-case MAC). Neighbour BSSIDs are kept.

**Rules kept.** Only `.205`. Only getters, `wl scan` starts, `cca_get_stats` and `phy_rxiqest` / `phy_rxiqest_sweep` (current/home channel only). No `wl` sets, no chanspec, power, country or nvram change, no process touched (acsd2 pid 12001 alive throughout), nothing left in the device's `/tmp`. Full-band sweeps were at least 30 s apart.

**Setup at start** (`t0_baseline.txt`).
- wl0 = 2.4 GHz, home `9u` (0x1907), `wl noise` -97. wl1 = 5 GHz, home `40/80` (0xe12a), `wl noise` -96. Country US. wl0 lists 1-11; wl1 lists 36-48 and 149-165 (no DFS). Global `scan_passive_time` 200, `scan_home_time` 45.
- User vifs up: wl01, wl02 (2.4), wl11, wl12, wl13 (5). Clients: one on wl02, one on wl12. The wl13 client had left before the first scan of this session and came back between T1 r2 and r3 (background churn, not scan-caused).
- **wl0 chanim still held the 11 records left by the earlier e7 sweep, about 1 400 s before** (identical values). acsd2 had not rescanned in that time. So persistence of old records is confirmed again.
- **wl1 chanim was empty**: `version: 3` and nothing else, not even the "Stats during last scan" header.
- Beacon rate at idle (`txbcnfrm`): wl0 about 19.5/s (2 BSSes), wl1 about 30/s (3 BSSes). Off-channel time below = (expected − sent beacons) / idle rate.

---

## T1: does a 5 GHz host scan fill wl1 chanim? (x3)

**Command.** `wl -i wl1 scan -t passive -p 110`, poll `scanresults` every 50 ms, then `chanim_stats all`. Snapshot of `chanim_stats all` before each call. Runs 25-40 s apart. Files `t1_wl1_passive_p110_r{1,2,3}.txt`.

| Run | Sweep | Beacons sent / expected | Off-channel | BSSes | Records |
|---|---|---|---|---|---|
| r1 | 1.27 s | 10 / 38.5 | ~0.94 s | 7 | 9 (none before) |
| r2 | 1.30 s | 12 / 39.2 | ~0.90 s | 7 | 9 |
| r3 | 1.24 s | 6 / 36.8 | ~1.04 s | 7 | 9 |

Per-record values (u = obss + nocat + nopkt):

| chanspec | r1 glitch / noise / tx / u | r2 | r3 |
|---|---|---|---|
| 0xd024 (36) | 121 / -101 / 0 / 1 | 25 / -101 / 0 / 9 | 43 / -101 / 1 / 3 |
| 0xd028 (40, home control) | 454 / -96 / 8 / 6 | 145 / -96 / 19 / 8 | 254 / -96 / 4 / 3 |
| 0xd02c (44) | 121 / -102 / 0 / 2 | 130 / -102 / 0 / 2 | 43 / -101 / 0 / 2 |
| 0xd030 (48) | 165 / -101 / 0 / 2 | 173 / -101 / 0 / 3 | 78 / -101 / 0 / 3 |
| 0xd095..0xd0a5 (149-165) | **0 / -100..-101 / 0 / 0** | same | same |

- **Yes for 36-48**: our host scan creates the 9 records, one per 20 MHz chanspec (no 80 MHz records), and refreshes 36-48 on every run (every one "changed" against the pre-call snapshot, crsglitch > 0).
- **No for 149-165**: every run leaves crsglitch 0, bad plcp 0 and all cca fields 0 there, with noise -100/-101. These are the same placeholders as the repo fixture. The sweep still seems to visit those channels: about 0.9-1.0 s off-channel matches 8-9 dwells of 110 ms, not the 3-4 dwells of 36-48 alone. No BSS was ever found on 149-165 either (all 7 BSSes are on the home block or ch48).
- **The freshness rule alone is not enough.** In r2, 0xd0a1 "changed" against the snapshot only because its placeholder noise moved -100 → -101. The §3.2 zero-record rule catches it; a freshness check that looks at `noise` alone would not. Keep both rules.
- Home control ch40 carries our own `txdur` 4-19 in the record, as ch9 does on 2.4 GHz.
- 5 GHz BSSes: our two sibling Decos (BSSIDs AE:A7:B9:3E:15:F8.. at -72 and AE:A7:B9:3E:16:90.. at -83, three vifs each, all on 0xe12a) and one neighbour on 48 at -88..-90. Our siblings are the only strong 5 GHz energy here.
- No client dropped on wl1 (wl12 `in network` kept growing, tx/rx bytes kept rising).

**Verdict.** T1 **passes for UNII-1 (36-48)** and **fails for UNII-3 (149-165)**: a host scan cannot measure 149-165 on this unit, at least through chanim. With the design as written, every 5 GHz band would end `ErrIncomplete` (149 block missing), or, without the zero rule, report UNII-3 as 0 % busy. See T2 for the single-channel check on 0xd095.

---

## T2: single-channel `-c` scans and the freshness rule

**Commands.** `wl -i wlX scan -t passive -p 110 -c <ch>`, 50 ms `scanresults` poll, `chanim_stats all` before and after each call. Files `t2_wl0_hex_rejected.txt`, `t2_wl0_single.txt` (`-c 1`, `-c 6`), `t2_wl1_single.txt` (`-c 36`, `-c 149`, `-c 48`), `t2_wl1_unii3_single.txt` (`-c 149..165`, 7 s apart).

**1. `-c` does not take hex chanspecs.** `-c 0x1001` fails with `could not parse chanspec starting at "0x1001"` / `error parsing chanspec list arg`, exit 254, and nothing is scanned (`t2_wl0_hex_rejected.txt`). The string form (`1`, `36`, presumably also `36/80`, `9u`) works. **§3.2 step 2 and `TestMeasureSpectrumChunked` must use the decimal channel / chanspec string, not `0x1001`.**

**2. What one call leaves in chanim** (record changed vs the snapshot just before the call):

| Call | Duration t0→t1 | Records changed | Target record after (glitch / noise / tx / u) | BSSes found |
|---|---|---|---|---|
| wl0 `-c 1` | 0.14 s | 0x1001, **0x1009** | 1121 / -104 / 0 / 22 | 3 (strongest -77) |
| wl0 `-c 6` | 0.14 s | 0x1006, **0x1009** | 686 / -91 / 0 / 17 | 2 (strongest -66) |
| wl1 `-c 36` | 0.20 s | 0xd024, **0xd028** | 60 / -101 / 0 / 3 | 0 |
| wl1 `-c 48` | 0.19 s | 0xd030, **0xd028** | 286 / -101 / 0 / 5 | 1 (-88) |
| wl1 `-c 149` (1st) | 0.14 s | 0xd095, **0xd028** | 8 / -99 / 0 / 1 | 0 |
| wl1 `-c 149` (2nd) | 0.14 s | 0xd095 (back to all-zero), **0xd028** | 0 / -100 / 0 / 0 | 0 |
| wl1 `-c 153`, `157`, `161`, `165` | 0.14-0.20 s | **0xd028 only**; target unchanged all-zero | 0 / -100..-101 / 0 / 0 | 0 |

- **Every call also rewrites the home control channel's record** (0x1009 on wl0, 0xd028 on wl1), even though the home channel was not in `-c`. Its values look like a real short measurement (wl0 ch9: `txdur` 6-7, `obss` 19-26; wl1 ch40: `txdur` 0-3, `obss` 0-9), sometimes with crsglitch 0 (wl1 c157: all fields 0 except noise). No other record moved. So "exactly that record" is **false**: it is that record plus the home control record.
- **2.4 GHz and UNII-1: pass.** The target record changed on every call, with crsglitch > 0 and cca filled. The freshness rule (§3.2 step 4) accepts all of them, correctly.
- **UNII-3: fail.** 149-165 never get a usable record from a single-channel call either. 153-165 did not change at all (stale → missing under the freshness rule). 149 changed once to a near-empty record (glitch 8, nopkt 1) and then back to all-zero (fresh under the freshness rule, but missing under the zero rule). The radio did leave the channel each time (0 of about 4 expected beacons in 0.14 s), and no BSS was ever found on 149-165 in any scan of this session.
- **Discovery at one 110 ms dwell is uneven.** `-c 1` found 3 BSSes (strongest -77) where the e4 110 ms sweep found 4 with control on ch1 (strongest -63) and e5 found 9 (-65). One dwell can miss the BSS that sets `P_bss` for the channel; the second pass of §3.2 is needed for `interference`, not only for `utilization`.

**Verdict.**
- `-c` works and refreshes the scanned record on 2.4 GHz and 36-48. The chunked plan is viable there, with two code consequences: pass the channel as a decimal string, and **do not treat a changed home-control record as evidence for any other channel**. The step-4 check must look only at the record for `cs`. The home record changes on every call, so if the home channel is one of the planned channels, its own call must be judged on the record taken right after that call, and the extra home updates from other calls should either be ignored or folded in deliberately (they carry our own `txdur`).
- UNII-3 cannot be measured through chanim on this unit, with either a sweep or `-c`. The §3.2 fallback trigger ("first chunked call returns no record") would fire on 149 and switch to the sweep, which does not measure 149-165 either. The 5 GHz design needs a decision: emit 20/40 MHz rows for 36-48 only and treat the 149 block as unmeasurable (omit, or keep the band abnormal), or find another source (T5, phy_rxiqest below).

---

## T3: off-channel time of one `-c` call (beacon counting)

**Method.** A 1-second call window can lose only whole beacon intervals, and a ~0.14 s call alone is too short to count beacons in. So each rep is two fixed 1.0 s windows, 1 s apart: an idle window and a window that starts one `wl -i wlX scan -t passive -p 110 -c <ch>` and polls `scanresults` to completion (`t3()` in the capture). Off-channel ≈ (idle rate × window − beacons in the call window) / idle rate. 8 reps per channel. Beacons come in groups of 2 (wl0: wl01 + wl02) or 3 (wl1: wl11, wl12, wl13) per 102.4 ms TBTT, so each lost TBTT shows as −2 or −3. Files `t3_wl0_offchannel.txt`, `t3_wl1_offchannel.txt`, `t3_idle_reference.txt`.

| Call | Idle beacons/s | Beacons in call windows (8 reps) | Call latency (start → scanresults ready) | Off-channel, mean (min-max) |
|---|---|---|---|---|
| wl0 `-c 1` | 19.6 | 18 ×7, 17 | 0.14-0.15 s | **119 ms** (101-162) |
| wl0 `-c 6` | 19.4 | 18 ×6, 16 ×2 | 0.14-0.15 s | **125 ms** (92-195) |
| wl1 `-c 36` | 30.0 | 27 ×5, 30 ×2, 24 | 0.14-0.22 s | **145 ms** (91-241) |
| wl1 `-c 149` | 29.1 | 30 ×3, 27 ×3, 24 ×2 | 0.14-0.22 s | **129 ms** (58-224) |

- A call loses one TBTT (beacon interval) most of the time and two in about 1 call in 4. That matches 110 ms dwell + a few ms retune; the §3.2 estimate of 130-140 ms per call holds as a mean.
- wl1 calls sometimes take 0.22 s to report done (vs 0.14 s), and those are the reps that lose two TBTTs. The tail is about 0.24 s, not 0.14 s.
- The 50 ms poll adds up to 50 ms of latency on the home channel; it does not add off-channel time.

**Client side (no drop, but retries).** All four clients stayed associated through every call (`in network` grew by the wall time). But per-client tx retries per MB sent (from `sta_info`, first vs last `AC` of each block; `acd.py` in the scratchpad):

| Window | f0197d79 (wl13, busiest) | 177f5794 (wl13) | 76c0915f (wl12) | 971e1247 (wl02) |
|---|---|---|---|---|
| idle 60 s, no scan | 116/MB (+1.6 MB) | 83/MB | 396/MB | 49/MB |
| 8 × wl0 `-c 1` / `-c 6` (2.4 GHz) | 196 / 240 | 406 / 850 | 120 / 240 | 223 / 323 |
| 8 × wl1 `-c 36` | **2 331/MB, txfail +2** (+2.8 MB) | 253 | 502 | 153 |
| 8 × wl1 `-c 149` | 740 | 1 569 | 957 | 65 |

- The 5 GHz clients' retry rate rose about 5-20× during the wl1 calls, and the busiest one got its first two hard tx failures (`tx failures` 0 → 2) during the `-c 36` block. The 2.4 GHz client (wl02) moved only within its idle noise during wl0 calls (49 → 223-323/MB at very low volume). Earlier, in T2, one `-c 36` call coincided with +3 113 retries for f0197d79.
- Retry rate per MB is a noisy metric at low volume (the wl12 client moves 120-957/MB with little traffic). For the busy client the jump is large and repeated, so it is a real effect: frames queued for a 5 GHz client while the radio is off-channel are retried rather than held.

**Verdict.** **Pass on the mean, marginal on the tail.** Mean off-channel 119-145 ms per call (criterion ≤ 150 ms). Beacons per call are within "expected − 3" on wl0 in 14 of 16 reps (one TBTT = 2 beacons) and on wl1 in 6 of 8 and 6 of 8 reps (one TBTT = 3 beacons; the 2-TBTT reps miss it). Design consequences: budget ~0.25 s worst case per call, not 0.14 s; and on 5 GHz the per-call gap does cost an active client retries and occasional tx failures, which T4 has to look at with real traffic.

---

## T7: `wl bss` and hostapd PING during a scan

**Method.** Start the scan, then loop until `scanresults` is ready, about every 30 ms: `wl -i <vif> bss`, `wl -i wlX isup`, `hostapd_cli -p /var/run/hostapd -i <vif> ping`, `wl -i wlX chanspec`. Three `-c` calls and one full passive 110 ms sweep per radio (vif wl02 on wl0, wl12 on wl1; sweeps 43 s apart). This is TP-Link's hostapd (ctrl dir `/var/run/hostapd`); the agent's own is under `/var/run/udeco-hostapd`, but the question is the same: is a userspace hostapd blocked while the radio is off-channel. File `t7_bss_hostapd_during_scan.txt`.

**Result.** 175 polls in all: **every one** read `bss=up`, `isup=1`, `PONG`. Nothing fails while the radio is off-channel.

**Side finding 1: `wl chanspec` reports the scan channel during a scan.** During `-c 1` it reads `1 (0x1001)`, during `-c 36` `36 (0xd024)`, and during the sweeps it walks through every scanned channel. It reads the home chanspec again only once the radio is back. So:
- Any read of `wl chanspec` while a band runs (collector stats for an inform, bcmwifi checks, §3.4's own "after the band" check if it races the last call) can see a foreign 20 MHz channel. The collector must not publish `channel` from a read taken during SCANNING, and the §3.4 check must run after `scanresults` is ready for the last call (it was correct in every capture once ready).
- It also gives a cheap progress probe if one were needed.

**Side finding 2: the whole-band sweep already returns home every two channels.** Sequence on wl0 (`-t passive -p 110`): home `9u` (~0.1 s, probably the ch9 dwell itself) → 10, 11 → home → 1, 2 → home → 3, 4 → home → 5, 6 → home → 7, 8 → home; each foreign channel about 110-120 ms, each home visit about 30-60 ms. wl1: home → 44, 48 → home → 149, 153 → home → 157, 161 → home → 165, 36 (then done). So the longest off-channel stretch of a sweep is about 0.23-0.25 s (two dwells), **not** 1.25 s as §2.3 / §8.3 assume. What the chunked plan really buys is longer home time between stretches (≥ 400 ms instead of 30-60 ms) and shorter stretches (one dwell instead of two), not a 10× shorter gap.
- This also explains the beacon counts in §2.3 (e4: 6 of 30 beacons sent, i.e. ~20 % home time).

**Verdict.** T7 **passes**: `wl bss` reads `up` and hostapd answers during a scan, so a health check that only uses `bss` and PING would not fail because of a scan. §8.7 can drop the health-check suppression **for that reason**, but keep a reason of its own if any check reads `chanspec` (side finding 1).

---

## T8: `-c <home control channel>`

**Commands.** wl0 `scan -t passive -p 110 -c 9` (home `9u`) and wl1 `-c 40` (home `40/80`): one call with chanim before/after, one with the T7 poll loop, and 8 reps of the T3 beacon windows each. File `t8_home_control.txt`.

| Call | Off-channel (8 reps) | Call latency | `wl chanspec` during | chanim records changed | BSSes |
|---|---|---|---|---|---|
| wl0 `-c 9` | **~0 ms** (20 of 19.5 expected beacons, every rep) | 0.13-0.14 s | `9u (0x1907)` throughout | **none** (0x1009 identical) | 5 |
| wl1 `-c 40` | **~0 ms** (30-33 of 28.8) | 0.13-0.14 s | `40/80 (0xe12a)` throughout | **none** (0xd028 identical) | 6 |

- The radio does not retune; the call just listens on the home channel for the dwell, with beacons and (by the client counters) normal traffic going on. `bss`/PING were fine as in T7.
- It returns the BSSes on the home channel (useful for `P_bss`), but it **does not write a chanim record**, not even for the home control channel. Combined with T2, the home control record is refreshed by **every other** channel's call and never by its own.
- The secondary 20 MHz channels of the home block are ordinary off-channel calls: `-c 36` and `-c 48` showed `chanspec 36`/`48` during the call (T7), lost beacons (T3) and produced a fresh record (T2).

**Verdict.** As expected for time (about 0 ms off), but a design trap for data: under §3.2 step 4 the home control call always finds its record unchanged (stale → missing), retries, and then trips the switch to the fallback sweep, on every band. Fix options: (a) skip the `-c <home control>` call and take the home record from the update that the next (or previous) call writes, judging freshness by "changed since the snapshot before that call"; or (b) keep the call for its BSS list and exempt its record from the freshness rule, then use the record from the following call. Either way the home row carries our own `txdur`/`inbss` (wl0 ch9 `txdur` 6-21 in these records), which §4.1 already excludes.

---

## T5: `cca_get_stats -c 0 -s 5`

**Commands.** `wl -i wlX cca_get_stats -c 0 -s 5` (and `-i` for per-second rows), plus `-c 1 -s 5` on wl0 and `-c 36 -s 5` on wl1. During each call a background loop read `wl chanspec` every ~0.15 s for ~6.5 s; chanim before and after; beacons over the call and over 2 s idle after. Files `t5_wl0_cca_get_stats.txt`, `t5_cca_variants.txt`, `t5_chanim_read_stability.txt`.

**Output** (wl0, `-c 0 -s 5 -i`):
```
chan dur      ibss           obss           interf       time
9   1004   84  8% Low     270 26% High      9  0% Low    4003
9   1004   94  9% Low     302 30% High     10  0% Low    4002
...
Summaries:
9   1004       7% Low         26% High         1% Low    5
Recommended channel: 9
```
wl1 `-c 0 -s 5`: only channel 40, ibss 1-2 %, obss 3-4 %, interf 0 %.

- **It does not measure, it reads history.** The call returns in **20 ms** (not 5 s). The rows are the driver's stored per-second CCA samples (`dur 1004` ms each, `time` = a seconds counter that runs backwards over the last 5 samples). `-s` picks how many past seconds to summarise.
- **Home channel only.** `-c 0` ("all channels") returned only the home control channel (9 / 40): the driver keeps history only where it has been. `-c 1` / `-c 36` return no rows and `Cannot find a good channel due to: Only 1 channel input`, exit 255 (plus `error` on stderr).
- **It does not leave the channel.** `wl chanspec` read the home chanspec at all 180 polls, idle beacon rate right after was normal (40 / 2 s on wl0, 57-60 / 2 s on wl1), and no chanim record changed (before/after identical on both radios).
- **Agreement with chanim on the home channel.** wl0 ch9: cca `ibss` 5-9 %, `obss` 24-30 %, `interf` 0-3 %; the last chanim 0x1009 records from T2 had `txdur` 6-7, `obss` 19-26, `nocat` 4-8. wl1 ch40: cca `ibss` 1-2 %, `obss` 3-4 %; chanim 0xd028 `txdur` 2-6, `obss` 3-9. Same picture, so `ibss` ≈ our own `txdur + inbss` and `obss` ≈ `cca_obss`.
- 120 reads of `chanim_stats all` (40 per radio at 0.25 s plus the before/after reads) were all complete and identical: the list does not flicker between scans.

**Verdict.** **Not a source for other channels.** It cannot measure off-channel, so it cannot replace chanim for the spectrum table, and it does not help with UNII-3. It is useful for something else: clean 1-second home-channel samples of own (`ibss`) and foreign (`obss`) airtime, with `dur` = 1004 ms per row. That makes it a better input for the §8.1 airtime gate than two `chanim_stats us` reads (no `total_tm` step error): `own ≈ mean(ibss %)` over `-s 5`, one call, no wait. [A until it is checked under load.]

**Client note.** The busy 5 GHz client (f0197d79, wl13) disassociated between 4 239 s and 4 304 s and came back at 4 322 s. The last off-channel scan on wl1 had ended at 4 087 s (T7), and only reads ran on wl1 in that window, so this is background churn like the wl13 drop before T1, not caused by a scan. Scanning on wl1 continued, with T4 set to stop on any drop during a run.

---

## Received power: `phy_rxiqest` and `phy_rxiqest_sweep`

**Help text** (live `wl -h` on .205, `trx_wl_help.txt`; same as the saved dump): `phy_rxiqest` "Get phy RX IQ noise in dBm" on the current channel, options `-s` samples (2^n), `-a` antenna, `-r` resolution, `-f`/`-w` filter overrides, `-g` gain correction, `-e` extra init gain, `-i` gain mode, `-n` averaging iterations, `-d` delay. `phy_rxiqest_sweep` is the same "for requested channels" with `-c all|<list>`.

**`phy_rxiqest`, default options, current channel, 5 calls 0.5 s apart per radio** (`trx_rxiqest_default.txt`). Output is one value per active antenna (core).

| Radio (home) | phy_rxiqest per antenna, 5 calls | `wl noise` | chanim current `knoise` | chanim current `chan_util` | Strongest co-channel BSS (T8 scan) |
|---|---|---|---|---|---|
| wl0 (9u) | -102/-100, -105/-103, **-72/-83**, -106/-104, **-78/-81** | -96 | -96 | 39-41 % (obss 22-29) | -51 (sibling Deco, 0x1907); then -52, -58, -62, -63 |
| wl1 (40/80) | -96/-97 ×5 | -96 | -96 | 7-8 % (obss 4) | -72 (sibling Deco); then -84 |

- Each call takes about 10 ms, stays on channel (`chanspec` unchanged, beacons normal: 53 in 2.66 s on wl0, 78 in 2.66 s on wl1), and did nothing visible to clients.
- **It is an instantaneous snapshot, not an in-channel average.** On the quiet 5 GHz home channel it reads the noise floor (-96/-97, equal to `wl noise`). On the busy 2.4 GHz home channel it reads either the floor (-100..-106, a few dB below `wl noise`) or, when a frame happened to be on the air during the short sample, a frame power (-72..-83). 2 of 5 calls hit traffic, which matches the 39-41 % busy time, but the level of a hit is whichever station was sending, not the strongest neighbour (-51) and not a mean power.
- To turn it into a received-power figure would need many samples per channel and a statistic over them (for example a high percentile, or the mean over busy samples). With default options and 5 samples it is neither stable nor comparable with `P_bss`.

**`phy_rxiqest_sweep -c <home>`** (wl0 `-c 9`, wl1 `-c 40`; no other channel was tried, `trx_rxiqest_sweep_home.txt`): **refused on both radios**, exit 233, output `error`, returns in 10 ms. `wl chanspec` stayed home and `bss` up at every 0.12 s poll for 1.4 s; beacons normal; no client effect. Most likely the driver accepts it only with the radio down or in a test mode; this was not pursued (it would need forbidden changes).

**Verdict.** **Neither gives in-channel received power for the spectrum table.** `phy_rxiqest` reads the current channel only, and its default single snapshot is the noise floor or a random frame's power. The sweep variant, the only way to reach other channels, is refused on a live AP even for the home channel. So `interference` stays as designed (§4.2: `max(Nhome, P_bss, N_elev)`), and UNII-3 has no alternative source here. §2.4's "not used" stands, now [M] instead of [D].

**Client note.** Client 177f5794 (wl13) left between 4 313 s and 4 322 s, at the moment f0197d79 re-joined wl13; only reads ran on wl1 then. It looks like one device switching between two MACs, or two devices of one owner; either way not scan-caused.

---

## T4 lite: the §3.2 chunked plan, once per radio

**Plan as written in §3.2.** Passive, 110 ms dwell, one channel per call (`-c <decimal channel>`, see T2), 2 passes (pass 2 reversed), 50 ms `scanresults` poll, `chanim_stats all` after each call, at least 400 ms from "scanresults ready" to the next call, 45 s budget. Guard before every call: every MAC of the radio's user vifs at the start must still be in `assoclist` (no `scanabort` was available under the test rules; a drop would have stopped further calls). Per-client `sta_info` counters before/after, then a scan-free window of the same length as a reference. wl0 at 4 533 s, wl1 at 4 610 s (63 s after wl0 ended). Files `t4_wl0_chunked.txt`, `t4_wl0_idleref.txt`, `t4_wl1_chunked.txt` (its idle window is inside the file). The per-call analysis below is `t4.py` in the scratchpad (rules of §3.2 step 4: OK = target record changed vs the snapshot before the call and not all-zero; STALE = unchanged; ZERO = all-zero placeholder).

**Timing.**

| Band | Calls | Duration | Beacons sent / scan-free equivalent | Off-channel total | Per off-channel call | Design estimate |
|---|---|---|---|---|---|---|
| wl0 (1-11) | 22 | **12.9 s** | 203 / 253 (19.5/s) | ~2.6 s (20 %) | ~128 ms (20 calls; the 2 home calls cost ~0) | 13-15 s, ~3 s off, 23 % |
| wl1 (36-165) | 18 | **11.0 s** | 271 / 321 (29.1/s) | ~1.7 s (16 %) | ~107 ms (16 calls) | 11-12 s |

Calls took 0.13-0.21 s from start to `scanresults` ready. No budget or guard abort. `chanspec` was home again after each band.

**Per-call chanim result.**
- wl0: 20 of 22 calls **OK**. Both ch9 calls (home control) **STALE**: the record is never refreshed by its own call (T8). Every other call also rewrote 0x1009 (T2).
- wl1: 36, 44, 48 **OK** in both passes; 40 (home control) **STALE** in both; all 10 calls on 149-165 **ZERO**. Every non-home call also rewrote 0xd028.
- So, run as written, **both bands would switch to the fallback sweep** (home channel stale), and wl1 would then fail as incomplete (UNII-3).

**Rows the plan would produce** (u = obss + nocat + nopkt per pass → mean; `P_bss` from the merged BSS list with the overlap model and the primary-gets-full-RSSI rule; `Nhome` = `wl noise` at the start):

| wl0 ch | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 (home) | 10 | 11 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| u, pass 1 / 2 | 16 / 19 | 5 / 6 | 10 / 10 | 4 / 5 | 3 / 5 | 19 / 21 | 5 / 6 | 11 / 10 | stale (41 / 44 from the neighbouring calls' rewrite) | 29 / 12 | 9 / 12 |
| u mean | 18 | 6 | 10 | 4 | 4 | 20 | 6 | 10 | - | 20 | 10 |
| P_bss (dBm) | -69 | -59 | -56 | -54 | -53 | -53 | -53 | -53 | -50 | -54 | -56 |
| BSSes with control here | 7 | 1 | 3 | 1 | 0 | 5 | 0 | 0 | 5 | 1 | 1 |

wl1: 36 u 2 / P_bss -78, 44 u 2 / -78, 48 u 4 / -78, 40 (home) stale (u 7-9 in the rewritten record, `txdur` 3-4), P_bss -72 (sibling Deco at -72, spread over 80 MHz → -78 on each part); 149-165 no data, no BSS. 7 BSSes merged on wl1, **24 on wl0** (as many as the 200 ms whole-band sweep e5; two 110 ms passes recover what one pass misses, T2).

- Pass-to-pass agreement is good on quiet channels (±2) and on ch1/ch6 (±3); ch10 moved 29 → 12. The rank 1 / 6 / 11 is 18 / 20 / 10 here; in e5 it was 30 / 28 / 13. One run cannot settle T9 (repeatability).
- The wl0 `interference` column is again set by the sibling Decos (-50..-56 on 3-11), as the design's VERIFIER notes say.

**Clients.** Every start-set client stayed associated with growing `in network` on both bands; nobody dropped during or after either band.

| Window | wl02 client (971e1247, 2.4) | wl12 client (76c0915f, 5) | wl13 client (f0197d79, 5, the busy one) |
|---|---|---|---|
| wl0 band, 12.9 s | +18.8 kB tx, +6.9 kB rx, retry +5, txfail 0 | (other radio) | (other radio) |
| wl0 scan-free 13 s | +27.7 kB, +5.6 kB, retry +6, txfail 0 | | |
| wl1 band, 11.0 s | (other radio) | +37.1 kB tx, +1.5 kB rx, retry +10 (269/MB), txfail 0 | **+700.7 kB tx**, +61.4 kB rx, retry +188 (268/MB), txfail 0 |
| wl1 scan-free 11 s | | +69.3 kB, +3.4 kB, retry +38 (549/MB) | +66.6 kB, +0.7 kB, retry +5 (75/MB) |

- The busy 5 GHz client moved 10× more data during the band than in the scan-free window right after, and kept its retry rate near the T3 idle level (116/MB) rather than the 740-2 331/MB seen in T3. With 400 ms home gaps the plan cost it retries but no hard failures. This is one run, with whatever traffic the clients happened to carry; no voice/video call or controlled stream was available, so the "video glitch" criterion of T4 and the §4.1 ch5-8 hypothesis remain untested.

**Verdict.** **Timing and client impact pass** for this run: 12.9 s / 11.0 s inside the 13-15 / 11-12 s estimates, 107-128 ms per off-channel call, ~16-20 % duty, no drop, no tx failure. **Data does not pass as designed**: the home control channel is always stale under the step-4 rule (needs the T8 fix), and UNII-3 is always zero (needs a 5 GHz design decision, T1/T2). With those two fixes the plan yields complete 2.4 GHz rows and 36-48 rows (20 MHz, and the 40 MHz blocks 36 and 44; the 80 MHz block 36 too), all from fresh records.

---

## Summary for the design

| Test | Result | Change needed in `spectrum-design.md` |
|---|---|---|
| T1 | 36-48 filled and fresh on every 5 GHz sweep; **149-165 always all-zero** | §2.1 / §13: 5 GHz is half measurable on this unit. Decide what to emit for the 149 block (omit rows or abnormal band). Keep the zero rule; freshness alone accepts a placeholder whose noise moved by 1 dB. |
| T2 | `-c` needs a decimal channel (`-c 0x1001` is rejected, exit 254). A call refreshes the target **and the home control record** | §3.2 step 2 and the call-sequence test: use `-c 1`, not `-c 0x1001`. Step 4 must look only at the target record. |
| T3 | 119-145 ms off per call (mean), up to ~0.24 s; on 5 GHz an active client's retries rise 5-20× during back-to-back calls | Budget ~0.25 s worst case per call. |
| T7 | `bss` up, `isup` 1, hostapd PONG at every poll. **`wl chanspec` reports the scan channel during a scan**; a whole-band sweep returns home after every 2 channels | §8.7: the health check would not fail on `bss`/PING; do not read `chanspec` for informs or checks while SCANNING. §2.3 / §8.3: a sweep's longest off stretch is ~0.25 s, not ~1.25 s. |
| T8 | `-c <home control>`: ~0 ms off, returns BSSes, **writes no chanim record** | §3.2: skip or exempt the home control call; take its record from the rewrite done by the other calls. Otherwise the fallback fires on every band. |
| T5 | `cca_get_stats` reads stored 1 s samples of the current channel only; instant; `-c <other>` fails | Not an off-channel source. Candidate input for the §8.1 airtime gate instead of `chanim_stats us`. |
| rxiqest | `phy_rxiqest` = one instantaneous snapshot (noise floor or a random frame's level); `phy_rxiqest_sweep -c <home>` refused (exit 233) | No received-power source; §4.2 stays as designed. |
| T4 lite | 12.9 s / 11.0 s, 16-20 % off duty, no drop, no tx failure | Timing estimates hold. Video/voice and T9 repeatability still open. |
