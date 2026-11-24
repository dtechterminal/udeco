# Deco spectrum_table design (quick-scan and spectrum-scan)

**Goal.** `udeco-ap` on a Deco X20 V2 answers the controller's nightly `cmd quick-scan` (per band, per width) and the manual `cmd spectrum-scan` with a `spectrum_table` that ranks channels the way the radio really sees them. The table must be good enough for UniFi's channel optimiser ("Optimize Network" / Channel AI).

**Status.** Design only. No device was touched and no Go code was changed while writing this; another workflow is editing `~/udeco` at the same time. Section 12 lists the device tests that must pass before the code relies on the unmeasured parts.
REV2: T1, T2, T3, T5, T7, T8 and a lite T4 have now run (§12 has the status of each). T6 (acsd2 stopped), T9 (repeatability), the voice/video part of T4 and the new T10 (is UNII-3 deaf or empty?) are still open. Still no Go code changed.

**VERIFIER: review of 2026-11-18 (adversarial pass, documents and saved captures only, no device touched).** Verdict: the overall shape (passive only, leave out `txdur`/`inbss`, power-like `interference`, keep the old table on failure) holds. Several claims were wrong or overstated and four design gaps needed fixing. Each change below is marked `VERIFIER:`. In short:
- **Stale chanim records are the likely failure, not missing ones.** Records persist and acsd2 can leave all 11 (repo fixture `internal/wl/testdata/wl_-i_wl0_chanim_stats_all.txt`). Read as written, §3.2 would accept an old record as this call's measurement and would never switch to the fallback. Fixed in §3.2 step 4.
- **All-zero records** (`crsglitch 0`, `bad plcp 0`, every cca field 0) exist in the repo's wl1 fixture for 149-165. Taken at face value they make a channel look perfectly clean. Such a record now counts as missing (§3.2).
- **5 GHz is not "entirely unmeasured".** The repo already holds a wl1 `chanim_stats all` with 9 records, 0xd024..0xd0a5 (§2.1).
- **Utilisation spread is far wider than "±10 points".** Home ch9 reads 24-76 % across six passive runs (§2.2). Two passes of 110 ms give about 0.22 s per channel, against about 2 s per channel on the U6 Pro. See the recommendation in §3.2.
- **The airtime gate's denominator was wrong.** `total_tm` steps by about 1.004 s, so a 2 s window has a ±50 % error. The gate now divides by wall time (§8.1).
- **Client-impact evidence is thinner than stated.** Only one client (on wl02) was on the scanned radio, and no 5 GHz client was ever exposed to a scan (§2.3).
- **The 2.4 GHz `interference` column is set mostly by our own mesh siblings** (two Deco BSSes on 0x1907 at -50 and -63). It is compressed into -52..-63 (§2.2, §4.2).

**REV2: revision of 2026-11-18 after the §12 device tests** (`docs/deco/spectrum-measurements.md`, captures in `internal/wl/testdata/spectrum/`; T1, T2, T3, T5, T7, T8, received power, T4 lite on .205, both radios). Rule for this pass: where a measurement contradicts the design, the design changes. Each change is marked `REV2:`. In short:
- **Scan shape is now chosen from evidence: chunked `-c` on both bands** (§3.2). It works on 2.4 GHz and 36-48 [M T2, T4], costs 16-20 % off-channel duty in ≤ 0.25 s stretches with no drop and no tx failure in one run per band [M T4]. The whole-band sweep stays as a fallback only, now at `-p 110` (§3.3).
- **`-c` takes a decimal channel** (`-c 1`, `-c 36`). Hex (`-c 0x1001`) is rejected with exit 254 and scans nothing [M T2]. The old §3.2 step 2 and `TestMeasureSpectrumChunked` were wrong.
- **The home control channel has no record of its own.** `-c <home control>` stays on channel and writes nothing, while every off-channel call rewrites the home control record [M T2, T8]. As written, §3.2 step 4 judged it stale and switched to the fallback on every band. The home control channel's `utilization` now comes from those rewrites (§3.2, §4.1). The call itself is kept, for its BSS list.
- **5 GHz is half measurable on this unit.** 36-48 fill and refresh. **149-165 never do**, by sweep or by `-c`, even though the radio tunes there [M T1, T2, T4, T7]. They are now an explicit *unmeasured* class: no row for them or for any block that contains them, and no fallback trip. On .205 the 5 GHz table is 36, 40, 44, 48 / 36, 44 / 36 at 20 / 40 / 80 MHz (§5, §6).
- **`interference` keeps the scanresults-RSSI formula.** `phy_rxiqest` is a single instantaneous snapshot (noise floor or whichever frame is on the air), and `phy_rxiqest_sweep` is refused on a live AP [M]. The two VERIFIER refinements (primary channel gets the full beacon RSSI; `N_elev` relative to the band's chanim baseline) are now adopted, and `N_elev` never applies to the home control channel (§4.2).
- **A whole-band sweep returns home after every two channels**, so its longest off-channel stretch is about 0.25 s, not 1.25-2.2 s [M T7]. §2.3, §3.3 and §8.3 are corrected.
- **`wl chanspec` reports the scan channel during a scan** [M T7]. The collector must not publish `channel` from a read taken while a band runs (§8.7, §11.1).
- **`wl bss` and hostapd PING are unaffected by a scan** [M T7]. The health check no longer needs to be suppressed for that reason, only serialised (§8.7).
- **`cca_get_stats -c 0 -s N`** reads stored 1 s home-channel samples in about 20 ms and never leaves the channel [M T5]. It replaces the two `chanim_stats us` reads in the airtime gate (§8.1).
- What is still assumed is listed in §13.1.

**Labels.** Every claim carries one of these:
- **[M]** measured on a Deco (.205, 2026-11-18), with the capture named. REV2: since the §12 tests this covers both radios. `[M Tn]` cites `spectrum-measurements.md` and the `t*` captures.
- **[D]** documented: `wl -h` help text, U6 Pro captures, existing code or `spectrum-controller-expectations.md` (cited as **CE §n**).
- **[A]** assumed: a design choice or an inference that has not been tested.

**Sources.**
- Controller side: `docs/deco/spectrum-controller-expectations.md` (CE). It is built on `docs/reference/u6pro/study-actions-scans.md` and the `actions-scans/` captures.
- Device side: 7 saved 2.4 GHz sweeps on .205. They live in the session scratchpad `/private/tmp/claude-501/-private-tmp/98c08704-0f7d-42d1-8ad0-d700c555e21a/scratchpad/spec/raw/` (`e1.txt` .. `e7_wl0_passive_p50_r2.txt`), with SSIDs hashed and vendor IEs dropped. The `wl -h` dump is in `.../scratchpad/wl-h.txt`. The per-field model used for the worked numbers below is `.../scratchpad/spec/design/model.py`. These files must be copied into `internal/wl/testdata/spectrum/` (§11.4), because the scratchpad can be wiped.
  - REV2: done. The e1-e7 files are now in `internal/wl/testdata/spectrum/` next to the `t*` captures, and that folder's `README.md` describes every file and line format.
- REV2: device tests: `docs/deco/spectrum-measurements.md` (one section per test) and the `t0`..`t8`, `trx_*`, `t_final_state` captures in `internal/wl/testdata/spectrum/`.
- Code: `internal/wl/scan.go`, `parse.go` (`parseChanimAll`), `survey.go`, `collect.go`, upstream's `openwrt/scan.go` (`Spectrum`, `SpectrumRows`), `cmd/udeco-ap/scan.go`, `actions.go`, `wifi.go`.

---

## 1. Decisions at a glance

| Topic | Decision | Label |
|---|---|---|
| Measurement source | `wl -i wlX scan -t passive` followed by `wl -i wlX chanim_stats all` ("Stats during last scan"), one 20 MHz record per scanned channel | [M] on 2.4 GHz. REV2: [M] on 5 GHz for 36-48 (T1, T2); 149-165 **cannot be measured** this way on .205 (T1, T2, T4) |
| Scan type | **Passive only.** Active scans inflate `cca_txdur` and `cca_inbss` on foreign channels. | [M] |
| Shape | ~~Chunked … Fallback: whole-band passive sweep at `-p 50`.~~ REV2: **Chunked on both bands**: one channel per `wl scan -t passive -p 110 -c <decimal channel>` call, ≥ 400 ms home between calls, 2 passes (pass 2 reversed, skipping unmeasured channels). The home control channel's call is kept for its BSS list; its record comes from the rewrites by the other calls. Fallback (only if `-c` is unusable): whole-band passive sweep at `-p 110`. | REV2: chunked [M] (T2, T3, T4); sweep shape [M] (T1, T7); 400 ms / 2 passes [A] |
| `utilization` | `cca_obss + cca_nocat + cca_nopkt` (our own `txdur`/`inbss` left out), mean over passes; a block takes the **max** of its 20 MHz parts. REV2: the home control channel uses the mean over the home-record rewrites of the band. | [A] formula from [M] fields; REV2: home rewrites [M] (T2, T4) |
| `interference` | `max(home noise floor, strongest neighbour power falling inside the channel, persistently raised chanim noise)` in dBm; a block takes the max of its parts. REV2: settled on scanresults RSSI; `phy_rxiqest` rejected; primary-channel rule and chanim-baseline `N_elev` adopted (§4.2). | [A] formula; ranges [M]/[D]; REV2: rxiqest rejection [M] |
| `interference_type`, `other_bss_count`, `perf_index`, `total_samples` | `[]`, 0, 0, 0, as the real AP sends on the nightly path | [D] CE §3 |
| Rows | Only chanspecs the radio lists at the requested width (`wl chanspecs`, country-aware). Channels the radio cannot use are **omitted**. REV2: channels the radio lists but cannot measure (every record all-zero, e.g. 149-165 on .205) are omitted too, with every block that contains one. | [D] real AP; omission [A]; REV2: unmeasurable set [M] |
| Width | Requested `scan-bw`, clamped to the widest the radio has (X20 V2: 80 on 5 GHz, 40 on 2.4 GHz) | [A] (CE §11 Q3) |
| Status | `quickscan_scanning: true` only while a quick-scan runs (absent otherwise). `spectrum_scanning` true only during a manual scan. Per radio: `spectrum_scanning_abnormal`, `spectrum_table_time` = age in seconds. | [D]/[A] |
| Failure | Keep the old table and its growing age, and set `abnormal`. Never send a fresh empty table. | [D] CE §6 |
| Safeguards | Defer while our own airtime is above 30 %. Abort the band if a client drops. Skip a radio that carries a wireless uplink. One radio at a time. `scanabort` on cancel. REV2: own airtime from `cca_get_stats -c 0 -s 5`; no `wl chanspec` read is published while a band runs. | [A]; REV2: inputs [M] (T5, T7) |
| Storage | In memory, mirrored to `/tmp/udeco/rftable_<radio>.json` (≤ 4 kB each, atomic rename, stamped with boot ID and uptime). Nothing on flash. | [A] |
| Modes | Takeover: scan. Observe: no scans. An opt-in `observe_scans` for testing was planned, since acsd2 coexists but loses its chanim records; it was never built (the agent's config has no such key and refuses it as unknown). | [M]/[A]; REV2: chanim with acsd2 **stopped** still untested (T6) |

---

## 2. Evidence base

### 2.1 What a host scan leaves in `chanim_stats all` [M]

- Every saved sweep (e1-e7, wl0, home chanspec `9u` = 0x1907, 40 MHz, control 9) left exactly **11 records, 0x1001-0x100b**, one per 20 MHz channel 1-11. Each record has `crsglitch`, `bad plcp`, `noise` (dBm) and `cca_txdur/inbss/obss/nocat/nopkt` (%).
- **A scan replaces the list.** Before any scan only channels 1-5 and 8 were listed (left by acsd2). After the first host scan, all 11 were there.
- The records **persist**: polling every 5 s for 60 s gave an unchanged md5 while acsd2 was running.
- **Discrepancy.** The measurement report says the first passive scan (e1) left the list empty. But the cleaned `raw/e1.txt` in the scratchpad holds 11 records (ch1 noise -70, ch9 obss 62). The report also counts 8 sweeps, while only 7 files exist. So the empty-list case is **not confirmed by the files**. The design still treats an empty or short list as "no data, retry" (§3.3), because that costs nothing.
- **5 GHz is unmeasured.** wl1's list was empty ("version: 3", no records) before any scan [M]. Whether a 5 GHz host scan fills it is unknown (§12 T1). REV2: superseded; see the REV2 bullets at the end of this section.
  - VERIFIER: overstated. The repo fixture `internal/wl/testdata/wl_-i_wl1_chanim_stats_all.txt` (a Deco, X20 channel set) holds **9 records, 0xd024..0xd0a5, one per 20 MHz channel, with cca fields**. So the driver does fill wl1 "last scan" records, at least from acsd2's scans. What is still unknown is whether **our** host scan fills them (T1).
  - In that fixture, 0xd095..0xd0a5 (149-165) have `crsglitch 0`, `bad plcp 0` and every cca field 0, with noise -100/-101. Every measured record seen anywhere has crsglitch ≥ 36, so these are most likely placeholders, not measurements [A]. If they were used as data, UNII-3 would look 0 % busy, which is the "every channel looks clean" failure. §3.2 step 4 now treats such records as missing.
- VERIFIER: "before any scan only channels 1-5 and 8 were listed" describes .205 at one moment. The repo fixture `wl_-i_wl0_chanim_stats_all.txt` shows acsd2 leaving **all 11** records. Together with the persistence above, this means a full set of **old** records is the normal state. "No record" is the unusual case.
- REV2: measured results on both radios [M, `spectrum-measurements.md`]:
  - **Persistence confirmed again.** At the start of the session wl0 still held e7's 11 records from about 1 400 s earlier, unchanged; acsd2 had not rescanned (`t0_baseline.txt`). 120 reads of `chanim_stats all` without a scan were all identical (`t5_chanim_read_stability.txt`): the list does not flicker.
  - **5 GHz, 36-48: [M].** wl1's list was empty (`version: 3` only). Our wl1 host sweep created 9 records, one per 20 MHz chanspec 0xd024..0xd0a5, no 80 MHz records. 36-48 were fresh on all 3 runs, crsglitch 25-454 (T1).
  - **5 GHz, 149-165: unmeasurable on .205 [M].** Every sweep (T1 ×3, the T7 sweep) and every `-c` call on them (T2: 149 ×2, 153-165 ×1; T4: 10 calls) left crsglitch 0, bad plcp 0, every cca field 0, noise -100/-101. The radio does tune there (`wl chanspec` read 0xd095..0xd0a5 during the T7 sweep; 0 of about 4 expected beacons during a `-c 149` call). One call left a near-empty record (149: glitch 8, nopkt 1, noise -99) that went back to all-zero on the next call. No BSS was ever found on 149-165 in any scan. **Whether the receiver is deaf there or the band is empty is unknown** (new T10, §12). So neither the chanim fields nor the absence of BSSes may be read as "clean".
  - **A placeholder can look fresh.** In T1 r2 and T4, 0xd0a1's placeholder noise moved -100 → -101, so the record "changed" against the snapshot. The freshness rule alone accepts it; the zero rule catches it. Both rules stay (§3.2).
  - **A `-c` call writes two records**: the target and the **home control channel's** (0x1009 on wl0, 0xd028 on wl1), never any other [M T2, T4: every one of 20 + 16 off-channel calls].
  - **`-c <home control>` writes nothing**, not even the home record [M T8]. The home control channel's record is refreshed by every other channel's call and never by its own.

### 2.2 Per-channel values: two runs of the same kind [M]

Passive 200 ms (`e5`) and passive default dwell (`e6`), both about 2.5 s per sweep. `old` is what the current code reports (`txdur+inbss+obss+nocat+nopkt`). `new` is §4.1. "noise" is chanim noise. "P_bss" is the strongest neighbour power falling into the channel (§4.2). Home noise floor is `wl noise` = -97 [M]. Computed by `design/model.py`.

| ch | e5 old | e5 new | e6 new | e5 noise | e6 noise | e5 P_bss | e5 interference | BSS with control on ch (e5) |
|---|---|---|---|---|---|---|---|---|
| 1 | 30 | 30 | 25 | -108 | -105 | -65 | **-65** | 9 |
| 2 | 7 | 7 | 9 | -108 | -96 | -59 | -59 | 0 |
| 3 | 6 | 6 | 9 | -105 | -101 | -56 | -56 | 1 |
| 4 | 8 | 8 | 11 | -108 | -105 | -54 | -54 | 1 |
| 5 | 3 | 3 | 3 | -108 | -108 | -53 | -53 | 0 |
| 6 | 28 | 28 | 31 | -104 | -106 | -53 | -53 | 6 |
| 7 | 9 | 9 | 6 | -96 | -77 | -53 | -53 | 0 |
| 8 | 30 | 28 | 15 | -93 | -76 | -53 | -53 | 0 |
| 9 (home) | **88** | **29** | 44 | -71 | -75 | -53 | -53 | 5 |
| 10 | 10 | 10 | 15 | -108 | -72 | -54 | -54 | 1 |
| 11 | 13 | 13 | 18 | -85 | -76 | -56 | -56 | 1 |

What the data shows:
- **Utilisation is usable.** In passive runs (p50, p110, p200, default) quiet channels 2-5 stay at 3-11 % and busy channels 1, 6 and 9 at 22-48 %. Across runs the busy channels move by about ±10 points [M]. The U6 Pro reported 26-54 % on 2.4 GHz [D CE §3].
  - VERIFIER: refuted as stated, because it leaves out e1 (passive, default dwell, 11 valid records).
    - With the new formula across the six passive runs (e1, e3, e4, e5, e6, e7): ch9 = 76, 29, 48, 29, 44, 24 (**24-76**); ch8 = 10, 18, 11, 28, 15, 6; ch5 = 6, 8, 5, 3, 3, 13; ch3 = 2 in e7.
    - So the site range is **2-76 %**, and the busiest channel swings by about ±26 points between single sweeps. That is bursty neighbour traffic (ch9 `obss` 12-62) measured over about 0.2 s.
    - The U6 Pro range is from another site and RF. It does not support or calibrate these numbers. Note too that its *floor* is 26 % on every 2.4 GHz channel, against our 3 %. If the controller has absolute thresholds tuned on QCA values, our rows will read much cleaner than a real AP's [A].
- **The home record includes our own airtime.** e5 ch9: `txdur 58` makes the old sum 88. The new formula gives 29 [M].
- **Active scans are unusable for utilisation.** e2 (active, 20 ms) shows `txdur 12-19` on every channel (our probes) and `inbss 28-39` on foreign channels 1, 6, 10 and 11 [M].
  - VERIFIER: small correction. e2 `txdur` is 12-19 on every channel **except home ch9 (1)**. `inbss` is 28, 10, 29, 15, 39 on ch1, 4, 6, 10, 11. Those are probe responses addressed to us. The conclusion stands.
- **Chanim noise is not a floor.** It jumps 20-35 dB between runs on busy channels: ch7 -96/-77/-105/-108, ch9 -71/-75/-66/-105/-101 [M]. Values like -108 are below the thermal floor of a 20 MHz channel, so the driver's estimate has an offset as well [A]. It cannot be used as `interference` directly. That is the current bug (CE §10).
- **One strong 40 MHz neighbour dominates.** At -50 dBm on 0x1907 (the same chanspec as .205's own radio, so probably a mesh sibling [A]), it spreads -53 dBm into each of channels 5-9. That lands the 2.4 GHz `interference` values in -53..-65 here, which matches the shape of the U6 Pro's -50..-64 [D CE §3].
  - VERIFIER: the sibling reading is supported by the captures.
    - Four BSSes on 0x1907 share one BSSID prefix: AA:A7:B9:3E:15:F8 / :26:FF at -50, and :27:90 / :27:97 at -63. Each pair is one SSID (hash `h:853695ed`) plus one hidden SSID, which matches the Deco client + dwds-backhaul vif pair. That makes **two** sibling Decos.
    - With siblings included, e5+e6 give ch1..11 = -63, -58, -55, -53, -52, -52, -52, -52, -52, -53, -55. Without them: -63, -64, -66, -64, -63, -63, -63, -63, -62, -60, -59.
    - So 10 of 11 channels sit within 6 dB of each other, and that level is set by our own network. The "shape matches the U6 Pro" argument is circumstantial: it is a different site, and the U6 Pro's values cannot be traced to any neighbour (CE §3).
- REV2: the chunked plan's own rows (T4 lite, one run, `t4_wl0_chunked.txt`, `t4_wl1_chunked.txt`) [M]:

  | wl0 ch | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 (home) | 10 | 11 |
  |---|---|---|---|---|---|---|---|---|---|---|---|
  | u pass 1 / 2 | 16 / 19 | 5 / 6 | 10 / 10 | 4 / 5 | 3 / 5 | 19 / 21 | 5 / 6 | 11 / 10 | 20 home rewrites: 24-44, mean 30 | 29 / 12 | 9 / 12 |
  | u (Go `math.Round`) | 18 | 6 | 10 | 5 | 4 | 20 | 6 | 11 | 30 | 21 | 11 |
  | P_bss (primary rule) | -69 | -59 | -56 | -54 | -53 | -53 | -53 | -53 | -50 | -54 | -56 |

  - The measurements file's T4 table shows ch4 / 8 / 10 / 11 as 4 / 10 / 20 / 10 because its script rounds halves to even; the agent uses `math.Round` (half away from zero), so the values above are what the code must produce.
  - wl1: 36 / 44 / 48 u = 2 / 2 / 4 (pass-to-pass ±1); home 40 from 16 rewrites u = 5-12, mean 8; `P_bss` -78 on 36/44/48 and -72 on 40 (sibling Deco on 0xe12a at -72, primary 40). 149-165: no data.
  - Pass-to-pass spread on wl0: ±1-3 on 9 of 10 off-channel channels, **17 points on ch10** (29 → 12). The home rewrites alone span 24-44 within 13 s. The rank of 1 / 6 / 11 was 18 / 20 / 10 here against 30 / 28 / 13 in e5. Repeatability (T9) is still untested.
  - Home control on wl0 cross-checks with two independent home-channel reads taken about 4 min apart: `chanim_stats` (current, 0x1907) obss + nocat + nopkt = 36 / 41, and `cca_get_stats` obss 24-30 % + interf 0-3 % (`trx_rxiqest_default.txt`, `t5_cca_variants.txt`) [M]. Same picture, different windows.
  - 5 GHz utilisation at this site is **1-12 %** on every measurable channel [M]; the U6 Pro's 2-48 % is from another site [D].

### 2.3 Timing and client impact on 2.4 GHz [M]

Off-channel share comes from beacon counting. At idle wl0 sends 19.2 beacons/s.

| Run | Sweep | Beacons sent / expected | Off-channel | BSSes found |
|---|---|---|---|---|
| active 20 ms (e2) | 0.39 s | 2 / 7.5 | ~0.3 s | 12 |
| passive 50 ms (e3, e7) | 0.75-0.76 s | 4-6 / 14.5 | ~0.5-0.6 s | 11-13 |
| passive 110 ms (e4) | 1.56 s | 6 / 30 | ~1.25 s (80 %) | 18 |
| passive 200 ms (e5) | 2.54 s | 8 / 48 | ~2.2 s (85 %) | 24 |
| passive default (e1, e6) | 2.50-2.52 s | 6 / 48 | ~2.2 s | 20 |

- Per-channel overhead beyond the dwell is about 20-30 ms: (1.56 − 11×0.110)/11 ≈ 32 ms and (0.75 − 11×0.050)/11 ≈ 18 ms [M, derived].
- A sweep does **not** spend `scan_home_time` (45 ms) between every channel. At 200 ms only about 0.3 s of 2.5 s was on the home channel [M].
- **No client dropped.** The clients on wl02, wl12 and wl13 kept increasing their in-network counters across all sweeps [M].
  - VERIFIER: weaker than it reads.
    - All sweeps were on **wl0**. wl12 and wl13 are 5 GHz vifs on wl1, which was never scanned. Only **one** client (OUI F4:CF:A2, on wl02) was exposed, and nothing shows it was passing traffic.
    - "in network" is association age. It proves the client stayed associated, not that no frames were lost.
    - There is **no** 5 GHz client-impact evidence at all. T4 must cover wl1 before 5 GHz scans are enabled.
- A 2.2 s mostly-off-channel stretch would probably glitch a live 2.4 GHz call [A, not tested]. That is why §3 splits the scan into short calls.
  - REV2: the premise is wrong [M T7]. A whole-band sweep is **not** one stretch. It returns home after every two channels (wl0 at `-p 110`: home → 10, 11 → home → 1, 2 → home → … ; wl1: home → 44, 48 → home → 149, 153 → …), with each foreign channel about 110-120 ms and each home visit about 30-60 ms. The longest off-channel stretch of a sweep is about **0.23-0.25 s**. What a sweep does have is about 80 % off-channel duty for its 1.3-2.5 s, with home visits too short for much traffic (e4: 6 of 30 beacons sent). The chunked plan's advantage is therefore **duty** (16-20 % against about 80 %) and **home time between stretches** (≥ 400 ms against 30-60 ms), plus one dwell per stretch instead of two. It is not a 10× shorter gap.
- REV2: single-channel `-c` calls, beacon counting over fixed 1 s windows, 8 reps each [M T3]:

  | Call | Off-channel, mean (min-max) | Call latency (start → scanresults ready) |
  |---|---|---|
  | wl0 `-c 1` / `-c 6` | 119 / 125 ms (92-195) | 0.14-0.15 s |
  | wl1 `-c 36` / `-c 149` | 145 / 129 ms (58-241) | 0.14-0.22 s |
  | wl0 `-c 9`, wl1 `-c 40` (home control, T8) | ~0 ms (no beacon lost in 8 reps) | 0.13-0.14 s |

  - A call loses one beacon interval most of the time and two in about 1 call in 4 on wl1 (the 0.22 s calls). Budget **0.25 s worst case per call**, 0.13 s mean.
  - In the T4 plan, the measured average was 128 ms (wl0) and 107 ms (wl1) per off-channel call; totals 12.9 s / 11.0 s per band, 2.6 s / 1.7 s off-channel (20 % / 16 %) [M T4].
- REV2: 5 GHz client impact now has evidence [M T3, T4]:
  - No client dropped in any test. Two 5 GHz clients disassociated during the session only while no scan was running on wl1 (one 150-220 s after the last off-channel wl1 call, the other while only reads ran); treated as background churn.
  - Back-to-back `-c` calls on wl1 (T3, 16 calls) raised the busiest 5 GHz client's tx retries 5-20× above idle (2 331/MB) and produced its first **2 hard tx failures**. The 2.4 GHz client stayed inside its idle noise at very low traffic.
  - The §3.2 plan on wl1 (T4, 18 calls) cost the busy client 268 retries/MB against 75/MB in the scan-free window right after, with **no tx failure**, while it moved 700 kB.
  - T3's calls were about 2 s apart, longer than T4's 400 ms gap, and still did worse. So the difference is **not** evidence that 400 ms is enough or that longer gaps help; it is most likely the traffic mix. What is measured is that **each 5 GHz off-channel call can cost an active client retries and occasionally a failed frame**. The design therefore minimises the number of off-channel calls (§3.2: no pass-2 calls on unmeasured channels).
  - Not tested: voice or video, a controlled stream, more than one run.
- Discovery depends on dwell: 11-13 BSSes at 50 ms against 24 at 200 ms [M]. A 50 ms dwell is shorter than the 102.4 ms beacon interval, so it misses about half of the beacons [A]. That matters for the `interference` term (§4.2), so the chunked plan uses 110 ms.
  - VERIFIER: from the union of 28 BSSes over e3-e7, the strongest BSS each sweep missed was: e4 (110 ms, 18 found) -78; e5 (200 ms) -85; e6 (default) -84; e3 and e7 (50 ms) **-63 and -68** (the BSSes that set ch1's and ch6's `P_bss`).
    - So 110 ms does **not** catch every beacon (deferred or collided beacons). It does catch the strong ones that decide `interference`.
    - At 50 ms it misses those, so the fallback sweep's `interference` can be 5-10 dB too low on a channel with a single strong neighbour.
- VERIFIER: the "per-channel overhead 20-30 ms" counts home-channel time as overhead. In e4 about 6 beacons (≈ 0.31 s) were sent during the 1.56 s sweep, so the real retune cost is about (1.25 − 1.21)/11 ≈ 4 ms per channel. The 130-140 ms per-call estimate in §3.2 is therefore conservative, not wrong.

### 2.4 Other `wl` facts used here

- `wl scan` / `escan` options: `-t passive`, `-p N` passive dwell, `-a N` active dwell, `-h N` home dwell, `-c L` chanspec list. `scanabort` / `escanabort` exist [D wl -h:560-600].
- `cca_get_stats [-c ch|0] [-s secs ≤ 60] [-i] [-n] [-curband]` [D wl -h:1248]. Not used in the main path; untested (§12 T5).
  - REV2 [M T5]: it **reads history, it does not measure**. It returns in about 20 ms with the driver's stored per-second samples (`dur 1004` ms each) for the **home control channel only** (`-c 0` lists only ch9 / ch40). `-c <other>` fails with exit 255 ("Only 1 channel input"). It never leaves the channel (180 `chanspec` polls at home, beacons normal, chanim unchanged). Its `ibss` (5-9 % on wl0) matches chanim `txdur + inbss` and its `obss` (24-30 %) matches `cca_obss`. Not a spectrum source; used for the airtime gate (§8.1).
- `phy_rxiqest` reads RX IQ noise power on the current channel. `phy_rxiqest_sweep -c all|list` retunes the PHY outside the scan engine [D wl -h:2190-2225]. **Not used**: `wl noise` is stable enough for the floor (-97 wl0, -95 wl1) [M]. The sweep variant is an unmanaged channel change.
  - REV2 [M, `trx_rxiqest_default.txt`, `trx_rxiqest_sweep_home.txt`]: "not used" is now measured, not only argued.
    - `phy_rxiqest` (default options, ×5 per radio, 10 ms each, stays on channel) returns **one instantaneous value per antenna**: on quiet wl1 -96/-97 every time (= `wl noise`); on busy wl0 either the floor (-100..-106) or whatever frame was on the air (-72..-83, 2 of 5 calls, about the 39-41 % busy share). A hit's level is that frame's sender, not the strongest neighbour (-51) and not a mean. It is not an in-channel received-power measurement and only covers the current channel.
    - `phy_rxiqest_sweep -c 9` (wl0) and `-c 40` (wl1), home channel only: **refused**, exit 233 `error`, no retune. No other channel was tried (the rules forbade it).
  - REV2: `wl noise` is not constant: wl0 read -97, -96, **-93** (T4 start) and -93 (final) within 20 min; wl1 -95/-96 [M `HDR` lines]. Read it once per band (§3.1), as designed.
- REV2: `wl chanspec` **reports the scan channel while a scan runs** (`1 (0x1001)` during `-c 1`; every channel in turn during a sweep) and the home chanspec again once `scanresults` is ready [M T7].
- REV2: `wl bss` (every user vif), `wl isup` and hostapd `PING` answered `up` / `1` / `PONG` at all 175 polls taken during `-c` calls and sweeps on both radios [M T7].
- REV2: `wl scan -c` takes channel numbers or chanspec strings (`1`, `36`), **not hex chanspecs**: `-c 0x1001` gives `could not parse chanspec`, exit 254, nothing scanned [M T2]. Only plain 20 MHz channel numbers were tried.
- REV2: `chanim_stats` without `all` returns the **current** home chanspec's interval stats (`tx inbss obss nocat nopkt … knoise idle`, plus `chan_util`) [M `trx_rxiqest_default.txt`]. Not used; noted as a cross-check (§2.2).
- `assoclist` ("AP only: Get the list of associated MAC addresses") [D wl -h:3325]. `dfs_status` [D wl -h:844].
- `chanim_mode` is `external (acsd)` and interference mitigation is 361 on both radios [M]. `wl help <cmd>` fails; use `wl -h` [M].
- The OpenWrt path already scans one channel per step "about 0.1 s away, then 1 s back on its channel" (`upstream's openwrt/scan.go:62-66`) [D]. The chunked plan follows the same principle.

---

## 3. Command sequence per band

### 3.1 Inputs, read once per band

All reads, no changes:
1. `wl -i wlX chanspec` gives the home chanspec, to restore and compare later (`collect.go` already parses it) [D]. REV2: also gives the **home control channel** `c_h` (9 for `9u`, 40 for `40/80`), which §3.2 treats specially. Read it before the first call, never during one (§2.4) [M T7].
2. `wl -i wlX noise` gives the home noise floor `Nhome` [M: -97 / -95]. REV2: [M] -93..-97 on wl0, -95..-96 on wl1 over 20 min.
3. The channel list comes from the cached `Caps.Channels` (`wl chanspecs`, `caps.go:180-189`): the 20 MHz chanspecs to measure, plus which 40/80 MHz blocks exist [D]. REV2: minus the radio's sticky **unmeasured** set (§3.2), which is probed in pass 1 only.
4. Clients: `wl -i <vif> assoclist` for each user vif of this radio (from `userVAPs`) [D].
5. Airtime gate: `wl -i wlX chanim_stats us`, twice, 2 s apart (§8.1) [D: parser `parseChanimUs`]. REV2: replaced by one `wl -i wlX cca_get_stats -c 0 -s 5` (§8.1) [M T5].
6. REV2: `wl -i wlX chanim_stats all`: the first pre-call snapshot (§3.2 step 4).

### 3.2 Chunked plan (primary) [A, depends on T2] — REV2: [M] on 2.4 GHz and 36-48 (T2, T3, T4); rewritten

REV2: chosen per band from the evidence, and the same for both bands:
- **2.4 GHz: chunked.** Every channel 1-11 except the home control channel gives a fresh record per call (T4: 20 of 20). 12.9 s per band, 20 % off-channel duty, ≤ 0.25 s per stretch, ≥ 400 ms home between stretches, no drop, no tx failure (T4). A sweep has the same ≤ 0.25 s stretch but about 80 % duty with 30-60 ms home visits (T7), which is worse for any traffic during the band. Two chunked passes found 24 BSSes, as many as a 200 ms sweep (T4 vs e5).
- **5 GHz: chunked.** 36, 44, 48 fresh on every call (T4: 6 of 6). The sweep does not measure 149-165 either (T1), so it buys nothing there. Each 5 GHz off-channel call can cost an active client retries (T3), so the plan also drops pass-2 calls on unmeasured channels.
- The chunked-vs-sweep comparison of **client impact on 5 GHz is not head-to-head**: no sweep ran with a busy 5 GHz client. The choice rests on duty and home time (measured) rather than on a measured impact difference [A].

The defaults below are constants in `wl.DefaultScanPlan()`, not configuration (§11.1).

```
Dwell   = 110 ms   # ≥ one beacon interval (102.4 ms); REV2 [M T4]: two passes found 24 BSSes on wl0 (= e5 at 200 ms)
Passes  = 2        # REV2: kept at 2 [A]; T9 decides 2 vs 4 (see below)
Chunk   = 1        # channels per wl scan call
HomeGap = 400 ms   # minimum time back on the home channel between calls; REV2: value [A], one run fine [M T4]
Budget  = 45 s     # hard limit for one band, within the agent's 60 s scanTO
Poll    = 50 ms    # scanresults poll while a call runs
CallMax = 1 s      # REV2 [A]: no scanresults by then → scanabort, the call counts as STALE (measured calls: 0.13-0.22 s [M T3, T4])
MinHome = 4        # REV2 [A]: home-record rewrites needed for the home control channel's utilization
```

Per band, before the first call: read §3.1 (home chanspec → home control channel `c_h`, `Nhome`, channel list, clients, gate), and take the first `chanim_stats all` snapshot `S`.

For each pass, for each 20 MHz channel `c` of the radio in ascending order (pass 2 in reverse [A]). REV2: pass 2 **skips** every channel that is in the radio's unmeasured set (sticky, or ZERO in pass 1):
1. Run the guard (§8): client-drop check, context and budget.
2. ~~`wl -i wlX scan -t passive -p 110 -c <cs>`~~ REV2: `wl -i wlX scan -t passive -p 110 -c <n>`, where `<n>` is the **decimal channel number** (`1`, `36`), never the hex chanspec: `-c 0x1001` is rejected with exit 254 and scans nothing [M T2]. On "Busy" (acsd2 or another scan running), retry after 1 s, up to 3 times. REV2: any other non-zero exit on a channel other than `c_h` switches the radio to the fallback (§3.3).
3. Poll `wl -i wlX scanresults` every 50 ms until it stops answering "Not Ready" / "Busy". "Not Found" counts as done with zero BSSes, as `Scan` already handles. REV2: stop at `CallMax`.
4. `wl -i wlX chanim_stats all` → `S'`. REV2: classify, using only the record for `c` and the home control record (T2: those are the only two a call writes):
   - **`c == c_h`** (the home control channel): nothing to classify. Its own call never writes a record and never leaves the channel [M T8]; the call is kept only for its BSS list (5 BSSes on wl0, 6 on wl1, the home channel's neighbours that no other call can hear) [M T8]. ~~The step-4 freshness rule applied here~~: under the VERIFIER rule it was always stale and tripped the fallback on every band [M T4].
   - **`c ≠ c_h`**, record `r = S'[c]`, previous `r0 = S[c]`:
     - **ZERO** if `crsglitch == 0 && bad plcp == 0` and all five cca fields are 0, whether or not it changed (T1 r2 / T4: a placeholder's noise moved -100 → -101, so it "changed") [M]. Add `c` to the radio's **unmeasured** set (sticky until the agent restarts), log it, no retry, no fallback.
     - **STALE** if `r` is absent or equal to `r0` in all eight fields. Read again after 100 ms; if still stale, queue one retry of this call at the end of the pass. Still stale after that → `c` is **missing**.
     - **OK** otherwise: fold `r` into `c`'s samples.
   - **Home rewrite**, only when `c ≠ c_h`: `h = S'[c_h]`. If `h ≠ S[c_h]` and `h` is not ZERO, fold `h` into the home samples `H`. A home rewrite is never evidence for any other channel (T2), and an all-zero one is dropped (seen on wl1: `-c 157` left 0xd028 with every field 0 [M T2]).
   - `S := S'`.
5. Merge the scanresults BSSes, keyed by BSSID, keeping the strongest RSSI.
6. Wait so that at least `HomeGap` has passed since step 3 finished. Polling latency counts towards it, because it is spent on the home channel.

REV2: after the last call, per channel:
- **unmeasured**: in the sticky set, or ZERO in any call of this band. No row, no block that contains it (§5, §6). Why sticky: one call can leave a *near-empty* record (149: glitch 8, nopkt 1, u 1) that passes both rules and then reverts to all-zero [M T2]. Without the sticky set, a band that happened to get two near-empty records would publish UNII-3 at about 1 % busy.
- **measured**: `c ≠ c_h`, not unmeasured, and OK in **every** pass that called it (after the retry).
- **home control**: measured if `|H| ≥ MinHome` (T4: 20 rewrites on wl0, 16 on wl1 [M]); otherwise missing. If `c_h` is also in the unmeasured set (a home on an unmeasurable channel), it is unmeasured.
- **missing**: anything else. A row that needs a missing channel makes the band fail (`ErrIncomplete`, §6.6).
- VERIFIER (fix), retained: the stale and zero rules, now with the classes above. The tests are renamed in §11.5.

**Expected cost** (REV2: measured where it says [M]):
- **2.4 GHz**, 11 channels × 2 passes = 22 calls, 20 off-channel. [M T4] 12.9 s, about 2.6 s off-channel (20 %), 107-128 ms per off-channel call on average, worst single call about 0.24-0.25 s [M T3]. The old estimate (13-15 s, about 3 s off, 23 %, 130-140 ms) holds.
- **5 GHz on .205**: pass 1 calls all 9 channels, pass 2 only 48, 44, 40, 36 → 13 calls, 11 off-channel. About **8 s**, about 1.4 s off-channel [A, derived from the T4 per-call figures]. A unit where 149-165 do measure: 18 calls, [M T4 timing] 11.0 s, about 1.7 s off (16 %).
- ~~"never more than about 140 ms in a row"~~ REV2: plan for 0.25 s worst case in a row [M T3].
- Process cost: about 6 `wl` execs per call (scan, 2-3 polls, chanim, assoclist per vif), so about 10 execs/s while a band runs [A].
- VERIFIER (recommendation, [A]): **Passes = 2 is too few for stable rows.**
  - Two 110 ms dwells give about 0.22 s per channel. The U6 Pro spends about 2 s per channel or block (25-27 s for 13 channels, 12-14 s for 6 blocks).
  - Single-sweep values for the home channel ranged 24-76 % (§2.2), so a two-pass mean can still move by about ±20 points from night to night. That can reorder channels 1/6/9 by itself.
  - Raising `Passes` to **4** keeps every off-channel stretch the same (same per-gap client impact). It takes 2.4 GHz to about 24-27 s (44 calls) and 5 GHz to about 20-22 s (36 calls), close to the real AP's times and inside `Budget` 45 s. The timing figures and the "22 calls" test counts in §11.5 change with it.
  - Decide with T4: if 4 passes cause no more client impact than 2, use 4.
  - REV2: **not decided by T4**, which ran 2 passes only. New evidence cuts both ways: wl0 pass-to-pass spread was ±1-3 on 9 of 10 off-channel channels but 17 points on ch10 [M T4]; and each 5 GHz off-channel call can cost an active client retries and occasional tx failures [M T3], so doubling the 5 GHz calls is not free. Keep 2 on both bands; T9 now compares 2 and 4 passes, with a busy 5 GHz client, before changing it. The home control channel already gets 16-20 samples per band and does not need more passes.
- VERIFIER: the `Dwell` comment "catches each neighbour's beacon" is too strong. e4 at 110 ms missed BSSes up to -78 dBm (§2.3). Read it as "catches most beacons; strong ones in practice".
  - REV2: one 110 ms dwell can miss the BSS that sets `P_bss` (`-c 1` found 3 BSSes, strongest -77, where e4 had one at -63 [M T2]); two passes together recovered all 24 [M T4]. So pass 2 is needed for `interference`, not only for `utilization`.

### 3.3 Fallback: whole-band sweep [M on 2.4 GHz] — REV2: [M] on both bands (e4, T1, T7); trigger and dwell changed

~~Switch to the fallback, and remember the choice for this radio until the agent restarts, when the first chunked call of a band returns no record for its chanspec even after the retry. That means `-c` scans do not fill chanim.~~

REV2: that trigger fired on every band, because the home control call never writes a record [M T4, T8], and on 5 GHz it fired on 149, where the sweep does not help either [M T1]. New trigger, remembered for the radio until the agent restarts:
- `wl scan -c <n>` exits non-zero, not "Busy", on a channel other than `c_h` (for example a firmware whose `-c` syntax differs, as with hex here [M T2]); or
- in pass 1, the first **two** channels other than `c_h` whose records are not ZERO both end **STALE** after their retry. That means `-c` scans do not refresh chanim on this unit.
- ZERO never triggers the fallback (unmeasured is a property of the channel, not of the scan shape [M T1]). A single later STALE channel makes that channel missing, not the radio's mode.

```
pass 1:  snapshot chanim_stats all
         wl -i wlX scan -t passive -p 110        # REV2: was -p 50. 1.24-1.56 s, ~1.0-1.25 s off in ≤ 0.25 s stretches [M e4, T1, T7]
         poll scanresults every 50 ms; read chanim_stats all; classify every record against the snapshot (ZERO / STALE / OK)
gap:     10 s on the home channel
pass 2:  the same
```

- REV2: in a sweep the **home control record is refreshed like any other** (0xd028 changed in all 3 T1 runs [M]), so it is classified normally and `H` is not used. Its own `txdur`/`inbss` are left out by §4.1 anyway.
- A sweep whose list is empty or short is retried once after 10 s. If that fails too, the band fails (§7).
- ~~The 50 ms dwell keeps every off-channel stretch near 0.6 s.~~ REV2: the premise was wrong. A sweep returns home every two channels at any dwell [M T7], so 50 ms only shortens each stretch from about 0.25 s to about 0.12 s, while it misses the strong BSSes that set `P_bss` (e3/e7 missed -63 and -68 [M]). 110 ms keeps the stretch at the chunked plan's worst case (about 0.25 s, T3) and gives 18 BSSes per sweep on wl0, 7 on wl1 (all that any scan found) [M e4, T1]. Its cost is duty: about 80 % off-channel for 1.3-1.6 s per pass.
- Measured utilisation at 50 ms agrees with 200 ms within about 8 points (e3+e7 against e5, §2.2 data in `model.py` output) [M].
  - VERIFIER: not for every channel. ch8 is 12 (e3+e7) against 28 (e5), a 16-point gap. ch1 is 22 against 30, ch5 10 against 3. The other channels agree within 8 points.
  - REV2: moot with `-p 110`.

### 3.4 After the band

1. `wl -i wlX chanspec` must equal the value read in §3.1. Every sweep so far returned home: beacon rate came back to 18-20/s [M]. A mismatch is logged loudly and the band is marked abnormal. Nothing re-pins the chanspec automatically [A: bcmwifi `Verify` does not check chanspec today, `internal/bcmwifi/apply.go:346-400`].
   - REV2: read it only **after `scanresults` is ready for the last call** (or after `scanabort`): during a call it reports the scan channel [M T7]. Every band and every call of this session ended on the home chanspec once ready [M T4, `t_final_state.txt`].
2. Build rows (§4, §5, §6), store them (§9), set the state (§7), and inform at once (`wakeLoop`, as today).

### 3.5 Manual `spectrum-scan`

- The real AP clears every rftable and runs `ubntquickscan -a` (all widths) on each radio [D CE §2.2].
- We do the same once: 5 GHz first, then 2.4 GHz, each with §3.2. One measurement per band yields rows at **20, 40 and 80 MHz** (whatever the radio lists), so the extra widths cost nothing.
- `spectrum_scanning` is true for the whole run.
- The `infinite` flag in `spectrum-cfg` is taken to mean "until done" [A]. We do not loop.

### 3.6 `cmd scan` (neighbour list)

- This command is unchanged in purpose: it feeds `scan_table` only, as the real `ath_scan` does [D CE §2.3].
- It must stop writing `spectrum_table`. Today it does, through `Scan` → `spectrum()`.

---

## 4. Field derivation

Notation: for 20 MHz channel `c`, `r_p(c)` is the chanim record from pass `p`, and `P` is the set of passes that produced a record for `c`.

### 4.1 `utilization` (int, %)

```
u_p(c)  = clamp(obss + nocat + nopkt, 0, 100)                     # from r_p(c)
u(c)    = round( mean_{p∈P} u_p(c) )
```

REV2: final form, with the classes of §3.2.

```
# c measured, c ≠ c_h  (OK records of this band, one per pass; chunked or sweep)
u(c)   = round( mean_{r ∈ OK(c)}  clamp(r.obss + r.nocat + r.nopkt, 0, 100) )
# c = c_h, chunked mode  (accepted home-record rewrites H, |H| ≥ MinHome = 4)
u(c_h) = round( mean_{h ∈ H}      clamp(h.obss + h.nocat + h.nopkt, 0, 100) )
# c = c_h, sweep mode: as for any other channel (the sweep refreshes its record [M T1])
# c unmeasured: no value, no row
round = Go math.Round (half away from zero)
```

- REV2: **home control channel from the rewrites [M T2, T4; window semantics A].** Every off-channel call rewrites the home control record with values that look like a short home measurement (wl0 ch9: txdur 0-11, obss 12-36, u 24-44, mean 30 over 20 rewrites; wl1 ch40: txdur 2-7, u 5-12, mean 8 over 16) [M T4]. They agree with two independent home reads (`chanim_stats` current: u 36/41; `cca_get_stats`: obss 24-30 % + interf 0-3 %) [M]. What window each rewrite covers (probably the home time since the previous scan) is not documented [A]. Rewrites can be all-zero or have crsglitch 0 (wl1 `-c 157`) [M T2]; the ZERO rule drops the former, the latter are kept. A mean over 16-20 rewrites is a larger sample than any other channel gets, so the home row is the steadiest row of the table.
- REV2: rejected alternative for the home row: `cca_get_stats -c 0 -s N` (obss + interf). It measures the same channel but with a different estimator and only home, so mixing it into a table of chanim rows would put the home row on another scale [A]. It stays in the airtime gate (§8.1).
- **Leave out `txdur` and `inbss`.**
  - On the home channel they are our own transmissions and our own BSS's receptions: e5 ch9 `txdur 58` [M].
  - On foreign channels in a passive scan they are 0-1 in every capture [M], so dropping them changes nothing there.
  - Whether the real AP counts its own traffic is unknown (CE §11 Q5). Not counting it stops our own clients from making our channel look busy, so the optimiser does not move off a channel because of its own load [A].
- **Keep `nocat` and `nopkt`.** They are CCA-busy time that was not attributed to a decoded frame: partly overlapping Wi-Fi and non-Wi-Fi energy. That is exactly what an interference-aware optimiser should avoid [A].
- **Expected range.** 2.4 GHz at this site: 3-48 % (quiet 3-12, busy 22-48) [M]. 5 GHz: unknown here. The U6 Pro reported 2-48 % [D].
  - VERIFIER: across all six passive runs the range is **2-76 %** (e1 ch9 = 76, e7 ch3 = 2). Busy channels swing by ±26 points per sweep (§2.2).
  - REV2: chunked T4 rows: 2.4 GHz **4-30** (home ch9 30 from rewrites; ch1/6/10 18/20/21); 5 GHz **2-8** (36/44/48 = 2/2/4, home 40 = 8) [M T4]. On foreign channels `txdur` and `inbss` were 0 on every `-c` record [M T2, T4], so the exclusion matters only for the home control channel.
- VERIFIER: checks on the `txdur`/`inbss` exclusion.
  - Leaving them out is right for ranking: our own load moves with us. Under CSMA, neighbours defer while we transmit and send in the remaining time, so `obss` as a share of wall time already estimates their demand. Rescaling by `100 − txdur` would overstate it (e5 ch9: 69 instead of 29), so **no rescale**.
  - Open hypothesis, untested [A]: while we dwell on a **secondary** 20 MHz channel of our own block (ch5-8 when home is 9u), our own clients' 40 MHz uplink frames may land in `nocat`/`nopkt` rather than `inbss`, because the data portion cannot be decoded at 20 MHz. If so, our own traffic would raise the home block's secondary channels, and through the §5 max, the home block.
  - The captures cannot show it: clients were idle, and ch5-8 `inbss`/`txdur` were 0-1. Add to T4: compare ch5-8 `nocat + nopkt` with a client streaming on wl02 against the idle values.
  - REV2: still untested (T4 lite had only light 2.4 GHz traffic: +18.8 kB in 12.9 s). Note a measured fact that weakens the hypothesis for the chunked plan: during a `-c 5` call the radio is tuned to 20 MHz ch5 and **away** from the home block [M T7: `wl chanspec` reads the scan channel], so our own BSS does not transmit, and our clients probably hold off [A]; T4's ch5-8 were 3-11 [M]. It remains open for loaded conditions.

### 4.2 `interference` (int, dBm, negative)

```
Nhome        = wl noise on the home channel (read once per band)       # -97 wl0, -95 wl1 [M]
span(c)      = [f(c) − 10, f(c) + 10] MHz
P_b(c)       = rssi_b + 10·log10( overlap(span(b), span(c)) / width_b )  # only when overlap > 0
P_bss(c)     = max over neighbour BSSes b of P_b(c)
N_elev(c)    = min_{p∈P} noise_p(c)   if that value ≥ Nhome + 6, else none
interference(c) = clamp( round( max(Nhome, P_bss(c), N_elev(c)) ), -110, -20 )
```

REV2: **settled.** The source is scanresults RSSI, not `phy_rxiqest`: that command gives one instantaneous snapshot of the current channel only (noise floor, or whichever frame was on the air: wl0 -72..-106 across 5 calls), and `phy_rxiqest_sweep`, the only way to reach other channels, is refused on a live AP (exit 233) [M, §2.4]. Final form, adopting the two VERIFIER refinements below:

```
Nhome       = wl noise, read once before the band                         # [M] wl0 -93..-97, wl1 -95..-96
BSS         = union of scanresults over all calls of the band (incl. the c_h call),
              by BSSID, strongest RSSI; our own BSSIDs left out
span(c)     = [f(c) − 10, f(c) + 10] MHz
span(b)     = [fc_b − w_b/2, fc_b + w_b/2]        # from the decoded chanspec in scanresults
P_b(c)      = rssi_b                                          if c is b's primary (control) channel
            = rssi_b + 10·log10( overlap(span(b), span(c)) / w_b )   if overlap > 0
            = none                                            otherwise
P_bss(c)    = max_b P_b(c)                         (none if no BSS overlaps c)
B           = median of noise over the band's OK records of channels ≠ c_h
m(c)        = min over c's OK records of noise
N_elev(c)   = Nhome + (m(c) − B)    if c ≠ c_h, every OK record of c has txdur + inbss ≤ 2, and m(c) ≥ B + 10
            = none                  otherwise
interference(c) = clamp( round( max(Nhome, P_bss(c), N_elev(c)) ), −110, −20 )    # c measured or c = c_h
                = no value, no row                                                 # c unmeasured
```

- REV2: **`N_elev` never applies to the home control channel.** In chunked mode its values come from rewrites whose `noise` is on a different scale from off-channel records (wl1: home rewrites -94..-96, the same as `wl noise`; foreign records -101/-102) and swings -70..-104 on wl0 while our own `txdur` is 0-11 [M T4]. The `txdur + inbss ≤ 2` rule would usually skip it anyway; making it explicit removes the rewrites' unknown window from this path.
- REV2: **the primary-channel rule is adopted** (VERIFIER item below). It is still [A, physics], but it decides the home row on both radios here: wl0 ch9 = -50 (sibling Deco at -50 on 0x1907, primary 9) instead of -53, and wl1 ch40 = -72 (sibling at -72 on 0xe12a, primary 40) instead of -78 [M T4 inputs].
- REV2: **the chanim-baseline `N_elev` is adopted** (VERIFIER fix below). wl1 now gives evidence for it: the OK records on 36/44/48 read -101/-102 in every run [M T1, T4], so `B` = -101 and no 5 GHz channel was elevated. On wl0 T4, `B` = -105 and ch6, 10, 11 **are** elevated (min noise -88, -93, -95 → `N_elev` -76, -81, -83 with `Nhome` -93), but `P_bss` beats each by 23-27 dB, so no row changes [M T4 inputs]. On 5 GHz, `interference` came out as `P_bss` (-78 on 36/44/48 from the sibling's 80 MHz spread) everywhere, the case the VERIFIER flagged. The +10 dB threshold is still [A].
- REV2: **unmeasured channels get no `interference` either.** No BSS was ever heard on 149-165, but whether the receiver is deaf there is unknown (§2.1, T10). Reporting `Nhome` there would claim "clean" from an absence of evidence.
- REV2: **results [M T4]**: wl0 1..11 = -69, -59, -56, -54, -53, -53, -53, -53, **-50**, -54, -56; wl1 36/40/44/48 = -78, **-72**, -78, -78.
- `span(b)` is the BSS's occupied band: centre frequency from the decoded chanspec in scanresults (`Chanspec: ... (0x1907)`, already parsed by `parseScanResults`) ± width/2 [D]. A BSS spreads its power evenly over its width, so a 40 MHz BSS puts `rssi − 3 dB` into each 20 MHz half [A, physics].
- **Why received power and not the noise floor.**
  - The real AP's values are received power (-50..-64 on busy 2.4 GHz). They fall to the noise floor only on an empty block (-96 on block 132) [D CE §3].
  - With this formula the e5 sweep gives -53..-65, a quiet channel gives `Nhome` (-97), and the ranking follows real neighbour energy [M via model].
- **Why `N_elev`.**
  - It catches energy from something that sends no beacons (non-Wi-Fi, or a BSS we missed) [A].
  - It uses the **minimum** over passes, because one contaminated reading must not set it (§2.2: one-run jumps of 20-35 dB) [M].
  - The 6 dB threshold is assumed. At this site `N_elev` never beat `P_bss` (`model.py`), so it changes nothing here [M].
- **Which BSSes count.** Every BSS we hear that is not one of our own BSSIDs (we cannot hear our own anyway), including mesh or UniFi siblings. Their energy is real interference on that channel, and the real AP's figure is a power measurement too [A].
- **Expected range.** 2.4 GHz: -52..-65 here, `Nhome` ≈ -97 on a channel with nothing overlapping [M via model]. 5 GHz: from about -95 (`wl noise` wl1 [M]) on an empty block up to about -55 [A, U6 Pro showed -59..-96 [D]]. REV2: [M T4] at this site 2.4 GHz -50..-69 (home ch9 -50) and 5 GHz -72..-78 on 36-48, all set by the two sibling Decos; no measurable channel fell back to `Nhome`.

VERIFIER: checks on §4.2 (units, scales and bias).
- **Units are consistent but the scales are not.** `Nhome` (`wl noise`, -97) and `rssi_b` are both dBm on the driver's RSSI scale. Chanim `noise` is a separate estimator: quiet channels read -105..-109, about 10 dB below `wl noise` on the same radio.
  - So `N_elev`'s threshold `Nhome + 6` = -91 sits about **16 dB** above chanim's own quiet baseline, not 6 dB.
  - When `N_elev` wins, it reports a value from the chanim scale inside a max() of driver-scale numbers.
  - Fix [A]: define the threshold against the sweep's own chanim baseline (`B` = median chanim noise of the band's records), elevate when `min_p noise_p(c) ≥ B + 10`, and report `Nhome + (min_p noise_p(c) − B)`.
- **`N_elev` mostly tracks Wi-Fi activity, not hidden non-Wi-Fi energy.** Raised chanim noise appears on the busy and sibling-adjacent channels: ch9 = -92, -66, -105, -71, -75, -101; ch10 and 11 reach -72..-86 in most runs. Quiet ch3-5 stay at -100..-109.
  - On ch9 (home control) it can include our own clients' frames: e5 has `txdur 58` on that record.
  - Fix [A]: skip `N_elev` for any record with `txdur + inbss > 2`, so that our own traffic cannot raise the home channel through this path.
  - At this site `N_elev` never wins (`P_bss` ≥ -60 everywhere), so neither fix changes the worked numbers. It matters on 5 GHz, where many channels will have no `P_bss`.
- **`P_bss` is a peak, duty-free power.** It is the beacon RSSI spread over the BSS width. A neighbour that only beacons counts the same as one at 90 % airtime. Duty enters only through `utilization`. That is a deliberate split, but the doc should not call `interference` "real neighbour energy": it is "strongest neighbour level when it transmits".
  - Beacons are 20 MHz frames on the primary, so the primary channel of a 40/80 MHz neighbour gets the full `rssi`, not `rssi − 3 / − 6` dB. The model understates the primary by up to 3 dB (40 MHz) or 6 dB (80 MHz) [A, physics]. Use `max(P_b(c), rssi_b)` when `c` is the BSS's primary.
- **Our own mesh siblings set the 2.4 GHz column** (§2.2). This is consistent with "every BSS we hear counts", and a real AP's power measurement would include siblings too. But it makes ch1 (9 BSSes, 28 % busy) look 10 dB better than ch5 (0 BSSes with their primary there, 3 % busy). Once the siblings are also UniFi-managed, part of this energy is the controller's own plan feeding back into its input. Keep the formula, but write `P_bss` both with and without known site BSSIDs to the diagnostics file (§9). Decide only after a controller test shows how `interference` is weighted (CE §11 Q1).
- **Home channel on a real AP.** The U6 Pro's own 5 GHz block (36, primary 40) reads **-59**, while the strongest neighbour in its scan_table on 40 is **-85**. That is 26 dB unexplained. Its 2.4 GHz home channel 13 reads -57 against a strongest neighbour of -72.
  - So the real AP's home-row `interference` is probably raised by something other than neighbour beacons: its own BSS, its clients, or siblings outside its own channel [A].
  - Our formula leaves our own BSS out, so our home row will look **relatively cleaner** than a real AP's would. That biases the optimiser towards staying, the safe direction. The controller may also expect, and discount, a raised home row; this is unknown (add to CE §11 Q5).

### 4.3 `interference_type` (array) = `[]`

- The real AP sends `[]` on every nightly row [D CE §3]. There is no classifier on Broadcom without spectral FFT access [A].
- Rejected idea: tagging `"Other"` when `nocat + nopkt ≥ 30` and nothing overlaps. It is unverified, and the controller is not known to read the field [D CE §3, SECONDARY].

### 4.4 `other_bss_count` (int) = 0

- The real AP sends 0 [D].
- We still compute `n_ctl(c)`, the number of BSSes whose control channel lies in the row's span (e5: ch1 9, ch6 6, ch9 5 [M]). It is written to the local diagnostics file (§9) and the log, not to the inform.
- Turning it on is a one-line change (`emitOtherBSS` constant) once a controller test shows it is read (CE §11 Q7).

### 4.5 `perf_index` = 0, `total_samples` = 0

- The real AP sends both as 0 on the nightly path [D CE §3].
- Both belong to the QCA spectral path. We have no equivalent [A].

### 4.6 `channel`, `width`, `center_freq`

- `channel` = the lowest 20 MHz channel of the row. `width` = the row width. `center_freq` = the centre of the whole block [D CE §3].
- For 20 MHz rows the centre is `f(c)`: 2.4 GHz `2407 + 5c`, 5 GHz `5000 + 5c` [D].

---

## 5. Aggregation into 40 and 80 MHz blocks

A block row exists only if (a) the radio lists that block in `wl chanspecs` and (b) **every** 20 MHz part has at least one record. Then:

REV2: (b) becomes: every 20 MHz part is **measured** in the §3.2 sense (the home control part through its rewrites). If any part is **unmeasured**, the block has no row and the band still succeeds; if any part is **missing**, the band fails (§6.6). On .205 this removes every 149-165 row at every width [M T1, T2, T4].

| Field | Block value | Why |
|---|---|---|
| `utilization` | **max** of the parts' `u(c)` | [A] A wide BSS can only send full width when every part is idle. The busiest part limits it, and a mean would hide one busy part. The union `1 − Π(1−u)` was rejected because it double counts correlated traffic and pushes quiet blocks to about 12 % (4 × 3 %). The real AP's choice is unknown (CE §3). The choice is isolated in `blockUtil` and pinned by tests. |
| `interference` | **max** of the parts' `interference(c)` | [A] The real AP reports -96 on an empty 80 MHz block, equal to its 20 MHz noise. So it does not add the +6 dB that integrating over 80 MHz would give [D CE §3]. |
| `other_bss_count` (local only) | BSSes whose control channel lies in the block | [A] |
| `channel` / `center_freq` | lowest part / block centre | [D] |

REV2: the `channel` / `center_freq` row above was stranded below the VERIFIER note and did not render as part of the table; moved back.

VERIFIER: CE §9 recommends the **mean** for block `utilization`, and this section chooses the **max**. Both are labelled unverified, and the reasons for max are sound. The two documents now disagree, though, so CE §9 should point here. A note on max: our own 40 MHz block's secondary parts may carry our own clients' traffic (see the hypothesis in §4.1), which max passes straight into the home block row.

REV2: **aggregation settled as max for both fields, still [A].** No test compares max with mean against a real AP, so the choice is not measured. What the T4 rows show [M T4]:
- 2.4 GHz 40 MHz blocks (pairs c, c+4), u by max / by mean: 1l 18 / 11, 2l 20 / 13, 3l 10 / 8, 4l 11 / 8, **5l (home block 9u) 30 / 17**, 6l 21 / 21, 7l 11 / 9. Max ranks 3l best, then 4l and 7l; mean ranks 3l and 4l best. Same winner, different spread. Under max the home block is the worst block (its control channel carries the busy sibling Decos, obss 12-36), which is the honest reading of that channel.
- 5 GHz 80 MHz block 36: parts 36 / 40 / 44 / 48 = u 2 / 8 / 2 / 4 → **8** (mean 4); interference -78 / -72 / -78 / -78 → **-72**. 40 MHz blocks: 36 → u 8, -72; 44 → u 4, -78.
- The home control part of any home block comes from rewrites (§4.1), so under max the home block's `utilization` is usually set by that one part. That is consistent with the max rationale, but it means a change in rewrite semantics would move every home-block row. Pinned by `TestBuildRowsHomeFromRewrites` (§11.5).

Blocks on the X20 V2 under country US [M: `wl chanspecs` capture in the scratchpad `wlcap/`]:

| Band, width | Rows (`channel` → `center_freq`) |
|---|---|
| 2.4 GHz, 20 | 1..11 → 2412..2462 |
| 2.4 GHz, 40 | 1..7 (pairs c, c+4: `1l..7l` = `5u..11u`) → 2422..2452 |
| 5 GHz, 20 | 36, 40, 44, 48, 149, 153, 157, 161, 165 → 5180..5825 |
| 5 GHz, 40 | 36 → 5190, 44 → 5230, 149 → 5755, 157 → 5795 |
| 5 GHz, 80 | **36 → 5210, 149 → 5775** |

REV2: rows **actually emitted on .205** (149-165 unmeasured) [M T1, T2, T4]:

| Band, width | Rows (`channel` → `center_freq`) |
|---|---|
| 2.4 GHz, 20 | 1..11 → 2412..2462 (all measured; 9 from home rewrites) |
| 2.4 GHz, 40 | 1..7 → 2422..2452 |
| 5 GHz, 20 | 36, 40, 44, 48 → 5180, 5200, 5220, 5240 |
| 5 GHz, 40 | 36 → 5190, 44 → 5230 |
| 5 GHz, 80 | 36 → 5210 |

A unit on which 149-165 do measure gets the full table above with the same code. Whether other X20 units (.241, .232) or other firmware behave like .205 is untested [A].

- Under country IN the radio lists DFS chanspecs as well [M: "DFS only with IN"]. The same rule then yields DFS rows, as the real AP sends [D CE §4].
- Passive scans are allowed on DFS channels [A, regulatory]. The scan command is still passive-only.

---

## 6. Which rows to emit

1. **Only the requested width** for a quick-scan, as the real AP does [D CE §4]. For a manual spectrum-scan: every width the radio lists (20/40/80).
2. **Width clamp** [A, CE §11 Q3]:
   - `w = max(width ∈ radio widths, width ≤ scan-bw)`. A request of 0 or below 20 becomes 20.
   - 5 GHz at 160/240/320 gets 80 MHz rows that say `width: 80`.
   - 2.4 GHz at 40 gets the 7 rows above.
3. **Channels the radio cannot use are omitted.**
   - The real AP lists exactly its regulatory set [D].
   - Inventing rows for, say, 52-144 under US would invite the optimiser to pick them [A].
   - If the controller picks a channel the Deco cannot use anyway (because the site country or the UAL6 model allows it), the translate/bcmwifi layer must clamp it. A spectrum row cannot prevent that.
   - Whether the controller treats a missing row as "skip" or "clean" is the top controller-side test (CE §11 Q2).
4. **The home channel or block is reported like any other row**, as the real AP does [D CE §4].
5. **6 GHz** (`scan-band 2`): no rows, no change to any table, logged. `actions.go` does this today [D].
6. **Incomplete measurement.** If any 20 MHz channel the requested rows need is still missing after the retries, the whole band fails (§7). Rows from different scans are never mixed in one table [A, CE §6].
   - REV2: "missing" (STALE after retry) and "unmeasured" (ZERO, or sticky) are now different (§3.2). Unmeasured channels drop their rows and every block containing them, and the band **succeeds** with the rest, `abnormal` false; the omitted channels are logged and written to the diagnostics file (§9). If no row is left at the requested width (for example a 5 GHz unit where every channel is unmeasured), the band **fails**: an empty table is never sent [D CE §6].
   - REV2: why not `abnormal: true` for a partial 5 GHz table: on .205 it would be true every night, and its meaning to the controller is unknown (CE §5) [A]. Why not rows for the unmeasured channels: the chanim fields are placeholders and the empty BSS list may be deafness (§2.1); either row value would be invented.
7. REV2: **unmeasured channels look like channels the radio cannot use** (rule 3): no row. Whether the optimiser then avoids them or treats them as clean is the same open controller question (CE §11 Q2). If it can pick the 149 block blind, the translate/bcmwifi layer is the only place to stop that; this design does not change the channel plan [A, §13.1].

---

## 7. State machine and inform fields

Per radio:

```
           quick-scan(band) / spectrum-scan
  IDLE ─────────────────────────────────────▶ PENDING ──gate ok / defer limit──▶ SCANNING
   ▲  (table T, age grows, abnormal=a)          │ guard abort, ctx cancel             │
   │                                            ▼                                     │
   ├──────────── success: T := new rows, t0 := now, abnormal := false ◀───────────────┤
   └──────────── failure/abort/budget: T unchanged, age keeps growing, abnormal := true ◀┘
```

| Field | Where | Value | Label |
|---|---|---|---|
| `spectrum_table` | each `radio_table[]` row | rows of the last **successful** scan of that radio. Absent until the first one (as today, `cmd/udeco-ap/scan.go:103-107`). | [D]/[A] |
| `spectrum_table_time` | each row | `uptime_now − uptime_at_success`, in whole seconds. It keeps growing between scans (a real AP shows about 66 000 s at rest). | [D CE §5] |
| `spectrum_scanning_abnormal` | each row, always sent | false at rest. true after the last attempt on that radio failed or was aborted, until the next success. | meaning [A] (CE §5) |
| `quickscan_scanning` | top level | `true` only while a quick-scan band is PENDING or SCANNING, **absent otherwise** (the real AP omits it at rest) | [A] |
| `spectrum_scanning` | top level, always sent | true only while a manual spectrum-scan runs. Today a quick-scan sets it; that changes. | [D]/[A] |
| `scan_radio_table` | top level | `[]` (unchanged) | [D] |

Rules:
- **Concurrency.** One scan at a time across both radios (`scanner.running` and `Collector.scanMu`, as today). A command that arrives while one runs is logged as `skipped: already in progress` and dropped, as mcad does [D CE §2.1].
- **Timing.** Inform immediately when PENDING starts (to show `quickscan_scanning`) and immediately at the end, whatever the result. The controller sends the next band about 1 s after that report [D CE §2.1].
- **Manual scan.** At the start of SCANNING, both radios' tables are cleared, as the real `spectrum_scan` does with `{}` [D CE §2.2]. A failed manual scan then leaves that radio with no table and `abnormal: true` until the next scan [A, mirrors the real AP].
- **Quick-scan** never clears a table first: the old one stays until the new one is complete [D CE §6].
- **Budget.** `PENDING` lasts at most 60 s (§8.1). `SCANNING` lasts at most `Budget` = 45 s, inside the agent's 60 s `scanTO`.

---

## 8. Client-impact safeguards

Most of these are [A]. The measured base: no drops in 7 sweeps, each up to 2.2 s off-channel (§2.3).
REV2: and now on both radios: no scan-caused drop in 3 wl1 sweeps, about 60 single-channel calls and one T4 band per radio; 2 hard tx failures for a busy 5 GHz client during 16 back-to-back wl1 calls (T3), none during the T4 band [M §2.3]. Each sweep is at most about 0.25 s off in a row, not 2.2 s [M T7].

1. **Airtime gate, before the band (PENDING).**
   - Read `chanim_stats us` twice, 2 s apart. `total_tm` moves in 1 s steps [D `survey.go`].
   - `own = (Δtx + Δinbss) / Δtotal`.
   - If `own > 30 %`, defer 20 s and read again, at most 3 times (60 s).
   - After that, scan anyway with `HomeGap = 1 s`, which halves the off-channel duty.
   - Deferring rather than skipping matters: the controller waits for each band's report before sending the next [D CE §2.1].
   - The 30 % threshold is assumed. It should flag a video stream or a backup, not idle phones.
   - VERIFIER (fix): **the denominator is wrong.** In `internal/wl/testdata/series_chanim_stats_10s.txt` (wl0, about 10.8 s apart), `Δtotal_tm` is 10.04 s or 11.04 s, so it moves in steps of about 1.004 s. In a 2 s window, `Δtotal` reads 1, 2 or 3 s for the same 2 s of wall time, a −33 %/+100 % error on `own`.
     - Measured idle `own` on wl0 is **8-11 %** (that file, 23 intervals). A real 16 % load could read 32 % and be deferred. A real 40 % load could read 27 % and be scanned.
     - Fix: `own = (Δtx + Δinbss) / Δwall`, with `Δwall` from the agent's monotonic clock around the two reads. Use a window of **≥ 5 s**, and use u64 modular deltas as `survey.go` does (the wl1 `total_tm` in `chanim_offsets` is close to 2^64).
   - VERIFIER: "the controller waits for each band's report before sending the next" is **INFERENCE** in CE §2.1, not [D]. Only the 1 s gap after `reportok` was observed.
   - VERIFIER: the gate cannot see **low-airtime, latency-sensitive** traffic. A voice or video call uses a few % of airtime and passes. It then gets about 22-44 gaps of about 130-140 ms over the band. This is accepted only because the scan runs at 03:00. Optional [A]: also defer while any associated station shows a sustained packet rate (`sta_info` tx/rx packet deltas) above a small threshold.
   - REV2: **input changed to `wl -i wlX cca_get_stats -c 0 -s 5`** [M T5 for format, speed and idle agreement; A under load]. One call, about 20 ms, no wait, never leaves the channel; it returns the last 5 stored 1 s samples of the home control channel (`dur 1004`), each with `ibss %` (own: matches chanim `txdur + inbss`, 5-9 % on wl0 at idle) and `obss %`. `own = mean of the 5 ibss %`. This removes the `total_tm` step error and the 5 s window of the VERIFIER fix. If the command fails or prints no row for the home channel, fall back to the VERIFIER method (`chanim_stats us`, Δwall, ≥ 5 s). Whether `ibss` still equals our own airtime under a heavy download is untested (T4 had no controlled load).
   - VERIFIER (implementation): PENDING (up to 60 s) plus SCANNING (`Budget` 45 s) is longer than the per-band `scanTO` context of 60 s (`cmd/udeco-ap/scan.go:51`, `agent.go:101`). The gate must run outside that context, or `scanTO` must be raised to about 110 s. Otherwise a deferred band is cancelled half-way through the scan.
2. **Client-drop abort (SCANNING).**
   - Take the union of `assoclist` over the radio's user vifs before the band. Check it again before each call.
   - If any MAC from the starting set is gone, call `wl -i wlX scanabort`, end the band as failed (old table kept, abnormal), and log the MAC's OUI only.
   - A client that roams away normally also triggers this. The only cost is a stale table [A].
   - VERIFIER: on a 2.4 GHz band full of IoT devices, "any MAC gone" can fail every night. ESP- and Tuya-class devices often drop and rejoin on their own timers, and a 13-27 s band gives them time to do it. The result is a table that never refreshes and `abnormal` that is always true.
     - Fix [A]: count only stations associated for ≥ 60 s at the start of the band.
     - Abort on the first drop only when it follows an off-channel call within 2 s. Otherwise allow one unexplained drop per band before aborting.
     - Log each drop with its timing relative to the last call, so T4 can tell scan-caused drops from background churn.
     - REV2: **adopted.** Background churn is measured on 5 GHz too: two wl13 clients left during the session while no off-channel call was running on wl1 (one 150-220 s after the last one, the other while only reads ran), and one of them looks like a device switching between two MACs [M §2.3]. Under the old "any MAC gone" rule, a band running at that moment would have aborted for nothing.
   - VERIFIER: the starting set is `userVAPs` only, so the backhaul vif (`wlX1`, dwds) is not watched. Under takeover it is down (agent-design §1), so this is fine there. With `observe_scans` (never built, §10) on a unit whose `wlX1` has peers (a wireless child Deco), scanning that radio would cut the child's backhaul. Treat "`wlX1` has associated peers" like a wireless uplink (§8.4) and skip the radio.
3. **Interleave.** At most one channel per call, at least `HomeGap` back home between calls, at most about 140 ms off in a row (§3.2). The fallback sweep is about 0.6 s off per pass with 10 s between passes (§3.3).
   - REV2 [M T3, T4, T7]: chunked: 107-145 ms per call on average, **up to about 0.25 s**, 16-20 % duty. Fallback sweep (`-p 110`): stretches of up to about 0.25 s with 30-60 ms home visits, about 80 % duty for 1.3-1.6 s, 10 s between passes. On 5 GHz, pass 2 skips unmeasured channels, which removes 5 of 16 off-channel calls on .205 (§3.2).
4. **Wireless uplink.**
   - If the uplink (`Snapshot.UplinkName`) is a `wl*` interface on the radio, do not scan that radio: log it and leave its table alone.
   - Real UniFi mesh downlinks skip scan commands too (`skip scan cmd due to AP is downlink`) [D CE §2.3].
   - .205 is wired (`eth1`) [M].
5. **DFS.** If `wl -i wl1 dfs_status` shows a CAC in progress, skip the band and mark it abnormal [A; command [D]]. This only matters under country IN.
6. **Cancel.** On context cancel or budget, send `wl -i wlX scanabort` so the radio comes back at once [D: command exists].
7. **Health check.**
   - The Wi-Fi health check (`cmd/udeco-ap/wifi.go:237`, two failures → rollback) does **not** run while a scan is SCANNING.
   - `Verify` reads `wl bss` and pings hostapd [D]. Whether `bss` reads `up` while the radio is off-channel is untested. A false failure would count towards a rollback to TP-Link [A].
   - REV2: **tested** [M T7]: `wl bss` read `up`, `wl isup` 1 and hostapd answered `PONG` at all 175 polls during `-c` calls and sweeps on both radios (TP-Link's hostapd; the agent's own hostapd uses the same driver and control-socket path [A]). So a scan cannot fail `Verify` through `bss` or PING, and the old reason for skipping the check is gone.
   - REV2: a new reason replaces it: **`wl chanspec` reports the scan channel during a call** [M T7]. The health check is therefore not skipped but **serialised**: it waits for the band to end (it takes the same lock as `MeasureSpectrum`), so no read of it can overlap a call. The same lock covers the collector's inform reads (`collect.go:88` reads `wl chanspec` without `scanMu` today): during SCANNING the collector reuses the home chanspec read in §3.1 instead of reading it, so an inform never reports `channel` 1 or 36 for a radio whose home is 9u or 40/80.
8. **One radio at a time.** Already true [D].

---

## 9. Storage

- `/tmp` is **ramfs**, shared with the whole system: mountinfo says `tmpfs size=420k`, but the kernel is built without SHMEM, so no size limit is enforced, a write never fails with ENOSPC, statfs reports 0 blocks, and every byte written is RAM that cannot be reclaimed (it counts against the memory that ends in the OOM reboot, interference-audit B8) [D interference-audit D6, agent-design §2]. The cost of a file here is RAM, not space. `/tp_data` is synced ubifs flash [D].
- As built (2026-11-19): the mirror below is **not implemented**; the tables live only in the per-radio `wl.SpectrumRunner` (`cmd/udeco-ap/spectrum.go`), so an agent restart starts with no table [D].
- As built (2026-11-20), replacing the mirror below: the 2026-11-19 release deploy restarted every agent and the Environment section stayed empty, so the last good table per band is now kept **on flash**, `/tp_data/udeco/state/spectrum.json` (`cmd/udeco-ap/specsave.go`): one versioned JSON file (model; per band radio, wall-clock measurement time, rows), written tmp + rename only when a band gets a new good table or a spectrum-scan clears the tables, and only when its bytes change (a few writes a night). At start it is restored into the runners and reported as a live table with its true age, keeping only the rows the radio lists now (re-checked while it is reported, so after an apply that changes the country or width cap too); dropped when older than 7 days, of another version, model or radio layout, unparsable, or measured after a clock that is set; held (not dropped) while the clock is not set (before `device.ClockSane`, X9). No `EVT_AP_QuickScanEvent` for a restored table: the controller usually keeps it in memory only, but a quick-scan it sent that ends without a new table (agent restarted during it, or skipped it) ends with its own `quickscan_scanning` true -> false and saves the restored table to the database as that scan's result; whether that also stamps `spectrum_scan_timestamp` is UNVERIFIED (see `specsave.go`). The /tmp mirror, `boot_id` and uptime age below are not used; scan_table is not saved.
- **In memory first.** The tables live in the agent's `spectrum` state (§11.3).
- **Mirror in `/tmp/udeco`** (the agent's existing run directory [D]):
  - `rftable_wl0.json` and `rftable_wl1.json`: `{"boot_id", "uptime_done", "wall_done", "kind", "width", "abnormal", "rows":[...]}`.
  - A row of 9 keys is about 150 B, so 11 rows on 2.4 GHz is about 1.7 kB, and a manual all-widths table is at most about 2.7 kB per radio. Each file stays under 4 kB.
  - Optionally `spectrum_wlX.last.json`: per-channel `ChannelStat`s (raw cca fields, noise min, `P_bss`, `n_ctl`) of the last attempt, successful or not, at about 3 kB, for local diagnosis.
  - REV2: it also carries each channel's class (measured / unmeasured / missing, home samples `|H|`) and the radio's sticky unmeasured set, so an omitted 149 block can be explained from the device. The sticky set itself lives only in memory (§3.2); it is relearned in pass 1 of the first band after a restart.
  - **Total under 16 kB.**
- **Writes.** Write `*.tmp`, then `rename`, mode 0600. If a write fails, log it and carry on with the in-memory copy; a failed write never fails a scan. ENOSPC does not happen on this ramfs (no limit), so the bound is the agent's own: the files above stay under 16 kB in total and are overwritten, never appended.
- **Restart and reboot.**
  - On agent start, load the files if `boot_id` (`/proc/sys/kernel/random/boot_id`) matches. Age = `uptime_now − uptime_done`, which survives NTP steps.
  - After a reboot `/tmp` is empty, so there is no table, as on a real AP whose `/var/run` is tmpfs [D CE §5; behaviour right after reboot unknown].
  - Nothing goes to `/tp_data`: there is no flash wear, and a stale table never survives a reboot.

---

## 10. Takeover and observe mode

**Takeover** (acsd2 killed by decosys; bcmwifi pins the chanspec) [D `services.go:94`, `bcmwifi/radio.go:94`]:
- We are the only one that scans, so chanim "last scan" records are ours and nothing else overwrites them.
- [A, T6] chanim keeps filling after acsd2 is gone. REV2: still untested; every [M] in this document was taken with acsd2 alive. Nothing indicates that acsd2 is needed (host scans filled it while acsd2 sat idle), but this has not been measured.
- The scan returns to the pinned chanspec on its own [M: beacons resume]. §3.4 checks it.
- Channel changes chosen by the optimiser come back as config and go through bcmwifi. That is outside this design.

**Observe** (TP-Link in charge, acsd2 alive):
- Default: **no scans**, as today. `actions.go` logs `quick-scan`/`spectrum-scan` in observe mode and does nothing [D].
- Reasons:
  - Observe mode promises "nothing on the unit changes".
  - Our scan replaces acsd2's chanim records (1-5 and 8 were gone after the first scan) [M], which feeds TP-Link's own channel logic with our data.
  - The controller cannot apply a channel in observe mode anyway, so the table would buy nothing.
- Opt-in for testing: config key `observe_scans` (bool, default false; the config rejects unknown keys, so it must be added to `config.go`) [A]. **Never built:** `cmd/udeco-ap/config.go` has no such key, so a config that sets it is refused as an unknown key, and observe mode runs no scans. The rest of this bullet is the plan as it was written.
  - When it is set, the same code runs.
  - "Busy" from `wl scan` (acsd2 scanning) is retried (§3.2 step 2).
  - Measured: 7 sweeps beside a live acsd2, with no client drop and no acsd2 rescan within 60 s [M].
  - REV2: the whole §12 session (about 20 min, both radios, sweeps and `-c` calls) ran beside acsd2 (pid 12001 throughout) without a `Busy` from `wl scan` and without acsd2 rescanning: e7's records were still in wl0 chanim 1 400 s later [M `t0_baseline.txt`, `t_final_state.txt`]. The `Busy` retry path (§3.2 step 2) is therefore untested.

---

## 11. Go changes

No code was changed for this document. Names are proposals.

### 11.1 `internal/wl`

New file `spectrum.go` (I/O) and `spectrum_calc.go` (pure functions):

```go
// ScanPlan shapes one band measurement (§3.2). DefaultScanPlan returns the constants.
type ScanPlan struct {
	Dwell   time.Duration // passive dwell per channel (110 ms)
	Passes  int           // 2
	Chunk   int           // channels per wl scan call (1); 0 = whole-band sweep
	HomeGap time.Duration // minimum home time between calls (400 ms)
	Budget  time.Duration // whole band (45 s)
}
func DefaultScanPlan() ScanPlan

// SpectrumRequest is one band of a quick-scan or one band of a manual scan.
type SpectrumRequest struct {
	Band   string // "ng" | "na"
	Widths []int  // rows to build: quick-scan {clamped scan-bw}; manual {20, 40, 80}
	Plan   ScanPlan
	// Guard runs before every wl scan call; a non-nil error stops the band
	// (wl scanabort is sent) and is returned wrapped in ErrScanAborted.
	Guard func(ctx context.Context, s ScanStep) error
}
type ScanStep struct {
	Radio        string
	Pass, Call   int
	Calls        int
	Chanspec     string // e.g. "0x1001"; REV2: plus Channel int, the decimal number passed to -c (§3.2 step 2)
}

// ChannelStat is what one 20 MHz channel measured (means over passes).
type ChannelStat struct {
	Channel, Freq                     int
	Samples                           int // records folded in (0 = missing)
	TxDur, Inbss, Obss, Nocat, Nopkt  int // %, mean
	NoiseMin                          int // dBm, min over passes
	Glitch, BadPLCP                   int // sums, diagnostics only
	PeakBSS                           int // dBm, P_bss; 0 = nothing overlaps
	CtlBSS                            int // BSSes with their control channel here
	Home                              bool
}

type SpectrumResult struct {
	Band, Radio   string
	HomeChanspec  string
	HomeNoise     int
	Mode          string // "chunked" | "sweep"
	Started, Done time.Time
	Channels      []ChannelStat
	Rows          map[int][]openwrt.SpectrumEntry // by width
	BSS           []openwrt.BSS                   // merged neighbours (also feed scan_table)
}

var ErrScanAborted = errors.New("wl: spectrum scan aborted")
var ErrIncomplete  = errors.New("wl: spectrum scan missed channels")

func (c *Collector) MeasureSpectrum(ctx context.Context, req SpectrumRequest) (*SpectrumResult, error)
func (c *Collector) Associated(ctx context.Context, radio string) ([]string, error) // assoclist over user vifs
func (c *Collector) OwnAirtime(ctx context.Context, radio string, window time.Duration) (float64, error)
```

Pure helpers in `spectrum_calc.go`, each table-tested:

```go
type chanimRecord struct{ CS chanspec; Glitch, BadPLCP, Noise, TxDur, Inbss, Obss, Nocat, Nopkt int }
func parseChanimRecords(b []byte) (recs []chanimRecord, ok bool) // ok=false: no "Stats during last scan" header
func foldRecords(st map[uint16]*ChannelStat, recs []chanimRecord, band string, only uint16)
func channelUtil(s ChannelStat) int                                // §4.1
func bssPower(b openwrt.BSS, lo, hi float64) (dBm float64, ok bool) // §4.2
func channelInterference(s ChannelStat, homeNoise int, bss []openwrt.BSS) int
func blockUtil(parts []int) int                                    // §5: max
func buildRows(st []ChannelStat, bss []openwrt.BSS, homeNoise int, band string, width int,
	widths map[int][]int) ([]openwrt.SpectrumEntry, error)        // §5, §6; ErrIncomplete
func clampWidth(req int, widths map[int][]int) int                // §6.2
```

REV2: changes to the proposals above, from the device tests:
- `ScanPlan` gains `CallMax time.Duration` (1 s) and `MinHome int` (4). The `-c` argument is `strconv.Itoa(channel)`, never the hex chanspec [M T2].
- `ChannelStat` gains `Class` (`measured` | `unmeasured` | `missing`), `HomeSamples int` (`|H|`, home control channel only) and `Zero, Stale int` (per-call counts, diagnostics).
- New pure helper `classifyRecord(before, after chanimRecord, present bool) recordClass` (ZERO before STALE before OK, §3.2 step 4), and `foldHome(st *ChannelStat, before, after chanimRecord)` for the rewrites. `foldRecords` folds **only** the record of the scanned channel (`only`) and never the home record into it [M T2].
- `channelInterference` takes the band's chanim baseline `B` and skips `N_elev` for the home control channel (§4.2). `bssPower` applies the primary-channel rule.
- `Collector` keeps the sticky unmeasured set per radio (`map[string]map[int]bool`, in memory) and the fallback mode per radio, both cleared only by a restart.
- `MeasureSpectrum` holds a lock that `Collect` also takes for its `wl chanspec` read; while a band runs, `Collect` reports the home chanspec captured at band start instead of reading it [M T7].
- `OwnAirtime` uses `wl cca_get_stats -c 0 -s 5` (mean `ibss %`), falling back to `chanim_stats us` with Δwall (§8.1). New parser `parseCCAGetStats`.

Changes to existing code:
- `parseChanimAll` / `chanimChannel`: keep each cca field instead of the summed `Utilization`. Replace them with `parseChanimRecords`.
- `Scan` stops building `Spectrum`. Today's `TestScan` expects 11 spectrum rows and must change.
- `Collector.sleep` / `now` stay the test hooks, so plan timing is tested without real sleeps.
- The package doc's "only mutating command is `wl scan`" becomes "`wl scan` and `wl scanabort`".

### 11.2 upstream's `openwrt` package

- `SpectrumEntry` gains `OtherBSS, PerfIndex, TotalSamples int` and `InterferenceType []string`.
- `SpectrumRows` emits all 9 keys, with `interference_type` as `[]`, never `null` [D CE §3: every real row carries all 9 keys].
- `Spectrum` (the OnHub/OpenWrt builder) is left alone apart from the extra zero-valued keys.

### 11.3 `cmd/udeco-ap`

- `collector` interface (`agent.go:39`): add `MeasureSpectrum`, `Associated`, `OwnAirtime`.
- New `spectrum.go`:
  ```go
  type rfTable struct {
  	Radio, Band, Kind string // kind "quick" | "manual"
  	Width             []int
  	Rows              []openwrt.SpectrumEntry
  	BootID            string
  	UptimeDone        float64
  	WallDone          time.Time
  	Abnormal          bool
  }
  type spectrumState struct {
  	mu      sync.Mutex
  	tables  map[string]*rfTable // by radio
  	abn     map[string]bool
  	quick   string // band PENDING/SCANNING, "" none
  	manual  bool
  	dir     string // /tmp/udeco
  }
  func (s *spectrumState) merge(f map[string]any, uptime float64)    // §7 fields
  func loadRFTables(dir, bootID string) map[string]*rfTable
  func saveRFTable(dir string, t *rfTable) error                     // tmp + rename, 0600
  func (a *agent) quickScan(ctx context.Context, band string, bw int) // PENDING → gate → SCANNING
  func (a *agent) manualSpectrum(ctx context.Context)
  func (a *agent) scanGuard(radio string, start []string) func(context.Context, wl.ScanStep) error
  ```
- `actions.go`:
  - `quick-scan:<band>:<bw>` → `quickScan`.
  - `spectrum-scan` → `manualSpectrum`.
  - `scan` keeps the neighbour scan.
  - Observe mode runs scans only when `observe_scans` is set. (`observe_scans` was never built: observe mode runs no scans.)
  - The "wl scans every channel" log line goes.
- `scan.go`:
  - `merge` no longer sets `spectrum_table` or `spectrum_scanning`. `spectrumState.merge` does.
  - `quickscan_scanning` is added only while true.
  - The quick-scan BSS list still refreshes `scan_table` through `KeepSeen`.
- `wifi.go`: `health` returns early while a spectrum band is SCANNING (§8.7). REV2: it waits for the band instead of skipping (§8.7); `bss`/PING are unaffected by a scan [M T7].
- `config.go`: `observe_scans` (bool). Never built: the key does not exist.

### 11.4 Fixtures: `internal/wl/testdata/spectrum/`

- The directory does not exist yet. Copy the cleaned captures in from the scratchpad, split per file into `<name>.chanim.txt` (the `chanim_stats all` block) and `<name>.scanresults.txt` (from the first `SSID:` line). Put the timing and client header lines (`TAG`, `SCAN`, `IDLE`, `AC`) into `README.md`.

| Fixture | From | Use |
|---|---|---|
| `wl0_passive_p200` | `e5_wl0_passive_p200.txt` | main expected values (home ch9 `txdur 58`) |
| `wl0_passive_default` | `e6_wl0_passive_nop_r2.txt` | second pass for the two-pass fold |
| `wl0_passive_p110` | `e4_wl0_passive_p110.txt` | |
| `wl0_passive_p50_a`, `_b` | `e3.txt`, `e7_wl0_passive_p50_r2.txt` | fallback-sweep values |
| `wl0_active` | `e2.txt` | shows why active is rejected |
| `wl0_passive_first` | `e1.txt` | the "empty" case. The saved file has 11 records, so also add a synthetic `chanim_empty.txt` (header only: `version: 3`, `CHAN Interference Measurement:`, `Stats during last scan:`). |
| `wl1_*` | **missing**, from T1 | 5 GHz rows and 80 MHz blocks; until then use synthetic 5 GHz records |

REV2: the directory now exists with the e1-e7 files and the `t*` captures, unsplit, each with a pre- and post-call `chanim_stats all` (README.md documents the line formats). Split them in the Go test helpers rather than on disk, so the captures stay as taken. Fixtures to add from them:

| Fixture | From | Use |
|---|---|---|
| `wl1_chanim_empty` | `t0_baseline.txt` (wl1) | the **real** empty case: `version: 3` and nothing else, **no** "Stats during last scan" header [M]. The synthetic `chanim_empty.txt` above has the header, which the device never printed. |
| `wl1_sweep_p110` | `t1_wl1_passive_p110_r1..r3.txt` | 9 records; 36-48 fresh, 149-165 ZERO; r2's 0xd0a1 noise-only change |
| `wl0_c_single`, `wl1_c_single` | `t2_wl0_single.txt`, `t2_wl1_single.txt` | per-call before/after: target + home control rewrite; 149 near-empty record (glitch 8) |
| `wl1_c_unii3` | `t2_wl1_unii3_single.txt` | 153-165 unchanged ZERO; all-zero home rewrite after `-c 157` |
| `wl0_c_hex` | `t2_wl0_hex_rejected.txt` | exit 254 text |
| `wl0_c_home`, `wl1_c_home` | `t8_home_control.txt` | home control call: BSS list, no chanim change |
| `wl0_chunked`, `wl1_chunked` | `t4_wl0_chunked.txt`, `t4_wl1_chunked.txt` | the full fake-runner script for the end-to-end plan tests (22 / 18 calls, real pre/post chanim per call) |
| `cca_get_stats` | `t5_cca_variants.txt` | `parseCCAGetStats`; the exit-255 text for another channel |

### 11.5 Tests

Expected numbers are from `design/model.py` on the fixtures. The `Nhome = -97` constant is the measured `wl noise`.

`internal/wl`:
- `TestParseChanimRecords`:
  - p200 gives 11 records; 0x1009 has `TxDur 58, Obss 12, Nocat 7, Nopkt 10, Noise -71`.
  - The empty fixture gives `ok=true` with 0 records.
  - REV2: `wl1_chanim_empty` (`version: 3` only, no header) also gives `ok=true` with 0 records [M t0]. `ok=false` is kept for output without the `version:` line.
  - Garbage gives `ok=false`.
- `TestChannelUtil`:
  - p200 ch9 → **29**, not 88; ch1 → 30; ch5 → 3.
  - Fold p200+default: ch9 → 37 ((29+44)/2 = 36.5 with Go `math.Round`; `model.py` printed 36 because Python rounds half to even), ch1 → 28.
- `TestBSSPower`:
  - 20 MHz BSS at -65 on ch1, measured into ch2 → -66.2 (15/20 overlap).
  - 40 MHz BSS at -50 on 0x1907 into ch5..9 → -53; into ch3 and ch11 → -56; into ch1 → none.
- `TestChannelInterference`:
  - p200 → ch1 -65, ch2 -59, ch5 -53, ch9 -53, ch11 -56.
  - With no BSSes and no raised noise → -97.
  - A synthetic record with noise -80 on both passes and no BSS → -80. With noise -80 in only one pass → -97.
- `TestBuildRows`:
  - REV2: the na cases below that include 149-165 (`{36: 5210, 149: 5775}`, "9 rows including 165") stay, but as a **synthetic** unit where 149-165 measure; the .205 expectations are in `TestMeasureSpectrumZeroRecordIsUnmeasured`.
  - ng/20 → 11 rows, `center_freq` 2412..2462.
  - ng/40 → 7 rows (1→2422 .. 7→2452), each `utilization = max` of its pair.
  - na/80 (synthetic) → exactly {36: 5210, 149: 5775}.
  - na/20 → 9 rows including 165.
  - A missing ch44 at na/80 → `ErrIncomplete`.
  - Row order is ascending by channel.
- `TestClampWidth`: na 160 → 80; ng 80 → 40; 0 → 20.
- `TestMeasureSpectrumChunked`: the fake runner serves per-call chanim built by filtering p200 to the scanned chanspec. Assert:
  - the call sequence is `scan -t passive -p 110 -c 0x1001`, polls, then `chanim_stats all`, ×11 ×2 passes, pass 2 reversed;
  - REV2: the argument is `-c 1` (decimal), not `-c 0x1001` [M T2]. Better: drive it from `wl0_chunked` (the real T4 per-call reads) and assert `Mode == "chunked"`, 22 calls, ch9 classified from 20 home rewrites with `u` 30 (mean 29.65), and rows 1..11 = u 18, 6, 10, 5, 4, 20, 6, 11, 30, 21, 11 (`math.Round`); interference -69, -59, -56, -54, -53, -53, -53, -53, -50, -54, -56 (with `Nhome` -93 as in that file's `HDR`).
  - `Guard` runs 22 times;
  - sleep requests are ≥ 400 ms between calls;
  - `Mode == "chunked"`.
- `TestMeasureSpectrumFallsBackToSweep`: the first per-channel chanim lacks the record twice. Expect one switch to two whole-band `scan -t passive -p 50` calls, and the mode is remembered for the radio.
  - REV2: the trigger is the first **two non-home, non-ZERO** channels STALE after retry, or a non-Busy error from `-c`; the sweep is `-p 110`. Add `TestMeasureSpectrumHomeControlNotStale`: with `wl0_chunked`, the ch9 call's unchanged record must **not** trigger a retry or the fallback (the old rule did [M T4]). Add `TestMeasureSpectrumHexRejectedFallsBack`: a fake `-c` that exits 254 → sweep.
- `TestMeasureSpectrumBusyRetry`: "wl: Busy" twice, then OK.
- `TestMeasureSpectrumGuardAbort`: the guard errors on call 5. Expect `ErrScanAborted` and that `wl -i wl0 scanabort` was sent.
- `TestMeasureSpectrumBudget`: the clock hook passes 45 s. Expect an abort and `scanabort`.
- `TestMeasureSpectrumChanspecRestored`: a different `chanspec` after the band → error, flagged abnormal.
- VERIFIER: `TestMeasureSpectrumStaleRecordIsMissing`: the fake runner returns the same full 11-record chanim before and after every `-c` call. Expect retry, then the switch to the sweep, and never rows built from the unchanged records.
- VERIFIER: `TestMeasureSpectrumZeroRecordIsMissing`: a record with crsglitch 0, bad plcp 0 and all cca 0 (the shape of the wl1 fixture's 0xd095 record) → missing → band incomplete (`ErrIncomplete`), never `utilization 0`.
  - REV2: replaced by `TestMeasureSpectrumZeroRecordIsUnmeasured`: ZERO → **unmeasured** (not missing), no row for that channel or any block containing it, band succeeds if other rows remain, never `utilization 0`, no fallback. With `wl1_chunked`: na/20 → exactly 36, 40, 44, 48; na/40 → 36 (u 8, -72), 44 (u 4, -78); na/80 → exactly {36: 5210, u 8, -72}; 13 calls, not 18 (pass 2 skips 149-165).
  - REV2: `TestUnmeasuredIsSticky`: pass 1 gives 149 a near-empty record (glitch 8, nopkt 1, from `wl1_c_single`), a later call gives ZERO → 149 unmeasured for this band and the next, even if the next band's records for 149 look OK.
  - REV2: `TestZeroBeatsFreshness`: 0xd0a1 changed only in noise (-100 → -101, `wl1_sweep_p110` r2) → ZERO.
  - REV2: `TestHomeRewriteZeroDropped`: an all-zero home rewrite (`wl1_c_unii3`, after `-c 157`) is not folded into `H`; fewer than `MinHome` accepted rewrites → home control channel missing → `ErrIncomplete`.
  - REV2: `TestBuildRowsHomeFromRewrites`: home block row's `utilization` equals the max of its parts with the home part from `H`.
  - REV2: `TestAllUnmeasuredFails`: every channel ZERO → band fails, old table kept.
- VERIFIER: `TestChannelInterference` additions: a record with `txdur 58` and noise -71 gives no `N_elev`. `N_elev` is relative to the sweep's chanim baseline (§4.2 VERIFIER).
- VERIFIER: `TestBSSPower` addition, if the primary rule in §4.2 is adopted: a 40 MHz BSS at -50 with primary 9 gives ch9 → -50 and ch5 → -53. This replaces ch9 in the "ch5..9 → -53" expectation above, and `TestChannelInterference` p200 ch9 becomes -50.

upstream's `openwrt` package:
- `TestSpectrumRowsNineKeys`: every row has the 9 keys and `interference_type` marshals to `[]`.

`cmd/udeco-ap`:
- `TestQuickScanNa80`:
  - after `quick-scan:na:80`, the na row has 2 rows of width 80, all 9 keys, `spectrum_table_time` 0 and `spectrum_scanning_abnormal` false;
  - the ng row is untouched;
  - `quickscan_scanning` is present during the scan and absent after;
  - `spectrum_scanning` is false throughout;
  - there were two immediate informs.
- `TestQuickScanFailureKeepsTable`: the age keeps growing, `abnormal` becomes true, and the rows are unchanged.
- `TestManualSpectrumClearsAndRefills`: both radios cleared at start, rows at 20/40/80, `spectrum_scanning` true during.
- `TestQuickScanSkippedWhileRunning`.
- `TestScanDeferredOnAirtime`: the airtime fake returns 0.5 three times → 3 deferrals, then a scan with `HomeGap` 1 s.
- VERIFIER: `TestOwnAirtimeUsesWallClock` (`internal/wl`): two `chanim_stats us` rows 2 s apart by the clock hook, whose `total_tm` differs by 1 004 000 µs and `tx` by 300 000 µs. Expect 0.15, not 0.30.
  - REV2: now the fallback path. Primary: `TestOwnAirtimeFromCCAGetStats` on `t5_cca_variants.txt` wl0 → mean ibss (8+9+5+5+6)/5 = 6.6 % → 0.066; exit 255 or no row → fallback.
- REV2: `TestCollectDuringScanKeepsHomeChanspec`: while a band holds the lock, `Collect` reports the band-start chanspec, never the fake's scan channel `1 (0x1001)` [M T7].
- `TestClientDropAborts`.
- `TestWirelessUplinkSkipsRadio`.
- `TestObserveModeNoScanUnlessOptIn`.
- `TestRFTablePersist`: same `boot_id` → restored with the right age; other `boot_id` → ignored; an unwritable dir → scan still succeeds.
- `TestHealthSkippedDuringScan`. REV2: renamed `TestHealthWaitsForScan` (§8.7).

---

## 12. Device tests before relying on the [A] parts

Run these on .205 (wired uplink). Reads plus `wl scan`/`scanabort` only. Keep the §8 abort rule by hand. Store the outputs in `internal/wl/testdata/spectrum/`.

| # | Question | Procedure | Pass criterion |
|---|---|---|---|
| T1 | Does a 5 GHz host scan fill wl1 chanim, and with one record per 20 MHz channel? | `wl -i wl1 scan -t passive -p 110`, then `chanim_stats all`, ×3 | 9 records 0xd024..0xd0a5 with cca fields. If 80 MHz records appear instead, §5 needs a per-block path. |
| T2 | Does `-c <chanspec>` work, and does it leave a record for that chanspec only? | `wl -i wl0 scan -t passive -p 110 -c 0x1001`, then `chanim_stats all`; repeat for 0x1006 and on wl1 0xd024 | one record matching the chanspec, with the cca fields filled |
| T3 | Off-channel time of a single-channel call | beacon-count method of `scanexp.sh` around one `-c` call | ≤ 150 ms off. Beacons per call ≥ the expected count minus 3. |
| T4 | Full chunked plan, client impact | the §3.2 plan on wl0 and on wl1, with a client streaming video on each band | no drop. Video glitch noted. Totals inside 13-15 s / 11-12 s. |
| T5 | Is `cca_get_stats -c 0 -s N` a cheaper or better source? | run it, beacon-count to see whether it leaves the channel; compare ibss/obss/interf with chanim | Informational only; switch sources only if it measures off-channel and is stable. |
| T6 | Does chanim still fill with acsd2 stopped? | on a takeover unit (or after acsd2 is stopped under takeover) repeat T2 | records appear |
| T7 | Does `wl bss` read `up` and hostapd answer ping during a scan call? | read them during T3 | if yes, §8.7 can be dropped |
| T8 | Does a home-channel record via `-c <home control>` stay on channel? | T3 on 0x1009 while home is 9u | about 0 ms off (informational) |

VERIFIER additions to the tests above:
- **T1 and T2**: take a `chanim_stats all` snapshot **before** each call as well, and pass only if the `cs` record **changed**. "A record is present" is not enough (§3.2 step 4). For T1, also require crsglitch > 0 on every record. The repo's wl1 fixture already has 9 records, with 149-165 all zero.
- **T4**: run it with a client on **wl1** as well. There is no 5 GHz client evidence today (§2.3). Include a voice or video call on each band, not only a bulk stream. Also record ch5-8 `nocat + nopkt` with and without a client streaming on wl02 (the §4.1 hypothesis).
- **T9 (new)**: repeatability. Run the chosen plan 5 times, 5 min apart, and report the per-channel spread of `utilization` and `interference`. Pass if the rank order of 1/6/11 (2.4 GHz) and 36/149 (5 GHz, 80 MHz) is stable in at least 4 of 5 runs. This settles `Passes` (§3.2).

REV2: status after the 2026-11-18 session (`spectrum-measurements.md`):

| # | Status | Result | Design change |
|---|---|---|---|
| T1 | **ran** (×3) | 9 records, one per 20 MHz channel; 36-48 fresh every run; 149-165 always ZERO | 5 GHz split into measured / unmeasured (§2.1, §3.2, §5, §6) |
| T2 | **ran** | hex `-c` rejected (exit 254); decimal works; a call writes the target **and** the home control record; UNII-3 never | decimal `-c`; home rewrites; ZERO class (§3.2) |
| T3 | **ran** (8 reps × 4) | 119-145 ms mean, up to about 0.24 s; 5 GHz active client: retries 5-20×, 2 tx failures | 0.25 s worst case; fewer 5 GHz calls (§3.2, §8.3) |
| T4 | **lite** (once per radio, no controlled stream, 2 passes only) | 12.9 s / 11.0 s, 20 % / 16 % duty, no drop, no tx failure; home stale and UNII-3 ZERO under the old rules | timing kept; data rules changed (§3.2). **Still open:** voice/video, controlled stream, §4.1 ch5-8 hypothesis, 2 vs 4 passes |
| T5 | **ran** | `cca_get_stats` = stored home samples, 20 ms, never off-channel; `-c <other>` exit 255 | airtime gate input (§8.1); not a spectrum source |
| T6 | **not run** | - | still [A] (§10) |
| T7 | **ran** (175 polls) | `bss` up, PING PONG throughout; `wl chanspec` shows the scan channel; sweep returns home every 2 channels | §8.7 serialise instead of skip; collector chanspec; §2.3 / §3.3 sweep shape |
| T8 | **ran** | `-c <home control>`: ~0 ms off, BSSes returned, **no chanim write** | home call kept for BSSes only (§3.2) |
| rx | **ran** | `phy_rxiqest` = one instantaneous snapshot; `phy_rxiqest_sweep` refused (exit 233) | §4.2 settled on scanresults RSSI |
| T9 | **not run** | - | `Passes` stays 2 [A]; now also compares 2 vs 4 passes with a busy 5 GHz client |
| `scanabort` | **not run** (forbidden by the session rules) | - | §8.2 / §8.6 abort path untested |

REV2: new test:
- **T10: is UNII-3 deaf or empty on .205?** Put a known BSS on 149 or 157 (a phone hotspot, or another AP at a known distance) and run `wl -i wl1 scan -t passive -p 110 -c 149` ×3, then `chanim_stats all`. Pass (receiver works, chanim just does not record): the BSS is listed at a plausible RSSI. Then `P_bss` for 149-165 is real, but `utilization` is still unavailable, so the rows stay omitted. Fail (no BSS): the radio cannot hear UNII-3 at all; treat it as a hardware limit, and raise with the channel-plan owner whether the optimiser should be allowed to put this radio on 149-165 (§13.1). Also repeat T1 on a second X20 (.241 or .232) to see whether UNII-3 ZERO is per-unit.

Controller-side tests that only a live controller can settle are in CE §11. The ones that change this design:
- Q2: missing rows → whether to emit rows for channels the radio cannot use.
- Q3: width 80 in reply to a 160 request.
- Q5: whether own airtime counts in `utilization`.

---

## 13. Risks and open points

- **5 GHz is entirely unmeasured** (T1, T2). If wl1 chanim does not fill, the 5 GHz band fails cleanly (abnormal, no table) until another source (T5) is designed in. No fabricated rows are sent.
  - REV2: resolved for 36-48 [M]. Replaced by: **UNII-3 is unmeasurable on .205** by every source tried (chanim via sweep and `-c`, `cca_get_stats`, `phy_rxiqest`, `phy_rxiqest_sweep`) [M]. The 5 GHz table covers the 36 block only, and the optimiser gets no data on 149-165.
- **The aggregation choices (max) and the overlap power model** are reasoned, not compared against a real AP on the same RF. A U6-Lite or U6 Pro beside a Deco at the 03:00 window would calibrate both.
- **The e1 "empty chanim" report conflicts with the saved file** (§2.1). The retry path covers either case.
  - REV2: the real empty case is now captured (wl1 at session start: `version: 3`, no header) [M t0]; parsing it as `ok=true`, 0 records is pinned (§11.5).
- **The 30 % airtime gate, the 400 ms home gap and the 110 ms dwell** are judgement calls. T4 should confirm them on a real call or stream.
- **Discovery at 110 ms** is better than at 50 ms, but a weak BSS can still be missed in both passes. That only lowers `interference` on that channel when nothing else overlaps.
- VERIFIER: **stale or placeholder chanim records** are the most likely silent failure. They produce a plausible table that never changes, or a clean-looking UNII-3. They are covered by the §3.2 step 4 rules and the new tests.
- VERIFIER: **row stability.** Two passes give one-night swings of about ±20 points on busy 2.4 GHz channels. Without T9 the optimiser may move channels on noise.
- VERIFIER: **the `interference` column depends on our own mesh siblings** (§2.2, §4.2). Whether that helps or hurts depends on the controller's weighting, which is unknown (CE §11 Q1).
- VERIFIER: **missing inputs.** `docs/deco/spectrum-measurements.md` and `internal/wl/testdata/spectrum/` do not exist yet. Every [M] claim above rests on the scratchpad files in "Sources", which can be wiped. §11.4 (copying them in) is a prerequisite, not a follow-up.
  - REV2: resolved. Both exist; the e* and t* captures are in the repo (untracked as of this writing; `docs/deco/` and `internal/wl/testdata/spectrum/` still need committing).
- REV2: **every [M] comes from one unit, one firmware, one 20-minute session, with acsd2 alive and light, uncontrolled client traffic.** The home-rewrite behaviour and the UNII-3 placeholders in particular are undocumented driver behaviour; a firmware update could change either. The ZERO / STALE / `MinHome` checks make such a change fail loudly (band incomplete or fallback) rather than publish wrong rows.
- REV2: **a near-empty placeholder can pass both record rules** (149: glitch 8, nopkt 1). The sticky unmeasured set and the "OK in every pass" rule cover the cases seen; two near-empty records in the first band after a restart would still publish a 149 row at about 1 % [A].

### 13.1 REV2: what is still assumed

Measured now and no longer assumed: 5 GHz chanim filling (36-48), `-c` semantics and syntax, per-call off-channel time, sweep shape, home-control behaviour, `bss`/PING during scans, `chanspec` aliasing, `cca_get_stats` and `phy_rxiqest` behaviour, T4 timing and the absence of drops in one run per band.

Still [A]:
1. **Why 149-165 read zero**, and whether no BSS there means "empty" or "deaf" (T10). Whether other X20 units or firmware behave the same.
2. **What window a home-control rewrite covers** (probably home time since the previous scan). Only its agreement with two other home reads is measured.
3. **`Passes` = 2** gives stable enough rows (T9; one T4 run showed a 17-point pass-to-pass swing on ch10). 2 vs 4 passes is undecided.
4. **`HomeGap` = 400 ms** and **`CallMax`, `MinHome`**: values chosen, not tuned. T4 shows 400 ms did no harm in one run; T3 shows per-call harm on 5 GHz that does not obviously depend on the gap.
5. **Chunked beats sweep for clients on 5 GHz**: argued from duty and home time; no head-to-head run with a busy 5 GHz client.
6. **Voice/video impact** of either shape (no call or stream was available), and the §8.1 option to defer on low-airtime real-time traffic.
7. **Airtime gate**: the 30 % threshold, and `cca_get_stats` `ibss` = own airtime under load.
8. **Client-drop rule** (≥ 60 s association, 2 s window after a call, one free drop): designed from measured churn, not tested against it.
9. **`utilization` = obss + nocat + nopkt**, no rescale, our own traffic left out; whether the controller expects own airtime (CE §11 Q5).
10. **`interference` model**: even spreading over the BSS width, full RSSI on the primary, the `N_elev` +10 dB threshold, counting sibling Decos, and the bias of a home row that excludes our own BSS.
11. **Block aggregation = max** for both fields (CE §9 says mean; no real-AP comparison).
12. **Omitting rows** for channels the radio cannot use *or* cannot measure, and how the controller reads a missing row (CE §11 Q2). If the optimiser can pick the 149 block blind, only the channel-plan layer can stop it; this design does not.
13. **`abnormal` stays false** for a table that omits unmeasured channels (CE §5 meaning unknown).
14. **chanim filling with acsd2 stopped** (T6), the `Busy` retry path, and `scanabort` (never run).
15. **Health check and collector serialisation** is a design choice; T7 only shows that `chanspec` aliases during a call.
16. **Width clamp, state machine, storage, observe mode** (§6.2, §7, §9, §10): unchanged and untested by this session.

---

## Implementation (build)

Built 2026-11-19 inside `internal/wl` only (no device touched; `cmd/udeco-ap`, upstream's `openwrt` package unchanged). The `go doc` of `wl.SpectrumRunner` has the full API comment.

**Files.** `spectrum.go` (runner, gate, guard, band lock), `spectrum_calc.go` (pure: records, classes, §4 formulas, blocks, rows, `cca_get_stats` parser), `spectrum_test.go` + `spectrum_calc_test.go`. Small edits: `collect.go` (current-channel reads go through `readCurrent`), `wl.go` (Collector fields; `scanMu` is now a ctx-aware lock with the same `Lock`/`Unlock`), `caps.go` (keeps each radio's chanspec list for blocks).

**API.**
```go
r, _ := col.Spectrum(ctx, "na")               // one runner per radio, kept for the Collector's life
res, err := r.Run(ctx, wl.SpectrumRequest{
	Widths: []int{80}, OwnBSSIDs: own, Uplink: snap.UplinkName,
	Manual: false, SkipGate: false, Guard: nil, OnPhase: func(wl.SpectrumPhase) {},
})
res.Rows[w]  // []wl.SpectrumRow: channel, width, center_freq, total_samples 0, interference,
             // utilization, perf_index 0, interference_type [] (never null), other_bss_count 0
res.Status   // Phase idle|pending|scanning, Manual, Abnormal, TableTime, last good Rows; Age(now)
res.Diag     // Mode, Fallback, HomeChanspec/Control/Noise, Baseline, |H|, Calls, Channels
             // (class, samples, cca means, P_bss, N_elev, n_ctl), Unmeasured, Omitted, BSS, Drops
r.Status(); r.ClearTable()                    // manual spectrum-scan clears both radios first
col.OwnAirtime(ctx, radio, homeControl, window)
col.WithoutScan(ctx, fn)                      // §8.7 health check: runs fn when no scan runs
```
Errors: `ErrScanAborted` (ctx, Budget, client drop, Guard), `ErrIncomplete` (a needed channel missing), `ErrNoRows` (a requested width has no row), `ErrChanspecChanged` (§3.4), `ErrRadioSkipped` (wireless uplink or dwds peers; table and `abnormal` untouched). Any other failure also keeps the old table and sets `Abnormal`.

**Verified by tests on the real captures** (`go test -race ./internal/wl/...`):
- `t4_wl0_chunked.txt` replayed call by call: 22 calls `scan -t passive -p 110 -c <decimal>`, ≥ 400 ms home before each, no retry, no fallback, ch9 from |H| = 20 rewrites. Rows 1..11: u 18, 6, 10, 5, 4, 20, 6, 11, 30, 21, 11; interference -69, -59, -56, -54, -53, -53, -53, -53, -50, -54, -56 (§2.2 REV2). 40 MHz: 18, 20, 10, 11, 30, 21, 11 (§5 REV2). 24 BSSes.
- `t4_wl1_chunked.txt` replayed: 13 calls (pass 2 skips 149-165), 149-165 unmeasured, no fallback. 20 MHz 36/40/44/48: u 2/8/2/4, interference -78/-72/-78/-78; 40 MHz 36 (8, -72), 44 (4, -78); 80 MHz 36 (5210, 8, -72).
- e5: u ch9 29, ch1 30, ch5 3; e5+e6 ch9 37, ch1 28; interference ch1 -65, ch2 -59, ch5 -53, ch9 -50, ch11 -56. T1 r2 0xd0a1 is ZERO; T2's 149 near-empty record passes both rules; T2 `-c 157` leaves an all-zero home rewrite. `cca_get_stats` (T5): wl0 0.066, wl1 0.012, summary-only 0.06, rc 255 → fallback.
- Synthetic fakes: sticky unmeasured set across bands, STALE re-read and one retry, fallback trigger, hex-style rejection → sweep, mode remembered, Busy retry, guard / budget / cancel / client-drop aborts with `scanabort`, CallMax, chanspec mismatch, all-ZERO band fails with the old table kept, Collect during a band reports the band-start chanspec and never reads `wl chanspec`.

**Differences from §11 (decided while building).**
- Per-radio `SpectrumRunner` instead of `Collector.MeasureSpectrum`; rows are `wl.SpectrumRow` (9 keys) because upstream's `openwrt` package was out of scope (`SpectrumRow.Entry()` gives the 5-key `openwrt.SpectrumEntry`). `Associated` is internal to the client guard. `ScanPlan` has no `Chunk`; it adds `StaleReread`, `BusyRetry/BusyTries`, `SweepGap`, `SweepMax` (5 s, [A]), the gate and client-guard numbers.
- The gate runs `cca_get_stats -c 0 -s 5 -i` (`-i` gives the per-second rows the §11.5 0.066 case needs); without rows it uses the Summaries row.
- The §3.3 STALE trigger fires as soon as the first two candidates are decided (after the second one's retry), not after every retry of pass 1.
- `scanresults` "Not Found" counts as done only after the dwell. `scanabort` is sent on any error after the first call, but not after "Busy" (that scan is acsd2's) and not for row errors after a finished band.
- While a band runs, Collect also reports the band-start `noise` and `txpwr_target_max` and leaves the channel-use survey unchanged (no `chanim_stats us` read).
- Busy after 3 retries fails the band (§3.2 did not say). A failed `-c <c_h>` call is noted and ignored.
- Review fix: only wl's own non-zero exit on `-c` is the §3.3 trigger. A `wl scan -c` killed at the per-call timeout (`signal: killed`) or never started (fork/exec) fails the band with `scanabort` instead, so a transient exec failure cannot leave the radio in sweep mode (about 80 % duty) until restart (`TestScanCallNotAnswerIsNotFallback`).
- Review fix: if the gate already deferred for load and the next airtime read fails, the band runs with `BusyHomeGap` (1 s), not the 400 ms gap (`TestGateFailureAfterDeferralKeepsSlowPlan`). With no deferral before the failure it still scans without the gate.

**Not done here (open).**
- `Scan` still builds `ScanResult.Spectrum` (`TestScan` unchanged) because `cmd/udeco-ap` still reads it; drop it when the agent switches to the runner (§3.6). The legacy `Scan` does not register with the band lock, so a `cmd scan` can still alias `wl chanspec` for Collect.
- §8.5 DFS/CAC skip (no `dfs_status` capture), the diagnostics `P_bss` without site BSSIDs (§4.2 VERIFIER), and everything in `cmd/udeco-ap` (§7 state machine, storage, `quickscan_scanning`, observe opt-in).
- All §13.1 assumptions still hold; nothing here was run on a device.

---

## MT7603 off-channel sweep (jio-mtk, 2026-11-20)

The JioFiber JCOW414 (`"platform": "jio-mtk"`, the Garage AP) reports a real 2.4 GHz `spectrum_table` from the MT7603's own off-channel scan, behind the same `wl.SpectrumRunner` as the Deco's bands (`wl.NewSpectrumRunner` with a `wl.SpectrumBackend`; `internal/mtkwifi/offchan.go`). Everything in `cmd/udeco-ap` is shared: quick-scan per band at `scan-bw`, manual spectrum-scan at every width with the tables cleared first, `quickscan_scanning` / `spectrum_scanning`, `spectrum_scanning_abnormal`, `EVT_AP_QuickScanEvent`, the saved tables (`specsave.go`, `/flash2/udeco/state/spectrum.json`). It runs only with `site_survey` (the key that already means "the controller's scans run on this unit"). The MT7663 (5 GHz, built into the kernel) has no `ApOffChanScan`; its band has the driver's own off-channel request instead, behind the same runner (next section).

**Mechanism** [Ghidra of `mt7603eap.ko`; M live 2026-11-20 with `mtkprobe`].
- `ApOffChanScan=passive:<ch>:<ms>` (private ioctl `0x8BE2`, in process on an `AF_INET` datagram socket; `struct iwreq` 32 bytes) visits `<ch>` for one dwell (u8 ms, 10 ms timer) and returns to the home channel. It never changes the operating channel or restarts the AP [M: the radio stayed on 6; a client pinged through a 13-visit sweep at 100 ms]. A channel off the driver's list is refused (ChannelSanity: no visit, no log line, and the ioctl fails with `EINVAL`: the handler returns 0, which `RTMPAPPrivIoctlSet` maps to `-EINVAL`); the unit's list is 1..11. Its "Network is down" return reads as success with no visit.
- At the end of the dwell `UpdateChannelInfo` reads MIB `0x2c048` Prim CCA Time (read-clear, 24 bits, µs) and stores `score = max(0, 100 − busy/4000)` with the channel in the slot of its list index. The counter runs from its last read, so `show mibinfo` (`0x8BF1`, the only reader; it also prints ~40 kernel-log lines and clears the other MIB counters) clears it right before each visit [M: ~1.2 ms before the request; busy matched the driver's debug print within 2.4 ms on four channels: ch1 24 ms, ch6 40, ch10 44-46, ch11 68-70 of 200].
- OID `0x2014` (`0x8BE1`, flags `0x2014`) answers 444 bytes of u32 LE `{score, channel}` pairs by list index (slots are not reset between visits; channel 0 = never filled; past the list: heap garbage). Set-OID `0x8999` (flags with bit 15) copies the channel list as 28-byte records `{channel, index, …, dfs at 0x18}` [UNVERIFIED live]; without it the sweep uses 1..11 plus what `0x2014` names at its own index.
- Kernel log at the module's own debug level (`RTDebugLevel` starts at 2 in `mt7603eap.ko`'s `.data`; nothing on the unit changes it): `ApSiteSurveyNew_by_wdev channel_index:<i> channel:<ch> time:<ms>` when the request is queued (any level), and `time_diff:<t> Busytime:<x> AvgNF:<dBm>` from `UpdateChannelInfo` at the end of the dwell (level ≥ 2; level ≥ 1 in the rebuilt `mt7603roam`, where only `Debug=0` silences it [M 2026-11-23: printed at the default level and at `Debug=1`, more than 1 s after the request]) [M 2026-11-20 03:4x: `passive:1:50` printed exactly `ApSiteSurveyNew_by_wdev channel_index:0 channel:1 time:50` and `time_diff:44 Busytime:7017 AvgNF:-89`, and the radio stayed on 6]. `t` is the ms since `ScanNextChannel` armed the dwell timer, + 1, as a u8; the timer is `ms/10` jiffies (`RTMP_OS_Add_Timer`: `ms × 100 / 1000`, HZ 100), so it fires more than `(ms/10 − 1) × 10` ms in, plus the MLME's delay (44 at 50 ms). `Busytime` is `AsicGetCCANavTxTime`, not the score's unit [M: 8789 next to a 24.4 ms score]: unused. The line is printed only while the ScanCtrl state is 1 or 2, which `Set_ApOffChanScan_Proc` sets in the ioctl itself (state 1, one channel, before `ApSiteSurveyNew_by_wdev`), never for a full-band survey, and `APScanTimeoutAction` restores the radio to its configured channel right after it in the same call. It names no channel and no radio. `Set_ApOffChanScan_Proc` is the start line's only caller: every other scan (`SiteSurvey=1`, ACS, the driver's own scans) goes through `ApSiteSurvey` and prints nothing at level 2. An off-channel scan of more than one channel (never ours) prints `Next OFFChannel scan for : …` at any level as it moves on. At level 3 there is more: `start offchannel scan on <ch> : channel list index = 0` (`APMlmeScanReqAction`), `channel <ch> busytime <B>` and `SYNC - End of SCAN, restore to <bw>MHz channel <home>` (`scan_ch_restore`) [M at level 3: once per visit; absent at the default level]. A scan already running when the request comes takes it over (`Set_ApOffChanScan_Proc` does not check for one): the MLME drops our request (`APInvalidStateWhenScan`), and the running scan's next channel timeout sees the off-channel state, ends the scan with our list index, writes its own busy time into our slot labelled with our channel, and prints one `time_diff`, timed from the last real off-channel dwell's start (stale: any value, a fitting one too), before restoring the radio. At level 2 that is our start line and exactly one `time_diff` [A: Ghidra of `Set_ApOffChanScan_Proc`, `APScanTimeoutAction`, `UpdateChannelInfo`; not seen on the unit]; at level 3 there is no `start offchannel scan` for it. Its end comes when the running scan's channel timer fires: within 140 ms of the request plus the MLME's delay for every scan but ACS (`set AutoChannelSel`, or the periodic check with a check period set and no station associated: 400 ms a channel). A channel off the list is refused with `EINVAL` [M: `passive:13:50` → `set (8BE2): Invalid argument`].
- Every visit runs `BssTableInit` (clears the driver's neighbour table): the neighbour survey runs after the sweep.

**One band.** Under the collector's scan lock: home channel (iwconfig) and width (profile `HT_BW`), the channel list, then one visit per channel with a visit start every 1 s (about 11 s for the band; 200 ms dwell). Before each visit: the agent's guard (observe mode, an apply or rollback, a TP-Link hold), the restart gate (`DriverRead`, held for that visit only) and the radio being up; any of them stops the band (old table, `abnormal`). Before each visit, ahead of those checks: the kernel log since the sweep's last read (all of it before the first band) must hold no off-channel scan the agent did not start: no start line of any channel or radio and no `Next OFFChannel scan` line (every one of the sweep's own lines is in a visit's log, and the agent starts no other scan while it holds the scan lock), and the last visit's log no other scan's line. Else that scan may still run and would take the visit over: the sweep waits 2 s (one `ApOffChanScan` visit is 255 ms at most; a list scan prints a line per channel) and looks at what came in the wait: nothing, and it goes on (the wait is in the diag notes); more, and the band stops. Each visit: the request's buffer built, pre-clear, request (nothing between the two syscalls), and, only without `/dev/kmsg` (below), an early kernel-log read 20 ms before the dwell could end (`(dwell/10 − 1) × 10` ms after the request: 190 ms at 200), the log again at dwell + 250 ms (re-read until the dwell's end shows), iwconfig, slot read; the visit's log is everything after the pre-visit read (anchored). An end line (`time_diff`, or `End of SCAN`) after our start line by the early read is not our dwell's: a running scan took the request over, and its value can fit ours; the visit is untrusted, as is one whose early read ended too late to tell (the longest is in the diag notes). After it ends, the radio's channel (iwconfig) must still be the band's home, or the band stops (`ErrChanspecChanged`): iwconfig gives the configured channel, which a visit never changes, so this catches an AP restart or a channel change; the radio's return itself rests on the `time_diff`, after which `APScanTimeoutAction` restores it in the same call. Trusted only with exactly one start line of the band for the channel and dwell, then exactly one `time_diff` line and none before it, its time from `(dwell/10 − 1) × 10` to dwell + 60 ms (the timer's last jiffy and the MLME's delay; mod 256), no other scan's line (another channel's start line, a `channel:0` one, a 5 GHz one: the `time_diff` line names no radio; a `Next OFFChannel scan` line), the level-3 lines, when present, agreeing (one `start offchannel scan` for it, one `End of SCAN` after it, none before; never required), no MIB block but the pre-clear's (another `show mibinfo` clears the counter mid-dwell), at most 10 ms from the pre-clear's start to the request's return (the longest is in the diag notes), and the slot of the start line's index naming the channel. A request that started no visit is untrusted, not refused; only `EINVAL` with no start line is a refused channel, and any other ioctl error stops the band. A start with neither a `time_diff` nor an `End of SCAN` within 2 s more stops the band (the visit's end is unknown); that is also every band at a debug level below 2. An `End of SCAN` on another channel stops it too (`ErrChanspecChanged`). Otherwise an untrusted visit (including one taken over by a running scan) is retried once after the last channel; still untrusted, the channel is missing and the band fails (`ErrIncomplete`) before the survey. A refused channel is unmeasured (no row, nor any block containing it). Then the fresh site survey, a last channel check, and `mibGap` (the next 2.4 GHz `cu_total` reading is skipped, as after a survey). Collect keeps its last reading while the band runs, and the band waits for a Collect already reading the driver before it starts (its `show mibinfo` would clear the counter in the first dwell).

**Takeover by the kernel's times** [M 2026-11-25]. The early read never worked on the unit: the `klogctl` read of the whole ring, started 20 ms before the dwell's earliest end, took 21-135 ms on the MIPS core, so it always ended after 190 ms and every visit was untrusted (no 2.4 GHz table was ever made). `/dev/kmsg` (the agent's own node `/tmp/udeco-kmsg` where the firmware has none) gives every record the kernel's µs time at print. For the band the sweep reads it beside the visits (`kmsgstamp.go`), keeps the start and `time_diff` lines, and for each visit measures the time from its start line (printed in the request's ioctl) to the first end line after it. Under `dwellEarliest` is a takeover (untrusted, retried), as the early read judged; the early read is then not made. With no record of both within 500 ms the visit is untrusted. Without `/dev/kmsg` the early read decides, as before. Live: 11 visits, all trusted at the first try, `time_diff` 191-197 at 200 ms; the controller got 18 rows.

**Rows** (§4-§6 shapes; only 20 MHz visits are made):
- `utilization` = busy / dwell in %, busy = (100 − score) × 4 ms (2 % steps at 200 ms). Off the home channel this is other networks' use (and non-Wi-Fi energy above CCA). On the home channel the radio is in scan mode (beacons stopped by `AsicDisableSync`, its own transmissions suspended by `RTMPSuspendMsduTransmission`), but our own clients may still transmit in the dwell [A]. As §4.1 leaves our own traffic out, the home visit's busy time loses our stations' receive airtime as the collector last estimated it (`staRx`, µs a second from the station byte counters and rates, used when under 2 min old and not invalidated by an apply) × the dwell; the diag notes say how much. It is an estimate of a 10 s average applied to 200 ms, so a burst in the dwell still shows; the home block's secondary channel at 40 MHz gets no correction (the §4.1 open hypothesis).
- `interference` = clamp(round(max(−95, P_bss(c))), −110, −20) (§4.2 without `N_elev`: the driver gives no per-channel noise; −95 is the stand-in noise floor Collect also reports), with `P_bss` from the post-sweep survey, our own BSSIDs left out.
- 40 MHz: a row per lowest channel c whose c + 4 is listed (1..7 on 1..11), centre c + 2, values the **max** of the two 20 MHz parts (§5).
- `interference_type` `[]`, `other_bss_count`, `perf_index`, `total_samples` 0, as the Deco.

**Not caught:** a running scan that prints no line and whose channel timer fires after the early read: only an ACS scan (400 ms a channel, above) can. One that takes a visit over at the default level ends it with a `time_diff` in the dwell's window roughly one time in six, and its busy time is trusted for that channel. The `time_diff` lines carry no time and the stale value cannot be told from ours without knowing the last real dwell's start.

**Not verified on the unit:** a visit taken over by a running scan (from the decompile only; two dwells cut short, `time_diff` 25 and 64, were seen in a sweep of 2026-11-25), and the `0x8999` list reply. Verified 2026-11-25: a sweep driven by the agent, `time_diff` 191-218 at the 200 ms dwell, and the table at the controller (`stat/spectrum-scan`).

## MT7663 off-channel visit (jio-mtk, 2026-11-24)

The 5 GHz band of the JCOW414 has its own `RadioDef.Spectrum` kind, `chaninfo` (`internal/mtkwifi/offchan5.go`), behind the same `wl.SpectrumRunner`: quick-scan, spectrum-scan, the saved tables and the events are the shared code's.

**Mechanism** [Ghidra of the kernel's `mt_wifi` MT7613_JCO4032_MESH V6.0.2.0 (`vmlinux`); M live 2026-11-24 with the `off5probe` tool and 2026-11-25 by the agent].
- The request is set-OID `0x955` (ioctl `0x8BE1`, flags `0x8955`), 160 bytes: `[0]` `0x22` (off-channel scan), `[1..16]` the interface, `[36..40]` up to five channels, `[41..45]` their scan types (`0x80` passive), `[46..50]` their dwells (u8 ms), `[52]` u32 LE how many (below 6). `RTMPAPSetInformation` hands it to `Channel_Info_MsgHandle`, which queues an off-channel scan of the list (`ApSiteSurveyNew_by_wdev`: `TakeChannelOpCharge`, beacons stopped, `BssTableInit` clearing the neighbour table). The ioctl returns 0 whether a visit starts or not.
- At each channel's end the driver sends an IWEVCUSTOM event on rtnetlink (`RTMGRP_LINK`), flags `0x955`, 160 bytes: `[0]` `0x23`, `[1..16]` the interface, `0x24` channel, `0x25` its index in the driver's list (255: not in it), `0x28` s32 noise floor (the band's running average, the same for every channel: not used), then u32 LE µs: rx `0x2c`, tx `0x30`, OBSS `0x34`, channel busy `0x38` (MIB `0x2d048` Prim CCA time, read-cleared as the visit starts), `0x3c` a DFS flag, `0x3d` the dwell the driver measured (u8 ms). [M: 200 ms asked, 191-206 measured; the radio was on its own channel after every visit.] The driver's one-second `ReadChannelStats` reads `0x2d050`, `0x2d098`, `0x2d09c`, not the busy counter; the agent's own 5 GHz reading is `show bgndscaninfo`, paused while the band runs.
- A dwell can come back short: DFS channel 52 after 2 ms every time [M]; ch 36 and ch 161 each once in a sweep [M 2026-11-25].
- **A stuck driver** [M 2026-11-24]: the radio's CNTL state machine sat in `CNTL_WAIT_DISASSOC` (at debug level 4: `cntl_mlme_error_handle [rai0 ]: [CNTL_WAIT_DISASSOC][CNTL_MLME_SCAN] ... ERR`) and dropped every off-channel request with no event, and every `SiteSurvey=1` too: the controller had only ch 149 neighbours from about 06:47 that day. A restart of the 5 GHz radio cleared it. Cause [A 2026-11-25]: the driver aged an FT key holder (R1KH) entry of a station that was still associated, and disassociated it through the AP's CNTL machine, which has no disassoc confirm and so never left `CNTL_WAIT_DISASSOC`; that day's agent counters had five KDP 0x52 (aged entry) signals. Since v0.3.4 the agent keeps the entries from aging (garage-ft.md, Key holder entries that age).

**One band.** Under the collector's scan lock: home channel and width, the agent's channel list for the band (`bandChannels`: 36-48 and 149-165, with `dfs` 52-64 too), an rtnetlink socket of its own (the agent's event listener ignores `0x955`), then one passive 200 ms visit per channel, a visit start every 1 s; before each the guard, the restart gate and the radio up, as on 2.4 GHz. A visit is the request and its event (this interface, this channel) within the dwell + 1.5 s. No event: retried once after the last channel, then missing (`ErrIncomplete`). No event at all in the first pass: the band stops (`errNoChanInfo`, naming the stuck driver). A measured dwell under half the asked one: retried; short again, the channel is unmeasured (no row, nor any block holding it). Then the fresh site survey and the home-channel check. Live: 9 visits and the survey in about 12 s.

**Rows.** `utilization` = busy / the measured dwell, in % (our stations' estimated uplink taken off the home channel's, as on 2.4 GHz); `interference` from the survey's neighbours over the −95 stand-in; 40 and 80 MHz rows for the `rf.Blocks5G` blocks whose 20 MHz channels are all listed (36, 44, 149, 157 at 40; 36, 149 at 80), the max of their parts (§5).

**Survey settle.** After the visits the 5 GHz survey table never stayed the same: the MT7663 rewrites a listed BSS's RSSI from the beacons it hears, and the table differed at nearly every 500 ms read for over 50 s [M], so the survey ran to the band's 1-minute budget. `freshSurvey` now settles on the neighbours listed (BSSID, channel, SSID: `surveyKey`), not their levels; the whole table was there 2 s after `SiteSurvey=1` [M].
