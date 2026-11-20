# What the UniFi controller expects from spectrum_table and scan_table

**Scope.** This note covers what the controller asks for in an RF scan, what a real AP sends back, and what the Deco X20 agent (`udeco-ap`) should send so that nightly channel optimisation ("Optimize Network" / Channel AI) and the RF environment page work well. Everything here comes from local files only. No device or network host was contacted, and no Go code was changed.

**Evidence labels.**
- **VERIFIED**: read directly in a local file (file:line given), or in the U6 Pro JSON captures.
- **SECONDARY**: taken from our own earlier notes on the decompiled controller (`docs/internals.md`). The decompiled jar (Network 10.6.109, `internal-dependencies.jar`) is **not** on this machine, so these notes could not be checked again.
- **INFERENCE**: my reading of the evidence. Not proven.

**Main limitation.** The controller's channel-scoring code (how it weighs utilisation, interference and neighbours, and what thresholds it uses) is **not available locally**. Nothing here shows the optimiser's formula. Section 11 lists the tests that would settle it.

Paths are relative to `~/udeco/docs/reference/u6pro/` unless stated otherwise. `AS/` is short for `actions-scans/`.

---

## 1. Summary

1. **The nightly job is `cmd quick-scan`, sent once per band.** It carries `scan-band` (0 = 2.4 GHz, 1 = 5 GHz, 2 = 6 GHz) and `scan-bw` (MHz). It is sent at 03:00, 5 GHz first. The 2.4 GHz command arrives about 1 s after the AP's inform with the finished 5 GHz table is acknowledged. (VERIFIED)
2. **Rows: one row per channel or block, at the requested width only, covering every channel in the country table at that width, DFS included.** On the U6 Pro (country IN) that gave 13 rows on 2.4 GHz at 20 MHz and 6 rows on 5 GHz at 80 MHz (36/52/100/116/132/149). Channel 165 had no row. (VERIFIED)
3. **`interference` is a received power in dBm that rises with interference.** On an empty block it drops to about the noise floor: -96 on block 132, where scan_table also shows noise -96. On busy 2.4 GHz channels it reads -50 to -64. **It must not be the noise floor on every row.** (VERIFIED values; the exact definition is INFERENCE)
4. **`utilization` is the percentage of time the channel was busy during the scan dwell.** (VERIFIED as a percent, from the `Utilization = %d%%` string; what counts as "busy" is INFERENCE)
5. **On the nightly path, a real AP sends `perf_index`, `total_samples` and `other_bss_count` as 0 and `interference_type` as `[]` on every row.** So the optimiser cannot need non-zero values there. Send the same. (VERIFIED)
6. **`spectrum_table_time` is the age of the table in seconds, per radio.** An 18-hour-old table (`66142`) is normal at rest. (VERIFIED)
7. **Status flags.** `spectrum_scanning` (top level) is `false` at rest. `spectrum_scanning_abnormal` (per radio) is `false` at rest. mcad also has a top-level `quickscan_scanning` key that is absent at rest. (VERIFIED from strings and the dump; when `quickscan_scanning` is sent is INFERENCE)
8. **scan_table hardly matters to the optimiser.** At rest, the real AP's scan_table lists only BSSes on its **own** operating channel, so it cannot tell the optimiser anything about other channels. scan_table feeds the rogue-AP and neighbour lists. The field-name gaps (`is_ubnt`, `ap_name`, `noise`, `rssi_age`) matter for those lists, not for channel choice. (VERIFIED own-channel only; "does not matter for the optimiser" is INFERENCE)

---

## 2. What the controller sends

### 2.1 `cmd quick-scan` (nightly optimisation)

- VERIFIED, `AS/syslog-mcad-syswrapper.txt:7-14` (Nov 17) and `:59-66` (Nov 18):
  ```
  03:00:00 [quick-scan] band/bw: 1 80  -> Scanning wifi1 (bw=80, vap=wifi1ap1)
  03:00:12 [event-reportok] complete spectral scan, resetting
  03:00:13 [quick-scan] band/bw: 0 20  -> Scanning wifi0 (bw=20, vap=wifi0ap0)
  03:00:38 [event-reportok] complete spectral scan, resetting
  ```
  - Each band took 12-14 s on 5 GHz (6 blocks at 80 MHz) and 25-27 s on 2.4 GHz (13 channels).
  - On both nights, the next band was requested 1 s after `reportok`.
- VERIFIED, mcad strings `AS/strings-mcad.txt:1769-1774`: `quick-scan`, `[quick-scan] skipped: already in progress`, `scan-band`, `scan-bw`, `[quick-scan] band/bw: %d %d`, `airtime-scan`.
- VERIFIED, the AP side: `AS/fw/usr/bin/syswrapper.sh:2679-2686` (`airtime-scan`) runs `mtk_quick_airtime_scan` on MediaTek and `ath_quick_airtime_scan` otherwise. The QCA version (`AS/fw/usr/etc/platdep_funcs.sh:502-597`):
  - touches `/var/run/quickscan.start`;
  - maps band 0/1/2 to radios by `2g/5g/6g_maxchwidth`;
  - keeps the existing `/var/run/rftable_<radio>` (writes `{}` only when the file is empty, `:574-575`);
  - runs `ubntquickscan -i <radio> -j <vap> -y <bw>`, with bw 240 rewritten to 320 on band 1 (`:589-593`).
- **`scan-bw` is the controller's choice, not the radio's operating width.** The 5 GHz VAP ran at 160 MHz (`wifi1ap1 bw 160`), yet the controller asked for 80, and the 2.4 GHz VAP ran at 20 and the controller asked for 20. (VERIFIED from one site.) That the controller caps 5 GHz quick-scan at 80 MHz is INFERENCE.
- **Sequencing.** mcad logs `complete spectral scan` only when the inform carrying the new rftable is acknowledged (`AS/strings-mcad.txt:1637-1639`, `:1680` for the failure case). The controller then sends the next band.
  - INFERENCE: the controller waits for the finished report before sending the next band. An agent that never reports a fresh table probably stalls the run after the first band.
  - No controller-side timeout value is known.

### 2.2 `cmd spectrum-scan` (manual "RF scan" button)

- VERIFIED: the payload is `spectrum-cfg` plus `infinite` (`AS/strings-mcad.txt:1775-1782`). mcad writes it to `/tmp/spectrum.cfg`.
- VERIFIED: `spectrum_scan` (`platdep_funcs.sh:416-470`) resets every radio's rftable to `{}` and runs `ubntquickscan -i wifiN -j vap -a`, where `-a` means "Scan all supported bandwidths" (`AS/strings-ubntquickscan.txt:195`).
  - So a manual scan legitimately returns rows at **several widths** (20/40/80/160).
  - A nightly quick-scan returns rows at **one width**.
- VERIFIED: mca-monitor resets on `spectral scan timed out` / `abnormal end` (`AS/strings-mcad.txt:748-755`).

### 2.3 `cmd scan` / `scan_band` (neighbour scan)

- These feed scan_table, not spectrum_table: `ath_scan` uses `iwlist` (active) or `ubntrfclient -f` (passive, `platdep_funcs.sh:270-300`).
- VERIFIED: mcad skips scan cmds on a mesh downlink (`skip scan cmd due to AP is downlink`, `AS/strings-mcad.txt:1767`).

---

## 3. spectrum_table, field by field

Real rows: `AS/rftable_wifi0.txt`, `AS/rftable_wifi1.json`, `AS/mca-dump.redacted.json`, `mca-dump.json` and `mca-dump-all.json`. All three dumps carry the same rows. The key order in the rftable file is `channel, width, center_freq, total_samples, interference, utilization, perf_index, interference_type, other_bss_count`.

| Field | Type / unit | Real values (U6 Pro, nightly quick-scan) | Meaning | Label |
|---|---|---|---|---|
| `channel` | int | 2.4 GHz: 1..13. 5 GHz: 36, 52, 100, 116, 132, 149 | 2.4 GHz: the 20 MHz channel. 5 GHz: the **lowest** 20 MHz channel of the block (36 for 36-48). | VERIFIED |
| `width` | int, MHz | 20 on ng, 80 on na | Equals the `scan-bw` asked for | VERIFIED |
| `center_freq` | int, MHz | 2412..2472, then 5210, 5290, 5530, 5610, 5690, 5775 | Centre of the whole block, not of the primary channel | VERIFIED |
| `utilization` | int, % | ng 26..54. na 2..48 (36: 11, 149: 48, 132: 6) | Share of the dwell on that channel or block during which the medium was busy | VERIFIED as %. INFERENCE: busy means CCA-busy from any source (other BSSes plus non-Wi-Fi energy). How a block is summed (mean or max of its 20 MHz parts) is unknown. |
| `interference` | int, dBm (negative) | ng -50..-64. na -59 (36), -81, -80, -89, **-96** (132), -86 (149) | Received power measured on that channel during the dwell. On a quiet block it falls to the noise floor (-96 equals scan_table `noise` -96). | Values VERIFIED. Definition INFERENCE: it comes from the QCA CBS survey `quick_scan_interf` (`AS/strings-ubntquickscan.txt:138, 142, 160`, `Interference = %d dBm`). It is **not** the noise floor: the same radio reports noise -96 and athstats `noise_floor` -95/-94. |
| `interference_type` | array of strings | `[]` on every row | The non-Wi-Fi interferer classes found. The only producer seen is the QCA spectral classifier in `ubntrfclient`, whose name strings are `None, Microwave, Bluetooth, DECT phone, Tone, Other` (`AS/strings-ubntrfclient.txt:616-621`), with detector messages for MWO/CW/WiFi/FHSS/BT (`:521-549`). | `[]` VERIFIED. The vocabulary that would go in the array is INFERENCE. |
| `other_bss_count` | int | 0 on every row | Probably the number of other BSSes on the channel. `ubntrfclient` has `ubnt_get_acs_nbss_number` and `acs_nbss_list` (`:350, 567, 577`). | 0 VERIFIED. Meaning INFERENCE. |
| `perf_index` | int | 0 on every row | Unknown. Probably a per-channel score from the full spectral or ACS path. | 0 VERIFIED. Meaning unknown. |
| `total_samples` | int | 0 on every row | Probably the number of spectral FFT samples behind the classification (`Spectral Classifier: Number of samples captured %zu`, `AS/strings-ubntrfclient.txt:420`). | 0 VERIFIED. Meaning INFERENCE. |

**Notes on the real numbers.**
- The 2.4 GHz `interference` values repeat across neighbouring channels: 1-3 read -52, 4-5 read -64, 6-9 read -53, 10-12 read -50, and 13 reads -57. The QCA survey seems to measure power over spans wider than 20 MHz (INFERENCE).
- Interference values are **stronger** than any neighbour BSS in scan_table (the strongest was -72 on channel 13 against interference -57). So `interference` is not "the strongest BSS RSSI in scan_table". scan_table holds only own-channel beacons, and part of the measured power may be non-beacon traffic or non-Wi-Fi energy. Without the driver source I cannot say which.
- The row schema seems to come from a shared libubnt routine, `prepare_spectrum_table_usi`. It appears in both `ubntquickscan` (`AS/strings-ubntquickscan.txt:73`) and `ubntrfclient` (`AS/strings-ubntrfclient.txt:88`), so every scanner writes the same 9 keys (INFERENCE).
- `ubntquickscan` also has a `%d_%d` format (`:212`). This is probably a `channel_width` key for merging rows into an existing rftable (INFERENCE).
- **What the controller reads (SECONDARY).** `docs/internals.md:761-764` lists `spectrum_table: [{channel, width, center_freq, utilization, interference}]` plus `spectrum_table_time`, served to the UI as `stat/spectrum-scan/<mac>`. No local note shows the controller reading `interference_type`, `other_bss_count`, `perf_index` or `total_samples`.
  - Because a real AP sends them as 0/`[]` on the nightly path, sending the same values is safe either way.
  - Send all 9 keys so that a parser expecting them does not fail. Whether the controller would fail without them is unknown.

### 3.1 The custom alert sent with the scan
VERIFIED: `ubntquickscan` builds a `mca-custom-alert.sh` call with `event_string`, `radio`, `radio_name`, `channel`, `width`, `center_freq`, `interference` and `utilization` (`AS/strings-ubntquickscan.txt:213`), and the string `EVT_AP_QuickScanEvent` sits next to `ubnt_send_event_to_net` (`:240-241`).
- INFERENCE: after a scan the AP pushes one event with the figures for its current channel. The controller may log it or show it as an event.
- Whether the optimiser needs it is unknown. It is optional for a first version.

---

## 4. Which rows to send

**What the real AP does (VERIFIED).** The rows match the AP's country channel table at the requested width:
- `active_chanlist` (from `mca-dump -g`, country IN) has `channels_ng` 1-13, which gave 13 rows at 20 MHz.
- `channels_na_80` has 36..161, whose 80 MHz blocks 36/52/100/116/132/149 gave 6 rows. DFS blocks (`channels_na_dfs`) are **included** (the radio reports `has_dfs: true`).
- 165 is in `channels_na` but in no 80 MHz block, so it has **no row** in an 80 MHz scan.
- The AP's own operating block (36-64 at 160 MHz, primary 40) is reported like every other block. It is not marked or left out.

**What the Deco X20 V2 should send** (country US, no DFS; DFS only under IN). INFERENCE, matching the real AP's behaviour:

| Request | Rows | `center_freq` |
|---|---|---|
| band 0, bw 20 | channels 1..11, width 20 | 2407 + 5·ch |
| band 0, bw 40 | if the controller ever asks: one row per 40 MHz pair the radio supports (the X20 lists 1l..7l / 5u..11u), keyed by the lower 20 MHz channel, centre = mean of the pair | the real AP was only ever seen at 20 here, so this is unverified |
| band 1, bw 20 | 36, 40, 44, 48, 149, 153, 157, 161, 165 | 5000 + 5·ch |
| band 1, bw 40 | 36 (5190), 44 (5230), 149 (5755), 157 (5795) | block centre |
| band 1, bw 80 | **36 (5210), 149 (5775)** | block centre |
| band 1, bw 160/240/320 | the X20 V2 has no 160 MHz. Answer with its widest blocks (80) and set `width: 80` truthfully | open question: see §11 |
| band 2 | no 6 GHz radio: no rows, and no change to `spectrum_table_time` | — |

**Channels the radio cannot use.** The real AP lists every channel its regulatory table allows and nothing beyond it. The DFS rows it sent are channels it can use.
- Do **not** invent rows for channels the Deco cannot use (52-144, 12-13 under US). The controller might pick a channel that has a row.
- If the site country or the emulated model (UAL6) lets the controller consider channels the Deco cannot use, the translate layer must clamp the channel the controller pushes. A row cannot prevent that choice (INFERENCE).
- Whether the controller treats a channel **without** a row as "unknown, skip" or as "assume clean" is not known. It is the most important thing to test (§11).

**Mixed widths.** Send only the requested width for a quick-scan. Sending 20 + 40 + 80 rows together, as `openwrt.Spectrum` does today, only matches the manual `spectrum-scan` (`-a`) path.

---

## 5. Timing and status fields

| Field | Where | Real value | Rule | Label |
|---|---|---|---|---|
| `spectrum_table_time` | each `radio_table[]` row | 66142 / 66155 at rest | **Age in seconds** of that radio's table: uptime minus `/var/run/rftable_<radio>.timestamp` (816096 − 749298 = 66798 matched the dump's 66799). Each radio has its own value, and it keeps growing until the next scan of that band. | VERIFIED (`study-actions-scans.md:128, 257`; `AS/rftable_wifi0.txt` tail `749298` / `815849.55`) |
| `spectrum_table` | each `radio_table[]` row | present at rest | Present while the rftable file exists. It is not cleared after reporting. | VERIFIED at rest. Behaviour right after a reboot (empty `/var/run`) is unknown. |
| `spectrum_scanning` | top level | `false` | `true` while an RF scan runs (SECONDARY, `docs/internals.md:763-764`). INFERENCE: it is tied to the manual `spectrum-scan` (`/var/run/spectrum-scan.start`). | |
| `quickscan_scanning` | top level | **absent** | The string sits next to `spectrum_scanning` (`AS/strings-mcad.txt:2425-2426`), and the marker `/var/run/quickscan.start` exists (`:1912`). INFERENCE: sent (true) only while a quick-scan runs. | |
| `spectrum_scanning_abnormal` | each `radio_table[]` row | `false` | INFERENCE: true after an abnormal or timed-out scan (`rftable_%s.abnormal` / `.pre_abnormal` markers, `AS/strings-mcad.txt:752-754`; `ubntrfclient` writes `.abnormal`). | |
| `rssi_histograms`, `suggested_channels` | each `radio_table[]` row | absent | Conditional. `suggested_channels` comes from `ubntrfclient` (`/var/run/rftable_best_channel_%s`, `AS/strings-ubntrfclient.txt:382-383`), meaning the AP's own suggestion from the full spectral path. Not sent on the nightly path. | VERIFIED absent. Meaning INFERENCE. |
| `scan_radio_table` | top level | `[]` | Leave it empty. | VERIFIED |

**Completion handshake.** This is what the agent must do so that the second band gets requested:
1. When `cmd quick-scan` arrives, reply at once and start the scan in the background. INFERENCE: optionally set `quickscan_scanning: true` while it runs.
2. When the scan finishes, replace that radio's `spectrum_table`, reset its `spectrum_table_time` to about 0, and **inform at once**. Do not wait for the next interval. mcad does this through the `rftable_%s.complete` marker and "complete spectral scan" (VERIFIED from the log order).
3. Keep each band's scan at a few tens of seconds. The real AP took 12-27 s per band.

---

**VERIFIED 2026-11-19 (Network 11.1.50, decompiled; agent-design.md "Storing on the controller").**
- Every inform: `spectrum_table` replaces the cached one only when non-empty and no quick-scan is in progress;
  `spectrum_table_time` (age) becomes `now - age` (epoch s) only when the inform carries it
  (`devmgr.gliBtHTTrWRd`, `DRUVu`). The cache keeps `spectrum_table` between informs, not its time
  (`devmgr.LJJVAQyQnWFEcts`).
- Saved to the database only by `EVT_AP_QuickScanEvent` (sets `spectrum_scan_timestamp` = now ms, upserts
  its row) or by the inform that ends a quick-scan (`quickscan_scanning` true -> false; the controller sets it true
  itself when it sends `quick-scan`, times it out after 10 min).
- `cmd spectrum-scan` (`devmgr.b.g.oViVvFSgD`) only sets `spectrum_scanning`; nothing ends it but the inform's
  `spectrum_scanning`.
- `stat/spectrum-scan/<mac>` = `scans` (per radio_table_stats row: name, radio, spectrum_table,
  spectrum_table_time) + `mac, spectrum_scanning, quickscan_scanning, quick_scan_state, spectrum_scan_timestamp`.
- The event arrives as an inform with `inform_as_notif: true`, `notif_reason: "event"`, `notif_payload` (object);
  the controller handles the top-level fields, dispatches the event, answers `noop` and skips the stats.

## 6. Stale, missing or failed tables

- VERIFIED: a real AP keeps sending an 18-hour-old table all day. So "stale" between nightly runs is normal, and the controller accepts ages of at least about 66000 s.
- VERIFIED: the quick-scan path keeps the previous rftable file until `ubntquickscan` writes over it (`platdep_funcs.sh:574-575`). Only the manual `spectrum-scan` resets it to `{}` first.
- If a scan fails, keep the previous rows and the previous (growing) `spectrum_table_time`. Do not send an empty table with a fresh time.
  - INFERENCE: a fresh empty table would tell the controller that nothing was measured just now.
  - `cmd/udeco-ap/scan.go` already keeps the old spectrum when a scan returns none.
  - Optionally set `spectrum_scanning_abnormal: true` until the next good scan (INFERENCE about what it means).
- What the controller does with no table at all, or with rows missing for some channels, is **not known**. No local controller code covers it. To be safe, always send a complete, consistent set (§4) for each radio once the first scan has run.

---

## 7. scan_table: does it matter for channel choice?

**What the real AP sends (VERIFIED, `AS/mca-dump.redacted.json`).**
- Every row has the keys `age, ap_name, band, bssid, bw, center_freq, channel, essid, freq, is_adhoc, is_ubnt, noise, rssi, rssi_age, security, signal`, plus `source:"beacon"` under `-g`.
- `rssi = signal − noise` held on all rows. `noise` is the radio's noise floor (-96).
- `rssi_age` is about 10× `age` (15→151, 18→186). It is probably deciseconds (INFERENCE).
- **Every row was on the AP's own operating channel**: all 12 rows on wifi0 had `channel` 13, and all 6 rows on wifi1 had `channel` 40.

**What the controller reads (SECONDARY, `docs/internals.md:752-760`).** `bssid, essid, channel, bw, freq, center_freq, rssi, signal, security, age, band, is_unifi, serialno`.
- Old rows are dropped.
- Non-UniFi rows younger than 30 s feed `stat/rogueap`.
- A non-UniFi row on a site SSID raises a rogue-AP alarm.
- `is_unifi` + `serialno` mark a sibling UniFi AP.

**Both key sets exist in firmware.** mcad has `is_ubnt` next to `scan_table` (`AS/strings-mcad.txt:1919-1920`) and also `is_adhoc, is_unifi, anonymous_network_application_id, serialno, fw_version` right after the scan-row keys (`:2264-2268`). INFERENCE: mcad adds `is_unifi`, `serialno` and related keys only for beacons that carry a UniFi vendor IE, and sends `is_ubnt` on every row.

**Does it matter for the optimiser?** INFERENCE: hardly.
- Since a real AP's scan_table covers only its own channel, the optimiser cannot use it to rank other channels. Per-channel information comes from spectrum_table.
- scan_table matters for: the rogue-AP alarm (site-SSID rows, sibling marking), the neighbour list in the UI, and possibly neighbour-AP counts on the current channel.
- **Gaps and what each one does**:
  - `is_ubnt` missing (we send `is_unifi`): low risk. The controller notes say it reads `is_unifi`/`serialno`. **Send both**: `is_ubnt` on every row, plus `is_unifi: true` and `serialno` on siblings.
  - `ap_name` missing: cosmetic (it was `""` on all real rows). Send `""`, or the sibling's name when known.
  - `noise` missing: the UI probably shows no SNR. Send the radio noise floor (from `wl noise` or chanim `noise`).
  - `rssi` formula: ours is `signal + 95`, the real AP's is `signal − noise`. Off by a few dB. Switch to `signal − noise` once `noise` is sent.
  - `rssi_age`: send `age × 10` (INFERENCE about the unit), or `age`.
  - Rows for channels other than our own: harmless as far as we know. They add to the neighbour and rogue list, which a real AP's background 11k scans also do.

---

## 8. MediaTek path (what a real U6-Lite runs)

- VERIFIED: `syswrapper.sh` picks `mtk_quick_airtime_scan` when `MTK_UAP=1` (`:22`, `:2682-2683`), and `spectrum_scan_clean` only on MT7615 (`:2693-2697`). **Neither function is defined in any local file.** They live in the MediaTek build of `platdep_funcs.sh`, which we do not have. `config-apply/scripts/` holds the same QCA copy.
- VERIFIED: the same mcad binary knows MT7603/MT7992/MT7981/MT7622/MT7615/MT7915 and keeps the markers `/var/run/rftable.start` and `/var/run/rftable_%s.complete` next to `/var/run/quickscan.start` (`AS/strings-mcad.txt:1904-1912`). It reads `/var/run/rftable_%s` with one code path for every platform (`:2174-2179`).
- INFERENCE: a U6-Lite receives the same `quick-scan` / `spectrum-scan` cmds and reports through the same rftable file and the same `spectrum_table` keys. What its MTK scanner puts in `interference` (power or noise) and `utilization` cannot be checked here.
  - This matters because we report as UAL6. If MTK units send noise-floor-like `interference`, the controller must cope with that too.
  - Settling it needs a U6-Lite firmware image (its `platdep_funcs.sh` and scanner binary) or a U6-Lite mca-dump.

---

## 9. What the Deco should send (recommendation, INFERENCE)

Aim: rows that **rank channels the way the radio sees them**. Every row should come from one scan with the same dwell, so that rows can be compared.

| spectrum field | Deco source | Notes |
|---|---|---|
| `utilization` | Per 20 MHz chanspec from `wl -i wlX chanim_stats all` after **our own** scan: `cca_obss + cca_nocat + cca_nopkt`, plus `cca_inbss + cca_txdur` only for channels other than our own. Alternatively `cca_get_stats -c <ch> -s <secs>` (ibss/obss/interf %). For an 80 MHz block: the **mean** of its four 20 MHz parts. Using the max instead is defensible; neither choice is verified. | Leaving out our own BSS airtime on the operating channel keeps our own clients from looking like interference. Whether the real AP includes it is unknown (§11). A 20 ms active dwell gives coarse percentages. Prefer a passive dwell of 100-200 ms, or several passes. |
| `interference` | **max(noise floor of that channel, strongest received power seen there)**. Noise floor = chanim `noise` or `wl noise`. Strongest power = the strongest `escanresults` BSS RSSI on that 20 MHz channel, or anywhere in the block. | Matches the real behaviour: quiet channels near -96, busy channels -50 to -70. **Never** send the chanim noise alone. Values of -91 to -108 spread across channels at random would mislead the ranking, which is the current bug (§10). |
| `interference_type` | `[]` | Same as the real nightly path |
| `other_bss_count` | 0 (the real AP sends 0). An honest count of BSSes per channel from escan is an option, but untested against the controller. | |
| `perf_index`, `total_samples` | 0 | Same as the real AP |
| `channel`, `width`, `center_freq` | §4 table | |
| `spectrum_table_time` | seconds since that band's scan finished | per radio |

Also: answer `quick-scan` per band with only that band's rows. Inform right after each band. Do not touch the other radio's table or time.

---

## 10. Where the current code differs (no code changed)

- `internal/wl/scan.go:78-89` → `upstream's openwrt/scan.go:368, 376-387`: `interference` is the chanim noise floor (block = the highest noise of its parts). Every channel looks interference-free, and random noise-floor differences decide the ranking.
- `upstream's openwrt/scan.go:366-395` (`Spectrum`): returns 20 MHz rows plus 40/80 MHz blocks together for every request. `scan-bw` is logged and ignored (`cmd/udeco-ap/actions.go:62-65`).
- `upstream's openwrt/scan.go:468-475` (`SpectrumRows`): sends only 5 of the 9 keys.
- `internal/wl/parse.go:292-298`: `utilization` = `txdur + inbss + obss + nocat + nopkt` from acsd2's or our "last scan" values. It is fine as a busy %, but it counts our own BSS on the home channel.
- `cmd/udeco-ap/scan.go:79` and `actions.go:65`: a quick-scan sets `spectrum_scanning=true`. `quickscan_scanning` and `spectrum_scanning_abnormal` are never sent.
- `cmd/udeco-ap/scan.go:103-107`: `spectrum_table` and its time are left out until the first scan. That is probably fine, since a freshly booted real AP has no rftable either; not verified.
- scan_table: `upstream's openwrt/scan.go:449-461` sends `is_unifi`/`serialno` and `rssi = signal + 95`, without `is_ubnt`, `noise`, `rssi_age` or `ap_name` (§7).

---

## 11. Open questions and the tests that settle them

1. **How the optimiser scores channels** (weights, thresholds, hysteresis, whether it uses `athstats.cu_*` history or client satisfaction). Needs the controller jar decompiled again: search the Network 10.6/11.x classes that read `spectrum_table` / `spectrum_table_time` / `quick-scan`, starting from the `UQKIrjV` / `DRUVu` notes in `docs/internals.md`.
2. **Missing rows.** Let the agent report rows for only some of the channels the controller allows (for example, none for 52-144 under country IN) and trigger "Optimize now". Does the controller skip those channels, pick them, or raise an error?
3. **Requested width above what the radio supports** (5 GHz `scan-bw` 160 against the X20's 80 maximum): does the controller accept `width: 80` rows in reply?
4. **Gating.** Does the next band's `quick-scan` wait on `spectrum_table_time` dropping, on `quickscan_scanning` going false, or only on the inform being acknowledged? A capture during the 03:00 window on the U6 Pro (decrypted inform payloads) would show which.
5. **Own-channel utilisation.** Does QCA `quick_scan_util` count the AP's own traffic on its home channel? Compare a U6 Pro row for its own block against `athstats.cu_total` / `cu_self_*` captured at the same time.
6. **What MTK reports.** A U6-Lite firmware or mca-dump, to see `interference` and `utilization` from `mtk_quick_airtime_scan`.
7. Whether `other_bss_count`, `perf_index`, `total_samples` and `interference_type` are ever non-zero on a firmware that runs a full spectral scan (`ubntrfclient`), and whether the RF environment page shows them.
