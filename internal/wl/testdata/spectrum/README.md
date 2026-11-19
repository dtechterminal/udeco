# Spectrum test captures (Deco X20 V2, 192.168.0.205)

Raw captures behind `docs/deco/spectrum-design.md` and `docs/deco/spectrum-measurements.md`. All from one unit on 2026-11-18. wl0 = 2.4 GHz (home `9u`, 0x1907), wl1 = 5 GHz (home `40/80`, 0xe12a), country US.

**Privacy.** SSIDs are replaced by `h:` + the first 8 hex digits of their md5 (`SSID: ""` = hidden). Vendor IEs are dropped. Neighbour BSSIDs are kept. In the `t*` files, client MACs are hashed on the device: `m:` + 8 hex of md5 of the upper-case MAC. The older `e*` files show the client's first three octets (OUI) only.

## Line formats

- `TAG <name> radio=<wlX> args=<wl scan args>`: one experiment.
- `HDR <wlX> chanspec=.. noise=.. up=..`: `wl chanspec`, `wl noise` (dBm) and `/proc/uptime` at that point.
- `AC <uptime> <vif>=<n>[ <client> ... ]`: association snapshot of wl01, wl02, wl11, wl12, wl13. In `t*` files each client is `m:<hash>/in=<in network s>/txB=<tx total bytes>/rxB=<rx data bytes>/txfail=../retry=<tx pkts retries>/rssi=<smoothed rssi>` (from `wl -i <vif> sta_info`). In `e*` files it is `<OUI>/<in network s>`.
- `SCAN rc=<wl scan exit> t0=<uptime before> t1=<uptime when scanresults answered> beacons=<txbcnfrm delta over t0..t1> polls=<50 ms scanresults polls>`.
- `IDLE t2 t3 beacons=`: beacons sent over an idle ~2 s window right after, for the idle rate. Off-channel time ≈ (rate·(t1−t0) − beacons) / rate.
- `BSSCOUNT n`, then `--- scanresults` and the `wl scanresults` text.
- `--- chanim_stats all <wlX> t=<uptime>`: one `wl -i wlX chanim_stats all` read. In `t*` files there is one before and one right after each scan call, so freshness can be checked per record.

## Files

### Earlier session (wl0 only, whole-band sweeps)
Each holds: `AC`, `TAG`, `SCAN`, `BSSCOUNT`, `IDLE`, then `--- chanim_stats all` (read about 3 s after the scan), `AC`, scanresults. No pre-scan chanim snapshot.

| File | Scan | Sweep | Beacons | BSSes | Notes |
|---|---|---|---|---|---|
| `e1.txt` | wl0 `-t passive` (default dwell) | 2.52 s | 6 | 20 | first host scan; 11 records (the "empty list" report is not borne out by this file) |
| `e2.txt` | wl0 active, default | 0.39 s | 2 | 12 | `txdur`/`inbss` raised on foreign channels: why active is rejected |
| `e3.txt` | wl0 `-t passive -p 50` | 0.76 s | 4 | 13 | fallback-sweep shape |
| `e4_wl0_passive_p110.txt` | wl0 `-t passive -p 110` | 1.56 s | 6 | 18 | |
| `e5_wl0_passive_p200.txt` | wl0 `-t passive -p 200` | 2.54 s | 8 | 24 | main design fixture; home ch9 `txdur 58` |
| `e6_wl0_passive_nop_r2.txt` | wl0 `-t passive` | 2.50 s | 6 | 20 | repeat of e1 |
| `e7_wl0_passive_p50_r2.txt` | wl0 `-t passive -p 50` | 0.75 s | 6 | 11 | repeat of e3; its records were still in wl0 chanim ~1 400 s later (`t0_baseline.txt`) |

### This session (§12 tests)

| File | Test | Content |
|---|---|---|
| `t0_baseline.txt` | baseline | reads only: AC, both radios' chanspec/noise, acsd2 pid, `bss` of every user vif, `chanim_stats all` on wl0 (still the e7 records) and wl1 (empty). |
| `t1_wl1_passive_p110_r1.txt` .. `_r3.txt` | T1 | wl1 `scan -t passive -p 110`, chanim before/after, scanresults. 36-48 records fresh each run; 149-165 always all-zero placeholders. |
| `t2_wl0_hex_rejected.txt` | T2 | wl0 `scan -c 0x1001` / `-c 0x1006`: rejected by `wl` (exit 254, "could not parse chanspec"); nothing scanned, chanim unchanged. |
| `t2_wl0_single.txt` | T2/T3 | wl0 `-c 1` and `-c 6`, 110 ms passive. Target record + home control 0x1009 change; 0 beacons during each 0.14 s call. |
| `t2_wl1_single.txt` | T2/T3 | wl1 `-c 36`, `-c 149`, `-c 48`. Target record + home control 0xd028 change; 149 gets a near-empty record (glitch 8). |
| `t2_wl1_unii3_single.txt` | T2/T3 | wl1 `-c 149`, `153`, `157`, `161`, `165`, 7 s apart. Only 0xd028 changes (149 reverts to all-zero); no BSS on UNII-3. |
| `t3_wl0_offchannel.txt` | T3 | wl0, 8 reps each of `-c 1` and `-c 6`: `W idle` and `W scan` 1.0 s windows (`beacons` = txbcnfrm delta, `done` = uptime when scanresults answered). AC before/after each block. |
| `t3_wl1_offchannel.txt` | T3 | same on wl1 with `-c 36` and `-c 149`. |
| `t3_idle_reference.txt` | T3/T4 | two AC lines 60 s apart with no scan: per-client idle retry/byte rates for comparison. |
| `t7_bss_hostapd_during_scan.txt` | T7 | `P` lines every ~30 ms during 3 × wl0 `-c 1`, a wl0 sweep, 3 × wl1 `-c 36`, a wl1 sweep: `bss`, `isup`, hostapd PING, `wl chanspec` (shows the scan channel and the sweep order). |
| `t8_home_control.txt` | T8 | wl0 `-c 9` and wl1 `-c 40` (home control channels): `run1` with chanim before/after (no record changes), `t7` poll (chanspec stays home), 8 × `t3` beacon windows (no beacons lost). |
| `t5_wl0_cca_get_stats.txt` | T5 | wl0 `cca_get_stats -c 0 -s 5`: summary for ch9 only; `P` lines = background `wl chanspec` polls during the call (home throughout); chanim before/after unchanged. |
| `t5_cca_variants.txt` | T5 | wl0 `-c 0 -s 5 -i` (per-second rows), wl0 `-c 1 -s 5` (rc 255, "Only 1 channel input"), wl1 `-c 0 -s 5 -i` (ch40 only), wl1 `-c 36 -s 5` (rc 255). |
| `t5_chanim_read_stability.txt` | T5 | 40 × `chanim_stats all` per radio, 0.25 s apart, no scan: record count and md5 of each read (all identical), then one full wl1 read. |
| `trx_wl_help.txt` | received power | live `wl -h` text for `phy_rxiqest` and `phy_rxiqest_sweep`. |
| `trx_rxiqest_default.txt` | received power | per radio: current `chanim_stats` (`knoise`, `chan_util`), 5 × `phy_rxiqest` (default options) with `wl noise` and `chanspec` (`IQ` lines), beacon count, current `chanim_stats` again. |
| `trx_rxiqest_sweep_home.txt` | received power | wl0 `phy_rxiqest_sweep -c 9`, wl1 `-c 40` (home control only): exit 233 `error`; `P` lines = background chanspec/bss polls; beacons; AC. |
| `t4_wl0_chunked.txt` | T4 | §3.2 chunked plan on wl0: `START_SET` (hashed client MACs guarded), then per call `CALL k pass= ch= rc= t= done= polls= bss=`, compact `BSS <bssid> <rssi> (<chanspec>)` lines and a full `chanim_stats all`; `BAND` line (duration, beacons, abort reason). Its trailing `_idleref` block slept only 1 s (script bug); use `t4_wl0_idleref.txt`. |
| `t4_wl0_idleref.txt` | T4 | 13 s scan-free window right after the wl0 band: AC before/after and beacons (254). |
| `t4_wl1_chunked.txt` | T4 | same plan on wl1 (36-165), plus its 11 s scan-free `_idleref` window. |
| `t_final_state.txt` | all | reads only after all tests: AC, both home chanspecs restored, acsd2 still pid 12001, every user vif `bss up`, no test file left in the device's `/tmp`. |

## Helper scripts (session scratchpad, not in the repo)
`spec2/pre.sh` (device-side shell functions: `ac`, `ca`, `run1`, `t3`, `t4`, `t5`, `t7`), `spec2/rr.sh` (ssh + SSID hashing via `spec/clean.pl`), `spec2/ca.py` (per-record changes between chanim reads), `spec2/t3.py` (beacon-window off-channel), `spec2/acd.py` (per-client deltas), `spec2/t4.py` (per-call freshness/zero verdicts and rows). They can be wiped with the scratchpad; the captures here are self-describing.

### 2026-11-19 (country IN, DFS listed)

| File | Test | Content |
|---|---|---|
| `t9_wl1_dfs_in.txt` | DFS | reads only (`## <command>` sections): wl1 `country` IN, home `40u`, `noise`, `scan_passive_time` 200, `chan_info` (52-64 "RADAR Sensitive, Passive"), `chanspecs` (20/40 only), `chanim_stats all` after the 03:30 spectrum-scan whose na band stopped on 56 (STALE in pass 2); 52/60/64 all-zero, 56 `cca_obss 1` with glitch 0. Basis of `spectrum_dfs_test.go`. |
