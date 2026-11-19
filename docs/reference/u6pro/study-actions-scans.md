# U6 Pro study: actions-scans

## Summary
I went through the U6 Pro at 192.168.1.32 read-only. It is BZ.8.8.14 on Qualcomm hardware (IPQ50xx "Maple" plus "Pine", the qca-wifi cfg80211tool/wlanconfig driver), not MediaTek. The script's MTK_UAP branches are for other models; a real U6-Lite would run them. One process, mcad, handles everything the controller asks for. It reads each inform reply by type (noop, setparam, cmd, upgrade, reboot, setdefault) and passes most actions to /usr/bin/syswrapper.sh. That script calls the driver through cfg80211tool, LEDs through /proc/gpio, and scans through ubntquickscan. Every action I traced has a shell path I could read and quote.

Five findings matter most:
1. The nightly 03:00 scan the controller really sends is `cmd quick-scan` with `scan-band`/`scan-bw`, which runs `syswrapper.sh airtime-scan`. Our session.go does not handle it.
2. The block list arrives as a top-level setparam field `blocked_sta` and is enforced in the driver's secondary MAC ACL.
3. Client isolation is the driver setting `ap_bridge 0`, not ebtables.
4. LED states are fixed pattern/tempo pairs; Locate is pattern 10 at 480 bpm.
5. Our scan_table uses `is_unifi`/`serialno`. The real AP sends `is_ubnt`, `ap_name`, `noise` and `rssi_age`, and its spectrum rows have extra fields.

All evidence is saved, redacted, under ~/udeco/docs/reference/u6pro/actions-scans/.

## Report
# U6 Pro: how controller actions and RF scans work (read-only)

**Device:** U6 Pro, BZ.8.8.14, kernel 5.4.213 armv7l. `/etc/board.info` gives `board.sysid=0xa650`, `radio.1.name=Maple` (ahb bus, 2.4 GHz `wifi0`) and `radio.2.name=Pine` (pci 17cb:1104, 5 GHz `wifi1`). The Wi-Fi stack is Qualcomm's qca-wifi (`cfg80211tool`, `wlanconfig`, `athstats`, NSS/ECM), **not MediaTek**.

I logged in as uid 0, so nothing needed sudo. I ran only reads (`cat`, `ls`, `strings` on local copies, `ubus -v list`, `ebtables -L`, `cfg80211tool <vap> get_*`, plain `mca-dump`). I did not run `mca-scan`, `mca-cli-op` or `syswrapper.sh`. The SSH login was refused once, probably because other sessions were logged in at the same time; the retry worked.

---
## 1. Processes and what each does

These come from `/etc/inittab` (written by ubntconf) and `ps w`.

| Process | Started as | Role (evidence) |
|---|---|---|
| **mcad** | `oom-protect -500 /usr/bin/mcad` (respawn) | **The inform agent.** Strings: `ace_reporter.reporter_handle_response_json`, `reporter_handle_setparam_json`, `cmd received (session): %s`. Local control socket `/tmp/.mcad` is used by `mca-ctrl`, `mca-cli`, `mca-cli-op` and `mca-dump` (mca.sh runs `mca-ctrl -t dump`). It handles setparam, cmd, upgrade, reboot and setdefault, and calls `/usr/bin/syswrapper.sh <action>`. |
| mca-monitor (= mcad) | watch | Watchdog. It soft-restarts or reboots on: `mcad.checkin` too old, setparam timeout, isolation too long, `[event] spectral scan timed out, resetting`. |
| uplink-monitor, reset-handler, mesh-monitor, element-adopt-monitor, redirector, radius-da-dispatcher | all symlinks to mcad | Uplink/mesh state (`/var/run/mesh.status`), reset button, guest-portal redirector, RADIUS CoA/DA. |
| **hostapd** | `/usr/bin/hostapd_wrapper.sh`, which runs `hostapd -s -g /var/run/hostapd/global` | A single global hostapd. VAPs are added with `hostapd_cli -i global raw ADD bss_config=<vap>:/etc/hostapd/<vap>.cfg` (unifi_hostapd_funcs.sh:297). The ubus objects `hostapd.<vap>` expose `del_client{addr,reason,deauth,ban_time}`, `rrm_nr_set`, `rrm_beacon_req`, `wnm_disassoc_imminent`, `bss_mgmt_enable` and `switch_chan`. |
| **wevent** (ubntbox applet) | respawn | Reads hostapd events from `/var/run/wevent_hostapd.sock` and logs lines like `wevent.ubnt_custom_event(): EVENT_STA_LEAVE wifi0ap0: <mac>`. Also sends L2-update frames and GARP on roam (`ui_l2uf_*`, `ui_garp_init`), runs a neighbour monitor and `rrm_scan`/`trigger_scan`, and sends station notifications to mcad. |
| **stahtd** (ubntbox) | watch | Station health tracker. Logs `[STA-TRACKER] {"message_type":"STA_ASSOC_TRACKER","event_type":"dns timeout",...}` and feeds the satisfaction anomalies that mcad logs (`log_sta_anomalies ... anomalies=dns_timeout`). |
| sysmon / sysmon_ctrl | watch | System monitor. `sysmon_ctrl -t factory_def` is used on reset. |
| autotxpow | watch | Automatic TX-power adjustment (`autotxpow_adjust_level`). |
| utermd | watch, TLS cert in /var/run | Remote debug terminal. mcad cmds `build-ssh-session`, `ssh-sdp-answer` and `close-ssh-session` (TURN/SDP) feed it. *Inference.* |
| upathmond | watch | Path monitor. Its ubus `pathmon status` result goes into the inform `pathmon` field. |
| ubntevent | started at boot | ubntbox applet; its exact role was not determined. |
| logread (x2) | respawn | Local `/var/log/messages`, plus encrypted remote syslog: `logread -f -u -r 192.168.1.1 5514 -h U6Pro -E <key> -P <mac>,U6-Pro-8.8.14+20179`. |
| mcsd | respawn | Multicast snooping (`mcsctl`). |
| lldpd, udhcpc, ntpd, dropbear | respawn | dropbear runs as `-p 22 -l br0`. |
| cnssdaemon, diag_lite_log | | QCA firmware support and logging. |
| blebrd, blebr2d, bleconnd, uanywhere-launcher (unifi-anywhere) | | BLE bridge/setup and remote access. |
| vap_check.sh | after provisioning | Sleeps 780 s, then sends a trace if any VAP's BSSID is 00:00:00:00:00:00. |

**Who does what:**
- **Inform and provisioning:** mcad. Provisioning goes through `syswrapper.sh apply-config /tmp/system.cfg`, which tries `do_fast_apply` first and otherwise runs `/usr/etc/rc.d/rc restart`. The config is turned into daemon files by `ubntconf` (inside ubntbox): inittab, passwd/shadow, snmp.conf and driver `cfg80211tool` calls.
- **Station management:** hostapd for auth, the driver for kick/ACL, wevent for events, stahtd for health.

---
## 2. How each action is implemented

### Controller reply types (mcad strings)
- `_type`: `noop`, `setparam` (`cfgversion`, `mgmt_cfg`, `system_cfg`, `blocked_sta`, `server_time_in_utc`), `cmd`, `upgrade` (`url`, `md5sum` or `sha256sum`, `use_fwupdate`, `fwupdate_options`), `reboot` (`[reboot] reboot`), `setdefault` (`[setdefault] reset to default`).
- `cmd` names found in mcad strings: `led-locate`, `set-locate`, `unset-locate`, `set-port-locate`, `kick-sta`, `block-sta`, `unblock-sta`, `authorize-guest`, `unauthorize-guest`, `dynamic-psk`, `rate-update`, `scan` (fields `freq`, `active`, `type`), `quick-scan` (`scan-band`, `scan-bw`), `airtime-scan`, `spectrum-scan` (`spectrum-cfg`, `infinite`), `scan_band` (`band`), `linkperf-start`/`-stop`, `set-meshv3-payload`, `mesh-halt`, `build-ssh-session`, `show-lcm-tracker`, `dhclient-renew-subnet`, `send-crashlog`, `get-support-file`, `pcap-start`/`-stop`, `relayctl`, `shellcmd`.
- **There is no `set-adopt` cmd in mcad.** `grep -c set-adopt strings-mcad.txt` returns 0. `set-adopt` exists only in syswrapper.sh.

### kick-sta
syswrapper.sh `kick-sta` calls `kick_sta` in platdep_funcs.sh:
```
for ath in $(list_vaps_all); do if is_vap_user_or_guest $ath; then cfg80211tool $ath kickmac "$1"; fi; done
```
- It only acts on VAPs whose `/var/run/vapusage.<vap>` is `user` or `guest`, never on uplink or mesh VAPs.
- Steering variants: `kick-sta-on <mac> <vap> <reason>` runs `cfg80211tool $vap kickmac mac reason`; `kick-sta-on-btmreq` uses BTM.

### block-sta / unblock-sta / the blocked list
syswrapper:
```
block-sta)   driver_kick_block_sta $1; add_mac /etc/persistent/cfg/blocked_sta "$1"; set_cfg_save
unblock-sta) del_mac /etc/persistent/cfg/blocked_sta "$1"; driver_unblock_sta $1
```
- `driver_kick_block_sta` runs `cfg80211tool $ath addmac_sec MAC` and then `kickmac MAC`. Unblock runs `delmac_sec`.
- The block list is the driver's **secondary** ACL, in deny mode. Live readings: `get_maccmd_sec:2` and `get_maccmd:0` on both VAPs. This leaves the primary ACL free for the SSID's MAC filter (`addmac`/`maccmd`, see the ubntbox strings `%s "%s" maccmd %d`).
- **The controller also sends the whole list in setparam.** `/etc/persistent/cfg/mgmt.setparam.backup` has the keys `["_type","blocked_sta","cfgversion","mgmt_cfg","server_time_in_utc","system_cfg"]`. `blocked_sta` is a newline-joined string (17 bytes = one MAC here).
- mcad logged `Successfully saved config in /etc/persistent/cfg/blocked_sta (length: 17 bytes)` and then runs `syswrapper.sh apply-blocked-sta`.
- `driver_apply_blocklist` writes `clear` to `/sys/class/net/<vap>/blocked_sta`, then writes the MACs in chunks of 220. The live value of `cat /sys/class/net/wifi0ap0/blocked_sta` is that one MAC.
- `apply-blocked-sta-ifup <vap>` re-applies the list when a VAP comes up.
- hostapd is not used for blocking. The hostapd configs have no `macaddr_acl` and no `deny_mac_file`.

### Locate and the LED
- **`set-locate`:** `echo true > /proc/ubnthal/status/IsLocated`, then `plat_lcm_control locate enable` (a no-op here: `/usr/sbin/lcm-control` is absent), then `state_reload`. `handle_led_special_cases` then sets **pattern 10, tempo 480** (pattern 20 at 480 if the AP is in factory default).
- **`unset-locate`:** reverts the above.
- **`led-locate <duration>`:** `/usr/etc/led_locate.sh $1 &` sets IsLocated, runs `syswrapper.sh reload`, sleeps for the duration, then clears it.
- **How the LED is driven on the U6 Pro:** pattern/tempo written to `/proc/gpio/led_pattern` and `/proc/gpio/led_tempo`. Live reading: `led_pattern=1`, `led_tempo=120 (beats per minute)`. `/proc/ubnt_ledbar` is absent, so there is no colour or brightness control.
- **The LED state table (syswrapper.sh):**

| State | Pattern @ tempo |
|---|---|
| ready / managed | 1 @ 120 |
| default (unadopted) or busy | 2 @ 120 |
| upgrading | 12 @ 120 (blue/white alternate) |
| uplink down | 11111110 @ 160 |
| locate | 10 @ 480 |
| LED off | 0 |

- **LED on/off:** comes from `mgmt_cfg` `led_enabled=true|false`, which mcad persists in `/etc/persistent/cfg/mgmt` as `mgmt.led_enabled`. `grep mgmt.led_enabled=false` then forces pattern 0. The optional overrides `mgmt.led_pattern_override` and `mgmt.led_tempo_override` exist.
- Colour and brightness only exist on ledbar models, through `/proc/ubnt_ledbar/{color,brightness}`.

### Restart
- `_type reboot` goes to `syswrapper.sh restart`: `indicate_reboot_intent` then `plat_restart`.
- `soft-restart` runs `rc restart` without rebooting. mca-monitor uses it, for example on a fatal radio error.

### Upgrade
1. `_type upgrade` with `url` and `md5sum`/`sha256sum`: mcad logs `[upgrade] download %s` and downloads to `/tmp/fwupdate.bin` (`fwupdate` is used if `use_fwupdate` is set).
2. It then runs `syswrapper.sh upgrade2`, which calls `do_upgrade`: cfg_save_check, LED 12@120, `fwupdate -c` (validates the UBNT magic and signature), then `plat_upgrade`.
3. `plat_upgrade` copies the image to `/var/log/fwupdate.bin`. It first tries an in-place A/B write (`fwupdate -I` then `fwupdate -k -m`) and reboots. If that fails, it runs `rc ministop`, reboots, and `rc.early_upgrade` flashes the image on the next boot.
- The CLI path is `mca-cli-op upgrade <url>` / `fwupdate --url ...`.

### set-inform and adoption
- The real AP is adopted over SSH: `syswrapper.sh set-adopt <url> <authkey>` runs `mca-ctrl -t connect -s <url> -k <authkey>`, or `mca-cli-op set-inform <url>`.
- After that the key arrives in setparam `mgmt_cfg` (`authkey`, `cfgversion`, `use_aes_gcm`, `led_enabled`, `stun_url`, `mgmt_url`, `capability=notif,notif-assoc-stat`, `report_crash`, `selfrun_guest_mode`).
- mcad persists it in `/etc/persistent/cfg/mgmt` and `mgmt.servers.1.url`.
- mcad has a config-test mode: `cfgtimeout` with automatic rollback (`setparam -T <cfgtimeout>`).

### Scans (neighbour, quick/airtime, spectrum)
- **Nightly channel optimisation is `quick-scan`.** Real log lines:
  ```
  Tue Nov 17 03:00:00 mcad: reporter_handle_response_json(): [quick-scan] band/bw: 1 80
  syswrapper: Starting quick airtime scan for band=1, bw=80
  syswrapper: Scanning wifi1 (bw=80, vap=wifi1ap1)
  03:00:14 mcad: reporter_ok(): [event-reportok] complete spectral scan, resetting
  03:00:15 [quick-scan] band/bw: 0 20  ->  Scanning wifi0 (bw=20, vap=wifi0ap0)
  ```
  - Band codes: 0 = 2.4 GHz, 1 = 5 GHz, 2 = 6 GHz.
  - `airtime-scan` calls `ath_quick_airtime_scan`, which runs `ubntquickscan -i wifiN -j <vap> -y <bw>`. That tool uses the QCA driver's ACS/CBS off-channel survey (strings: `quick_scan_util`, `quick_scan_interf`, `Utilization = %d%%`, `Interference = %d dBm`).
  - It writes `/var/run/rftable_wifiN` (`{"spectrum_table":[...]}`) and `/var/run/rftable_wifiN.timestamp` (uptime at the time of the scan).
  - mcad reports this as `radio_table[].spectrum_table` and `spectrum_table_time`, which is the **age in seconds**: uptime 815440 minus timestamp 749298 = 66142, matching `spectrum_table_time:66142`.
  - Each radio also gets `spectrum_scanning_abnormal`. The top level gets `spectrum_scanning`.
  - Once the controller has acknowledged the report, mcad runs `syswrapper.sh spectrum-scan-qca-done` (removes any temporary `airtime*` VAPs).
- **`spectrum-scan` (manual RF scan):** the `spectrum-cfg` payload is written to `/tmp/spectrum.cfg`, then `syswrapper.sh spectrum-scan` runs `ubntquickscan -i wifiN -j vap -a` on every radio, with the marker `/var/run/spectrum-scan.start`. mca-monitor gives up after a timeout ("spectral scan timed out"). `spectrum-scan-restore` runs `rc restart`.
- **`scan` / `scan_band` (neighbour scan):** `ath_scan` (getopts `t:` active|passive, `m:` sync|async, `i:` radio, `f:` freq). Active mode runs `iwlist <vap> scan`; passive mode runs `ubntrfclient -i radio -j vap -f`. If hard_noisefloor is on, `sens_level` is temporarily set to -96. Afterwards it runs `mca-cli-op inform`.
- **11k:** when `aaa.N.11k.status` is enabled, ubntconf runs `syswrapper.sh 11k-boot`: two randomised scans within 5 minutes after boot, then two within each nightly hour (`elevenk_scan`).
- **Neighbour list in the inform:** `radio_table[].scan_table`, read by mcad from the driver scan cache (`get_scanlist`, "Performing wireless scan on VAP"). Fields: `age, ap_name, band, bssid, bw, center_freq, channel, essid, freq, is_adhoc, is_ubnt, noise, rssi, rssi_age, security, signal`. I saw 18 entries.
- **Spectrum row fields:** `center_freq, channel, interference, interference_type[], other_bss_count, perf_index, total_samples, utilization, width`.
- `scan_radio_table` was `[]` here.
- **Rogue APs:** decided by the controller from scan_table using `is_ubnt` and `ap_name`. Same-ESS UniFi APs come from the kernel module `/proc/ui_neighbor/ess_ap_list` (empty here, since there is only one AP). `mca-ap-neighbor-max-signal` reads that.

### RRM / neighbour reports
- On this site 11k is off (`aaa.1.11k.status=disabled`, `aaa.1.bss_transition=disabled`).
- hostapd offers `rrm_nr_set`, `rrm_beacon_req` and `wnm_disassoc_imminent` over ubus, but neither mcad nor ubntbox contains any `rrm_nr` string.
- So I could not confirm how the AP fills its neighbour reports. *My guess:* the 11k scans feed the QCA driver's own neighbour-report logic.
- The UBNT_ROAM/IAPP path is visible: hostapd logs `UBNT_ROAM: STA=... broadcasting roam=1`, and the hostapd configs have `iapp_key`.

### Client isolation
- `wireless.N.l2_isolation=enabled` makes ubntconf run `cfg80211tool <vap> ap_bridge 0` (string `%s "%s" ap_bridge "%d"`).
- Verified live: `wifi0ap0 get_ap_bridge:0` (l2_isolation enabled) and `wifi1ap1 get_ap_bridge:1` (disabled).
- ebtables has no filter rules, only the broute VLAN drops from `system_cfg ebtables.N.cmd`.

### Syslog
- `syslog.remote.{ip,port,encrypt,key}` becomes the inittab line `logread -f -u -r <ip> <port> -h <host> -E <key> -P <mac>,<model>-<ver>`. This is UniFi's encrypted syslog to the console on port 5514.

### SNMP
- `snmp.*` keys produce `/etc/snmp.conf` (sysName/sysLocation/rocommunity...) and an snmpd line in inittab (`/etc/init.d/snmpd` says "handled by inittab").
- This site sends no `snmp.*` keys.

### SSH credentials
- The controller's device SSH settings arrive in system_cfg as `users.1.name`, `users.1.password` (a `$6$` SHA-512 crypt hash, 98 characters), `sshd.auth.passwd=enabled`, and `sshd.auth.key.N`.
- ubntconf writes `/etc/passwd` (uid 0, home `/etc/persistent`, shell `/bin/ash`), `/etc/shadow`, and `/etc/dropbear/authorized_keys` (rewritten at provisioning; 0 bytes here).
- dropbear itself comes from inittab (`sshd.1.ifname=br0` becomes `-l br0`).

---
## 3. Mapping to our code and to Broadcom `wl`

Each Broadcom equivalent is my inference; I did not test any of them.

| Action | Real U6 Pro | Ours | Broadcom equivalent (inference) |
|---|---|---|---|
| kick-sta | `cfg80211tool <vap> kickmac` on user/guest VAPs | session.go:463 → `kick:` action → main.go:637 → openwrt/actions.go:67, hostapd ubus `del_client` (reason 5, ban_time 0) on every `hostapd.*` | `hostapd_cli -i wlX deauthenticate <mac>` keeps hostapd's state; or `wl -i wlX deauthenticate <mac> [reason]`; skip uplink/backhaul BSS |
| block / unblock | Driver secondary ACL `addmac_sec`/`delmac_sec`, `maccmd_sec=2`; sysfs bulk loader; persisted in /etc/persistent/cfg/blocked_sta; also the setparam `blocked_sta` | session.go:500 (cmd) and the setparam path (`setBlocked`); actions.go:80 `hostapd_cli deny_acl ADD_MAC`, else a timed ban; refreshed every BanTime/3 (main.go:310-315) | `wl -i wlX macmode 1` + `wl -i wlX mac <list>`, then `wl deauthenticate`. Broadcom has **one** MAC list per BSS, so it must be merged with the SSID MAC filter (deny filter: union; allow filter: subtract the blocked). Or keep hostapd `deny_acl` if hostapd owns auth on the Deco. |
| set-locate / unset-locate | IsLocated → LED pattern 10 @ 480 | session.go:449-458 → main.go:649-660 `ledUpdate` (+ beep) | Deco LED GPIO/sysfs (not looked at) |
| led-locate `<duration>` | led_locate.sh timed | **Missing**: falls through to `default:` at session.go:525 | — |
| LED on/off | mgmt_cfg `led_enabled` → pattern 0 | session.go:288 → `led:on`/`led:off` | — |
| reboot | `_type reboot` → syswrapper restart | session.go:241 and cmd at :444 → main.go:666 `ap.Reboot()` (actions.go:41) | `reboot` |
| upgrade | Download, validate, fwupdate A/B | session.go:402-417 pretends: reports the target version and fakes a reboot | Out of scope (no UBNT image) |
| set-inform / adopt | SSH `mca-ctrl -t connect`; key in mgmt_cfg authkey | session.go:433 accepts a `set-adopt`/`adopt` cmd (the real mcad has none); mgmt_cfg authkey at :282 | — |
| quick-scan / airtime-scan (nightly) | ubntquickscan → rftable → spectrum_table + age | **Missing**: no `quick-scan`/`airtime-scan`/`scan_band` case; falls to `default:` session.go:525 | `wl -i wlX chanim_stats` (per-channel busy/interference/noise), `acs_cli`/acsd dumps; per band and width |
| spectrum-scan | ubntquickscan -a on all radios | session.go:519 → main.go:646 `scans.start(..., spectrum=true)` (cmd/uow/scan.go:36), iw survey | `wl -i wlX scan` + `wl scanresults`/`escanresults`, plus `wl chanim_stats` for utilisation |
| scan (neighbour) | iwlist / ubntrfclient → driver cache → scan_table | session.go:519 → scan.go, `iw ... scan ap-force` (internal/openwrt/scan.go:66) | `wl -i wlX scan` (or `escan`), then `wl scanresults` |
| RRM neighbour list | No rrm_nr evidence; 11k scans | scan.go `syncRRM` → openwrt/rrm.go:71 `rrm_nr_set` | hostapd `rrm_nr_set` if hostapd; else `wl rrm_nbr_add_nbr`/`rrm_nbr_list` |
| client isolation | `cfg80211tool ap_bridge 0` | translate.go:217 → uci `isolate` | `wl -i wlX ap_isolate 1` |
| syslog | logread -u -r ... -E key | translate/syslog.go + main.go:1038 syslogForwarder (encrypted) | same |
| SNMP | ubntconf snmp.conf | main.go:1223 syncSNMP | same |
| SSH users/keys | ubntconf → passwd/shadow/authorized_keys | translate/users.go | Deco dropbear: same files |

### Inform field differences
- **scan_table** (internal/openwrt/scan.go:452-461): we send `is_unifi` and `serialno`. The real AP sends `is_ubnt` and `ap_name`, plus `noise` and `rssi_age`, which we do not send.
- **spectrum_table** (scan.go:468-475): we leave out `interference_type` ([]), `other_bss_count`, `perf_index` and `total_samples`.
- **radio_table:** we do not send `spectrum_scanning_abnormal`.

---
## Saved files
Everything is under `~/udeco/docs/reference/u6pro/actions-scans/` (all redacted):
- `ps.txt`, `fs-listing.txt` (inittab and directory listings; the syslog `-E` key is redacted)
- `fw/`: syswrapper.sh, platdep_funcs.sh, led_locate.sh, unifi_hostapd_funcs.sh, init.d, board.info and other stock scripts
- `strings-mcad.txt`, `strings-ubntbox.txt`, `strings-ubntquickscan.txt`, `strings-ubntrfclient.txt`
- `mca-dump.redacted.json` (`guest_token` and key-like fields redacted)
- `mgmt.redacted`, `hostapd-confs.redacted`
- `rftable_wifi0.txt` (includes timestamp and uptime), `rftable_wifi1.json`
- `runtime-state.txt` (cfg80211tool getters, LED proc values, ebtables, hostapd ubus methods)
- `syslog-mcad-syswrapper.txt` (lines with authkeys or keys removed)

I left no existing files changed. The local binary copies are in the scratchpad, not the repo.

## Key findings
- The U6 Pro (BZ.8.8.14) is Qualcomm IPQ50xx 'Maple' (2.4 GHz wifi0, ahb) plus 'Pine' (5 GHz wifi1, PCI 17cb:1104) with the qca-wifi driver (cfg80211tool/wlanconfig), not MediaTek. The MTK_UAP branches in syswrapper.sh are for other models, such as the U6-Lite.
- mcad (/usr/bin/mcad, a multi-call binary) is the inform agent. It reads replies by _type (noop, setparam, cmd, upgrade, reboot, setdefault) and runs most actions as `/usr/bin/syswrapper.sh <action>`. mca-monitor, uplink-monitor, reset-handler, mesh-monitor and redirector are mcad symlinks.
- mcad's cmd names: led-locate, set-locate, unset-locate, kick-sta, block-sta, unblock-sta, authorize-guest, unauthorize-guest, dynamic-psk, rate-update, scan (freq/active/type), quick-scan (scan-band/scan-bw), airtime-scan, spectrum-scan (spectrum-cfg/infinite), scan_band, build-ssh-session, pcap-start, get-support-file, shellcmd and others. There is no set-adopt cmd in mcad (grep count 0).
- The real nightly channel-optimisation scan at 03:00 is cmd quick-scan with scan-band/scan-bw. Log: `[quick-scan] band/bw: 1 80`, then `syswrapper.sh airtime-scan`, then `ubntquickscan -i wifi1 -j wifi1ap1 -y 80`, then /var/run/rftable_wifiN. After the controller acks, mcad runs spectrum-scan-qca-done ('complete spectral scan, resetting').
- spectrum_table_time is the age in seconds of the last RF scan. Verified: uptime 815440 minus rftable timestamp 749298 = 66142, matching mca-dump spectrum_table_time=66142.
- Kick is `cfg80211tool <vap> kickmac <mac>`, run only on VAPs whose /var/run/vapusage.<vap> is user or guest.
- Block is the driver's secondary MAC ACL: addmac_sec/delmac_sec with maccmd_sec=2 (deny, verified live), bulk-loaded through /sys/class/net/<vap>/blocked_sta and persisted in /etc/persistent/cfg/blocked_sta. The controller also sends the full list as a top-level setparam string 'blocked_sta' (newline-separated), and mcad then runs `syswrapper.sh apply-blocked-sta`. hostapd plays no part.
- Client isolation (wireless.N.l2_isolation) is the driver setting `cfg80211tool <vap> ap_bridge 0`. Verified live: get_ap_bridge:0 on the isolated SSID and 1 on the other. There are no ebtables filter rules.
- LED states are pattern@tempo written to /proc/gpio/led_pattern and /proc/gpio/led_tempo: ready 1@120, default 2@120, upgrading 12@120, uplink down 11111110@160, locate 10@480 (20@480 when in factory default), off 0. led_enabled=false is stored as mgmt.led_enabled in /etc/persistent/cfg/mgmt. led-locate <duration> runs led_locate.sh with a timer.
- Upgrade: mcad downloads to /tmp/fwupdate.bin ([upgrade] download), then syswrapper upgrade2, do_upgrade, `fwupdate -c`, and plat_upgrade (in-place A/B `fwupdate -I` / `-k -m`, otherwise flashed by rc.early_upgrade on reboot).
- scan_table rows on the real AP carry: age, ap_name, band, bssid, bw, center_freq, channel, essid, freq, is_adhoc, is_ubnt, noise, rssi, rssi_age, security, signal. spectrum_table rows carry: center_freq, channel, interference, interference_type[], other_bss_count, perf_index, total_samples, utilization, width. Each radio also has spectrum_scanning_abnormal; the top level has spectrum_scanning.
- SSH credentials: system_cfg users.1.name and users.1.password ($6$ SHA-512 crypt), sshd.auth.passwd and sshd.auth.key.N are turned by ubntconf into /etc/passwd, /etc/shadow and /etc/dropbear/authorized_keys. dropbear runs from inittab with -l br0.
- Remote syslog runs from inittab as `logread -f -u -r <ip> 5514 -h <host> -E <key> -P <mac>,<model>-<ver>` (encrypted UniFi syslog). SNMP is ubntconf writing /etc/snmp.conf plus an inittab snmpd line; this site sends no snmp.* keys.
- hostapd is one global instance. VAPs are added with `hostapd_cli -i global raw ADD bss_config=<vap>:<cfg>`, and ubus objects hostapd.<vap> expose del_client, rrm_nr_set, rrm_beacon_req, wnm_disassoc_imminent and bss_mgmt_enable. No rrm_nr usage was found in mcad or ubntbox; 11k is disabled on this site.

## Gaps vs our code
- internal/device/session.go:431-528 (cmd switch) has no case for 'quick-scan' or 'airtime-scan' (fields scan-band/scan-bw), the command the controller sends for the nightly 03:00 scan. It falls to `default:` at session.go:525 and is logged as ignored, so spectrum_table is never refreshed by the scheduled optimisation.
- internal/device/session.go:449-458 handles set-locate and unset-locate but not 'led-locate' (carries a duration and reverts on its own). It also falls to default at :525.
- internal/device/session.go:519 treats 'scan' and 'spectrum-scan' alike and ignores the payload. The real 'scan' carries freq/active/type, 'spectrum-scan' carries spectrum-cfg/infinite, and 'scan_band' carries band; none of these fields are read.
- internal/openwrt/scan.go:452-461 (ScanTable) sends 'is_unifi' and 'serialno', which the real AP (8.8.14) does not send. The real AP sends 'is_ubnt' and 'ap_name' for that purpose, plus 'noise' and 'rssi_age', all missing from ours.
- internal/openwrt/scan.go:468-475 (SpectrumRows) leaves out interference_type ([]), other_bss_count, perf_index and total_samples, which the real AP includes in every spectrum_table row.
- cmd/uow/scan.go:175-207 never sets radio_table[].spectrum_scanning_abnormal, which the real AP reports per radio (false normally).
- internal/openwrt/actions.go:67 (Kick) sends hostapd del_client to every hostapd.* object. The real AP kicks only on user/guest VAPs (vapusage), never on uplink/mesh/backhaul BSSs. A Deco agent should skip the backhaul BSS.
- internal/openwrt/actions.go:80-105 (EnforceBlocked/Unblock) uses hostapd deny_acl or timed bans, reapplied every BanTime/3 (cmd/uow/main.go:310-315). The real AP uses a separate driver deny ACL that survives hostapd reloads and is reapplied when a VAP comes up (apply-blocked-sta-ifup). On Broadcom 'wl' there is one maclist per BSS, so blocked_sta must be merged with the SSID MAC filter (wireless.N.mac_acl.policy).
- internal/device/session.go:433-443 accepts a 'set-adopt'/'adopt' cmd that the real mcad does not have. Real adoption is SSH (`mca-ctrl -t connect -s url -k key` via `syswrapper.sh set-adopt`) or mgmt_cfg authkey in setparam (handled at session.go:282). This is harmless but not ground truth.
- internal/device/session.go:402-417 (upgrade) never downloads; it reports the target version and fakes a reboot. The real AP downloads to /tmp/fwupdate.bin, validates (UBNT magic, md5sum/sha256sum, fwupdate -c) and shows LED 12@120 during the upgrade.
- The LED mapping in cmd/uow/main.go:1192 (ledUpdate) should follow the real pattern table: default 2@120 alternating, upgrading 12@120, uplink down 11111110@160, locate 10@480 (20@480 if default). Whether ours distinguishes the 'default' and 'uplink down' states was not checked.

## Open questions
- The exact JSON for each controller cmd (for example whether kick-sta carries 'mac' only, or also a VAP or reason) is not provable from strings, because short names like 'mac' and 'url' are merged into longer strings. Capturing a decrypted inform reply while clicking Reconnect, Block or Locate in UniFi Network would settle it.
- How the QCA AP fills 802.11k neighbour reports: hostapd offers rrm_nr_set over ubus, but no rrm_nr string exists in mcad or ubntbox, and 11k is disabled on this site. Turning 11k on for a test SSID and reading `ubus call hostapd.<vap> rrm_nr_list` would show whether the driver or a daemon fills them.
- Does mcad's scan_table come only from the driver's cached results, or does building an inform trigger a scan? Entries showed age 0 and 6 although the last off-channel scan was about 18 h earlier. The QCA driver probably keeps refreshing from beacons heard on the operating channel; not verified.
- A real U6-Lite (UAL6, MediaTek) runs the MTK_UAP branches (mtk_quick_airtime_scan, spectrum_scan_clean). Does the controller send UAL6 the same quick-scan/spectrum-scan cmds and expect identical spectrum_table fields? Not verifiable on this U6 Pro.
- Broadcom equivalents are untested inferences: on the Deco X20, does hostapd own auth (so hostapd_cli deauthenticate and deny_acl work), or does the wl driver or nas, so that `wl deauthenticate` and `wl macmode`/`wl mac` must be used? Can `wl chanim_stats` or acsd supply per-channel utilisation and interference comparable to ubntquickscan?
- The ubntevent applet's role was not determined.
- mca-dump.redacted.json still holds the home network's client MACs, hostnames and IPs in vap_table.sta_table. They are not secrets under the redaction rules, but they are private. Decide whether they should stay in the repo.

# VERIFIER
## Corrections
- CLAIM: Mapping table, spectrum-scan / quick-scan row: our spectrum_table is roughly equivalent and differs only in missing fields (interference_type, other_bss_count, perf_index, total_samples).
  CORRECTION: The row values also mean different things. On the real AP `interference` is the interference power that ubntquickscan's CBS survey measured, typically -50 to -64 dBm on 2.4 GHz. That is not the noise floor: the same radio's scan_table reports noise=-96. Ours (internal/openwrt/scan.go:368 and :387) puts the iw survey noise floor (about -95) into `interference`, so to the controller every channel looks interference-free. The row set differs too. A quick-scan at scan-bw=80 returns only 80 MHz blocks on 5 GHz (6 rows: channels 36/52/100/116/132/149 with block centre freqs 5210/5290/5530/5610/5690/5775). Ours mixes 20, 40 and 80 MHz rows (scan.go:366-395).
  EVIDENCE: Fresh mca-dump: wifi1 spectrum rows {'center_freq':5210,'channel':36,'interference':-59,'utilization':11,'width':80} ... {'center_freq':5775,'channel':149,'interference':-86,'width':80}. wifi0 has 13 rows, width 20, channels 1-13, interference -50..-64. scan_table rows on the same radio have noise -96. ubntquickscan strings: 'CBS channel %d (%d MHz): utilization=%d%% interference=%d dBm'.
- CLAIM: Gap list implies scan_table differs from ours only in field names (is_unifi/serialno vs is_ubnt/ap_name, plus noise/rssi_age).
  CORRECTION: `rssi` is computed differently as well. On the real AP rssi = signal - noise (SNR against the measured noise floor); this held for all 17 rows. Ours is signal+95, clamped at 0 (scan.go:449). `rssi_age` is a separate counter, about 10x `age` (age 15 -> 151, 18 -> 186, 5 -> 51, 4 -> 49). It looks like deciseconds, but that is an inference.
  EVIDENCE: Fresh mca-dump scan_table: sig -70 noise -96 rssi 26; sig -82 noise -96 rssi 14; sig -90 noise -96 rssi 6 (snr check True for every row); age/rssi_age pairs 15/151, 18/186, 5/51, 4/49, 2/28.
- CLAIM: 'There is no set-adopt cmd in mcad' (implying mcad has no inform-URL command at all).
  CORRECTION: This is true for controller cmds: grep -c set-adopt strings-mcad.txt returns 0. mcad does contain `set-inform`, but as a local mca-cli/mca-ctrl op next to exit/quit/mesh-halt/inject-inform-response/set-default, not as a controller cmd. It is reached through `syswrapper.sh set-inform` -> `mca-cli-op set-inform`. Leaving this out invites a misreading.
  EVIDENCE: strings-mcad.txt:721 'set-inform' sits in the CLI op list (lines 717-731), next to '"op":"connect"' (638). syswrapper.sh:2921-2923 'set-inform) mca-cli-op set-inform $1'.

## Confirmed
- Hardware/firmware: BZ.8.8.14 (cat /etc/version); board.info sysid 0xa650, radio.1 Maple (ahb), radio.2 Pine (pci); stock scripts saved match the device (md5 15ccbd1e... syswrapper.sh, 6083d242... platdep_funcs.sh identical locally and on the AP). Login is uid 0.
- spectrum_table_time is a per-radio age in seconds. Rechecked on both radios: uptime 816096 - rftable_wifi0.timestamp 749298 = 66798 (dump 66799), and 816096 - rftable_wifi1.timestamp 749285 = 66811 (dump 66812).
- Nightly scan is cmd quick-scan, sequential per band. Log lines 'Wed Nov 18 03:00:00 mcad ... [quick-scan] band/bw: 1 80' -> 'Starting quick airtime scan for band=1, bw=80' -> 'Scanning wifi1 (bw=80, vap=wifi1ap1)' -> 03:00:12 '[event-reportok] complete spectral scan, resetting' -> 03:00:13 '[quick-scan] band/bw: 0 20' -> 03:00:38 reportok. The same pattern appears on Nov 17.
- syswrapper airtime-scan -> ath_quick_airtime_scan (platdep_funcs.sh:502) touches /var/run/quickscan.start, maps band 0/1/2 to 2g/5g/6g_maxchwidth, and runs `ubntquickscan -i <radio> -j <vap> -y <bw>` (bw 240 becomes 320 on band 1).
- spectrum-scan-qca-done -> scan_devnames_destroy (platdep_funcs.sh:400) deletes only temporary airtime* VAPs.
- Real scan_table keys exactly: age, ap_name, band, bssid, bw, center_freq, channel, essid, freq, is_adhoc, is_ubnt, noise, rssi, rssi_age, security, signal. spectrum rows: center_freq, channel, interference, interference_type[], other_bss_count, perf_index, total_samples, utilization, width. Per radio: spectrum_scanning_abnormal=false. Top level: spectrum_scanning=false, scan_radio_table=[].
- kick_sta / driver_kick_block_sta / driver_unblock_sta act only on VAPs with vapusage user|guest (platdep_funcs.sh:600-636). Live: vapusage.wifi0ap0=user, vapusage.wifi1ap1=user.
- Block list uses the secondary driver ACL. Live: get_maccmd_sec:2 and get_maccmd:0 on both VAPs; /sys/class/net/<vap>/blocked_sta holds 1 MAC; /etc/persistent/cfg/blocked_sta is 17 bytes. mcad logs 'Successfully saved config in /etc/persistent/cfg/blocked_sta (length: 17 bytes)' (Nov 17 20:54:38 and Nov 18 21:17:45). syswrapper block-sta/unblock-sta/apply-blocked-sta/apply-blocked-sta-ifup are at syswrapper.sh:3039-3058.
- Client isolation is ap_bridge. Live: wireless.1 (wifi0ap0) l2_isolation=enabled -> get_ap_bridge:0; wireless.2 (wifi1ap1) disabled -> get_ap_bridge:1.
- LED: _set_led writes /proc/gpio/led_pattern+led_tempo (live: 1 / '120 (beats per minute)'). Values: ready 1@120, default/other 2@120, upgrading 12@120, uplink down 11111110@160 (non-a69e/a6bf), locate 10@480 (20@480 if IsDefault), led_enabled=false -> 0@120, mgmt.led_pattern_override/led_tempo_override (syswrapper.sh:418-470, 505-533, 825-845).
- 11k/BSS transition disabled on both SSIDs (aaa.N.11k.status=disabled, aaa.N.bss_transition=disabled).
- Our code citations are accurate: session.go:431-528 cmd switch has no quick-scan/airtime-scan/led-locate/scan_band case (default at :525); :519 treats scan and spectrum-scan alike; :402-417 upgrade is faked; :433 accepts set-adopt; Reply.BlockedSta at :204 handles setparam blocked_sta; openwrt/actions.go:67 Kick goes to every hostapd.* via del_client; :80-105 deny_acl/BanTime; main.go:310-315 re-enforces every BanTime/3; scan.go:453-461 sends is_unifi/serialno.
- Redaction audit of every file under ~/udeco/docs/reference/u6pro/ (actions-scans/, config-apply/, and the top-level mca-dump*.json, inform-*.tsv/txt): no secret values leaked. wpa_passphrase, sae_password, iapp_key, aaa.N.wpa.psk, users.N.password, unifi.key, syslog.remote.key, mgmt.authkey, guest_token and the logread -E key are all ***REDACTED***. There are no $1$/$6$ hashes, private keys or ssh-* keys. The only 32-hex strings are anon_client_id hashes, the public UniFi factory default key ba86f2bb... in strings-mcad.txt (also in our internal/inform/packet.go:55), and a firmware iBeacon UUID. No file needed changing.

## Gaps filled
- [Controller sequencing of quick-scan (behaviour the controller depends on)] The controller sends one quick-scan per band and sends the next band only after the AP has reported the finished scan. mcad logs '[event-reportok] complete spectral scan, resetting' when the inform carrying the new rftable is acked, and the next band's quick-scan arrives about 1 s later. An agent that ignores quick-scan, or never reports completion (fresh spectrum_table, spectrum_table_time reset, scanning flags back to false), will probably stall the nightly optimisation after the first band. The mechanism is inferred from log ordering.
  EVIDENCE: /var/log/messages: 03:00:00 quick-scan 1 80 -> 03:00:12 reportok -> 03:00:13 quick-scan 0 20 -> 03:00:38 reportok (same pattern on Nov 17: 03:00:14 -> 03:00:15). strings-mcad.txt:1637-1639 '[event-reportok] complete spectral scan, resetting', 'spectrum-scan-qca-done'; :1680 '[event-reportfail] ...'.
- [quickscan_scanning and other conditional inform fields] mcad has a top-level `quickscan_scanning` key next to `spectrum_scanning`, plus per-radio `rssi_histograms` and `suggested_channels` next to spectrum_table. None of them appear in an idle dump, so they are conditional: quickscan_scanning is probably emitted while /var/run/quickscan.start exists (inference). Our scan.go:178 only sends spectrum_scanning. The study and inform-keys-diff.txt miss all three.
  EVIDENCE: strings-mcad.txt:2425-2426 'spectrum_scanning','quickscan_scanning'; :2174-2179 '/var/run/rftable_%s','spectrum_table','spectrum_table_time','spectrum_scanning_abnormal','rssi_histograms','suggested_channels'; :1910-1912 '/var/run/rftable.start','/var/run/rftable_%s.complete','/var/run/quickscan.start'. Fresh dump top-level scan keys: only scan_radio_table, spectrum_scanning.
- [spectrum_scanning_abnormal source and scan timeouts] ubntquickscan writes /var/run/rftable_<radio>.{timestamp,pre_abnormal,...}. mcad watches rftable_%s.start, .abnormal and .pre_abnormal, and resets with '[event] spectral scan abnormal end, resetting' or 'spectral scan timed out'. spectrum_scanning_abnormal is presumably derived from the .abnormal markers (inference). ubntquickscan also sends a custom notification through `mca-custom-alert.sh -k event_string ... -k channel -k width -k center_freq -k interference -k utilization`. The event_string literal could not be determined.
  EVIDENCE: strings-mcad.txt:748-755; strings-ubntquickscan.txt:206-218 (rftable paths, 'pre_abnormal','timestamp', mca-custom-alert format string); fw/usr/bin/mca-custom-alert.sh.
- [scan-bw is not simply the radio's current width] The controller sent quick-scan scan-bw=80 for 5 GHz, but the same AP's vap_table reports wifi1ap1 bw=160. The resulting 5 GHz rows are all width 80. The agent should scan and report at the scan-bw the controller asks for, not its operating width. This is one sample; that the controller caps 5 GHz quick-scan at 80 is an inference.
  EVIDENCE: Fresh mca-dump vap_table: ('wifi1ap1', bw 160, channel 40); log '[quick-scan] band/bw: 1 80'; spectrum rows width 80.
- [Other action details missed] (a) unauthorize-guest also kicks the station (`guest_unauthorize; kick_sta $1`); ours should do the same. (b) mcad skips scan cmds when the AP is a mesh downlink ('skip scan cmd due to AP is downlink'). (c) Reset-to-default sets LED 3@120 (blue/white). (d) led_locate.sh sets duration=30 when no argument is given but then runs `sleep $1`, so the 30 s default is never used (a stock bug; the controller presumably always passes a duration). (e) mcad exposes per-AP `guest_kicks` (present in the dump, value 0) and a `"kicks":%d` stat. (f) Upgrade can also arrive as a cmd ('cmd-upgrade', 'invalid upgrade cmd: %s'), which our session.go:461 already accepts.
  EVIDENCE: syswrapper.sh 'unauthorize-guest) guest_unauthorize "$@"; kick_sta $1'; strings-mcad.txt:1767, :1978, :2046, :1660; syswrapper.sh:2959 '_set_led 3 120 1'; fw/usr/etc/led_locate.sh; fresh dump '.guest_kicks 0'.
- [Own-BSS / same-site rows in scan_table] The real scan_table contained none of the AP's own BSSIDs and no foreign BSS carrying the site's ESSIDs. This matches our exclusion (scan.go:435-441), but with only one UniFi AP on site it does not show how same-ESS UniFi neighbours are reported (is_ubnt=true, ap_name set).
  EVIDENCE: Fresh mca-dump: check of vap_table bssids/essids against scan_table found no matches; all rows is_ubnt=false, ap_name=''.

## Still open
- The exact payload shape of the controller's `scan`, `scan_band` and `spectrum-scan` cmds (freq/active/type, band, spectrum-cfg/infinite) and how mcad maps them to syswrapper arguments. Only field names come from strings; no instance was seen in logs.
- What the event_string is in ubntquickscan's mca-custom-alert notification, and whether the controller uses it (interference alerts).
- Whether quickscan_scanning (and rssi_histograms/suggested_channels) is emitted only during a scan and whether the controller gates the next quick-scan band on it, or only on spectrum_table_time changing. Seeing this needs a capture during the 03:00 window.
- Units of rssi_age (it looks like deciseconds, about 10x age); not confirmed from code.
- How the real AP reports a same-ESS UniFi neighbour in scan_table (is_ubnt/ap_name values) needs a site with a second UniFi AP; /proc/ui_neighbor/ess_ap_list is empty here.
- Semantics of other_bss_count/perf_index/total_samples: always 0 on this QCA quick-scan, so whether the controller needs non-zero values (e.g. from a full spectrum-scan -a) is unknown.
- Whether our ledWanted() distinguishes the default (2@120) and uplink-down (11111110@160) states was not checked by either review.
