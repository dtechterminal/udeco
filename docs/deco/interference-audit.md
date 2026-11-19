# Deco X20: what can interfere with udeco-ap (audit, 2026-11-18)

This audit looks for firmware, kernel and network mechanisms that can undo, bypass or reboot the on-device agent
(`udeco-ap`) on a TP-Link Deco X20 V2. Units: .205 (test satellite), .241 (master), .232 (satellite).

How it was done: five read-only sweeps, each followed by an independent verification pass:
- kernel and datapath;
- time-based jobs;
- event hooks;
- remote and cross-unit control;
- resources and self-healing.

Only mechanisms the verifiers **confirmed** or left **unverifiable** are listed here. Refuted claims are in §4.
Where a verifier corrected a sweep, the corrected version is used.

Builds on `services.md` and `wifi-bringup.md` (scratchpad research reports), `agent-design.md`,
`device-capabilities.md` and `topology-and-tplink-scrub.md`.

Evidence paths that start with `research/` are relative to the session scratchpad. That folder is temporary, so
anything worth keeping must be copied out.

Status meanings:
- **C**: confirmed, with evidence on the device.
- **U**: unverifiable read-only; this is a hypothesis.
- **C/U**: the mechanism is confirmed but its effect is not.

`Rn` refers to the requirements in §3.

Context that applies to everything below:
- All three units rebooted shortly before the probes: .205 at about 22:22, .241 and .232 at about 21:32. The cause
  is unknown.
- Every decosys stop is lost on a reboot, so all boot-window items recur on every boot.
- The agent's real boot hook is the **uci firewall include** `/data/persist_shell.sh`. It runs at S45, about
  31 s into boot. It is not `/data/startup.sh`, which nothing references.

---

## 1. Mechanisms

### 1.1 Breaks: undoes takeover, cuts the LAN, or reboots the unit

| # | Mechanism | St | Trigger | Effect | Evidence | Already handled? | Countermeasure |
|---|---|---|---|---|---|---|---|
| B1 | **Agent starts mid-boot.** The S45 firewall include starts it before most of TP-Link has started. | C | Every boot. The include runs at about 31 s (/data/dropbear starttime 3178 ticks). It also runs on every firewall start or restart. | The first Enforce and the provision apply happen before these exist: sync-server (55 s), TP-Link hostapd (60-67 s), wifi_set_done (81 s), acsd2 (73 s), ntpd (82 s), nrd (83 s), and the S90-S99 one-shot scripts (qos, guest_eth, iptv, networkx, zzzz_cron_add, zzz). Late starters then run unopposed until the 2nd Enforce, 60 s later: acsd2 can move the channel, nrd can deauth, sync-server can trigger repacd. The one-shot scripts leave tc, iptables and bridge state that stopping a daemon does not revert. The first wl.Collect may also see an incomplete radio set. | uci `firewall.@include[1].path=/data/persist_shell.sh` on all 3 units. `/lib/firewall/core_init.sh:295-307` sources it. rc.d order and /proc starttimes on .205. `decosys/plan.go:208` `rebuilding()` matches only `/etc/init.d/repacd` and `/sbin/wifi`. | Partly. The 60 s Enforce catches up eventually. No gate waits for boot to finish. | R1, R2 |
| B2 | **.241's persist_shell.sh: the cron guard never matches the line it adds.** | C | The next reboot of .241, or any run while the crontab lacks the string `/data/dropbear`. The hand-added pgrep line lives in ramfs `/etc`, so it is gone after a reboot. | Each run appends another `* * * * * sh /data/persist_shell.sh` line and restarts cron, so the line count doubles every minute. The ceilings are kernel.threads-max 3936 (enforced for root; RLIMIT_NPROC is not) and RAM, because the crontab and the shells live in ramfs. That ends in the OOM path and a reboot (B8), then a loop. | .241 `/data/persist_shell.sh` (mtime 21:36) guard: `grep -q '/data/dropbear' … \|\| echo '* * * * * sh /data/persist_shell.sh' >>`. The .205 and .232 variants grep for `/data/persist_shell`. | No. `stripCron` keeps duplicate lines (`cron.go:36-56`). | R16, R29 (the user fixes the file; we do not edit it) |
| B3 | **Supervision gaps.** Per-minute supervision is not guaranteed on .241 or .232, and the keepalive tests are broken. | C | (a) The .232 crontab has no persist line (until the next reboot). The .241 crontab has only the pgrep/dropbear line. (b) busybox `pgrep -f X` matches its own parent `sh -c`. (c) dropbear's per-connection children keep the cmdline `/data/dropbear -p 22 …`. (d) `stripCron` reads the file then renames over it, so an `echo >>` in that window is lost. | A crashed agent is never restarted until the next reboot. A dead :22 listener is never restarted while any SSH session is open, because of (b) and (c), which cuts off deploys and rollbacks. | crontabs of all 3 units at 23:18. On .205, `sh -c "pgrep -f /data/zz-no-such…"` gave rc=0; the bracketed pattern gave rc=1. `cron.go:97-121`. `deploy/deco-ap.sh` step 5 edits only persist_shell.sh. | No | R16, R28, R29 |
| B4 | **One press of the reset button factory-resets the unit, and root persistence goes with it.** | C | A physical press while `/tmp/done_boot` exists. procd's `hotplug.json` runs `/etc/rc.button/reset` on ACTION=pressed, with no hold-time check. | `config_factory()` loads default-config into user-config and reboots. That wipes the takeover, and also the **firewall include**, so `/data/persist_shell.sh` and `/data/dropbear` survive on ubifs but never run again. The unit comes back as stock TP-Link with no root until it is re-rooted. | `/etc/rc.button/reset:14-24`. `/etc/hotplug.json` button rule. config.lua strings (nvrammanager -r default-config, `rm -rf /etc/config`). In vmlinux.strings, board_button.c emits both `BUTTON=%s` and `SEEN=%ld`, next to the 'reset pressed' string. | No | R11 |
| B5 | **netifd still holds the lan config 192.168.0.1/22, which is the UCG's own address.** | C | (a) Every boot: lan comes up at .1/22 about 20 s before smartipd removes it. (b) After takeover: a netifd crash and procd respawn (600/5/5), `network restart`, `ubus call network…up`, or a config.change on the network_sync, iptv_v2 or passthrough.init triggers. | br-lan answers ARP for the gateway's IP, which can take down the whole LAN. The ifup of lanv6 also runs `03-lanv6` `replug_brlan_device`, which power-cycles the eth0 and eth1 PHYs and runs `wifi disconnsta lan\|guest`. That deauths every station on wl02/wl12/wl03/wl13, which are the agent's own vifs. 15-tpbrd, 16-imsnoop and 20-firewall run as well. | `ubus call network.interface.lan status` shows 192.168.0.1/22, while the live br-lan address is .205/24. The .205 and .232 boot logs show `smartip: !!ip addr del!! … 192.168.0.1`. `etc/hotplug.d/iface/03-lanv6:1111-1126`. `/sbin/wifi:309-324`. | Partly. decosys never restarts the network (`decosys.go:13-14`), but nothing removes the alias once it reappears. | R8a, R31 (user) |
| B6 | **smartipd (kept running) acts on DHCP lease and role changes.** | C (conditional) | A renew or rebind that changes IP, subnet, gateway or DNS. A satellite's lease moving to another subnet. On the master (FAP role): DHCP detect fails because the UCG is down at boot or renewal. Nothing shows that an unchanged 12 h renew fires any of these. | The possible actions are: `wifi disconnsta/disconnclient` (deauths every agent client); `ifconfig br-lan 0.0.0.0`; `ethctl ethX phy-power down/up` (cuts the uplink); restarting udhcpc and dhcp_hook_d; **a rogue udhcpd on br-lan** (pool .100-.250, router .1, 60 s lease) from the master; and hotplug ip FAPIPUPDATE, which leads to reload_config. smartipd is also what removes the boot-time .1 alias (B5). | smartipd strings: 'lan ip change to another subnet, disconnect all sta', ' AP mode dhcp detect_fail to make dhcpd on.', 'ethctl %s phy-power down'. `/tmp/udhcpd_lan.conf` is ready on all 3 units. `/tmp/work_mode`: .241 FAP, the others RE. | Partly. Its input writers are stopped (awnd, sync-server, conn-indicator), so its inputs freeze. Its lease paths are untouched. | R8b, R20, R31 |
| B7 | **The second Ethernet port is bridged as soon as it gets link, with no loop protection.** | C | A cable in the non-uplink port. This was seen live on .232 (eth0), 22:34-22:39. | br-lan forwards at once (STP off, forward delay 0). After takeover nothing but the kernel reacts: conn-indicator and wanDetection are stopped. A second path into the LAN, or to another Deco, makes a broadcast storm. | .232 logread: 'br-lan: port 2(eth0) entered forwarding state'. .205 br-lan `stp_state=0`, `forward_delay=0`. The loop guard exists only as a requirement in `topology-and-tplink-scrub.md:34`; there is no Go code for it. | No | R9 |
| B8 | **Memory exhaustion reboots the unit; nothing can contain it.** | C (policy) | Any memory that cannot be freed: runaway ramfs files (B2, D6), kernel slab growth, or an allocation where the OOM killer is not called. | `CONFIG_BCM_KF_OOM_REBOOT` ('Reboot due to persistent out of memory codition'), `panic_on_oops=1`, `softlockup_panic=1` and `panic=3` all reboot within 3 s, which restores stock TP-Link. There are no cgroups, so no memory limit can be set. A plain Go heap leak more likely ends with the OOM killer picking the agent (largest RSS), and persist_shell then restarts it. | /proc/config.gz; vmlinux strings 2660-2661. `/proc/sys/kernel/*`. MemAvailable 96-100 MB, of which about 91 MB is wl slab (SUnreclaim). The largest other RSS is 4.6 MB. | No. There is no SetMemoryLimit or GOGC in the Go code. | R3, R4, R10j |
| B9 | **TMP over SSH on :20001 gives the master root, using a shared 512-bit RSA group key.** | C | The boot window only: S50dropbear and S50tmpsvr run until the first effective Enforce, about 60 s after the agent starts. The master logs in every ~16 s and within about 35 s of a unit booting. | Through tmpsvr the master can call sync_config (rewrites the user-config partition, then uci_apply: Wi-Fi rebuild, or `reboot -f` if sysmode differs), sync_firmware, unbind/reset, or any opcode. authorized_keys has no command= restriction, so the key also gives a full root shell. The key is 512-bit RSA and can be factored from the public key. | .205 logread: 239 logins from .241 in about 56 min. `/etc/dropbear/authorized_keys` is one unrestricted line with a 116-character blob. `/etc/init.d/dropbear:149-160, 251`. libtmpv2 hard-codes port 20001. | Steady state: yes (`services.go:52, 102-106`; no respawn path is left). Boot window: no. | R5, R1 |
| B10 | **Firmware flash path (cloud → master → RE) and no guard for an upgrade in flight.** | C (path) | A cloud or app upgrade (Auto Update) that reaches an RE in the boot window: master CHECK_FIRMWARE/SYNC_FIRMWARE → sshhttpget → `/usr/bin/upgrade` → `nvrammanager -u` → reboot. | New firmware discards the takeover and may close the root path or migrate config. If decosys stops tmpsvr in the middle of a transfer or flash, the flash may fail. Nothing is pending today: upgrade_info equals the installed build. | Master `/lib/sync-server/scripts/firmware:26,36`. `.205 /usr/bin/upgrade:20`. ctl_sync strings `/tmp/firmware_upgrade_flag`, `/var/run/force_upgrade.pid`. | Steady state: yes. Guard: no (`plan.go:208` knows only Wi-Fi rebuilds). | R5, R17, R29 |
| B11 | **The root hook lives in TP-Link's synced user-config.** | U | A SYNC_CONFIG from the master in the boot window, a factory reset (B4), or a firmware upgrade that migrates config. | If the user-config pushed down no longer contains the firewall include, the next boot comes up stock: no :22, no agent. On .205 the include is the **only** hook (its firewall.user is stock); on .232 firewall.user also calls persist_shell. | .205 `/etc/config/firewall` was restored from flash at boot (mtime is the pre-NTP clock), so the include is in .205's flash. 'firewall' is not in the sync module list, but sync_config writes a whole blob. Whether the master's flash holds the include is unknown. | No | R10h, R28, R29 |
| B12 | **The off-device udeco may still model .205 under the same MAC.** | U | The Unraid udeco container runs with deco-205 in `units[]`, or the controller keeps the old deco-205 record. | Informs for b0:a7:b9:3e:17:00 arrive from two senders with different authkeys and cfgversions: adoption flaps, setdefault, provisioning that bounces between them. The container appears to be down today (22201-22203 closed, no logins from .4). | `agent.go:306-322` (the br-lan MAC is the identity). `docs/deco/README.md` units table. | No | R28 |

### 1.2 Degrades: wrong forwarding, multicast, performance or exposure

| # | Mechanism | St | Trigger | Effect | Evidence | Already handled? | Countermeasure |
|---|---|---|---|---|---|---|---|
| D1 | **The flow cache and Archer HW forward established flows past the bridge, ebtables and qdiscs.** | C (latent) | Any policy change while flows exist: a VLAN remap of an SSID, a loop-guard delif, and later guest ebtables rules or tc limits. `brctl delif/addif` evicts nothing (flush_fdb = destroy_fdb = 0 on all 3 units); only link-down or an explicit flush does. | Flows learned before the change keep their old path. After a VLAN remap they can keep leaving untagged until they idle out, and a long stream never idles. New ebtables or tc rules never see those packets. Client block is **not** affected: the wl macmode deny ACL disassociates the station. | `research/datapath/205_fclists.txt` (WPHY HW_tpl rows), `205_archer_dmesg.txt`. kconfig `CONFIG_BLOG=y`, `# CONFIG_BRIDGE_EBT_BLOG`. vmlinux.strings 8166-8194 (no ebtables or vlan skip reason). `/proc/fcache/stats/{evict,notify}`. | No. There is no fc/fcctl/archerctl call anywhere in ~/udeco. | R21 |
| D2 | **One HTB enqueue makes the whole vif non-accelerable; other qdiscs are bypassed.** | U (latent) | Future Deco shaping. Reusing openwrt `shape.go` (whole-vif htb, match-all ifb mirred) would trigger it. | `blog_skip(sch_htb)` takes every flow through that vif onto the slow path. That is 3 usable CPUs (isolcpus=3), and load is already 1.8-2.8. bcm_ingqos then drops under CPU congestion. A limiter built from tbf, police or prio alone only applies to a flow's first packets. | vmlinux.strings 8174-8175. traffic_control.ko imports `hnat_skip`. qos_kctl 'flush fc'. 'Archer IQ status changed from 0 to 1'. | No. The Deco path applies no shaping today (`bcmwifi/desired.go:63, 98`). | R24 |
| D3 | **fq_codel, codel, fq, cls_basic/flow, ematch and skbedit are not in this kernel, and shape.go swallows the failure.** | C (latent) | `openwrt/shape.go:54,58` reused on the Deco. | Each `tc qdisc add … fq_codel` fails. The script runs under `sh -s` with no `set -e` and ends with `true`, so SetShaping reports success and the leaves stay pfifo. | `/proc/config.gz`. Available: HTB, SFQ, TBF, PRIO, INGRESS, U32, FW, MIRRED, POLICE, GACT, IFB. TP-Link itself uses an sfq leaf. | No | R24 |
| D4 | **apsd and tpbr type br-lan ports; vifs the agent adds may get the wrong type.** | U | The agent puts a vif into br-lan that tpbr does not list. Today tpbr lists only wl02, wl12, wl13, eth0 and eth1; **wl03 is not in br-lan**. A 3rd native-VLAN SSID would land on wl04/wl14, which `/tmp/apsd.json` puts in the IoT compat_group 10. `brctl addif` emits no uevent, and apsd's reconfig needs awnd's link_state event. | tpbr (GRPREL) hooks `br_get_dst`, `br_ports_compatible` and loop avoidance, per port. An untyped or IoT-typed vif might not exchange unicast or broadcast with eth1 (norelay, compat 3) or with the other vifs. | `research/datapath/205_tpbr.txt` (`tpbrctl show`), `205_apsd.txt`. ko/tpbr.ko strings. `/proc/tpbr_filter/hw_switching=1`. | No. decosys keeps apsd and 'never touches tpbr' (`decosys.go:11-14`). | R22, R23 |
| D5 | **imsnoop restarts on every netdev the agent adds or removes, and manages only TP-Link's interface list.** | C (trigger), U (multicast impact) | Any add or remove of `wl*\|eth*\|eth*.*\|br*` while `mcsd.config.Enable=1`: creating or deleting eth1.<vid> or br-v<vid>, and wds peers. ifb* does not match. Restarts within 2 s of each other collapse into one. | The MDB and flood tables on br-lan are rebuilt (a multicast blip). imsnoop logs at daemon.err (1114 of 6596 log lines), which crowds the 1 MB log ring. Its ManagedInterfacesList is wl02, wl12, wl03, wl13, eth1, eth0, so a vif outside it (a 3rd SSID) may never be learned as a member, and its IPTV, CoAP or Matter multicast may be dropped. VLAN 491 collides with imsnoop's br-iptv. | `etc/hotplug.d/net/28-imsnoop:5-15, 22-24, 35-40`. `/tmp/ims.conf` is identical on all 3. `imsctl -g br-lan mdbtbl`. `/usr/lib/ims_reconf.sh`. | Partly. bcmwifi's VLAN steps are already diff-based (`plan.go:176-211`), so restarts happen only when the VLAN set changes. | R22, R23 |
| D6 | **/tmp, /var, /etc, /mnt and /dev are ramfs: the "420 kB tmpfs" limit is not enforced.** | C | Always (`# CONFIG_SHMEM is not set`). | No write ever fails with ENOSPC, and statfs reports 0 blocks. Every byte under /tmp/udeco and /etc/udeco is RAM that cannot be reclaimed, heading toward B8. Usage already exceeds the stated limit: /tmp is 2.8, 4.2 and 3.2 MB and /etc is 3.6-3.9 MB on the three units. | mountinfo `/tmp tmpfs size=420k` (0:15). `du -sk`. Shmem 0 kB. The wrong 420 kB claim is at `bcmwifi/bcmwifi.go:51` and `agent-design.md:26`. | No | R4, R30 |
| D7 | **Stopping awnd also silences its link_state events, so nothing reacts to an uplink change.** | U | The uplink moves between eth1 and eth0, or a cable is unplugged, after takeover. | apsd's 'eth link state change, need_reconfig' and smartipd's RE link handling no longer run. tpbr port types stay stale (on .205: eth1 norelay, eth0 relay), so broadcast or multicast through the new uplink may be filtered. | awnd is the only sender of `ubus send link_state/apsd.link_state/smartip` (on-device grep). `tpbrctl show`. | Partly. awnd is stopped; nothing takes over its job. | R9, R22 |
| D8 | **WDS peer hotplug bridges any backhaul STA straight into br-lan.** | C (code) | A `wdsX.Y.Z` netdev appears: a TP-Link Deco that has not been taken over joins wl01/wl11 while those BSSes are up (up today, zero peers). | `01-wds` runs `brctl addif br-lan wdsX.Y.Z.1`, `wl wds_enable 1`, a gratuitous ARP and an imsnoop restart. That adds a bridge port the agent did not create, which can loop with a wired path. | `etc/hotplug.d/net/01-wds:24-80`. wl01/wl11 on .205 have bss up, dwds 1, 0 peers. | Mostly. Apply takes wlN1 down (`apply.go:107`, `plan_test.go:82`); nothing re-checks afterwards. | R10d |
| D9 | **The master's TDP probe on UDP 20002 broadcast (membership, config push, unbind).** | C | The boot window, while tmpsvr answers. | The master can schedule to_update (a config push, B9) or to_reset (an unbind) for the unit. Once tmpsvr is stopped, the master ages the unit out after 4 missed probes and shows it offline. | Master `probe:29, 323-330, 673, 813-818`. The master's mesh_dev_list has .205 with countdown 4. udp 0.0.0.0:20002 is tmpsvr. | Steady state: yes (`services.go:102`). | R5; do not use 'Remove Deco' in the app |
| D10 | **Role escalation in the boot window once the master is no longer TP-Link.** | U | A satellite reboots while .241 runs the agent. awnd's RE stages go FIRST → … → HAP, then `repacd restart_in_cap_mode`. smartipd follows (HAP: restart dhcpd, fall back to the default lan IP). | A full Wi-Fi rebuild, a changed work_mode or role, a possible udhcpd, and frozen files that outlive awnd's stop. | awnd and smartipd strings. `/tmp/auto-wifi-network.conf` (scan every 6 s, aging 4 s). | Partly. `wifi.go:139-183` already defers apply while a rebuild is seen, but `rebuilding()` only matches repacd or /sbin/wifi in argv. Note that `/tmp/wifi_state` does not exist on this firmware. | R1, R10b, R17 |
| D11 | **Root-capable and adoption listeners are reachable from the whole LAN.** | C | Any br-lan host: wired LAN, Wi-Fi clients on br-lan SSIDs, other Decos. IPv4, plus IPv6 link-local only (the 'global' address has an all-zero prefix). | `/data/dropbear :22` allows root password logins (no -s/-g). On .205 the hash is the stock firmware md5crypt; .241 and .232 had /etc/shadow rewritten. `:2222` (agent ssh-adopt) accepts any password but filters on console_ip only. That port is not root-capable, but anything that can source or spoof 192.168.0.1 can redirect inform and authkey (a controller hijack). | iptables `zone_lan_ACCEPT -i br-lan -j ACCEPT`. dropbear argv. `internal/device/sshadopt.go:66-71, 93`. | No. decosys installs only egress rules. | R5, R12 |
| D12 | **An unknown TMP client at 192.168.0.1 holds :20001 sessions to .241 and .232.** | C (observation) | Live now: .241 has 192.168.0.1:35370 (since master boot +144 s) and .232 has 192.168.0.1:49220. Neither dropbear session has a child process, so they are direct-tcpip port forwards to tmpsvr. | Something holding the mesh group key can drive units directly, not only through the master. 192.168.0.1 is also the agent's console_ip for :2222 (D11). | netstat with socket→pid on .241 and .232. The UCG has none of 2222 or 22201-22203 open. | No | R12, Q13 |
| D13 | **TP-Link's QoS htb is already the root qdisc on br-lan from boot.** | U | `S99qos` → `/lib/qos/core_qos.sh` on every boot. A later qos stop or reload (mode hotplug from awnd) deletes the br-lan root. | Any agent tc work on br-lan meets `qdisc htb 2: root … default 202` with sfq 202. That htb only shapes local traffic today; whether it also skips acceleration (D2) is untested. | `tc qdisc show` on .205. core_qos.sh 537, 563, 844. | No | R24 |
| D14 | **A netifd respawn may strip the agent's vifs from br-lan.** | U | netifd crashes and respawns, or a network restart (B5). | netifd's br-lan config names only `eth1 eth0`. It has system_if_clear_state ('Remove device … from bridge'), and nothing re-adds wl ports (there is no network.wireless object). Agent SSIDs could then lose their wired path. | strings /sbin/netifd. uci network.lan.ifname. | No | R10c |
| D15 | **A TP-Link client block can cut management SSH.** | U (low) | An app or luci client block pushed in the boot window against the management host's or gateway's MAC or IP. | `zone_lan` `block_entry_list` DROPs tcp 80, 22 and 20002, so :22 to the unit is lost until reboot. The chain is empty today. | `iptables -S zone_lan`. `/lib/firewall/tpcmd.sh _block_rt_access_*`. | No | R5 (an ACCEPT ahead of zone_lan) |
| D16 | **The master's nrd keeps steering clients toward .205's old TP-Link BSSIDs.** | U | Satellites are taken over while .241 is still TP-Link. | 802.11k/v steering toward BSSIDs that no longer exist or no longer match, so roams fail. | Master log `ar_pat_calc_cand_datarate: patrate for B0A7B93E1700`. | No | R29 (take over the master soon after, or use non-colliding BSSIDs) |
| D17 | **A management address on br-v<vid> would be dropped by INPUT.** | U | The agent ever puts its management IP on a VLAN bridge (management VLAN). | INPUT policy is DROP and only `-i br-lan` gets zone_lan ACCEPT, so inbound adopt and SSH would silently fail. | `iptables -S` on .205. | No | R5 (UDECO-IN follows the management interface) |

### 1.3 Cosmetic, or already handled

| # | Mechanism | St | Trigger | Effect | Evidence | Already handled? | Countermeasure |
|---|---|---|---|---|---|---|---|
| X1 | Cloud cron lines with absolute dates, and their re-adders | C | Cron lines added by cloud_client, cloud_getDevToken and report_get_device_status, scheduled about 24 h ahead (at least 120 s). | Token deletion, feature uploads and possibly aviraservice, if they ever fired. The year-field line fails to parse ('parse error at 2026'). | The crontabs. `cloud_client:6-41`. `cloud_getDevToken:107-115`. | **Yes.** `cron.go:36-56` drops them every 60 s, and cloud_* is stopped (`services.go:63-67`). | Optional: kill the orphan cloud_client NTP-wait subshell (R18) |
| X2 | `isTPLinkCron` misses TP-Link jobs prefixed with an interpreter or an echo | C | Router or FAP-with-DPI features add lines such as `*/10 * * * * echo 3 > …drop_caches`, `sh /lib/snort/checkSnortRules.sh …` and `sh /lib/netifd/dhcp6c_slaac.sh &`. None is present now. | These lines would be kept after takeover. | `app-classifier:9, 94-96`. `checkSnortRules.sh:6-7`. `dhcp6c.sh:120-121`. `cron.go:45-54`. | No | R15 |
| X3 | tsched schedules, and the leftover leds_night_mode procd trigger | C | A config.change on 'leds' → `leds_night_mode reload` → `leds_schedule TURN_ON` → `ubus call leds switch on`. Every writer of that config (tmpsvr, sync, uhttpd) is stopped. | Would undo a UniFi "LED off". The nightly flash write comes from `tsched.d/script.d/iot_device_stats` (saveconfig); tsched is stopped. | `ubus call service list {name:leds_night_mode}`. `/etc/tsched.d/*`. `services.go:85, 124`. | Mostly | R18, R10g (re-assert the LED state) |
| X4 | The replacement ntpd never writes TP-Link's sync marker `/tmp/run/ntpd.uptime` | U | **The default case at every boot**: the agent's ntpd (about 32 s) starts before TP-Link's (about 82 s) has synced. | cloud_client's wait loop and leds_set_nightmode spin `sleep 1` forever. `leds switch` with check:true is refused. The clock itself is fine: the gateway serves NTP at stratum 2. | busybox strings `/var/run/ntpd.uptime`. getopt has an undocumented `C`. `ntp.go:24`. | Mostly | R18; never pass check:true |
| X5 | Satellite timezone loop (`update_dst_from_ap`) | C | time_settings start or reload on an RE whose master is not TP-Link. | It polls the master every ~64 s forever. /etc/localtime is never written, so cron and log times shift to UTC. | `update_dst_from_ap:16-17, 60-91`. `/etc/init.d/time_settings:19-21`. | No | R18 |
| X6 | A firewall restart deletes UDECO-OUT (and re-runs persist_shell) | C | `/etc/init.d/firewall restart\|reload`, luci `vpn.lua`, or `nat.lua:591`. All are reachable only through uhttpd or tmpsvr, which are stopped. | Egress is open (and the INPUT policy is briefly DROP) until the next tick. | `/lib/firewall/core.sh:20, 84, 102-110`. `core_init.sh:311-320`. | **Yes**, within 60 s, but only when `egress` is on (`egress.go:66-93`, `wifi.go:160`). | R10g (count re-inserts) |
| X7 | New VLAN netdevs inherit IPv6 defaults | C | `ip link add … type vlan` and `brctl addbr br-v<vid>`. | The AP gets an fe80:: address and sends DAD and MLD into guest VLANs. ip6tables still drops everything except ICMPv6 and DHCPv6, apart from a brief ACCEPT window during `fw_stop`. | `/proc/sys/net/ipv6/conf/default/*` = 0, 1, 1, 1. `ip6tables -S`. | No | R25 |
| X8 | The TIPC bearer stays on br-lan (non-IP, so iptables cannot filter it) | C | Master tipc-server or nrd messages. | Nothing in userspace acts on them once tipc-server, sync-server, awnd and nrd are stopped. | `tipc-config -n/-nt`. `/etc/config/tipc_config`. | Yes (`services.go:52, 54, 78, 96, 99`) | Optional: self-check that no process holds a TIPC socket; test `tipc-config -bd=deco:br-lan` (Q17) |
| X9 | No RTC: the clock reads 2025-09-12 until NTP | C | Every boot. The agent starts about 10 s before the first sync. | Crash-loop entries recorded before the clock step are pruned, so a crash loop is undercounted. History files are mis-ordered and early inform times are wrong. | `# CONFIG_RTC_CLASS`. `/etc/init.d/sysfixtime`. `system.go:135-153`. `session.go:385`. | Partly. ntpd uses the gateway. | R7 |
| X10 | The evidence rings are short | C | Always: logd -S 1024 (about 10-13 KB/min, so it wraps in about 80 min), and dmesg is 16 KB. | Agent diagnostics, and the smartip, boot and button history, are overwritten. imsnoop and dropbear logins dominate the ring. | `logread` growth. `CONFIG_LOG_BUF_SHIFT=14`. | Partly. nrd, the largest source, is stopped. | R13 |
| X11 | Two agents can start at once (the PID file is not a lock) | C (code) | Two persist_shell runs overlap within milliseconds. That is realistic only under B2's duplicated cron lines. | Two agents inform under the same MAC and run competing hostapd applies. | `cmd/udeco-ap/system.go:84-100` (no flock, no O_EXCL). | No | R6 |
| X12 | neighbor_discover.ko keeps advertising the unit as a wired SON neighbour | U | Always (ethertype 0x893a, in kernel). | The master's view stays 'neighbour present' while TDP is silent. Diagnostic noise only. | `/proc/net/ptype` handler inside the module's range. | No | None (note only) |
| X13 | Broadcom rxchain power-save on the master | U | The nvram keys say 1800 s quiet → one RX chain. | Lower RX sensitivity overnight, **if** the setting is live. On .205 the live driver has it off despite the same nvram, which is evidence against. | nvram on .205 and .241. `wl` getters on .205 return 0. | No | Q12 (read .241's live value when allowed) |
| X14 | Only 3 CPUs are usable (`isolcpus=3 irqaffinity=0`) | C | Always. | Userspace and the slow path share CPUs 0-2, and every IRQ lands on CPU0. The Wi-Fi kthreads are SCHED_RR, so the agent cannot starve them, but losing acceleration (D2) costs more. | `/proc/cmdline` on all 3 units. | n/a | R3 (GOMAXPROCS stays at 3 or lower, sized for 3 CPUs) |

Counts: **12 breaks, 17 degrades, 14 cosmetic, 43 in all.** Of these, 29 are confirmed (C, including C-with-qualifier)
and 14 are unverifiable (U): breaks 10 C / 2 U, degrades 8 C / 9 U, cosmetic 11 C / 3 U.

---

## 2. Already neutralised (no new work; listed so nobody re-investigates)

- **Remote control in steady state**: TMP :20001, TDP :20002, sync-server, cloud_*, uhttpd and uhttpd-fw (`services.go:52-106`).
- **Absolute-date cron jobs**: see X1.
- **Firewall restart**: see X6.
- **TIPC daemons**: see X8.
- **tsched**: stopped, which also stops the reboot schedule and the nightly flash saves.
- **Hotplug mode/bridge subsystems**: dormant once awnd and wanDetection are stopped.
- **Remaining procd config triggers**: they fire only from reload_config, and no kept process reaches it without awnd.
- **No hardware watchdog**: `CONFIG_WATCHDOG` is unset and `ubus system watchdog` is offline.
- **No hung-task panic.**
- **debug_monitor and bcm_service_check**: inactive.
- **Kernel nvram (wlcsm)**: holds no runtime Wi-Fi keys.
- **bcmvlan**: has no rules on eth0/eth1.
- **Conntrack**: cannot be filled by client traffic (there is no br_netfilter).
- **LLDP and 802.1Q tags**: always reach the CPU.
- **Netdev counters and the FDB**: stay correct under acceleration.
- **powermanager**: touches only dutycycle and pwrthrottle.
- **The `bcm-wlan-drivers.sh` sysrq-reboot path**: gated on an empty nvram key.
- **zzzmonit**: keeps the persist line.
- **cron restart**: does not kill an agent started from cron.

---

## 3. Requirements

Each requirement names an owner and a test. Tests on .205 must follow the device rules. Anything that changes
persistent state, reboots the unit, or runs `wifi`, `network` or init scripts needs the user's go-ahead first.

### cmd/udeco-ap (startup, self-protection, self-check)

1. **R1 Boot gate (two phases).** At agent start, phase 1 only installs the inbound fence (R5). It runs no
   decosys stop, no bcmwifi Apply and no inform.
   - Phase 2 starts once all of the following hold:
     - `/tmp/done_boot` exists;
     - `/tmp/wifi_set_done` exists;
     - `/tmp/acsd2_channel_select_done` exists;
     - `/proc/uptime` ≥ 120 s;
     - no upgrade is in flight (R17).
   - Do not use `/tmp/wifi_state`; it does not exist on this firmware.
   - After the gate opens, run Enforce every 5 s until two passes in a row find no new target, for at least
     3 min, then fall back to 60 s.
   - Test: reboot .205 (with the user's OK) and check that:
     - the log shows the gate-open time;
     - no stop target is alive 10 s after the gate;
     - no 'Child connection from .241' on :20001 succeeds after phase 1;
     - the first inform lists both radios.
2. **R2 Hold the first inform and the provision apply** until the R1 gate passes. Keep the existing
   `rebuilding` deferral (`wifi.go:139-183`).
3. **R3 Memory and CPU limits.**
   - At start: `debug.SetMemoryLimit(48<<20)`, `GOGC=50`, and leave GOMAXPROCS at 3 or lower.
   - Write `oom_score_adj` = 300 (never negative), so the restartable agent dies before hostapd or netifd.
   - Test: unit-test the settings. On .205, read `/proc/<pid>/oom_score_adj` and `/proc/<pid>/status` VmRSS.
4. **R4 Memory self-watchdog.** Every tick:
   - read the agent's VmRSS, system MemAvailable, and `du` of `/tmp` + `/etc` (a file walk, never statfs);
   - if MemAvailable drops below 40 MB, shed scans and stats fan-out;
   - if VmRSS > 64 MB or MemAvailable < 20 MB, exit cleanly so persist_shell restarts the agent;
   - alarm when /tmp + /etc grows more than 8 MB above the baseline taken at start.
   - Test: inject the readings through a fake procRoot.
5. **R5 Inbound fence `UDECO-IN`.**
   - Build it as decosys code alongside Egress, idempotent like UDECO-OUT, v4 and v6, as INPUT rule 1, ahead of
     zone_lan.
   - Rules, in order:
     1. ACCEPT ESTABLISHED,RELATED and lo.
     2. ACCEPT tcp/22 from the configured management sources (default: 192.168.1.0/24 and the gateway).
     3. ACCEPT tcp/2222 from console_ip.
     4. DROP tcp/20001, tcp+udp/20002, tcp/80, tcp/443 and tcp/20003.
     5. Fall through for everything else.
   - Follow the management interface, so R5 also covers D17.
   - Install it in phase 1 of R1. Re-assert it every tick and count re-inserts.
   - Safety: if the management-source config is empty, rule 2 accepts :22 from all of br-lan.
   - Test (unit): rule generation.
   - Test (.205, with the user's OK):
     - from .241, `ssh -p 20001 root@.205` times out;
     - from the Mac, `ssh` to :22 still works;
     - the master shows .205 offline after 4 probes.
6. **R6 Single instance.** Take `syscall.Flock(LOCK_EX|LOCK_NB)` on `/tmp/udeco/udeco-ap.lock` and hold it for
   the whole process lifetime (`system.go:84-100`). A second start exits non-zero.
   - Test: start two agents concurrently in a unit test using a temp dir.
7. **R7 Clock-safe bookkeeping.**
   - Crash-loop accounting uses `/proc/uptime` (or monotonic time), not the wall clock.
   - Treat `time.Now()` earlier than 2026-01-01 as unsynced, and defer history writes and timestamped state until
     it passes.
   - Test: a unit test with a 2025 clock.
8. **R8 Address and DHCP watch.** Every tick:
   - (a) if br-lan carries any IPv4 address other than the current lease (192.168.0.1/22 in particular),
     `ip addr del` it at once and log a loud event;
   - (b) alarm on any `udhcpd` process, any `wifi disconn*` or `ethctl … phy-power` child, or any `smartip:`
     logread line containing disconnect, clear ip, phy-power or restart udhcpc.
   - Test: fake logread/ps/ip output in unit tests.
9. **R9 Loop guard and uplink tracking.**
   - Determine the uplink from carrier plus the port on which the gateway MAC (brforward) or the UCG's LLDP
     chassis is seen.
   - Default policy at takeover: remove the non-uplink port from br-lan unless the controller enables it.
   - If the gateway shows up on both ports: `brctl delif` the non-uplink port, run `fc flush --if <port>` (R21),
     and log.
   - On an uplink change: re-read `tpbrctl show` and alarm if the new uplink is typed norelay.
   - Re-assert every tick, because a netifd restart re-adds both ports.
   - Test on .205 (with the user's OK): plug eth0 into the same switch. eth0 is removed within one tick and
     broadcast counters stay flat.
10. **R10 Foreign-state self-check.** Each tick, report counts in inform/log for:
    - (a) the br-lan address (R8);
    - (b) `/tmp/work_mode` and role unchanged since takeover, and no repacd process;
    - (c) bridge membership: every agent vif in its intended bridge, the non-uplink port out (D14);
    - (d) `wl -i wl01/wl11 bss` down and no `wds*` netdev; otherwise bring the BSS down and run `brctl delif`;
    - (e) tpbr rows for agent vifs (R22);
    - (f) imsnoop restart count and apsd presence;
    - (g) the UDECO-OUT and UDECO-IN jumps present, with re-insert counts, and the LED state equal to the
      controller's intent (re-assert it via `ubus call leds`, never with check:true);
    - (h) the persistence hook: `uci get firewall.@include[*].path` contains `/data/persist_shell.sh`, the crontab
      has the persist line, and crond is running;
    - (i) no tddp or telnetd process;
    - (j) the R4 memory figures.
    - Test: table-driven unit tests over fake command output.
11. **R11 Reset button wrapper.**
    - At takeover, copy `/etc/rc.button/reset` to `/etc/udeco/reset.tplink` and install a wrapper in its place.
      The wrapper:
      - ignores ACTION=pressed (logs only);
      - on ACTION=released with `SEEN` ≥ 5, execs the saved script;
      - on a shorter press, logs and blinks the LED.
    - Re-install it every tick, because /etc is ramfs.
    - Document that a factory reset loses root (B4).
    - Test on .205: run the wrapper by hand with `ACTION=released SEEN=1` (expect no action) and
      `ACTION=pressed` (expect no action). Never run it with SEEN ≥ 5.
12. **R12 Harden ssh-adopt (:2222).**
    - Before adoption, keep console_ip filtering.
    - After adoption, require the controller-provided device SSH credentials instead of accepting any password
      (`sshadopt.go:66-71`).
    - Until the origin of the 192.168.0.1 :20001 sessions is known (D12), do not treat the source IP alone as
      authentication for anything beyond set-inform.
    - Test: unit tests for wrong and right passwords after adoption.
13. **R13 Logging budget.**
    - Write at most a few lines a minute to syslog; never one per inform.
    - Keep a small ring of rare events (gate open, reboot detected, rollback, R8/R9/R10 alarms) in `/tp_data/udeco`,
      at most 64 KB and written only on events.
    - Report `/proc/uptime` and a 'rebooted' event in inform.

### decosys

14. **R14 Write order for the takeover phases.** Stop dropbear :20001 and tmpsvr in the first phase, not
    phaseLast (`services.go:101` already says they are obsolete). Do this only after R17 confirms no upgrade is
    in flight.
15. **R15 Cron classification.**
    - In `isTPLinkCron`, strip a leading `sh`, `ash`, `/bin/sh` or `lua` interpreter (reuse `procs.go`
      program()) before the prefix test.
    - Classify the literal `echo 3 > /proc/sys/vm/drop_caches` job as TP-Link.
    - Add `TestCronClassification` cases for:
      - the drop_caches line;
      - the checkSnortRules line;
      - the `dhcp6c_slaac.sh &` line;
      - the year-field line `36 14 29 11 2026 /usr/sbin/report_get_device_status` (expect it dropped).
16. **R16 Cron invariant.** In `cronStep`, every Enforce:
    - make sure exactly one `* * * * * sh /data/persist_shell.sh` line exists, appending it if no line
      references `/data/persist_shell.sh`;
    - collapse byte-identical duplicate lines;
    - re-read the file just before the rename, and retry if its size or mtime changed (the lost-append race).
    - Do not touch any other user line.
    - Test with `testdata/crontab-232` (adds the line), `crontab-241` (adds it and keeps the pgrep line), and a
      file holding 64 duplicate persist lines (collapses to one).
17. **R17 Rebuild and upgrade guard.** Extend `rebuilding()` (`plan.go:208`) into a "do not interfere"
    detector. It reports:
    - an **upgrade in flight** when any of these is present:
      - `/usr/bin/upgrade`;
      - `nvrammanager -u`;
      - `sshhttpget`;
      - `/tmp/firmware_upgrade_flag`;
      - `/var/run/force_upgrade.pid`;
      - any file in `/tmp/upgrade/`;
    - the **rc.d boot chain** still running (`/etc/rc.common /etc/rc.d/S*` processes).
    - While an upgrade is in flight: never stop tmpsvr or dropbear, never kill nvrammanager, and warn loudly.
    - Test: unit tests using argv fixtures.
18. **R18 Extra targets.**
    - Add kill targets: `tddp`, `telnetd`, `update_dst_from_ap`, and the orphan cloud_client NTP-wait subshell
      (`/bin/sh /etc/rc.common /etc/init.d/cloud_client start`).
    - Add `leds_night_mode` to `triggerServices` (`services.go:124`); `reboot_schedule` and `time_settings` are
      optional.
    - Check whether `rsched` runs as its own process (Q14) and add it if so.
19. **R19 Report a missing apsd as drift** (do not restart it). Keep the `dwds_tpbr_check` strip, because its
    other branch restarts tpbr.
20. **R20 smartipd decision, staged on .205.**
    - Target: stop smartipd and its udhcpc, then run
      `udhcpc -i br-lan -s /tmp/udeco/dhcp.sh -p /var/run/udeco-udhcpc.pid`.
    - The script only sets the address, default route and resolv.conf, and deletes the 192.168.0.1 alias. It
      never calls wifi, ethctl or hotplug.
    - Until that ships:
      - the user reserves each Deco's IP on the UCG;
      - the agent pins smartipd's inputs (`/tmp/eth_runtime_info` from real carrier, `/tmp/is_online` present,
        `/tmp/work_mode` unchanged);
      - R8 watches for the outcomes.
    - Test: 24 h on .205 across one renew. No deauth, no PHY bounce, no udhcpd.
21. **R21 Flow-cache flush.** Owned by decosys or bcmwifi; a shared helper is fine.
    - After every bridge add/del, VLAN netdev create/delete, SSID→VLAN move, loop-guard delif, and (later)
      every ebtables or tc change: run `fc flush` scoped as narrowly as possible (`--if <dev>` or
      `--mac <sta>`, else the whole cache).
    - Then confirm with `grep -ic <mac> /proc/fcache/brlist` = 0.
    - Test on .205 (with the user's OK): remap an SSID to a VLAN while a client streams. Its rows leave brlist
      and its traffic shows up tagged.
22. **R22 tpbr and imsnoop for agent vifs on br-lan.** Choose one after the .205 test (Q3, Q4).
    - (a) Keep both. After each `brctl addif` to br-lan, require the vif's `tpbrctl show br-lan` row to equal
      wl02's (relay, grp 1, compat 255, class 0), and fix it with `tpbrctl setifgrp/setifcompat` otherwise. After
      each imsnoop restart, apply flood policy (`imsctl -s br-lan policy flood`).
    - (b) Detach. Stop apsd and imsnoop through procd, set `mcsd.config.Enable=0` **without** `uci commit`
      (ramfs), and run `tpbrctl detach br-lan`, so br-lan is a plain bridge like br-v<vid>.
    - Test: ARP, broadcast, mDNS and an IGMP join from a client on wl03 and wl04.

### bcmwifi

23. **R23 Vif choice.** Put br-lan SSIDs only on vifs that are already TP-Link-managed (wl02/wl12, then wl03/wl13)
    until R22 is settled. Refuse, with a logged reason, a 3rd native-VLAN SSID that would land on wl04/wl14.
    Never use VLAN 491. Keep VLAN changes in one burst (they already are) so imsnoop restarts coalesce.
24. **R24 Shaping rules, for when Deco rate limits are implemented.**
    - Use htb with sfq leaves only; fq_codel, codel, fq, tbf alone and police alone are not acceptable.
    - Use one `u32 match ether src <mac>` mirred filter per limited MAC, never `match u32 0 0`.
    - Explicitly replace or skip TP-Link's `htb 2:` root on br-lan.
    - Run every tc command with error checking (no `sh -s … ; true`).
    - Run `fc flush --mac` after each limit.
    - A/B test on .205: brlist still shows HW/SW hits for unlimited clients, and loadavg stays sane.
    - Fix openwrt `shape.go` error swallowing separately, if it is reused.
25. **R25 IPv6 on VLAN netdevs.** In `vlanUpSteps` (`plan.go:176`), write 1 to
    `/proc/sys/net/ipv6/conf/{<uplink>.<vid>,br-v<vid>}/disable_ipv6` after creating each device and before
    link up.
    - Test: a golden plan test, plus `ip -6 addr show br-v<vid>` empty on .205.
26. **R26 Hostapd apply gating.** The first Apply after start also requires the R1 gate.

### deploy (`deploy/deco-ap.sh`) and the user

27. **R27 Fail-safe ordering.** Deploy installs the binary and the supervise line only after preflight (R28)
    passes. Rollback stays a single command.
28. **R28 Preflight checks.** Refuse to deploy unless all of these hold:
    - `/etc/crontabs/root` has a line running `/data/persist_shell.sh`;
    - the guard string in `persist_shell.sh` occurs in the line it appends (this rejects .241's current file);
    - uci has the firewall include for `/data/persist_shell.sh`;
    - `/tp_data` keeps at least 1 MB free after install;
    - the off-device `udeco.json` does not list the target's MAC (or the user confirms that the container and
      the controller record were removed);
    - for .241/.232, the 192.168.0.1 :20001 client has been identified (D12).
    - Print the user checklist from R29.
29. **R29 User actions** (we do not do these ourselves):
    - Fix .241's guard to grep `/data/persist_shell`.
    - Optionally make the keepalive test listener-based (for example `netstat -ltn | grep -q ':22 '`) rather
      than `pgrep -f /data/dropbear`, which matches its own shell and the dropbear session children.
    - Turn off Auto Update in the Deco app.
    - Make no Deco-app changes and no 'Remove Deco' while any unit is taken over.
    - Reserve the Decos' IPs on the UCG.
    - Migration order: satellites first, then the master soon after (D16).
    - Optionally run /data/dropbear with `-s` (key-only).
30. **R30 Docs fixes.**
    - Replace "tmpfs (420 kB)" with "ramfs, unbounded, RAM-backed" in `bcmwifi/bcmwifi.go:51` and
      `agent-design.md:26`.
    - `agent-design.md` §3.5 should say the boot hook is the firewall include and that cron supervision exists
      only where the crontab has the line.
    - The `ntp.go:15` comment overstates sysntpd hotplug restarts: they happen only on wan ifup, which never
      fires in AP mode.
31. **R31 The lan default IP.** Tell the user that TP-Link's lan static address (192.168.0.1/22) equals the
    UCG's. The boot window (B5) cannot be fixed by the agent. The fix is to change the Deco lan IP to a
    non-colliding value in the app before takeover, if the app allows it in AP mode.

---

## 4. Refuted claims (do not act on these)

- Per-VLAN bridges with kernel multicast snooping left on are harmless: 4.1 floods when there is no querier, and
  link-local groups are never snooped. br-guest and br-iptv are snoop=1 too.
- Driver WMF following UniFi's multicast-enhance setting is controller intent, not a defect, and bcmwifi already
  sets it while the BSS is down.
- `dwds_tpbr_check` is not the only apsd watchdog: apsd is a procd instance with respawn. Stripping the line is
  correct.
- tddp and telnet starting after a factory reset or calibration is no threat to the agent, which is never running
  in those states.
- decosys does not keep the year-field cron line: the command is `f[5]` = `/usr/sbin/…`, so the line is dropped.
- `/tp_data` cannot fill from system_cfg resends: the controller resends only on a cfgversion change, and history
  is capped at 5.
- The agent cannot contend with the Wi-Fi datapath for CPU: wl0/wl1-kthrd run SCHED_RR at prio 5.
- Partial corrections already folded into the tables:
  - a client block is not bypassed by the flow cache;
  - the agent does no sniffer-based accounting;
  - `wifi.go` already defers apply during a rebuild;
  - `/tmp/wifi_state` does not exist;
  - RLIMIT_NPROC does not bind root;
  - the button emitter does set SEEN;
  - `iwpriv mcastenhance` is a no-op (there is no iwpriv);
  - the boot hook is the firewall include, not `/data/startup.sh`;
  - "MemFree 11-12 MB" is true only on .205;
  - the IPv6 'global' address is not routable;
  - :2222 is a controller-hijack risk, not root access;
  - "root hash identical on every X20" cannot be shown, because the hashes differ per unit;
  - the NTP-marker race is the default case, not a rare one;
  - the nightly flash write comes from iot_device_stats.

## 5. Open questions that need a live takeover test on .205

Each needs the user's go-ahead where it changes state or reboots.

1. **Q1 Boot gate (R1/R5).** Reboot with the agent installed. Measure the gate time, check that no :20001 login
   succeeds, and check that every late starter is stopped. Also check whether the S99 one-shots leave state
   behind (tc on br-lan, guest_eth iptables).
2. **Q2 Role escalation with an agent-run master (D10).** This can only be tested after .241 is taken over:
   reboot a satellite and watch work_mode, repacd and udhcpd.
3. **Q3 tpbr and agent vifs (D4).** ARP, broadcast and mDNS from a client on wl03 and on wl04 in br-lan, with
   tpbr kept, and then with it detached.
4. **Q4 imsnoop (D5).** Multicast (an IGMP join, IPTV-style 239.x) to a client on an unmanaged vif; then
   `Enable=0` without commit.
5. **Q5 netifd respawn (B5/D14).** Does it re-add 192.168.0.1/22, strip the wl ports from br-lan, or re-run
   lanv6 replug? Is `network reload` with unchanged config a no-op? (This needs a deliberate netifd restart.)
6. **Q6 smartipd replacement (R20).** 24 h across a lease renew.
7. **Q7 Persistence across SYNC_CONFIG (B11).** Does the master's user-config blob contain the firewall include?
   Is the include in .241's flash?
8. **Q8 HTB de-acceleration (D2).** A whole-vif htb versus a prio root with an htb child; read brlist and
   loadavg.
9. **Q9 VLAN remap of a live flow (D1/R21).** Without `fc flush`, does the old flow keep leaving untagged? With
   the flush, does it stop at once?
10. **Q10 Uplink move eth1 → eth0 (D7).** Check tpbr typing, ping, DHCP, mDNS and broadcast counters.
11. **Q11 Broadcom OOM-reboot threshold and timer (B8).** There are no kallsyms, so this can only be read from
    behaviour. Do not provoke it; take the measurement from any reboot that happens.
12. **Q12 rxchain_pwrsave_enable live on .241 (X13).** Read it when reads on .241 are allowed.
13. **Q13 The origin of the 192.168.0.1 :20001 TMP sessions (D12).** UCG process list or conntrack: does
    something on the gateway hold the mesh group key?
14. **Q14 Is `rsched` (S99reboot_schedule) a separate running process?**
15. **Q15 The reboots of all three units before the probes.** The cause is unknown and there is no trace in
    dmesg or /data. The R13 'rebooted' event and an uptime report will catch the next one.
16. **Q16 A stale UniFi record for b0:a7:b9:3e:17:00 (B12).** Check in the controller before the first inform.
17. **Q17 Is `tipc-config -bd=deco:br-lan` safe and useful (X8)?** It reverts at reboot.
18. **Q18 Is the button really named 'reset' (B4)?** Kernel strings say yes. Confirm from the R11 wrapper's log
    on a real short press.
