# U6 Pro study: config-apply

## Summary
I traced the whole config-apply path on the real U6 Pro (read-only; uid 0, so sudo was not needed). The controller's system_cfg is written to /tmp/system.cfg. `syswrapper.sh apply-config` then runs `ubntconf -c /tmp/system.cfg -p /tmp/running.cfg -d /tmp/apply.sh`. ubntconf compares the two files and writes a shell plugin script per config family into /etc/sysinit/*.conf. A fast apply runs only the commands for keys that changed. When fast apply is refused, `/usr/etc/rc.d/rc restart` stops and restarts every plugin in /etc/startup.list order.

Most Wi-Fi settings do not go into hostapd at all. They are applied as driver calls (`cfg80211tool <vap> <param>`): DTIM, U-APSD, client isolation, proxy-ARP, multicast enhancement, minimum and beacon rates, PMF bookkeeping, the per-SSID VLAN tag and 802.11k/v. hostapd gets a small per-VAP file (/etc/hostapd/<vap>.cfg) and is driven through `hostapd_cli -i global raw ADD bss_config=...`.

VLAN-per-SSID works through hostapd's dynamic-VLAN support:
- The driver tags all frames on the VAP (`vlan_id 2 1`).
- hostapd's vlan_file creates the 802.1Q device wifi0ap0.2 and adds it to bridge br0.2.
- br0.2 also holds the tagged uplink eth0.2.
- The bare VAP is explicitly taken out of the bridge (`brctl delif br0.2 wifi0ap0`).
- ebtables broute rules pass tagged frames up to the 802.1Q devices instead of bridging them.

Client isolation is done in the driver, inside one SSID only (`ap_bridge 0` + `isolation 1`). This site has no guest SSID, so guest isolation could not be watched live. Firmware code and strings show the method: the driver flag `guest_vap 1`, skb marks, ebtables nat GUESTIN/GUESTOUT chains and ipsets.

Important correction: this unit is Qualcomm (IPQ5018 + QCN9074, qca-wifi, cfg80211tool), not MediaTek. The firmware has a separate code path for a MediaTek U6-Pro revision. I saved 63 redacted artefacts under ~/udeco/docs/reference/u6pro/config-apply/.

## Report
# How a real U6 Pro turns controller provisioning into running config

**Device:** UniFi U6 Pro, firmware BZ.8.8.14, controller 11.1.50. All access was read-only over SSH. The account is uid 0, so sudo was not needed.

**The hardware is Qualcomm, not MediaTek.**
- `radio.1.name=Maple bus=ahb vendorid=0x17cb` is the IPQ5018 SoC radio (2.4 GHz, `wifi0`).
- `radio.2.name=Pine bus=pci id=0x17cb1104` is a QCN9074 (5 GHz, `wifi1`).
- The firmware uses `cfg80211tool`, `wlanconfig`, `/lib/wifi/qcawifi*.sh`, `/tmp/IPQ5018` and `/tmp/qcn9000`.
- `syswrapper.sh` has a separate `MTK_UAP`/`RADIO_MT7622` branch ("skip U6-Pro mt7622 radio"), so a MediaTek U6-Pro revision exists. This unit (sysid 0xa650) is not it.

All saved artefacts are under `~/udeco/docs/reference/u6pro/config-apply/`.

## 1. Where the provisioned config lives

| File | What it is |
|---|---|
| `/tmp/system.cfg` (saved as `tmp_system.cfg.redacted`) | The controller's `system_cfg` exactly as received. It is the file that gets applied. |
| `/tmp/running.cfg` | The last config that was applied. It was byte-identical to system.cfg (`cmp` printed `same`). |
| `/tmp/previous.cfg` | The config before the last apply. |
| `/tmp/diff.cfg` | Output of ubntconf: `+key` added, `~key` changed, `-key` removed. |
| `/tmp/apply.sh` | The generated fast-apply script. |
| `/var/run/fastapply/<timestamp>/{previous,current,diff}.cfg,apply.sh,fastapply.log` | History of the last 10 applies. |
| `/etc/persistent/cfg/mgmt` | The `mgmt_cfg` (authkey, cfgversion, inform URL, `use_aes_gcm`). |
| `/tmp/setmgmt.cfg` | The last `mgmt_cfg` received. |
| `/etc/persistent/cfg/blocked_sta` | The controller's block-client list. It persists across reboots. |
| `/tmp/default.cfg`, `/usr/etc/default-a650.cfg` | Factory defaults. |

**Who writes it:** mcad (pid 3529) calls `syswrapper.sh apply-config`. Log evidence:

```
syswrapper[14177][3529]: [apply-config] using fast apply ... Provision took 2 sec, full=0
```

### Key families in system.cfg

**`radio.N.*`** — one block per radio:
- phyname, devname, `ieee_mode` (11nght20 / 11naht160)
- channel, txpower_mode/txpower, `countrycode=356`
- antenna/gain, ampdu, cwm, `acsdfs`, bcmc_l2_filter, bgscan, hard_noisefloor
- Global keys: `radio.countrycode` and `radio.outdoor`.

**`aaa.N.*`** — security, which ends up in hostapd. The same index N as `wireless.N`, the same devname and the same `id`:
- ssid, devname, `br.devname`, `driver=madwifi`, `wpa=2`
- `wpa.key.1.mgmt` (WPA-PSK, or SAE alone with `wpa3.transition=enabled`), `wpa.psk`, `wpa.1.pairwise`, `wpa.group_rekey`
- pmf.status / pmf.mode / pmf.cipher, `ft.status`, `wpa3.ft.status`, `11k.status`, `bss_transition`
- proxy_arp, is_guest, tdls_prohibit, p2p, country_beacon, `sae.anti_clogging`, `sae.sync`, iapp_key, radius.*, hide_ssid
- Defined in the binary but not used at this site: `mobility_domain`, `ft_over_ds`, `ft_r0r1_*`, `rsn_preauth`, `radius.auth/acct.N.*`, `radius.das.*`, `owe_*`, `hs20.*`.

**`wireless.N.*`** — per-VAP driver settings:
- mode, devname, parent, usage (user / guest / uplink / downlink), id, status, ssid, hide_ssid
- `l2_isolation`, `is_guest`, mac_acl.status/policy, wmm, uapsd, puren/pureg
- `mcast.enhance`, `multicast.inspect`, mcastrate, bga_filter, `dtim_period`
- `minrate_data`, `beacon_rate`, `mgmt_rate`, `minrate_cck_rates.status`
- qbssload, iot, no2ghz_oui, schedule_enabled, vwire/vport/wds/autowds, element_adopt, `btm_disassoc.status`
- Defined in the binary only: `advanced_isolation.*`, `ap_bridge_mode`, `minrate_below_disable`, `multicast.suppressor`.

**Networking:**
- `vlan.N.devname/id` — tagged sub-interfaces.
- `bridge.N.devname`, `.port.M.devname`, `.stp.status`, `.fd`.
- `netconf.N.devname/ip/up/promisc` — interface addresses and flags.
- `ebtables.N.cmd` — raw ebtables arguments; `ebtables.add_vlan.status`.
- `iptables.*`, `ip6tables.*`, `ipset.*`, `redirector.*`, `dnsmasq.*` — guest/portal features, all disabled here.

**Other families:**
- `mark.N.name/bits/shift/location`: `guest` 2 bits at shift 30 in the skb; `vapid` 5 bits at shift 11 and `associd` 11 bits at shift 0, both in the ubnt mark field.
- `bandsteering.*`, `stamgr.*` (minrssi, loadbalance), `qos.*` (group / vap / if rates). All disabled at this site.
- `mesh.*`, `connectivity.*`, `switch.*`, `dhcpc.*`, `resolv.*`, `route.*`, `syslog.*`, `netconsole.*`, `sshd.*`, `users.*`, `ntpclient.*`, `pathmon.*`, `dpi.ip/port`, `unifi.*` (version, mcip, key, siteid), `system.*`, `locale.*`.

## 2. The apply engine: ubntconf, plugins and hostapd

1. `syswrapper.sh apply-config` runs `do_fast_apply`, which runs `ubntconf -c /tmp/system.cfg -p /tmp/running.cfg -d /tmp/apply.sh`.
   - On success, `/bin/sh -x /tmp/apply.sh` runs.
   - Otherwise it does a full provision: `/usr/etc/rc.d/rc restart`. That stops every plugin in reverse order of `/etc/startup.list`, regenerates `/etc/sysinit/*.conf` with `/sbin/ubntconf`, and starts every plugin in order. Kernel modules are reloaded only when `radio.outdoor` changed.
2. **Plugin start order** (`/etc/startup.list`): system resolv syslog users ledbar radio wireless mesh element_adopt wevent spdtst ebtables diag_lite_log vlan bridge switch_vlan unifi_block mcsd switch net connectivity route dhcpc certs aaa ntpclient mdns redirector poepass lldpd pathmon unifi infrared.
3. Each plugin is a shell file with `plugin_start` and `plugin_stop`, sourced by `run_plugin` in `/usr/share/ubntconf/plugin.funcs`. `ubntconf` is a symlink to `ubntbox`, a C multi-call binary; it holds the command templates (see `ubntbox-config-strings.txt`).
4. **Fast apply is fine-grained.** Observed example: the diff was `~sshd.status=enabled`, `+wireless.2.btm_disassoc.status=disabled`. The generated apply.sh:
   - ran a single `cfg80211tool "wifi0ap0" no2ghz_oui ...`
   - moved the new wireless.conf into /etc/sysinit
   - ran `run_plugin sshd stop`/`start`
   - set `FAST_RELOAD_VAPS=true` and called `syswrapper.sh hostapd-reload-vaps`
   - deduplicated inittab and ran `init -q`.
5. **hostapd** is a single global process, `hostapd -s -g /var/run/hostapd/global` (started by `hostapd_wrapper.sh` from inittab). BSSes are added by `hostapd_cli -i global raw ADD bss_config=<vap>:/etc/hostapd/<vap>.cfg` and removed with `REMOVE` (`unifi_hostapd_funcs.sh: hostapd_add_or_reload_bss`).
   - The base `.cfg` (ssid, wpa, vlan_*) comes from the aaa generator.
   - `hostapd_config_update` then appends channel, ht_capab/vht_capab (read from `/sys/class/net/<vap>/cfg80211_htcaps`), `ieee80211n/ac/ax`, `he_oper_chwidth` and `he_oper_centr_freq_seg0_idx`, using `/var/run/wifiN.{ch,bw,band,mode}`.
   - `/var/run/<vap>.reload` forces a REMOVE+ADD.
   - Schedules are enforced at apply time (`within_schedule`).
6. **Hooks:** `/var/run/if_up_hook.<vap>` holds commands run on interface up, for example `iwconfig wifi1ap1 txpower 24` and `cfg80211tool <vap> vap_contryie 1`.

### Generated hostapd config (redacted: `hostapd/wifi1ap1.cfg.redacted`)

```
interface=wifi1ap1
driver=nl80211
nas_identifier=$bssid
ssid=Example Network
wpa_group_rekey=3600
wpa_group_update_count=4
wpa_gmk_rekey=86400
beacon_prot=0
wpa_passphrase=***REDACTED***
sae_require_mfp=1
sae_password=***REDACTED***
sae_anti_clogging_threshold=5
sae_sync=5
accept_mac_file=/etc/hostapd/wifi1ap1.accept
vlan_tagged_interface=eth0
vlan_naming=1
vlan_bridge=br0.
vlan_file=/etc/hostapd/wifi1ap1.vlan
wpa=2
eapol_version=2
ieee80211w=1
group_mgmt_cipher=AES-128-CMAC
wpa_pairwise=CCMP
wpa_key_mgmt=WPA-PSK SAE
wlan_id=3c27
iapp_key=***REDACTED***
dpi_port=10101
dpi_ip=192.168.1.1
own_ip_addr=192.168.1.32
he_oper_chwidth=2
he_oper_centr_freq_seg0_idx=50
ht_capab=...[HT40-][SHORT-GI-40]
vht_capab=...
ieee80211n=1
ieee80211ac=1
ieee80211ax=1
channel=40
```

`wlan_id`, `iapp_key` and `dpi_*` are Ubiquiti-patched hostapd options. The file has **no** `dtim_period`, `ap_isolate`, `proxy_arp`, `uapsd`, `rrm_*`, `bss_transition`, `max_num_sta` or rate options; those go to the driver.

**Proof that the driver value wins:**
- `hostapd_cli -i wifi1ap1 status` reports `dtim_period=2` (hostapd's default).
- `cfg80211tool wifi1ap1 get_dtim_period` reports `3`, which matches `wireless.2.dtim_period=3`.

### Driver settings per VAP (`sysinit/wireless.conf`, sent as one `cfg80211tool_batch`)

`dtim_period`, `uapsd`, `ap_bridge`, `isolation`, `mcastenhance`, `minrate_data`, `bcast_rate`, `mcast_rate`, `mgmt_rate`, `set_bcn_rate`, `minrate_nobelow`, `pureg`, `puren`, `hide_ssid`, `qbssload`, `dgaf_disable`, `rrm 1` (always), `twt_responder 3`, `wds 0`, `guest_vap`, `randomized_gtk 0`, `maccmd_sec 2`, `mc_inspect 1`, `bcfilt*`, `btm_dis_thld -80`, `btm_disassoc`, `acparams 1 0 1 0`, `enablertscts 0x21`, `countryie 1`.

`sysinit/aaa.conf` sets: `cfg80211tool <vap> vlan_id <vid> <tagged>`, `proxyarp`, `wnm`, `/var/run/pmf_mode.<vap>`, and `syswrapper.sh handle-dyn accept-mac apply`.

Getter results that confirm the values took effect:

| Getter | wifi0ap0 | wifi1ap1 |
|---|---|---|
| `get_ap_bridge` | 0 | 1 |
| `get_proxyarp` | 0 | 1 |
| `g_mcastenhance` | 0 | 5 |
| `get_rrm` | 1 | 1 |
| `g_vlan_id` | `svlan-2` | `default-1` |
| `get_mcast_rate` | 1000 | 6000 |

### Radio settings (`sysinit/radio.conf`)

- `wlanconfig wifi1ap1 create wlandev wifi1 wlanmode ap -cfg80211`
- `cfg80211tool wifi1ap1 mode 11AHE160` (from `ieee_mode` 11naht160)
- `cfg80211tool wifiN setCountryID 356`
- `txchainmask`/`rxchainmask`, `ant_gain`
- `block_acs_channel` lists
- `dcs_enable 0`, `obss_rssi_th 30`, `preCACEn`
- The txpower command goes into the if_up hook.

Note that `txpower_mode=high/medium` gave 24/14 dBm even though `txpower=6`. autotxpow is also running.

## 3. Mapping: system.cfg key to UniFi runtime to Broadcom `wl` + hostapd equivalent

"Inference" in the right-hand column means I did not verify it on a Deco; the left-hand columns are observed on the U6 Pro.

| system.cfg key | Real U6 Pro (QCA) runtime | Broadcom wl + hostapd equivalent |
|---|---|---|
| `aaa.N.ssid` / `wireless.N.ssid` | hostapd `ssid=`; `iwconfig <vap> essid` | hostapd `ssid=` |
| `aaa.N.wpa=2`, `wpa.key.1.mgmt=WPA-PSK` | hostapd `wpa=2`, `wpa_key_mgmt=WPA-PSK`, `wpa_pairwise=CCMP`, `wpa_passphrase` | same hostapd options |
| `wpa.key.1.mgmt=SAE` + `wpa3.transition=enabled` | `wpa_key_mgmt=WPA-PSK SAE`, `sae_password=<same psk>`, `sae_require_mfp=1`, `ieee80211w=1` | same (OpenWrt `sae-mixed`); wl needs `wl mfp`/SAE offload off (inference) |
| `aaa.N.pmf.status/mode/cipher` | `ieee80211w=<mode>` (only when enabled), `group_mgmt_cipher=AES-128-CMAC`, `/var/run/pmf_mode.<vap>` | hostapd `ieee80211w`; `wl -i wlX.Y mfp` if the driver does MFP (inference) |
| `aaa.N.wpa.group_rekey` (3600 / 0) | `wpa_group_rekey=3600`, `wpa_gmk_rekey=86400`, `wpa_group_update_count=4`; a value of 0 makes both 0 | hostapd same |
| `aaa.N.sae.anti_clogging` / `sae.sync` | `sae_anti_clogging_threshold=5`, `sae_sync=5` | hostapd same |
| `aaa.N.hide_ssid` / `wireless.N.hide_ssid` | driver `hide_ssid "0/1"` | hostapd `ignore_broadcast_ssid` or `wl -i wlX.Y closed 1` |
| `aaa.N.proxy_arp=enabled` | driver `cfg80211tool <vap> proxyarp 1` (bridge `proxy_arp_wifi` stays off) | hostapd `proxy_arp=1` + bridge port `proxyarp_wifi`, or Broadcom `wl proxy_arp` if the build has it (inference) |
| `aaa.N.bss_transition` | driver `wnm 0/1`; when on, also `hostapd_cli set bss_transition 1` (template string) | hostapd `bss_transition=1` + `wnm_sleep_mode`; `wl wnm` (inference) |
| `wireless.N.btm_disassoc.status` | driver `btm_disassoc 0/1`, `btm_dis_thld -80` | no hostapd equivalent; agent-side BTM-then-deauth (inference) |
| `aaa.N.11k.status` | driver `rrm 1` **always**; `11k.status` only starts or stops the neighbour-scan scheduler (`syswrapper.sh 11k-boot`/`11k-stop`) | hostapd `rrm_neighbor_report=1`, `rrm_beacon_report=1`; `wl rrm` (inference) |
| `aaa.N.ft.status`, `mobility_domain`, `ft_*` | template strings: `mobility_domain=%s`, `r0kh=ff:ff:ff:ff:ff:ff * <key>`, `r1kh=00:00:00:00:00:00 00:00:00:00:00:00 <key>`, `ft_psk_generate_local=1`, `pmk_r1_push=1`, `reassociation_deadline=3000`, `ft_over_ds`, `ft_r0_key_lifetime`, `rkh_pos_timeout=86400` (not live; FT is off here) | hostapd same (needs `CONFIG_IEEE80211R`) |
| `aaa.N.iapp_key`, `dpi.ip/port`, `wlan_id` | Ubiquiti-patched hostapd options | no equivalent; drop |
| `wireless.N.l2_isolation=enabled` | driver `ap_bridge 0` + `isolation 1` (stops client-to-client traffic in the same BSS) | hostapd `ap_isolate=1` / `wl -i wlX.Y ap_isolate 1` |
| `wireless.N.is_guest=true` | driver `guest_vap 1`, `/var/run/vapusage=guest`, ebtables nat mark `guest` (skb bits 30-31); controller-sent `ebtables.N.cmd` GUESTIN/GUESTOUT chains + ipsets (guest_portal_funcs.sh) | `ap_isolate` + ebtables/nftables bridge filter on the VAP (inference) |
| `wireless.N.dtim_period` | driver `dtim_period N` (hostapd reports its default, 2) | hostapd `dtim_period`, or `wl -i wlX.Y dtim N` |
| `wireless.N.uapsd` | driver `uapsd 1` | hostapd `uapsd_advertisement_enabled=1`; `wl wme_apsd 1` |
| `wireless.N.wmm` | WMM always on, `acparams 1 0 1 0` | hostapd `wmm_enabled=1` |
| `wireless.N.minrate_data`, `beacon_rate`, `mgmt_rate`, `minrate_cck_rates.status` | driver `minrate_data 1000`, `bcast_rate`/`mcast_rate`/`mgmt_rate`/`set_bcn_rate 1000`, `minrate_nobelow 1`. With no minrate: 6000 kbps on 5G and `minrate_nobelow 0` | hostapd `supported_rates`/`basic_rates`/`beacon_rate` per BSS; `wl -i wlX.Y rateset`, `bcmc_rate` (per-BSS support uncertain, inference) |
| `wireless.N.mcastrate` | `mcast_rate` | `wl mrate` (inference) |
| `wireless.N.mcast.enhance=1` | driver `mcastenhance 5` (multicast converted to unicast) + `mcsd` IGMP snooping on every bridge (`mcsctl -s br0 state enable`, `policy flood`, `aging 260`) | Broadcom WMF `wl -i wlX.Y wmf_bss_enable 1` or bridge `multicast_to_unicast` + `igmp_snooping` (inference) |
| `wireless.N.multicast.inspect` | `mc_inspect 1`, `/proc/ui_multicast/mc_inspect/mdns_enabled` | no equivalent |
| `wireless.N.qbssload` | `qbssload 0/1` (on when the key is absent) | hostapd `bss_load_update_period=60` |
| `wireless.N.pureg/puren` | `pureg`, `puren` | `wl gmode`, `wl nmode` (inference) |
| `wireless.N.mac_acl.status/policy` + blocked_sta | `maccmd_sec 2` (deny); `accept_mac_file`; `/etc/persistent/cfg/blocked_sta` written to `/sys/class/net/<vap>/blocked_sta`; `addmac_sec` + `kickmac` | hostapd `macaddr_acl=0` + `deny_mac_file`; `wl macmode 1`/`wl mac` |
| `wireless.N.schedule*` | `/var/run/schedules/schedule.<vap>` lines (`0=00:00-23:59` ...); `within_schedule` REMOVEs or ADDs the BSS | agent-side `hostapd_cli disable`/`enable` |
| `wireless.N.iot=enabled` (IoT SSID) | `qbssload=disabled`, `dtim 1`, CCK minrates; `wifitool setUnitTestCmd 10 ...` (opaque) | partly: dtim and rates only |
| `radio.N.channel`, `ieee_mode` | `/var/run/wifiN.{ch,bw,mode}`; driver `mode 11AHE160`; hostapd `channel`, `he_oper_chwidth`, `he_oper_centr_freq_seg0_idx`, ht/vht_capab | hostapd `channel`/`vht_oper_*`, or `wl chanspec 40/160` |
| `radio.N.txpower_mode`/`txpower` | `iwconfig <vap> txpower <dBm>` in the if_up hook; autotxpow daemon | `wl txpwr1 -o -d <dBm>` (inference) |
| `radio.countrycode=356` | `cfg80211tool wifiN setCountryID 356` | `wl country IN/xx` |
| `stamgr.N.minrssi.*` | template: `cfg80211tool <vap> minrssi N`, `/var/run/<radio>.minrssi` (off here) | hostapd `rssi_reject_assoc_rssi` + agent kicks; `wl assoc_rssi_thresh` (inference) |
| `bandsteering.N.*` | defined in the binary, off here; no daemon running | agent-side (inference) |
| `qos.vap.N.*` (user-group rate limits) | `qos_control.sh`: tc HTB root 1:, class 1:100 per VAP, per-STA classes with fq_codel, `fw` filter on the ubnt mark (`vapid<<11 \| associd`, from `mark.*`) | tc HTB on wlX.Y keyed by MAC (u32/flower), or Broadcom per-STA rate limits (inference) |
| `vlan.N.devname/id` | `vconfig add eth0 <vid>` (`DEV_PLUS_VID_NO_PAD`), IPv6 disabled on it | `ip link add link <uplink> name <uplink>.<vid> type vlan id <vid>` |
| `bridge.N.*` | `brctl addbr`, `multicast_snooping 0` (then mcsd sets it to 1), `setfd 1`, `stp off`, prio 65535, `/sys/class/net/<br>/brif/<uplink>/uplink 1` (custom) | `ip link add type bridge` + addif |
| `netconf.N.*` | `ifconfig <dev> 0.0.0.0 [promisc] up/down` + allmulti | `ip link set` |
| `ebtables.N.cmd` | executed verbatim (see section 4) | not needed on stock Linux (see section 4) |

## 4. How VLAN-per-SSID is built

The 2.4 GHz "EXN IOT" SSID is on VLAN 2.

**Config sent by the controller:**

```
vlan.1.devname=eth0  vlan.1.id=2
bridge.2.devname=br0.2
bridge.2.port.1.devname=wifi0ap0
bridge.2.port.2.devname=eth0.2
netconf.3.devname=br0.2  netconf.3.ip=0.0.0.0
aaa.1.br.devname=br0.2
ebtables.1.cmd=-t broute -A BROUTING -i wifi0ap0 -p 802_1Q -j DROP
ebtables.2.cmd=-t broute -A BROUTING --vlan-id 2 -p 802_1Q -j DROP
```

**Build sequence:**
1. **vlan plugin:** `vconfig add eth0 2` creates eth0.2, the tagged sub-interface of the uplink.
2. **bridge plugin:**
   - `brctl addbr br0.2` with br0's MAC.
   - `brctl addif br0.2 wifi0ap0` (temporarily) and `brctl addif br0.2 eth0.2`.
   - Marks eth0.2 as the bridge uplink (`/sys/class/net/br0.2/brif/eth0.2/uplink`).
3. **aaa plugin:**
   - `brctl delif br0.2 wifi0ap0` removes the bare VAP from the bridge.
   - `cfg80211tool wifi0ap0 vlan_id 2 1` makes the driver tag every frame from the VAP's stations with VLAN 2 (getter: `svlan-2`).
   - The untagged SSID gets `vlan_id 1 0` (`default-1`).
4. **hostapd** (`wifi0ap0.cfg`: `vlan_tagged_interface=eth0`, `vlan_bridge=br0.`, `vlan_naming=1`, `vlan_file=/etc/hostapd/wifi0ap0.vlan`). The vlan file contains:
   ```
   *	wifi0ap0.#
   2	wifi0ap0.2	br0.2
   ```
   hostapd's full dynamic-VLAN code creates the 802.1Q device `wifi0ap0.2` on top of the VAP and adds it to `br0.2`. The `*` wildcard line allows RADIUS-assigned VLANs: `wifi0ap0.<vid>` is placed in `br0.<vid>` together with `eth0.<vid>`.

**Result:**

```
br0    eth0, wifi1ap1
br0.2  eth0.2, wifi0ap0.2
```

```
/proc/net/vlan/config:
  eth0.2     | 2 | eth0
  wifi0ap0.2 | 2 | wifi0ap0
```

**What the ebtables broute rules do.** In the broute table, DROP means "do not bridge; pass the frame up the stack". This ensures tagged frames from the VAP, and VLAN-2-tagged frames arriving on eth0 (which is a port of br0), reach the 802.1Q devices rather than being bridged untagged into br0. Packet counters were 0.

On a stock kernel the VLAN device takes the frame before the bridge handler does. So for a Deco agent that puts the VAP *untagged* straight into a per-VLAN bridge (`br-uow<vid>` over `<uplink>.<vid>`), these rules are not needed (inference). That untagged design is functionally the same as the UniFi result.

**Guest and client isolation:**
- `l2_isolation` gives `ap_bridge 0` + `isolation 1` in the driver. This blocks client-to-client traffic within one BSS only. There are no bridge-port `isolated` flags or ebtables rules, and other bridge ports are not isolated.
- Guest SSIDs (none configured here, so not observed live) get:
  - `guest_vap 1` in the driver;
  - `/var/run/vapusage.<vap>=guest`;
  - ebtables nat `-j mark --mark-or <guest bit 30>` on the VAP or its VLAN sub-interface (`guest_update_interface_ebtables`, also run as `syswrapper.sh wireless-vlan-add` when hostapd creates a VLAN device);
  - controller-supplied `ebtables.N.cmd`/`iptables.N.cmd` chains (GUESTIN/GUESTOUT, authorized-guest ipset, REDIRECTOR for the portal).

  Sources: `scripts/guest_portal_funcs.sh` and the ubntbox strings `ebtables -t nat -%c PREROUTING --in-interface %s -j mark %s %#x`.

**Secrets:** I redacted every saved file with an awk filter. Values I confirmed must not be stored and redacted in place: the mesh SAE/PSK in uplink.conf, `unifi.key` in spdtst.conf and ubnt_protocol.info, and the syslog `-E` key in syslog.conf. The format strings in `ubntbox-config-strings.txt` are only templates (`%s`).

## Key findings
- The hardware is Qualcomm, not MediaTek: IPQ5018 'Maple' (ahb, 2.4 GHz, wifi0) plus QCN9074 'Pine' (PCI 17cb:1104, 5 GHz, wifi1), using qca-wifi, cfg80211tool and wlanconfig. syswrapper.sh has a separate MTK_UAP/RADIO_MT7622 branch, so a MediaTek U6-Pro revision exists; this unit (sysid a650) is not it.
- Apply pipeline: mcad (pid 3529) calls `syswrapper.sh apply-config`, which runs `ubntconf -c /tmp/system.cfg -p /tmp/running.cfg -d /tmp/apply.sh` (ubntconf is the C binary ubntbox). This writes /tmp/diff.cfg (+/~/-) and per-plugin shell scripts in /etc/sysinit/<plugin>.conf. Fast apply runs only the commands for changed keys (here one cfg80211tool call plus an sshd restart, logged as 'Provision took 2 sec, full=0'). Otherwise `/usr/etc/rc.d/rc restart` stops and starts every plugin in /etc/startup.list order.
- hostapd is one global process (`hostapd -s -g /var/run/hostapd/global`). BSSes are added with `hostapd_cli -i global raw ADD bss_config=<vap>:/etc/hostapd/<vap>.cfg`. The .cfg is small (ssid, wpa, sae, vlan_*, plus the patched options wlan_id, iapp_key and dpi_ip/port); hostapd_config_update then appends channel, ht/vht caps and he_oper_*.
- Most per-SSID behaviour is set in the driver, not hostapd: `cfg80211tool <vap>` dtim_period, uapsd, ap_bridge/isolation, proxyarp, mcastenhance, minrate_data, bcast/mcast/mgmt/bcn rate, minrate_nobelow, pureg, qbssload, rrm, wnm, btm_disassoc, guest_vap, maccmd_sec, vlan_id. Proof: hostapd status shows dtim_period=2 while `cfg80211tool wifi1ap1 get_dtim_period` shows 3, matching wireless.2.dtim_period=3.
- VLAN-per-SSID: `vconfig add eth0 2` creates eth0.2 in br0.2. The bare VAP is taken out of br0.2 (`brctl delif br0.2 wifi0ap0`), the driver tags all frames (`cfg80211tool wifi0ap0 vlan_id 2 1`, getter `svlan-2`), and hostapd's vlan_file line `2 wifi0ap0.2 br0.2` creates the 802.1Q device wifi0ap0.2 and adds it to br0.2. The wildcard line `* wifi0ap0.#` enables RADIUS-assigned VLANs in br0.<vid>.
- The controller sends raw ebtables broute rules (`-i wifi0ap0 -p 802_1Q -j DROP`, `--vlan-id 2 -p 802_1Q -j DROP`). They make tagged frames go up to the 802.1Q devices instead of being bridged into br0; their counters were 0.
- l2_isolation is enforced only within one BSS by the driver (`ap_bridge 0` + `isolation 1`). There are no bridge-port isolation flags or ebtables rules. Guest isolation (not live here) is: driver guest_vap 1, an ebtables nat mark on guest bits 30-31, and controller-sent GUESTIN/GUESTOUT ebtables chains plus ipsets and a REDIRECTOR iptables chain (guest_portal_funcs.sh).
- 802.11k: the driver always gets `rrm 1`, even with aaa.N.11k.status=disabled. 11k.status only starts or stops the neighbour-scan scheduler (`syswrapper.sh 11k-boot`/`11k-stop`). 802.11v: aaa.N.bss_transition sets driver wnm plus `hostapd_cli set bss_transition`. FT exists only as templates: `r0kh=ff:ff:ff:ff:ff:ff * <key>`, `r1kh=00:00:00:00:00:00 00:00:00:00:00:00 <key>`, ft_psk_generate_local=1, pmk_r1_push=1, reassociation_deadline=3000.
- WPA2/WPA3 transition: the controller sends only `wpa.key.1.mgmt=SAE` plus `wpa3.transition=enabled` (and the psk twice). The AP turns this into wpa_key_mgmt=WPA-PSK SAE, sae_password equal to the psk, sae_require_mfp=1, ieee80211w=1 and group_mgmt_cipher=AES-128-CMAC. Group rekey 3600 also produces wpa_gmk_rekey=86400 and wpa_group_update_count=4; group_rekey 0 makes both 0.
- Multicast: mcast.enhance=1 becomes driver `mcastenhance 5` (multicast to unicast), and mcsd/mcsctl IGMP snooping runs on every bridge (policy flood, aging 260) regardless of SSID settings. multicast.inspect becomes `mc_inspect 1` plus the mDNS inspect /proc knobs.
- Per-client rate limiting (qos.*) uses qos_control.sh: a tc HTB tree on the VAP with an fw filter on the Ubiquiti skb mark (vapid<<11 | associd, from the mark.* keys) and fq_codel per station. qos is disabled at this site, so this was read from code only.
- Blocked clients persist in /etc/persistent/cfg/blocked_sta and are pushed into /sys/class/net/<vap>/blocked_sta for every user/guest VAP (in chunks of 220 MACs), plus `addmac_sec` and `kickmac` on block. With mac_acl policy deny the driver gets maccmd_sec 2 and hostapd gets accept_mac_file.

## Gaps vs our code
- internal/translate/translate.go:168-302: aaa.N.proxy_arp is never read. The real AP sets `cfg80211tool wifi1ap1 proxyarp 1` (getter proxyarp:1). The OpenWrt/hostapd equivalent is wifi-iface `proxy_arp 1` (hostapd proxy_arp=1 with bridge proxyarp_wifi).
- internal/translate/translate.go:168-302: wireless.N.mcast.enhance is not mapped. The real AP sets driver mcastenhance 5 and runs IGMP snooping on every bridge (sysinit/mcsd.conf). The equivalent is multicast_to_unicast on the wifi-iface plus bridge igmp_snooping, or Broadcom `wl wmf_bss_enable 1` (inference).
- internal/translate/translate.go:168-302: aaa.N.wpa.group_rekey is not mapped. The real hostapd gets wpa_group_rekey=3600, wpa_gmk_rekey=86400, wpa_group_update_count=4 (or 0/0 when group_rekey=0). aaa.N.sae.anti_clogging and aaa.N.sae.sync are not mapped either (real: sae_anti_clogging_threshold=5, sae_sync=5).
- internal/translate/translate.go:243 maps aaa.N.11k.status to ieee80211k on/off. The real AP always advertises RRM (driver `rrm 1`, get_rrm:1 even with 11k.status=disabled); 11k.status only controls the neighbour-scan scheduler. Our AP therefore drops the RRM capability when the controller has 11k off, which a real UAP does not.
- internal/translate/translate.go:244 handles aaa.N.bss_transition, but wireless.N.btm_disassoc.status is ignored (real: driver btm_disassoc 0/1 and btm_dis_thld -80).
- internal/translate/rates.go:67-70 collapses per-WLAN minimum rates to radio level. The real AP applies them per VAP (minrate_data, bcast_rate, mcast_rate, mgmt_rate, set_bcn_rate and minrate_nobelow on each VAP). The 5G SSID without a minrate still gets bcast/mcast/mgmt/beacon 6000 and minrate_nobelow 0. wireless.N.mcastrate is also not mapped.
- internal/translate/vlan.go:12-25 describes the VAP as sitting directly in the VLAN bridge. On the real AP the bare VAP is removed from br0.2 and hostapd creates the 802.1Q device wifi0ap0.2 (vlan_file) because the driver tags frames. Our untagged-VAP-in-br-uow<vid> design is functionally equivalent, so only the comment's model is wrong.
- internal/translate/vlan.go:63-71 uses the first port of br-lan as the uplink to tag. The controller names the uplink explicitly in vlan.N.devname (eth0), and the real AP tags exactly that device (`vconfig add eth0 2`).
- VLAN handling has no RADIUS-assigned VLAN support: no dynamic_vlan, vlan_tagged_interface, vlan_bridge or vlan_naming, nor anything like the '* <vap>.#' wildcard. The real AP always writes vlan_tagged_interface=eth0, vlan_bridge=br0., vlan_naming=1 and a vlan_file with a wildcard (internal/translate/vlan.go has none of this).
- internal/translate/translate.go:91: the handled map lacks 'ebtables', 'mark', 'mesh', 'iptables', 'ipset' and 'redirector', so the ebtables.N.cmd broute rules and the mark.* bit layout (guest bits 30-31, vapid 5 bits at 11, associd 11 bits at 0) are skipped. The broute rules are probably unnecessary on stock Linux (inference). internal/openwrt/guest.go reimplements GUESTIN/GUESTOUT separately.
- internal/translate/translate.go:218: the comment says U-APSD is 'UniFi default off'. Network 11.1 sends wireless.N.uapsd=enabled and the real driver has uapsd 1. The code reads the key correctly, so only the comment is wrong.
- internal/translate/qos.go:16-35 reads qos.vap.N.dwnlink/uplink maxspeed. The real AP limits per station (a qos_control.sh HTB class per vapid/associd with fq_codel) under a per-VAP class, not per VAP as a whole. Check that the agent's limiter is per client.
- wireless.N.qbssload (BSS Load IE; on when the key is absent, off for the IoT SSID), pureg/puren, uapsd/wmm acparams and multicast.inspect are not mapped anywhere in internal/translate. The hostapd equivalent for qbssload is bss_load_update_period.

## Open questions
- Guest SSID isolation was not observed live because this site has no guest WLAN. To capture the exact GUESTIN/GUESTOUT ebtables chains, ipsets and mark rules the controller sends, a temporary guest SSID would have to be enabled (not done: read-only).
- FT/802.11r, 11k-enabled, stamgr min-RSSI, band steering and qos rate limits are all disabled at this site. Their runtime form comes only from the ubntbox format strings and the scripts, not from live config.
- The meaning of `wifitool <vap> setUnitTestCmd 10 3 6 2 3` (2.4G) and `setUnitTestCmd 10 6 35 25 8 75 100 400` (5G), and of `no2ghz_oui "0,0,0,3,2,16,30"`, was not determined. They look like QCA vendor tuning (possibly IoT or probe suppression).
- txpower: radio.N.txpower=6 was ignored in favour of txpower_mode (medium gave 14 dBm on 2G, high gave 24 dBm on 5G through the if_up hook). The exact formula, and how much autotxpow adjusts it, was not traced.
- Broadcom equivalents in the mapping table (wl wmf_bss_enable, wl rateset per bsscfg, wl proxy_arp, wl assoc_rssi_thresh) are inferences and need checking against the Deco X20's wl build.
- Housekeeping: a sibling agent's file in the shared scratchpad (actions-scans/ap.sh) contains the SSH password in plain text, against the no-password-in-files rule. I did not modify it; whoever owns it should delete it.

# VERIFIER
## Corrections
- CLAIM: A MediaTek U6-Pro revision exists, based on syswrapper.sh's MTK_UAP/RADIO_MT7622 branch ('skip U6-Pro mt7622 radio').
  CORRECTION: This is not established. The same shared script attributes MT7622 to the U6-LR, and the comment at line 1169 is probably mislabelled. The point that matters more is that the model udeco emulates (UAL6/U6-Lite) is a MediaTek model, so the firmware takes the MTK_UAP branch for it: iwpriv instead of cfg80211tool, ra*/rai* VAP names, and no 11k neighbour scan (elevenk_*). Facts that are specific to QCA (for example 'rrm 1 always') cannot be carried over to what a real U6-Lite does without checking.
  EVIDENCE: config-apply/scripts/syswrapper.sh:22 `MTK_UAP=...grep -c -e MT`; :30 `RADIO_MT7622=`; :1169-1176 `skip U6-Pro mt7622 radio` with `iwpriv "$ath" set uif=` vs `cfg80211tool`; :2860-2862 `elif [ "${RADIO_MT7622}" = "1" ]; then # U6-LR write log to persistent`; :2654/:2658 `[ "$MTK_UAP" = "1" ] || elevenk_boot`.
- CLAIM: Fast apply runs only the commands for changed keys (here one cfg80211tool call plus an sshd restart).
  CORRECTION: Fast apply works per plugin section, not exactly per key. The diff added `wireless.2.btm_disassoc.status=disabled` (wifi1ap1), but the generated apply.sh ran `cfg80211tool "wifi0ap0" no2ghz_oui ...` on a different VAP and never issued `btm_disassoc` for wifi1ap1. It then replaced the whole wireless.conf and ran `hostapd-reload-vaps`. The diff also contained `~unifi.version`, `+sshd.auth.passwd` and `~sshd.1.ifname`, which the study did not mention.
  EVIDENCE: On the device, /var/run/fastapply/20261118211746/diff.cfg: `~unifi.version=11.1.50 +wireless.2.btm_disassoc.status=disabled ~sshd.status=enabled +sshd.auth.passwd=enabled ~sshd.1.ifname=br0`; apply.sh: `cfg80211tool "wifi0ap0" no2ghz_oui "0,0,0,3,2,16,30"`, `mv -f '/var/run/fast_apply/wireless.conf' "/etc/sysinit"`, `run_plugin sshd stop/start`, `FAST_RELOAD_VAPS="true"`.
- CLAIM: With mac_acl policy deny the driver gets maccmd_sec 2 and hostapd gets accept_mac_file.
  CORRECTION: accept_mac_file is not part of the deny mechanism. It is the dynamic per-MAC accept/VLAN file that `syswrapper.sh handle-dyn accept-mac` maintains (line format `MAC [VLANID]`). Here it holds only header comments, and no macaddr_acl is set, so hostapd uses its default (0). Blocking is done entirely in the driver: `maccmd_sec 2` plus the blocked_sta sysfs list. Also, the controller sends `wireless.N.mac_acl.status=enabled`/`policy=deny` on every WLAN even though site-level `macacl.status=disabled`. This per-WLAN deny ACL carries the block list and is unrelated to a user-configured MAC filter.
  EVIDENCE: hostapd/wifi0ap0.accept.redacted and wifi1ap1.accept.redacted contain only `# Dynamic entries below here` and `# SSID=...`; scripts/unifi_util_funcs.sh:100-104 (accept-mac, RELOAD_CMD=reload_accept_mac) and :190-205 (MAC then optional VLANID); tmp_system.cfg.redacted:118-119, 190-191 (`wireless.N.mac_acl.status=enabled`, `policy=deny`) vs :291 `macacl.status=disabled`; sysinit/wireless.conf:50,142 `maccmd_sec 2`.
- CLAIM: Fast apply keeps a history of the last 10 applies in /var/run/fastapply.
  CORRECTION: Ten is only the retention limit (`sed -e '1,10d'`). The device currently holds one entry (20261118211746), and provision counters show a single fast apply (count 1, 2 s) since boot.
  EVIDENCE: `ls /var/run/fastapply/` returned `20261118211746`; scripts/syswrapper.sh:1506 `ls -t /var/run/fastapply/ | sed -e '1,10d'`.

## Confirmed
- Hardware is QCA: radio names Maple (wifi0) and Pine (wifi1), kernel modules qca_ol/umac/wifi_3_0/qca_mcs, and cfg80211tool in use. Running `id` shows uid=0(3r4FNrkS), so sudo is not needed.
- /tmp/system.cfg and /tmp/running.cfg are identical (`cmp ... && echo same` printed `same`).
- The apply path is as described: `ubntconf -c /tmp/system.cfg -p /tmp/running.cfg -d /tmp/apply.sh` (syswrapper.sh:1511). It falls back to `/usr/etc/rc.d/rc restart` (:2747). rc regenerates the plugins with /sbin/ubntconf and reloads kernel modules only when the diff contains radio.outdoor (rc:50-55, 87-123). Plugins start in /etc/startup.list order (rc:137) and stop in reverse (rc:208).
- hostapd runs as a single global process: `hostapd -s -g /var/run/hostapd/global -P /var/run/hostapd/global.pid` (pid 3504). BSSes are added with `hostapd_cli -i global raw ADD bss_config=$bss_ifname:$cfg_path` and removed with REMOVE (unifi_hostapd_funcs.sh:291-304). A `/var/run/<vap>.reload` file forces REMOVE+ADD (:169-173).
- The driver value wins for DTIM. `hostapd_cli status` reports dtim_period=2 on both VAPs. `cfg80211tool get_dtim_period` reports 1 on wifi0ap0 (wireless.1.dtim_period=1) and 3 on wifi1ap1 (wireless.2.dtim_period=3).
- Driver getters re-run match the study's table. wifi0ap0: get_ap_bridge 0, get_proxyarp 0, g_mcastenhance 0, g_vlan_id svlan-2, get_rrm 1, get_uapsd 1, get_qbssload 0. wifi1ap1: ap_bridge 1, proxyarp 1, mcastenhance 5, default-1, rrm 1, qbssload 1.
- l2_isolation is enforced in the driver. `cfg80211tool wifi0ap0 g_isolation` returns 1 and wifi1ap1 returns 0. Note that `get_isolation` returns the unrelated `get_isolationen:0`, so g_isolation is the right getter. ap_bridge is 0 on the isolated SSID. The ebtables filter and nat tables are empty, and wifi0ap0.2 has bridge port `isolated off`.
- rrm is 1 on both VAPs while aaa.1.11k.status and aaa.2.11k.status are both disabled. ubntbox emits `%s "%s" rrm 1` unconditionally next to the `wireless.%d.ap` template (strings-ubntbox.txt:7358-7360).
- VLAN-per-SSID is built as described. brctl shows `br0: eth0, wifi1ap1` and `br0.2: eth0.2, wifi0ap0.2`. /proc/net/vlan/config lists `eth0.2|2|eth0` and `wifi0ap0.2|2|wifi0ap0` (RAW_PLUS_VID_NO_PAD). `ip -d link` shows wifi0ap0.2 as an `802.1Q id 2` device with master br0.2. aaa.conf runs `brctl delif br0.2 wifi0ap0` and then `cfg80211tool "wifi0ap0" vlan_id 2 1`. The vlan file contains `* wifi0ap0.#` and `2 wifi0ap0.2 br0.2`.
- The ebtables broute table holds exactly 2 rules with zero counters: `-p 802_1Q -i wifi0ap0 -j DROP , pcnt = 0` and `-p 802_1Q --vlan-id 2 -j DROP , pcnt = 0`.
- mark.* layout: guest 2 bits at shift 30 (location skb); vapid 5 bits at shift 11 (ubnt); associd 11 bits at shift 0 (ubnt). No tc qdiscs are set: every device shows `noqueue`. qos_control.sh builds a per-station HTB class keyed by `(VAP << associd_bits) + AID` with fq_codel.
- WPA3 transition: aaa.2.wpa.key.1.mgmt=SAE with wpa3.transition=enabled and wpa.psk sent twice becomes hostapd `wpa_key_mgmt=WPA-PSK SAE`, `sae_require_mfp=1`, `ieee80211w=1` (pmf.mode=1) and `group_mgmt_cipher=AES-128-CMAC`. aaa.2.wpa.group_rekey=3600 (read on the device) gives wpa_group_rekey=3600 and wpa_gmk_rekey=86400. aaa.1 group_rekey=0 gives 0/0, but wpa_group_update_count=4 is still emitted.
- The guest mechanism in code matches the study: guest_portal_funcs.sh:486-549 (guest_update_interface_ebtables, nat PREROUTING/POSTROUTING `-j mark`, GUESTIN/GUESTOUT derived from the controller's auth chain). The ubntbox templates include `%s "%s" guest_vap %d`.
- blocked_sta is written to /sys/class/net/$ath/blocked_sta in chunks of 220 MACs (platdep_funcs.sh:639-663).
- The udeco gap claims check out against the code. translate.go:91 has no ebtables/mark/mesh/iptables/ipset/redirector in its handled map. translate.go:218 comment says 'UniFi default off'. translate.go:243 maps 11k.status directly. vlan.go:63-71 takes the first br-lan port as the uplink. Nothing in internal/ reads proxy_arp, mcast.enhance, group_rekey, sae.*, btm_disassoc or qbssload.
- Redaction audit: every file under ~/udeco/docs/reference/u6pro/ (172 files, including actions-scans/ and the top-level mca-dump*.json) was checked. No secret values leaked. The following are all ***REDACTED***: wpa.psk, mesh.psk, unifi.key, syslog.remote.key, users.N.password, mgmt.authkey, wpa_passphrase, sae_password, iapp_key, guest_token, the logread -E key in ps.txt and syslog.conf, the spdtst key, and the uplink.conf sae_password/psk. The only 32-hex strings are anon_client_id values, and the hash-pattern hits are `$1$2` shell variables in common.sh. I made no file changes.

## Gaps filled
- [Config-test mode / auto-rollback and the cfgversion trio (controller-visible, missed)] mcad supports `setparam [-T <cfgtimeout>] [-V <cfgversion>] [-P <system.cfg>]: config test mode with auto-rollback after cfgtimeout seconds`. It keeps mgmt.cfgversion, cfgversion_effective, cfgversion_saved and cfgtimeout, backs up to /etc/persistent/cfg/mgmt.setparam.backup, and calls `syswrapper.sh apply-config <cfg> nopersist`, which cancels the pending flash write. On timeout it logs 'Config test mode timeout expired, reverting to previous config' and 'Rollback: cfgversion_effective %s -> %s'. The inform reports all three versions (here all 330bbdd498df1412, cfgtimeout=0). udeco reports only cfgversion: inform-keys-diff.txt lists cfgversion_effective and cfgversion_saved as 'in real, not ours'. It takes the new cfgversion when the setparam arrives (internal/device/session.go:315-318), before anything is applied, and it has no cfgtimeout handling (mgmtKeys at internal/device/unhandled.go:213 lacks it). An agent should report effective/saved only after the apply and the flash save have succeeded, and should implement the rollback.
  EVIDENCE: actions-scans/strings-mcad.txt:787, 1455-1458, 1546, 1573-1576, 1613, 1644-1663, 1728, 1992-2000; scripts/syswrapper.sh:2719-2735 (`apply-config <cfg_file> [nopersist]`); etc_persistent_cfg_mgmt.redacted (`mgmt.cfgversion_effective`, `mgmt.cfgversion_saved`, `mgmt.cfgtimeout=0`).
- [Persistence and post-apply signalling] After a successful apply that is not in nopersist mode, `set_cfg_save` creates /var/run/need_cfg_save. cfgmon (every 30 s) then runs `cfgmtd -w -p /etc /tmp/system.cfg` to write the config to flash. A full provision flushes pending saves first (`flush_pending_cfg_save 60`). On QCA the script waits up to 60 s in `wait_vaps_ready`. On the fast path only, and only if mcad's pid is unchanged, it runs `mca-ctrl -q -t notify-bg-provision-done`. A full provision restarts mcad, because the unifi plugin_stop removes the /usr/bin/mcad inittab entry, so the inform session drops during a full provision. /var/run/need_cfg_save is currently absent, meaning the config has been saved.
  EVIDENCE: scripts/syswrapper.sh:165-196 (cfg_save via cfgmtd), :2743-2776 (apply-config body), :2731 comment 'cfgmon polls every 30s'; sysinit/unifi.conf plugin_stop `sed -i '\`/usr/bin/mcad\`d' /etc/inittab`; `ls /var/run/need_cfg_save` gave 'No such file'.
- [PPSK / dynamic PSK and per-MAC VLAN (missed feature family)] ubntbox has a private-PSK path that the study did not mention: aaa.N.wpa.psk_file.status and aaa.N.wpa.psk_file.M.{mac,keyid,vlanid}, aaa.N.sae.psk.M.{mac,vlan,id} and aaa.N.wpa.psk_radius, rendered as `keyid=%s vlanid=%s` lines. At runtime `syswrapper.sh handle-dyn psk` writes /etc/hostapd/<vap>.psk (default MAC 00:00:00:00:00:00) and reloads with reload_wpa_psk, and accept-mac maps a MAC to a VLAN. udeco's translate has no psk_file, sae.psk or psk_radius handling. The study only saw the templates because PPSK is not configured at this site.
  EVIDENCE: actions-scans/strings-ubntbox.txt:4366-4373, 4388-4391, 4477; strings-mcad.txt:1752 `dynamic-psk`; scripts/unifi_util_funcs.sh:91-98, 187-202; `rg psk_file internal/` returned no matches.
- [Deco backend does not go through translate.Plan] The Deco agent reads the controller's Wi-Fi intent through translate.WLANs/wlanFeatures (internal/deco/wlan.go:186-191 → internal/translate/wlans.go:107-195), not through translate.Plan, the OpenWrt UCI planner that all of the study's translate.go line references point at. wlanFeatures flags only 802.11r/k/v, pmf-required, l2-isolation, uapsd, schedule, vlan, min-rate, mac-filter, dtim and rate-limit. proxy_arp, mcast.enhance, group_rekey, sae.*, btm_disassoc, qbssload, mcastrate, multicast.inspect and PPSK are therefore neither applied nor reported as clamped on the Deco. wlanFeatures also treats DTIM 1 and 3 as defaults (`d != "1" && d != "3"`), while the real AP applies both explicitly per VAP (driver 1 and 3). Every gap the study listed for translate.go also needs a matching field in translate.WLAN.
  EVIDENCE: internal/translate/wlans.go:13-14 comment 'Backends that do not write UCI (the Deco backend) read the controller's Wi-Fi intent from here', :160-195 wlanFeatures; internal/deco/wlan.go:191 `all := translate.WLANs(cfg)`.
- [Inform echoes of the applied config] Each vap_table entry echoes the config: `id` = wireless.N.id ('3' for wifi0ap0, '1' for wifi1ap1), `name` = devname, `radio_name` = parent, and `usage` comes from wireless.N.usage, which wireless.conf writes to /var/run/vapusage.<vap>. udeco hard-codes `"usage": "user"` for every non-uplink VAP (internal/openwrt/unifi.go:266). That would be wrong if the controller sends a usage other than 'user' (for example guest), though that could not be checked live because there is no guest SSID. Also, hostapd's `wlan_id` (87ff/3c27) is not present anywhere in system.cfg, so ubntbox derives it.
  EVIDENCE: mca-dump.json vap_table: `{'id': '1', 'name': 'wifi1ap1', 'radio_name': 'wifi1', 'usage': 'user', ...}` and `{'id': '3', 'name': 'wifi0ap0', ...}`; sysinit/wireless.conf:68,160 `echo "user" > /var/run/vapusage.<vap>`; grepping /tmp/system.cfg for 87ff|3c27 found nothing; strings-ubntbox.txt:4580 `wlan_id=%s`.
- [Ubiquiti kernel modules behind band steering, roaming and multicast] Band steering, assisted roaming and multicast features are handled by Ubiquiti kernel modules exposed under /proc, not by a userspace daemon (no stamgr or bandsteer process runs). The modules present are /proc/ui_bandsteer, /proc/ui_assisted_roamin (clients), /proc/ui_neighbor (2g/5g/6g_chans, ess_ap_list, net_discovered_nr, same_chan_include, ssid; mcad reads ess_ap_list and ssid for the inform), /proc/ui_multicast (mc_inspect, mc_suppressor, mdns_filter per VAP and VLAN), /proc/ui_bcfilter, /proc/ui_dns_bypass and /proc/ui_dns_cache. wireless.conf writes `echo wifi0ap0 0 > /proc/ui_multicast/mc_suppressor/enable` (wireless.N.multicast.suppressor) and `echo false > /proc/ui_neighbor/same_chan_include`. A full provision flushes ui_neighbor. A Broadcom equivalent would need to be built in the agent (inference).
  EVIDENCE: `ls -d /proc/ui_*` on the device; strings-mcad.txt:2061-2074; strings-ubntbox.txt:5058, 5242-5245, 7036-7040, 7126; sysinit/wireless.conf:9,56,148; syswrapper.sh:1528.
- [Bridge details and dead or no-op rules] VLAN bridges get `disable_ipv6=1`, `arp_accept=1`, hash_max 2048, multicast_snooping 0 at creation, priority 65535 and setfd 1, and carry no IP address (netconf.3.ip=0.0.0.0). bridge.conf writes `echo add,mark=eth0,wifi1ap1,wifi0ap0,eth0.2, > /proc/nfbypass/netdevs`, but /proc/nfbypass does not exist on this unit, so the write does nothing. The first broute rule (`-i wifi0ap0`) refers to an interface that is no longer a bridge port after `brctl delif`, so it cannot match (inference, consistent with pcnt=0). bridge-nf-call-iptables is 1, but the iptables tables are empty.
  EVIDENCE: sysinit/bridge.conf:10-39; `ls /proc/nfbypass` gave 'No such file or directory'; `cat /proc/sys/net/bridge/bridge-nf-call-iptables` returned 1; `iptables -S` showed only ACCEPT policies.
- [Redaction side effect] The redaction pattern `key=` also matched `rekey=`, so tmp_system.cfg.redacted:159 reads `aaa.2.wpa.group_rekey=***REDACTED***`, while line 93 keeps `aaa.1.wpa.group_rekey=0`. The value is not secret: on the device it is `aaa.2.wpa.group_rekey=3600`. This is over-redaction, not a leak. I left the file unchanged because my brief allows edits only to redact leaked values.
  EVIDENCE: On the device, `grep -n group_rekey /tmp/system.cfg` returned `93:aaa.1.wpa.group_rekey=0` and `159:aaa.2.wpa.group_rekey=3600`.

## Still open
- Whether driver `rrm 1` actually puts an RM Enabled Capabilities IE into beacons/probe responses with 11k off. This was not verifiable read-only, because `iw scan` is forbidden and no client-side capture was taken.
- How a real U6-Lite (MediaTek, MTK_UAP branch), the model udeco emulates, applies the same keys: VAP names (ra*/rai*?), iwpriv parameters, whether RRM is always on, and the skipped 11k scheduler. This U6 Pro cannot show it.
- Live guest-isolation behaviour (guest_vap, ebtables mark, GUESTIN/GUESTOUT, ipsets, the REDIRECTOR chain) and the wireless.N.usage value the controller sends for guest WLANs. There is no guest SSID at this site.
- Which controller actions send mgmt cfgtimeout>0 (config-test mode with rollback). It is 0 here, and no test-mode apply was observed.
- Runtime PPSK (/etc/hostapd/<vap>.psk) and per-MAC VLAN accept entries. These are not configured, so only templates and code were seen.
- How hostapd's wlan_id (87ff/3c27) is derived. It does not appear in system.cfg.
- Whether hostapd itself or the `syswrapper.sh wireless-vlan-add` hook creates wifi0ap0.2. The result is confirmed; which component creates it was not traced.
- Two of roughly 12 SSH logins with the correct password were rejected ('Permission denied') and then succeeded on retry, possibly due to dropbear rate limiting. Anyone scripting against this AP should allow retries.
