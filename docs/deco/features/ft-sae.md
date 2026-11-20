# 802.11r for WPA3 (FT-SAE)

**Status: on with `wpa3` (2026-11-19, explicit peers), not yet live-tested.** The agent claims
radio_caps2 0x2 in takeover with `"wpa3": true` unless `"ft_sae": false`; WPA3 clients then roam
between units with FT-SAE. hostapd 2.9 cannot use UniFi's wildcard key holders, so the agents learn
each other's key holders and list them explicitly (below).

### Why not the wildcard (hostapd 2.9 source)

`src/ap/wpa_auth_glue.c`, identical to the copy the Deco's binary matches (it has `FT: Send RRB
data directly to locally managed BSS` but not 2.10's `RRB(%s): local delivery`): with a wildcard
R0KH the target AP sends its SEQ_REQ and PULL to ff:ff:ff:ff:ff:ff via
`hostapd_wpa_auth_send_oui`. `hostapd_wpa_auth_oui_iter` gives a multicast frame to the first
other BSS of the same process and returns 1, so `eth_p_oui_send` never runs. Every agent hostapd
has the placeholder (`interface=`) as another BSS, so the PULL never reaches another Deco; the
target waits `rkh_pull_timeout` (1 s) and fails. hostapd 2.10 fixed this.

### Explicit peers

Per FT-SAE BSS, per peer BSS of the same WLAN key, mobility domain and bridge:

```
r0kh=<peer BSSID> <peer R0KH-ID = its nas_identifier, the BSSID as 12 hex> <iapp_key>
r1kh=<peer BSSID> <peer R1KH-ID = its r1_key_holder, as a MAC> <iapp_key>
pmk_r1_push=1
```

A unicast PULL or push is sent (`oui_iter` takes a unicast frame only for a BSS of the same process
whose own address it is, so it goes to `eth_p_oui_send`), and `pmk_r1_push` pushes the PMK-R1 to
every listed R1KH right after the initial SAE (`wpa_ft_push_pmk_r1` skips only all-zero entries).

**Discovery** (`internal/ftpeer`, `cmd/udeco-ap/ftsae.go`). Each agent sends, every 20 s and at
once after a change or on hearing a new unit, one frame per WLAN key per bridge carrying an FT-SAE
BSS (br-lan or br-vN, the L2 path its RRB uses): EtherType 0x88b5 (IEEE local experimental) to
03:75:64:66:74:31, payload `UDFT` v1, unit MAC, epoch (agent start, unix ns), sequence, key id,
then per holder band, MDID, BSSID, R1KH-ID, R0KH-ID, and HMAC-SHA256/128 under
HMAC-SHA256(iapp_key, "udeco ft-sae announce v1"). The key id is HMAC-SHA256(iapp_key, "udeco
ft-sae key id v1")[:8]; the key itself is never on the wire, and the SSID name is not either. A
receiver accepts a frame only: from another unit (own unit MAC and Ethernet source ignored), whose
Ethernet source is the unit it names, within the rate limits (per source 2/s burst 12, all sources
30/s burst 60, checked before any cryptography), under a key it serves on the bridge it heard it on,
with a valid HMAC, newer than the last frame of that unit under that key (epoch, then sequence),
with holders a conf line can carry (R0KH-ID 1-48 of `[0-9A-Za-z._:-]`, unicast MACs). A frame is
the complete list for (unit, key, bridge): an empty one withdraws. Peers expire after 70 s without
an announcement, and the replay state with them (so a unit that rebooted with its clock behind is
accepted again; a replayed old frame can at most re-add a stale peer for one TTL). Refused frames
are counted and summarised in the log once per interval (counts only). Optional cross-check: a new
peer whose BSSID is not in the last neighbour scan is logged as such (not refused: it may be out of
radio range and still on the LAN).

**hostapd** (`internal/bcmwifi/ftpeers.go`). The worker hands the peers to bcmwifi
(`SetFTPeers`): a Plan writes the peers known then into the conf. The `r0kh=`/`r1kh=` lines are
left out of the comparison that decides a restart (`sameConf`), so a peer coming or going never
restarts a radio; the key id goes into `drv-wlN.json` (`ft_key_id`, not the key), so a key change
still does. New peers go into the running hostapd with `SET r1kh ...` / `SET r0kh ...` over its
control socket (`SyncFTPeers`, after every apply, on every discovery change, and on every worker
tick). Verified in the 2.9 source: `hostapd_ctrl_iface_set` -> `hostapd_set_iface` ->
`hostapd_config_fill` -> `add_r0kh`/`add_r1kh`, which prepend to `bss->r0kh_list`/`r1kh_list`;
`hostapd_wpa_auth_conf` points `wconf->r0kh_list` at `&conf->r0kh_list`, so the entry is live at
once; the following `hostapd_set_security_params(bss, 0)` and `hostapd_config_check(conf, 0)` are
idempotent for a conf that started. The command carries the key, so it goes over the unix socket
from Go (`Options.Ctrl`), never `hostapd_cli` (argv, Step, logs). hostapd logs the SET value only at
`-d` (`CTRL_IFACE SET`), which the agent never uses.

Removal: 2.9 has no command that removes a configured entry (only the temporary ones a wildcard
creates have timeouts). An expired peer therefore stays in the running hostapd until its next
restart, when the conf is written with the peers known then. Harmless: the entry is used only for a
station whose R0KH-ID is that peer's (a PULL to an absent BSSID times out and the station does a
full SAE; while that peer's hostapd still runs, e.g. its agent died, the entry keeps working), and
`pmk_r1_push` sends one small encrypted frame to it per SAE association. No restart is forced for
it. Entries are never added twice (the live set is tracked per hostapd pid, in
`/tmp/udeco/ftpeers-wlN.json`, 0600, MACs and ids only, so an agent restart does not re-add), and
at most 64 per BSS are added between restarts. With two entries for one peer hostapd uses the
older (`wpa_ft_rrb_lookup_r0kh` keeps the last match of a prepend-ordered list), so a key change is
never patched live: the running BSS is skipped until the apply that the key id difference triggers.

### Same unit, other radio

Each radio runs its own hostapd. A PULL from the 5 GHz process to the 2.4 GHz BSSID goes out on the
bridge, whose FDB holds that BSSID as a local entry of its port (the wl vif): the frame is handed to
the wl driver, not looped back to the other process's ETH_P_OUI socket (a protocol-specific packet
socket sees received frames only). Options evaluated:

- (a) Both radios in one hostapd (`hostapd conf_wl0 conf_wl1`): 2.9 delivers a unicast RRB frame to
  a BSS of the same process (`oui_iter`), so cross-radio FT would work. Cost: every reconcile of
  either radio (a channel or country change, a vif missing, a conf change) restarts both and drops
  every client of the unit; a conf error on one radio fails both; takeover, hand-back, rollback and
  `planRadio`'s per-radio reconcile (pid file, `StepStop` match, `StepWait`) all assume one process
  per radio, and the live facts F1-F6 were established for that layout only. Not taken without a
  live test of the dual-interface process on the X20.
- (b) An agent relay: capture the 0x88b7 frames one process sends (ETH_P_ALL tap on the bridge) and
  inject them as received through a TAP port added to the bridge (`/dev/net/tun` exists on .205,
  kernel 4.1.52). Needs a new bridge port that floods into the agent (ebtables to stop that), the
  bridge warns "own address as source" for every injected frame, and it is untested on this
  kernel and the Broadcom datapath. Not taken.
- (c) Taken: the two radios do not list each other, and an FT-SAE BSS gets a mobility domain of
  its own band (`sha256("udeco-mdid:" + SSID + "\x00" + band)`, never the same on both bands). A
  client moving between the two radios of one unit (band steering included) sees another mobility
  domain and does a full SAE, as without FT-SAE, instead of an FT attempt that fails. Roams between
  units on the same band are FT-SAE; between units across bands they are a full SAE. FT-PSK on a
  transition SSID uses the same per-band domain (a cross-band WPA2 roam is then a 4-way handshake;
  a WPA2/WPA3 SSID without FT-SAE keeps the SSID-wide domain). When the controller sends
  `aaa.N.mobility_domain` it is used on both bands, with a plan note: SAE clients then try FT
  across one unit's radios, are refused at once ("unknown R0KH"), and fall back to a full SAE.

## What the controller sends

Network 10.6.109, decompiled (`XHjguBsIf`, the UAP builder the MediaTek builder `iqHfwSoIdFucUE`
extends; `ubntconf.mxOcyUBrAqNY`, the SAE section; `ubntconf.qemBJTmR`, the per-device WLAN filter):

| system_cfg key | from | notes |
|---|---|---|
| `aaa.N.ft.status` | `fast_roaming_enabled` | cleared by the filter for a WPA3-only WLAN on a radio without radio_caps2 0x2 |
| `aaa.N.wpa3.ft.status` | `isWpa3SaeFastRoamingEnabled()`: `wpa3_fast_roaming` on a transition WLAN, `fast_roaming_enabled` on WPA3-only | `wpa3_fast_roaming` is cleared unless radio_caps2 has 0x2 |
| `aaa.N.iapp_key` | the WLAN's `x_iapp_key`, while `iapp_enabled` (default true) | 32 hex digits (`WlanConf` schema `[0-9A-Fa-f]{32}`; generated with length 32 from `0123456789abcdef`). The same value goes to every AP of the WLAN |
| `aaa.N.nas_identifier` | only with a RADIUS profile (`nas_identifier_type`) | not used for FT |

Not sent by 10.6.109, though ubntbox reads them: `aaa.N.mobility_domain`, `aaa.N.ft_over_ds`,
`aaa.N.r0_key_lifetime`, `aaa.N.pmk_r1_push`, `aaa.N.reassociation_deadline`. No R0KH/R1KH lists and
no other key material are sent.

## How a UniFi AP builds it

ubntbox format strings (U6 Pro ubntbox strings around
`aaa.%d.iapp_key`; U6 Pro ubntbox config strings):

```
nas_identifier=$bssid            (default; Ubiquiti's hostapd expands it)
mobility_domain=%s               (aaa.N.mobility_domain)
r0kh=ff:ff:ff:ff:ff:ff * %s      (immediately after aaa.%d.iapp_key: the key is the iapp_key)
r1kh=00:00:00:00:00:00 00:00:00:00:00:00 %s
ft_psk_generate_local=1  pmk_r1_push=1  reassociation_deadline=3000  rkh_pos_timeout=86400
ft_over_ds=0  ft_r0_key_lifetime=0  ft_r0r1_cache_size=1024
```

The U6 Pro reference has FT off, so these are format strings, not live lines. What MDID a UniFi
AP uses when the controller sends no `mobility_domain` is not in the reference (open item).

## What bcmwifi builds (internal/bcmwifi/ftsae.go, ftpeers.go)

For a WPA3 or WPA2/WPA3 SSID with `ft.status` and `wpa3.ft.status` enabled and a valid key
(32 or 64 hex digits), with FT-SAE on (`wpa3`, `ft_sae`):

```
wpa_key_mgmt=WPA-PSK FT-PSK SAE FT-SAE     (WPA3 only: SAE FT-SAE, ieee80211w=2)
mobility_domain=<aaa.N.mobility_domain, else sha256("udeco-mdid:"+SSID+"\x00"+band)[0:2]>
nas_identifier=<BSSID hex>   r1_key_holder=<BSSID hex>
ft_over_ds=<aaa.N.ft_over_ds, default 0>
ft_psk_generate_local=1      (when FT-PSK is listed)
reassociation_deadline=1000  (TP-Link's, matches wl fbt_reassoc_time)
r0kh=<peer BSSID> <peer BSSID hex> <iapp_key>          one per peer BSS (none until one is known)
r1kh=<peer BSSID> <peer BSSID> <iapp_key>
pmk_r1_push=1
```

hostapd 2.9 (the Deco's `/sbin/hostapd`, which has FT-SAE, `FT OLDKEY` and RRB-OUI) accepts a
128-bit key and stretches it with `hmac_sha256_kdf(key, "FT OLDKEY")` (`rkh_derive_key`), so Decos
and newer UniFi hostapds derive the same 256-bit RRB key from the same iapp_key. RRB runs on the
BSS's bridge (`br-lan` or `br-vN`), ethertype 0x890d / 0x88b7.

Without the controller's WPA3 fast roaming or without a usable key: a transition SSID gets FT-PSK
only, a WPA3-only one no 802.11r, with a plan note (the key is never in a note, a log, an
announcement, `drv-wlN.json` or the public last-good; it lives in the 0600 hostapd conf and
last-good.secrets.json). Driver: the same `wl fbt/fbt_ap/fbt_mdid/fbt_r0kh_id/fbt_reassoc_time` as
FT-PSK (`fbt_mdid` is the band's domain, byte-swapped), plus `wl fbtoverds 1` only with FT over the DS.

**`fbt_mdid` is byte-swapped (2026-11-20).** The driver beacons `fbt_mdid` little-endian: `fbt_mdid
0xd530` puts MDIE bytes `30 d5` on air, while hostapd's `mobility_domain=d530` (and a UniFi AP's) is
`d5 30`. The driver forwards every FT-SAE initial association (STA AKM FT-SAE, auth alg SAE) to
hostapd, which checks the request's MDIE against its own and refused them all with status 54
(Invalid MDE). That is why WPA3 phones failed to join on 2026-11-19 after a good SAE exchange. The
agent writes `bits.ReverseBytes16(mdid)`; a GL.iNet KVM (wpa_supplicant 2.10) then joined FT-SAE
and got its PMK-R0/R1, the assoc response and msg 3/4 carrying MDIE `d5 30` and the FTIE. Its
full-MAC driver (aicwf) cannot do an FT roam from wpa_supplicant, so the roam is verified with phones.

The agent claims radio_caps2 0x2 only in takeover with `wpa3` and `ft_sae` not false, and a backend
that builds FT-SAE (`DecoAgentFeatures.WPA3FT`, bcmwifi `ServesFTSAE`: `Options.WPA3 &&
Options.FTSAE`); a drop to observe clears it and withdraws the announcements. The discovery runs
only with `apply` as well (a dry-run unit serves no BSS of its own). With `"ft_sae": false`, an
SSID for which the controller still sends `wpa3.ft.status` enabled gets FT-PSK and SAE without FT,
no key in any file, and a plan note.

## Live test (not yet run)

On two Decos running the agent in takeover with `"wpa3": true` (`ft_sae` default), one WLAN
WPA2/WPA3 with fast roaming and WPA3 fast roaming on:

1. Inform `radio_caps2` is 3; after a settings change the system_cfg has `wpa3.ft.status=enabled`
   and `aaa.N.iapp_key` (check presence only).
2. logread: `ft-peers: unit <other> heard on br-lan` and `ft-peers: peer na <BSSID> ...` on both;
   `bcmwifi: FT-SAE peer added live: wl12: r0kh ...` on the unit that started first (no hostapd
   restart: `hostapd_cli ... status` keeps its uptime, stations stay associated). `tcpdump -i br-lan
   ether proto 0x88b5` shows the announcements, no key in the hex.
3. `hostapd_cli -p /var/run/udeco-hostapd -i wl12 get_config` lists `FT-SAE`; the two units'
   `mobility_domain` lines match per band and differ between bands.
4. A WPA3 client (Android 10+/iOS 13+) roams between the units on 5 GHz: hostapd logs (`-d` only
   on a test run) `FT: RRB ... PULL`/`RESP` or a pushed PMK-R1 on the target; the station's
   `AKMSuiteSelector=000fac-9` (FT-SAE). A roam from 5 GHz to 2.4 GHz of the same unit is a full
   SAE (`000fac-8`), with no failed FT authentication before it.
5. Expiry: stop the agent on one unit (its hostapd keeps running); after about 70 s the other logs
   the peers gone and changes nothing in its hostapd; roams to the stopped-agent unit still use FT.
6. Mixed with a UniFi AP on the same WLAN: its MDID (SSID-wide, from ubntbox) differs from the
   Deco's per-band one, so roaming between them is a full SAE (open item: what MDID ubntbox uses
   without `mobility_domain`).
