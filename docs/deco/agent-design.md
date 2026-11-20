# udeco-ap: a UniFi U6-Lite agent that runs on each Deco X20

Status: design, 2026-11-18. Replaces the off-device TMP design (design.md) for rooted units.

## 1. Goal

One static binary runs on every rooted Deco X20. Each unit presents itself to UniFi Network (UCG at
192.168.0.1, inform `http://192.168.0.1:8080/inform`) as a **U6-Lite (UAL6)** with its own MAC and IP.
After adoption, **the controller drives the AP natively**: WLANs, security, VLANs, radios, client
actions, LEDs and restarts all come from UniFi's provisioning, and nothing comes from TP-Link.
TP-Link's software is stopped, and the unit's own traffic to the internet is blocked.

The Decos are standalone APs on wired backhaul, so no mesh is involved. A wireless uplink would be
a later phase (UniFi mesh emulation).

## 2. Ground truth (research reports, 2026-11-18)

Read these before changing anything. They are in
`/private/tmp/claude-501/-private-tmp/98c08704-0f7d-42d1-8ad0-d700c555e21a/scratchpad/research/reports/`:
`wifi-bringup.md`, `services.md`, `collector.md` and `unifi-surface.md`. Each contains its
**verifier's corrections**, and those corrections win over the report body. The U6 Pro reference
(real AP inform payload and config) goes to `docs/reference/u6pro/`.

Key facts:
- **Platform.** Kernel 4.1 armv7 (4 cores, neon/vfpv4), busybox, Broadcom `wl` 17.10, hostapd 2.9 (nl80211), 252 MB RAM (about 97 MB available).
- **Storage.** `/tp_data` is persistent ubifs with 11 MB free, mounted sync; write to it rarely. `/tmp`, `/var` and `/etc` are ramfs: unbounded and RAM-backed (mountinfo says `tmpfs size=420k`, but the kernel has no SHMEM, so no limit is enforced and every byte written is unreclaimable RAM; interference-audit D6). `/data` has 584 kB free.
- **Radios.** `wl0` is 2.4 GHz and `wl1` is 5 GHz. Each radio has its own primary interface plus vifs `wlX1..wlX6`, and the driver allows mbss8 per radio.
  - `wlX1` is TP-Link's backhaul vif (`dwds=1`, `bss_maxassoc 16`). It never carries a client SSID: the agent's hostapd uses it as its hidden `interface=` placeholder and keeps it BSS down.
- **hostapd and vifs (live, .205, 2026-11-19).** TP-Link runs `hostapd -B -P /tmp/wlX.1_hapd.pid /tmp/wlX.1_hapd.conf` per radio: `interface=wlX1`, then `bss=wlX2..wlX6`, each with `bssid=`. This hostapd creates the `bss=` vifs itself and deletes them the moment it exits (only `wlX` and `wlX1` remain; `wl -i wlX2 ...` then says `wl driver adapter not found`; there is no `iw`). It needs `interface=` to exist and a `bssid=` per `bss=` ("Invalid BSSID mask" otherwise), finishes its BSS setup after `-B` returns, sets every BSS down (the `interface=` one too) and does not honour `bridge=`; TP-Link's `/lib/wifi/tplink_brcm.sh` then does `ifconfig up`, `wl bss up` and `brctl addif` per enabled vap. `proxy_arp=1` on a `bss=` vif fails the whole process (x_snoop needs a bridge port at BSS setup). A second hostapd with the same `-P` fails and deletes the running one's pid file.
- **SSIDs.** An SSID is "up" when its vif is `bss up` and the vif is bridged.
- **Channels.** hostapd does not own the channel: `wl chanspec` and `wl txpwr*` do. A DFS channel is written to hostapd's conf as 36, so that hostapd never runs a CAC of its own; the driver runs the CAC and radar detection with `wl spect 1` (docs/deco/features/dfs.md). A radio on auto keeps its live channel, except for one pick when a provision restarts a radio anyway (docs/deco/features/auto-channel.md).
  - 2.4 GHz: channels 1-11 at 20/40 MHz.
  - 5 GHz: 36-48 and 149-165 at up to 80 MHz. DFS (52-64) appears only with country code IN; there is no 160 MHz.
  - Maximum power target: 24 dBm on 2.4 GHz, 23.5 dBm on 5 GHz.
- **hostapd.** It supports SAE, FT-PSK/FT-SAE (802.11r), ieee80211w, RADIUS, `bss_transition`, `rrm_*`, `rssi_reject_assoc_rssi` and `multicast_to_unicast`.
  - It has **no** `dynamic_vlan` config keys, so VLANs need one bridge per VLAN: `<uplink>.<vid>` plus `br-v<vid>`.
  - The config file **must not contain inline comments**.
- **Uplink and ports.** The uplink port varies by unit: eth1 on .205, eth0 on .241. Detect it from the bridge FDB entry for the gateway's MAC; never hard-code it.
- **Counters.**
  - `wl chanim_stats us` gives µs counters that may carry ±k·2^32 offsets after a radio re-init. **Use only u64 modular deltas.**
  - Busy time = busy_tm + tx.
  - Use `wl -i <vif> sta_info all`, one call per vif. "tx ucast" bytes are the bytes sent to the client.
- **What undoes our changes.** All of these must be stopped or neutralised before the agent owns Wi-Fi:
  - processes: awnd, repacd, sync-server, tipc-server, sync-check, acsd2, nrd, wpsd, tmpsvr, uhttpd (Lua);
  - procd config triggers on `wifi`, `sysmode` (`reboot -f`!) and `guest-*`;
  - cron jobs: `dwds_tpbr_check` and `tmpsvr_check`.
- **Never run** `/etc/init.d/repacd …`, `wifi reload`, `/etc/init.d/network restart|reload`, a uci commit of `sysmode`, or anything under `tpbr`. Never write kernel nvram (`/data/.kernel_nvram.setting`, wlcsm).
- **Mesh coupling.** TP-Link's mesh on a satellite SSHes to the master. Taking over one unit must not break the others while they still run TP-Link. A unit that has been taken over simply leaves the Deco mesh; that is expected.
- **Known code defect** (`internal/device/session.go:164-175`): once adopted, the payload replaces the real `radio_table_stats` and `sys_stats` with canned U7PG2 constants. Fix it: use canned values only when Extra did not provide them. **Fixed 2026-11-18** (test `TestAdoptedPayloadKeepsExtraStats`).

## 3. Architecture

```
cmd/udeco-ap/            the agent: config, inform loop, adoption, action dispatch, supervision
internal/apstate/        the reading model (Snapshot, scan rows) and its UniFi inform rendering (Fields); no I/O
internal/wl/             READ: Broadcom/Deco collector  -> apstate.Snapshot, hardware Caps, Scan
internal/decosys/        TP-Link takeover: stop and keep stopped the TP-Link services, egress firewall, NTP
internal/bcmwifi/        WRITE: desired Wi-Fi state -> wl + hostapd + bridges/VLANs; apply, verify, rollback; kick and block
internal/translate/intent.go   system_cfg -> backend-neutral Intent (additive file; reuses the package's unexported helpers)
deploy/deco-ap.sh        build linux/arm GOARM=7 static stripped; R28 preflight; install to /tp_data/udeco (+ launcher);
                         print the persist_shell.sh line to approve (writes it only with --edit-persist)
```

Every package that executes commands takes a `Runner` and a filesystem root, so tests run against
the fixtures in `internal/wl/testdata/` and fakes. Nothing in the tests needs a device.

```go
// internal/wl (also used by decosys and bcmwifi through their own copies of this small interface)
type Runner interface {
    Run(ctx context.Context, name string, args ...string) ([]byte, error) // exec with timeout; stdout
}
```

### 3.1 internal/wl (read)

```go
type Options struct {
    Root   string        // filesystem root ("/" on the device; a testdata tree in tests)
    Run    Runner
    Uplink string        // optional fixed uplink port name; "" = gateway FDB detection
}
func New(o Options) *Collector
func (c *Collector) Collect(ctx context.Context) (*apstate.Snapshot, error)
func (c *Collector) Caps(ctx context.Context) (Caps, error)      // static hardware facts, cached
func (c *Collector) Scan(ctx context.Context, band string) (*apstate.ScanResult, error) // triggers 'wl scan', then scanresults
type Caps struct {
    Country string
    Bands map[string]BandCaps // "ng", "na"
    MaxBSS int                // per radio (8)
}
type BandCaps struct {
    Channels map[int][]int // width MHz -> allowed primary channels
    TxMinDBm, TxMaxDBm int
    NSS int
    HT, VHT, HE bool
    DFS bool
}
```
- Fill every Snapshot field that `Snapshot.Fields` consumes: system (from /proc and /sys directly, with no exec), radios (phy level, `Phy`="wl0"/"wl1") with `VAPs` (the user-facing vifs: bss up, bridged, not dwds), stations from `sta_info all`, survey from chanim µs deltas (modular u64), ports eth0/eth1, FDB parsed from `/sys/class/net/br-lan/brforward` in Go (binary `__fdb_entry`), ARP, gateway, and LLDP left empty.
- One collection runs `wl` about 11 times (about 50 ms). Everything else is file reads.
- Never run a mutating `wl` command, except `wl scan`, which only `Scan` runs.

### 3.2 internal/decosys (takeover)

```go
type Options struct {
    Root string; Run Runner
    ControllerIP, GatewayIP string; LANCIDR string; UnitIP string
    MgmtSources []string; ConsoleIP string; SSHDPort int   // the inbound fence (R5)
    DryRun bool; Logf func(string, ...any)
}
func New(o Options) *Manager
func (m *Manager) Plan(ctx context.Context) ([]Step, error)            // what Enforce would do now
func (m *Manager) Enforce(ctx context.Context) (Report, error)         // idempotent; Report.Foreign, Report.Guard
func (m *Manager) Egress(ctx context.Context, on bool) error           // iptables chain UDECO-OUT (own traffic only)
func (m *Manager) Ingress(ctx context.Context, on bool) error          // iptables chain UDECO-IN (R5), first in INPUT
func (m *Manager) SetLAN(l LAN) bool                                   // gateway, LAN CIDR, unit IP from a reading (R8a)
func (m *Manager) Counts() map[string]int                              // cumulative foreign-state counts (R10)
func (m *Manager) FlushFlows(ctx context.Context, s FlowScope) error   // fc flush --if/--mac (R21)
func (m *Manager) Restore(ctx context.Context) error                   // best-effort undo for rollback/uninstall
func InFlight(root string) (Guard, error)                              // R17: upgrade, rebuild, boot chain now
```
- **Stop set:** the STOP column of services.md, with the verifier's corrections applied.
  - Includes the IoT, Hue and cloud-brd services that run only on the master.
  - Stop through `/etc/init.d/X stop` for procd services, which also drops their triggers. Drop the procd `wifi`, `sysmode` and `guest-*` triggers.
  - Kill the script-started daemons by PID, then strip the TP-Link cron lines while keeping `/data/persist_shell.sh`.
  - Neutralise the paths that rebuild Wi-Fi directly (awnd, repacd, sync-check, the Lua handlers via uhttpd, radar).
- **Keep:** procd, ubusd, netifd, logd, `/bin/login`, crond, `/data/dropbear`, smartipd plus udhcpc (the unit's own IP), powermanager (thermal), leds (the LED backend), imsnoop, and eapd until it has been tested.
- **Egress:** `UDECO-OUT` is jumped from OUTPUT.
  - Allow: loopback, ESTABLISHED/RELATED, the LAN subnet (which covers the controller, the gateway's NTP and DHCP, SSH and syslog), and broadcast/multicast for DHCP.
  - Drop everything else, **including DNS** to non-LAN servers.
  - Forwarded client traffic is untouched: these are bridged frames, and there is no `br-nf` FORWARD rule.
- **NTP:** run busybox `ntpd -n -p <GatewayIP>` in place of the pool hostnames.

### 3.3 internal/translate/intent.go (controller config -> neutral intent)

```go
func IntentFromCfg(systemCfg string) (Intent, []string /* unsupported/ignored notes */)
type Intent struct {
    Country string
    Radios  map[string]RadioIntent // "ng", "na"
    WLANs   []WLANIntent
    Users   []User                 // device SSH users (x_ssh_*), if present
    LED     *bool
    Syslog  *SyslogIntent
}
type RadioIntent struct {
    Enabled bool; Channel int /*0=auto*/; Width int; TxPowerMode string; TxPower int; MinRSSI int /*0=off*/
    MaxClients int; BandSteer string
}
type WLANIntent struct {
    ID, SSID string; Bands []string; Enabled, Hidden, Guest bool
    Security string // open, wpa2, wpa3, wpa2wpa3, wpa2-enterprise, wpa3-enterprise, owe
    Passphrase string; PMF string; GroupRekey int
    VLAN int; Isolation bool; FT bool; BSSTransition bool; RRM bool; UAPSD bool; ProxyARP bool
    MulticastToUnicast bool; DTIM map[string]int; MinRateKbps map[string]int
    MACFilter *MACFilter; Radius *Radius; Schedule []string; RateLimit *RateLimit
}
```
It is pure parsing with no exec, and it reuses the existing unexported helpers in package translate.
Unknown keys go into the notes; they are never silently dropped.

### 3.4 internal/bcmwifi (write)

```go
type Options struct {
    Root string; Run Runner; StateDir string /* /tp_data/udeco/state */; RunDir string /* /tmp/udeco */
    Uplink string; DryRun bool; Logf func(string, ...any)
}
func New(o Options) *Applier
func (a *Applier) Plan(ctx context.Context, d Desired) (Plan, error)    // diff vs live state; Plan.Steps human-readable
func (a *Applier) Apply(ctx context.Context, p Plan) error              // stops TP-Link hostapd, writes confs, wl settings, bridges, starts ours
func (a *Applier) Verify(ctx context.Context, d Desired) error          // every SSID beaconing (bss up, ssid, bridged), hostapd ctrl ping
func (a *Applier) Rollback(ctx context.Context) error                   // last-good Desired; if none: hand Wi-Fi back to TP-Link (decosys.Restore + its hostapd confs)
func (a *Applier) Kick(ctx context.Context, mac string) error           // hostapd_cli deauthenticate
func (a *Applier) SetBlocked(ctx context.Context, macs []string) error   // hostapd deny list on every BSS + kick
func (a *Applier) LED(ctx context.Context, mode string) error            // on/off/locate via 'ubus call leds'
type Desired struct { Country string; Radios map[string]Radio; SSIDs []SSID } // mapped from translate.Intent by the agent
```
- **Vif allocation:** client SSIDs use `wlX2..wlX7`: those that exist or whose BSSID is known (TP-Link's conf `bssid=` lines, the baseline), since a `bss=` vif only exists while a hostapd serves it. On stock firmware that is `wlX2..wlX6` (5 per radio). `wlX1` and the primary interfaces carry no SSID; unused vifs do not exist.
  - **Stable slots (2026-11-19, `slots.go`).** An SSID keeps the vif it is on when its radio's SSID set changes (another SSID added, removed, disabled or scheduled off): a move changes its BSSID and drops its clients (live: olive# moved between wl13 and wl14). The placement in force is read back from the driver-state files the last apply wrote (`RunDir/drv-wlN.json`, vif -> WLAN id); `RunDir/slots.json` (ramfs, written after every verified apply or rollback) also remembers the vifs of SSIDs that are off now. Per radio and pass, SSIDs with a remembered vif go first and keep it while it may carry them; the others take the first free vif nobody is remembered on, else the first free one. With no record (first takeover) the order is the WLAN id, as before. A move happens only when unavoidable and is noted (`ssid N: moved from wl13 to wl14`): with R23 in force a new br-lan SSID may only use wlX2/wlX3, so a VLAN SSID remembered there makes room.
  - **Per-vif files.** Every plan removes the deny/accept/private-key files (`wlXN.deny`, `.accept`, `.psk`) of the radio's vifs that carry no SSID (removed, moved, off), and only those; the files of the vifs in use are never touched. Only existing files get a step, so a clean RunDir plans nothing; `Tick` runs the same removal (it is a non-disruptive step), which also clears files an earlier build left (live: `/tmp/udeco/wl14.deny`).
- **hostapd:** one process per radio, conf at `/tmp/udeco/hapd-wlN.conf`, ctrl at `/var/run/udeco-hostapd`, and no inline comments. `interface=wlX1` is a placeholder BSS (hidden, random SSID, WPA2-PSK with a fresh `crypto/rand` passphrase, reused from the conf while it exists so an unchanged radio keeps its hostapd), kept BSS down; each SSID is a `bss=` section with `bssid=`. Passphrases are written only there (0600) and never logged.
- **Reconcile order per radio:** lower every existing vif while its hostapd still runs; stop it (TP-Link's is found by its pid file, else by `/proc/<pid>/cmdline` naming its conf); scrub only the survivor `wlX1` (unbridge, MAC flush, `dwds 0` best effort); PHY; files; start hostapd and wait (15 s) until its vifs exist and `hostapd_cli status` says `state=ENABLED`; `wl -i wlX1 bss down` (optional); then per SSID vif: driver iovars (dwds, closednet, ap_isolate, maxassoc, wmf, rrm, fbt, MAC filter, rateset) while its BSS is down, `brctl addif`, `proxyarp_wifi`, `ifconfig up`, `wl bss up`. Lower and unbridge steps on a vif that does not exist are nothing to do.
- **Proxy ARP:** not via hostapd (`proxy_arp` kills it on a created vif). An isolated SSID with proxy ARP gets the bridge port attribute `/sys/class/net/<vif>/brport/proxyarp_wifi=1` (optional step). Limitation: the bridge answers only from its neighbour table; there is no DHCP/ND snooping table as hostapd's proxy_arp would build, so unknown addresses are flooded as before.
- **Hand-back to TP-Link:** only on radios where TP-Link's hostapd is not running (a restart that is not needed is skipped, not an error; a lost pid file is rewritten). There: lower, stop ours, unbridge, PHY back, restart TP-Link's hostapd with its captured argv, wait for its vifs, restore each vif's driver state from the baseline, then `ifconfig up` + `wl bss up` for vifs the baseline had up and `brctl addif` for those it had bridged.
- **Radio settings** through `wl`: chanspec, txpwr, country/regrev, `bss up/down`, `ap_isolate`, maxassoc. Bridges and VLANs through `brctl`/`vconfig`/`ip link`.
- **Apply sequence:** apply, verify within 30 s, else roll back. Save last-good to `StateDir`, and only on success.

### 3.5 cmd/udeco-ap

- **Config:** `/tp_data/udeco/udeco-ap.json`. Fields: `inform_url`, `console_ip`, `model` (UAL6), `sshd_port` (2222), `takeover` (bool, default false), `apply` (bool, default false), `egress` (bool, default false), `log` (`syslog` or `stderr`), `mgmt_sources` (optional list of IPv4/IPv6 addresses or CIDRs allowed to reach :22; default the LAN), `min_rates` (bool, default false; takeover only; docs/deco/features/minrate.md), `wpa3` (bool, default false; takeover only; radio_caps2 WPA3 and SAE serving, docs/deco/features/wpa3.md), `ft_sae` (bool, default true with `wpa3`, refused true without it; radio_caps2 WPA3 fast roaming, FT-SAE with peer discovery, docs/deco/features/ft-sae.md), `mdns_bridge` (bool, default false; takeover with `apply` only; fw2_caps mDNS service bridge, docs/deco/features/mdns-bridge.md), `hotspot2` (bool, default false; takeover only; fw_caps Hotspot 2.0, docs/deco/features/hotspot2.md), `site_survey` (bool, default false; takeover only; platform jio-mtk only, ignored with a log line on the Deco; the controller's scans run on the unit and RF_SCAN is claimed: `scan` runs the driver's site survey (scan_table); 2.4 GHz `quick-scan` and spectrum-scan run the MT7603's off-channel sweep as the band's spectrum runner, reported as the Deco's (spectrum_table, the scanning flags, EVT_AP_QuickScanEvent, saved on flash: internal/mtkwifi/offchan.go, spectrum-design.md "MT7603 off-channel sweep"); 5 GHz (MT7663) has no runner, so its quick-scan and its turn in a spectrum-scan run the site survey (scan_table only, a quick-scan's survey holding `quickscan_scanning` true until it ends: cmd/udeco-ap/sitesurvey.go)), `twt` (bool, default true; takeover only; Deco only, refused on jio-mtk; 802.11ax Target Wake Time on both radios as `wl -i wlN twt enab 1`, as a U6 Pro sets `twt_responder 3` on every VAP; false keeps TP-Link's `twt enab 0`. The driver refuses it while the radio is up, so it is written only inside a radio down/up the agent makes anyway (radioProfile on a PHY change, a full reconcile's dwds/rrm cycle, Tick's dwds repair) and never by a restart of its own; a radio that reads otherwise is reported in the plan notes and once per change in Tick's log until then; the hand-back restores the baseline's state, else 0: internal/bcmwifi/twt.go), `rx_desense` (bool, default false; takeover only; Deco only, refused on jio-mtk; true keeps TP-Link's glitch-based receiver desense (interference mitigation mode bit 0x1, `interference_override`); absent, the agent clears it live as a U6 Pro runs `ani_enable 0`. An opt-out because desense trades sensitivity for robustness in a noisy room, and only the unit's own environment can say which is better: internal/bcmwifi/parity.go, docs/deco/features/radio-parity.md), `driver_country` (string, optional; the regulatory table the radios run in instead of the controller's site country. It was needed while India ran as IN/0, whose table has no 80 MHz chanspec. India now runs as IN/288, with IN as a fallback the driver cannot refuse, so the override is no longer recommended: docs/deco/features/dfs.md), `uplink_ssid_down` (bool, default true; takeover only; Deco only, refused on jio-mtk; every served SSID goes `wl bss down` after 5 s without carrier on the tracked uplink port and back up after 10 s of carrier, never during an apply or a takeover hold: docs/deco/features/uplink-loss.md), `uplink_gateway_down` (bool, default false; needs `uplink_ssid_down`; a gateway unanswered by the agent's own ICMP echo for 60 s also counts as a lost uplink), `sta_snoop` (bool, default true; takeover only; Deco only, refused on jio-mtk; connection-timing STA_ASSOC_TRACKER events success/failure/soft failure/fixup from hostapd's syslog and control sockets and a read-only AF_PACKET tap per served BSS for ARP, DHCP and DNS: docs/deco/features/connection-events.md), `assoc_garp` (bool, default true; takeover only; Deco only; true needs `sta_snoop`; a gratuitous ARP on the station's behalf on its bridge's wired ports once it is authorized and its address is known: docs/deco/features/assoc-garp.md), `uplink_loss` (bool, default true; platform jio-mtk only, refused elsewhere; takeover with `apply`; with no carrier on the uplink port for 15 s every SSID goes down except one management SSID, back after 30 s of carrier, as a U6's uplink monitor takes its user and guest VAPs down: internal/mtkwifi/uplinkloss.go), `uplink_loss_ssid` (string; platform jio-mtk only; the SSID kept up, default the first LAN SSID without a VLAN; with none served nothing is taken down), `bss_pinning` (bool, default false; platform jio-mtk only; each WLAN keeps its profile slot, netdev and BSSID while others come and go, slot 0 always on a WLAN: internal/mtkwifi/slots.go), `proxy_arp` (bool, default true; platform jio-mtk only; the controller's per-WLAN proxy ARP is served by an AF_PACKET responder with ebtables drops (chain UDECO-PARP, policy RETURN) on both radios; false leaves requests on the air: internal/mtkwifi/proxyarp.go), `proxy_arp_driver` (bool, default false; platform jio-mtk only, needs `proxy_arp`; the MT7663 drops the 5 GHz requests itself, `iwpriv rai<N> set hs_flag=3`, and hands them to the agent's responder as 0x93b events, set only while that listener and responder are healthy: garage-parity.md section 13), `dfs` (bool, default false; platform jio-mtk only; the 5 GHz radio serves the controller's 52-64 with a live region change, CAC quiet time and radar follow-up, and claims has_dfs: internal/mtkwifi/dfs.go; all five: docs/deco/features/garage-parity.md), `driver_country_bands` (object, optional; takeover only; the country of one of the Deco's radios, over `driver_country` for that band: keys `ng` and `na`, values a two-letter code or Broadcom's `#a` table, which keeps Wi-Fi 6 on the DFS channels but runs no radar detection, so the agent refuses channels 120-128 under it: docs/deco/features/dfs.md), `platform` (string, default `""`: a TP-Link Deco X20, reported as `model` UAL6; `jio-mtk`: a JioFiber JCOW414 used as a plain AP, reported as `model` U7LT or UHDIW: internal/mtkwifi, internal/jiosys. Refused on jio-mtk: `mdns_bridge`, `hotspot2`, `egress`, `twt`, `uplink_ssid_down`, `uplink_gateway_down`, `sta_snoop`, `assoc_garp`, `rx_desense`), `ports_unlocked` (list of LAN ports 1-3; platform jio-mtk as `model` UHDIW only; the controller's port VLANs always apply to ports 2 and 3, to port 1 only when it is listed here, and never to port 4, the uplink: cmd/udeco-ap/ports.go, internal/jioports), `ports_confirm_s` (seconds, 60-900, default 90; UHDIW only; how long a port change waits for an inform the controller answers before it is reverted), `ports_loss_s` (seconds, 60-3600, default 300; UHDIW only; how long the controller may stay unreachable before every port the agent may change goes back on the LAN), `login_lock` (bool, default true with takeover and `apply`, on both platforms; true without them is an error; new connections to the unit's root login ports are dropped while the controller's Device SSH Authentication is off and the controller answers: docs/deco/features/login-lock.md), `login_lock_failopen_s` (seconds, 60-3600, default 600; needs the lock on; how long the controller may stay silent before the lock opens). Unknown keys are an error. This list has every key of `Config` in `cmd/udeco-ap/config.go` (a test holds it to the struct).
- **Modes:**
  - **observe** (`takeover=false`): read-only collector plus inform. TP-Link stays in charge, and the controller's WLAN plan is only logged.
  - **takeover:** `decosys.Enforce`, then `bcmwifi` owns Wi-Fi from the controller's config (`apply=true`), with `egress` on.
- **Inform loop:** port `cmd/udeco/runner.go` (gate removed; single unit). Fields come from `wl.Collect` and `Snapshot.Fields` with the UAL6 radio capability words. Fix the session.go overwrite (§2).
- **Actions:** restart (`reboot` after a reply), locate/LED (`bcmwifi.LED`), kick, block/unblock (`SetBlocked`), scan (`wl.Scan`, scan_table), spectrum-scan and quick-scan (`wl.SpectrumRunner`, spectrum_table; §3.6 Spectrum), and upgrade (acknowledged, never applied). Takeover only (§3.6).
- **Adoption:** SSH on `:2222`, only from `console_ip`, using `device.SSHAdopt`.
- **Supervision:** the boot hook is the firewall include (`/etc/config/firewall` `include` -> `/data/persist_shell.sh`); on .205 it is the only hook. `persist_shell.sh` starts the agent when it isn't running. Per-minute supervision by cron exists only on a unit whose crontab has the persist line (interference-audit B3), so a crashed agent may not come back before the next reboot. The agent holds a flock on `/tmp/udeco/agent.lock` and writes its PID file in `/tmp/udeco`. A crash loop (5 starts in 10 min of uptime) leaves the agent in observe mode, persistently (§3.7), and the stopped TP-Link services stay stopped.

### 3.6 cmd/udeco-ap as built (decisions, 2026-11-18)

Files (see §3.7 for the build-2 files): `main.go` (flags, PATH, lock, crash-loop guard), `config.go`, `agent.go` (setup, inform loop),
`wifi.go` (the Wi-Fi worker: decosys + bcmwifi), `actions.go`, `scan.go`, `system.go` (runner, logging,
PID, start log). Tests use fakes for wl/decosys/bcmwifi and an in-process controller; nothing touches a device.

**Paths.** Session state (`state.json`, `system_cfg.txt` + 5 history copies, `unhandled.json`, SSH host
keys) in `/tp_data/udeco/session` (0700). bcmwifi last-good in `/tp_data/udeco/state`. Persistent markers in
`/tp_data/udeco`: `force-observe`, `events.log` (64 KB ring), `boot_id`. ramfs `/tmp/udeco`:
`agent.lock`, `udeco-ap.pid`, `starts` (crash-loop log, uptime seconds), bcmwifi run files. PATH is set to
`/usr/sbin:/usr/bin:/sbin:/bin` at start (cron's PATH lacks /usr/sbin).

**Config.** Exactly the §3.5 keys, unknown keys and trailing data rejected. Extra validation: `inform_url`
must be `http://` (no https: the agent's inform client is plain HTTP, §3.7) with no userinfo and an IPv4
literal host (egress blocks outside DNS; an IPv4-mapped IPv6 literal such as `[::ffff:192.168.0.1]` is
refused too) and an optional port 1-65535, `console_ip` IPv4, `model` must be UAL6 (on platform jio-mtk: U7LT or
UHDIW), `sshd_port` never 22, `mgmt_sources` each an IP or CIDR. Keys that are an error in observe mode:
`apply`, `egress`, `min_rates`, `wpa3`, `hotspot2`, `twt`, `driver_country_bands`, `rx_desense`, `uplink_ssid_down`, `uplink_gateway_down`, `sta_snoop`, `assoc_garp` and `site_survey` require `takeover`;
`mdns_bridge` and `login_lock` require `takeover` and `apply` (`login_lock` only when it is true). The checks
are `validate` in `cmd/udeco-ap/config.go`.

**inform_url changes.** The same rule (`device.CheckInformURL`) guards every way the URL can change after
start: a setparam's `mgmt_cfg` `inform_url` ("Override inform host"), `cmd set-adopt`'s `uri`, and an SSH
`set-adopt <url> <key>` / `set-inform <url>` (`Session.ApplyAdopt`). A URL that fails it is not taken: the
old URL stays, and the event log says `ignored ... keeping <old url>` (with the reason). Only the URL is
refused; the rest of the message is handled as before (a set-adopt still stores its key). A setparam the
controller then repeats unchanged stops hurrying after the third (§3.6 session).

**Startup.** Nothing is informed until the first successful `wl.Collect` (a guessed radio set would stick in
the controller). The identity (br-lan MAC, IP), the uplink (gateway's br-lan FDB port, like
`apstate.Snapshot.gatewayPort`) and the LAN CIDR come from that reading. decosys and bcmwifi are only built in
takeover mode: decosys in phase 1 (for the fence) and handed the LAN from that reading (`SetLAN`), bcmwifi
from the reading.

**Modes.** Observe: no decosys/bcmwifi handle exists; every controller action is logged only (restart and
upgrade are faked by the session), scans are not run (`wl scan` takes the radio off channel), the WLAN plan is
logged masked. Takeover: a single worker goroutine owns all changes; the inform loop never blocks on an apply.
`apply=false` builds bcmwifi with `DryRun`, so plans (and LED/kick/block) are logged only, while decosys runs
for real.

**Ordering.** First worker job is `decosys.Enforce`; a provision that arrives before an Enforce has returned
without error waits (`pending`) and runs right after the first clean one. Every Enforce tick (60 s) runs
`Egress(true)` when `egress` is on, then a health check: `Verify(applied)`, two failures in a row ->
`Rollback`. After every `Apply`/`Rollback`: `Collector.Invalidate()`. `SetBlocked(controller list)` before the
plan (so bcmwifi folds it in) and after a successful apply, at startup when adopted, and on every blocked-list
change. Provisioning is triggered by a changed system_cfg (sha256 of `system_cfg.txt`), not by cfgversion
alone (the controller may bump cfgversion in mgmt_cfg before it sends the new system_cfg).

**Hand-back.** An Apply error, or a Rollback that returns `ErrNoBaseline` or leaves no agent hostapd conf,
means Wi-Fi is TP-Link's again: `decosys.Restore`, mode -> observe, persistent marker
`/tp_data/udeco/force-observe` (a restarted agent stays in observe, across reboots, until the marker is removed;
§3.7; `Restore` also puts TP-Link's reset-button handler and QoS back and removes the inbound fence),
loud log and event. An Apply error after which the agent still owns Wi-Fi
(rolled back to last-good) keeps takeover; that system_cfg is retried once when the controller sends it again
(§3.7, cfgversion), otherwise not until another arrives.
"Owns Wi-Fi" is read from bcmwifi's hostapd confs (`RunDir/hapd-wlN.conf`; the agent takes the names from `bcmwifi.ConfPath` and `bcmwifi.Primaries`), see open items.
Note this includes an Apply that failed before changing anything (baseline capture): TP-Link still has Wi-Fi,
so its services are restored too.

**Crash loop.** 5 starts within 10 min of `/proc/uptime` (start log on ramfs, so it restarts with the boot)
-> forced observe, and with `takeover` configured the persistent marker is written; TP-Link services an
earlier run stopped stay stopped (observe never restores).

**SIGTERM.** Informing stops; the worker finishes the job it is in (jobs run on a context SIGTERM does not
cancel, so an apply is never cut between stopping TP-Link's hostapd and starting ours); no Rollback, no
Restore.

**Actions (takeover).** reboot -> `reboot` after the reply is handled and the state saved; `led_enabled` ->
`LED(on|off)`; set-/unset-locate -> `LED(locate|locate-off)`; kick-sta -> `Kick`; block/unblock/blocked_sta ->
`SetBlocked(list)`; scan -> `wl.Scan` (neighbours) on ng and na; spectrum-scan and quick-scan -> the
spectrum runner (Spectrum, below). setdefault: back to pending, Wi-Fi left as it is.
upgrade: faked as before. authorize-guest / unauthorize-guest -> `bcmwifi.AuthorizeGuest` /
`UnauthorizeGuest` (§3.7 guests). Reported uptime follows the session's boot time, so a faked restart/upgrade
shows.

**scan_table.** `openwrt.ScanTable` rows plus the U6 Pro's keys (§3.7). Neighbours missed by one scan are
kept 10 min. `cmd scan` reports neighbours only; the legacy `ScanResult.Spectrum` rows are never reported.

**Spectrum (as built 2026-11-19; spectrum-design.md, spectrum-controller-expectations.md).** Takeover only:
observe mode logs the commands and runs nothing (`actions.go`), and does not claim RF_SCAN (capability table
below). `cmd/udeco-ap/spectrum.go` drives `internal/wl`'s per-radio `SpectrumRunner`:
- `cmd quick-scan` {`scan-band` 0 = ng, 1 = na, 2 = 6e; `scan-bw`}: one band per command, rows at that width
  (the runner clamps it; 0 or junk becomes 20). Band 6e: logged, nothing scanned, no table touched. The old
  table stays until the new one is complete. When the band ends, whatever the result, the loop informs at
  once, so the controller's next-band sequencing proceeds.
- `cmd spectrum-scan`: every radio's table is cleared first (the real AP resets each rftable to `{}`), then
  na and ng are measured once each with rows at every width the radio lists (20/40/80, clamped).
- One scan of any kind at a time (agent `scanner` and `wl`'s `scanMu`; the legacy `cmd scan` takes the same
  lock): a command that arrives meanwhile is skipped and logged (`[quick-scan] skipped: already in
  progress`, as mcad). Low memory (R4 shedding) skips them too. A band has 2 min (`spectrumTO`: airtime gate
  up to 60 s + Budget 45 s + margin).
- Inform: per radio_table row `spectrum_table` (all nine keys of `wl.SpectrumRow`) and `spectrum_table_time`
  (age in seconds), absent until the first good table and after a spectrum-scan cleared it;
  `spectrum_scanning_abnormal` per row (a failed band keeps the old table and sets it); top-level
  `spectrum_scanning` (true only while a spectrum-scan runs) and `quickscan_scanning` (sent, true, only
  while a quick-scan runs; omitted at rest). Neighbours a band hears refresh scan_table.
- Client guard (wl, spectrum-design §8.2): only the start set counts (stations associated for at least 60 s
  when the band began; one that joins later is never judged). A start-set station that is gone is
  scan-caused when it was listed at the start of the last off-channel call, was active then (idle <= 2 s,
  or its tx failures rising) and left within 2 s of that call: the band aborts at once. Other drops are
  background churn: up to 2 per band, the 3rd aborts. A channel still STALE after its retry ends the band early
  (`ErrIncomplete`); `wl scanabort` is sent only while a `wl scan` of ours may be running.
- Health check: `Verify` runs inside `WithoutScan` (serialised with the scans: `wl chanspec` shows the scan
  channel during a call), waiting up to `healthWait` 150 s; a wait that runs out skips the check and counts
  for nothing, so a scan never causes a rollback.
- **Storing on the controller (2026-11-19, Network 11.1.50 decompiled).** The controller copies an inform's
  `spectrum_table` into its in-memory `radio_table_stats` and turns `spectrum_table_time` (age) into an epoch,
  but it saves spectrum results only on (a) `EVT_AP_QuickScanEvent` (handler `devmgr.e.c.qeIWtmwxgQ`: sets
  `spectrum_scan_timestamp`, upserts that row by channel+width, saves `radio_table_stats`) or (b) a
  `quickscan_scanning` true -> false transition (it saves the non-empty tables and `quick_scan_state`). A manual
  `spectrum-scan` only sets `spectrum_scanning`, so before this its table was never saved and had no
  timestamp; Radio AI's prescan (`devmgr.ecPpL`) also waits for `spectrum_scan_timestamp` (freshData). So after
  every band with a table the agent sends the event as ubntquickscan does (mca-custom-alert keys
  `event_string, radio, radio_name, channel, width, center_freq, interference, utilization`), as a full inform
  with `inform_as_notif: true, notif_reason: "event", notif_payload: {...}`, the inform after the one that
  carried the new table (so the saved table is the new one), at once (immediate wait). The row is the block of
  the radio's own channel at the widest measured width up to the operating one (`eventRow`). A failed band
  sends none and, on a spectrum-scan, keeps no table (cleared first), as the real AP's per-radio ubntquickscan;
  the other band's result is still reported and saved. An unanswered event inform is resent, at most 3 times.
  An inform that says `quickscan_scanning: true` does not count as the carrier (Network sets the cached
  quick-scan state from that inform before it reads `radio_table`, so it ignores that `spectrum_table`). A due
  event whose radio is missing from `radio_table` (no `radio_name` to send) counts each such inform as a try and
  is dropped after 3, so it cannot keep the loop informing every immediate wait.
- **Passive (DFS) channels.** `wl chan_info` ("RADAR Sensitive, Passive"; without an answer 5 GHz 52-144) gives
  the band's passive channels. Every call is `wl scan -t passive`, so nothing is sent on them; their chunked
  calls dwell `PassiveDwell` 200 ms (the driver's own `scan_passive_time`) instead of 110 ms. A passive channel
  still STALE after its retry is *unheard*: unmeasured for that band only (no row, no block containing it; not
  sticky), never `ErrIncomplete`. On .205 under IN (03:30 run, `t9_wl1_dfs_in.txt`) 56 kept a non-zero record
  that pass 2 did not rewrite and stopped the whole 5 GHz band; 52/60/64 are all-zero (ZERO, sticky) as UNII-3.
- The tables live in the runners; since 2026-11-20 the last good one per band is also kept on flash
  (`/tp_data/udeco/state/spectrum.json`, `cmd/udeco-ap/specsave.go`), written only when a band gets a new table
  or a spectrum-scan clears them, and restored at start: reported as a live table with its true age, without an
  `EVT_AP_QuickScanEvent`. Usually the controller then keeps it in its in-memory `radio_table_stats` only, but a
  quick-scan the controller sent that ends without a new table of ours (the agent restarted during it, or the
  restarted agent skipped it: shed, an apply, a hold, busy) ends with the controller's `quickscan_scanning`
  true -> false, and that saves the restored table to the database as the quick-scan's result (INFERENCE: as a
  real AP's kept rftable would be). Whether that save also stamps `spectrum_scan_timestamp` (Radio AI's freshData) is
  UNVERIFIED. Only the rows the radio lists now are kept (`wl.SpectrumRunner.FitRestored`), re-checked while it is
  reported, so after the first apply (a driver country set before the restart) too. Not restored while an apply
  runs. Dropped when older than 7 days, of another model or radio layout, unparsable, or measured after a clock
  that is set; held while the clock is not set (before `device.ClockSane`). jio-mtk (with `site_survey`): the same
  for the 2.4 GHz table only (`/flash2/udeco/state/spectrum.json`); a saved table of a band with no runner is dropped. scan_table is
  not saved.
- Not wired: `SpectrumRequest.Guard` is not set, so a band that has started is not stopped by a Wi-Fi apply
  or by a firmware upgrade that begins meanwhile (the worker's hold check covers applies, not scans).

**Session changes (internal/device/session.go).** Canned sys_stats/radio_table_stats only when Extra did not
send them; `cmd quick-scan` parsed (`scan-band`/`scan-bw` as numbers or numeric strings) into action
`quick-scan:<band>:<bw>`; both fields marked as read in the unhandled ledger.

#### UAL6 capability words (`models.DecoAgentProfile`)

Rule: claim a bit only when its meaning is known **and** the agent implements the feature. A missing bit
only makes the controller hold a setting back; a wrong bit makes it send configuration nothing applies.
Shape: 6.x-style inform (radio_table with channel/ht/tx_power, radio_table_stats, stat), matching the claimed
firmware 6.7.54.15663, not the 8.x U6 Pro shape.

Bit names (hypothesis, consistent): docs/internals.md lists the 18 named bits of the U7PG2 word 559857373
(bits 0,2,3,4,6,7,9,10,11,12,13,15,17,18,19,20,24,29, plus unnamed 22). Read in ascending order they give WPA3
= bit 17, which matches the independently used WPA3 value 131072. That anchor is the only verification.

| word | bit | name (inferred) | claimed | why |
|---|---|---|---|---|
| wifi_caps | 0 | VWIRE | no | no wireless uplink/mesh |
| | 2 | BANDSTEER | **takeover only** | claimed when the Wi-Fi applier implements `SteerToBand` (agent-side steering, §3.7): bcmwifi does; observe mode steers nothing |
| | 3 | BANDSTEER_PER_VAP | no | per-VAP steering not implemented |
| | 4 | RF_SCAN | **takeover only** | scan, spectrum-scan, quick-scan (wl.Scan, wl.SpectrumRunner); observe mode runs no scans, and a drop to observe clears the bit from the next inform. Scans (scan, spectrum-scan, quick-scan) are refused, and a running band stops, in observe mode, during a TP-Link upgrade, Wi-Fi rebuild or boot hold (`holdReason`), and during our own apply or rollback (`scanBlock`); the hold (`scanHold`) is refreshed only at worker ticks, so a scan can overlap the start of a hold by up to one tick |
| | 6 | BGA_FILTER | no | not implemented |
| | 7, 11 | MESH, MESHV3 | no | no mesh |
| | 9 | MINRATE_CTRL (`supportMinRateCtrl`) | **takeover + `min_rates`** | bcmwifi applies the controller's minrate_data / beacon_rate / minrate_cck_rates as a per-BSS `wl rateset` (rates.go, docs/deco/features/minrate.md). Network 11.1.50 never consults this bit (the minrate keys go to every UAP), so claiming it only states what the agent does. `min_rates` is off by default until the live test; a drop to observe clears the bit |
| | 10 | MULTIPLE_ACL_LIST | no | meaning not established (MAC filter + block list do exist) |
| | 12 | RADIUS_MAC_AUTH (`supportRadiusMacAuth`) | no | the Broadcom driver does 802.11 auth/association itself, so hostapd 2.9 checks the station in `hostapd_notif_assoc`, where `macaddr_acl=2` returns PENDING and the station is refused before any RADIUS query (inferred from hostapd 2.9 and the binary's strings; docs/deco/features/radius-macauth-hs20-radsec.md). The controller sends `radius.macacl.*` whatever the bit says (no caller of `supportRadiusMacAuth`); bcmwifi then fails closed. Since 2026-11-19 a block-list change no longer sends ACCEPT_ACL to such a BSS (it would have skipped RADIUS) |
| | 13 | OPEN_HOSTAPD | no | we do run hostapd, but what the controller sends for it is unknown; WPA3 works with bit 17 alone in udeco/uow |
| | 15 | ELEMENT_ADOPT | no | not implemented |
| | 17 | WPA3 | **yes** | SAE / transition via hostapd 2.9 (bcmwifi wpa3, wpa2wpa3) |
| | 18 | FILS | no | not implemented |
| | 19 | QOS_MARK_BITS (`supportQOSMarkBits`) | no | the bit switches the controller to the mark.N.* layout, written by a UAP to /proc/ubnt_frame_id (a Ubiquiti kernel module). The X20 has no such module and the agent's per-client limits are tc classes without marks (docs/deco/features/minrate.md) |
| | 20 | WPA_PSK_FILE (`supportWpaPpsk`) | **takeover only** | private pre-shared keys: without the bit the controller does not send a PPSK WLAN at all. bcmwifi writes the keys to a 0600 hostapd `wpa_psk_file` (ppsk.go). Only keys on the WLAN's own VLAN are served: this hostapd has no `dynamic_vlan`/`vlan_file`, so a key for another network is dropped with a note (its stations fail the handshake, never land on the wrong VLAN). On WPA2/WPA3 transition the keys work for WPA2 clients only. docs/deco/features/ppsk.md |
| | 22, 21, 31 | unknown | no | unknown |
| | 24 | LOCK_AP (`supportLockAp`) | **takeover only** | the controller offers "Lock to Access Point" only when every AP of the site has this bit (otherwise the UI shows an "update to UAP 5.76.0" tooltip). It enforces a lock by giving every OTHER AP the client in its `macacl` section (`type=lock2ap`); bcmwifi applies a change that touches only the station ACLs in place (hostapd DENY_ACL/ACCEPT_ACL by difference, driver MAC filter, flow flush) without restarting hostapd (acllive.go, docs/deco/features/lock-to-ap.md). Observe mode applies no MAC filter, so a Deco in observe hides the setting for the whole site |
| | 29 | QCA_VAP_NOMENCLATURE_V2 | no | QCA naming (`<radio>ap<idx>`), used only for Atheros models; a U6-Lite is MediaTek, whose VAP names come from the radio names (§3.8) |
| wifi_caps2 | 0x10 | ACS_DFS (`supportsAcsDfs`) | no | no ACS (acsd2 killed; channel 0 keeps the live one) |
| | 0x20 | ROAMING_ASSISTANT (`supportsAssistedRoaming`) | **takeover only** (with a backend that implements `RoamAssist`) | the controller then sends `wireless.N.btm_disassoc.status=enabled` / `.threshold=<dBm>` on 5/6 GHz VAPs. The agent sends an 802.11v BSS transition request with a disassociation timer (`hostapd_cli bss_tm_req`, a candidate list of the SSID's other-band BSS and scanned siblings) to a BTM-capable station below the threshold in two readings; no candidate, no request (cmd/udeco-ap/roaming.go, docs/deco/features/roaming-assistant.md). The word is sent only when non-zero; the controller reads a missing word as 0 |
| | 0x200 | NEIGHBOUR_IN_SCAN (`supportNeighbourInScan`) | no | promises UniFi neighbours in every inform's scan_table; the agent scans only on command, so Radio AI would plan from no data (docs/deco/features/roaming-assistant.md) |
| | 0x400000 | MULTICAST_SUPPRESSOR (`supportsMulticastSuppressor`) | no | maps to a closed UAP kernel module; what it suppresses is not known (docs/deco/features/multicast-inspect.md) |
| | others | | no | unknown or not implemented |
| fw_caps | 0x400 | SHA-512 SSH users | **yes** | site users installed from users.N, and ssh-adopt checks `$6$` hashes (§3.7) |
| | 0x1000 | WLAN schedule multi-block (`supportMultiBlockWlanSchedule`) | **yes** | without it the controller writes every window of a day to one un-indexed `schedule_<day>` key (only the last survives); with it, `schedule_<day>.<i>`. `translate.wlanSchedule` reads the indexed form (un-indexed as a fallback) and `schedule.go` applies schedules. Before 2026-11-19 the bit was not claimed and a scheduled WLAN would have parsed as "never on" (SSID off) |
| | 0x400000 | WLAN schedule invert (`supportWlanScheduleInvert`) | **yes** | the controller sends "off during" schedules with `schedule_invert=enabled` instead of inverting them itself; translate handles it |
| | 0x40000000 | LLDP (`supportsLldp`) | no | only feeds the UniFi OS (udapi) `lldp` block, not an AP's system_cfg; our LLDP works without it |
| | 0x1000000 | encrypted syslog (`supportSyslogEncryption`) | **yes** (both modes) | `logread -f -l 1` forwarded to `syslog.remote.ip:port`, sealed with `device.SealSyslog` (AES-256-GCM with the device key and hash_id) when `syslog.remote.encrypt=enabled`, else plain RFC 3164 (cmd/udeco-ap/syslogfwd.go). Only reads the unit, so observe mode claims it too. Without the bit an "encrypted only" logging setting sends no syslog section at all. The key is never logged |
| | 0x20000000 | RADIUS filter (`supportsRadiusFilter`) | **takeover only** | for a WPA-EAP WLAN on the console's RADIUS server the controller sends `aaa.N.filter_id` (wpa-eap, uid-wifi); bcmwifi writes `radius_auth_req_attr=11:s:<id>` (Filter-Id) in that BSS (radiusfilter.go). hostapd is the agent's only in takeover |
| | 0x4000 | SNMPv3 (`supportsSNMPv3`) | **yes** (both modes) | with it the controller adds `snmp.version=3\|all` and `snmp.user.1.{name,password}` (v1/v2c is sent without any bit). The agent's read-only SNMP agent in Go (internal/snmpagent, cmd/udeco-ap/snmp.go) serves v1/v2c by community and v3 USM authPriv (MD5/SHA/SHA-2 with DES/AES-128) on UDP/161, to loopback and the unit's LAN prefix only; Set is refused. It only reads the unit, so observe mode claims it too (docs/deco/features/snmp.md) |
| | 0x800000 | Hotspot 2.0 (`supportHotspot2`) | **takeover + `hotspot2`** | the controller sends `aaa.N.hs20.*`/`aaa.N.osu.*` for a WPA-EAP WLAN; internal/hs20 renders hostapd 2.9 interworking/hs20 lines, each checked against hostapd's own parser limits (bcmwifi hs20.go). Off by default: whether wl puts the Interworking/ANQP elements in beacons and passes GAS frames to hostapd is unverified. OSEN, Terms and Conditions, icons and the QoS map are not carried (the WLAN stays off for OSEN and T&C). Passpoint also needs RadSec (docs/deco/features/hotspot2.md) |
| | others | | no | 0x100000 RADIUS DAE, 0x800/0x4000000 HTTPS/SHA-256 firmware upgrade (never upgrade): not implemented |
| fw2_caps | 0x80000 | RadSec (`supportsRadSec`) | **takeover only** | the controller sends `certs.*` (base64 PEM: CA bundle, client cert, key) and `aaa.N.radius.*.M.tls/ca_cert/client_cert/private_key[_passwd]`; hostapd 2.9 is UDP-only (tls_none), so the agent's internal/radsec proxy listens on 127.0.0.1 and carries RADIUS/TLS (CA-only trust, IP-SAN check, client cert, TLS >= 1.2, re-signed with the server secret, accounting too); a WLAN whose RadSec server cannot be served stays off (docs/deco/features/radsec.md) |
| | 0x10000000 | mDNS service bridge (`supportsMdnsSdBridge`) | **takeover + `apply` + `mdns_bridge`** | the controller sends `mdns_sd.*` (proxies between VLAN bridges, per-VAP service filters) for WLANs in mDNS auto/custom mode; internal/mdnsbr runs it with AF_PACKET taps and sends on the bridge ports and an ebtables chain (`UDECO-MDNS`) that intercepts the filtered vifs (cmd/udeco-ap/mdnsbr.go). Off by default: once the bit is claimed the controller puts every "auto" WLAN in mDNS auto mode, and AF_PACKET sends on the wl vifs are unverified, so a vif whose re-injection never reached the air would lose all mDNS. Stopped on a drop to observe, R4 shedding or agent stop; a crashed run's chain is removed at the next start (docs/deco/features/mdns-bridge.md) |
| | others | | no | the word is sent only when RadSec or the mDNS bridge is claimed |
| fw3_caps | 0x40 | path monitoring (`supportsPathMonitoring`) | **yes** (both modes) | the controller sends the `pathmon` section and asks for the inform's `pathmon` block; internal/pathmon probes the gateway and the LLDP uplink neighbour with raw ICMP echoes (U6 Pro row shape). Sending echoes changes nothing on the unit, so observe mode claims it. Also turns on the site feature INFRASTRUCTURE_PATHMON (docs/deco/features/pathmon.md) |
| | 0x80 | multicast inspect (`supportsMulticastInspect`) | **takeover only** | `wireless.N.multicast.inspect=true` and "multicast" in include_blocks; per-client `sta_table[].multicast` from AF_PACKET taps (no promiscuous mode, no group joins) on the agent's vifs (internal/mcinspect, docs/deco/features/multicast-inspect.md). The readers stop on a drop to observe or R4 shedding |
| | 0x8 | DNS assistance (`supportsDnsAssistance`) | no | controller sends wireless.N.dns_cache.status / dns_bypass.status=enabled (+ dns_bypass.servers in manual mode) for UAP kernel modules ui_dns_cache/ui_dns_bypass that rewrite bridged client DNS; X20 kernel has no CONFIG_BRIDGE_NETFILTER and no ebtables dnat/redirect/snat (kernel config and libebt_* both lack them), and a broute route decision is dropped by ip_rcv as OTHERHOST, so neither ebtables nor iptables can divert bridged DNS; a userspace AF_PACKET proxy would be the only route (not built; AUTO-mode servers unknown). A test keeps the bit unclaimed (internal/models/dnsassist_test.go) |
| | others | | no | |
| hw_caps | all | | no (not sent) | no LED colour/brightness (ubus leds is on/off/blink) |
| radio ieee_modes | ng 90, na 85 | b/n/ac-rates/ax, a/n/ac/ax | yes | the measured U6 Pro (11ax) values; a non-HE radio gets the U7PG2 10/21 |
| radio_caps | MIMO bit | 1x1..4x4 | yes | `models.RadioCapsMIMO`; other bits have no known name |
| radio_caps2 | 0x1 | WPA3 (SAE) per radio | **takeover + `wpa3`** | without it the controller sends a WPA2/WPA3 WLAN as WPA2 only and drops a WPA3-only one (§3.8). Off by default until SAE is verified on the X20 (docs/deco/features/wpa3.md): radio_caps2 is then 0 and bcmwifi serves no SAE (`Options.WPA3`: a WPA2/WPA3 SSID as WPA2, a WPA3-only one not at all, with a note); a drop to observe clears the bit from the next inform |
| | 0x2 | WPA3 fast roaming (FT-SAE) | **takeover + `wpa3` + `ft_sae`** (`ft_sae` defaults to on with `wpa3`) | with 0x1, when the Wi-Fi backend builds FT-SAE (`DecoAgentFeatures.WPA3FT`, bcmwifi `ServesFTSAE`: `Options.WPA3 && Options.FTSAE`). Without it the controller clears `wpa3_fast_roaming` and sends `wpa3.ft.status` disabled. The agents learn each other's key holders (internal/ftpeer) and list them as explicit r0kh/r1kh entries, since hostapd 2.9's wildcard PULL never leaves the process; per-band mobility domain (docs/deco/features/ft-sae.md) |
| | 0x4, 0x8 | WPA3-Enterprise 192, OWE | no | bcmwifi builds neither Suite-B nor OWE. A real U6 Pro sends 0x1f |
| has_dfs, has_fccdfs | | | false | radar handling not owned by the agent (TP-Link's radar daemon is stopped) |

Result (2026-11-19). Observe mode: `wifi_caps 131072` (WPA3), `fw_caps 0x1405403` (placeholder bits, SHA-512 SSH,
SNMPv3, the two schedule bits, encrypted syslog), `fw3_caps 0x40` (path monitoring), no wifi_caps2/fw2_caps/hw_caps. Takeover:
`wifi_caps 17956884` (0x1120014: WPA3 | RF_SCAN | BANDSTEER | WPA_PSK_FILE | LOCK_AP, plus MINRATE_CTRL 0x200 with
`min_rates`), `wifi_caps2 0x20` (Roaming Assistant), `fw_caps 0x21405403` (+ RADIUS filter; + Hotspot 2.0 0x800000
with `hotspot2`), `fw2_caps 0x80000` (RadSec; + mDNS bridge 0x10000000 with `apply` and `mdns_bridge`), `fw3_caps 0xc0`
(+ multicast inspect), radio_caps2 0x1 on both radios with `wpa3` (else 0). Every word is sent as uint32 and only when non-zero (`device.Session`); the controller reads a
missing word as 0 (payload `getInt` default), so clearing a word's last bit also clears it there. A drop to observe
(hand-back) clears every takeover-only bit at once (`models.DecoAgentTakeover*`, in `agent.fields`); BANDSTEER stays
claimed until the agent restarts (steering itself stops: it needs takeover). None of the takeover features has been
tested on a unit yet; each feature document has its live test.

**Deviations from this document.** (1) `model` other than UAL6 is rejected. (2) Observe mode does not run
scans, LED or kicks (§3.5 lists them as actions; observe changes nothing). (3) Takeover with `apply=false`
still stops TP-Link's services (decosys for real) but bcmwifi is a dry run. (4) Supervision restarts are
recorded on ramfs, so the crash-loop count resets at reboot; the forced-observe marker does not (build 2: it
lives in `/tp_data` and needs a manual `rm`). (5) `deploy/deco-ap.sh` does not edit `/data/persist_shell.sh`
unless `--edit-persist` is given (§3.7 deploy).

### 3.7 Build 2: boot safety, self-protection, topology (decisions, 2026-11-18)

Requirement numbers are interference-audit.md's R-list. New files: `boot.go` (lock, limits, gate, crash
loop, marker, resources, events), `cfgack.go`, `topology.go` (+ `internal/lldp`), `users.go`, `schedule.go`,
`steer.go`, `selfcheck.go` (R10), `post.go` (inform HTTP client). R8a and R11 are decosys's (they run inside
`Enforce`); the agent's own copies (`guard.go`) are gone.

**Start order** (`agent.run`). Lock (R6) -> limits (R3) -> crash-loop/marker check -> reboot detection ->
phase 1 (takeover only: decosys is built with the controller, console, sshd port and `mgmt_sources`, and
`decosys.Ingress(true)` installs the inbound fence, R5; the LAN is not known yet, so :22 stays open until
the first reading) -> boot gate (the fence is re-asserted at every check: TP-Link's firewall start during boot
rebuilds INPUT) -> first reading (`SetLAN`: gateway, LAN CIDR, unit IP) -> setup -> SSH -> resource watchdog
-> LLDP -> worker -> inform loop. Every later reading hands decosys the lease again (`SetLAN`; a change is
an event), so the R8a address watch never deletes the unit's renewed lease.

**setLAN refuses the gateway's and the controller's addresses.** A reading whose first br-lan address equals
the gateway's IP or the controller's (the `inform_url` host) is never handed over as the unit's lease: that is
TP-Link's lan default `192.168.0.1/22` coming back ahead of the lease (interference-audit B5). Handed over, the
R8a watch would keep that alias and delete the real lease. The refusal is one event per refused address;
decosys keeps the LAN it was told before, so the watch still removes the alias. A reading without an address
or gateway changes nothing either.

**R6 lock.** `flock(LOCK_EX|LOCK_NB)` on `/tmp/udeco/agent.lock`, held for the process lifetime; a second
start logs and exits 1. The PID is written to the lock file and to `udeco-ap.pid` (for the documented kill
command); the PID file is no longer the lock.

**R3 limits.** `debug.SetMemoryLimit(48 MiB)`, `SetGCPercent(50)`, GOMAXPROCS capped at 3, and
`/proc/self/oom_score_adj` raised to 300 (never lowered if already higher). Logged at start.

**R1/R2 gate.** Open when `/tmp/done_boot`, `/tmp/wifi_set_done`, `/tmp/acsd2_channel_select_done` exist,
uptime >= 120 s, no upgrade is in flight and TP-Link's rc.d boot chain has ended, all read through decosys's
R17 detector (`decosys.InFlight`: upgrade flag files and `nvrammanager -u` / `upgrade` / `sshhttpget`
processes; the boot chain). If the files never appear, or a boot script never ends, the gate opens anyway at
600 s uptime (decision: a firmware that renames a flag must not keep the agent dark forever); an upgrade in
flight always holds it. Checked every 5 s; nothing is informed, built or applied before it opens. After the
gate, Enforce runs every 5 s until two clean passes and 3 min, then 60 s.

**Worker tick** (`wifi.go`, every Enforce interval). In this order: `Ingress(true)` -> `Enforce` (which also
re-asserts R8a, R11, the R16 cron invariant and the QoS removal) -> each `Report.Foreign` finding logged ->
hold check -> `Egress(true)` -> site users -> then, unless held, a pending provision, else `bcmwifi.Tick`
(non-disruptive repairs of MAC filters, WDS peers, bridge membership, guest chains, rate limits; its
datapath repairs end with its own flow-cache flush) and the health check (`Verify`, then `Rollback`). Held
means `Report.Guard` shows a TP-Link firmware upgrade or Wi-Fi rebuild in flight, or the boot chain while
uptime < 600 s: no apply, no Tick, no rollback. Drift that only an apply fixes (`TickReport.NeedsApply`) is
counted and left to the health check.

**R10 self-check** (`selfcheck.go`). Each finding is logged when Enforce reports it; findings that break the
LAN or the agent's persistence (address, DHCP server, reset button, smartip, process, boot hook, crond,
work_mode, unit IP) also go to the event ring, at most once an hour each. Every 5 min, and only when the
counts changed, one line: `self-check: foreign state since start: <kind>=<n> ...; agent VmRSS, MemAvailable,
/tmp+/etc` with decosys's cumulative `Counts()` plus the agent's own (`wifi-foreign`, `wifi-repair`,
`rate-limit`, `wifi-needs-apply` from `bcmwifi.Tick`) and the R4 figures of the last watchdog reading.

**R7 clock.** The crash-loop log stores `/proc/uptime` seconds, and entries later than the current uptime
(an earlier boot) are dropped. Wall-clock times before 2026-01-01 count as unsynced
(`device.ClockSane`): session history copies are skipped and event lines are prefixed `unsynced`.

**Persistent observe marker.** A hand-back (Apply error that left Wi-Fi with TP-Link) or a crash loop with
`takeover` configured writes `/tp_data/udeco/force-observe` (reason, one line). While it exists the agent
starts in observe mode, across reboots. To leave it (after fixing the cause):

    rm /tp_data/udeco/force-observe; kill $(cat /tmp/udeco/udeco-ap.pid)

(persist_shell restarts the agent; where cron supervision is missing, start it the same way persist_shell
does, or reboot.)

**R4 watchdog.** Every 60 s: VmRSS (`/proc/self/status`), MemAvailable, and a file walk of `/tmp` + `/etc`
(never statfs). MemAvailable < 40 MB sheds scans (refused with a log) and band steering; VmRSS > 64 MB or MemAvailable < 20 MB ends
`run` with `errResources` (exit 1; persist_shell restarts it); /tmp + /etc growing > 8 MB over the start
baseline raises an event. A failed read skips the check (logged once).

**R13 events.** `/tp_data/udeco/events.log`, a ring capped at 64 KB, written only on rare events: gate open,
reboot detected (kernel `boot_id` differs from `/tp_data/udeco/boot_id`), forced observe, hand-back, health
rollback, R8a/R9/R11 alarms, uplink change. Not done: the inform 'rebooted' field.

**R13 alive record.** `/tp_data/udeco/alive` (one JSON line, 0600): boot id, uptime, wall time (once the clock
is set), pid, state `running`/`stopped` and the worker job in progress. Rewritten at start, every 5 min, before
and after every worker job except the routine `enforce`/`schedules` ticks, and with state `stopped` when the
agent exits. The reboot event names how the previous boot ended: the agent had stopped cleanly (a userland
stop or reboot: procd sends SIGTERM), or it was still running when last seen (power loss, kernel panic or
SIGKILL, within 5 min of that time), and in which job; or there is no record from that boot (alive.go).

**R8a address watch and R11 reset button** are decosys's, inside every `Enforce`, with the unit IP the agent
hands over through `SetLAN` (the agent's earlier copies were removed to keep one owner). Findings come back
as `Report.Foreign` (kinds `addr`, `button`), which the self-check logs and counts. `decosys.Restore` puts
TP-Link's handler back on hand-back.

**R12 ssh-adopt.** Before adoption: any password, only from console_ip (as before). Once adopted:
user + password must match a site user from the saved system_cfg (`users.N.name` / `users.N.password`,
`$6$` sha512-crypt, or `$5$`/`$1$`, verified by `device.VerifyCrypt`, constant-time); no site user known yet means every
login is refused. The credential set is refreshed at setup, after every system_cfg, on adoption-state
changes and after `set-adopt`. Passwords and hashes are never logged.

**Site SSH users.** Takeover only: `users.N` (enabled) become `/etc/passwd` + `/etc/shadow` entries with
uid 0, home /root, shell /bin/ash (as a UniFi AP installs them), marked by the GECOS `udeco-ap site user`.
Only marked accounts are added, changed or removed; root, system accounts and any unmarked account are never
touched (a site user with such a name is skipped and logged). Files are rewritten atomically, keeping their
mode, only on a change; re-asserted at start and every Enforce tick (ramfs). Assumption: uid 0 is what a UAP
does; the controller's users are site admins.

**Site SSH logins** (`cmd/udeco-ap/sitessh.go`, `internal/device/sitessh.go`). Takeover only. The site users
log in on the agent's own SSH server (`sshd_port`, 2222), never on port 22 (the owner's dropbear, untouched).
The controller sends `users.N` whether Device SSH Authentication is on or off; the switch is the sshd section
(seen 2026-11-19 on .205): on = `sshd.status=enabled`, `sshd.1.ifname=br0`; off = `sshd.status=disabled`,
`sshd.1.ifname=lo` (a UAP keeps the account, its sshd listens on loopback only). `translate.SSHD` parses it;
logins are on only while `sshd.status=enabled`, `sshd.auth.passwd` is not `disabled` and an enabled
`sshd.N.ifname` is not `lo`. A user may log in when the saved system_cfg lists it with hash H **and** the
worker installed it as a marked account with hash H (a skipped name never logs in; a new password works once
installed). A system_cfg that switches logins off or removes or changes a user applies at once (refreshCreds,
before any provisioning wait) and ends that user's open sessions. Sources: `mgmt_sources` (IPv4) when set,
else the LAN; decosys opens the fence on `sshd_port` for them only while logins are on (IPv6 stays dropped,
as before). Checks: `$6$`/`$5$`/`$1$` crypt (`device.VerifyCrypt`, constant-time; an unknown user costs one
crypt of the same shape as a known user's), never root or a system account, never an empty/locked/unknown hash, 3 tries per connection,
per-source backoff after 3 failures (2 s doubling to 5 min) and a global block (20 failures/min: 1 min),
8 connections (at most 3 per source not yet logged in) and 4 sessions at most, 30 s to log in, 15 min idle timeout. Sessions: PTY (TERM, window size
and changes) or pipes, `/bin/ash` as a login shell or `ash -c <command>`, dropbear's environment (USER,
LOGNAME, HOME=/root, SHELL, PATH, SSH_CLIENT, SSH_CONNECTION, SSH_TTY; LANG/LC_* from the client), exit status
or exit signal, signal requests; no port forwarding, no sftp. Logged: user, source, result; never a password,
a hash or a command line. From console_ip nothing changes for adoption: the same password decision, and
set-adopt/set-inform (or anything naming syswrapper.sh, mca-cli-op, mca-ctrl) and a shell without a PTY still
only reach the adoption parser; a site user's PTY shell or other command from the console host runs for real.

**cfgversion acknowledgement.** The session (`Session.DeferCfgAck`) keeps the controller's cfgversion as
`cfgversion_pending` and keeps reporting the last acknowledged one. The worker acknowledges after the Wi-Fi
apply succeeded (or the plan was empty); in observe mode after the plan was logged. A failed apply keeps the
previous cfgversion, so the controller shows the AP as not provisioned and resends. A resend of the same
system_cfg (a "force provision") after a failure calls `ForgetFailed()` on bcmwifi once and provisions
again; a further failure waits for a different system_cfg. A cfgversion bump for a system_cfg already live
is acknowledged at once.

**R9 topology and loop guard** (`internal/lldp`, `topology.go`).
- LLDP: an AF_PACKET socket per Ethernet port with LLDP multicast membership. The receive side is bound with
  ETH_P_ALL plus a classic BPF filter that keeps only ethertype 0x88cc (untagged or behind one 802.1Q tag):
  on a port enslaved to br-lan a 0x88cc-bound socket never sees a neighbour's LLDPDU, because the bridge
  consumes the link-local 01:80:c2:00:00:0e group before protocol handlers run (`internal/lldp/filter.go`).
  Our own looped-back announcements are dropped by packet type. Every 30 s a
  frame goes out on the uplink only: chassis = AP MAC (subtype MAC), port `eth0`, TTL 120, system name =
  hostname, description `"<model display> <version>"` (UAP-like; the exact UAP string is an assumption),
  capabilities Bridge + WLAN AP (enabled), management IPv4 = own address. Received neighbours expire by TTL.
- **LLDP runs in observe mode too**, transmit included: the agent is started with it in both modes
  (`startLLDP`, unless built with `noLLDP`), and the announcement follows the detected uplink. It changes
  nothing on the unit, but it does put one frame every 30 s on the wire (the gateway then lists the Deco as an
  LLDP neighbour), so "observe changes nothing" means nothing on the unit, not nothing on the LAN.
- Uplink: the port where the gateway's MAC is learned (br-lan FDB) and that has carrier; else the single
  port hearing LLDP; else the single port with carrier. A change raises an event and is handed to bcmwifi
  through a worker job (`SetUplink`); the VLAN devices follow at bcmwifi's next plan or tick: `br-v<vid>`
  gets `<new>.<vid>`, and the old port's VLAN device is detached and deleted (so a VLAN bridge never holds
  both ports, which would loop them).
- Inform: shaped like the U6 Pro: `uplink "eth0"`, `has_eth1 false`, no port_table, `gateway_mac`, one
  `if_table` row `eth0` carrying the real uplink port's counters/speed, and `lldp_table` rows
  (chassis_id, chassis_id_subtype, is_wired, local_port_idx 1, local_port_name eth0, mgmt_ips, port_id;
  an empty list when nothing is heard). The controller thus sees a one-port AP whatever the physical port.
- Loop guard (takeover): the gateway heard by LLDP on both ports, or its MAC learned on both, takes the
  non-uplink port out of br-lan (`brctl delif br-lan <p>`, `decosys.FlushFlows{Dev: p}`, invalidate the reading) with
  a loud log and event; re-asserted every reading. It goes back (`brctl addif`) when it loses carrier or
  becomes the only uplink (`brctl addif`, again followed by the flow flush, R21). LLDP evidence keeps it out while heard; FDB-only evidence holds until carrier
  drops. Observe mode logs only (one event per run; see below for ports recorded by an earlier takeover run). Not done: R9's default removal of the non-uplink port at takeover, and the
  `tpbrctl show` norelay check.
- **Removed ports persist across agent restarts** in `/tmp/udeco/loopguard` (run dir, ramfs; one
  `<port> <lldp|fdb>` line per port, written atomically after each successful `brctl`, mode 0600). A restarted
  agent (crash, deploy, R4 exit) loads it and logs each port, so it still brings the port back on carrier loss
  or uplink loss; without it a port taken out by an earlier run would stay out (FDB evidence is invisible on a
  port outside br-lan), and if that port later carried the only cable the unit would be cut off. A reboot
  rebuilds br-lan with both ports and clears the file with the rest of ramfs.
- Hand-back: `decosys.Restore` puts every port listed in `decosys.Options.LoopGuardFile` back into br-lan
  (`brctl addif`, flow flush; a port already a bridge member is left alone) and removes the file. The agent
  passes `LoopGuardFile` (`/tmp/udeco/loopguard`) to decosys, so a hand-back's Restore puts the ports back and
  the loop forgets them at its next reading. An agent starting in observe mode with a record restores them
  through `decosys.RestoreLoopGuard`, which keeps a port out while it and another br-lan Ethernet port both
  have carrier (br-lan has no STP: re-adding it could close the loop it was taken out for).
- **Observe mode never changes br-lan** apart from that start-time `RestoreLoopGuard`: it takes no port out,
  and it puts none back by itself (brctl jobs are worker jobs, and the worker runs only in takeover). A port
  still recorded as out stays tracked as out, which keeps the uplink choice truthful; when it could come back
  (carrier lost, uplink lost, LLDP gone) one event per reason says so and that restarting the agent (whose
  observe start runs `RestoreLoopGuard` again) or a reboot puts it back. It is forgotten only once a reading
  shows it in br-lan again. Residual risk: if such a port later becomes the only cabled one, the unit has no
  bridged uplink until the agent is restarted or the unit rebooted.
- Loop-guard bookkeeping: a delif job queued for a port (take-out, or "put back by someone else") is not
  queued again while it is pending, so readings taken before the worker runs it neither repeat the job nor
  report the port as re-added by someone else. A port's FDB sighting of the gateway's MAC is forgotten when a
  reading shows the port without carrier, so when the cable moves (and the uplink with it) the old uplink is
  not taken out on that stale sighting should it regain carrier within the 60 s FDB window. Sightings are not
  cleared on every uplink move: in a real loop the gateway's MAC flaps between ports with carrier, moving the
  uplink each reading, and those sightings are the evidence.

**Band steering.** Agent-side, since the Deco has no bsd and a UAP steers by itself. Only when the
controller enabled band steering for 2.4 GHz (`bcmwifi.Desired` radio `BandSteer`), takeover, not shedding,
and the applier implements `SteerToBand(ctx, vif, mac, bssid)` (bcmwifi does). A client on a 2.4 GHz SSID with
signal >= -60 dBm that was seen on 5 GHz in the last 24 h, whose SSID also has a 5 GHz BSS, gets an 802.11v
request for that BSS through the vif it is on; at most once per client per 10 min and 2 per reading; mode `equal` steers only while
5 GHz has fewer clients. Thresholds are assumptions to tune live.

**WLAN schedules.** The WLAN schedules of system_cfg (translated to windows such as `mon 0800-1730`, end
exclusive, local time = the unit's TZ, UTC on .205) are evaluated every minute. The agent re-plans with the
out-of-window SSIDs disabled and applies (once per window edge; hostapd restarts only on the radios whose SSID
set changed). Decision: no per-SSID switch hook. A scheduled-off SSID must stay off through bcmwifi's
`Verify`, `Tick` and `Rollback`, which only a Desired with that SSID disabled guarantees. Provisioning applies
the current window state at once.

**Guests.** A system_cfg with a guest SSID (`aaa.N.is_guest`) gives bcmwifi a `GuestPolicy`: the controller's
restricted and pre-allowed ranges and portal flag (`translate.GuestPolicy`), plus what only the unit knows, the
gateway's MAC (from ARP/FDB, kept by the topology tracker) and IP. Without the gateway's MAC there is no policy
and bcmwifi does not serve the guest SSID (it fails closed); the plan notes say so. `authorize-guest` /
`unauthorize-guest` go to `bcmwifi.AuthorizeGuest` / `UnauthorizeGuest` (UDECO-GAUTH; bcmwifi flushes the
guest's flows and kicks it on unauthorise). The session keeps each guest's end time on /tp_data; the agent
unauthorises expired guests itself (the controller sends nothing at expiry) and re-authorises unexpired ones
at start, since bcmwifi's list lives on ramfs. There is no HTTP redirect to a portal (ebtables cannot
redirect): unauthorised guests reach DHCP, DNS, the pre-allow list and the portal host only.

**Inform HTTP client** (`post.go`). net/http (with crypto/tls, HTTP/2, IDNA and the proxy code) was the
largest part of the binary. The inform is one plain-HTTP POST to an IPv4 literal, so a minimal HTTP/1.1
client replaces it: one request per connection (`Connection: close`), `Content-Length`, chunked or
read-to-EOF answers, 1xx skipped, a 4 MiB answer cap, a 16 KiB header cap, a 10 s deadline and SIGTERM
cancelling the connection at once. No TLS, redirects, proxies or keep-alive: `https://` inform URLs are
refused at config load.

**Binary size and import graph.** The reading model and its inform rendering moved from `internal/openwrt`
to `internal/apstate` (aliases kept in openwrt), so the agent no longer links the OpenWrt SSH collector
(`x/crypto/ssh/knownhosts`, its `os/exec` use) or anything off-device. `x/crypto/ssh` stays: the SSH adopt
server (`device.SSHAdopt`) needs it. Stripped linux/arm GOARMv7: 9,371,772 bytes before, 7,602,300 after
(gzip -9: 3,084,295). No UPX.

**Deploy** (`deploy/deco-ap.sh`, R27-R29). Over 6 MiB the stripped binary ships as `udeco-ap.gz` with the md5
of the binary in `udeco-ap.md5`; at or below, the plain binary ships. The launcher `/tp_data/udeco/start.sh`
exits while an agent runs; otherwise it unpacks the gzip to ramfs `/tmp/udeco-bin` (only when the copy there
does not match the md5), checks the md5 and execs the agent. Cost: the unpacked binary (about 7.3 MiB) is RAM
that cannot be reclaimed, against flash-backed pages for a plain binary on /tp_data. The preflight is
read-only and judged on the deploying machine: armv7, /tp_data, the persist file, a crontab line running
it, a persist file whose cron guard occurs in the line it appends, the firewall include, at least 1 MiB left
on /tp_data after the install; a warning (only) when `--udeco-config` lists the unit's MAC. The persist file
is the user's: the script prints the one line to approve,
`[ -f /tp_data/udeco/start.sh ] && sh /tp_data/udeco/start.sh </dev/null >/dev/null 2>&1 & # udeco-ap supervise (deploy/deco-ap.sh)`,
and writes it only with `--edit-persist` (every other line checked byte for byte). It ends with the R29
checklist and a single rollback command (drop the line and the launcher, stop the agent, reboot).

**scan_table convention.** Each row carries both key sets: the controller-documented ones (`is_unifi`,
`serialno`, `age` in s) and the U6 Pro's (`is_ubnt` = is_unifi, `ap_name` "", `noise`, `rssi_age`).
`rssi = max(0, signal - noise)`, as on all 17 rows of the U6 Pro's mca-dump; `noise` is the radio's noise
floor from the collector, else -95, so with no noise reading rssi equals the previous `signal + 95`.
`rssi_age = age x 10` (U6 Pro pairs suggest deciseconds; inference).

### 3.8 Radio names, VAP devnames and WPA3 (2026-11-19)

Controller evidence: Network 10.6.109 decompiled (class names below are that release's; the live 11.1.50
is a native image, but both live symptoms are reproduced exactly by this code).

**Chipset.** The controller picks the config builder from the model's chipset, not from the inform:
`XCfthFC.isMediaTekAP()` is the model enum's chipset (UAL6 and UAE6 are `MEDIATEK`, type UAP), and
`CjTLEUfgfDYCfBSnbyC` returns the MediaTek builder (`iqHfwSoIdFucUE`, flavor MEDIATEK) for it.

**VAP devnames for MediaTek** (`ubntconf.rKjGTvdyNuMoNj`, then the persisted config meta
`ubntconf.meta.rKjGTvdyNuMoNj`): radio name minus its last character, plus the VAP's index on that
radio; then, per radio, if no VAP with index 0 is named exactly like the radio, the first VAP is renamed
to the radio name (index 0). Uplink VAPs are `apcli0` (radio `ra0`) / `apclii0` (others). The controller
hard-codes `ra0` / `rai0` as MediaTek radio names (config-meta migrations, the spectrum builder's default
`rai0`), and the firmware's syswrapper tells 5 GHz VAPs by the third character `i`.
- Radios reported as `ra0` / `rai0` (a real U6-Lite): `ra0, ra1, ...` and `rai0, rai1, ...`, one per SSID.
- Radios reported as `wifi0` / `wifi1` (what the agent did up to 2026-11-19): 2.4 GHz `wifi0`, `wifi1`, ...;
  5 GHz `wifi0, wifi1, ...` with the first renamed to `wifi1`, i.e. `wifi1, wifi1, wifi2, ...`. So the
  first two 5 GHz VAPs share `wifi1`, and a second (third) 2.4 GHz VAP shares `wifi1` (`wifi2`) with a 5 GHz
  one; a third 5 GHz SSID is unique (live 2026-11-19: `udeco-test` on 5 GHz got `wifi2`). Live on
  .205: Example Network 5 GHz and olive# were both `wifi1`, listed by `br0` and `br0.3`, and
  `aaa.2.br.devname=br0.3` for the Home SSID. translate then put every `wifi1` VAP on VLAN 3; a 5 GHz-only
  Home SSID next to a 5 GHz VLAN SSID is mis-bridged (`TestIntentDuplicateDevnameNoted` notes it).

**Agent naming** (`cmd/udeco-ap/radionames.go`, `device.State.RadioNames`, `apstate.CfgInfo.RadioNames`).
The controller merges reported radio rows by name and never drops one (`gliBtHTTrWRd`, radio_table
merge), so renaming the radios of an adopted AP would leave four rows and every WLAN deployed twice per
band. Hence:
- a new state (no state.json) reports `ra0` / `rai0`;
- a state from an earlier build (no `radio_names`) keeps `wifi0` / `wifi1` while that adoption lasts
  (logged with the cost, once per start);
- setdefault (Forget in the controller) switches to `ra0` / `rai0` before the next inform and saves it.
To move .205: Forget the AP in the controller, wait for it to show as pending again (it informs on the
factory key with `ra0` / `rai0`), adopt it. Do not rename by editing state.json while it is adopted.
VAP rows find their devname by radio name, else by band, so a system_cfg built for the other naming still
labels the vap_table.

**WPA3.** wifi_caps WPA3 is not enough. The per-device WLAN filter (`ubntconf.qemBJTmR`) keeps WPA3 on a
radio only when that radio's `radio_caps2` has 0x1 (`RadioTableEntry`: radio_caps2 = "radio capabilities
extended"); otherwise a transition WLAN loses `wpa3_support`/`wpa3_transition` (system_cfg
`wpa.key.1.mgmt=WPA-PSK`, no `wpa3.*`), and a WPA3-only WLAN is not sent ("SAE cannot provision"). The agent
reported 0, which is exactly what .205 shows. With the config key `wpa3` (takeover only, off by default
until SAE is verified live; docs/deco/features/wpa3.md) it claims 0x1 on both radios (`models.RadioCap2WPA3`,
`DecoAgentFeatures.WPA3`) and bcmwifi serves SAE (`Options.WPA3`); without it radio_caps2 is 0, as before
2026-11-19, and bcmwifi serves a WPA2/WPA3 SSID as WPA2 and no WPA3-only SSID.
With `wpa3` the agent also claims 0x2 (WPA3 fast roaming) unless the config key `ft_sae` is false (kill
switch, default on with `wpa3`): bcmwifi serves FT-SAE (`Options.FTSAE`). hostapd 2.9 keeps a wildcard
R0KH's broadcast PULL inside its own process, so UniFi's wildcard key holders cannot work; instead the
agents announce their key holders to each other (internal/ftpeer: EtherType 0x88b5 on each FT-SAE bridge,
HMAC under a key derived from the WLAN's iapp_key, replay and rate limits, 70 s expiry) and bcmwifi lists
every peer BSS explicitly (`r0kh`/`r1kh` per peer, `pmk_r1_push`), new ones added to the running hostapd
over its control socket without a restart (stale ones stay until its next restart: 2.9 cannot remove
them). One unit's two radios run separate hostapds that cannot pass a PMK-R1, so an FT-SAE BSS gets a
per-band mobility domain and a cross-band roam on one unit is a full SAE (docs/deco/features/ft-sae.md,
with the one-process and relay alternatives). radio_caps2 is copied
from every inform (no re-adoption needed); the controller re-provisions on the next settings change (§3.6:
capability words alone do not trigger provisioning).

### 3.9 Monotonic inform counters (2026-11-19)

**Symptom.** The controller showed 1.57 TB "Past 24H" on .205's 5 GHz radio (`stat.wireless.by_radio_name`
wifi1 tx 1.494e12 over about 3 h) while the real traffic was megabytes.

**Controller (Network 10.6.109 decompiled; the live 11.1.50 matches the symptom).** Two delta paths, both
keyed by name, never by interface:
- `com.ubnt.service.devmgr.lVGbxbqo` (`stat-helper-lastknown`): per namespace and field, `delta = new - last`,
  counted only when `last != 0 && delta > 0`; the new value is stored either way. Used for the VAP bytes
  (`ap-<mac>-<radio>-<vap name>-<wlanconf_id>`, tx/rx bytes), the VAP Wi-Fi counters (`<obj>-<mac>-<vap name>`:
  `wifi_tx_attempts`, `wifi_tx_dropped`, `tx_retries`), the uplink and the athstats.
- stat3 (`com.ubnt.service.system.xFcFXmUmQb`, counter type `com.ubnt.service.system.q.a.a.vFiJoQiuQjMZUx`):
  per stat `user|guest-<radio_name>-<vap name>-<wlanconf_id>-<field>` for rx/tx packets, bytes, errors,
  dropped, retries, `wifi_tx_attempts`, `wifi_tx_dropped`; same rule (a drop counts nothing and becomes the
  new base). Per-radio and per-band totals (`<radio_name>-tx_bytes`, `user-...`) are sums of these VAP
  deltas (`JLudBrawuIVqu`), so a radio total is only as good as its VAP keys.

So a counter that drops is taken as a reset, and when it climbs back the whole rise is counted. Two sources
alternating under one key (the two VAPs named `wifi1`, rows in one inform even) are counted as the difference
of their totals at every inform: about 1.4 GB per inform on .205. Other ways to alternate: an SSID moving to
another vif, a vif recreated by hostapd (counters from 0), observe mode's position-based `athN` names moving
between TP-Link vifs, a station listed on two vifs, the if_table row (the uplink renamed eth0) moving from
eth1 to eth0, and a 32-bit counter wrapping. Where `wlanconf_id` comes from was not traced; on .205 it did
not keep the two `wifi1` rows apart.

**Agent (`apstate.Counters`, `cmd/udeco-ap/counters.go`).** Every counter the inform carries per VAP name
(`vap_table` netdev counters and the station sums `tx_retries`, `wifi_tx_attempts`, `wifi_tx_dropped`,
`tx_total`, `tx_success`), per station MAC (`sta_table` bytes, packets, retries) and in the if_table row is a
total that only grows:
- each source is read on its own: a vif or port by name and interface index, a station by MAC, vif and
  association (its "in network" time); only the source's own rise since its last reading is added to the
  total of the key it is reported under now, and every row with that key (same name, same MAC) in one
  inform carries the same value;
- a netdev's drop is a 32-bit wrap when the last value fits 32 bits (the driver's `net_device_stats` are
  `unsigned long` on this armv7 kernel) and its identity is confirmed (the same interface index at both
  readings), else a reset to 0: a vif whose index was unreadable at a reading (being recreated) may be a new
  instance, and a reset read as a wrap adds up to 4 GiB that never was;
- a station's drop is always a reset: a reassociation the "in network" time did not reveal (the old
  association a few seconds old and the new one made right after a reading, or no "in network" line at all).
  wl sta_info's byte counters are 64-bit and its packet counters do not wrap within one association in
  practice;
- a new interface index, or a station association younger than the gap since its last reading, means the
  counters started at 0: all of them are new traffic;
- a netdev read for the first time under a key that already has a total (a TP-Link vif with traffic from
  before, a cable moved to the other port) is a baseline: it adds nothing. A key's first source starts the
  total at its value (what a real AP would report). When unsure, count less, never more.
- `wlX1` is never a user VAP (collector: TP-Link's backhaul in observe, the agent's placeholder in
  takeover), even when its `dwds` cannot be read, so its counters are never reported under a user VAP name.

The state (`/tmp/udeco/counters.json`, 0600, at loop exit, at once after a change a restart from an older
state would not repeat: a source or key first seen, a reset, a wrap, a new association; else at most every
30 s) holds each source's last raw
values next to the totals, so a restarted agent (crash, deploy, R4) continues the totals and counts the
traffic of the gap once; its clock is the unit's uptime, and a state from another boot is dropped. A reboot
clears it, as it clears a real AP's counters. Retention: station sources 1 h after last seen, station totals
24 h, the rest 7 days. Radios report no byte counters of their own (`radio_table_stats` has none; the
controller fills `tx_packets`/`tx_retries` from the stations).

Limits: with colliding names (the legacy `wifi0`/`wifi1` naming of an adoption from before 2026-11-19, §3.8)
every row of a name carries the name's total, so per-radio graphs can count a shared name's traffic on both
radios (bounded, no spike; re-adopting with ra0/rai0 names ends it). A station associated but unread for over
an hour (its VAP not user-facing meanwhile) is counted from its association again. The `sta_table[].multicast`
blocks (mcinspect) are per agent run and not covered.

## 4. Safety rules for development and rollout
1. Unit tests and fakes only. No package test touches a device.
2. Live tests run **only on 192.168.0.205**, which is the only rooted unit. Observe mode comes first. Takeover follows, with a written rollback; the fallback is a reboot, which restores stock TP-Link.
3. Never copy Wi-Fi passphrases or device private keys into the repo. `internal/wl/testdata/tmp_getfirm-product-info.txt` contains device RSA keys and must be redacted before any commit.
