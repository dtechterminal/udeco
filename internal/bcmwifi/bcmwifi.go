// SPDX-License-Identifier: GPL-2.0-or-later

// Package bcmwifi is the write side of the Deco X20 agent: it turns a
// desired Wi-Fi state (radios and SSIDs, mapped by the agent from
// translate.Intent) into Broadcom wl settings, hostapd 2.9 configs, and
// bridges/VLANs, then verifies the result and rolls back when it does not
// come up.
//
// Ownership model (see docs/deco/agent-design.md §3.4 and the wifi-bringup
// research report):
//
//   - hostapd owns security and BSS beaconing, one process per radio, config
//     at RunDir/hapd-wlN.conf (0600, the only place a passphrase, RADIUS
//     secret or placeholder passphrase is written), control sockets under
//     CtrlDir. hostapd does not own the PHY on this driver. This hostapd
//     (live facts F1-F5, .205, 2026-11-19) needs interface= to be an existing
//     netdev, creates every bss= vif itself (bssid= required), and deletes
//     those vifs when it exits; it leaves every BSS down and does not bridge
//     (bridge= is not honoured). So interface= is always wlN1 (the radio's
//     first vif, the only one that survives a hostapd exit) as a hidden
//     WPA2-PSK placeholder with a random SSID and passphrase, kept BSS down,
//     and each SSID is a bss= section. After starting hostapd the agent
//     waits for its BSS setup, then per vif does what TP-Link's wifi script
//     does: driver iovars, brctl addif, ifconfig up, wl bss up.
//   - wl owns the PHY: country, chanspec, bw_cap, txpwr_degrade, plus the
//     per-BSS driver iovars TP-Link sets next to hostapd (dwds, closednet,
//     ap_isolate, bss_maxassoc, wmf_bss_enable, rrm, fbt, macmode/mac, and
//     with Options.MinRates the rateset), set on the fresh vif while its BSS
//     is down.
//   - Client SSIDs use the vifs wlN2..wlN7 in WLAN-ID order: those that
//     exist or whose BSSID is known (TP-Link's conf, the baseline), since a
//     bss= vif exists only while a hostapd serves it; on the stock firmware
//     that is wlN2..wlN6. Until R22 is settled, br-lan SSIDs only go on
//     wlN2/wlN3 (Options.AnyVifOnLAN). Unused vifs do not exist (no idle
//     beacons). The primaries wl0/wl1 (STA on a satellite) carry no SSID.
//     TP-Link's driver MAC filters (its per-client band/unit binding) go
//     with the vifs at takeover; the primary's and wlN1's are flushed, and
//     every vif's is compared with the live driver on every Plan.
//   - Proxy ARP: hostapd's proxy_arp needs the vif to be a bridge port at BSS
//     setup, impossible for a vif it creates (F5). An isolated SSID asking
//     for it gets the bridge port's proxyarp_wifi instead, which answers
//     only from the bridge's neighbour table (no DHCP/ND snooping table).
//   - VLANs: hostapd has no dynamic_vlan keys, so each VLAN gets its own
//     bridge br-v<vid> holding <uplink>.<vid> (kernel 802.1Q). VLAN 0 means
//     br-lan.
//   - Guest SSIDs are isolated with ebtables (guest.go), per-client rate
//     limits use tc htb/sfq (shape.go), and the Broadcom flow cache is
//     flushed after each datapath change (fcache.go, audit R21) and turned
//     off while any tc limit is built (accelerated flows bypass tc).
//
// Nothing here writes Broadcom nvram (user or kernel), runs wlconf, or
// touches TP-Link's /tmp/wlN*.conf files. Every change is volatile, so a
// reboot always returns the unit to stock TP-Link Wi-Fi.
package bcmwifi

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/ftpeer"
	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

// Runner executes a command and returns its stdout. It is the same small
// interface internal/wl and internal/decosys use; implementations apply a
// timeout.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Default locations on the device.
const (
	DefaultStateDir = "/tp_data/udeco/state" // persistent (ubifs, mounted sync): last-good only
	DefaultRunDir   = "/tmp/udeco"           // ramfs, unbounded, RAM-backed: confs, pids, ACLs, baseline
	CtrlDir         = "/var/run/udeco-hostapd"
)

// Options configures an Applier.
type Options struct {
	// Root is the filesystem root: "/" on the device, a test tree in tests.
	// Device paths (sysfs, /proc, RunDir, StateDir) are resolved under it.
	Root string
	// Run executes wl, hostapd, hostapd_cli, brctl, ip, ifconfig, kill and
	// ubus.
	Run Runner
	// StateDir holds last-good.json and last-good.secrets.json (0600).
	StateDir string
	// RunDir holds the hostapd confs, pid files, ACL files and the TP-Link
	// baseline captured at takeover.
	RunDir string
	// Uplink is the wired port VLAN devices are created on (eth0/eth1). ""
	// picks the only br-lan eth port with carrier; pass the collector's
	// gateway-FDB detection here when available.
	Uplink string
	// DryRun makes Apply, Rollback, Kick, SetBlocked and LED log the steps
	// they would run and change nothing. Plan and Verify only read.
	DryRun bool
	// Logf receives progress lines. Lines never contain secrets.
	Logf func(format string, args ...any)
	// VerifyTimeout bounds the post-apply verification (default 30 s).
	VerifyTimeout time.Duration
	// MinRates applies SSID.MinRateKbps as each BSS's rateset (wl rateset,
	// set while the BSS is down; beacons go at the lowest basic rate).
	// Off by default: untested on the X20, and the Deco does not claim
	// MINRATE_CTRL until it is.
	MinRates bool
	// WPA3 serves SAE: SSID security wpa3 and wpa2wpa3. Off by default
	// until SAE is verified live on the X20 (the agent then claims
	// radio_caps2 WPA3, so the controller sends WPA3 at all): a wpa2wpa3
	// SSID is served as WPA2 and a wpa3 one is skipped, with a note.
	WPA3 bool
	// FTSAE serves FT-SAE (802.11r for SAE clients, ftsae.go) on top of
	// WPA3, with the other units' key holders listed explicitly (hostapd
	// 2.9 cannot use UniFi's wildcard entries: ftsae.go) as SetFTPeers
	// hands them over, new ones added to the running hostapd by
	// SyncFTPeers. Off in a zero Options; the agent sets it from its
	// config (wpa3 and ft_sae). Without it the agent does not claim
	// radio_caps2 0x2 and an SSID keeps FT-PSK and SAE without FT.
	FTSAE bool
	// NoTWT keeps TP-Link's TWT setting on the radios (`wl twt enab 0`).
	// TWT is on in a zero Options, as a U6 Pro sets twt_responder 3 on
	// every VAP; the agent sets NoTWT from its config (twt false). The
	// state is written only inside a radio down/up the plan makes anyway
	// (twt.go).
	NoTWT bool
	// KeepDesense keeps TP-Link's glitch-based receiver desense (the
	// interference mitigation mode's bit 0x1). Off in a zero Options: the
	// agent clears it, as a U6 Pro runs ani_enable 0 (parity.go); the agent
	// sets it from its config (rx_desense true).
	KeepDesense bool
	// Ctrl sends one command to the hostapd control socket of vif
	// (CtrlDir/<vif>) and returns the reply. nil = a unix datagram socket
	// under Root. Used for the commands that carry a secret (SET r0kh/r1kh
	// with the FT key), so the key is never on a command line or in a
	// Step.
	Ctrl func(ctx context.Context, vif, cmd string) (string, error)
	// AnyVifOnLAN lets br-lan (VLAN 0) SSIDs use any vif. Off by default
	// (audit R23): only wlN2/wlN3, which TP-Link's tpbr types for br-lan,
	// until R22 decides how other vifs are typed.
	AnyVifOnLAN bool
	// Caps, when set, returns the driver's hardware facts (pass the
	// collector's wl.Collector.Caps). Plan then checks each radio's channel
	// and width against Caps.Bands[band].Channels (and the DFS flag) when
	// Caps.Country is the country in force, and clamps what the driver does
	// not allow (auto channel, narrower width) with a note instead of
	// applying it. nil (or an error) keeps the static channel table only.
	Caps func(ctx context.Context) (wl.Caps, error)
}

// Applier applies desired Wi-Fi state to the Broadcom radios.
type Applier struct {
	o Options

	mu      sync.Mutex
	applied *Desired          // last Desired applied and verified in this process
	blocked []string          // normalized blocked MACs; nil = not loaded yet
	macs    map[string]string // vif -> cur_etheraddr (fixed per unit)
	ledOn   bool
	failed  *failedApply               // the last Desired whose Apply failed and rolled back
	ph      map[string]hapdPlaceholder // anchor vif -> hostapd placeholder BSS (secret)
	anchors map[string]string          // primary -> hostapd's interface= vif as last seen (anchor.go)
	nbr     nbrState                   // 802.11k neighbor scans (neighbors.go)
	now     func() time.Time
	ftPeers []ftpeer.Peer           // other units' FT key holders (SetFTPeers)
	ftLive  map[string]*ftLiveState // primary -> entries added to its running hostapd (ftpeers.go)
	// clientRates: per-client limits (clientrate.go); nil = not loaded yet
	clientRates map[string]RateLimit
	// fcOff: the agent turned the flow cache off for its tc limits (also
	// RunDir/fc-off); fcNote: the last fc status problem logged (fcache.go)
	fcOff  bool
	fcNote string
	// twtSeen: band -> the TWT line Tick logged last (twt.go)
	twtSeen map[string]string
	// txCeil: radio+chanspec -> tx power ceiling (dBm), txRep: band -> the
	// last planned tx power (txpower.go)
	// refused: StepCmd argv a driver refused and an Alts stood in for
	// (country IN/288); dfsMoved: primary -> a radar move followed,
	// radarQ: radar moves Tick has not reported yet (dfs.go)
	refused  map[string]bool
	dfsMoved map[string]dfsMove
	radarQ   []RadarEvent
	txMu     sync.Mutex
	txCeil   map[string]float64
	txRep    map[string]txReport
	liveCh   map[string]int // band -> live control channel (LiveChannel)

	sleep func(time.Duration)
	poll  time.Duration
}

// New returns an Applier. It does no I/O.
func New(o Options) *Applier {
	if o.Root == "" {
		o.Root = "/"
	}
	if o.StateDir == "" {
		o.StateDir = DefaultStateDir
	}
	if o.RunDir == "" {
		o.RunDir = DefaultRunDir
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.VerifyTimeout <= 0 {
		o.VerifyTimeout = 30 * time.Second
	}
	return &Applier{
		o:       o,
		macs:    map[string]string{},
		ph:      map[string]hapdPlaceholder{},
		anchors: map[string]string{},
		ledOn:   true,
		sleep:   time.Sleep,
		now:     time.Now,
		poll:    2 * time.Second,
	}
}

// layout places d with this Applier's options. Plan, Verify, the ACL refresh
// and Tick all go through it so they agree on placement.
func (a *Applier) layout(d Desired) *layout {
	g, notes := normalizeGuest(d.Guest)
	l := planLayout(d, a.vifKnown, layoutOpts{anyVifOnLAN: a.o.AnyVifOnLAN, minRates: a.o.MinRates, guestOK: g != nil,
		prior: a.priorSlots(), noSAE: !a.o.WPA3, noFTSAE: !a.ServesFTSAE(), anchor: a.anchor})
	l.Guest = g
	l.Notes = append(notes, l.Notes...)
	return l
}

// Errors returned by the Applier.
var (
	// ErrNotOwned means the agent's hostapd is not running, so there is no
	// BSS to act on (Kick).
	ErrNotOwned = errors.New("bcmwifi: Wi-Fi is not owned by the agent")
	// ErrNoBaseline means Rollback had neither a last-good state nor a
	// TP-Link baseline from this boot; TP-Link's hostapd was restarted but
	// BSS and bridge state could not be restored exactly. Reboot the unit
	// for a full restore.
	ErrNoBaseline = errors.New("bcmwifi: no TP-Link baseline for this boot; reboot to restore stock Wi-Fi")
	// ErrDesiredFailed means Apply was given the same Desired that already
	// failed (and was rolled back) in this process; it changed nothing.
	// Applying it again would only take Wi-Fi down and up once more. A
	// different Desired, a successful Apply, or ForgetFailed clears it.
	ErrDesiredFailed = errors.New("bcmwifi: this Desired already failed to apply; not retried")
)
