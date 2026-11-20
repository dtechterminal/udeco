// SPDX-License-Identifier: GPL-2.0-or-later

package deco

// wlan.go turns the UniFi WLANs of a system_cfg into partial 0x4008 Sets
// shaped like the Deco app's (docs/deco/design.md §8; P§8.4), and applies
// them with a backup, a verify window and an automatic rollback (§8.4).
//
// Only the config owner's runner (the master's) may cause an apply; every
// other submission is logged only. With apply off (the default) plans are
// logged and nothing is sent. Passphrases never reach a log line: plans
// print them through translate.Mask and RedactJSON.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dtechterminal/udeco/internal/translate"
)

// ---- planning ----

// bandPatch is the set of keys udeco writes on one band's host or guest
// object; nil fields are left alone.
type bandPatch struct {
	Enable, Hide, WPA3 *bool
	SSID, Password     *B64
}

// wifiPatch is what one Set changes, per WirelessInfo band name.
type wifiPatch struct {
	kind  string // "host" or "guest"
	bands map[string]bandPatch
}

// WLANPlan is what the controller's Wi-Fi config asks of the Deco mesh.
type WLANPlan struct {
	Host    *WirelessInfo // partial 0x4008 body for the main network; nil = no change
	Guest   *WirelessInfo // partial 0x4008 body for the guest network; nil = no change
	Changes []string      // differences from the current wireless info; secrets masked
	Notes   []string      // UniFi settings clamped or skipped, and planning decisions

	host, guest wifiPatch
}

// Empty reports whether nothing needs sending.
func (p *WLANPlan) Empty() bool { return p.Host == nil && p.Guest == nil }

// String renders the plan for logs. Passphrases are masked.
func (p *WLANPlan) String() string {
	var b strings.Builder
	if p.Empty() {
		b.WriteString("no change")
	}
	for _, c := range p.Changes {
		b.WriteString("\n  change: " + c)
	}
	for _, n := range p.Notes {
		b.WriteString("\n  note: " + n)
	}
	for _, x := range []struct {
		name string
		body *WirelessInfo
	}{{"host", p.Host}, {"guest", p.Guest}} {
		if x.body != nil {
			js, _ := json.Marshal(x.body)
			fmt.Fprintf(&b, "\n  %s Set 0x%04x: %s", x.name, OpSetWireless, RedactJSON(js))
		}
	}
	return b.String()
}

// wirelessBands lists the band slots of a WirelessInfo in a fixed order.
// band60 is left out: Sets mirror it from band5_1 (P§8.4).
func wirelessBands(w *WirelessInfo) []struct {
	name string
	b    **WirelessBand
} {
	return []struct {
		name string
		b    **WirelessBand
	}{{"band2_4", &w.Band2G4}, {"band5_1", &w.Band5G1}, {"band5_2", &w.Band5G2}, {"band6", &w.Band6G}, {"band6_2", &w.Band6G2}}
}

func bandNamed(w *WirelessInfo, name string) *WirelessBand {
	if w == nil {
		return nil
	}
	for _, s := range wirelessBands(w) {
		if s.name == name {
			return *s.b
		}
	}
	if name == "band60" {
		return w.Band60G
	}
	return nil
}

// unifiBand maps a WirelessInfo band to a UniFi system_cfg band.
func unifiBand(name string) string {
	switch name {
	case "band2_4":
		return "2g"
	case "band5_1", "band5_2":
		return "5g"
	}
	return "6g"
}

// wlanNet is one UniFi network: the WLANs of one SSID across radios.
type wlanNet struct {
	ssid  string
	guest bool
	per   map[string]translate.WLAN // band -> WLAN
}

func (n *wlanNet) on(band string) bool {
	w, ok := n.per[band]
	return ok && w.Enabled && !w.RadioOff
}

// ref is the WLAN whose settings apply: the 2.4 GHz one if enabled, else
// the first enabled, else any.
func (n *wlanNet) ref() translate.WLAN {
	for _, b := range []string{"2g", "5g"} {
		if n.on(b) {
			return n.per[b]
		}
	}
	for _, b := range []string{"2g", "5g"} {
		if w, ok := n.per[b]; ok {
			return w
		}
	}
	return translate.WLAN{}
}

func (n *wlanNet) features() []string {
	seen := map[string]bool{}
	var out []string
	for _, w := range n.per {
		for _, f := range w.Features {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	sort.Strings(out)
	return out
}

// differs reports whether the radios disagree on a setting the Deco keeps
// network-wide.
func (n *wlanNet) differs() bool {
	a, okA := n.per["2g"]
	b, okB := n.per["5g"]
	return okA && okB && (a.PSK != b.PSK || a.Hidden != b.Hidden || a.Encryption != b.Encryption)
}

// PlanWLAN maps the controller's WLANs to partial 0x4008 Sets against cur,
// the current 0x4009 result (design §8.1-8.3):
//
//   - the main network is the first enabled non-guest WLAN on both radios
//     (else on either); its SSID, PSK, hide_ssid and WPA3 go to every band's
//     host, and a band's host is enabled iff some user WLAN is enabled on it;
//   - the first guest WLAN goes to every band's guest object; with no guest
//     WLAN in UniFi the Deco guest network is turned off, and with only guest
//     WLANs the Deco cannot carry (open, enterprise, ...) it is left unchanged;
//   - open, WEP, OWE and enterprise WLANs, mesh and element-adopt VAPs, and
//     features the Deco lacks are noted, not applied;
//   - nothing is planned that would turn the main network off on every band.
//
// Keys udeco does not manage keep their current values, and a plan whose
// managed keys already match cur is empty.
func PlanWLAN(cfg translate.Cfg, cur *WirelessInfo) WLANPlan {
	var p WLANPlan
	note := func(f string, a ...any) { p.Notes = append(p.Notes, fmt.Sprintf(f, a...)) }
	var nets []*wlanNet
	byName := map[string]*wlanNet{}
	all := translate.WLANs(cfg)
	guestSkipped := "" // a guest WLAN exists in UniFi but cannot be applied
	for _, w := range all {
		if w.Guest && guestSkipped == "" && !w.Mesh && !w.ElementAdopt &&
			(w.Band != "2g" && w.Band != "5g" || w.Encryption == "" || w.Encryption == "none") {
			guestSkipped = w.SSID
		}
		switch {
		case w.Mesh:
			note("wlan.%s %q: mesh/uplink VAP, skipped", w.Index, w.SSID)
			continue
		case w.ElementAdopt:
			note("wlan.%s %q: UniFi element-adopt SSID, skipped", w.Index, w.SSID)
			continue
		case w.Band != "2g" && w.Band != "5g":
			note("wlan.%s %q on %s: no such band on the Deco, skipped", w.Index, w.SSID, w.Radio)
			continue
		case w.Encryption == "":
			note("wlan.%s %q: %s: not applied", w.Index, w.SSID, w.EncNote)
			continue
		case w.Encryption == "none":
			note("wlan.%s %q: open network: not applied to the Deco", w.Index, w.SSID)
			continue
		}
		n := byName[w.SSID]
		if n == nil {
			n = &wlanNet{ssid: w.SSID, per: map[string]translate.WLAN{}}
			byName[w.SSID] = n
			nets = append(nets, n)
		}
		n.guest = n.guest || w.Guest
		if _, dup := n.per[w.Band]; dup {
			note("wlan.%s %q: a second VAP on %s, ignored", w.Index, w.SSID, w.Band)
			continue
		}
		n.per[w.Band] = w
	}
	if len(all) == 0 {
		note("no WLANs in system_cfg: nothing planned")
		return p
	}

	var main, guest *wlanNet
	var users []*wlanNet
	for _, n := range nets {
		if n.guest {
			if guest == nil {
				guest = n
			} else {
				note("guest WLAN %q skipped: the Deco has one guest network (using %q)", n.ssid, guest.ssid)
			}
			continue
		}
		users = append(users, n)
	}
	for _, pass := range []func(*wlanNet) bool{
		func(n *wlanNet) bool { return n.on("2g") && n.on("5g") },
		func(n *wlanNet) bool { return n.on("2g") || n.on("5g") },
		func(*wlanNet) bool { return true },
	} {
		for _, n := range users {
			if main == nil && pass(n) {
				main = n
			}
		}
	}
	bandOn := map[string]bool{}
	for _, n := range users {
		bandOn["2g"] = bandOn["2g"] || n.on("2g")
		bandOn["5g"] = bandOn["5g"] || n.on("5g")
		if n != main {
			note("WLAN %q skipped: the Deco has one main network (using %q); per-radio SSIDs are not applied", n.ssid, main.ssid)
		}
	}
	for _, n := range []*wlanNet{main, guest} {
		if n == nil {
			continue
		}
		if f := n.features(); len(f) > 0 {
			note("%q: %s not supported by the Deco: clamped", n.ssid, strings.Join(f, ", "))
		}
		if n.differs() {
			note("%q: settings differ per radio; the Deco keeps one set, using the %s one", n.ssid, n.ref().Band)
		}
	}
	if radioSettings(cfg) {
		note("radio channel, width and tx power are not applied: the Deco manages them mesh-wide")
	}
	if cur == nil {
		note("wireless info not read yet: nothing planned")
		return p
	}

	if main == nil {
		note("no usable main WLAN: host network unchanged")
	} else {
		p.planHost(cur, main, bandOn, note)
	}
	switch {
	case guest != nil:
		p.planGuest(cur, guest, note)
	case guestSkipped != "":
		// UniFi has a guest WLAN, just not one the Deco can carry: leave the
		// Deco guest network as it is rather than turn it off (design §8.2).
		note("guest WLAN %q cannot be applied: the Deco guest network is left unchanged", guestSkipped)
	case main != nil:
		p.planGuestOff(cur, note)
	}
	return p
}

func radioSettings(cfg translate.Cfg) bool {
	for k, v := range cfg {
		if strings.HasPrefix(k, "radio.") && (strings.HasSuffix(k, ".channel") && v != "auto" && v != "0" ||
			strings.HasSuffix(k, ".txpower") && v != "auto" && v != "") {
			return true
		}
	}
	return false
}

func (p *WLANPlan) planHost(cur *WirelessInfo, main *wlanNet, bandOn map[string]bool, note func(string, ...any)) {
	var base *WirelessHost
	for _, b := range []*WirelessBand{cur.Band2G4, cur.Band5G1, cur.Band5G2} {
		if b != nil && b.Host != nil {
			base = b.Host
			break
		}
	}
	if base == nil {
		note("no host network in the wireless info: main network not applied")
		return
	}
	ref := main.ref()
	h := *base
	h.Enable = nil
	ssid := B64(main.ssid)
	h.SSID = &ssid
	patch := bandPatch{SSID: &ssid}
	if ref.PSK != "" {
		pw := B64(ref.PSK)
		h.Password, patch.Password = &pw, &pw
	} else {
		note("%q: no passphrase in system_cfg: Deco password unchanged", main.ssid)
	}
	hide := ref.Hidden
	h.EnableHideSSID, patch.Hide = &hide, &hide
	wpa3 := ref.Encryption == "sae" || ref.Encryption == "sae-mixed"
	h.EnableWPA3, patch.WPA3 = &wpa3, &wpa3
	if ref.Encryption == "sae" {
		note("%q: WPA3-only in UniFi; enable_wpa3 may mean WPA2/WPA3 transition on the Deco (OPEN)", main.ssid)
	}
	body := BuildHostSet(cur, h)
	p.host = wifiPatch{kind: "host", bands: map[string]bandPatch{}}
	anyOn := false
	for _, s := range wirelessBands(body) {
		b := *s.b
		if b == nil {
			continue
		}
		on := bandOn[unifiBand(s.name)]
		if unifiBand(s.name) == "6g" {
			on = curEnable(bandNamed(cur, s.name), "host") // no 6 GHz radio in UniFi's view: keep
		}
		b.Host.Enable = &on
		bp := patch
		bp.Enable = &on
		p.host.bands[s.name] = bp
		anyOn = anyOn || on
	}
	if !anyOn {
		note("refusing to turn the main network off on every band")
		p.host = wifiPatch{}
		return
	}
	for _, s := range wirelessBands(body) {
		if *s.b != nil && unifiBand(s.name) != "6g" && !bandOn[unifiBand(s.name)] {
			note("%s: no enabled UniFi WLAN on %s: the Deco host network there is turned off", s.name, unifiBand(s.name))
		}
	}
	if ch := p.host.diff(cur); len(ch) > 0 {
		p.Host = body
		p.Changes = append(p.Changes, ch...)
	}
}

func (p *WLANPlan) planGuest(cur *WirelessInfo, guest *wlanNet, note func(string, ...any)) {
	base := baseGuest(cur)
	if base == nil {
		note("guest WLAN %q: no guest network object in the wireless info: not applied", guest.ssid)
		return
	}
	ref := guest.ref()
	g := *base
	on := guest.on("2g") || guest.on("5g")
	ssid := B64(guest.ssid)
	g.Enable, g.SSID = &on, &ssid
	patch := bandPatch{Enable: &on, SSID: &ssid}
	if ref.PSK != "" {
		pw := B64(ref.PSK)
		g.Password, patch.Password = &pw, &pw
	} else {
		note("guest %q: no passphrase in system_cfg: Deco guest password unchanged", guest.ssid)
	}
	wpa3 := ref.Encryption == "sae" || ref.Encryption == "sae-mixed"
	g.EnableWPA3, patch.WPA3 = &wpa3, &wpa3
	if ref.Hidden {
		note("guest %q: hidden SSID is not supported for the Deco guest network: clamped", guest.ssid)
	}
	if on && guest.on("2g") != guest.on("5g") {
		note("guest %q is on one radio only in UniFi; the Deco guest network spans every band", guest.ssid)
	}
	p.setGuest(cur, g, patch)
}

// planGuestOff turns the Deco guest network off when UniFi has none.
func (p *WLANPlan) planGuestOff(cur *WirelessInfo, note func(string, ...any)) {
	base := baseGuest(cur)
	if base == nil {
		return
	}
	g := *base
	off := false
	g.Enable = &off
	before := len(p.Changes)
	p.setGuest(cur, g, bandPatch{Enable: &off})
	if len(p.Changes) > before {
		note("no guest WLAN in UniFi: the Deco guest network is turned off")
	}
}

func (p *WLANPlan) setGuest(cur *WirelessInfo, g WirelessGuest, patch bandPatch) {
	body := BuildGuestSet(cur, g)
	p.guest = wifiPatch{kind: "guest", bands: map[string]bandPatch{}}
	for _, s := range wirelessBands(body) {
		if *s.b != nil {
			p.guest.bands[s.name] = patch
		}
	}
	if ch := p.guest.diff(cur); len(ch) > 0 {
		p.Guest = body
		p.Changes = append(p.Changes, ch...)
	}
}

func baseGuest(cur *WirelessInfo) *WirelessGuest {
	for _, b := range []*WirelessBand{cur.Band2G4, cur.Band5G1, cur.Band5G2} {
		if b != nil && b.Guest != nil {
			return b.Guest
		}
	}
	return nil
}

func curEnable(b *WirelessBand, kind string) bool {
	if b == nil {
		return false
	}
	if kind == "guest" {
		return b.Guest != nil && on(b.Guest.Enable)
	}
	return b.Host != nil && on(b.Host.Enable)
}

// fields reads the managed keys of one band's host or guest object.
func fields(b *WirelessBand, kind string) bandPatch {
	var f bandPatch
	if b == nil {
		return f
	}
	if kind == "guest" {
		if g := b.Guest; g != nil {
			f = bandPatch{Enable: g.Enable, WPA3: g.EnableWPA3, SSID: g.SSID, Password: g.Password}
		}
		return f
	}
	if h := b.Host; h != nil {
		f = bandPatch{Enable: h.Enable, Hide: h.EnableHideSSID, WPA3: h.EnableWPA3, SSID: h.SSID, Password: h.Password}
	}
	return f
}

// diff lists how cur differs from the patch on the patched keys only.
// Passphrases are masked.
func (w wifiPatch) diff(cur *WirelessInfo) []string {
	var names []string
	for n := range w.bands {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []string
	for _, name := range names {
		want := w.bands[name]
		have := fields(bandNamed(cur, name), w.kind)
		pre := name + "." + w.kind + "."
		boolKey := func(key string, want, have *bool) {
			if want != nil && *want != (have != nil && *have) {
				out = append(out, fmt.Sprintf("%s%s: %s -> %t", pre, key, fmtBool(have), *want))
			}
		}
		boolKey("enable", want.Enable, have.Enable)
		if want.SSID != nil && (have.SSID == nil || *have.SSID != *want.SSID) {
			out = append(out, fmt.Sprintf("%sssid: %q -> %q", pre, b64s(have.SSID), string(*want.SSID)))
		}
		if want.Password != nil && (have.Password == nil || *have.Password != *want.Password) {
			out = append(out, fmt.Sprintf("%spassword: %s -> %s", pre, translate.Mask(b64s(have.Password)), translate.Mask(string(*want.Password))))
		}
		boolKey("enable_hide_ssid", want.Hide, have.Hide)
		boolKey("enable_wpa3", want.WPA3, have.WPA3)
	}
	return out
}

func fmtBool(b *bool) string {
	if b == nil {
		return "unset"
	}
	return fmt.Sprint(*b)
}

// restore builds the Set that puts the patched bands back as backup has
// them, each band from its own object, and the patch that verifies it.
func (w wifiPatch) restore(backup *WirelessInfo) (*WirelessInfo, wifiPatch) {
	body := &WirelessInfo{}
	back := wifiPatch{kind: w.kind, bands: map[string]bandPatch{}}
	for _, s := range wirelessBands(body) {
		want, ok := w.bands[s.name]
		b := bandNamed(backup, s.name)
		if !ok || b == nil {
			continue
		}
		have := fields(b, w.kind)
		var bp bandPatch
		if want.Enable != nil {
			bp.Enable = boolOr(have.Enable)
		}
		if want.Hide != nil {
			bp.Hide = boolOr(have.Hide)
		}
		if want.WPA3 != nil {
			bp.WPA3 = boolOr(have.WPA3)
		}
		if want.SSID != nil {
			bp.SSID = have.SSID
		}
		if want.Password != nil {
			bp.Password = have.Password
		}
		if w.kind == "guest" && b.Guest != nil {
			g := *b.Guest
			*s.b = &WirelessBand{Guest: &g}
		} else if w.kind == "host" && b.Host != nil {
			h := *b.Host
			*s.b = &WirelessBand{Host: &h}
		} else {
			continue
		}
		back.bands[s.name] = bp
	}
	if backup.Band60G != nil && body.Band5G1 != nil {
		body.Band60G = &WirelessBand{Host: body.Band5G1.Host, Guest: body.Band5G1.Guest}
	}
	if len(back.bands) == 0 {
		return nil, back
	}
	return body, back
}

func boolOr(b *bool) *bool {
	v := b != nil && *b
	return &v
}

// ---- apply engine ----

// WLAN apply defaults (design §8.4).
const (
	WLANDebounce      = 10 * time.Second
	WLANVerifyWindow  = 3 * time.Minute
	WLANRollbackEvery = 30 * time.Second
	WLANRollbackFor   = 30 * time.Minute
	WLANMinInterval   = 5 * time.Minute
	wlanReadTimeout   = 2 * time.Minute
	wlanRepoll        = 30 * time.Second
)

// ErrApplyLatched: a rollback happened; Wi-Fi apply stays off until restart.
var ErrApplyLatched = errors.New("deco wlan: apply latched off after a rollback")

// meshPort is what the applier needs from the Mesh.
type meshPort interface {
	Snapshot() MeshState
	Submit(Command) <-chan CommandResult
	RequestPoll(op uint16)
}

// WLANConfig configures a WLANApplier. Durations left zero take the defaults.
type WLANConfig struct {
	// Apply sends Sets. False (the default) logs plans only.
	Apply bool
	// BackupDir receives wireless-<ts>.json (mode 0600: it holds PSKs)
	// before every apply. Required for apply.
	BackupDir string
	// Units are the configured unit MACs; those online before an apply must
	// be back and online for it to verify.
	Units []string

	Debounce, VerifyWindow, RollbackEvery, RollbackFor, MinInterval time.Duration

	Logf func(format string, args ...any)
}

type wlanPhase int

const (
	phaseIdle wlanPhase = iota
	phaseRead
	phaseSend
	phaseVerify
	phaseRollback
)

type wlanSet struct {
	body  *WirelessInfo
	patch wifiPatch
}

// WLANApplier debounces Wi-Fi plans from the runners and applies them
// through the Mesh with backup, verify and rollback, off the inform path.
// Drive it with Run (or Step in tests).
type WLANApplier struct {
	cfg  WLANConfig
	mesh meshPort
	now  func() time.Time
	wake chan struct{}

	mu      sync.Mutex
	pending translate.Cfg
	pendAt  time.Time
	latched bool

	// Owned by the Run goroutine.
	phase     wlanPhase
	cfgNow    translate.Cfg
	since     time.Time // phase start
	waitLog   bool
	lastApply time.Time
	backup    *WirelessInfo
	expect    []string // unit MACs that must come back
	sets      []wlanSet
	sent      []wlanSet
	inflight  <-chan CommandResult
	sentAt    time.Time
	lastPoll  time.Time
	rbBodies  []wlanSet
	rbWait    []<-chan CommandResult
	rbOK      bool
	rbSentAt  time.Time
	rbNext    time.Time
}

// NewWLANApplier returns an applier writing through mesh (normally a *Mesh).
func NewWLANApplier(cfg WLANConfig, mesh meshPort) *WLANApplier {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&cfg.Debounce, WLANDebounce)
	def(&cfg.VerifyWindow, WLANVerifyWindow)
	def(&cfg.RollbackEvery, WLANRollbackEvery)
	def(&cfg.RollbackFor, WLANRollbackFor)
	def(&cfg.MinInterval, WLANMinInterval)
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	return &WLANApplier{cfg: cfg, mesh: mesh, now: time.Now, wake: make(chan struct{}, 1)}
}

// Latched reports whether apply was turned off by a rollback.
func (a *WLANApplier) Latched() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.latched
}

// Submit hands the applier the system_cfg a runner received. The plan
// against the cached wireless info is logged (masked). Only the owner
// (the master's runner) with apply on queues it; the latest submission wins
// and is applied after the debounce. Safe from any goroutine.
func (a *WLANApplier) Submit(unit string, owner bool, cfg translate.Cfg) {
	s := a.mesh.Snapshot()
	p := PlanWLAN(cfg, s.Wireless.Value)
	why := ""
	switch {
	case !owner:
		why = "not the config owner: log only"
	case !a.cfg.Apply:
		why = "apply=false: log only"
	case a.Latched():
		why = "apply latched off after a rollback: log only"
	}
	a.cfg.Logf("deco wlan [%s]: plan from system_cfg (%s): %s", unit, orStr(why, "queued"), p.String())
	if why != "" {
		return
	}
	a.mu.Lock()
	a.pending, a.pendAt = cfg, a.now()
	a.mu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Run drives the applier until ctx ends.
func (a *WLANApplier) Run(ctx context.Context) error {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		a.Step()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		case <-a.wake:
		}
	}
}

// Step advances the apply state machine once.
func (a *WLANApplier) Step() {
	now := a.now()
	switch a.phase {
	case phaseIdle:
		a.stepIdle(now)
	case phaseRead:
		a.stepRead(now)
	case phaseSend:
		a.stepSend(now)
	case phaseVerify:
		a.stepVerify(now)
	case phaseRollback:
		a.stepRollback(now)
	}
}

func (a *WLANApplier) logf(f string, args ...any) { a.cfg.Logf("deco wlan: "+f, args...) }

func (a *WLANApplier) stepIdle(now time.Time) {
	a.mu.Lock()
	cfg, at, latched := a.pending, a.pendAt, a.latched
	if cfg == nil || now.Sub(at) < a.cfg.Debounce {
		a.mu.Unlock()
		return
	}
	if latched {
		a.pending = nil
		a.mu.Unlock()
		a.logf("apply latched off after a rollback: plan dropped")
		return
	}
	if !a.lastApply.IsZero() && now.Sub(a.lastApply) < a.cfg.MinInterval {
		a.mu.Unlock()
		if !a.waitLog {
			a.waitLog = true
			a.logf("rate-limited: next apply after %s", a.lastApply.Add(a.cfg.MinInterval).Format(time.RFC3339))
		}
		return
	}
	a.pending = nil
	a.mu.Unlock()
	a.waitLog = false
	a.cfgNow, a.phase, a.since = cfg, phaseRead, now
	// Diff against a fresh 0x4009 and device list (design §8.4.1).
	a.mesh.RequestPoll(OpGetWireless)
	a.mesh.RequestPoll(OpGetDeviceList)
}

func (a *WLANApplier) toIdle() {
	a.phase, a.cfgNow, a.sets, a.sent, a.inflight = phaseIdle, nil, nil, nil, nil
	a.rbBodies, a.rbWait, a.rbOK = nil, nil, false
}

func (a *WLANApplier) stepRead(now time.Time) {
	s := a.mesh.Snapshot()
	if !s.Wireless.OK || s.Wireless.Value == nil || s.Wireless.At.Before(a.since) {
		if now.Sub(a.since) > wlanReadTimeout {
			a.logf("no fresh wireless info within %s: apply skipped", wlanReadTimeout)
			a.toIdle()
		}
		return
	}
	p := PlanWLAN(a.cfgNow, s.Wireless.Value)
	if p.Empty() {
		a.logf("Deco already matches UniFi: nothing to apply%s", notesSuffix(p.Notes))
		a.toIdle()
		return
	}
	if err := masterOK(&s); err != nil {
		a.logf("apply refused: %v", err)
		a.toIdle()
		return
	}
	path, err := a.writeBackup(s.Wireless.Value, now)
	if err != nil {
		a.logf("apply refused: backup failed: %v", err)
		a.toIdle()
		return
	}
	a.backup = s.Wireless.Value
	a.expect = nil
	for _, u := range a.cfg.Units {
		if UnitOnline(FindUnit(&s, u)) {
			a.expect = append(a.expect, NormMAC(u))
		}
	}
	a.sets = nil
	if p.Host != nil {
		a.sets = append(a.sets, wlanSet{p.Host, p.host})
	}
	if p.Guest != nil {
		a.sets = append(a.sets, wlanSet{p.Guest, p.guest})
	}
	a.logf("applying (backup %s): %s", path, p.String())
	a.phase, a.since, a.sent = phaseSend, now, nil
	a.sendNext()
}

func notesSuffix(n []string) string {
	if len(n) == 0 {
		return ""
	}
	return "; notes: " + strings.Join(n, "; ")
}

// masterOK: a write needs the device list to agree with the configured
// master; the Mesh checks it again before sending (design §3.3).
func masterOK(s *MeshState) error {
	if !s.Connected {
		return errors.New("no session to the master")
	}
	if s.Devices.Value == nil {
		return errors.New("device_list not read")
	}
	return nil
}

func (a *WLANApplier) writeBackup(w *WirelessInfo, now time.Time) (string, error) {
	if a.cfg.BackupDir == "" {
		return "", errors.New("no backup directory configured")
	}
	if err := os.MkdirAll(a.cfg.BackupDir, 0o700); err != nil {
		return "", err
	}
	b, err := json.Marshal(w)
	if err != nil {
		return "", err
	}
	p := filepath.Join(a.cfg.BackupDir, "wireless-"+now.UTC().Format("20060102T150405.000Z")+".json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return "", err
	}
	return p, nil
}

func (a *WLANApplier) sendNext() {
	set := a.sets[0]
	// Exempt from the Mesh's per-Set rate limit: the applier limits applies
	// itself, and a guest Set follows the host Set of the same apply.
	a.inflight = a.mesh.Submit(Command{Kind: CmdSetWireless, Wireless: set.body, SkipRateLimit: true})
}

// notSent: errors that mean the Mesh did not put the Set on the wire.
func notSent(r CommandResult) bool {
	return r.DryRun || errors.Is(r.Err, ErrOwnerMismatch) || errors.Is(r.Err, ErrRateLimited) ||
		errors.Is(r.Err, ErrLatched) || errors.Is(r.Err, ErrStopped) || errors.Is(r.Err, ErrNotConnected)
}

func (a *WLANApplier) stepSend(now time.Time) {
	var r CommandResult
	select {
	case r = <-a.inflight:
	default:
		return
	}
	set := a.sets[0]
	switch {
	case r.Err == nil && !r.DryRun:
		a.sent = append(a.sent, set)
		a.sets = a.sets[1:]
		a.lastApply = now
		if len(a.sets) > 0 {
			a.sendNext()
			return
		}
		a.phase, a.sentAt, a.since, a.lastPoll = phaseVerify, now, now, now
		a.mesh.RequestPoll(OpGetWireless)
		a.mesh.RequestPoll(OpGetDeviceList)
		a.logf("Set accepted; verifying for up to %s", a.cfg.VerifyWindow)
	case notSent(r) && len(a.sent) == 0:
		why := "mesh apply=false"
		if r.Err != nil {
			why = r.Err.Error()
		}
		a.logf("apply not sent: %s", why)
		a.toIdle()
	default:
		// The device may hold part of the change: restore the backup.
		a.lastApply = now
		a.sent = append(a.sent, set)
		why := "mesh apply=false"
		if r.Err != nil {
			why = r.Err.Error()
		}
		a.logf("Set failed (%s): rolling back", why)
		a.startRollback(now)
	}
}

func (a *WLANApplier) stepVerify(now time.Time) {
	s := a.mesh.Snapshot()
	problem := a.verify(&s)
	if problem == "" {
		a.logf("apply verified: wireless info shows the change and every unit is back")
		a.toIdle()
		return
	}
	if now.Sub(a.since) >= a.cfg.VerifyWindow {
		a.logf("apply NOT verified within %s (%s): rolling back", a.cfg.VerifyWindow, problem)
		a.startRollback(now)
		return
	}
	if now.Sub(a.lastPoll) >= wlanRepoll {
		a.lastPoll = now
		a.mesh.RequestPoll(OpGetWireless)
	}
}

// verify returns "" when the apply holds (design §8.4.4), else what is missing.
func (a *WLANApplier) verify(s *MeshState) string {
	switch {
	case !s.Connected:
		return "no session to the master"
	case !s.Wireless.OK || s.Wireless.Value == nil || !s.Wireless.At.After(a.sentAt):
		return "no wireless info read since the Set"
	case !s.Devices.OK || s.Devices.Value == nil || !s.Devices.At.After(a.sentAt):
		return "no device list read since the Set"
	}
	for _, set := range a.sent {
		if d := set.patch.diff(s.Wireless.Value); len(d) > 0 {
			return "wireless info still differs: " + strings.Join(d, "; ")
		}
	}
	for _, u := range a.expect {
		if !UnitOnline(FindUnit(s, u)) {
			return "unit " + u + " not back online"
		}
	}
	return ""
}

func (a *WLANApplier) startRollback(now time.Time) {
	a.rbBodies = nil
	for _, set := range a.sent {
		if body, patch := set.patch.restore(a.backup); body != nil {
			a.rbBodies = append(a.rbBodies, wlanSet{body, patch})
		}
	}
	a.phase, a.since, a.rbNext, a.rbOK, a.rbWait = phaseRollback, now, now, false, nil
	a.stepRollback(now)
}

func (a *WLANApplier) latch(msg string) {
	a.mu.Lock()
	a.latched, a.pending = true, nil
	a.mu.Unlock()
	a.logf("%s; Wi-Fi apply LATCHED OFF until restart", msg)
	a.toIdle()
}

func (a *WLANApplier) stepRollback(now time.Time) {
	if len(a.rbBodies) == 0 {
		a.latch("ROLLBACK impossible: no backup of the changed bands")
		return
	}
	if len(a.rbWait) > 0 {
		var left []<-chan CommandResult
		failed := false
		for _, ch := range a.rbWait {
			select {
			case r := <-ch:
				if r.Err != nil || r.DryRun {
					failed = true
					a.logf("rollback Set failed: %v", r.Err)
				}
			default:
				left = append(left, ch)
			}
		}
		a.rbWait = left
		if failed {
			a.rbOK = false
		}
		if len(left) == 0 && !failed && !a.rbOK {
			a.rbOK, a.rbSentAt, a.lastPoll = true, now, now
			a.mesh.RequestPoll(OpGetWireless)
		}
	}
	if a.rbOK {
		s := a.mesh.Snapshot()
		if s.Wireless.OK && s.Wireless.Value != nil && s.Wireless.At.After(a.rbSentAt) {
			ok := true
			for _, set := range a.rbBodies {
				if len(set.patch.diff(s.Wireless.Value)) > 0 {
					ok = false
				}
			}
			if ok {
				a.latch("ROLLED BACK to the pre-apply Wi-Fi settings")
				return
			}
			a.rbOK = false // re-read still differs: send again on the next tick
		} else if now.Sub(a.lastPoll) >= wlanRepoll {
			a.lastPoll = now
			a.mesh.RequestPoll(OpGetWireless)
		}
	}
	if now.Sub(a.since) >= a.cfg.RollbackFor {
		a.latch(fmt.Sprintf("ROLLBACK FAILED for %s: check the Deco Wi-Fi settings by hand", a.cfg.RollbackFor))
		return
	}
	if len(a.rbWait) == 0 && !a.rbOK && !now.Before(a.rbNext) {
		a.rbNext = now.Add(a.cfg.RollbackEvery)
		for _, set := range a.rbBodies {
			js, _ := json.Marshal(set.body)
			a.logf("rollback Set 0x%04x: %s", OpSetWireless, RedactJSON(js))
			a.rbWait = append(a.rbWait, a.mesh.Submit(Command{Kind: CmdSetWireless, Wireless: set.body, SkipRateLimit: true}))
		}
	}
}
