// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

// Runner executes commands on the device.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Options configures an Applier.
type Options struct {
	Root     string // "/" on the device
	Run      Runner
	StateDir string // last-good.json (0600, holds passphrases)
	RunDir   string // ramfs: the vendor baseline of this boot, the owned marker
	Bridge   string // the LAN bridge (bdg2)
	Uplink   string // the uplink bridge port (eth0.4.1); VLAN devices go on its parent
	DryRun   bool
	WPA3     bool // serve SAE where the driver has it (5 GHz); the agent claims WPA3 on that radio only
	Logf     func(string, ...any)
	Layout   []RadioDef // nil = JCOW414
	// KeepSSID is the SSID kept up while the uplink is down
	// (uplinkloss.go); "" = the first LAN SSID
	KeepSSID string
	// DFS lets the 5 GHz radio (RadioDef.HSFlag: the MT7663) serve 52-64
	// (dfs.go)
	DFS bool
	// PinSlots keeps each WLAN on its profile slot (netdev, BSSID) while
	// others come and go (slots.go); off = the controller's order
	PinSlots bool
	// ProxyARP serves the controller's proxy ARP (proxyarp.go); off = the
	// requests go out on the air as without it
	ProxyARP bool
	// ProxyARPDriver lets the MT7663 drop the requests itself (hs_flag=3,
	// with the 0x93b events to the responder) instead of the agent-side
	// path; off by default (garage-final proxyarp: with no responder the
	// flag black-holes inbound ARP to the BSS)
	ProxyARPDriver bool
	// sendFrame sends one Ethernet frame on a netdev (nil: an AF_PACKET
	// socket; tests record them)
	sendFrame func(dev string, frame []byte) error
	// VerifyTimeout bounds the wait for the BSSes after an apply (20 s).
	VerifyTimeout time.Duration
	// Settle: how long after a radio restart the collector's driver reads
	// stay off (20 s; restartgate.go).
	Settle time.Duration
	sleep  func(context.Context, time.Duration) error
	// mono is a monotonic clock (time since an arbitrary start, > 0): the
	// settle time of radio restarts runs on it, never on the wall clock
	mono     func() time.Duration
	writeLED func(path, s string) error // one LED table row (tests record them)
}

// Applier implements the agent's Wi-Fi applier on the MediaTek driver.
type Applier struct {
	o    Options
	mu   sync.Mutex
	live map[string]RadioPlan // what this process applied or found live
	// adopted: the radios Plan found serving what this build writes,
	// before this process applied anything (adopt); Apply starts from them
	adopted map[string]RadioPlan
	blocked []string
	failed  string // hash of the last Desired that failed to apply
	uplink  string
	// station ACLs: the SSIDs' MAC filters (UniFi's Lock to AP arrives as
	// lock2ap deny entries on every other AP) folded with the block list.
	desired bcmwifi.Desired     // the last Desired planned (its MAC filters)
	acl     map[string]ifaceACL // by BSS netdev: what was last written
	// portVLANs: the VLAN bridges the LAN ports use (internal/jioports,
	// SetPortVLANs); cleanVLANs keeps them
	portVLANs map[int]bool
	// status LED (led.go), under its own lock so it never waits for an apply
	ledMu    sync.Mutex
	ledOn    bool // led_enabled; the controller's last word
	locating bool
	// the collector's driver reads against radio restarts (restartgate.go):
	// gate's write side is held through Apply and Rollback; quietUntil
	// (Options.mono, ns) is the end of the last restart's settle time
	gate       sync.RWMutex
	quietUntil atomic.Int64
	onChange   atomic.Pointer[func(context.Context)] // OnChange
	// live settings waiting for a restart's settle time to end, by band
	// (live.go): the per-BSS ones, and the power
	due, txDue map[string]bool
	// weak: per station, the minimum RSSI kick's count and back-off
	// (minrssi.go)
	weak map[string]*weakSta
	// uplinkDown: the uplink is down and the SSIDs are isolated
	// (uplinkloss.go); want: the controller's plan a.live is made from
	// (a.live is its isolated form meanwhile)
	uplinkDown bool
	want       map[string]RadioPlan
	// pins: WLAN id -> profile slot per band (slots.go)
	pins map[string]map[string]int
	// proxy ARP (proxyarp.go): the responder, the event listener's health,
	// the 5 GHz flags sent (per netdev; absent = unknown), the 2.4 GHz
	// drop rules' vifs and state
	parp      parpResponder
	eventsOK  func() bool
	parpFlag  map[string]bool
	parpJumps []string
	parpEb    string
	// dfs: the 5 GHz region, the DFS channel, NOPs, radar (dfs.go)
	dfs dfsState
}

const (
	ownedFile    = "mtk-owned"       // RunDir: the agent's profiles are installed
	appliedFile  = "mtk-applied"     // RunDir: hash of the plans live now
	txModeFile   = "mtk-txmode.json" // RunDir: the controller's power mode per band (collector.go radioTx)
	aclFile      = "mtk-acl.json"    // RunDir: the station ACLs last written (lost with the driver's at reboot)
	baselineDir  = "mtk-baseline"
	lastGoodFile = "last-good.json"
	// lastGoodDesired: the Desired last-good came from (its guest policy
	// and ACLs; a rollback must not take them from the failed Desired)
	lastGoodDesired = "last-good-desired.json"
)

// New returns an Applier; nothing changes until Apply.
func New(o Options) *Applier {
	if o.Root == "" {
		o.Root = "/"
	}
	if o.Bridge == "" {
		o.Bridge = "bdg2"
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Layout == nil {
		o.Layout = JCOW414
	}
	if o.DFS {
		l := append([]RadioDef(nil), o.Layout...)
		for i := range l {
			l[i].DFS = l[i].HSFlag // the MT7663
		}
		o.Layout = l
	}
	if o.VerifyTimeout <= 0 {
		o.VerifyTimeout = 20 * time.Second
	}
	if o.Settle <= 0 {
		o.Settle = defaultSettle
	}
	if o.mono == nil {
		o.mono = monoSince(time.Now())
	}
	if o.sleep == nil {
		o.sleep = func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		}
	}
	if o.writeLED == nil {
		o.writeLED = writeProc
	}
	if o.sendFrame == nil {
		o.sendFrame = sendFrame
	}
	a := &Applier{o: o, uplink: o.Uplink, ledOn: true}
	if o.ProxyARP && !o.DryRun {
		a.parp = newResponder(o.Logf, func() { a.ProxyARPDown(context.Background()) })
	}
	return a
}

func (a *Applier) dev(p string) string { return filepath.Join(a.o.Root, p) }

// OnChange has f called, with the caller's context, before each command
// that changes the unit (ifconfig, iwpriv set, brctl, ip: everything run
// goes through; the reads, iwconfig and sysfs, do not). The agent marks
// its alive record from it.
func (a *Applier) OnChange(f func(context.Context)) { a.onChange.Store(&f) }

func (a *Applier) run(ctx context.Context, name string, args ...string) error {
	if a.o.DryRun {
		a.o.Logf("mtkwifi: dry run: %s %s", name, strings.Join(redactArgs(args), " "))
		return nil
	}
	if f := a.onChange.Load(); f != nil {
		(*f)(ctx)
	}
	out, err := a.o.Run.Run(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("%s %s: %v %s", name, strings.Join(redactArgs(args), " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func redactArgs(args []string) []string {
	out := append([]string(nil), args...)
	for i, s := range out {
		if strings.HasPrefix(s, "WPAPSK") {
			out[i] = "WPAPSK=<secret>"
		}
	}
	return out
}

func plansHash(ps map[string]RadioPlan) string {
	j, _ := json.Marshal(ps)
	h := sha256.Sum256(j)
	return hex.EncodeToString(h[:])
}

// Owned reports whether the agent's profiles are installed (the agent uses
// it to tell a rollback that handed Wi-Fi back from one that did not).
func (a *Applier) Owned() bool {
	_, err := os.Stat(a.dev(filepath.Join(a.o.RunDir, ownedFile)))
	return err == nil
}

// Plan compares d with what is live. A plan whose hash matches what this
// boot applied last (an agent restart) is empty when the radios still
// look like it: nothing is restarted. With another hash (another build),
// each radio whose installed profile is the one this build writes, and
// that serves it, is kept (adopt). A radio is restarted only when what a
// restart makes live changes (change).
func (a *Applier) Plan(ctx context.Context, d bcmwifi.Desired) (bcmwifi.Plan, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	full, notes := plans(d, a.o.Layout, a.o.WPA3)
	if a.o.ProxyARP {
		notes = slices.DeleteFunc(notes, func(n string) bool { return strings.HasSuffix(n, "proxy ARP not applied") })
	}
	full, _ = a.pinned(full)
	want := a.effective(full)
	p := bcmwifi.Plan{Desired: d, Notes: notes}
	cur := a.live
	if cur == nil {
		if h, err := os.ReadFile(a.dev(filepath.Join(a.o.RunDir, appliedFile))); err == nil &&
			strings.TrimSpace(string(h)) == plansHash(want) && a.check(ctx, want, true) == nil {
			a.live, a.want = want, full
			a.desired = d
			a.planACL(&p, want)
			return p, nil
		}
		// another build's plan (its hash differs): the radios that serve
		// what this one writes are kept as they are
		cur = a.adopt(ctx, want)
		a.adopted = cur
		if len(cur) == len(a.o.Layout) {
			a.live, a.adopted, a.want = cur, nil, full
			a.desired = d
			a.planACL(&p, want)
			return p, nil
		}
	}
	for _, rd := range a.o.Layout {
		w := want[rd.Band]
		c, ok := cur[rd.Band]
		switch ch := a.change(rd, c, ok, w); {
		case ch == radioKeep:
		case ch == radioLive:
			p.Steps = append(p.Steps, bcmwifi.Step{Kind: bcmwifi.StepCmd,
				Desc: fmt.Sprintf("%s: hidden/isolation/client limits live (iwpriv)", rd.Band)})
		case !w.On:
			p.Steps = append(p.Steps, bcmwifi.Step{Kind: bcmwifi.StepCmd, Desc: rd.Band + ": radio off"})
		default:
			var names []string
			for _, b := range w.BSS {
				names = append(names, strconv.Quote(b.SSID))
			}
			p.Steps = append(p.Steps, bcmwifi.Step{Kind: bcmwifi.StepCmd,
				Desc: fmt.Sprintf("%s: profile and restart (ch %s, %d MHz, %d%% power): %s", rd.Band,
					chanText(w.Channel), w.Width, w.TxPct, strings.Join(names, ", "))})
		}
	}
	a.desired = d
	a.planACL(&p, want)
	return p, nil
}

// radioChange is what one radio needs to go from what it serves to a plan.
type radioChange int

const (
	radioKeep    radioChange = iota // nothing
	radioLive                       // iwpriv and the profile, no restart (applyLive)
	radioRestart                    // profile and restart, or off (applyRadio)
)

// change says what radio rd needs to go from c (ok: c is what it serves)
// to w. A restart only when what a restart makes live differs
// (restartKey): a plan difference the written profile does not show (a
// setting equal to the vendor's) is no reason to drop the radio's clients.
func (a *Applier) change(rd RadioDef, c RadioPlan, ok bool, w RadioPlan) radioChange {
	switch {
	case !ok:
		return radioRestart
	case c.hash() == w.hash(), !c.On && !w.On:
		return radioKeep
	}
	if base, err := a.baseline(rd); err == nil {
		if restartKey(base, rd, c) == restartKey(base, rd, w) || a.dfsLive(base, rd, c, w) {
			return radioLive
		}
		return radioRestart
	}
	if c.structural() == w.structural() {
		return radioLive
	}
	return radioRestart
}

// baseline is the vendor's profile of rd captured this boot.
func (a *Applier) baseline(rd RadioDef) ([]byte, error) {
	return os.ReadFile(a.dev(filepath.Join(a.o.RunDir, baselineDir, rd.Band+".dat")))
}

// adopt returns the radios that already serve want although this process
// has applied nothing: the agent's last apply of this boot finished
// (mtk-applied; it may be another build's, whose plan JSON and so hash
// differ), the radio's installed profile is byte for byte the one this
// build writes for want, and its netdevs serve want (up, SSIDs, bridges).
// A radio off in want needs only its netdevs down. Restarting such a radio
// would change nothing but drop its clients (a new build deployed with the
// controller's settings unchanged).
func (a *Applier) adopt(ctx context.Context, want map[string]RadioPlan) map[string]RadioPlan {
	if _, err := os.Stat(a.dev(filepath.Join(a.o.RunDir, appliedFile))); err != nil || !a.Owned() {
		return nil
	}
	out := map[string]RadioPlan{}
	for _, rd := range a.o.Layout {
		w := want[rd.Band]
		if w.On {
			base, err := a.baseline(rd)
			if err != nil {
				continue
			}
			if cur, err := os.ReadFile(a.dev(rd.Dat)); err != nil || !bytes.Equal(cur, profile(base, rd, w)) {
				continue
			}
		}
		if err := a.checkRadio(ctx, rd, w, true); err != nil {
			continue
		}
		a.o.Logf("mtkwifi: %s already serves this plan (another build applied it): not restarted", rd.Band)
		out[rd.Band] = w
	}
	return out
}

// planACL adds a step when the station ACLs want differ from what was last
// written (a lock, an unlock, a MAC filter edit): Apply then rewrites them
// in place, with no radio restart.
func (a *Applier) planACL(p *bcmwifi.Plan, want map[string]RadioPlan) {
	if a.acl == nil {
		// an agent restart: the driver still holds what the last run wrote
		if b, err := os.ReadFile(a.dev(filepath.Join(a.o.RunDir, aclFile))); err == nil {
			_ = json.Unmarshal(b, &a.acl)
		}
	}
	if w := wantACLs(a.desired, want, a.o.Layout, a.blocked); !sameACLs(w, a.acl) {
		p.Steps = append(p.Steps, bcmwifi.Step{Kind: bcmwifi.StepCmd,
			Desc: "station ACLs (MAC filters, Lock to AP, blocks) live (iwpriv)"})
	}
}

func chanText(c int) string {
	if c == 0 {
		return "auto"
	}
	return strconv.Itoa(c)
}

// Apply makes p live. A failure rolls back to last-good (else to the
// vendor's Wi-Fi of this boot) and the same Desired is not retried.
func (a *Applier) Apply(ctx context.Context, p bcmwifi.Plan) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	full, _ := plans(p.Desired, a.o.Layout, a.o.WPA3)
	full, pins := a.pinned(full)
	want := a.effective(full)
	h := plansHash(full)
	if h == a.failed {
		return bcmwifi.ErrDesiredFailed
	}
	if a.o.DryRun {
		a.o.Logf("mtkwifi: dry run: %d step(s) not applied", len(p.Steps))
		return nil
	}
	defer a.changingRadios()() // no driver reads by the collector meanwhile
	if err := a.captureBaseline(ctx); err != nil {
		return fmt.Errorf("%w: %v", bcmwifi.ErrNoBaseline, err)
	}
	cur := a.live
	if cur == nil {
		cur = a.adopted // what Plan found already live
	}
	a.adopted = nil
	a.desired = p.Desired
	err := a.applyPlans(ctx, want, cur)
	if err == nil {
		err = a.waitLive(ctx, want)
	}
	if err != nil {
		a.failed = h
		a.o.Logf("mtkwifi: apply failed: %v: rolling back", err)
		if rerr := a.rollback(ctx); rerr != nil {
			return fmt.Errorf("%v; rollback: %v", err, rerr)
		}
		return err
	}
	a.live, a.want = want, full
	a.savePins(pins)
	a.saveLastGood(full, p.Desired)
	a.flushLive(ctx)
	a.dfsStep(ctx)
	a.syncProxyARP(ctx)
	return nil
}

func (a *Applier) applyPlans(ctx context.Context, want, cur map[string]RadioPlan) error {
	if err := os.WriteFile(a.dev(filepath.Join(a.o.RunDir, ownedFile)), []byte("1\n"), 0o644); err != nil {
		return err
	}
	_ = os.Remove(a.dev(filepath.Join(a.o.RunDir, appliedFile)))
	// guest chains before any guest SSID comes up (guest.go)
	if err := a.syncGuest(ctx, &a.desired, want, false); err != nil {
		return fmt.Errorf("guest isolation: %w", err)
	}
	for _, rd := range a.o.Layout {
		w := want[rd.Band]
		c, ok := cur[rd.Band]
		var err error
		switch a.change(rd, c, ok, w) {
		case radioKeep:
			continue
		case radioLive:
			err = a.applyLive(ctx, rd, c, w)
		default:
			err = a.applyRadio(ctx, rd, w)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", rd.Band, err)
		}
	}
	if err := a.syncGuest(ctx, &a.desired, want, true); err != nil {
		return fmt.Errorf("guest isolation: %w", err)
	}
	if err := a.cleanVLANs(ctx, want); err != nil {
		a.o.Logf("mtkwifi: removing unused VLAN bridges: %v", err)
	}
	if err := a.applyACL(ctx, want); err != nil {
		a.o.Logf("mtkwifi: station ACLs: %v", err)
	}
	writeTxModes(a.dev(a.o.RunDir), want)
	return os.WriteFile(a.dev(filepath.Join(a.o.RunDir, appliedFile)), []byte(plansHash(want)+"\n"), 0o644)
}

// applyRadio writes the radio's profile and restarts its BSSes (every
// client of the radio reassociates).
func (a *Applier) applyRadio(ctx context.Context, rd RadioDef, rp RadioPlan) error {
	base, err := a.baseline(rd)
	if err != nil {
		return fmt.Errorf("baseline profile: %w", err)
	}
	defer a.restarted() // the collector leaves the driver alone a while longer
	a.parpRestarted(rd)
	for i := len(rd.Ifaces) - 1; i >= 0; i-- {
		if err := a.run(ctx, "ifconfig", rd.Ifaces[i], "down"); err != nil {
			return err
		}
	}
	if !rp.On {
		a.o.Logf("mtkwifi: %s: radio off", rd.Band)
		return nil
	}
	pw := a.dfsProfilePlan(rd, rp)
	if err := writeFile(a.dev(rd.Dat), profile(base, rd, pw), 0o600); err != nil {
		return err
	}
	if rd.DFS && isDFS(pw.Channel) {
		defer a.quietFor(dfsQuiet) // the CAC after the restart
	}
	// slot 0 first: the radio's first BSS netdev up reads the profile
	order := make([]int, len(rp.BSS))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(x, y int) bool { return rp.slot(order[x]) < rp.slot(order[y]) })
	for _, i := range order {
		if err := a.run(ctx, "ifconfig", a.ifaceOf(rd, rp, i), "up"); err != nil {
			return err
		}
	}
	for i, b := range rp.BSS {
		if err := a.bridgeTo(ctx, a.ifaceOf(rd, rp, i), b.VLAN); err != nil {
			return err
		}
	}
	a.o.Logf("mtkwifi: %s: %d SSID(s) up (ch %s, %d MHz)", rd.Band, len(rp.BSS), chanText(rp.Channel), rp.Width)
	// the per-BSS live settings, after the settle time (live.go); the
	// power came from the profile
	a.queueLive(rd.Band, false)
	return nil
}

// applyLive sets the live settings of each BSS that changed from c and
// keeps the profile in step (a later restart re-reads it).
func (a *Applier) applyLive(ctx context.Context, rd RadioDef, c, rp RadioPlan) error {
	for i, b := range rp.BSS {
		if i < len(c.BSS) && c.BSS[i].Hidden == b.Hidden && c.BSS[i].Isolate == b.Isolate && c.BSS[i].MaxSta == b.MaxSta {
			continue
		}
		ifc := a.ifaceOf(rd, rp, i)
		for _, kv := range []string{"HideSSID=" + b01(b.Hidden), "NoForwarding=" + b01(b.Isolate), "MaxStaNum=" + strconv.Itoa(b.MaxSta)} {
			if err := a.run(ctx, "iwpriv", ifc, "set", kv); err != nil {
				return err
			}
		}
	}
	if c.TxPct != rp.TxPct || c.MinRSSI != rp.MinRSSI {
		a.queueLive(rd.Band, c.TxPct != rp.TxPct)
	}
	// a channel move into or out of 52-64 is dfsStep's, after the apply
	return a.writeProfile(rd, rp)
}

func writeFile(p string, b []byte, mode os.FileMode) error {
	tmp := p + ".udeco"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ------------------------------------------------------------- bridging

func vlanBridge(vid int) string { return "br-v" + strconv.Itoa(vid) }

// vlanParent is the switch port device of the uplink: eth0.4 for eth0.4.1.
func (a *Applier) vlanParent() (string, error) {
	u := a.uplink
	if u == "" {
		return "", errors.New("no uplink port known: VLAN SSIDs cannot be bridged")
	}
	if i := strings.LastIndex(u, "."); i > 0 && strings.Count(u, ".") == 2 {
		return u[:i], nil
	}
	return u, nil
}

func (a *Applier) exists(dev string) bool {
	_, err := os.Stat(a.dev("/sys/class/net/" + dev))
	return err == nil
}

func (a *Applier) bridgeOf(dev string) string {
	l, err := os.Readlink(a.dev("/sys/class/net/" + dev + "/brport/bridge"))
	if err != nil {
		return ""
	}
	return filepath.Base(l)
}

// bridgeTo puts ifc into the LAN bridge (vid 0) or the VLAN's bridge.
func (a *Applier) bridgeTo(ctx context.Context, ifc string, vid int) error {
	br := a.o.Bridge
	if vid > 0 {
		var err error
		if br, err = a.ensureVLAN(ctx, vid); err != nil {
			return err
		}
	}
	cur := a.bridgeOf(ifc)
	if cur == br {
		return nil
	}
	if cur != "" {
		if err := a.run(ctx, "brctl", "delif", cur, ifc); err != nil {
			return err
		}
	}
	return a.run(ctx, "brctl", "addif", br, ifc)
}

func (a *Applier) ensureVLAN(ctx context.Context, vid int) (string, error) {
	parent, err := a.vlanParent()
	if err != nil {
		return "", err
	}
	vdev, br := parent+"."+strconv.Itoa(vid), vlanBridge(vid)
	if !a.exists(vdev) {
		if err := a.run(ctx, "ip", "link", "add", "link", parent, "name", vdev, "type", "vlan", "id", strconv.Itoa(vid)); err != nil {
			return "", err
		}
	}
	if !a.exists(br) {
		if err := a.run(ctx, "brctl", "addbr", br); err != nil {
			return "", err
		}
	}
	if a.bridgeOf(vdev) != br {
		if err := a.run(ctx, "brctl", "addif", br, vdev); err != nil {
			return "", err
		}
	}
	for _, d := range []string{vdev, br} {
		if err := a.run(ctx, "ip", "link", "set", d, "up"); err != nil {
			return "", err
		}
	}
	return br, nil
}

var vlanBr = regexp.MustCompile(`^br-v([0-9]+)$`)

// cleanVLANs removes the agent's VLAN bridges neither a BSS nor a LAN port
// (SetPortVLANs) uses any more. A LAN port's device still in a bridge being
// removed is rescued first (rescuePorts): its untagged device goes back to
// the LAN bridge, a tagged one is deleted.
func (a *Applier) cleanVLANs(ctx context.Context, want map[string]RadioPlan) error {
	used := a.portVLANsUsed()
	for _, rp := range want {
		for _, b := range rp.BSS {
			used[b.VLAN] = true
		}
	}
	ents, err := os.ReadDir(a.dev("/sys/class/net"))
	if err != nil {
		return err
	}
	parent, _ := a.vlanParent()
	for _, e := range ents {
		m := vlanBr.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		vid, _ := strconv.Atoi(m[1])
		if used[vid] {
			continue
		}
		if err := a.rescuePorts(ctx, e.Name()); err != nil {
			// a LAN port might be left in no bridge: keep the bridge
			a.o.Logf("mtkwifi: %s kept: moving a LAN port out of it failed: %v", e.Name(), err)
			continue
		}
		_ = a.run(ctx, "ip", "link", "set", e.Name(), "down")
		if err := a.run(ctx, "brctl", "delbr", e.Name()); err != nil {
			return err
		}
		if parent != "" && a.exists(parent+"."+m[1]) {
			if err := a.run(ctx, "ip", "link", "del", parent+"."+m[1]); err != nil {
				return err
			}
		}
	}
	return nil
}

// ------------------------------------------------------------- reading

func (a *Applier) isUp(dev string) bool {
	b, err := os.ReadFile(a.dev("/sys/class/net/" + dev + "/flags"))
	if err != nil {
		return false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 0, 64)
	return err == nil && v&1 == 1
}

// essidRE: the MT7603 prints `ESSID:"name"  ` at the end of its line, the
// MT7663 `ESSID:"name"  Nickname:""`.
var essidRE = regexp.MustCompile(`(?m)ESSID:"(.*?)"(?:\s+Nickname:|[ \t]*\r?$)`)

func (a *Applier) essid(ctx context.Context, ifc string) string {
	out, err := a.o.Run.Run(ctx, "iwconfig", ifc)
	if err != nil {
		return ""
	}
	if m := essidRE.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

// check compares the radios with want: BSS netdevs up with their SSIDs and
// bridges, the rest down. ssids false: sysfs only, no iwconfig (a radio
// restart's settle time, restartgate.go).
func (a *Applier) check(ctx context.Context, want map[string]RadioPlan, ssids bool) error {
	var bad []string
	for _, rd := range a.o.Layout {
		if err := a.checkRadio(ctx, rd, want[rd.Band], ssids); err != nil {
			bad = append(bad, err.Error())
		}
	}
	if len(bad) > 0 {
		return errors.New(strings.Join(bad, "; "))
	}
	return nil
}

// checkRadio is check for one radio.
func (a *Applier) checkRadio(ctx context.Context, rd RadioDef, rp RadioPlan, ssids bool) error {
	var bad []string
	served := bssOf(rd, rp)
	for _, ifc := range rd.Ifaces {
		i, ok := served[ifc]
		if !ok {
			if a.isUp(ifc) {
				bad = append(bad, ifc+" is up but serves nothing")
			}
			continue
		}
		b := rp.BSS[i]
		if !a.isUp(ifc) {
			bad = append(bad, ifc+" is down")
			continue
		}
		if ssids {
			if s := a.essid(ctx, ifc); s != b.SSID {
				bad = append(bad, fmt.Sprintf("%s serves %q, not %q", ifc, s, b.SSID))
			}
		}
		br := a.o.Bridge
		if b.VLAN > 0 {
			br = vlanBridge(b.VLAN)
		}
		if got := a.bridgeOf(ifc); got != br {
			bad = append(bad, fmt.Sprintf("%s is in bridge %q, not %q", ifc, got, br))
		}
	}
	if len(bad) > 0 {
		return errors.New(strings.Join(bad, "; "))
	}
	return nil
}

func (a *Applier) waitLive(ctx context.Context, want map[string]RadioPlan) error {
	deadline := time.Now().Add(a.o.VerifyTimeout)
	for {
		err := a.check(ctx, want, true)
		if err == nil || time.Now().After(deadline) {
			return err
		}
		if e := a.o.sleep(ctx, time.Second); e != nil {
			return err
		}
	}
}

// Verify is the health check: the radios still serve what d asks. Within
// a radio restart's settle time the SSIDs are not read (sysfs only).
func (a *Applier) Verify(ctx context.Context, d bcmwifi.Desired) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	want, _ := plans(d, a.o.Layout, a.o.WPA3)
	want, _ = a.pinned(want)
	return a.check(ctx, a.effective(want), !a.settling())
}

// ------------------------------------------------------- baseline, rollback

type baselineState struct {
	Up      []string          // BSS netdevs up at takeover
	Bridges map[string]string // netdev -> bridge at takeover
}

// captureBaseline saves the vendor's profiles and BSS state once per boot
// (RunDir is ramfs; the vendor regenerates its profiles at every boot).
func (a *Applier) captureBaseline(ctx context.Context) error {
	dir := a.dev(filepath.Join(a.o.RunDir, baselineDir))
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st := baselineState{Bridges: map[string]string{}}
	for _, rd := range a.o.Layout {
		b, err := os.ReadFile(a.dev(rd.Dat))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, rd.Band+".dat"), b, 0o600); err != nil {
			return err
		}
		for _, ifc := range rd.Ifaces {
			if a.isUp(ifc) {
				st.Up = append(st.Up, ifc)
			}
			if br := a.bridgeOf(ifc); br != "" {
				st.Bridges[ifc] = br
			}
		}
	}
	j, _ := json.Marshal(st)
	return os.WriteFile(filepath.Join(dir, "state.json"), j, 0o600)
}

// Rollback goes back to last-good; without one (or when it fails) to the
// vendor's Wi-Fi of this boot.
func (a *Applier) Rollback(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer a.changingRadios()() // no driver reads by the collector meanwhile
	return a.rollback(ctx)
}

// rollback brings back last-good with the Desired it came from (the guest
// chains and ACLs follow a.desired: the failed Desired's guest policy
// would leave last-good's guest SSID open), isolated while the uplink is
// down (what Verify checks: otherwise every health check fails and rolls
// back again, two radio restarts each time).
func (a *Applier) rollback(ctx context.Context) error {
	if lg, err := a.loadLastGood(); err == nil {
		gd, ok := a.loadLastGoodDesired()
		switch {
		case ok:
			a.desired = gd
		case len(guestVifs(a.o.Layout, lg)) > 0:
			// an older build's last-good: its guest policy is unknown
			a.o.Logf("mtkwifi: last-good has a guest SSID but no saved guest policy: restoring the vendor's Wi-Fi")
			return a.restoreBaseline(ctx)
		}
		eff := a.effective(lg)
		err := a.applyPlans(ctx, eff, nil)
		if err == nil {
			err = a.waitLive(ctx, eff)
		}
		if err == nil {
			a.live, a.want = eff, lg
			a.o.Logf("mtkwifi: rolled back to last-good")
			return nil
		}
		a.o.Logf("mtkwifi: last-good did not come up (%v): restoring the vendor's Wi-Fi", err)
	}
	return a.restoreBaseline(ctx)
}

func (a *Applier) restoreBaseline(ctx context.Context) error {
	dir := a.dev(filepath.Join(a.o.RunDir, baselineDir))
	j, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return fmt.Errorf("%w: %v", bcmwifi.ErrNoBaseline, err)
	}
	var st baselineState
	if err := json.Unmarshal(j, &st); err != nil {
		return err
	}
	a.clearLive(ctx)    // what only the agent sets live (live.go)
	a.parpOff(ctx)      // proxy ARP (proxyarp.go)
	defer a.restarted() // the collector leaves the driver alone a while longer
	for _, rd := range a.o.Layout {
		for i := len(rd.Ifaces) - 1; i >= 0; i-- {
			_ = a.run(ctx, "ifconfig", rd.Ifaces[i], "down")
		}
		b, err := os.ReadFile(filepath.Join(dir, rd.Band+".dat"))
		if err != nil {
			return err
		}
		if err := writeFile(a.dev(rd.Dat), b, 0o644); err != nil {
			return err
		}
	}
	for _, ifc := range st.Up {
		_ = a.run(ctx, "ifconfig", ifc, "up")
	}
	for _, rd := range a.o.Layout {
		for _, ifc := range rd.Ifaces {
			cur, want := a.bridgeOf(ifc), st.Bridges[ifc]
			if cur == want {
				continue
			}
			if cur != "" {
				_ = a.run(ctx, "brctl", "delif", cur, ifc)
			}
			if want != "" {
				_ = a.run(ctx, "brctl", "addif", want, ifc)
			}
		}
	}
	_ = a.cleanVLANs(ctx, nil)
	_ = a.syncGuest(ctx, nil, nil, true)
	a.live, a.want = nil, nil
	_ = os.Remove(a.dev(filepath.Join(a.o.RunDir, ownedFile)))
	_ = os.Remove(a.dev(filepath.Join(a.o.RunDir, appliedFile)))
	a.o.Logf("mtkwifi: the vendor's Wi-Fi of this boot is back")
	return nil
}

func (a *Applier) saveLastGood(ps map[string]RadioPlan, d bcmwifi.Desired) {
	if a.o.StateDir == "" {
		return
	}
	j, _ := json.Marshal(ps)
	jd, _ := json.Marshal(d)
	p := a.dev(filepath.Join(a.o.StateDir, lastGoodFile))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err == nil {
		// the Desired first: a last-good never pairs with a newer Desired
		if err := writeFile(a.dev(filepath.Join(a.o.StateDir, lastGoodDesired)), jd, 0o600); err != nil {
			a.o.Logf("mtkwifi: saving last-good: %v", err)
		}
		if err := writeFile(p, j, 0o600); err != nil {
			a.o.Logf("mtkwifi: saving last-good: %v", err)
		}
	}
}

// loadLastGoodDesired is the Desired last-good came from (an older build
// did not save it: false).
func (a *Applier) loadLastGoodDesired() (bcmwifi.Desired, bool) {
	var d bcmwifi.Desired
	if a.o.StateDir == "" {
		return d, false
	}
	j, err := os.ReadFile(a.dev(filepath.Join(a.o.StateDir, lastGoodDesired)))
	if err != nil || json.Unmarshal(j, &d) != nil {
		return d, false
	}
	return d, true
}

func (a *Applier) loadLastGood() (map[string]RadioPlan, error) {
	if a.o.StateDir == "" {
		return nil, os.ErrNotExist
	}
	j, err := os.ReadFile(a.dev(filepath.Join(a.o.StateDir, lastGoodFile)))
	if err != nil {
		return nil, err
	}
	var ps map[string]RadioPlan
	return ps, json.Unmarshal(j, &ps)
}

// ------------------------------------------------------------ the tick

// Tick repairs bridge membership in place and reports drift only an apply
// fixes (a BSS down or serving another SSID: something rewrote the driver).
// Within a radio restart's settle time the SSIDs are not read.
func (a *Applier) Tick(ctx context.Context) (bcmwifi.TickReport, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var r bcmwifi.TickReport
	if a.live == nil {
		return r, nil
	}
	a.flushLive(ctx)
	// the guest chains (an ebtables flush by something else is rebuilt)
	if err := a.syncGuest(ctx, &a.desired, a.live, true); err != nil {
		r.Problems = append(r.Problems, err.Error())
	}
	a.dfsStep(ctx)
	a.syncProxyARP(ctx)
	ssids := !a.settling()
	for _, rd := range a.o.Layout {
		rp := a.live[rd.Band]
		served := bssOf(rd, rp)
		for _, ifc := range rd.Ifaces {
			i, ok := served[ifc]
			if !ok {
				if a.isUp(ifc) {
					r.Foreign = append(r.Foreign, ifc+" is up but serves nothing")
					r.NeedsApply = true
				}
				continue
			}
			b := rp.BSS[i]
			if !a.isUp(ifc) {
				r.Foreign = append(r.Foreign, ifc+" went down")
				r.NeedsApply = true
				continue
			}
			if ssids {
				if s := a.essid(ctx, ifc); s != b.SSID {
					r.Foreign = append(r.Foreign, fmt.Sprintf("%s serves %q", ifc, s))
					r.NeedsApply = true
					continue
				}
			}
			br := a.o.Bridge
			if b.VLAN > 0 {
				br = vlanBridge(b.VLAN)
			}
			if got := a.bridgeOf(ifc); got != br {
				r.Foreign = append(r.Foreign, fmt.Sprintf("%s was in bridge %q", ifc, got))
				if err := a.bridgeTo(ctx, ifc, b.VLAN); err != nil {
					r.Problems = append(r.Problems, err.Error())
				} else {
					r.Steps++
				}
			}
		}
	}
	return r, nil
}

// --------------------------------------------------- clients and the rest

func (a *Applier) upIfaces() []string {
	var out []string
	for _, rd := range a.o.Layout {
		for _, ifc := range rd.Ifaces {
			if a.isUp(ifc) {
				out = append(out, ifc)
			}
		}
	}
	return out
}

// Kick disconnects mac from every BSS.
func (a *Applier) Kick(ctx context.Context, mac string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	mac = strings.ToUpper(mac)
	var errs []string
	for _, ifc := range a.upIfaces() {
		if err := a.run(ctx, "iwpriv", ifc, "set", "DisConnectSta="+mac); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// SetBlocked keeps macs off every BSS (the driver's deny list).
func (a *Applier) SetBlocked(ctx context.Context, macs []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	b := make([]string, 0, len(macs))
	for _, m := range macs {
		b = append(b, strings.ToUpper(m))
	}
	sort.Strings(b)
	a.blocked = b
	if a.live == nil {
		return nil
	}
	if a.acl != nil && sameACLs(wantACLs(a.desired, a.live, a.o.Layout, a.blocked), a.acl) {
		return nil // the driver has it (the agent sets the list before and after each apply)
	}
	return a.applyACL(ctx, a.live)
}

// ifaceACL is one BSS's driver access list: Policy 0 off, 1 allow only
// MACs, 2 deny MACs (upper case, sorted).
type ifaceACL struct {
	Policy int
	MACs   []string
}

// aclUnknown: a BSS whose list could not be written (applyACL).
const aclUnknown = -1

// maxACL is the driver's access-list size per BSS (MAX_NUM_OF_ACL_LIST).
const maxACL = 64

// wantACLs is each served BSS's access list: the SSID's MAC filter (allow:
// only its MACs, less any blocked; deny: its MACs) with the block list
// denied everywhere, as bcmwifi's computeACL does on the Deco.
func wantACLs(d bcmwifi.Desired, want map[string]RadioPlan, layout []RadioDef, blocked []string) map[string]ifaceACL {
	byID := map[string]*bcmwifi.MACFilter{}
	for _, s := range d.SSIDs {
		byID[s.ID] = s.MACFilter
	}
	isBlocked := map[string]bool{}
	for _, m := range blocked {
		isBlocked[strings.ToUpper(m)] = true
	}
	out := map[string]ifaceACL{}
	for _, rd := range layout {
		rp := want[rd.Band]
		for i, b := range rp.BSS {
			if rp.slot(i) >= len(rd.Ifaces) {
				break
			}
			deny := map[string]bool{}
			for m := range isBlocked {
				deny[m] = true
			}
			var acl ifaceACL
			if mf := byID[b.ID]; mf != nil {
				switch mf.Policy {
				case "allow":
					acl.Policy, acl.MACs = 1, []string{}
					seen := map[string]bool{}
					for _, m := range mf.MACs {
						m = strings.ToUpper(m)
						if !isBlocked[m] && !seen[m] {
							seen[m] = true
							acl.MACs = append(acl.MACs, m)
						}
					}
				case "deny":
					for _, m := range mf.MACs {
						deny[strings.ToUpper(m)] = true
					}
				}
			}
			if acl.Policy == 0 && len(deny) > 0 {
				acl.Policy = 2
				for m := range deny {
					acl.MACs = append(acl.MACs, m)
				}
			}
			sort.Strings(acl.MACs)
			out[rd.Ifaces[rp.slot(i)]] = acl
		}
	}
	return out
}

// sameACLs compares two sets of access lists; a BSS with the list off is
// the same as one not listed.
func sameACLs(a, b map[string]ifaceACL) bool {
	key := func(m map[string]ifaceACL) string {
		var ks []string
		for k, x := range m {
			if x.Policy != 0 {
				ks = append(ks, fmt.Sprintf("%s=%d:%s", k, x.Policy, strings.Join(x.MACs, ",")))
			}
		}
		sort.Strings(ks)
		return strings.Join(ks, ";")
	}
	return key(a) == key(b)
}

// applyACL writes every up BSS's access list (iwpriv, no restart) and
// disconnects the stations it newly keeps out: MACs newly denied, or taken
// off an allow list. BSSes not served get the list cleared.
func (a *Applier) applyACL(ctx context.Context, want map[string]RadioPlan) error {
	w := wantACLs(a.desired, want, a.o.Layout, a.blocked)
	var errs []string
	for _, ifc := range a.upIfaces() {
		acl := w[ifc]
		macs := acl.MACs
		if len(macs) > maxACL {
			a.o.Logf("mtkwifi: %s: %d access-list entries, the driver holds %d: the rest are not applied", ifc, len(macs), maxACL)
			macs = macs[:maxACL]
		}
		cmds := []string{"ACLClearAll=1", "AccessPolicy=" + strconv.Itoa(acl.Policy)}
		if acl.Policy != 0 {
			for _, m := range macs {
				cmds = append(cmds, "ACLAddEntry="+m)
			}
		}
		failed := false
		for _, c := range cmds {
			if err := a.run(ctx, "iwpriv", ifc, "set", c); err != nil {
				errs = append(errs, err.Error())
				failed = true
				break
			}
		}
		if failed {
			// not known to the driver: never the same as any list, so the
			// next SetBlocked or plan writes it again
			w[ifc] = ifaceACL{Policy: aclUnknown}
			continue
		}
		for _, m := range keptOut(a.acl[ifc], acl) {
			_ = a.run(ctx, "iwpriv", ifc, "set", "DisConnectSta="+m)
		}
	}
	a.acl = w
	if b, err := json.Marshal(w); err == nil {
		_ = os.WriteFile(a.dev(filepath.Join(a.o.RunDir, aclFile)), b, 0o600)
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// keptOut lists the MACs that next keeps out and prev let in: newly denied,
// or dropped from an allow list.
func keptOut(prev, next ifaceACL) []string {
	in := func(xs []string, m string) bool {
		for _, x := range xs {
			if x == m {
				return true
			}
		}
		return false
	}
	var out []string
	switch next.Policy {
	case 2:
		for _, m := range next.MACs {
			if prev.Policy != 2 || !in(prev.MACs, m) {
				out = append(out, m)
			}
		}
	case 1:
		if prev.Policy == 1 {
			for _, m := range prev.MACs {
				if !in(next.MACs, m) {
					out = append(out, m)
				}
			}
		}
	}
	return out
}

func (a *Applier) ForgetFailed() {
	a.mu.Lock()
	a.failed = ""
	a.mu.Unlock()
}

func (a *Applier) SetUplink(port string) {
	a.mu.Lock()
	a.uplink = port
	a.mu.Unlock()
}
