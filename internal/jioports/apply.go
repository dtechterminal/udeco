// SPDX-License-Identifier: GPL-2.0-or-later

package jioports

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
)

// Bridger is what the port VLANs need of the Wi-Fi applier
// (*mtkwifi.Applier): the VLAN bridges are shared with the VLAN SSIDs, and
// VLAN N's bridge br-vN also holds the uplink's eth0.4.N.
type Bridger interface {
	LANBridge() string
	BridgeOf(dev string) string
	Exists(dev string) bool
	// PortToBridge: vid 0 = the LAN bridge, > 0 = br-v<vid> (made with the
	// uplink's VLAN device when missing), < 0 = no bridge.
	PortToBridge(ctx context.Context, dev string, vid int) error
	EnsurePortVLAN(ctx context.Context, parent string, vid int) (string, error)
	DelPortVLAN(ctx context.Context, dev string) error
	PortVLANDevs(parent string) map[int]string
	SetPortVLANs(vids map[int]bool)
	PruneVLANs(ctx context.Context) error
}

// Options configures a Manager.
type Options struct {
	B Bridger
	// Unlocked are the LAN ports (1-3) the controller may change besides
	// ports 2 and 3, which it always may (config ports_unlocked). Port 1
	// is locked unless listed.
	Unlocked []int
	// Uplink is the port the agent tracks as the uplink now (eth0.4.1);
	// a LAN port whose untagged device it is, is not changed.
	Uplink func() string
	// DryRun: plans are logged, nothing changes (config apply=false).
	DryRun bool
	Logf   func(string, ...any)
}

// Manager applies the controller's port VLANs.
type Manager struct {
	o      Options
	locked map[int]bool
	noted  map[string]bool // notes already logged (one line per change)
	// failed: unit port -> the setting whose change failed and was rolled
	// back; not retried until the controller wants something else
	failed map[int]string
}

// New returns a Manager; nothing changes until Apply.
func New(o Options) *Manager {
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Uplink == nil {
		o.Uplink = func() string { return Untagged(UplinkPhys) }
	}
	m := &Manager{o: o, locked: map[int]bool{1: true}, noted: map[string]bool{}, failed: map[int]string{}}
	for _, p := range o.Unlocked {
		delete(m.locked, p)
	}
	return m
}

// Locked reports whether the controller may not change port phys: the
// uplink always, port 1 unless unlocked.
func (m *Manager) Locked(phys int) bool { return phys == UplinkPhys || m.locked[phys] }

// Live is a LAN port as it is now.
type Live struct {
	Bridge string         // the untagged device's bridge ("" = none)
	Tagged map[int]string // VLAN -> tagged device
	// TaggedBr: VLAN -> the tagged device's bridge
	TaggedBr map[int]string
}

// live reads port phys.
func (m *Manager) live(phys int) Live {
	l := Live{Bridge: m.o.B.BridgeOf(Untagged(phys)), Tagged: m.o.B.PortVLANDevs(Parent(phys)), TaggedBr: map[int]string{}}
	for v, d := range l.Tagged {
		l.TaggedBr[v] = m.o.B.BridgeOf(d)
	}
	return l
}

var vlanBrRE = regexp.MustCompile(`^br-v([0-9]+)$`)

// is reports whether live already is want.
func (m *Manager) is(l Live, want PortWant) bool {
	if !matchBridge(l.Bridge, nativeOf(want), m.o.B.LANBridge()) {
		return false
	}
	tagged := map[int]bool{}
	if !want.Disabled {
		for _, v := range want.Tagged {
			tagged[v] = true
		}
	}
	if len(tagged) != len(l.Tagged) {
		return false
	}
	for v := range tagged {
		if _, ok := l.Tagged[v]; !ok || l.TaggedBr[v] != "br-v"+strconv.Itoa(v) {
			return false
		}
	}
	return true
}

// nativeOf is where want sends the untagged frames (-1 = nowhere).
func nativeOf(want PortWant) int {
	if want.Disabled {
		return -1
	}
	return want.Native
}

func matchBridge(br string, native int, lan string) bool {
	switch {
	case native < 0:
		return br == ""
	case native == 0:
		return br == lan
	}
	return br == "br-v"+strconv.Itoa(native)
}

// usedVLANs are the VLAN bridges the LAN ports use now.
func (m *Manager) usedVLANs() map[int]bool {
	out := map[int]bool{}
	for _, p := range LANPorts {
		l := m.live(p)
		if s := vlanBrRE.FindStringSubmatch(l.Bridge); s != nil {
			v, _ := strconv.Atoi(s[1])
			out[v] = true
		}
		for v := range l.Tagged {
			out[v] = true
		}
	}
	return out
}

// wantedVLANs are the VLAN bridges want gives the ports the controller
// may change.
func (m *Manager) wantedVLANs(w Want) map[int]bool {
	out := map[int]bool{}
	for _, p := range LANPorts {
		if m.Locked(p) {
			continue
		}
		for _, v := range w.Port(Idx(p)).VLANs() {
			out[v] = true
		}
	}
	return out
}

// Prepare tells the Wi-Fi applier, before it applies a new system_cfg, the
// VLAN bridges the ports use now and will use under w, so the Wi-Fi apply
// does not remove one a port is about to keep or join.
func (m *Manager) Prepare(w Want) {
	vids := m.usedVLANs()
	for v := range m.wantedVLANs(w) {
		vids[v] = true
	}
	m.o.B.SetPortVLANs(vids)
}

// Report is the result of an Apply or Restore.
type Report struct {
	Steps  int            // changes made (or planned, dry run)
	Notes  []string       // what was not carried out, and why
	Failed map[int]error  // by unit port: the change failed and the port was put back on the LAN
	Ports  map[int]string // by unit port: what the port is now (changed ports only)
}

func (r *Report) note(f string, args ...any) { r.Notes = append(r.Notes, fmt.Sprintf(f, args...)) }

// Apply makes w live on the LAN ports the controller may change. A port
// whose change fails is put back on the untagged LAN (and loses its tagged
// VLANs); the other ports go on. Locked ports and the uplink are never
// touched; a locked port's wanted change is reported in the notes.
func (m *Manager) Apply(ctx context.Context, w Want) Report {
	r := Report{Failed: map[int]error{}, Ports: map[int]string{}}
	m.Prepare(w)
	uplink := m.o.Uplink()
	for _, p := range LANPorts {
		want := w.Port(Idx(p))
		l := m.live(p)
		switch {
		case m.Locked(p):
			if !want.Default() {
				r.note("port %d is locked (config ports_unlocked): the controller's setting (%s) is not applied; it stays on the untagged LAN", p, want)
			}
			if !m.is(l, PortWant{}) {
				r.note("port %d is locked and is not on the plain LAN now (%s): left as it is", p, m.describe(l))
			}
			continue
		case Untagged(p) == uplink:
			r.note("port %d is the uplink now: the controller's setting (%s) is not applied", p, want)
			continue
		case m.is(l, want):
			delete(m.failed, p)
			continue
		case m.failed[p] == want.String():
			r.note("port %d: %s failed to apply before and was put back on the LAN: not retried until the controller sends another setting", p, want)
			continue
		}
		delete(m.failed, p)
		if m.o.DryRun {
			r.Steps++
			r.Ports[p] = want.String()
			m.o.Logf("ports: dry run: port %d would be %s (now %s)", p, want, m.describe(l))
			continue
		}
		n, err := m.applyPort(ctx, p, want, l)
		r.Steps += n
		if err != nil {
			r.Failed[p] = err
			m.failed[p] = want.String()
			if rerr := m.rollback(ctx, p); rerr != nil {
				err = fmt.Errorf("%v; putting it back on the LAN: %v", err, rerr)
				r.Failed[p] = err
			}
			continue
		}
		r.Ports[p] = want.String()
	}
	if !m.o.DryRun {
		m.o.B.SetPortVLANs(m.usedVLANs())
		if err := m.o.B.PruneVLANs(ctx); err != nil {
			r.note("removing VLAN bridges no port or SSID uses: %v", err)
		}
	}
	return r
}

// applyPort changes port p from l to want: the tagged VLANs it should not
// carry go first, then the untagged device moves, then the tagged VLANs it
// should carry come.
func (m *Manager) applyPort(ctx context.Context, p int, want PortWant, l Live) (int, error) {
	steps := 0
	keep := map[int]bool{}
	if !want.Disabled {
		for _, v := range want.Tagged {
			keep[v] = true
		}
	}
	var gone []int
	for v := range l.Tagged {
		if !keep[v] {
			gone = append(gone, v)
		}
	}
	sort.Ints(gone)
	for _, v := range gone {
		if err := m.o.B.DelPortVLAN(ctx, l.Tagged[v]); err != nil {
			return steps, err
		}
		steps++
	}
	if native := nativeOf(want); !matchBridge(l.Bridge, native, m.o.B.LANBridge()) {
		if err := m.o.B.PortToBridge(ctx, Untagged(p), native); err != nil {
			return steps, err
		}
		steps++
	}
	var add []int
	for v := range keep {
		add = append(add, v)
	}
	sort.Ints(add)
	for _, v := range add {
		if d, ok := l.Tagged[v]; ok && l.TaggedBr[v] == "br-v"+strconv.Itoa(v) && m.o.B.Exists(d) {
			continue
		}
		if _, err := m.o.B.EnsurePortVLAN(ctx, Parent(p), v); err != nil {
			return steps, err
		}
		steps++
	}
	if live := m.live(p); !m.is(live, want) {
		return steps, fmt.Errorf("port %d is %s after the change, not %s", p, m.describe(live), want)
	}
	return steps, nil
}

// rollback puts port p back as the vendor has it: untagged LAN, no tagged
// VLANs.
func (m *Manager) rollback(ctx context.Context, p int) error {
	var errs []error
	l := m.live(p)
	for _, d := range l.Tagged {
		if err := m.o.B.DelPortVLAN(ctx, d); err != nil {
			errs = append(errs, err)
		}
	}
	if l.Bridge != m.o.B.LANBridge() {
		if err := m.o.B.PortToBridge(ctx, Untagged(p), 0); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Restore puts every LAN port the controller may change back on the
// untagged LAN without tagged VLANs (the agent hands the unit back). Locked
// ports and the uplink are not touched.
func (m *Manager) Restore(ctx context.Context) Report {
	r := Report{Failed: map[int]error{}, Ports: map[int]string{}}
	if m.o.DryRun {
		return r
	}
	for _, p := range LANPorts {
		if m.Locked(p) || m.is(m.live(p), PortWant{}) {
			continue
		}
		if err := m.rollback(ctx, p); err != nil {
			r.Failed[p] = err
			continue
		}
		r.Steps++
		r.Ports[p] = PortWant{}.String()
	}
	m.o.B.SetPortVLANs(m.usedVLANs())
	return r
}

// Note logs s once per distinct text (the notes repeat at every apply).
func (m *Manager) Note(s string) {
	if m.noted[s] {
		return
	}
	m.noted[s] = true
	m.o.Logf("ports: %s", s)
}

// describe is a live port in PortWant's words.
func (m *Manager) describe(l Live) string {
	pw := PortWant{Native: -1}
	switch s := vlanBrRE.FindStringSubmatch(l.Bridge); {
	case l.Bridge == "":
	case s != nil:
		pw.Native, _ = strconv.Atoi(s[1])
	default:
		pw.Native = 0
		if l.Bridge != m.o.B.LANBridge() {
			return "in bridge " + l.Bridge
		}
	}
	for v := range l.Tagged {
		pw.Tagged = append(pw.Tagged, v)
	}
	sort.Ints(pw.Tagged)
	return pw.String()
}
