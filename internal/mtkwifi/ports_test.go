// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/jioports"
)

// newPortsDev is the fake JCOW414 with its four switch ports: eth0.P with
// eth0.P.1 in bdg2 (eth0.4/eth0.4.1, the uplink, come from newFakeDev).
func newPortsDev(t *testing.T) *fakeDev {
	f := newFakeDev(t)
	for _, p := range []string{"eth0.1", "eth0.2", "eth0.3"} {
		f.mkdev(p, 1)
		f.mkdev(p+".1", 1)
		f.link(p+".1", "bdg2")
	}
	return f
}

func (f *fakeDev) exists(dev string) bool {
	_, err := os.Stat(filepath.Join(f.root, "sys/class/net", dev))
	return err == nil
}

// uplinkUntouched: no command named the uplink port or its untagged
// device other than to add a VLAN device on it (or remove one an unused
// bridge held: br-vN's eth0.4.N).
func uplinkUntouched(t *testing.T, f *fakeDev, from int) {
	t.Helper()
	for _, c := range f.log[from:] {
		switch {
		case strings.Contains(c, "eth0.4.1"):
			t.Errorf("uplink's LAN device touched: %s", c)
		case strings.HasPrefix(c, "ip link add link eth0.4 name eth0.4."),
			strings.HasPrefix(c, "brctl addif br-v") && strings.Contains(c, " eth0.4."),
			strings.HasPrefix(c, "ip link set eth0.4.") && strings.HasSuffix(c, " up"),
			strings.HasPrefix(c, "ip link del eth0.4."):
		case strings.Contains(c, "eth0.4"):
			t.Errorf("uplink touched: %s", c)
		}
	}
	if f.bridge("eth0.4.1") != "bdg2" {
		t.Errorf("uplink's LAN device in %q", f.bridge("eth0.4.1"))
	}
}

func portsManager(a *Applier, unlocked ...int) *jioports.Manager {
	return jioports.New(jioports.Options{B: a, Unlocked: unlocked})
}

// TestPortVLANsApply: port 2 native VLAN 3 (olive#'s bridge) with VLAN 2
// tagged, port 3 VLAN 5 tagged; port 1 (locked) keeps the LAN; the uplink
// gets the VLAN devices and nothing else. Then the Wi-Fi drops olive# while
// port 2 still uses br-v3 (kept), and the ports go back to the LAN when the
// switch section goes (the bridges no one uses are removed).
func TestPortVLANsApply(t *testing.T) {
	f := newPortsDev(t)
	a := newApplier(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, home())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	n := len(f.log)
	m := portsManager(a)
	w := jioports.Want{VLAN: true, Ports: map[int]jioports.PortWant{
		1: {Native: 2}, 2: {Native: 3, Tagged: []int{2}}, 3: {Tagged: []int{5}}}}
	r := m.Apply(ctx, w)
	if len(r.Failed) != 0 || r.Steps != 3 {
		t.Fatalf("apply %+v", r)
	}
	for dev, br := range map[string]string{"eth0.1.1": "bdg2", "eth0.2.1": "br-v3", "eth0.2.2": "br-v2", "eth0.4.2": "br-v2",
		"eth0.3.1": "bdg2", "eth0.3.5": "br-v5", "eth0.4.5": "br-v5", "eth0.4.3": "br-v3", "rai1": "br-v3"} {
		if f.bridge(dev) != br {
			t.Errorf("%s in %q, want %q", dev, f.bridge(dev), br)
		}
	}
	for _, d := range []string{"eth0.2.2", "eth0.3.5", "eth0.4.2", "eth0.4.5"} {
		if !f.up(d) {
			t.Errorf("%s down", d)
		}
	}
	if f.exists("eth0.1.2") || strings.Contains(strings.Join(f.log[n:], "\n"), "eth0.1") {
		t.Errorf("locked port 1 touched: %v", f.log[n:])
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "port 1 is locked") {
		t.Errorf("port 1's setting not reported: %q", r.Notes)
	}
	uplinkUntouched(t, f, n)

	// the same switch section again: nothing to do
	n = len(f.log)
	if r := m.Apply(ctx, w); r.Steps != 0 || len(f.log) != n {
		t.Errorf("re-apply changed %d: %v", r.Steps, f.log[n:])
	}

	// olive# goes; port 2 keeps br-v3 (and the uplink's eth0.4.3)
	d := home()
	d.SSIDs = append(d.SSIDs[:1], d.SSIDs[2:]...)
	m.Prepare(w)
	p, _ = a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if f.bridge("eth0.2.1") != "br-v3" || f.bridge("eth0.4.3") != "br-v3" {
		t.Errorf("port 2's VLAN bridge went with the SSID: eth0.2.1 in %q, eth0.4.3 in %q", f.bridge("eth0.2.1"), f.bridge("eth0.4.3"))
	}

	// Enable Port VLAN off: every port back on the LAN, bridges removed
	n = len(f.log)
	r = m.Apply(ctx, jioports.Want{})
	if len(r.Failed) != 0 {
		t.Fatalf("back to LAN: %+v", r.Failed)
	}
	for _, dev := range []string{"eth0.1.1", "eth0.2.1", "eth0.3.1"} {
		if f.bridge(dev) != "bdg2" {
			t.Errorf("%s in %q, want bdg2", dev, f.bridge(dev))
		}
	}
	for _, dev := range []string{"eth0.2.2", "eth0.3.5", "br-v2", "br-v3", "br-v5", "eth0.4.2", "eth0.4.3", "eth0.4.5"} {
		if f.exists(dev) {
			t.Errorf("%s left behind", dev)
		}
	}
	uplinkUntouched(t, f, n)
}

// TestPortVLANsFailureRollsBack: a port whose change fails is put back on
// the LAN without tagged VLANs, and the same setting is not retried.
func TestPortVLANsFailureRollsBack(t *testing.T) {
	f := newPortsDev(t)
	a := newApplier(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, home())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	m := portsManager(a)
	f.fail["brctl addif br-v7 eth0.2.1"] = true
	w := jioports.Want{VLAN: true, Ports: map[int]jioports.PortWant{2: {Native: 7, Tagged: []int{8}}, 3: {Tagged: []int{9}}}}
	// the tagged VLAN first: the failure comes after a change was made
	w.Ports[2] = jioports.PortWant{Native: 7, Tagged: []int{8}}
	f.mkdev("eth0.2.8", 1)
	f.link("eth0.2.8", "br-v8")
	r := m.Apply(ctx, w)
	if r.Failed[2] == nil || len(r.Failed) != 1 {
		t.Fatalf("failures %+v", r.Failed)
	}
	if f.bridge("eth0.2.1") != "bdg2" || f.exists("eth0.2.8") {
		t.Errorf("port 2 not rolled back: eth0.2.1 in %q, eth0.2.8 exists %v", f.bridge("eth0.2.1"), f.exists("eth0.2.8"))
	}
	if f.bridge("eth0.3.9") != "br-v9" {
		t.Errorf("port 3 did not go on: eth0.3.9 in %q", f.bridge("eth0.3.9"))
	}
	n := len(f.log)
	r = m.Apply(ctx, w)
	if strings.Contains(strings.Join(f.log[n:], "\n"), "eth0.2") || !strings.Contains(strings.Join(r.Notes, "\n"), "not retried") {
		t.Errorf("failed setting retried: %v notes %q", f.log[n:], r.Notes)
	}
	delete(f.fail, "brctl addif br-v7 eth0.2.1")
	w.Ports[2] = jioports.PortWant{Native: 7}
	if r := m.Apply(ctx, w); len(r.Failed) != 0 || f.bridge("eth0.2.1") != "br-v7" {
		t.Errorf("a new setting was not applied: %+v, eth0.2.1 in %q", r.Failed, f.bridge("eth0.2.1"))
	}
}

// TestPortVLANsGuards: port 1 changes only when unlocked; a port the agent
// tracks as the uplink is not changed; the applier refuses the uplink's
// devices outright.
func TestPortVLANsGuards(t *testing.T) {
	f := newPortsDev(t)
	a := newApplier(f)
	ctx := context.Background()
	w := jioports.Want{VLAN: true, Ports: map[int]jioports.PortWant{1: {Native: 3}, 2: {Native: 3}}}
	m := jioports.New(jioports.Options{B: a, Unlocked: []int{1}, Uplink: func() string { return "eth0.2.1" }})
	r := m.Apply(ctx, w)
	if f.bridge("eth0.1.1") != "br-v3" || f.bridge("eth0.2.1") != "bdg2" {
		t.Errorf("eth0.1.1 in %q (unlocked), eth0.2.1 in %q (tracked uplink)", f.bridge("eth0.1.1"), f.bridge("eth0.2.1"))
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "port 2 is the uplink now") {
		t.Errorf("notes %q", r.Notes)
	}
	if err := a.PortToBridge(ctx, "eth0.4.1", 3); err == nil || f.bridge("eth0.4.1") != "bdg2" {
		t.Errorf("uplink moved: %v", err)
	}
	if _, err := a.EnsurePortVLAN(ctx, "eth0.4", 9); err == nil {
		t.Errorf("tagged VLAN added on the uplink by the port code")
	}
	if err := a.DelPortVLAN(ctx, "eth0.4.3"); err == nil {
		t.Errorf("uplink VLAN device removed by the port code")
	}
	if _, err := a.EnsurePortVLAN(ctx, "eth0.2", 1); err == nil {
		t.Errorf("VLAN 1 tagged accepted")
	}
	// Restore puts the unlocked port back; the default Manager never
	// touches port 1
	if r := m.Restore(ctx); len(r.Failed) != 0 || f.bridge("eth0.1.1") != "bdg2" {
		t.Errorf("restore %+v, eth0.1.1 in %q", r, f.bridge("eth0.1.1"))
	}
	f.link("eth0.1.1", "br-v3")
	n := len(f.log)
	r = portsManager(a).Restore(ctx)
	if len(f.log) != n || f.bridge("eth0.1.1") != "br-v3" {
		t.Errorf("locked port 1 restored: %v", f.log[n:])
	}
}

// TestCleanVLANsRescuesPorts: a VLAN bridge removed while a port's
// untagged device is still in it (the ports did not say they use it)
// hands that device back to the LAN bridge and drops a port's tagged one:
// a port is never left in no bridge.
func TestCleanVLANsRescuesPorts(t *testing.T) {
	f := newPortsDev(t)
	a := newApplier(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, home())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	f.mkdev("br-v7", 1)
	f.link("eth0.2.1", "br-v7")
	f.mkdev("eth0.3.7", 1)
	f.link("eth0.3.7", "br-v7")
	if err := a.PruneVLANs(ctx); err != nil {
		t.Fatal(err)
	}
	if f.exists("br-v7") || f.bridge("eth0.2.1") != "bdg2" || f.exists("eth0.3.7") {
		t.Errorf("br-v7 exists %v, eth0.2.1 in %q, eth0.3.7 exists %v", f.exists("br-v7"), f.bridge("eth0.2.1"), f.exists("eth0.3.7"))
	}
	// with the ports saying they use it, it stays
	f.mkdev("br-v7", 1)
	f.link("eth0.2.1", "br-v7")
	a.SetPortVLANs(map[int]bool{7: true})
	if err := a.PruneVLANs(ctx); err != nil || !f.exists("br-v7") || f.bridge("eth0.2.1") != "br-v7" {
		t.Errorf("used port bridge removed: %v", err)
	}
}

// TestHandBackRemovesPortVLANs: an apply whose rollback cannot bring
// last-good up hands Wi-Fi back to the vendor (restoreBaseline); the
// agent then puts the ports back on the LAN (dropToObserve: portsRestore).
// Nothing the agent made stays: no br-vN, no eth0.4.N, no port VLAN
// device. Port 1 (locked) keeps its bridge.
func TestHandBackRemovesPortVLANs(t *testing.T) {
	f := newPortsDev(t)
	a := newApplier(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, home())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	m := portsManager(a)
	w := jioports.Want{VLAN: true, Ports: map[int]jioports.PortWant{2: {Native: 2}, 3: {Tagged: []int{5, 3}}}}
	if r := m.Apply(ctx, w); len(r.Failed) != 0 {
		t.Fatalf("ports %+v", r.Failed)
	}
	for _, dev := range []string{"br-v2", "br-v3", "br-v5", "eth0.4.2", "eth0.4.3", "eth0.4.5", "eth0.3.5"} {
		if !f.exists(dev) {
			t.Fatalf("%s missing before the hand-back", dev)
		}
	}
	// a new Desired whose 5 GHz radio does not come up, nor does last-good's
	m.Prepare(w)
	f.fail["ifconfig rai0 up"] = true
	d := home()
	d.Radios["na"] = bcmwifi.Radio{Enabled: true, Channel: 149, Width: 40}
	p, _ = a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err == nil {
		t.Fatal("apply succeeded")
	}
	if a.Owned() {
		t.Fatal("still owned: the test wants a hand-back to the vendor")
	}
	delete(f.fail, "ifconfig rai0 up")
	if r := m.Restore(ctx); len(r.Failed) != 0 {
		t.Fatalf("restore %+v", r.Failed)
	}
	for _, dev := range []string{"eth0.1.1", "eth0.2.1", "eth0.3.1", "eth0.4.1"} {
		if f.bridge(dev) != "bdg2" {
			t.Errorf("%s in %q, want bdg2", dev, f.bridge(dev))
		}
	}
	for _, dev := range []string{"br-v2", "br-v3", "br-v5", "eth0.4.2", "eth0.4.3", "eth0.4.5", "eth0.3.3", "eth0.3.5", "eth0.2.2"} {
		if f.exists(dev) {
			t.Errorf("%s left behind after the hand-back", dev)
		}
	}
}

type changeKey struct{}

// TestOnChangeBeforeChanges: the change hook runs, with the caller's
// context, before each command that changes the unit (a port moved, a
// VLAN bridge pruned, a BSS put back in its bridge) and never for an idle
// Tick, Verify or PruneVLANs, nor in a dry run.
func TestOnChangeBeforeChanges(t *testing.T) {
	f := newPortsDev(t)
	a := newApplier(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, home())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	var calls []int // len(f.log) at each call
	var tags []any
	a.OnChange(func(ctx context.Context) {
		calls = append(calls, len(f.log))
		tags = append(tags, ctx.Value(changeKey{}))
	})
	tctx := context.WithValue(ctx, changeKey{}, "tick")
	m := portsManager(a)

	// idle: nothing to change
	if _, err := a.Tick(tctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(tctx, home()); err != nil {
		t.Fatal(err)
	}
	if err := a.PruneVLANs(tctx); err != nil {
		t.Fatal(err)
	}
	m.Apply(tctx, jioports.Want{})
	if len(calls) != 0 {
		t.Fatalf("hook called %d time(s) with nothing to change: %v", len(calls), f.log)
	}

	// a BSS out of its bridge, a port moved, an unused bridge pruned: the
	// hook runs right before each change, never before a read (iwconfig)
	for _, step := range []func(){
		func() { f.link("rai1", "bdg2"); a.Tick(tctx) },
		func() { m.Apply(tctx, jioports.Want{VLAN: true, Ports: map[int]jioports.PortWant{2: {Native: 7}}}) },
		func() { f.mkdev("br-v8", 1); a.PruneVLANs(tctx) },
	} {
		n, c := len(f.log), len(calls)
		step()
		var changes []int
		for i := n; i < len(f.log); i++ {
			if !strings.HasPrefix(f.log[i], "iwconfig ") {
				changes = append(changes, i)
			}
		}
		if len(changes) == 0 {
			t.Fatalf("the step changed nothing: %v", f.log[n:])
		}
		if got := calls[c:]; !slices.Equal(got, changes) {
			t.Errorf("hook called at %v, the changes are at %v: %v", got, changes, f.log[n:])
		}
	}
	for _, tag := range tags {
		if tag != "tick" {
			t.Errorf("hook got another context: %v", tag)
		}
	}

	// dry run: nothing runs, no hook
	d := New(Options{Root: f.root, Run: f, RunDir: "/tmp/udeco", Uplink: "eth0.4.1", DryRun: true})
	hooked := false
	d.OnChange(func(context.Context) { hooked = true })
	d.PortToBridge(ctx, "eth0.3.1", 9)
	if hooked {
		t.Error("hook called in a dry run")
	}
}
