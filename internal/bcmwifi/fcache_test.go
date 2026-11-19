// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

// fcLog collects an Applier's log lines.
type fcLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *fcLog) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *fcLog) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

// fcCalls lists the fc commands run (status included).
func (f *fakeDev) fcCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if c[0] == "fc" {
			out = append(out, strings.Join(c, " "))
		}
	}
	return out
}

func (f *fakeDev) fcRan(cmd string) bool {
	for _, c := range f.fcCalls() {
		if c == cmd {
			return true
		}
	}
	return false
}

func fcApplier(t *testing.T, f *fakeDev) (*Applier, *fcLog) {
	t.Helper()
	a := newTestApplier(f, false)
	l := &fcLog{}
	a.o.Logf = func(format string, args ...any) { l.logf(format, args...); t.Logf(format, args...) }
	return a, l
}

// A per-client limit turns the flow cache off (then flushes it whole) and
// the last one going turns it back on; idle syncs only read the status.
func TestFlowCachePerClient(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a, logs := fcApplier(t, f)
	d := twoSSIDs()
	applyOK(t, a, d)
	if f.fcOff || f.fcRan("fc disable") {
		t.Fatal("flow cache turned off with no limit")
	}
	main5 := vifOf(t, a, d, "a-main", "na")
	f.state[main5+" assoclist"] = "assoclist " + strings.ToUpper(sta1) + "\nassoclist " + strings.ToUpper(sta2)
	f.reset()
	if _, err := a.SetClientRates(ctx, map[string]RateLimit{sta1: {DownKbps: 512, UpKbps: 768}}); err != nil {
		t.Fatal(err)
	}
	if !f.fcOff {
		t.Fatal("flow cache still learning with a per-client limit")
	}
	calls := strings.Join(f.fcCalls(), "\n")
	if !strings.Contains(calls, "fc status\nfc disable\nfc flush\n") {
		t.Errorf("want status, disable, whole flush in order:\n%s", calls)
	}
	if logs.count("flow cache off: 1 per-client / 0 SSID limits need the slow path") != 1 {
		t.Errorf("flip not logged: %q", logs.lines)
	}
	if !f.exists(a.fcOffPath()) {
		t.Error("fc-off not recorded in RunDir")
	}
	// Idle: the status is read, nothing flips.
	f.reset()
	if _, err := a.SyncRateLimits(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.fcCalls(); len(got) != 1 || got[0] != "fc status" {
		t.Errorf("idle sync ran %v", got)
	}
	// The station leaves: its limit is no longer built, the cache comes back.
	f.state[main5+" assoclist"] = "assoclist " + strings.ToUpper(sta2)
	if _, err := a.SyncRateLimits(ctx); err != nil {
		t.Fatal(err)
	}
	if f.fcOff {
		t.Fatal("flow cache still off with no station limited")
	}
	if logs.count("flow cache on: no limits") != 1 {
		t.Errorf("flip back not logged: %q", logs.lines)
	}
	if f.exists(a.fcOffPath()) {
		t.Error("fc-off left in RunDir")
	}
	// The station is back, then its entry goes (rate-update -1/-1).
	f.state[main5+" assoclist"] = "assoclist " + strings.ToUpper(sta1)
	if _, err := a.SyncRateLimits(ctx); err != nil || !f.fcOff {
		t.Fatalf("rejoin: off=%v err=%v", f.fcOff, err)
	}
	if _, err := a.SetClientRates(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if f.fcOff {
		t.Error("flow cache still off after the last limit went")
	}
	// No limit and nothing of ours: no fc call at all.
	f.reset()
	if _, err := a.SyncRateLimits(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.fcCalls(); len(got) != 0 {
		t.Errorf("sync without limits ran %v", got)
	}
}

// SSID-wide limits count too, and a cache turned back on behind the agent's
// back (TP-Link, by hand) is turned off again at the next Tick.
func TestFlowCacheSSIDLimitAndDrift(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a, logs := fcApplier(t, f)
	d := limitedDesired()
	applyOK(t, a, d)
	if f.fcOff {
		t.Fatal("flow cache off with a limited SSID but no station")
	}
	f.state["wl12 assoclist"] = "assoclist " + strings.ToUpper(sta1)
	if _, err := a.SyncRateLimits(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.fcOff || logs.count("flow cache off: 0 per-client / 1 SSID limits need the slow path") != 1 {
		t.Fatalf("SSID limit: off=%v logs %q", f.fcOff, logs.lines)
	}
	// Something turns it back on.
	f.fcOff = false
	f.reset()
	r, err := a.Tick(ctx)
	if err != nil || len(r.Problems) > 0 {
		t.Fatalf("Tick %+v %v", r, err)
	}
	if !f.fcOff || !f.fcRan("fc disable") || !f.fcRan("fc flush") {
		t.Errorf("drift not repaired: off=%v calls %v", f.fcOff, f.fcCalls())
	}
	if logs.count("need the slow path (it had been turned back on)") != 1 {
		t.Errorf("repair not logged: %q", logs.lines)
	}
	// A station with its own limit on the limited SSID: both counted.
	f.state["wl12 assoclist"] = "assoclist " + strings.ToUpper(sta1) + "\nassoclist " + strings.ToUpper(sta2)
	f.fcOff = false
	if _, err := a.SetClientRates(ctx, map[string]RateLimit{sta2: {DownKbps: 300}}); err != nil {
		t.Fatal(err)
	}
	if logs.count("flow cache off: 1 per-client / 1 SSID limits need the slow path") != 1 {
		t.Errorf("mixed counts not logged: %q", logs.lines)
	}
}

// The hand-back leaves the flow cache on: after the agent's limits, and
// also when someone else had turned it off.
func TestFlowCacheHandback(t *testing.T) {
	ctx := context.Background()
	for _, ours := range []bool{true, false} {
		t.Run(fmt.Sprintf("ours=%v", ours), func(t *testing.T) {
			f := newFakeDev(t)
			a, logs := fcApplier(t, f)
			d := limitedDesired()
			applyOK(t, a, d)
			if ours {
				f.state["wl12 assoclist"] = "assoclist " + strings.ToUpper(sta1)
				if _, err := a.SyncRateLimits(ctx); err != nil || !f.fcOff {
					t.Fatalf("off=%v err=%v", f.fcOff, err)
				}
			} else {
				f.fcOff = true
			}
			if err := a.handback(ctx); err != nil {
				t.Fatal(err)
			}
			if f.fcOff {
				t.Error("flow cache left off after the hand-back")
			}
			if logs.count("flow cache on: no limits (hand-back to TP-Link)") != 1 {
				t.Errorf("hand-back flip not logged: %q", logs.lines)
			}
			if f.exists(a.fcOffPath()) {
				t.Error("fc-off left in RunDir")
			}
		})
	}
}

// A cache someone else turned off while no limit is set is left alone;
// one the agent turned off in an earlier run (RunDir/fc-off) is restored by
// RestoreFlowCache, which runs nothing otherwise.
func TestFlowCacheRestore(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a, _ := fcApplier(t, f)
	f.fcOff = true
	if err := a.RestoreFlowCache(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.fcOff || len(f.fcCalls()) != 0 {
		t.Errorf("not ours: off=%v calls %v", f.fcOff, f.fcCalls())
	}
	applyOK(t, a, twoSSIDs())
	if !f.fcOff {
		t.Error("someone else's off state undone with no limit set")
	}
	// An earlier run turned it off (the marker is in RunDir); a new
	// process restores it.
	f.write(a.fcOffPath(), "x\n")
	b := newTestApplier(f, false)
	if err := b.RestoreFlowCache(ctx); err != nil {
		t.Fatal(err)
	}
	if f.fcOff || f.exists(b.fcOffPath()) {
		t.Errorf("earlier run's off state not restored: off=%v", f.fcOff)
	}
}

// No fc on the unit: limits are still built, no enable/disable is tried and
// the missing tool is logged once.
func TestFlowCacheMissing(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	f.noFC = true
	a, logs := fcApplier(t, f)
	d := limitedDesired()
	applyOK(t, a, d)
	f.state["wl12 assoclist"] = "assoclist " + strings.ToUpper(sta1)
	for i := 0; i < 3; i++ {
		if _, err := a.SyncRateLimits(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !f.tcCalled("qdisc add dev wl12 root handle 1: htb default 1") {
		t.Error("limits not built without fc")
	}
	for _, c := range f.fcCalls() {
		if c == "fc enable" || c == "fc disable" {
			t.Errorf("ran %q without fc", c)
		}
	}
	if n := logs.count("no flow cache control"); n != 1 {
		t.Errorf("missing fc logged %d times: %q", n, logs.lines)
	}
	if f.exists(a.fcOffPath()) {
		t.Error("fc-off recorded without fc")
	}
	if err := a.handback(ctx); err != nil {
		t.Fatal(err)
	}
}

// Dry run: the status is read, the flip only logged.
func TestFlowCacheDryRun(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a, logs := fcApplier(t, f)
	d := limitedDesired()
	applyOK(t, a, d)
	f.state["wl12 assoclist"] = "assoclist " + strings.ToUpper(sta1)
	a.o.DryRun = true
	f.reset()
	if _, err := a.SyncRateLimits(ctx); err != nil {
		t.Fatal(err)
	}
	if f.fcOff || f.fcRan("fc disable") || logs.count("dry-run: fc disable") != 1 || f.exists(a.fcOffPath()) {
		t.Errorf("dry run: off=%v calls %v", f.fcOff, f.fcCalls())
	}
}

func (f *fakeDev) exists(p string) bool {
	_, err := os.Stat(f.path(p))
	return err == nil
}

// A failing fc disable is retried at the next sync, not taken for drift.
func TestFlowCacheDisableFails(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a, logs := fcApplier(t, f)
	applyOK(t, a, limitedDesired())
	f.state["wl12 assoclist"] = "assoclist " + strings.ToUpper(sta1)
	f.failOn = func(argv []string) bool { return argv[0] == "fc" && argv[1] == "disable" }
	if _, err := a.SyncRateLimits(ctx); err != nil {
		t.Fatal(err)
	}
	if f.fcOff || f.exists(a.fcOffPath()) {
		t.Fatal("failed disable recorded as ours")
	}
	f.failOn = nil
	if _, err := a.SyncRateLimits(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.fcOff || logs.count("turned back on") != 0 || logs.count("flow cache off: 0 per-client / 1 SSID limits need the slow path") != 1 {
		t.Errorf("retry: off=%v logs %q", f.fcOff, logs.lines)
	}
}

// fc-off is on disk before `fc disable` runs: an agent killed between the
// two (a crash loop drops to observe, whose start restores only what fc-off
// records) must not leave the cache off with nothing to turn it back on.
func TestFlowCacheRecordedBeforeDisable(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a, _ := fcApplier(t, f)
	applyOK(t, a, limitedDesired())
	f.state["wl12 assoclist"] = "assoclist " + strings.ToUpper(sta1)
	recorded, ran := false, false
	f.failOn = func(argv []string) bool {
		if argv[0] == "fc" && argv[1] == "disable" {
			ran, recorded = true, f.exists(a.fcOffPath())
		}
		return false
	}
	if _, err := a.SyncRateLimits(ctx); err != nil {
		t.Fatal(err)
	}
	if !ran || !recorded || !f.fcOff {
		t.Errorf("fc disable ran=%v with fc-off recorded=%v (off=%v)", ran, recorded, f.fcOff)
	}
}

// Dry run, synced twice: nothing was turned off, so the second sync is not
// reported as the cache having been turned back on.
func TestFlowCacheDryRunNoDrift(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a, logs := fcApplier(t, f)
	applyOK(t, a, limitedDesired())
	f.state["wl12 assoclist"] = "assoclist " + strings.ToUpper(sta1)
	a.o.DryRun = true
	for i := 0; i < 2; i++ {
		if _, err := a.SetClientRates(ctx, nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := logs.count("dry-run: fc disable"); n != 2 {
		t.Errorf("dry-run disable logged %d times, want 2", n)
	}
	if n := logs.count("turned back on"); n != 0 || f.fcOff || a.fcOff {
		t.Errorf("dry run: off=%v owned=%v, %d drift lines", f.fcOff, a.fcOff, n)
	}
}

// TestParseFCStatus pins the parser to the real `fc status` output of the
// X20: the state is the "Flow Learning Enabled/Disabled :" line, not the
// first line, and not "OVS Flow Learning <...>".
func TestParseFCStatus(t *testing.T) {
	for _, c := range []struct {
		name   string
		out    string
		on, ok bool
	}{
		{"enabled", fcStatusOut("Enabled"), true, true},
		{"disabled", fcStatusOut("Disabled"), false, true},
		{"blog line", "Broadcom Packet Flow Cache learning via BLOG disabled.\n", false, true},
		{"ovs only", "\tOVS Flow Learning <Disabled> \n\tMCast Learning <Disabled>\n", false, false},
		{"empty", "", false, false},
	} {
		on, ok := parseFCStatus(c.out)
		if on != c.on || ok != c.ok {
			t.Errorf("%s: got on=%v ok=%v, want on=%v ok=%v", c.name, on, ok, c.on, c.ok)
		}
	}
}
