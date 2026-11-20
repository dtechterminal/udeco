// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/wl"
)

// fixtureCaps reads the unit's hardware caps with the real collector from
// the .205 fixtures (country US: ng 1-11, na 36-48 and 149-165, no DFS).
func fixtureCaps(t *testing.T, f *fakeDev) wl.Caps {
	t.Helper()
	c, err := wl.New(wl.Options{Root: f.root, Run: f}).Caps(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.Country != "US" || c.Bands["na"].DFS || len(c.Bands["ng"].Channels[20]) != 11 {
		t.Fatalf("fixture caps not as expected: %+v", c)
	}
	return c
}

func TestDesiredChanspecCaps(t *testing.T) {
	caps := fixtureCaps(t, newFakeDev(t))
	ng, na := caps.Bands["ng"], caps.Bands["na"]
	dfsNA := na
	dfsNA.DFS = true
	dfsNA.Channels = map[int][]int{20: append([]int{52, 56}, na.Channels[20]...), 40: na.Channels[40], 80: na.Channels[80]}
	live5, live2 := chanspec{44, 80}, chanspec{2, 40}
	for _, c := range []struct {
		name   string
		band   string
		r      Radio
		live   chanspec
		bc     *wl.BandCaps
		want   string
		change bool
		note   string
	}{
		{"allowed", "na", Radio{Channel: 36, Width: 80}, live5, &na, "36/80", true, ""},
		{"ng 13 not in US: auto keeps live", "ng", Radio{Channel: 13, Width: 40}, live2, &ng, "2l", false, "channel 13 is not allowed"},
		{"ng 13 not in US: auto, width still applied", "ng", Radio{Channel: 13, Width: 20}, live2, &ng, "2", true, "channel 13 is not allowed"},
		{"ng 13 auto applies the width", "ng", Radio{Channel: 13, Width: 20}, chanspec{6, 40}, &ng, "6", true, "auto"},
		{"DFS without DFS: auto", "na", Radio{Channel: 52, Width: 80}, live5, &na, "44/80", false, "channel 52 is not allowed"},
		{"DFS listed but flag off: auto", "na", Radio{Channel: 52, Width: 80}, live5, func() *wl.BandCaps { b := dfsNA; b.DFS = false; return &b }(), "44/80", false, "not allowed"},
		{"DFS allowed at 20, not 80: narrowed", "na", Radio{Channel: 52, Width: 80}, live5, &dfsNA, "52", true, "not allowed at 80 MHz here: 20 MHz"},
		{"ng 11 at 40 is listed (11u)", "ng", Radio{Channel: 11, Width: 40}, live2, &ng, "11u", true, ""},
		{"ng 1 at 40 not listed: 20", "ng", Radio{Channel: 1, Width: 40}, live2, &wl.BandCaps{Channels: map[int][]int{20: {1, 6, 11}, 40: {6}}}, "1", true, "not allowed at 40 MHz here: 20 MHz"},
		{"live channel not listed: left", "na", Radio{Channel: 0, Width: 20}, chanspec{100, 80}, &na, "100/80", false, "live channel 100"},
		// caps read with the radio at 40 MHz list no 80 MHz chanspec (the
		// driver filters by bw_cap): 80 is unknown there, not forbidden
		{"80 not listable at read time: applied", "na", Radio{Channel: 149, Width: 80}, chanspec{149, 40},
			&wl.BandCaps{Channels: map[int][]int{20: {36, 149}, 40: {36, 149}}, MaxListedWidth: 40}, "149/80", true, ""},
		{"80 listable and absent: narrowed", "na", Radio{Channel: 149, Width: 80}, chanspec{149, 40},
			&wl.BandCaps{Channels: map[int][]int{20: {36, 149}, 40: {36, 149}}, MaxListedWidth: 80}, "149l", false, "not allowed at 80 MHz here: 40 MHz"},
		{"no caps: static table only", "ng", Radio{Channel: 13, Width: 20}, live2, nil, "13", true, ""},
	} {
		cs, ch, notes := desiredChanspec(c.band, c.r, c.live, c.bc)
		if cs.String() != c.want || ch != c.change {
			t.Errorf("%s: got %s/%t, want %s/%t (%q)", c.name, cs, ch, c.want, c.change, notes)
		}
		if n := strings.Join(notes, "\n"); c.note != "" && !strings.Contains(n, c.note) {
			t.Errorf("%s: notes %q lack %q", c.name, n, c.note)
		}
	}
}

// With Options.Caps, Plan never sets a channel the driver does not list:
// no apply-then-rollback for it.
func TestPlanClampsToCaps(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	caps := fixtureCaps(t, f)
	a := newTestApplier(f, false)
	a.o.Caps = func(context.Context) (wl.Caps, error) { return caps, nil }
	d := twoSSIDs()
	d.Radios["ng"] = Radio{Enabled: true, Channel: 13, Width: 20}
	d.Radios["na"] = Radio{Enabled: true, Channel: 100, Width: 80}
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	s := p.String()
	if strings.Contains(s, "chanspec 13") || strings.Contains(s, "chanspec 100") {
		t.Fatalf("plan sets a channel outside the caps:\n%s", s)
	}
	if !strings.Contains(s, "wl -i wl0 chanspec 2") { // auto + 20 MHz on the live channel 2
		t.Errorf("ng width not applied on the live channel:\n%s", s)
	}
	for _, n := range []string{"channel 13 is not allowed", "channel 100 is not allowed"} {
		if !strings.Contains(s, n) {
			t.Errorf("no note %q:\n%s", n, s)
		}
	}

	// Caps for another country than the one in force: not used.
	d.Country = "CA"
	if p, _ = a.Plan(ctx, d); !strings.Contains(p.String(), `caps are for country "US", not "CA"`) || !strings.Contains(p.String(), "chanspec 13") {
		t.Errorf("caps for US used for CA:\n%s", p)
	}
	// Caps unreadable: noted, static table.
	a.o.Caps = func(context.Context) (wl.Caps, error) { return wl.Caps{}, errors.New("boom") }
	d.Country = "US"
	if p, _ = a.Plan(ctx, d); !strings.Contains(p.String(), "hardware caps unavailable") {
		t.Errorf("no caps error note:\n%s", p)
	}
}

// A Desired that failed and rolled back is not applied again: no second
// Wi-Fi outage per agent cycle.
func TestApplyRefusesFailedDesired(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	failing := true
	f.failOn = func(argv []string) bool {
		return failing && argv[0] == "hostapd" && strings.Contains(argv[len(argv)-1], "hapd-wl1")
	}
	d := twoSSIDs()
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, p); err == nil || errors.Is(err, ErrDesiredFailed) {
		t.Fatalf("first Apply = %v", err)
	}
	// Same Desired, re-planned as the agent would: refused, nothing run.
	p, _ = a.Plan(ctx, d)
	f.reset()
	err = a.Apply(ctx, p)
	if !errors.Is(err, ErrDesiredFailed) {
		t.Fatalf("second Apply = %v, want ErrDesiredFailed", err)
	}
	if m := f.mutating(); len(m) != 0 {
		t.Errorf("refused Apply ran %v", m)
	}
	if strings.Contains(err.Error(), testPSK) {
		t.Error("error leaks the passphrase")
	}
	// After ForgetFailed it runs again (and, fixed, succeeds).
	failing = false
	a.ForgetFailed()
	p, _ = a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatalf("Apply after ForgetFailed = %v", err)
	}

	// A different Desired is not refused; a success clears the memory.
	failing = true
	bad := twoSSIDs()
	bad.SSIDs[1].SSID = "Renamed"
	p, _ = a.Plan(ctx, bad)
	if err := a.Apply(ctx, p); err == nil || errors.Is(err, ErrDesiredFailed) {
		t.Fatalf("Apply(bad) = %v", err)
	}
	failing = false
	other := twoSSIDs()
	other.SSIDs[1].SSID = "Other"
	p, _ = a.Plan(ctx, other)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatalf("Apply(other) = %v", err)
	}
	p, _ = a.Plan(ctx, bad)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatalf("Apply(bad) after a success = %v, want it tried (and now passing)", err)
	}
}

// A failure caused by the caller's context is not held against the Desired.
func TestApplyCancelledNotRemembered(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	ctx, cancel := context.WithCancel(context.Background())
	p, err := a.Plan(ctx, twoSSIDs())
	if err != nil {
		t.Fatal(err)
	}
	f.failOn = func(argv []string) bool {
		if argv[0] == "hostapd" && strings.Contains(argv[len(argv)-1], "hapd-wl0") {
			cancel()
		}
		return false
	}
	if err := a.Apply(ctx, p); err == nil {
		t.Fatal("cancelled Apply succeeded")
	}
	f.failOn = nil
	p, _ = a.Plan(context.Background(), twoSSIDs())
	if err := a.Apply(context.Background(), p); err != nil {
		t.Fatalf("Apply after a cancelled one = %v", err)
	}
}
