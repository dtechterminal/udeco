// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

func argvOf(st []Step) string {
	var b strings.Builder
	for _, s := range st {
		b.WriteString(strings.Join(s.Argv, " ") + "\n")
	}
	return b.String()
}

// radioProfile turns TWT on with the explicit `twt enab` form (a real U6
// Pro sets twt_responder 3 on every VAP), never TP-Link's `twt 0`; off
// (config twt false) it is TP-Link's value, 0.
func TestRadioProfileTWT(t *testing.T) {
	for _, band := range []string{"ng", "na"} {
		on := argvOf(radioProfile("wl1", band, true))
		if !strings.Contains(on, "wl -i wl1 twt enab 1\n") || strings.Contains(on, "twt 0") {
			t.Errorf("%s on:\n%s", band, on)
		}
		off := argvOf(radioProfile("wl1", band, false))
		if !strings.Contains(off, "wl -i wl1 twt enab 0\n") || strings.Contains(off, "twt enab 1") {
			t.Errorf("%s off:\n%s", band, off)
		}
	}
}

// A takeover cycles each radio (dwds/rrm) anyway: TWT goes on inside that
// down/up, where the driver takes it, and the next plan is empty.
func TestTakeoverEnablesTWT(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "radio na: TWT enab 0 -> 1") {
		t.Errorf("notes %q", p.Notes)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"wl0", "wl1"} {
		if got := f.state[r+" twt"]; got != "1" {
			t.Errorf("%s twt %q, want 1", r, got)
		}
		if f.called("wl -i " + r + " twt 0") {
			t.Errorf("%s: TP-Link's twt 0 form used", r)
		}
		if f.state[r+" radio"] != "up" {
			t.Errorf("%s radio left %q", r, f.state[r+" radio"])
		}
	}
	p2, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if !p2.Empty() {
		t.Fatalf("plan after apply not empty:\n%s", p2)
	}
	if !strings.Contains(strings.Join(p2.Notes, "\n"), "radio na: TWT on (twt enab 1)") {
		t.Errorf("notes %q", p2.Notes)
	}
}

// Config twt false: TP-Link's 0, set on a radio found with TWT on, and no
// TWT write at all where it is already off.
func TestTWTOptOut(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	f.state["wl1 twt"] = "1"
	a := newTestApplier(f, false)
	a.o.NoTWT = true
	p, err := a.Plan(ctx, twoSSIDs())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got := f.state["wl1 twt"]; got != "0" {
		t.Errorf("wl1 twt %q, want 0", got)
	}
	// wl0's channel changes: its radioProfile re-asserts the off state
	if f.state["wl0 twt"] != "0" || f.called("twt enab 1") {
		t.Errorf("TWT turned on with twt false (wl0 twt %q)", f.state["wl0 twt"])
	}
	// wl1 keeps its channel: off only inside the takeover's dwds/rrm cycle
	if i, j := stepIndex(t, p, "wl -i wl1 twt enab 0"), stepIndex(t, p, "radio wl1 down for dwds/rrm"); i < j {
		t.Errorf("wl1 TWT step %d before its radio down %d", i, j)
	}
	if p, _ := a.Plan(ctx, twoSSIDs()); !strings.Contains(strings.Join(p.Notes, "\n"), "radio ng: TWT off (twt enab 0, config twt false)") {
		t.Errorf("notes %q", p.Notes)
	}
}

// An agent upgraded under a running hostapd finds TWT off: no radio
// restart for TWT alone (not by Plan, not by Tick), only a note and one
// log line per state; the next radio down/up for another reason (here a
// client vif's dwds that Tick repairs) sets it.
func TestTWTWaitsForARadioRestart(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	f.state["wl0 twt"], f.state["wl1 twt"] = "0", "0" // the old agent's driver state

	b := newTestApplier(f, false) // the new agent process
	var mu sync.Mutex
	var logs []string
	b.o.Logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	twtLines := func() []string {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for _, l := range logs {
			if strings.Contains(l, "TWT") {
				out = append(out, l)
			}
		}
		return out
	}
	f.reset()
	p2, err := b.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if !p2.Empty() {
		t.Fatalf("TWT alone planned steps:\n%s", p2)
	}
	if n := strings.Join(p2.Notes, "\n"); !strings.Contains(n, "radio na: TWT enab 0, config wants 1: set at the next radio down/up") {
		t.Errorf("notes %q", p2.Notes)
	}
	for i := 0; i < 2; i++ {
		r, err := b.Tick(ctx)
		if err != nil || r.NeedsApply || r.Steps != 0 {
			t.Fatalf("tick %d: %+v %v", i, r, err)
		}
	}
	if f.called("wl -i wl0 down") || f.called("wl -i wl1 down") || f.state["wl1 twt"] != "0" {
		t.Fatalf("radio cycled for TWT alone (twt %q)", f.state["wl1 twt"])
	}
	if l := twtLines(); len(l) != 2 || !strings.Contains(strings.Join(l, "\n"), "radio na: TWT enab 0, config wants 1") {
		t.Errorf("TWT log lines (want one per radio):\n%s", strings.Join(l, "\n"))
	}

	// a client vif's dwds drifts: Tick's radio down/up for it carries TWT
	f.state["wl12 dwds"] = "1"
	f.reset()
	if r, err := b.Tick(ctx); err != nil || r.NeedsApply || len(r.Problems) != 0 {
		t.Fatalf("tick: %+v %v", r, err)
	}
	if f.state["wl12 dwds"] != "0" || f.state["wl1 twt"] != "1" {
		t.Errorf("wl12 dwds %q, wl1 twt %q", f.state["wl12 dwds"], f.state["wl1 twt"])
	}
	if f.called("wl -i wl0 down") || f.state["wl0 twt"] != "0" {
		t.Error("wl0 cycled for wl1's dwds")
	}
	if _, err := b.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if l := twtLines(); !strings.Contains(l[len(l)-1], "radio na: TWT on (twt enab 1)") {
		t.Errorf("convergence not logged:\n%s", strings.Join(l, "\n"))
	}
}

// The hand-back restores TP-Link's TWT state: the baseline's value, else
// TP-Link's 0 (tplink_brcm.sh), inside a radio down/up while no hostapd
// runs on the radio.
func TestHandbackRestoresTWT(t *testing.T) {
	for _, c := range []struct {
		name, tplink string
		dropField    bool
		want         string
	}{
		{"baseline 0", "0", false, "0"},
		{"baseline 1", "1", false, "1"},
		{"baseline without twt", "0", true, "0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFakeDev(t)
			f.state["wl0 twt"], f.state["wl1 twt"] = c.tplink, c.tplink
			a := newTestApplier(f, false)
			p, _ := a.Plan(ctx, twoSSIDs())
			if err := a.Apply(ctx, p); err != nil {
				t.Fatal(err)
			}
			bp := f.path("/tmp/udeco/tplink-baseline.json")
			raw, err := os.ReadFile(bp)
			if err != nil {
				t.Fatal(err)
			}
			var b map[string]any
			if err := json.Unmarshal(raw, &b); err != nil {
				t.Fatal(err)
			}
			for _, r := range b["radios"].([]any) {
				m := r.(map[string]any)
				if m["twt"] != c.tplink {
					t.Errorf("baseline %s twt %v, want %q", m["primary"], m["twt"], c.tplink)
				}
				if c.dropField {
					delete(m, "twt")
				}
			}
			out, _ := json.Marshal(b)
			if err := os.WriteFile(bp, out, 0o600); err != nil {
				t.Fatal(err)
			}
			f.reset()
			if err := a.handback(ctx); err != nil {
				t.Fatal(err)
			}
			for _, r := range []string{"wl0", "wl1"} {
				if got := f.state[r+" twt"]; got != c.want {
					t.Errorf("%s twt %q after hand-back, want %q", r, got, c.want)
				}
				if f.state[r+" radio"] != "up" {
					t.Errorf("%s radio left %q", r, f.state[r+" radio"])
				}
			}
			if c.want == "1" && (f.called("twt enab 0") || f.called("twt enab 1")) {
				t.Error("TWT rewritten although it matched TP-Link's")
			}
		})
	}
}
