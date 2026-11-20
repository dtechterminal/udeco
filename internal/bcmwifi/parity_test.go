// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// tplinkDriver puts TP-Link's radio-wide driver settings on the fake, as
// read on the Bedroom Deco 2026-11-20 (bssload 0 from wifi_features_set,
// implicit beamforming on, 2.4 GHz vendor VHT, interference mode 361).
func tplinkDriver(f *fakeDev) {
	for _, r := range []string{"wl0", "wl1"} {
		f.state[r+" bssload"] = "0"
		f.state[r+" txbf_imp"] = "1"
		f.state[r+" rxchain_pwrsave_enable"] = "0"
		f.state[r+" radio_pwrsave_enable"] = "0"
		f.state[r+" interference"] = "361"
		f.state[r+" interference_override"] = "-1"
	}
	f.state["wl0 vht_features"] = "0x7"
}

func noteHas(p Plan, s string) bool { return strings.Contains(strings.Join(p.Notes, "\n"), s) }

// The BSS Load element follows the controller's qbssload per radio: on by
// default (the key is absent), off only when every SSID of the radio turns
// it off, on with a note when they disagree (the iovar is radio-wide).
func TestRadioBSSLoad(t *testing.T) {
	rl := func(off ...bool) *radioLayout {
		r := &radioLayout{}
		for i, o := range off {
			r.Used = append(r.Used, vifAssign{SSID: SSID{ID: string(rune('a' + i)), NoBSSLoad: o}})
		}
		return r
	}
	for _, c := range []struct {
		name string
		r    *radioLayout
		want bool
		note bool
	}{
		{"no SSID", rl(), true, false},
		{"default", rl(false, false), true, false},
		{"all off", rl(true, true), false, false},
		{"mixed", rl(true, false), true, true},
	} {
		got, n := radioBSSLoad(c.r)
		if got != c.want || (n != "") != c.note {
			t.Errorf("%s: %v %q", c.name, got, n)
		}
	}
}

// At takeover the U6 Pro's driver settings go on: BSS Load and the
// interference mode live, the radio-down ones (implicit beamforming, 2.4
// GHz vendor VHT, power save) inside the restart the takeover makes
// anyway. The plan after the apply is empty.
func TestTakeoverDriverParity(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	tplinkDriver(f)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if !noteHas(p, "radio na: driver settings to a U6 Pro's: bssload 0 -> 1, txbf_imp 1 -> 0, interference mode 361 -> 360") {
		t.Errorf("notes %q", p.Notes)
	}
	// wl1 keeps its channel: its radio-down settings ride the dwds/rrm cycle
	if i, j := stepIndex(t, p, "wl -i wl1 txbf_imp 0"), stepIndex(t, p, "radio wl1 down for dwds/rrm"); i < j {
		t.Errorf("wl1 txbf_imp step %d before its radio down %d", i, j)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"wl0 bssload": "1", "wl1 bssload": "1", "wl0 txbf_imp": "0", "wl1 txbf_imp": "0",
		"wl0 vht_features": "0x6", "wl0 interference": "360", "wl1 interference": "360",
		"wl0 rxchain_pwrsave_enable": "0", "wl1 radio_pwrsave_enable": "0",
	} {
		if got := f.state[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if f.called("wl -i wl1 vht_features") {
		t.Error("vht_features written on the 5 GHz radio")
	}
	if f.called("bssload 0") {
		t.Error("TP-Link's bssload 0 written")
	}
	p2, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if !p2.Empty() {
		t.Fatalf("plan after apply:\n%s", p2)
	}
	if !noteHas(p2, "radio na: driver settings as a U6 Pro") {
		t.Errorf("notes %q", p2.Notes)
	}
}

// Drift after the apply: BSS Load and interference are re-asserted live by
// Tick; a radio-down setting waits for a radio down/up made for something
// else, never a restart of its own.
func TestDriverParityDrift(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	tplinkDriver(f)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	f.state["wl1 bssload"] = "0"
	f.state["wl1 interference"] = "361"
	f.state["wl1 txbf_imp"] = "1"
	f.reset()
	r, err := a.Tick(ctx)
	if err != nil || r.NeedsApply {
		t.Fatalf("tick: %+v %v", r, err)
	}
	if f.state["wl1 bssload"] != "1" || f.state["wl1 interference"] != "360" {
		t.Errorf("live settings not re-asserted: bssload %q interference %q", f.state["wl1 bssload"], f.state["wl1 interference"])
	}
	if f.called("wl -i wl1 down") || f.state["wl1 txbf_imp"] != "1" {
		t.Fatalf("radio restarted for txbf_imp alone (%q)", f.state["wl1 txbf_imp"])
	}
	p2, _ := a.Plan(ctx, d)
	if !noteHas(p2, "txbf_imp 1 -> 0; the radio-down ones at the next radio down/up") {
		t.Errorf("notes %q", p2.Notes)
	}
	// a client vif's dwds drifts: Tick's radio down/up for it carries it
	f.state["wl12 dwds"] = "1"
	if r, err := a.Tick(ctx); err != nil || r.NeedsApply {
		t.Fatalf("tick: %+v %v", r, err)
	}
	if f.state["wl1 txbf_imp"] != "0" {
		t.Errorf("txbf_imp %q after the dwds repair", f.state["wl1 txbf_imp"])
	}
}

// The controller's qbssload=disabled on every SSID of a radio turns the
// element off there (live, no restart).
func TestBSSLoadOff(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	tplinkDriver(f)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	for i := range d.SSIDs {
		d.SSIDs[i].NoBSSLoad = d.SSIDs[i].ID == "b-iot" // the IoT SSID is on 2.4 GHz only
	}
	p2, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if !noteHas(p2, "radio ng: ssid b-iot: the controller turned the BSS Load element off") {
		t.Errorf("notes %q", p2.Notes)
	}
	for i := range d.SSIDs {
		d.SSIDs[i].NoBSSLoad = true
	}
	p3, _ := a.Plan(ctx, d)
	if stepIndex(t, p3, "wl -i wl0 bssload 0") < 0 || stepIndex(t, p3, "wl -i wl1 bssload 0") < 0 {
		t.Errorf("plan:\n%s", p3)
	}
}

// rx_desense (KeepDesense) leaves TP-Link's interference mitigation alone.
func TestKeepDesense(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	tplinkDriver(f)
	f.state["wl1 interference_override"] = "1"
	a := newTestApplier(f, false)
	a.o.KeepDesense = true
	p, _ := a.Plan(ctx, twoSSIDs())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if f.called("interference 360") || f.called("interference_override -1") {
		t.Error("interference mitigation written with rx_desense")
	}
	g := newFakeDev(t)
	tplinkDriver(g)
	g.state["wl1 interference_override"] = "1"
	b := newTestApplier(g, false)
	p, _ = b.Plan(ctx, twoSSIDs())
	if i, j := stepIndex(t, p, "wl -i wl1 interference_override -1"), stepIndex(t, p, "wl -i wl1 interference 360"); i < 0 || j < i {
		t.Errorf("override %d, mode %d:\n%s", i, j, p)
	}
}

// The hand-back puts TP-Link's driver settings back: the baseline's, else
// TP-Link's known ones (an older agent's baseline has no iovars).
func TestHandbackRestoresDriver(t *testing.T) {
	for _, drop := range []bool{false, true} {
		ctx := context.Background()
		f := newFakeDev(t)
		tplinkDriver(f)
		a := newTestApplier(f, false)
		p, _ := a.Plan(ctx, twoSSIDs())
		if err := a.Apply(ctx, p); err != nil {
			t.Fatal(err)
		}
		bp := f.path("/tmp/udeco/tplink-baseline.json")
		raw, _ := os.ReadFile(bp)
		var b map[string]any
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatal(err)
		}
		for _, r := range b["radios"].([]any) {
			m := r.(map[string]any)
			if m["iovars"] == nil {
				t.Fatalf("baseline %s has no iovars", m["primary"])
			}
			if drop {
				delete(m, "iovars")
			}
		}
		out, _ := json.Marshal(b)
		_ = os.WriteFile(bp, out, 0o600)
		if err := a.handback(ctx); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"wl0 bssload": "0", "wl1 bssload": "0", "wl0 txbf_imp": "1", "wl1 txbf_imp": "1",
			"wl0 vht_features": "0x7", "wl1 interference": "361"}
		if drop {
			want["wl1 interference"] = "360" // no known TP-Link value without a baseline: left alone
		}
		for k, v := range want {
			if f.state[k] != v {
				t.Errorf("drop %v: %s = %q after hand-back, want %q", drop, k, f.state[k], v)
			}
		}
		for _, r := range []string{"wl0", "wl1"} {
			if f.state[r+" radio"] != "up" {
				t.Errorf("%s radio left %q", r, f.state[r+" radio"])
			}
		}
	}
}

func TestParseInterference(t *testing.T) {
	for in, want := range map[string]int{"361": 361, "Mode 361": 361, "mode: 360 (desense)": 360,
		"All interference mitigation is enabled. (mode 3)": 3} {
		if got, ok := parseInterference(in); !ok || got != want {
			t.Errorf("%q: %d %v", in, got, ok)
		}
	}
	if _, ok := parseInterference("wl: Unsupported"); ok {
		t.Error("unsupported parsed")
	}
}
