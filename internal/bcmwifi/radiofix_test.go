// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// A radar move to a non-DFS channel other than 36 (149/80 under IN/288 at
// 80 MHz) must not change hostapd's conf: wl owns the channel, and a
// changed conf would make every Tick a NeedsApply (no repairs) and every
// provision a hostapd restart until the dfs-reset.
func TestRadarMoveTo149KeepsConf(t *testing.T) {
	ctx := context.Background()
	f, a, d := dfsApplied(t)
	f.state["wl1 chanspec"] = "149/80"
	f.state["wl1 chan_info"] = nop100
	f.state["wl12 dwds"] = "1"
	f.reset()
	r, err := a.Tick(ctx)
	if err != nil || r.NeedsApply || len(r.Problems) > 0 {
		t.Fatalf("tick after the radar move: %+v %v", r, err)
	}
	if len(r.Radar) != 1 || r.Radar[0].To != "149/80" {
		t.Fatalf("radar %+v", r.Radar)
	}
	if f.state["wl12 dwds"] != "0" {
		t.Errorf("dwds drift not repaired after the radar move: %q", f.state["wl12 dwds"])
	}
	p, _ := a.Plan(ctx, d)
	if p.RadioRestart() || !p.Empty() {
		t.Fatalf("plan after the radar move restarts a radio:\n%s", p)
	}
	conf, _ := os.ReadFile(f.path("/tmp/udeco/hapd-wl1.conf"))
	if !strings.Contains(string(conf), "\nchannel=36\n") {
		t.Errorf("conf channel changed:\n%s", conf)
	}
}

// stripBaselineIovars makes the baseline look like one an older agent
// captured (no radio-wide driver settings).
func stripBaselineIovars(t *testing.T, f *fakeDev) {
	t.Helper()
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
		delete(r.(map[string]any), "iovars")
	}
	out, _ := json.Marshal(b)
	if err := os.WriteFile(bp, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A unit already in takeover under an older agent (its baseline has no
// driver settings, and the older agent never changed them) upgraded in
// place: the hand-back still puts TP-Link's receiver desense and spect back.
func TestHandbackAfterUpgradeRestoresDesense(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	tplinkDriver(f)
	f.state["wl1 spect"] = "0"
	old := newTestApplier(f, false)
	p, _ := old.Plan(ctx, twoSSIDs())
	if err := old.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	// What the older agent left: TP-Link's driver settings untouched, a
	// baseline without them.
	tplinkDriver(f)
	f.state["wl1 spect"] = "0"
	stripBaselineIovars(t, f)
	a := newTestApplier(f, false)
	if r, err := a.Tick(ctx); err != nil || r.NeedsApply {
		t.Fatalf("tick: %+v %v", r, err)
	}
	if f.state["wl1 interference"] != "360" {
		t.Fatalf("desense not cleared by the new agent: %q", f.state["wl1 interference"])
	}
	f.state["wl1 spect"] = "1" // as a later radio down would set it
	if err := a.handback(ctx); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"wl0 interference": "361", "wl1 interference": "361", "wl1 spect": "0", "wl1 txbf_imp": "1"} {
		if f.state[k] != v {
			t.Errorf("%s = %q after hand-back, want %q", k, f.state[k], v)
		}
	}
}

// Without any reading of TP-Link's interference mode (an older baseline
// and no live reading before the agent cleared desense) the hand-back
// uses TP-Link's known 361.
func TestHandbackDesenseFallback(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	tplinkDriver(f)
	a := newTestApplier(f, false)
	p, _ := a.Plan(ctx, twoSSIDs())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	stripBaselineIovars(t, f)
	b := newTestApplier(f, false) // a new process: reads the cleared value
	if err := b.handback(ctx); err != nil {
		t.Fatal(err)
	}
	if f.state["wl1 interference"] != "361" || f.state["wl0 interference"] != "361" {
		t.Errorf("interference after hand-back: wl0 %q wl1 %q", f.state["wl0 interference"], f.state["wl1 interference"])
	}
}

// rx_desense set after an earlier run cleared desense puts it back (live,
// the baseline's mode), with no radio restart.
func TestKeepDesenseRestores(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	tplinkDriver(f)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if f.state["wl1 interference"] != "360" {
		t.Fatalf("interference %q", f.state["wl1 interference"])
	}
	b := newTestApplier(f, false)
	b.o.KeepDesense = true
	f.reset()
	r, err := b.Tick(ctx)
	if err != nil || r.NeedsApply {
		t.Fatalf("tick: %+v %v", r, err)
	}
	if f.state["wl1 interference"] != "361" || f.state["wl0 interference"] != "361" {
		t.Errorf("desense not restored: wl0 %q wl1 %q", f.state["wl0 interference"], f.state["wl1 interference"])
	}
	if f.called("wl -i wl1 down") {
		t.Error("radio restarted to restore desense")
	}
	if p2, _ := b.Plan(ctx, d); !p2.Empty() {
		t.Errorf("plan after restore:\n%s", p2)
	}
}

// oldDrvState rewrites drv-wlN.json as the previous build wrote it: rrm
// 0x0 for an SSID with 11k off, no wnm key; and the driver as it left it.
func oldDrvState(t *testing.T, f *fakeDev) {
	t.Helper()
	for _, r := range []string{"wl0", "wl1"} {
		pth := f.path("/tmp/udeco/drv-" + r + ".json")
		raw, err := os.ReadFile(pth)
		if err != nil {
			t.Fatal(err)
		}
		var drv []vifDriver
		if err := json.Unmarshal(raw, &drv); err != nil {
			t.Fatal(err)
		}
		for i, d := range drv {
			if d.NbrScan == 0 {
				drv[i].RRM = "0x0"
				f.state[d.Vif+" rrm"] = "0x0"
			}
			drv[i].WNM = ""
			f.state[d.Vif+" wnm"] = "0x1"
		}
		out, _ := json.MarshalIndent(drv, "", " ")
		if err := os.WriteFile(pth, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// After an upgrade the new rrm/wnm values ride the next radio down/up made
// for something else (as TWT); they never restart a radio by themselves.
func TestUpgradeRRMWNMRideAlong(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	oldDrvState(t, f)
	b := newTestApplier(f, false)
	p2, err := b.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if p2.RadioRestart() {
		t.Fatalf("upgrade plan restarts a radio for rrm/wnm alone:\n%s", p2)
	}
	if !noteHas(p2, "rrm 0x0 -> 0x33") {
		t.Errorf("notes %q", p2.Notes)
	}
	f.reset()
	r, err := b.Tick(ctx)
	if err != nil || r.NeedsApply {
		t.Fatalf("tick: %+v %v", r, err)
	}
	if f.state["wl12 rrm"] != "0x0" {
		t.Fatalf("rrm written without a radio down: %q", f.state["wl12 rrm"])
	}
	// a dwds repair takes the radio down: rrm and wnm ride along
	f.state["wl12 dwds"] = "1"
	if r, err := b.Tick(ctx); err != nil || r.NeedsApply {
		t.Fatalf("tick: %+v %v", r, err)
	}
	if f.state["wl12 rrm"] != "0x33" || f.state["wl12 wnm"] != "0" {
		t.Errorf("after the dwds repair: rrm %q wnm %q", f.state["wl12 rrm"], f.state["wl12 wnm"])
	}
	p3, _ := b.Plan(ctx, d)
	if noteHas(p3, "wl1") && noteHas(p3, "rrm 0x0") || !p3.Empty() && p3.RadioRestart() {
		t.Errorf("plan after the ride-along:\n%s\nnotes %q", p3, p3.Notes)
	}
}

// A chanspec move to a channel with a lower limit: the old chanspec's
// ceiling is not carried over; the move runs at no degrade, the next plan
// reads the new chanspec's target maximum and sets the preset live.
func TestTxCeilingAfterMove(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	r := d.Radios["na"]
	r.TxPowerMode = "medium"
	d.Radios["na"] = r // 44/80: target max 23.5 (fixture)
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if f.state["wl1 txpwr_degrade"] != "37" {
		t.Fatalf("degrade %q", f.state["wl1 txpwr_degrade"])
	}
	r.Channel = 149
	d.Radios["na"] = r
	p2, _ := a.Plan(ctx, d)
	if !planHas(p2, "wl -i wl1 txpwr_degrade 0") {
		t.Errorf("move plan does not measure the new chanspec at no degrade:\n%s", p2)
	}
	if err := a.Apply(ctx, p2); err != nil {
		t.Fatal(err)
	}
	f.state["wl1 txpwr_target_max"] = "Maximum Tx Power Target (chanspec:0xe29b):\t18.00  18.00  "
	f.reset()
	p3, _ := a.Plan(ctx, d)
	if !planHas(p3, "wl -i wl1 txpwr_degrade 26") || p3.RadioRestart() {
		t.Fatalf("plan after the move:\n%s", p3)
	}
	if err := a.Apply(ctx, p3); err != nil {
		t.Fatal(err)
	}
	if m, dbm, ok := a.TxPower("na"); !ok || m != "medium" || dbm != 12 {
		t.Errorf("TxPower na = %s %d %v", m, dbm, ok)
	}
	// the degraded reading afterwards does not move the learnt ceiling
	for i := 0; i < 2; i++ {
		if p4, _ := a.Plan(ctx, d); !p4.Empty() {
			t.Fatalf("plan %d:\n%s", i, p4)
		}
	}
}

// The ceiling is per country too: the same chanspec under another country
// is measured again.
func TestTxCeilingPerCountry(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	r := d.Radios["na"]
	r.TxPowerMode = "medium"
	d.Radios["na"] = r
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	d.Country = "IN"
	p2, _ := a.Plan(ctx, d)
	if !planHas(p2, "wl -i wl1 txpwr_degrade 0") {
		t.Errorf("country change keeps the old country's ceiling:\n%s", p2)
	}
}

// RadioRestartBand names only the radio the plan takes down.
func TestPlanRadioRestartBand(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	p, _ := a.Plan(ctx, d)
	if !p.RadioRestartBand("ng") || !p.RadioRestartBand("na") {
		t.Error("takeover restarts both radios")
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	f.state["wl02 dwds"] = "1"
	p2, _ := a.Plan(ctx, d)
	if !p2.RadioRestartBand("ng") || p2.RadioRestartBand("na") {
		t.Errorf("dwds repair on wl02: ng %v na %v\n%s", p2.RadioRestartBand("ng"), p2.RadioRestartBand("na"), p2)
	}
}

// lastStep is the index of the last step containing sub (-1: none).
func lastStep(p Plan, sub string) int {
	n := -1
	for i, s := range p.Steps {
		if strings.Contains(s.String(), sub) {
			n = i
		}
	}
	return n
}

// The DFS chanspec is (re)applied after hostapd is up (deco-crosscheck dfs
// step 4), inside the dwds/rrm radio down/up the reconcile makes anyway:
// hostapd starts with channel 36 in its conf, and its START_AP must not
// leave the radio there.
func TestDFSChanspecAfterHostapd(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	d.Radios["na"] = Radio{Enabled: true, Channel: 100, Width: 80}
	p, _ := a.Plan(ctx, d)
	start := stepIndex(t, p, "hostapd -B -P /tmp/udeco/hapd-wl1.pid")
	down := lastStep(p, "radio wl1 down for dwds/rrm")
	cs := lastStep(p, "wl -i wl1 chanspec 100/80")
	up := lastStep(p, "radio wl1 up")
	if !(start < down && down < cs && cs < up) {
		t.Fatalf("start %d down %d chanspec %d up %d:\n%s", start, down, cs, up, p)
	}
	// a non-DFS channel: hostapd's conf names it, nothing to re-apply
	d.Radios["na"] = Radio{Enabled: true, Channel: 44, Width: 80}
	g := newFakeDev(t)
	b := newTestApplier(g, false)
	p2, _ := b.Plan(ctx, d)
	if n := strings.Count(p2.String(), "wl -i wl1 chanspec"); n > 1 {
		t.Errorf("chanspec written %d times for a non-DFS channel:\n%s", n, p2)
	}
}
