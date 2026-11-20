// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
)

// planHas: a step of p contains s.
func planHas(p Plan, s string) bool {
	for _, st := range p.Steps {
		if strings.Contains(st.String(), s) {
			return true
		}
	}
	return false
}

// India runs as IN/288 (80 MHz and DFS on 5 GHz); the plan after the apply
// is empty.
func TestCountryIndia(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	d.Country = "IN"
	p, _ := a.Plan(ctx, d)
	for _, r := range []string{"wl0", "wl1"} {
		if !planHas(p, "wl -i "+r+" country IN/288") {
			t.Fatalf("plan:\n%s", p)
		}
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if p2, _ := a.Plan(ctx, d); planHas(p2, "country") {
		t.Fatalf("second plan:\n%s", p2)
	}
}

// A driver that refuses IN/288 gets IN (its own rev) instead of failing
// the apply, and the plans after it do not try IN/288 again.
func TestCountryIndiaFallback(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	f.failOn = func(argv []string) bool { return slices.Contains(argv, "IN/288") }
	f.failOut = "wl: Bad Channel"
	a := newTestApplier(f, false)
	d := twoSSIDs()
	d.Country = "IN"
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got := f.state["wl1 country"]; !strings.HasPrefix(got, "IN ") {
		t.Fatalf("wl1 country %q", got)
	}
	p2, _ := a.Plan(ctx, d)
	if planHas(p2, "country") || !noteHas(p2, "IN/288 refused") {
		t.Fatalf("second plan:\n%s\nnotes %q", p2, p2.Notes)
	}
}

// A DFS channel: 802.11h on before the chanspec in the same radio down,
// hostapd's conf names a non-DFS channel (wl owns the channel; hostapd
// must not run its own channel availability check).
func TestDFSChannel(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	d.Country = "US"
	d.Radios["na"] = Radio{Enabled: true, Channel: 100, Width: 80}
	p, _ := a.Plan(ctx, d)
	down, sp, cs, up := stepIndex(t, p, "wl -i wl1 down"), stepIndex(t, p, "wl -i wl1 spect 1"), stepIndex(t, p, "wl -i wl1 chanspec 100/80"), stepIndex(t, p, "wl -i wl1 up")
	if !(down < sp && sp < cs && cs < up) {
		t.Errorf("order down %d spect %d chanspec %d up %d", down, sp, cs, up)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	conf, _ := os.ReadFile(f.path("/tmp/udeco/hapd-wl1.conf"))
	if !strings.Contains(string(conf), "\nchannel=36\n") || !strings.Contains(string(conf), "ieee80211h=1") {
		t.Errorf("conf:\n%s", conf)
	}
	if p2, _ := a.Plan(ctx, d); !p2.Empty() {
		t.Fatalf("second plan:\n%s", p2)
	}
}

const (
	cacStatus = "state PRE-ISM Channel Availability Check(CAC) time elapsed 3000ms radar channel cleared by DFS channel 100/80 (0xe06a)"
	ismStatus = "state In-Service Monitoring(ISM) time elapsed 75000ms radar channel cleared by DFS channel 100/80 (0xe06a)"
	nop100    = "Channel 36\tA Band\nChannel 100\tA Band, RADAR Sensitive, Passive, Temporarily Out of Service for 1795 seconds\nChannel 104\tA Band, RADAR Sensitive, Passive, Temporarily Out of Service for 1795 seconds\n"
)

func TestParseDFS(t *testing.T) {
	for in, want := range map[string]bool{cacStatus: true, ismStatus: false, "state IDLE": false,
		"state Channel Availability Check(CAC) time elapsed 10ms": true} {
		if got := parseDFSStatus(in); got != want {
			t.Errorf("%q: %v", in, got)
		}
	}
	nop := parseNOP(nop100)
	if !nop[100] || !nop[104] || nop[36] {
		t.Errorf("nop %v", nop)
	}
}

func dfsApplied(t *testing.T) (*fakeDev, *Applier, Desired) {
	t.Helper()
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	d.Country = "US"
	d.Radios["na"] = Radio{Enabled: true, Channel: 100, Width: 80}
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	return f, a, d
}

// During the channel availability check (about 60 s, the BSS does not
// beacon) Verify passes and Tick restarts nothing; after it, Tick repairs.
func TestDFSCAC(t *testing.T) {
	ctx := context.Background()
	f, a, d := dfsApplied(t)
	f.state["wl1 dfs_status"] = cacStatus
	f.state["wl12 bss"] = "down"
	if err := a.Verify(ctx, d); err != nil {
		t.Errorf("Verify during CAC: %v", err)
	}
	f.state["wl12 dwds"] = "1"
	f.reset()
	r, err := a.Tick(ctx)
	if err != nil || r.NeedsApply || f.called("wl -i wl1 down") {
		t.Fatalf("tick during CAC: %+v %v (radio restarted %v)", r, err, f.called("wl -i wl1 down"))
	}
	f.state["wl1 dfs_status"] = ismStatus
	f.state["wl12 bss"] = "up"
	if r, err := a.Tick(ctx); err != nil || r.NeedsApply || f.state["wl12 dwds"] != "0" {
		t.Fatalf("tick after CAC: %+v %v dwds %q", r, err, f.state["wl12 dwds"])
	}
}

// Radar: the driver leaves the DFS channel (its non-occupancy list holds
// it). The agent follows the move, reports it once, and the controller's
// dfs-reset goes back once the channel is usable again.
func TestRadarMove(t *testing.T) {
	ctx := context.Background()
	f, a, d := dfsApplied(t)
	f.state["wl1 chanspec"] = "36/80"
	f.state["wl1 chan_info"] = nop100
	f.reset()
	r, err := a.Tick(ctx)
	if err != nil || r.NeedsApply {
		t.Fatalf("tick: %+v %v", r, err)
	}
	if len(r.Radar) != 1 || r.Radar[0].Band != "na" || r.Radar[0].Channel != 100 || r.Radar[0].To != "36/80" {
		t.Fatalf("radar %+v", r.Radar)
	}
	if f.called("chanspec 100/80") {
		t.Error("moved back onto the radar channel")
	}
	if r2, _ := a.Tick(ctx); len(r2.Radar) != 0 || r2.NeedsApply {
		t.Errorf("second tick %+v", r2)
	}
	p, _ := a.Plan(ctx, d)
	if !p.Empty() || !noteHas(p, "radar") {
		t.Fatalf("plan:\n%s\nnotes %q", p, p.Notes)
	}
	// still in the non-occupancy period: dfs-reset waits
	if a.DFSReset(ctx) {
		t.Error("dfs-reset during the non-occupancy period")
	}
	f.state["wl1 chan_info"] = "Channel 36\tA Band\nChannel 100\tA Band, RADAR Sensitive, Passive\n"
	if !a.DFSReset(ctx) {
		t.Fatal("dfs-reset: nothing to do")
	}
	p2, _ := a.Plan(ctx, d)
	if !planHas(p2, "wl -i wl1 chanspec 100/80") {
		t.Fatalf("plan after dfs-reset:\n%s", p2)
	}
	if r3, _ := a.Tick(ctx); len(r3.Radar) != 0 {
		t.Errorf("radar re-reported after dfs-reset: %+v", r3.Radar)
	}
}

// RadioRestart: the plan takes a radio down (a full takeover, a channel
// change); a live repair does not.
func TestPlanRadioRestart(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	p, _ := a.Plan(ctx, d)
	if !p.RadioRestart() {
		t.Error("takeover plan does not restart a radio")
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	f.state["wl1 bssload"] = "0"
	if p2, _ := a.Plan(ctx, d); p2.Empty() || p2.RadioRestart() {
		t.Errorf("live repair:\n%s", p2)
	}
}
