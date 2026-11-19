// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

var allVifs = []string{"wl01", "wl02", "wl03", "wl04", "wl05", "wl06", "wl11", "wl12", "wl13", "wl14", "wl15", "wl16"}

func applyOK(t *testing.T, a *Applier, d Desired) Plan {
	t.Helper()
	p, err := a.Plan(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	return p
}

// Scrub requirement 2: at takeover TP-Link's driver deny lists go from every
// vif, used or not, and from the primaries; they are reported as foreign.
func TestTakeoverFlushesEveryMACFilter(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	p := applyOK(t, a, twoSSIDs())
	for _, v := range []string{"wl0", "wl1", "wl01", "wl02", "wl03", "wl11", "wl12"} {
		if got := f.state[v+" macmode"]; got != "0" {
			t.Errorf("%s macmode %q after takeover, want 0", v, got)
		}
		if l := f.maclist[v]; len(l) != 0 {
			t.Errorf("%s mac list %v after takeover", v, l)
		}
	}
	// The surviving placeholder is flushed even when it read 0/empty; the
	// unused bss= vifs are gone with TP-Link's hostapd (F2).
	if !f.called("wl -i wl01 mac none") || !f.called("wl -i wl11 macmode 0") {
		t.Error("the placeholder vif was not flushed at takeover")
	}
	for _, v := range []string{"wl04", "wl05", "wl06", "wl13", "wl14", "wl15", "wl16"} {
		if f.netdevExists(v) {
			t.Errorf("unused %s still exists", v)
		}
	}
	foreign := strings.Join(p.Foreign, "\n")
	for _, w := range []string{"wl02: driver MAC filter macmode 1 with 3 entries", "wl12: driver MAC filter macmode 1 with 3 entries", "wl06: driver MAC filter macmode 1 with 0 entries"} {
		if !strings.Contains(foreign, w) {
			t.Errorf("foreign report lacks %q:\n%s", w, foreign)
		}
	}
	if !strings.Contains(foreign, "02:00:00:00:0d:01") {
		t.Errorf("foreign report does not name the entries:\n%s", foreign)
	}
}

// Scrub requirement 3: a deny list re-added behind the agent's back (the
// driver state, not drv-wlN.json, changed) is found by the next Plan and
// removed live, without restarting hostapd; Tick does the same.
func TestLiveMACFilterDriftIsRepaired(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	applyOK(t, a, d)
	f.state["wl12 macmode"] = "1"
	f.maclist["wl12"] = []string{"02:00:00:00:00:01"}
	f.state["wl01 macmode"] = "2"
	f.state["wl1 macmode"] = "1"
	f.maclist["wl1"] = []string{"02:00:00:00:00:02"}

	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if p.disruptive {
		t.Fatalf("MAC filter drift reconciles a radio:\n%s", p)
	}
	for _, w := range []string{"wl -i wl12 macmode 0", "wl -i wl12 mac none", "wl -i wl01 macmode 0", "wl -i wl1 mac none"} {
		stepIndex(t, p, w)
	}
	if strings.Contains(p.String(), "hostapd") {
		t.Errorf("drift repair touches hostapd:\n%s", p)
	}
	foreign := strings.Join(p.Foreign, "\n")
	if !strings.Contains(foreign, "wl12: driver MAC filter macmode 1 with 1 entries not set by the agent [02:00:00:00:00:01]") {
		t.Errorf("foreign:\n%s", foreign)
	}

	f.reset()
	r, err := a.Tick(ctx)
	if err != nil || r.NeedsApply || len(r.Problems) > 0 {
		t.Fatalf("Tick = %+v, %v", r, err)
	}
	if len(r.Foreign) != 3 || r.Steps == 0 {
		t.Errorf("tick report %+v", r)
	}
	if f.state["wl12 macmode"] != "0" || len(f.maclist["wl12"]) != 0 || f.state["wl01 macmode"] != "0" || len(f.maclist["wl1"]) != 0 {
		t.Error("Tick left the foreign filter in place")
	}
	if p, _ := a.Plan(ctx, d); !p.Empty() {
		t.Errorf("plan after repair not empty:\n%s", p)
	}
	// The controller's own block list is kept: it is not foreign.
	if err := a.SetBlocked(ctx, []string{"aa:bb:cc:dd:ee:ff"}); err != nil {
		t.Fatal(err)
	}
	if p, _ := a.Plan(ctx, d); !p.Empty() || len(p.Foreign) != 0 {
		t.Errorf("plan with the agent's own block list:\n%s%v", p, p.Foreign)
	}
}

// vlanSSIDs fills a radio with VLAN SSIDs so the backhaul vif carries the
// last one (R23 keeps br-lan SSIDs off it).
func vlanSSIDs(n int) Desired {
	d := Desired{Country: "US", Radios: map[string]Radio{"ng": {Enabled: true, Channel: 6, Width: 20, MaxClients: 40}}}
	for i := 0; i < n; i++ {
		d.SSIDs = append(d.SSIDs, SSID{ID: fmt.Sprintf("v%d", i), SSID: fmt.Sprintf("VLAN %d", i), Bands: []string{"ng"}, Enabled: true,
			Security: SecWPA2, Passphrase: "vlan-passphrase", VLAN: 30 + i, Hidden: i == n-1})
	}
	return d
}

// wlN1 is hostapd's interface= placeholder, never an SSID: a full radio
// of VLAN SSIDs fills wlN2..wlN6 only; wlN1 stays BSS down and unbridged,
// its dwds goes off where the driver takes it (best effort), and the
// hand-back gives it TP-Link's backhaul settings back.
func TestPlaceholderVif(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := vlanSSIDs(6)
	d.SSIDs[4].Hidden = true // on wl06
	p := applyOK(t, a, d)
	if !strings.Contains(strings.Join(p.Notes, "\n"), "ssid v5: no free vif on ng") {
		t.Errorf("6th SSID not refused: %v", p.Notes)
	}
	// dwds is set while wl01 is down and TP-Link's hostapd is gone, and
	// optional: the driver may refuse it on the persistent vif.
	dw := stepIndex(t, p, "wl -i wl01 dwds 0 [if wl01 exists] [optional]")
	if st := stepIndex(t, p, "stop hostapd from /tmp/wl0.1_hapd.pid"); st > dw {
		t.Error("placeholder dwds set before TP-Link's hostapd stopped")
	}
	for k, want := range map[string]string{"wl01 dwds": "0", "wl01 bss": "down", "wl02 closednet": "0", "wl06 bss": "up", "wl06 closednet": "1", "wl06 bss_maxassoc": "40"} {
		if got := f.state[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if f.bridgeOf("wl01") != "" || f.bridgeOf("wl06") != "br-v34" {
		t.Errorf("wl01 in %q, wl06 in %q", f.bridgeOf("wl01"), f.bridgeOf("wl06"))
	}
	if err := a.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	// 5 GHz has no SSIDs: no hostapd, only the persistent wl11 is left, down.
	for _, v := range []string{"wl12", "wl13", "wl14", "wl15", "wl16"} {
		if f.netdevExists(v) {
			t.Errorf("%s exists without a hostapd", v)
		}
	}
	if f.state["wl11 bss"] != "down" {
		t.Error("wl11 beacons")
	}
	if p, _ := a.Plan(ctx, d); !p.Empty() {
		t.Fatalf("second plan not empty:\n%s", p)
	}

	// Hand-back: TP-Link's backhaul again.
	if err := a.handback(ctx); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"wl01 dwds": "1", "wl01 closednet": "1", "wl01 bss_maxassoc": "16", "wl11 dwds": "1", "wl04 dwds": "1", "wl01 bss": "up", "wl11 bss": "up", "wl12 bss": "up"} {
		if got := f.state[k]; got != want {
			t.Errorf("after hand-back %s = %q, want %q", k, got, want)
		}
	}
	if f.bridgeOf("wl01") != "" || f.bridgeOf("wl12") != "br-lan" {
		t.Errorf("after hand-back wl01 in %q, wl12 in %q", f.bridgeOf("wl01"), f.bridgeOf("wl12"))
	}
}

// Without a baseline (RunDir lost) the hand-back still puts TP-Link's
// backhaul settings back on wlN1.
func TestHandbackWithoutBaselineRestoresBackhaul(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	f.killProc(10510, true) // TP-Link's hostapds are gone, so is the baseline
	f.killProc(10912, true)
	f.state["wl01 dwds"] = "0"
	f.state["wl01 closed"] = "0"
	if err := a.Rollback(context.Background()); !errors.Is(err, ErrNoBaseline) {
		t.Fatalf("Rollback = %v", err)
	}
	for _, w := range []string{"wl -i wl01 dwds 1", "wl -i wl01 closednet 1", "wl -i wl01 bss_maxassoc 16", "wl -i wl11 dwds 1",
		"hostapd -B -P /tmp/wl0.1_hapd.pid /tmp/wl0.1_hapd.conf", "hostapd -B -P /tmp/wl1.1_hapd.pid /tmp/wl1.1_hapd.conf"} {
		if !f.called(w) {
			t.Errorf("missing %q", w)
		}
	}
	if !f.netdevExists("wl02") || !f.netdevExists("wl16") {
		t.Error("TP-Link's vifs not back")
	}
}

// The baseline records the backhaul's dwds so a later hand-back restores
// it exactly.
func TestBaselineRecordsDWDS(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	applyOK(t, a, twoSSIDs())
	b, err := os.ReadFile(f.path("/tmp/udeco/tplink-baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{`"dwds",`, `"rateset": "1b 2b 5.5b 6 9 11b 12 18 24 36 48 54"`} {
		if !strings.Contains(string(b), w) {
			t.Errorf("baseline lacks %s:\n%s", w, b)
		}
	}
}

// Audit D8: a WDS peer bridged by TP-Link's hotplug and the placeholder
// brought back up are undone by the next Tick (the placeholder's dwds is
// left: a BSS that is down takes no WDS peer); a client vif whose dwds was
// switched on gets it off again (BSS cycled, hostapd kept).
func TestTickUndoesWDSPeer(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	applyOK(t, a, twoSSIDs())
	f.mkNetdev("wds0.1.1")
	f.addif("br-lan", "wds0.1.1")
	f.state["wl01 bss"] = "up"
	f.state["wl01 dwds"] = "1"
	f.reset()
	r, err := a.Tick(ctx)
	if err != nil || r.NeedsApply {
		t.Fatalf("Tick = %+v %v", r, err)
	}
	if f.bridgeOf("wds0.1.1") != "" {
		t.Error("WDS peer still bridged")
	}
	if f.state["wl01 bss"] != "down" {
		t.Errorf("wl01 bss %q", f.state["wl01 bss"])
	}
	if !f.called("fc flush") {
		t.Error("no flow-cache flush after unbridging")
	}
	foreign := strings.Join(r.Foreign, "\n")
	for _, w := range []string{"WDS peer wds0.1.1 in br-lan, unbridged", "wl01: unused vif was up"} {
		if !strings.Contains(foreign, w) {
			t.Errorf("tick report lacks %q:\n%s", w, foreign)
		}
	}

	// A client vif.
	f2 := newFakeDev(t)
	b := newTestApplier(f2, false)
	applyOK(t, b, vlanSSIDs(5))
	f2.state["wl06 dwds"] = "1"
	if _, err := b.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if f2.state["wl06 dwds"] != "0" || f2.state["wl06 bss"] != "up" {
		t.Errorf("used wl06 dwds %q bss %q", f2.state["wl06 dwds"], f2.state["wl06 bss"])
	}
}

// Audit D14: a vif netifd dropped from its bridge is re-added by Tick, and
// the flow cache is flushed.
func TestTickRebridgesVif(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	applyOK(t, a, twoSSIDs())
	f.delif("br-lan", "wl12")
	f.delif("br-v20", "wl03")
	f.reset()
	r, err := a.Tick(ctx)
	if err != nil || r.NeedsApply || len(r.Problems) > 0 {
		t.Fatalf("Tick = %+v %v", r, err)
	}
	if f.bridgeOf("wl12") != "br-lan" || f.bridgeOf("wl03") != "br-v20" {
		t.Errorf("not re-bridged: wl12=%q wl03=%q", f.bridgeOf("wl12"), f.bridgeOf("wl03"))
	}
	if !f.called("fc flush") {
		t.Error("no flow-cache flush")
	}
	if !strings.Contains(strings.Join(r.Foreign, "\n"), "wl12: out of br-lan") {
		t.Errorf("report %v", r.Foreign)
	}
	// Nothing left: the next Tick runs no step.
	f.reset()
	if r, _ := a.Tick(ctx); r.Steps != 0 || len(r.Foreign) != 0 {
		t.Errorf("second tick %+v", r)
	}
}

// Drift only a full apply fixes (TP-Link's hostapd back) is reported, not
// acted on.
func TestTickNeedsApply(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	if r, err := a.Tick(ctx); err != nil || r.Steps != 0 || r.NeedsApply {
		t.Fatalf("Tick before takeover = %+v %v", r, err)
	}
	applyOK(t, a, twoSSIDs())
	f.startProc(31000, &fakeHapd{argv: []string{"hostapd", "-B", "-P", "/tmp/wl1.1_hapd.pid", "/tmp/wl1.1_hapd.conf"}, pidFile: "/tmp/wl1.1_hapd.pid", ready: true})
	f.reset()
	r, err := a.Tick(ctx)
	if err != nil || !r.NeedsApply {
		t.Fatalf("Tick = %+v %v", r, err)
	}
	if m := f.mutating(); len(m) != 0 {
		t.Errorf("Tick changed things while a full apply is needed: %v", m)
	}
}
