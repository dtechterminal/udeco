// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"os"
	"strings"
	"testing"
)

// On the mesh master hostapd's interface= is wlN itself and wlN1 exists only
// while TP-Link's hostapd runs: with the anchor at wl0 the SSIDs are placed
// although wl01 is missing, and the placeholder is wl0 (the .241 failure,
// 2026-11-19: "wl01 does not exist").
func TestPlacementMasterAnchor(t *testing.T) {
	d := Desired{Radios: map[string]Radio{"ng": {Enabled: true}}, SSIDs: []SSID{{ID: "a", SSID: "A", Bands: []string{"ng"}, Enabled: true, Security: SecOpen}}}
	noWl01 := func(n string) bool { return n != "wl01" && fixtureVifs(n) }
	l := planLayout(d, noWl01, layoutOpts{anyVifOnLAN: true, anchor: func(p string) string { return p }})
	rl := l.radio("ng")
	if rl.Anchor != "wl0" || len(rl.Used) != 1 || rl.Used[0].Vif == "wl0" || rl.Used[0].Vif == "wl01" {
		t.Fatalf("anchor %q used %+v notes %v", rl.Anchor, rl.Used, l.Notes)
	}
	// the satellite default is unchanged
	l = planLayout(d, fixtureVifs, layoutOpts{anyVifOnLAN: true})
	if l.radio("ng").Anchor != "wl01" {
		t.Fatalf("satellite anchor %q", l.radio("ng").Anchor)
	}
}

func TestAnchorLearned(t *testing.T) {
	a := &Applier{}
	known := func(n string) bool { return n == "wl0" || n == "wl1" || n == "wl11" }
	if g := a.anchorWith("wl0", known); g != "wl0" {
		t.Errorf("no wl01, nothing learned: %q", g)
	}
	if g := a.anchorWith("wl1", known); g != "wl11" {
		t.Errorf("wl11 exists: %q", g)
	}
	a.learnAnchor("wl1", "wl1") // TP-Link's master conf: interface=wl1
	a.learnAnchor("wl0", "wl05")
	if g := a.anchorWith("wl1", known); g != "wl1" {
		t.Errorf("learned wl1: %q", g)
	}
	if g := a.anchorWith("wl0", known); g != "wl0" {
		t.Errorf("a foreign interface= was learned: %q", g)
	}
}

// The master end to end on the fake: the takeover runs the agent's hostapd
// with interface=wl0 after an AP reset, and a failed apply hands back to
// TP-Link's /tmp/wlN_hapd.conf after the same reset.
func TestMasterTakeoverAndHandback(t *testing.T) {
	ctx := context.Background()
	f := newFakeDevLayout(t, true)
	a := newTestApplier(f, false)
	p, err := a.Plan(ctx, twoSSIDs())
	if err != nil {
		t.Fatal(err)
	}
	if reset, start := stepIndex(t, p, "wl -i wl0 ap 1"), stepIndex(t, p, "start hostapd on wl0"); reset > start {
		t.Errorf("AP reset after the hostapd start:\n%s", p)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(f.path("/tmp/udeco/hapd-wl0.conf"))
	if err != nil || !strings.Contains(string(conf), "interface=wl0\n") || strings.Contains(string(conf), "interface=wl01") {
		t.Fatalf("conf %v:\n%s", err, conf)
	}
	if err := a.Verify(ctx, twoSSIDs()); err != nil {
		t.Fatal(err)
	}
	if got := f.bridgeOf("wl02"); got != "br-lan" {
		t.Errorf("wl02 bridge %q", got)
	}

	// a failed apply on the master hands back to TP-Link's own hostapd
	f2 := newFakeDevLayout(t, true)
	a2 := newTestApplier(f2, false)
	f2.failOn = func(argv []string) bool {
		return argv[0] == "hostapd" && strings.Contains(argv[len(argv)-1], "hapd-wl1")
	}
	p2, err := a2.Plan(ctx, twoSSIDs())
	if err != nil {
		t.Fatal(err)
	}
	if err := a2.Apply(ctx, p2); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("Apply = %v, want rolled back", err)
	}
	if !f2.called("hostapd -B -P /tmp/wl0_hapd.pid /tmp/wl0_hapd.conf") || !f2.called("hostapd -B -P /tmp/wl1_hapd.pid /tmp/wl1_hapd.conf") {
		t.Error("TP-Link hostapd not restarted")
	}
	if !f2.called("wl -i wl1 ap 0") {
		t.Error("no AP reset before TP-Link's restart on wl1")
	}
	if got := f2.bridgeOf("wl02"); got != "br-lan" {
		t.Errorf("wl02 bridge after hand-back %q", got)
	}
	if got := f2.state["wl01 bss"]; got != "up" {
		t.Errorf("wl01 bss after hand-back %q", got)
	}
}
