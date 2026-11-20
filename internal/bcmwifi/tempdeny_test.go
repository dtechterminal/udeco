// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// A short ban on one BSS (minimum RSSI, "restrict to 5 GHz"): the station
// goes into that vif's driver MAC filter (deny mode, which also hides the
// probe responses) and is deauthenticated from it; the stored driver state
// and hostapd's files do not change, so neither Plan nor Tick sees drift
// while it lasts. Lifting it puts the filter back.
func TestTempDeny(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	until := time.Now().Add(30 * time.Second)
	if err := a.TempDeny(ctx, "wl02", sta1, until); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("before takeover: %v", err)
	}
	d := twoSSIDs()
	applyOK(t, a, d)
	f.reset()
	if err := a.TempDeny(ctx, "wl02", strings.ToUpper(sta1), until); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"wl -i wl02 macmode 1",
		"wl -i wl02 mac " + sta1,
		"hostapd_cli -p /var/run/udeco-hostapd -i wl02 deauthenticate " + sta1,
	} {
		if !f.called(want) {
			t.Errorf("missing %q in %v", want, f.mutating())
		}
	}
	if !slices.Contains(f.maclist["wl02"], strings.ToUpper(sta1)) || len(f.maclist["wl12"]) != 0 {
		t.Fatalf("driver lists %v", f.maclist)
	}
	if f.called("hostapd_cli -p /var/run/udeco-hostapd -i wl12 deauthenticate " + sta1) {
		t.Error("deauthenticated from another BSS")
	}
	if p, err := a.Plan(ctx, d); err != nil || !p.Empty() {
		t.Fatalf("plan while banned: %v\n%s", err, p)
	}
	if r, err := a.Tick(ctx); err != nil || len(r.Foreign) != 0 || r.Steps != 0 {
		t.Fatalf("tick while banned: %+v %v", r, err)
	}
	// a block-list change keeps the ban
	if err := a.SetBlocked(ctx, []string{sta2}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.maclist["wl02"], strings.ToUpper(sta1)) {
		t.Fatalf("block list change dropped the ban: %v", f.maclist["wl02"])
	}
	if err := a.SetBlocked(ctx, nil); err != nil {
		t.Fatal(err)
	}
	// lifted
	if err := a.TempDeny(ctx, "wl02", sta1, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if len(f.maclist["wl02"]) != 0 {
		t.Fatalf("still listed: %v", f.maclist["wl02"])
	}
	if p, _ := a.Plan(ctx, d); !p.Empty() {
		t.Fatalf("plan after the ban:\n%s", p)
	}
	// not a BSS the agent serves; a bad MAC
	if err := a.TempDeny(ctx, "wl05", sta1, until); err == nil {
		t.Error("wl05 accepted")
	}
	if err := a.TempDeny(ctx, "wl02", "x", until); err == nil {
		t.Error("bad MAC accepted")
	}
	// an allow-list SSID: a deny entry in an allow-mode filter would admit
	// the station, so it is refused
	d.SSIDs[1].MACFilter = &MACFilter{Policy: "allow", MACs: []string{sta1}}
	applyOK(t, a, d)
	if err := a.TempDeny(ctx, "wl02", sta1, until); !errors.Is(err, ErrAllowList) {
		t.Fatalf("allow list: %v", err)
	}
}

// A ban the agent never lifted (it stopped) lapses: well past its end
// Plan and Tick no longer keep it.
func TestTempDenyLapses(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	now := time.Now()
	a.now = func() time.Time { return now }
	d := twoSSIDs()
	applyOK(t, a, d)
	if err := a.TempDeny(ctx, "wl02", sta1, now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30*time.Second + tempDenyGrace + time.Second)
	if _, err := a.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.maclist["wl02"]) != 0 {
		t.Fatalf("lapsed ban kept: %v", f.maclist["wl02"])
	}
}
