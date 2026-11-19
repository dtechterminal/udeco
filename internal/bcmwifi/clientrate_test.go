// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vifOf is the vif the layout gives SSID id on band.
func vifOf(t *testing.T, a *Applier, d Desired, id, band string) string {
	t.Helper()
	a.mu.Lock()
	l := a.layout(d)
	a.mu.Unlock()
	for _, r := range l.Radios {
		for _, u := range r.Used {
			if u.SSID.ID == id && u.Band == band {
				return u.Vif
			}
		}
	}
	t.Fatalf("ssid %s not placed on %s", id, band)
	return ""
}

// A per-client limit on SSIDs without one: only that station is shaped, in
// both directions, on the vif it is associated on, and only its flows are
// flushed. Re-joining another SSID (another radio) moves the limit there.
// -1 (no entry) removes it.
func TestClientRatesOnUnlimitedSSIDs(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	applyOK(t, a, d)
	main5 := vifOf(t, a, d, "a-main", "na")
	iot := vifOf(t, a, d, "b-iot", "ng")
	f.state[main5+" assoclist"] = "assoclist " + strings.ToUpper(sta1) + "\nassoclist " + strings.ToUpper(sta2)
	f.reset()
	f.tcCalls = nil
	n, err := a.SetClientRates(ctx, map[string]RateLimit{strings.ToUpper(sta1): {DownKbps: 3000, UpKbps: 500}})
	if n != 1 || err != nil {
		t.Fatalf("SetClientRates = %d, %v", n, err)
	}
	for _, w := range []string{
		"qdisc add dev " + main5 + " root handle 1: htb default 1",
		"class add dev " + main5 + " parent 1: classid 1:10 htb rate 3000kbit ceil 3000kbit",
		"filter add dev " + main5 + " parent 1: protocol all prio 1 handle 800::10 u32 match ether dst " + sta1 + " classid 1:10",
		"qdisc add dev ifb1 root handle 1: htb default 1",
		"class add dev ifb1 parent 1: classid 1:10 htb rate 500kbit ceil 500kbit",
		"filter add dev ifb1 parent 1: protocol all prio 1 handle 800::10 u32 match ether src " + sta1 + " classid 1:10",
		"filter add dev " + main5 + " parent ffff: protocol all prio 1 handle 800::10 u32 match ether src " + sta1 + " action mirred egress redirect dev ifb1",
	} {
		if !f.tcCalled(w) {
			t.Errorf("missing tc %q", w)
		}
	}
	// the other station, the backhaul, the 2.4 GHz side and TP-Link's
	// br-lan are left alone; no match-all
	for _, bad := range []string{sta2, "dev wl01", "dev wl11", "dev ifb0", "dev br-lan", "u32 0 0"} {
		if f.tcCalled(bad) {
			t.Errorf("tc call with %q", bad)
		}
	}
	if !f.called("fc flush --mac "+sta1) || f.called("fc flush --mac "+sta2) {
		t.Error("flow flush not limited to the limited station")
	}
	// Idle: nothing changes.
	f.tcCalls = nil
	if n, err := a.SyncRateLimits(ctx); n != 0 || err != nil {
		t.Errorf("idle sync = %d, %v", n, err)
	}
	for _, c := range f.tcCalls {
		if c[1] != "show" {
			t.Errorf("idle sync ran tc %v", c)
		}
	}
	// sta1 re-joins another SSID on the other radio: the limit follows it
	// at the next sync (Tick), and the old vif's tree goes.
	f.state[main5+" assoclist"] = "assoclist " + strings.ToUpper(sta2)
	f.state[iot+" assoclist"] = "assoclist " + strings.ToUpper(sta1)
	f.tcCalls = nil
	r, err := a.Tick(ctx)
	if err != nil || len(r.Problems) > 0 || r.RateLimitChanges != 1 {
		t.Fatalf("Tick %+v %v", r, err)
	}
	for _, w := range []string{
		"class add dev " + iot + " parent 1: classid 1:10 htb rate 3000kbit ceil 3000kbit",
		"class add dev ifb0 parent 1: classid 1:10 htb rate 500kbit ceil 500kbit",
		"filter add dev " + iot + " parent ffff: protocol all prio 1 handle 800::10 u32 match ether src " + sta1 + " action mirred egress redirect dev ifb0",
		"qdisc del dev " + main5 + " root",
		"qdisc del dev " + main5 + " ingress",
		"qdisc del dev ifb1 root",
	} {
		if !f.tcCalled(w) {
			t.Errorf("missing tc %q", w)
		}
	}
	// The controller clears it (rate-update -1/-1: no entry): every tree goes.
	f.reset()
	if n, err := a.SetClientRates(ctx, nil); n != 1 || err != nil {
		t.Fatalf("clear = %d, %v", n, err)
	}
	for _, dev := range []string{iot, main5, "ifb0", "ifb1"} {
		if s := strings.Join(f.tc[dev], "\n"); strings.Contains(s, "htb 1:") || strings.Contains(s, "ingress") {
			t.Errorf("%s still shaped: %v", dev, f.tc[dev])
		}
	}
	if !f.called("fc flush --mac " + sta1) {
		t.Error("no flow flush after the limit was removed")
	}
}

// With a SSID-wide limit, a station's entry replaces it only in the
// directions the entry limits; the other stations keep the SSID's limit,
// and clearing the entry gives the station the SSID's limit back.
func TestClientRatesWithSSIDLimit(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := limitedDesired() // a-main 2000 down / 1000 up
	applyOK(t, a, d)
	main5 := vifOf(t, a, d, "a-main", "na")
	f.state[main5+" assoclist"] = "assoclist " + strings.ToUpper(sta1) + "\nassoclist " + strings.ToUpper(sta2)
	if _, err := a.SyncRateLimits(ctx); err != nil {
		t.Fatal(err)
	}
	f.reset()
	f.tcCalls = nil
	// sta1 (id 10 on both devices) gets 8000 down, no own upload limit
	n, err := a.SetClientRates(ctx, map[string]RateLimit{sta1: {DownKbps: 8000, UpKbps: -1}})
	if n != 1 || err != nil {
		t.Fatalf("SetClientRates = %d, %v", n, err)
	}
	if !f.tcCalled("class change dev " + main5 + " parent 1: classid 1:10 htb rate 8000kbit ceil 8000kbit") {
		t.Errorf("download limit not replaced in place: %v", f.tcCalls)
	}
	for _, c := range f.tcCalls {
		if c[1] != "show" && !(c[1] == "change" && c[3] == main5) {
			t.Errorf("unexpected tc %v (the SSID's limits must stay as they are)", c)
		}
	}
	if !f.called("fc flush --mac "+sta1) || f.called("fc flush --mac "+sta2) {
		t.Error("flow flush not limited to the station that changed")
	}
	// cleared: back to the SSID's 2000
	f.tcCalls = nil
	if n, err := a.SetClientRates(ctx, map[string]RateLimit{}); n != 1 || err != nil {
		t.Fatalf("clear = %d, %v", n, err)
	}
	if !f.tcCalled("class change dev " + main5 + " parent 1: classid 1:10 htb rate 2000kbit ceil 2000kbit") {
		t.Errorf("SSID limit not restored: %v", f.tcCalls)
	}
	// the SSID-wide limit itself still works for a station that joins
	if !strings.Contains(strings.Join(f.tc["ifb1"], "\n"), "htb 1:") {
		t.Error("ifb1 upload tree gone")
	}
}

// The list survives an agent restart (a new Applier on the same unit): the
// first Tick shapes from RunDir before the agent hands the list over again.
// A station that joins later is shaped at the next sync.
func TestClientRatesKeptAcrossRestart(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	applyOK(t, a, d)
	main5 := vifOf(t, a, d, "a-main", "na")
	if _, err := a.SetClientRates(ctx, map[string]RateLimit{sta1: {DownKbps: 4000}, "junk": {DownKbps: 1}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(f.tc[main5], "\n"), "htb 1:") {
		t.Fatal("tree built with no limited station associated")
	}
	b := newTestApplier(f, false) // restart: b reads last-good and RunDir
	f.state[main5+" assoclist"] = "assoclist " + strings.ToUpper(sta1)
	f.tcCalls = nil
	r, err := b.Tick(ctx)
	if err != nil || r.RateLimitChanges != 1 {
		t.Fatalf("Tick %+v %v", r, err)
	}
	if !f.tcCalled("class add dev " + main5 + " parent 1: classid 1:10 htb rate 4000kbit ceil 4000kbit") {
		t.Errorf("restart lost the per-client limit: %v", f.tcCalls)
	}
	if f.tcCalled("ifb") {
		t.Error("upload shaped with no upload limit")
	}
}

// Dry-run changes nothing on the unit.
func TestClientRatesDryRun(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, true)
	if _, err := a.SetClientRates(context.Background(), map[string]RateLimit{sta1: {DownKbps: 4000}}); err != nil {
		t.Fatal(err)
	}
	if a.exists(a.clientRatesPath()) {
		t.Error("dry-run wrote the list")
	}
}

func TestNormClientRates(t *testing.T) {
	got := normClientRates(map[string]RateLimit{
		"AA:BB:CC:DD:EE:01": {DownKbps: 100, UpKbps: -1},
		"aa:bb:cc:dd:ee:02": {DownKbps: -1, UpKbps: -1},
		"aa:bb:cc:dd:ee:03": {},
		"nope":              {DownKbps: 5},
	})
	if len(got) != 1 || got["aa:bb:cc:dd:ee:01"] != (RateLimit{DownKbps: 100}) {
		t.Errorf("normClientRates = %v", got)
	}
}

// A vif whose association list cannot be read keeps the per-client limits
// built on it (no teardown, no flush) while the other vifs are synced.
func TestClientRatesUnreadableVifKept(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	applyOK(t, a, d)
	main5 := vifOf(t, a, d, "a-main", "na")
	iot := vifOf(t, a, d, "b-iot", "ng")
	f.state[main5+" assoclist"] = "assoclist " + strings.ToUpper(sta1)
	if _, err := a.SetClientRates(ctx, map[string]RateLimit{sta1: {DownKbps: 3000, UpKbps: 500}, sta2: {DownKbps: 700}}); err != nil {
		t.Fatal(err)
	}
	f.failOn = func(argv []string) bool {
		return argv[0] == "wl" && strings.Join(argv[1:], " ") == "-i "+main5+" assoclist"
	}
	f.state[iot+" assoclist"] = "assoclist " + strings.ToUpper(sta2)
	f.reset()
	f.tcCalls = nil
	n, err := a.SyncRateLimits(ctx)
	if err != nil || n != 1 {
		t.Fatalf("sync = %d, %v", n, err)
	}
	for _, c := range f.tcCalls {
		if strings.Contains(strings.Join(c, " "), main5) && c[1] != "show" || c[1] == "filter" && c[2] == "del" {
			t.Errorf("tc %v on an unreadable vif's trees", c)
		}
	}
	if f.called("fc flush --mac " + sta1) {
		t.Error("kept station flushed")
	}
	if !f.tcCalled("class add dev " + iot + " parent 1: classid 1:10 htb rate 700kbit ceil 700kbit") {
		t.Errorf("readable vif not synced: %v", f.tcCalls)
	}
	if !strings.Contains(strings.Join(f.tc["ifb1"], "\n"), "htb 1:") {
		t.Error("upload tree of the unreadable vif removed")
	}
}

// A list that cannot be kept in RunDir is still the one shaped, now and at
// every Tick (the agent's log says a failure is retried at the next tick).
func TestClientRatesRunDirUnwritable(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	applyOK(t, a, d)
	main5 := vifOf(t, a, d, "a-main", "na")
	f.state[main5+" assoclist"] = "assoclist " + strings.ToUpper(sta1)
	// a directory where the file goes: the rename onto it fails
	if err := os.MkdirAll(filepath.Join(a.fsPath(a.clientRatesPath()), "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.tcCalls = nil
	if n, err := a.SetClientRates(ctx, map[string]RateLimit{sta1: {DownKbps: 3000}}); n != 1 || err != nil {
		t.Fatalf("SetClientRates = %d, %v", n, err)
	}
	if !f.tcCalled("class add dev " + main5 + " parent 1: classid 1:10 htb rate 3000kbit ceil 3000kbit") {
		t.Errorf("limit not shaped: %v", f.tcCalls)
	}
	// Tick keeps it (it does not fall back to the list it had)
	f.tcCalls = nil
	if r, err := a.Tick(ctx); err != nil || r.RateLimitChanges != 0 {
		t.Fatalf("Tick %+v %v", r, err)
	}
	if !strings.Contains(strings.Join(f.tc[main5], "\n"), "htb 1:") {
		t.Error("Tick removed the per-client limit")
	}
}
