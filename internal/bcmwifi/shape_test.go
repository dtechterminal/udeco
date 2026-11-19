// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"strings"
	"testing"
)

const (
	sta1 = "02:00:00:00:00:a1"
	sta2 = "02:00:00:00:00:a2"
)

func limitedDesired() Desired {
	d := twoSSIDs()
	d.SSIDs[1].RateLimit = &RateLimit{DownKbps: 2000, UpKbps: 1000} // a-main on wl02 and wl12
	return d
}

func (f *fakeDev) tcCalled(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.tcCalls {
		if strings.Contains(strings.Join(c, " "), sub) {
			return true
		}
	}
	return false
}

func TestRateLimitsPerClient(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := limitedDesired()
	applyOK(t, a, d) // Apply syncs the limits once d is live (no stations yet: the vifs are new)
	f.state["wl12 assoclist"] = "assoclist " + strings.ToUpper(sta1) + "\nassoclist " + strings.ToUpper(sta2)
	if n, err := a.SyncRateLimits(ctx); n != 2 || err != nil {
		t.Fatalf("sync = %d, %v", n, err)
	}
	for _, w := range []string{
		"qdisc add dev ifb1 root handle 1: htb default 1",
		"qdisc add dev ifb1 parent 1:1 handle 1001: sfq perturb 10",
		"class add dev ifb1 parent 1: classid 1:10 htb rate 1000kbit ceil 1000kbit",
		"filter add dev ifb1 parent 1: protocol all prio 1 handle 800::10 u32 match ether src " + sta1 + " classid 1:10",
		"qdisc add dev wl12 root handle 1: htb default 1",
		"class add dev wl12 parent 1: classid 1:11 htb rate 2000kbit ceil 2000kbit",
		"qdisc add dev wl12 parent 1:11 handle 11: sfq perturb 10",
		"filter add dev wl12 parent 1: protocol all prio 1 handle 800::11 u32 match ether dst " + sta2 + " classid 1:11",
		"qdisc add dev wl12 handle ffff: ingress",
		"filter add dev wl12 parent ffff: protocol all prio 1 handle 800::10 u32 match ether src " + sta1 + " action mirred egress redirect dev ifb1",
	} {
		if !f.tcCalled(w) {
			t.Errorf("missing tc %q", w)
		}
	}
	if !f.called("ip link set ifb1 up") {
		t.Error("ifb1 not raised")
	}
	// R24: no match-all redirect, no fq_codel, TP-Link's br-lan qdisc and
	// the unlimited station-less vif left alone.
	for _, bad := range []string{"u32 0 0", "fq_codel", "dev br-lan", "dev wl02", "dev ifb0"} {
		if f.tcCalled(bad) {
			t.Errorf("tc call with %q", bad)
		}
	}
	for _, m := range []string{sta1, sta2} {
		if !f.called("fc flush --mac " + m) {
			t.Errorf("no flow flush for %s", m)
		}
	}
	// Nothing moved: nothing to do.
	f.tcCalls = nil
	if n, err := a.SyncRateLimits(ctx); n != 0 || err != nil {
		t.Errorf("idle sync = %d, %v", n, err)
	}
	for _, c := range f.tcCalls {
		if c[1] != "show" {
			t.Errorf("idle sync ran tc %v", c)
		}
	}
	// sta2 leaves: its filter and class go by handle; sta1 keeps its ids.
	f.state["wl12 assoclist"] = "assoclist " + strings.ToUpper(sta1)
	f.reset()
	if n, err := a.SyncRateLimits(ctx); n != 1 || err != nil {
		t.Fatalf("sync after leave = %d, %v", n, err)
	}
	for _, w := range []string{
		"filter del dev wl12 parent 1: protocol all prio 1 handle 800::11 u32",
		"class del dev wl12 classid 1:11",
		"filter del dev ifb1 parent 1: protocol all prio 1 handle 800::11 u32",
		"filter del dev wl12 parent ffff: protocol all prio 1 handle 800::11 u32",
	} {
		if !f.tcCalled(w) {
			t.Errorf("missing tc %q", w)
		}
	}
	if !f.called("fc flush --mac "+sta2) || f.called("fc flush --mac "+sta1) {
		t.Error("flow flush not limited to the station that changed")
	}
	// A new limit changes the class in place.
	d.SSIDs[1].RateLimit.DownKbps = 5000
	applyOK(t, a, d)
	if !f.tcCalled("class change dev wl12 parent 1: classid 1:10 htb rate 5000kbit ceil 5000kbit") {
		t.Error("rate change not applied in place")
	}
	// Last limited station gone: the trees are removed.
	f.state["wl12 assoclist"] = ""
	if _, err := a.SyncRateLimits(ctx); err != nil {
		t.Fatal(err)
	}
	for _, dev := range []string{"wl12", "ifb1"} {
		if strings.Contains(strings.Join(f.tc[dev], "\n"), "htb 1:") {
			t.Errorf("%s still shaped: %v", dev, f.tc[dev])
		}
	}
	if strings.Contains(strings.Join(f.tc["wl12"], "\n"), "ingress") {
		t.Error("wl12 ingress left")
	}
	if !strings.Contains(strings.Join(f.tc["br-lan"], "\n"), "htb 2: root") {
		t.Error("TP-Link's br-lan qdisc touched")
	}
}

// R24: every tc command is checked; a failure is reported and the device is
// rebuilt from scratch at the next sync. A tree removed by something else is
// rebuilt too.
func TestRateLimitsFailureAndRebuild(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	f.state["wl12 assoclist"] = "assoclist " + strings.ToUpper(sta1)
	f.state["wl02 assoclist"] = ""
	d := limitedDesired()
	d.SSIDs[1].RateLimit.UpKbps = 0
	applyOK(t, a, d)
	f.state["wl12 assoclist"] = "assoclist " + strings.ToUpper(sta1) + "\nassoclist " + strings.ToUpper(sta2)
	f.failOn = func(argv []string) bool {
		return argv[0] == "tc" && argv[1] == "qdisc" && argv[2] == "add" && strings.Contains(strings.Join(argv, " "), "parent 1:11")
	}
	if _, err := a.SyncRateLimits(ctx); err == nil || !strings.Contains(err.Error(), "wl12") {
		t.Fatalf("sync with a failing tc = %v", err)
	}
	f.failOn = nil
	f.tcCalls = nil
	if _, err := a.SyncRateLimits(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.tcCalled("qdisc del dev wl12 root") || !f.tcCalled("qdisc add dev wl12 root handle 1: htb default 1") {
		t.Errorf("dirty device not rebuilt: %v", f.tcCalls)
	}
	// Removed behind our back (a TP-Link qos script): rebuilt by Tick.
	f.tc["wl12"] = []string{"qdisc pfifo_fast 0: root refcnt 2 bands 3"}
	f.tcCalls = nil
	r, err := a.Tick(ctx)
	if err != nil || len(r.Problems) > 0 || r.RateLimitChanges != 2 {
		t.Fatalf("Tick %+v %v", r, err)
	}
	if !f.tcCalled("qdisc add dev wl12 root handle 1: htb default 1") {
		t.Error("tree not rebuilt")
	}
	// Hand-back removes every tree.
	if err := a.handback(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(f.tc["wl12"], "\n"), "htb 1:") {
		t.Error("tree left after hand-back")
	}
}

func TestAllocID(t *testing.T) {
	id, err := allocID(map[string]int{"a": 0x10, "b": 0x12})
	if err != nil || id != 0x11 {
		t.Errorf("allocID = %x, %v", id, err)
	}
	full := map[string]int{}
	for i := 0x10; i <= 0xfff; i++ {
		full[string(rune(i))] = i
	}
	if _, err := allocID(full); err == nil {
		t.Error("no error when full")
	}
}
