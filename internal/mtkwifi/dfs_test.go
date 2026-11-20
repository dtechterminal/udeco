// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

func dfsHome(ch int) bcmwifi.Desired {
	d := home()
	r := d.Radios["na"]
	r.Channel = ch
	d.Radios["na"] = r
	return d
}

func dfsApplier(f *fakeDev) (*Applier, *time.Duration) {
	now := new(time.Duration)
	*now = time.Hour
	a := New(Options{Root: f.root, Run: f, RunDir: "/tmp/udeco", StateDir: "/state", Uplink: "eth0.4.1", DFS: true,
		VerifyTimeout: time.Millisecond, sleep: func(context.Context, time.Duration) error { return nil },
		mono: func() time.Duration { return *now }})
	return a, now
}

// TestDFSPlan: 52-64 only with the option; 100-144 never.
func TestDFSPlan(t *testing.T) {
	f := newFakeDev(t)
	a, _ := dfsApplier(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, dfsHome(52))
	if strings.Contains(joined(p.Notes), "channel 52") {
		t.Errorf("52 refused with DFS: %q", p.Notes)
	}
	p, _ = a.Plan(ctx, dfsHome(100))
	if !strings.Contains(joined(p.Notes), "channel 100 is not allowed") {
		t.Errorf("100 allowed: %q", p.Notes)
	}
	b := newApplier(newFakeDev(t))
	p, _ = b.Plan(ctx, dfsHome(52))
	if !strings.Contains(joined(p.Notes), "channel 52 is not allowed") {
		t.Errorf("52 allowed without DFS: %q", p.Notes)
	}
}

// TestDFSMove: from 36 to 52 the radio does not restart; after the
// settle time the region goes to 0 first, then the channel (a CAC: 90 s
// quiet); the profile carries both. Back to 36: the channel first, then
// the vendor's region.
func TestDFSMove(t *testing.T) {
	f := newFakeDev(t)
	a, now := dfsApplier(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, dfsHome(36))
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	f.na = 36
	*now += time.Minute
	n := len(f.log)
	p, _ = a.Plan(ctx, dfsHome(52))
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if r := restarts(f.log[n:]); len(r) > 0 {
		t.Errorf("restarted for a DFS move: %v", r)
	}
	got := strings.Join(f.log[n:], "\n")
	reg, ch := strings.Index(got, "iwpriv rai0 set CountryRegionABand=0"), strings.Index(got, "iwpriv rai0 set Channel=52")
	if reg < 0 || ch < 0 || reg > ch {
		t.Fatalf("region %d channel %d:\n%s", reg, ch, got)
	}
	dat := readDat(t, f, 1)
	if v, _ := getKey(dat, "CountryRegionABand"); v != "0" {
		t.Errorf("profile region %q", v)
	}
	if v, _ := getKey(dat, "Channel"); v != "52" {
		t.Errorf("profile channel %q", v)
	}
	if !a.settling() {
		t.Error("no quiet time for the CAC")
	}
	*now += 80 * time.Second
	if !a.settling() {
		t.Error("quiet time shorter than 90 s")
	}
	*now += 15 * time.Second
	if a.settling() {
		t.Error("still quiet")
	}
	if !a.OnDFS() {
		t.Error("OnDFS false on 52")
	}
	// back to 36
	n = len(f.log)
	p, _ = a.Plan(ctx, dfsHome(36))
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	got = strings.Join(f.log[n:], "\n")
	ch, reg = strings.Index(got, "iwpriv rai0 set Channel=36"), strings.Index(got, "iwpriv rai0 set CountryRegionABand=10")
	if reg < 0 || ch < 0 || ch > reg {
		t.Fatalf("channel %d region %d:\n%s", ch, reg, got)
	}
	if v, _ := getKey(readDat(t, f, 1), "CountryRegionABand"); v == "0" {
		t.Error("profile kept region 0")
	}
}

// TestDFSRadar: the driver leaving the DFS channel is a radar detection:
// reported once, the channel is out for 31 minutes (all of 52-64 at
// 80 MHz) with the moved-to channel in the profile; then the radio goes
// back. A move the driver refuses (a NOP from before the agent started)
// is no radar.
func TestDFSRadar(t *testing.T) {
	f := newFakeDev(t)
	a, now := dfsApplier(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, dfsHome(52))
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	*now += time.Minute
	if !a.settling() {
		t.Error("a restart onto a DFS channel keeps only the 20 s settle time")
	}
	*now += time.Minute // the restart's CAC
	a.Tick(ctx)
	if f.na != 52 {
		t.Fatalf("on %d", f.na)
	}
	*now += 2 * time.Minute
	a.Tick(ctx)
	if ev := a.TakeRadar(); len(ev) != 0 {
		t.Fatalf("radar %v", ev)
	}
	f.na = 149 // radar: the driver moved
	a.Tick(ctx)
	ev := a.TakeRadar()
	if len(ev) != 1 || ev[0].Channel != 52 || ev[0].MovedTo != 149 || ev[0].Freq != 5260 {
		t.Fatalf("radar %+v", ev)
	}
	if v, _ := getKey(readDat(t, f, 1), "Channel"); v != "149" {
		t.Errorf("profile channel %q", v)
	}
	n := len(f.log)
	*now += 10 * time.Minute
	a.Tick(ctx)
	if c := cmdsFrom(f, n, "iwpriv rai0 set Channel="); len(c) > 0 {
		t.Errorf("moved back during the NOP: %v", c)
	}
	if ev := a.TakeRadar(); len(ev) != 0 {
		t.Errorf("radar repeated %v", ev)
	}
	*now += 25 * time.Minute
	a.Tick(ctx)
	if c := cmdsFrom(f, n, "iwpriv rai0 set Channel=52"); len(c) != 1 || f.na != 52 {
		t.Errorf("not back after the NOP: %v", c)
	}
	if v, _ := getKey(readDat(t, f, 1), "Channel"); v != "52" {
		t.Errorf("profile channel %q", v)
	}

	// a refused move is no radar
	g := newFakeDev(t)
	b, bnow := dfsApplier(g)
	p, _ = b.Plan(ctx, dfsHome(36))
	b.Apply(ctx, p)
	g.na = 36
	*bnow += time.Minute
	g.noMove = true
	p, _ = b.Plan(ctx, dfsHome(56))
	b.Apply(ctx, p)
	*bnow += 2 * time.Minute
	b.Tick(ctx)
	if ev := b.TakeRadar(); len(ev) != 0 {
		t.Errorf("refused move reported as radar: %v", ev)
	}
	n = len(g.log)
	*bnow += time.Minute
	b.Tick(ctx)
	if c := cmdsFrom(g, n, "iwpriv rai0 set Channel=56"); len(c) > 0 {
		t.Errorf("retried at once: %v", c)
	}
}

// TestDFSCollector: with DFS the 5 GHz capability lists 52-64; a fresh
// 5 GHz scan is refused while the radio is on a DFS channel (it would
// leave the channel the CAC cleared).
func TestDFSCollector(t *testing.T) {
	d := newKlogDev(t)
	d.na = 52
	ck := &clock{t: time.Unix(1_000_000, 0)}
	c := newTestCollector(d, ck, true)
	c.o.DFS = true
	caps, _ := c.Caps(context.Background())
	if ch := caps.Bands["na"].Channels[80]; !containsInt(ch, 52) || !containsInt(ch, 64) || containsInt(ch, 100) {
		t.Errorf("80 MHz channels %v", ch)
	}
	if _, err := c.Scan(context.Background(), "na"); err == nil || !strings.Contains(err.Error(), "DFS") {
		t.Errorf("scan on 52: %v", err)
	}
	for _, l := range d.iwpriv() {
		if strings.Contains(l, "SiteSurvey") {
			t.Errorf("surveyed: %s", l)
		}
	}
	plain := newTestCollector(newKlogDev(t), ck, true)
	caps, _ = plain.Caps(context.Background())
	if containsInt(caps.Bands["na"].Channels[20], 52) {
		t.Error("52 without DFS")
	}
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
