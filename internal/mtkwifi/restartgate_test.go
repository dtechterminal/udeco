// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// hookRun is the applier's runner on a klogDev: before runs ahead of each
// command (the test probes the collector from there, mid-restart).
type hookRun struct {
	*klogDev
	before func(cmd string)
}

func (h hookRun) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if h.before != nil {
		h.before(name + " " + strings.Join(args, " "))
	}
	return h.klogDev.Run(ctx, name, args...)
}

// driverCmds are the driver probes (iwconfig, iwpriv) logged from n on.
func driverCmds(d *klogDev, n int) []string {
	var out []string
	for _, l := range d.fakeDev.log[n:] {
		if strings.HasPrefix(l, "iwconfig ") || strings.HasPrefix(l, "iwpriv ") {
			out = append(out, l)
		}
	}
	return out
}

func vapSSID(s *apstate.Snapshot, band, iface string) string {
	if r := radioOf(s, band); r != nil {
		for _, v := range r.VAPs {
			if v.Iface == iface {
				return v.SSID
			}
		}
	}
	return ""
}

// TestCollectorKeepsOffRestartingRadios: while the applier restarts the
// radios (ifconfig down/up, profiles rewritten) and for the settle time
// after the last restart, Collect, HomeScan and Scan never run iwconfig or
// iwpriv and never wait for the apply: Collect gives the last reading,
// HomeScan the last survey, Scan refuses. After the settle time the driver
// is read again.
func TestCollectorKeepsOffRestartingRadios(t *testing.T) {
	d := newKlogDev(t)
	d.prints["ra0 stainfo"] = macDump
	d.survey["ra0"] = fixture(t, "site_survey_ra0.txt")
	ck := &clock{t: time.Unix(1_000_000, 0)}
	c := newTestCollector(d, ck, false)
	fresh := newTestCollector(d, ck, true)
	ctx := context.Background()

	var probes, during int
	hr := hookRun{klogDev: d}
	a := New(Options{Root: d.root, Run: &hr, RunDir: "/tmp/udeco", StateDir: "/state", Uplink: "eth0.4.1",
		VerifyTimeout: time.Millisecond, sleep: func(context.Context, time.Duration) error { return nil }, now: ck.now})
	c.FollowRestarts(a)
	fresh.FollowRestarts(a)
	// a fresh survey that never ends (the table does not change) is cut
	// short: only whether it reaches the driver matters
	scan := func(band string) (*apstate.ScanResult, error) {
		sctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
		return fresh.Scan(sctx, band)
	}

	// before: the driver is read; the survey's baseline, then a change
	s, err := c.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(driverCmds(d, 0)) == 0 {
		t.Fatal("no driver reads before the apply")
	}
	before := vapSSID(s, "ng", "ra0")
	if before != "Example Network(2.4GHz)" {
		t.Fatalf("ra0 serves %q before the apply", before)
	}
	if _, err := c.HomeScan(ctx, "ng"); err != nil {
		t.Fatal(err)
	}
	d.survey["ra0"] = strings.Replace(d.survey["ra0"], "Neighbour00", "Neighbour0X", 1)
	res, err := c.HomeScan(ctx, "ng")
	if err != nil || len(res.BSS) == 0 {
		t.Fatalf("survey before the apply: %v, %v", res, err)
	}
	survey := len(res.BSS)

	// mid-restart: every ifconfig of the apply probes the collector, the
	// cache time run out each time
	hr.before = func(cmd string) {
		if !strings.HasPrefix(cmd, "ifconfig ") {
			return
		}
		probes++
		ck.t = ck.t.Add(defaultCacheTTL + time.Second)
		n := len(d.fakeDev.log)
		var res *apstate.ScanResult
		var herr, serr error
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = c.Collect(ctx)
			res, herr = c.HomeScan(ctx, "ng")
			_, serr = scan("na")
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("the collector waited for the apply (at %s)", cmd)
		}
		if got := driverCmds(d, n); len(got) > 0 {
			during++
			t.Errorf("at %s the collector probed the driver: %v", cmd, got)
		}
		if herr != nil || len(res.BSS) != survey {
			t.Errorf("at %s HomeScan gave %v, %v; want the last survey's %d rows", cmd, res, herr, survey)
		}
		if !errors.Is(serr, ErrRadioRestart) {
			t.Errorf("at %s Scan: %v, want ErrRadioRestart", cmd, serr)
		}
	}
	p, err := a.Plan(ctx, home())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	hr.before = nil
	if probes == 0 {
		t.Fatal("the apply restarted no radio")
	}

	// within the settle time (10 s after the last restart, past the cache
	// time): the last reading, no driver read
	ck.t = ck.t.Add(10 * time.Second)
	n := len(d.fakeDev.log)
	if s, err = c.Collect(ctx); err != nil {
		t.Fatal(err)
	}
	if res, err := c.HomeScan(ctx, "ng"); err != nil || len(res.BSS) != survey {
		t.Errorf("HomeScan while settling: %v, %v", res, err)
	}
	if got := driverCmds(d, n); len(got) > 0 {
		t.Errorf("the collector probed the driver while it settles: %v", got)
	}
	if got := vapSSID(s, "ng", "ra0"); got != before {
		t.Errorf("ra0 while settling: %q, want the last reading's %q", got, before)
	}
	if _, err := scan("ng"); !errors.Is(err, ErrRadioRestart) {
		t.Errorf("Scan while settling: %v, want ErrRadioRestart", err)
	}

	// past the settle time: the driver is read again, the new SSIDs show
	ck.t = ck.t.Add(15 * time.Second)
	n = len(d.fakeDev.log)
	if s, err = c.Collect(ctx); err != nil {
		t.Fatal(err)
	}
	if len(driverCmds(d, n)) == 0 {
		t.Errorf("no driver read after the settle time")
	}
	if got := vapSSID(s, "ng", "ra0"); got != "Example Network" {
		t.Errorf("ra0 after the settle time: %q, want Example Network", got)
	}
}

// TestRestartWaitsForReadInFlight: a driver read under way when an apply
// starts finishes before any radio command runs.
func TestRestartWaitsForReadInFlight(t *testing.T) {
	d := newKlogDev(t)
	ck := &clock{t: time.Unix(1_000_000, 0)}
	started := make(chan string, 1)
	hr := hookRun{klogDev: d, before: func(cmd string) {
		select {
		case started <- cmd:
		default:
		}
	}}
	a := New(Options{Root: d.root, Run: &hr, RunDir: "/tmp/udeco", StateDir: "/state", Uplink: "eth0.4.1",
		VerifyTimeout: time.Millisecond, sleep: func(context.Context, time.Duration) error { return nil }, now: ck.now})
	ctx := context.Background()
	p, err := a.Plan(ctx, home())
	if err != nil {
		t.Fatal(err)
	}
	done, ok := a.DriverRead()
	if !ok {
		t.Fatal("driver read refused before any restart")
	}
	applied := make(chan error, 1)
	go func() { applied <- a.Apply(ctx, p) }()
	select {
	case cmd := <-started:
		t.Fatalf("%s ran while a driver read was under way", cmd)
	case <-time.After(200 * time.Millisecond):
	}
	if _, ok := a.DriverRead(); ok {
		t.Error("a new driver read was let through while an apply waits")
	}
	done()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the apply did not go on after the read ended")
	}
	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	if _, ok := a.DriverRead(); ok {
		t.Error("driver read let through right after the restart")
	}
	ck.t = ck.t.Add(defaultSettle)
	if done, ok := a.DriverRead(); !ok {
		t.Error("driver read refused after the settle time")
	} else {
		done()
	}
}
