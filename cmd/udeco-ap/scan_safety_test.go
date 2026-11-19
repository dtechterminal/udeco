// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Scan safety (device-safety review): no scan starts or goes on in observe
// mode, while TP-Link upgrades or rebuilds its Wi-Fi, or while an apply or
// rollback of ours changes the radios. Fakes only.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

// Every spectrum band carries a Guard (run before each wl scan call) that
// stops it once the agent dropped to observe, a TP-Link upgrade or rebuild
// is in flight, or an apply or rollback runs; without one, a band already
// running when the agent hands the unit back keeps scanning for up to
// about 105 s in observe mode.
func TestSpectrumGuardStopsBand(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover = true })
	a := h.a
	g := a.spectrumRequest([]int{20}, false).Guard
	if g == nil {
		t.Fatal("no Guard on the spectrum request")
	}
	step := wl.ScanStep{Radio: "wl1", Channel: 40}
	if err := g(context.Background(), step); err != nil {
		t.Fatalf("takeover, nothing in flight: %v", err)
	}
	a.takeover.Store(false)
	if err := g(context.Background(), step); err == nil || !strings.Contains(err.Error(), "observe") {
		t.Errorf("observe mode: %v", err)
	}
	a.takeover.Store(true)
	a.wifiBusy.Store(true)
	if err := g(context.Background(), step); err == nil {
		t.Error("an apply is running: band not stopped")
	}
	a.wifiBusy.Store(false)
	a.scanHold.Store("a TP-Link firmware upgrade is in flight (x)")
	if err := g(context.Background(), step); err == nil || !strings.Contains(err.Error(), "upgrade") {
		t.Errorf("upgrade in flight: %v", err)
	}
	a.scanHold.Store("")
	if err := g(context.Background(), step); err != nil {
		t.Errorf("all clear again: %v", err)
	}
}

// A TP-Link firmware upgrade in flight (the worker's hold) refuses every
// scan command: neither the neighbour scan nor a spectrum band starts.
func TestNoScanDuringUpgrade(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover = true
		o.t.enforceEvery, o.t.fastEnforce = 5*time.Millisecond, 5*time.Millisecond
	})
	h.sys.report = decosys.Report{Guard: decosys.Guard{Upgrade: []string{"/tmp/firmware_upgrade_flag"}}}
	h.ctl.queue(adoptReply)
	h.start()
	eventually(t, "the hold", func() bool { return strings.Contains(h.logs.all(), "no Wi-Fi change until it has finished") })
	h.ctl.queue(`{"_type":"cmd","cmd":"scan"}`,
		`{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":20}`,
		`{"_type":"cmd","cmd":"spectrum-scan","spectrum-cfg":"","infinite":false}`)
	eventually(t, "three refusals", func() bool {
		return strings.Count(h.logs.all(), "skipped, a TP-Link firmware upgrade is in flight") >= 3
	})
	h.stop()
	for _, c := range []string{"scan:na", "scan:ng", "spectrum:na", "spectrum:ng"} {
		if h.rec.index(c) >= 0 {
			t.Errorf("%s during an upgrade: %v", c, h.rec.list())
		}
	}
}

// An apply and a rollback mark the radios busy for the scans while they
// run, and only then.
func TestApplyAndRollbackBlockScans(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		o.t.enforceEvery, o.t.fastEnforce = 5*time.Millisecond, 5*time.Millisecond
	})
	var mu sync.Mutex
	seen := map[string]string{}
	h.wifi.during = func(op string) {
		mu.Lock()
		seen[op] = h.a.scanBlock()
		mu.Unlock()
	}
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	eventually(t, "apply", func() bool { return h.rec.index("apply") >= 0 })
	h.wifi.mu.Lock()
	h.wifi.verify = &bcmwifi.VerifyError{Problems: []string{"test"}}
	h.wifi.mu.Unlock()
	eventually(t, "rollback", func() bool { return h.rec.index("rollback") >= 0 })
	h.stop()
	mu.Lock()
	defer mu.Unlock()
	for _, op := range []string{"apply", "rollback"} {
		if !strings.Contains(seen[op], "apply or rollback") {
			t.Errorf("during %s scanBlock = %q", op, seen[op])
		}
	}
	if why := h.a.scanBlock(); strings.Contains(why, "apply or rollback") {
		t.Errorf("still busy after the apply: %q", why)
	}
}
