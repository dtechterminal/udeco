// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Device-safety regressions (review of the assembled agent). Fakes only:
// nothing here touches a device or a real controller.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/decosys"
)

// After SIGTERM the worker finishes the job it is in and starts no other:
// a queued apply or a due Enforce tick must not run. select picks at random
// among ready cases, so without the ctx check about half of the runs below
// start a queued job.
func TestWorkerNoJobAfterSIGTERM(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		o.t.enforceEvery = time.Nanosecond // a tick is always due
	})
	a := h.a
	a.sys, a.wifi = h.sys, h.wifi
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // SIGTERM
	var ran atomic.Int32
	for i := 0; i < 30; i++ {
		for len(a.jobs) < cap(a.jobs) {
			a.submit("apply", func(context.Context) { ran.Add(1) })
		}
		time.Sleep(time.Microsecond) // let the ticker fire
		a.workerLoop(ctx)
	}
	if n := ran.Load(); n != 0 {
		t.Fatalf("%d queued job(s) started after SIGTERM", n)
	}
	if n := h.rec.count("enforce"); n != 0 {
		t.Fatalf("%d Enforce tick(s) ran after SIGTERM", n)
	}
}

// rebuildSys is fakeSys whose Enforce reports a TP-Link Wi-Fi rebuild in
// flight while rebuild is set (the warning text real decosys produces, see
// TestRebuildWarningMatchesDecosys).
type rebuildSys struct {
	*fakeSys
	rebuild atomic.Bool
}

func (s *rebuildSys) Enforce(ctx context.Context) (decosys.Report, error) {
	rep, err := s.fakeSys.Enforce(ctx)
	if s.rebuild.Load() {
		rep.Warnings = append(rep.Warnings, rebuildWarning+" (pid 4242: /bin/sh /etc/rc.common /etc/init.d/repacd restart); not interrupted")
	}
	return rep, err
}

// While decosys sees a TP-Link Wi-Fi rebuild (repacd restart, /sbin/wifi)
// in flight, nothing is applied and nothing is rolled back: the rebuild
// restarts TP-Link's hostapd and raises its BSSes, so an apply racing it
// would be undone (or leave two hostapds on one radio). Before the fix the
// first clean-error Enforce marked the takeover done and the queued
// provision applied at once.
func TestRebuildInFlightDefersApply(t *testing.T) {
	var rs *rebuildSys
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		o.t.enforceEvery = 10 * time.Millisecond
	})
	rs = &rebuildSys{fakeSys: h.sys}
	rs.rebuild.Store(true)
	h.a.o.newSys = func(decosys.Options) sysManager { return rs }
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	eventually(t, "enforces during the rebuild", func() bool { return h.rec.count("enforce") >= 4 && h.ctl.pending() == 0 })
	if h.rec.index("plan") >= 0 || h.rec.index("apply") >= 0 {
		t.Fatalf("Wi-Fi planned/applied during a TP-Link rebuild: %v", h.rec.list())
	}
	rs.rebuild.Store(false)
	eventually(t, "apply after the rebuild", func() bool { return h.rec.index("apply") >= 0 })

	// a rebuild seen later suspends the health check (no rollback racing
	// it). The worker is sequential: once Enforce n+2 has started, tick
	// n+1, which began after the Store, has finished.
	rs.rebuild.Store(true)
	n := h.rec.count("enforce")
	eventually(t, "a tick that saw the rebuild", func() bool { return h.rec.count("enforce") >= n+2 })
	h.wifi.mu.Lock()
	h.wifi.verify = &bcmwifi.VerifyError{Problems: []string{"TP-Link hostapd still running (/tmp/wl1.1_hapd.pid)"}}
	h.wifi.mu.Unlock()
	n = h.rec.count("enforce")
	eventually(t, "more enforces", func() bool { return h.rec.count("enforce") >= n+5 })
	h.stop()
	if h.rec.index("rollback") >= 0 {
		t.Errorf("rolled back during a TP-Link rebuild: %v", h.rec.list())
	}
	if !strings.Contains(h.logs.all(), "rebuild is still running") {
		t.Error("no log of the deferred change")
	}
}

// The agent recognises the warning real decosys emits for a rebuild.
func TestRebuildWarningMatchesDecosys(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "proc", "4242")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "cmdline"), []byte("/bin/sh\x00/etc/rc.common\x00/etc/init.d/repacd\x00restart\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := decosys.New(decosys.Options{Root: root, Run: cannedRunner{"{}"}, DryRun: true})
	rep, err := m.Enforce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range rep.Warnings {
		found = found || strings.HasPrefix(w, rebuildWarning)
	}
	if !found {
		t.Fatalf("decosys warnings %q lack %q", rep.Warnings, rebuildWarning)
	}
}

type cannedRunner struct{ out string }

func (r cannedRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte(r.out), nil
}

// seqWifi is fakeWifi whose Apply fails from the second call on (rolled
// back to last-good, still owned).
type seqWifi struct {
	*fakeWifi
	mu sync.Mutex
	n  int
}

func (w *seqWifi) Apply(ctx context.Context, p bcmwifi.Plan) error {
	w.mu.Lock()
	w.n++
	n := w.n
	w.mu.Unlock()
	if n >= 2 {
		w.fakeWifi.mu.Lock()
		w.fakeWifi.applyErr = errors.New("bcmwifi: apply: verify: wl12 bss is \"down\" (rolled back)")
		w.fakeWifi.mu.Unlock()
	}
	return w.fakeWifi.Apply(ctx, p)
}

// An apply that fails and rolls back to last-good (the agent still owns
// Wi-Fi) leaves that last-good under the health check: a later fault is
// still found and rolled back. Before the fix wifiFailed cleared the applied
// state, so the health check stopped for the rest of the run.
func TestApplyErrorKeepsHealthCheck(t *testing.T) {
	var sw *seqWifi
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		o.t.enforceEvery = 10 * time.Millisecond
	})
	sw = &seqWifi{fakeWifi: h.wifi}
	h.a.o.newWifi = func(bcmwifi.Options) wifiApplier { return sw }
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	eventually(t, "first apply", func() bool { return h.rec.count("apply") == 1 })
	h.ctl.queue(provisionReply(strings.Replace(testCfg, "ssid=net", "ssid=net-b", 1)))
	eventually(t, "second (failed) apply", func() bool { return h.rec.count("apply") == 2 })
	n := h.rec.count("verify")
	eventually(t, "health checks after the failed apply", func() bool { return h.rec.count("verify") >= n+2 })
	h.wifi.mu.Lock()
	h.wifi.verify = &bcmwifi.VerifyError{Problems: []string{"hostapd for wl1 not running"}}
	h.wifi.mu.Unlock()
	eventually(t, "rollback of the faulty last-good", func() bool { return h.rec.index("rollback") >= 0 })
	h.stop()
	if !h.a.takeover.Load() || h.rec.index("restore") >= 0 {
		t.Errorf("takeover %v calls %v", h.a.takeover.Load(), h.rec.list())
	}
}
