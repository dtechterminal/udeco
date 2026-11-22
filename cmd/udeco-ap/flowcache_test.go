// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// fcWifi is the fake Wi-Fi backend with bcmwifi's RestoreFlowCache.
type fcWifi struct{ *fakeWifi }

func (w fcWifi) RestoreFlowCache(context.Context) error { w.rec.add("fc-restore"); return nil }

func writeFCOff(t *testing.T, h *harness) {
	t.Helper()
	p := filepath.Join(h.root, "tmp/udeco", bcmwifi.FlowCacheOffFile)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// An observe-mode start after a takeover run that left the flow cache off
// (RunDir/fc-off) turns it back on through a bcmwifi handle built for that
// alone; without the record nothing is built (TestObserveMode).
func TestObserveRestoresFlowCache(t *testing.T) {
	h := newHarness(t, nil)
	fw := fcWifi{h.wifi}
	h.a.o.newWifi = func(bcmwifi.Options) wifiApplier { h.built++; return fw }
	writeFCOff(t, h)
	h.ctl.queue(adoptReply)
	h.start()
	eventually(t, "restored", func() bool { return h.rec.count("fc-restore") == 1 })
	eventually(t, "replies consumed", func() bool { return h.ctl.pending() == 0 && h.ctl.count() > 1 })
	h.stop()
	if h.built != 1 || len(h.rec.list()) != 1 {
		t.Errorf("built %d, calls %v", h.built, h.rec.list())
	}
}

// jio-mtk has no flow cache: neither the observe-mode start nor the drop
// to observe touches it, record or not (and with no udeco_rl loaded
// nothing runs: TestObserveRemovesRateLimiter).
func TestFlowCacheUntouchedOnJio(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Platform, c.Model = PlatformJio, "U7LT" })
	fw := fcWifi{h.wifi}
	h.a.o.newWifi = func(bcmwifi.Options) wifiApplier { h.built++; return fw }
	writeFCOff(t, h)
	ctx := context.Background()
	h.a.observeFlowCacheRestore(ctx)
	h.a.restoreFlowCache(ctx, fw)
	if h.built != 0 || len(h.rec.list()) != 0 {
		t.Errorf("jio-mtk: built %d, calls %v", h.built, h.rec.list())
	}
	// the same on the Deco does restore
	h.a.cfg.Platform = ""
	h.a.restoreFlowCache(ctx, fw)
	if h.rec.count("fc-restore") != 1 {
		t.Errorf("deco: calls %v", h.rec.list())
	}
}

// jio-mtk: the observe-mode start and the drop to observe remove a
// udeco_rl module an earlier takeover run left loaded (its table cleared
// first); the Deco never touches it.
func TestObserveRemovesRateLimiter(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Platform, c.Model = PlatformJio, "U7LT" })
	proc := filepath.Join(h.root, "proc/udeco_rl")
	if err := os.MkdirAll(filepath.Dir(proc), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(proc, []byte("udeco_rl 1 entries=1 hwnat=live\n"), 0o600)
	ctx := context.Background()
	h.a.observeFlowCacheRestore(ctx)
	if b, _ := os.ReadFile(proc); string(b) != "clear\n" || h.rec.count("run:rmmod udeco_rl") != 1 {
		t.Errorf("observe start: proc %q, calls %v", b, h.rec.list())
	}
	os.Remove(proc) // rmmod removed it
	h.a.restoreFlowCache(ctx, h.wifi)
	if h.rec.count("run:rmmod udeco_rl") != 1 {
		t.Errorf("nothing loaded: calls %v", h.rec.list())
	}
	h.a.cfg.Platform = ""
	os.WriteFile(proc, []byte("udeco_rl 1 entries=1 hwnat=live\n"), 0o600)
	h.a.observeFlowCacheRestore(ctx)
	if h.rec.count("run:rmmod udeco_rl") != 1 {
		t.Errorf("deco: calls %v", h.rec.list())
	}
}
