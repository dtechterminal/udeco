// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
)

// writeLoopRecord puts an earlier run's loop-guard record under root.
func writeLoopRecord(t *testing.T, root, body string) string {
	t.Helper()
	f := filepath.Join(root, "tmp/udeco", loopFile)
	if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// The takeover decosys handle knows the loop guard's record, so
// dropToObserve's Restore puts the ports back (without it Restore leaves
// the bridge alone).
func TestLoopGuardRecordReachesDecosys(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover = true })
	h.start()
	eventually(t, "enforce", func() bool { return h.rec.count("enforce") > 0 })
	h.stop()
	if got, want := h.sopts.LoopGuardFile, "/tmp/udeco/"+loopFile; got != want {
		t.Errorf("decosys LoopGuardFile %q, want %q", got, want)
	}
}

// restoringSys is fakeSys whose Restore does what decosys.Restore does to
// the loop guard's record: the ports are back, the record is gone.
type restoringSys struct {
	*fakeSys
	record string
}

func (s restoringSys) Restore(ctx context.Context) error {
	os.Remove(s.record)
	return s.fakeSys.Restore(ctx)
}

// After dropToObserve's Restore put the loop guard's ports back, the loop
// forgets them: it no longer tracks a port as "taken out" that is in br-lan
// again (observe mode would never act on it).
func TestDropToObserveForgetsLoopGuardPorts(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover = true })
	f := writeLoopRecord(t, h.root, "eth0 fdb\n")
	h2 := newHarness(t, func(c *Config, o *options) { c.Takeover = true; o.root = h.root })
	h2.col.snap = func() *apstate.Snapshot { return twoPorts(true, false) } // eth0 out, carrier on both
	h2.a.o.newSys = func(decosys.Options) sysManager { return restoringSys{h2.sys, f} }
	if h2.a.topo.removed["eth0"] != "fdb" {
		t.Fatalf("record not loaded: %v", h2.a.topo.removed)
	}
	h2.start()
	eventually(t, "enforce", func() bool { return h2.rec.count("enforce") > 0 })
	h2.a.submit("drop", func(ctx context.Context) { h2.a.dropToObserve(ctx, "test") })
	eventually(t, "restore", func() bool { return h2.rec.index("restore") >= 0 })
	n := h2.ctl.count()
	eventually(t, "a reading after the drop", func() bool { return h2.ctl.count() > n+1 })
	h2.stop()
	if len(h2.a.topo.removed) != 0 {
		t.Errorf("still tracked as out of br-lan after Restore: %v", h2.a.topo.removed)
	}
}

// An agent that starts in observe mode (here forced) with an earlier
// takeover run's record puts those ports back into br-lan with the real
// decosys, removes the record and changes nothing else; without a record it
// builds no decosys handle at all (TestObserveMode).
func TestObserveStartPutsLoopGuardPortsBack(t *testing.T) {
	h := newHarness(t, nil)
	for _, b := range []string{"usr/sbin/brctl", "usr/bin/fc"} {
		p := filepath.Join(h.root, b)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, nil, 0o755)
	}
	f := writeLoopRecord(t, h.root, "eth0 lldp\n")
	var opts []decosys.Options
	h2 := newHarness(t, func(c *Config, o *options) {
		c.Takeover = true
		o.root = h.root
		o.forceObserve = "crash loop"
	})
	h2.a.o.newSys = func(so decosys.Options) sysManager { opts = append(opts, so); return decosys.New(so) }
	h2.col.snap = func() *apstate.Snapshot { return twoPorts(true, false) }
	h2.start()
	eventually(t, "an inform", func() bool { return h2.ctl.count() > 1 })
	h2.stop()
	if len(opts) != 1 || opts[0].LoopGuardFile != "/tmp/udeco/"+loopFile {
		t.Fatalf("decosys handles %+v", opts)
	}
	var runs []string
	for _, c := range h2.rec.list() {
		if strings.HasPrefix(c, "run:") {
			runs = append(runs, c)
		}
	}
	if want := []string{"run:/usr/sbin/brctl addif br-lan eth0", "run:/usr/bin/fc flush --if eth0"}; strings.Join(runs, "|") != strings.Join(want, "|") {
		t.Errorf("commands %q, want %q", runs, want)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("record left behind: %v", err)
	}
	if len(h2.a.topo.removed) != 0 || h2.a.takeover.Load() {
		t.Errorf("removed %v takeover %v", h2.a.topo.removed, h2.a.takeover.Load())
	}
}
