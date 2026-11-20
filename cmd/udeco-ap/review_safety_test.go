// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dtechterminal/udeco/internal/apstate"
)

// Audit B5: netifd can bring TP-Link's lan default 192.168.0.1/22 (the
// gateway's own address) back on br-lan ahead of the lease. A reading whose
// first br-lan address is the gateway's must never become decosys's UnitIP:
// the R8a address watch keeps UnitIP and deletes every other address, so it
// would delete the real lease and keep the gateway's alias (the unit answers
// ARP for the gateway, and management is cut).
func TestGatewayAddressNeverBecomesUnitIP(t *testing.T) {
	var mu sync.Mutex
	ip, mask, reads := "192.168.0.205", "255.255.255.0", 0
	h := newHarness(t, func(c *Config, o *options) { c.Takeover = true })
	h.col.snap = func() *apstate.Snapshot {
		mu.Lock()
		defer mu.Unlock()
		reads++
		s := testSnapshot()
		s.IP, s.Netmask = ip, mask
		return s
	}
	readings := func() int {
		mu.Lock()
		defer mu.Unlock()
		return reads
	}
	h.start()
	eventually(t, "the lease handed to decosys", func() bool {
		return h.rec.index("setlan:192.168.0.1,192.168.0.0/24,192.168.0.205") >= 0
	})
	mu.Lock()
	ip, mask = "192.168.0.1", "255.255.252.0" // the gateway's address first on br-lan
	mu.Unlock()
	n := readings()
	eventually(t, "readings with the gateway's address first", func() bool { return readings() >= n+5 })
	h.stop()
	for _, c := range h.rec.list() {
		if strings.HasPrefix(c, "setlan:") && strings.HasSuffix(c, ",192.168.0.1") {
			t.Fatalf("the gateway's own address was handed to decosys as the unit's lease: %s", c)
		}
	}
	if got := h.sys.lan.UnitIP; got != "192.168.0.205" {
		t.Errorf("decosys UnitIP %q, want the last real lease 192.168.0.205", got)
	}
	if n := strings.Count(h.logs.all(), "not taken as the unit's lease"); n != 1 {
		t.Errorf("refusal logged %d times, want once", n)
	}
}

// R9 across an agent restart: a port the loop guard took out stays out of
// br-lan when the agent restarts (crash, deploy, R4 exit). The new agent must
// still know it took it out, or it never brings it back: FDB evidence is not
// seen on a port outside br-lan, and once that port carries the only cable
// (the old uplink unplugged) the unit has no bridged uplink at all.
func TestLoopGuardSurvivesRestart(t *testing.T) {
	var mu sync.Mutex
	eth1Up := true
	snap := func() *apstate.Snapshot {
		mu.Lock()
		defer mu.Unlock()
		s := twoPorts(true, false) // eth0: carrier, out of br-lan (an earlier run's delif)
		s.Ports[1].Up = eth1Up
		return s
	}
	h := newHarness(t, func(c *Config, o *options) { c.Takeover = true })
	f := filepath.Join(h.root, "tmp/udeco", loopFile)
	if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte("eth0 fdb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// the record is read when the agent is built
	h2 := newHarness(t, func(c *Config, o *options) { c.Takeover = true; o.root = h.root })
	h2.col.snap = snap
	h2.start()
	n := 0
	eventually(t, "a few readings", func() bool { n++; return n > 20 && h2.rec.count("enforce") > 0 })
	if i := h2.rec.index("run:brctl addif br-lan eth0"); i >= 0 {
		t.Fatal("eth0 put back while the loop may still be there")
	}
	mu.Lock()
	eth1Up = false // the old uplink is unplugged: eth0 is the only cable now
	mu.Unlock()
	eventually(t, "eth0 back into br-lan", func() bool { return h2.rec.index("run:brctl addif br-lan eth0") >= 0 })
	eventually(t, "record cleared", func() bool {
		b, _ := os.ReadFile(f)
		return !strings.Contains(string(b), "eth0")
	})
	h2.stop()
}

// The loop guard's delif is recorded in the run directory for a restarted
// agent, and the addif clears it.
func TestLoopGuardRecord(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover = true })
	f := filepath.Join(h.root, "tmp/udeco", loopFile)
	h.a.sys = h.sys
	h.a.bridgePort(context.Background(), "eth0", "lldp", false)
	if b, _ := os.ReadFile(f); string(b) != "eth0 lldp\n" {
		t.Errorf("after delif: %q", b)
	}
	if got := loadLoopGuard(f); got["eth0"] != "lldp" {
		t.Errorf("loaded %v", got)
	}
	h.a.bridgePort(context.Background(), "eth0", "", true)
	if got := loadLoopGuard(f); len(got) != 0 {
		t.Errorf("after addif: %v", got)
	}
}
