// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

func counterAgent(t *testing.T, root string) *agent {
	t.Helper()
	a := &agent{o: options{root: root, runDir: "/tmp/udeco", logf: t.Logf}, topo: newTopology()}
	a.loadCounters()
	return a
}

func writeIfindex(t *testing.T, root, dev string, idx string) {
	t.Helper()
	p := filepath.Join(root, "sys/class/net", dev)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "ifindex"), []byte(idx+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ifRow(f map[string]any) map[string]any { return f["if_table"].([]map[string]any)[0] }

// The if_table row is the uplink port renamed eth0: when the cable moves
// from eth1 to eth0 the row's counters do not drop (the controller would
// count eth1's total again on the way back); the state survives an agent
// restart through the run dir (0600), and a reading's totals continue.
func TestIfTableMonotonicAcrossUplinkMoveAndRestart(t *testing.T) {
	root := t.TempDir()
	writeIfindex(t, root, "eth0", "8")
	writeIfindex(t, root, "eth1", "9")
	a := counterAgent(t, root)
	read := func(uptime int64, port string, rx int64) int64 {
		t.Helper()
		a.topo.uplink = port
		a.ctr.Begin(uptime)
		f := map[string]any{"if_table": []map[string]any{{"name": "eth0", "rx_bytes": rx, "tx_bytes": rx / 10}}}
		a.monoIfTable(f)
		return ifRow(f)["rx_bytes"].(int64)
	}
	v0 := read(100, "eth1", 860_000_000)
	v1 := read(110, "eth1", 860_001_000)
	v2 := read(120, "eth0", 5_000) // cable moved: eth0's first reading is a baseline
	v3 := read(130, "eth0", 7_000)
	if v0 != 860_000_000 || v1-v0 != 1000 || v2 != v1 || v3-v2 != 2000 {
		t.Errorf("rx_bytes %d %d %d %d", v0, v1, v2, v3)
	}
	a.saveCounters(time.Now(), true)
	fi, err := os.Stat(a.counterPath())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}
	b := counterAgent(t, root)
	b.topo.uplink = "eth0"
	b.ctr.Begin(140)
	f := map[string]any{"if_table": []map[string]any{{"name": "eth0", "rx_bytes": int64(9_000), "tx_bytes": int64(900)}}}
	b.monoIfTable(f)
	if got := ifRow(f)["rx_bytes"].(int64); got != v3+2000 {
		t.Errorf("after restart rx_bytes %d, want %d", got, v3+2000)
	}
}

// The agent's inform carries monotonic counters, persisted in the run dir.
func TestAgentPersistsCounters(t *testing.T) {
	h := newHarness(t, nil)
	tx := int64(1_000_000)
	h.col.snap = func() *apstate.Snapshot {
		s := testSnapshot()
		tx += 100
		s.Radios[1].VAPs[0].Stats = map[string]int64{"tx_bytes": tx}
		return s
	}
	h.start()
	eventually(t, "three informs", func() bool { return h.ctl.count() >= 3 })
	h.stop()
	b, err := os.ReadFile(filepath.Join(h.root, "tmp/udeco", counterFile))
	if err != nil {
		t.Fatal(err)
	}
	c := apstate.LoadCounters(b)
	if len(c.Acc) == 0 || len(c.Src) == 0 {
		t.Errorf("state %s", b)
	}
}
