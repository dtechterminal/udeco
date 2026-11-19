// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"testing"
	"time"
)

// The agent is killed (no save at loop exit) within counterEvery of a
// reading that made a new baseline (the cable moved to eth0) and of one
// that counted eth0's traffic. The restarted agent must not report less
// than the killed one did: a change a restart would not repeat is saved at
// once.
func TestCountersNoDropAfterKillInSaveWindow(t *testing.T) {
	root := t.TempDir()
	writeIfindex(t, root, "eth0", "8")
	writeIfindex(t, root, "eth1", "9")
	a := counterAgent(t, root)
	t0 := time.Unix(1_700_000_000, 0)
	read := func(a *agent, uptime int64, port string, rx int64, at time.Duration) int64 {
		t.Helper()
		a.topo.uplink = port
		a.ctr.Begin(uptime)
		f := map[string]any{"if_table": []map[string]any{{"name": "eth0", "rx_bytes": rx, "tx_bytes": rx / 10}}}
		a.monoIfTable(f)
		a.saveCounters(t0.Add(at), false)
		return ifRow(f)["rx_bytes"].(int64)
	}
	read(a, 100, "eth1", 860_000_000, 0)
	read(a, 110, "eth1", 860_001_000, 10*time.Second)
	read(a, 120, "eth0", 5_000, 20*time.Second) // baseline
	last := read(a, 130, "eth0", 2_000_000, 25*time.Second)
	// killed here; a new agent starts from the run dir
	b := counterAgent(t, root)
	if got := read(b, 140, "eth0", 2_001_000, 40*time.Second); got < last {
		t.Errorf("restarted agent reports rx_bytes %d, below the %d reported before the kill", got, last)
	}
}
