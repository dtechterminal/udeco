// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// topoAgent is the least agent the loop guard runs on: jobs queue up
// unrun, events are kept.
func topoAgent(t *testing.T, takeover bool) (*agent, *[]string) {
	t.Helper()
	var events []string
	rec := &recorder{}
	a := &agent{topo: newTopology(), jobs: make(chan job, 32)}
	a.o.root = t.TempDir()
	a.o.runDir = "/tmp/udeco"
	a.o.logf = func(string, ...any) {}
	a.o.now = time.Now
	a.o.run = &fakeRunner{rec: rec}
	a.o.col = &fakeCol{rec: rec}
	a.sys = &fakeSys{rec: rec}
	a.events = &eventLog{logf: func(f string, args ...any) { events = append(events, fmt.Sprintf(f, args...)) }}
	a.takeover.Store(takeover)
	return a, &events
}

func countEvents(events []string, sub string) int {
	n := 0
	for _, e := range events {
		if strings.Contains(e, sub) {
			n++
		}
	}
	return n
}

// Observe mode changes nothing on the unit: a port an earlier takeover run
// took out (and the observe-mode start's RestoreLoopGuard kept out) that
// loses carrier is not handed to a worker that never runs in observe mode,
// nor reported as back into br-lan; it stays tracked as out (it is), the
// reason is logged once, and it is forgotten once a reading shows it in
// br-lan again.
func TestObserveLoopGuardKeepsRecordedPortTruthful(t *testing.T) {
	a, events := topoAgent(t, false)
	a.topo.uplink = "eth1"
	a.topo.removed["eth0"] = "fdb"
	ports := map[string]apstate.Port{
		"eth0": {Name: "eth0", Up: false},
		"eth1": {Name: "eth1", Up: true, BridgePort: 2},
	}
	for i := 0; i < 3; i++ {
		a.loopGuard(ports, nil, time.Now())
	}
	if a.topo.removed["eth0"] != "fdb" {
		t.Errorf("eth0 no longer tracked as out of br-lan, though nothing put it back: %v", a.topo.removed)
	}
	if n := len(a.jobs); n != 0 {
		t.Errorf("%d jobs queued in observe mode", n)
	}
	if n := countEvents(*events, "back into br-lan:"); n != 0 {
		t.Errorf("claims eth0 is back: %q", *events)
	}
	if n := countEvents(*events, "observe mode changes nothing"); n != 1 {
		t.Errorf("hold logged %d times, want once: %q", n, *events)
	}
	// someone (a reboot of br-lan, an operator) put it back
	ports["eth0"] = apstate.Port{Name: "eth0", Up: true, BridgePort: 1}
	a.loopGuard(ports, nil, time.Now())
	if len(a.topo.removed) != 0 || len(a.jobs) != 0 {
		t.Errorf("removed %v jobs %d after eth0 showed up in br-lan", a.topo.removed, len(a.jobs))
	}
}

// fdbReading: both ports, the gateway's MAC learned on bridge port fdbPort.
func fdbReading(eth0Up bool, fdbPort int) *apstate.Snapshot {
	const gw = "1c:6a:1b:c5:04:c1"
	return &apstate.Snapshot{
		Gateway: "192.168.0.1",
		ARP:     map[string]string{gw: "192.168.0.1"},
		FDB:     []apstate.FDBEntry{{MAC: gw, Port: fdbPort}},
		Ports: []apstate.Port{
			{Name: "eth0", Up: eth0Up, BridgePort: 1},
			{Name: "eth1", Up: true, BridgePort: 2},
		},
	}
}

// When the uplink moves, the gateway's MAC learned on the old uplink is no
// loop evidence: a port that was the uplink a few seconds ago and regains
// carrier (a client cabled to it) must not be taken out of br-lan.
func TestUplinkMoveForgetsOldUplinkFDB(t *testing.T) {
	a, events := topoAgent(t, true)
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	a.o.now = func() time.Time { return now }
	a.observeReading(fdbReading(true, 1), map[string]any{})
	if a.topo.uplink != "eth0" {
		t.Fatalf("uplink %q, want eth0", a.topo.uplink)
	}
	now = now.Add(5 * time.Second)
	a.observeReading(fdbReading(false, 2), map[string]any{}) // cable moved to eth1
	if a.topo.uplink != "eth1" {
		t.Fatalf("uplink %q, want eth1", a.topo.uplink)
	}
	now = now.Add(5 * time.Second)
	a.observeReading(fdbReading(true, 2), map[string]any{}) // a client on eth0
	if len(a.topo.removed) != 0 || len(a.jobs) != 0 {
		t.Errorf("eth0 taken out on the old uplink's FDB entry: removed %v jobs %d events %q", a.topo.removed, len(a.jobs), *events)
	}
}

// A port put back by someone else is taken out again once: while that
// delif is queued (the worker busy), later readings, which still show the
// port in br-lan, queue nothing more; once the job ran, a re-add is caught
// again. The same holds right after the first take-out.
func TestLoopGuardDelifQueuedOnce(t *testing.T) {
	a, events := topoAgent(t, true)
	a.topo.uplink = "eth1"
	ports := map[string]apstate.Port{
		"eth0": {Name: "eth0", Up: true, BridgePort: 1},
		"eth1": {Name: "eth1", Up: true, BridgePort: 2},
	}
	lldp := []string{"eth0", "eth1"}
	for i := 0; i < 4; i++ {
		a.loopGuard(ports, lldp, time.Now())
	}
	if n := len(a.jobs); n != 1 {
		t.Fatalf("%d delif jobs queued, want 1", n)
	}
	if n := countEvents(*events, "by someone else"); n != 0 {
		t.Errorf("our own pending delif reported as someone else's re-add: %q", *events)
	}
	j := <-a.jobs
	j.fn(context.Background())
	// netifd re-adds it
	for i := 0; i < 4; i++ {
		a.loopGuard(ports, lldp, time.Now())
	}
	if n := len(a.jobs); n != 1 {
		t.Errorf("%d delif jobs queued after the re-add, want 1", n)
	}
	if n := countEvents(*events, "by someone else"); n != 1 {
		t.Errorf("re-add logged %d times, want once: %q", n, *events)
	}
}
