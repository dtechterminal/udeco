// SPDX-License-Identifier: GPL-2.0-or-later

package jioports

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// fakeBridger is the unit's bridge table: dev -> bridge ("" = none).
// fail makes PortToBridge(dev, vid) fail; strand leaves the device in no
// bridge when it does (brctl delif done, addif failed).
type fakeBridger struct {
	br     map[string]string
	fail   map[string]bool // "dev vid"
	strand bool
	ops    []string
}

func newFakeBridger() *fakeBridger {
	b := &fakeBridger{br: map[string]string{}, fail: map[string]bool{}}
	for p := 1; p <= 4; p++ {
		b.br[Untagged(p)] = "bdg2"
	}
	b.br["eth0.4.3"] = "br-v3" // a VLAN SSID's device on the uplink
	return b
}

func (b *fakeBridger) LANBridge() string        { return "bdg2" }
func (b *fakeBridger) BridgeOf(d string) string { return b.br[d] }
func (b *fakeBridger) Exists(d string) bool {
	_, ok := b.br[d]
	return ok
}
func (b *fakeBridger) PortToBridge(_ context.Context, dev string, vid int) error {
	if strings.HasPrefix(dev, "eth0.4") {
		return fmt.Errorf("%s is on the uplink", dev)
	}
	if b.fail[dev+" "+strconv.Itoa(vid)] {
		if b.strand {
			b.br[dev] = ""
		}
		return fmt.Errorf("brctl addif %s: failed", dev)
	}
	b.ops = append(b.ops, fmt.Sprintf("bridge %s %d", dev, vid))
	switch {
	case vid < 0:
		b.br[dev] = ""
	case vid == 0:
		b.br[dev] = "bdg2"
	default:
		b.br[dev] = "br-v" + strconv.Itoa(vid)
	}
	return nil
}
func (b *fakeBridger) EnsurePortVLAN(_ context.Context, parent string, vid int) (string, error) {
	d := parent + "." + strconv.Itoa(vid)
	b.br[d] = "br-v" + strconv.Itoa(vid)
	b.ops = append(b.ops, "vlan "+d)
	return d, nil
}
func (b *fakeBridger) DelPortVLAN(_ context.Context, dev string) error {
	if strings.HasPrefix(dev, "eth0.4") {
		return fmt.Errorf("%s is on the uplink", dev)
	}
	delete(b.br, dev)
	b.ops = append(b.ops, "del "+dev)
	return nil
}
func (b *fakeBridger) PortVLANDevs(parent string) map[int]string {
	out := map[int]string{}
	for d := range b.br {
		if v, err := strconv.Atoi(strings.TrimPrefix(d, parent+".")); err == nil && strings.HasPrefix(d, parent+".") && v > 1 {
			out[v] = d
		}
	}
	return out
}
func (b *fakeBridger) SetPortVLANs(map[int]bool)        {}
func (b *fakeBridger) PruneVLANs(context.Context) error { return nil }

func want(ports map[int]PortWant) Want { return Want{VLAN: true, Ports: ports} }

// TestApplyRollbackFailureRetried: a port whose move and rollback both
// failed sits in no bridge; the next Applies put it back on the LAN (not
// on the failed setting), say "not on the LAN" while that keeps failing,
// and leave the failed setting alone once it is back.
func TestApplyRollbackFailureRetried(t *testing.T) {
	ctx := context.Background()
	b := newFakeBridger()
	m := New(Options{B: b})
	b.fail["eth0.2.1 5"], b.fail["eth0.2.1 0"], b.strand = true, true, true
	w := want(map[int]PortWant{2: {Native: 5}})
	r := m.Apply(ctx, w)
	if r.Failed[2] == nil || b.br["eth0.2.1"] != "" {
		t.Fatalf("first apply: failed %v, port 2 in %q", r.Failed, b.br["eth0.2.1"])
	}
	for i := 0; i < 2; i++ {
		r = m.Apply(ctx, w)
		if !strings.Contains(strings.Join(r.Notes, "\n"), "port 2 is not on the LAN") || b.br["eth0.2.1"] != "" {
			t.Fatalf("retry %d: notes %q, port 2 in %q", i, r.Notes, b.br["eth0.2.1"])
		}
	}
	delete(b.fail, "eth0.2.1 0")
	r = m.Apply(ctx, w)
	if b.br["eth0.2.1"] != "bdg2" || r.Ports[2] != "native LAN" {
		t.Fatalf("put back: port 2 in %q, report %+v", b.br["eth0.2.1"], r)
	}
	ops := len(b.ops)
	r = m.Apply(ctx, w)
	if len(b.ops) != ops || !strings.Contains(strings.Join(r.Notes, "\n"), "not retried until the controller sends another setting") {
		t.Errorf("failed setting retried: ops %q notes %q", b.ops[ops:], r.Notes)
	}
	// another setting: applied
	delete(b.fail, "eth0.2.1 5")
	if r = m.Apply(ctx, want(map[int]PortWant{2: {Native: 6}})); b.br["eth0.2.1"] != "br-v6" || r.Before[2].String() != "native LAN" {
		t.Errorf("new setting: port 2 in %q, before %v", b.br["eth0.2.1"], r.Before)
	}
}

// TestRevert: a reverted port goes back to the setting it had before (a
// VLAN, or the LAN), its setting is not re-applied until the controller
// sends another one, and Settle retries a put-back that failed.
func TestRevert(t *testing.T) {
	ctx := context.Background()
	b := newFakeBridger()
	m := New(Options{B: b})
	m.Apply(ctx, want(map[int]PortWant{3: {Native: 7}}))
	r := m.Apply(ctx, want(map[int]PortWant{2: {Native: 5, Tagged: []int{8}}, 3: {Native: 9}}))
	if r.Before[2].String() != "native LAN" || r.Before[3].String() != "native VLAN 7" {
		t.Fatalf("before %v", r.Before)
	}
	r = m.Revert(ctx, r.Before, map[int]string{2: "native VLAN 5, tagged 8", 3: "native VLAN 9"})
	if b.br["eth0.2.1"] != "bdg2" || b.Exists("eth0.2.8") || b.br["eth0.3.1"] != "br-v7" || len(r.Failed) != 0 {
		t.Fatalf("reverted: %v, report %+v", b.br, r)
	}
	ops := len(b.ops)
	r = m.Apply(ctx, want(map[int]PortWant{2: {Native: 5, Tagged: []int{8}}, 3: {Native: 9}}))
	if len(b.ops) != ops || r.Steps != 0 {
		t.Fatalf("reverted settings re-applied: %q", b.ops[ops:])
	}

	// a put-back that fails: in Failed, then Settle retries until it is back
	m.Apply(ctx, want(map[int]PortWant{2: {Native: 6}}))
	b.fail["eth0.2.1 0"] = true
	r = m.Revert(ctx, map[int]PortWant{2: {}}, map[int]string{2: "native VLAN 6"})
	if r.Failed[2] == nil || b.br["eth0.2.1"] != "br-v6" {
		t.Fatalf("failed revert: %+v, port 2 in %q", r, b.br["eth0.2.1"])
	}
	if r = m.Settle(ctx); !strings.Contains(strings.Join(r.Notes, "\n"), "port 2 is not on the LAN") {
		t.Errorf("settle notes %q", r.Notes)
	}
	delete(b.fail, "eth0.2.1 0")
	if r = m.Settle(ctx); b.br["eth0.2.1"] != "bdg2" || r.Steps != 1 {
		t.Errorf("settle: port 2 in %q, %+v", b.br["eth0.2.1"], r)
	}
	if r = m.Settle(ctx); r.Steps != 0 || len(r.Notes) != 0 {
		t.Errorf("settle again: %+v", r)
	}
}

// TestRestoreLeavesLockedAndUplink: Restore and OffLAN never look at the
// locked port 1 or the uplink, wherever they are.
func TestRestoreLeavesLockedAndUplink(t *testing.T) {
	ctx := context.Background()
	b := newFakeBridger()
	b.br["eth0.1.1"] = "br-v3"
	b.br["eth0.1.4"] = "br-v4"
	uplink := Untagged(UplinkPhys)
	m := New(Options{B: b, Uplink: func() string { return uplink }})
	m.Apply(ctx, want(map[int]PortWant{2: {Native: 5}, 3: {Tagged: []int{6}}}))
	if off := m.OffLAN(); fmt.Sprint(off) != "[2 3]" {
		t.Fatalf("off LAN %v", off)
	}
	ops := len(b.ops)
	r := m.Restore(ctx)
	if b.br["eth0.2.1"] != "bdg2" || b.Exists("eth0.3.6") || len(r.Failed) != 0 || r.Steps != 2 {
		t.Fatalf("restore %+v: %v", r, b.br)
	}
	for _, op := range b.ops[ops:] {
		if strings.Contains(op, "eth0.1.") || strings.Contains(op, "eth0.4.") {
			t.Errorf("touched %s", op)
		}
	}
	if b.br["eth0.1.1"] != "br-v3" || b.br["eth0.1.4"] != "br-v4" || b.br["eth0.4.1"] != "bdg2" || b.br["eth0.4.3"] != "br-v3" {
		t.Errorf("port 1 or the uplink changed: %v", b.br)
	}
	// the uplink moved to port 3 (the agent tracks it): port 3 is left alone
	m.Apply(ctx, want(map[int]PortWant{3: {Tagged: []int{6}}}))
	uplink = Untagged(3)
	if off := m.OffLAN(); len(off) != 0 {
		t.Errorf("off LAN with port 3 as the uplink: %v", off)
	}
	if m.Restore(ctx); !b.Exists("eth0.3.6") {
		t.Errorf("the uplink's VLAN device removed")
	}
}
