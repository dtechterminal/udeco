// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A failed apply whose Desired carried no usable guest policy rolls back
// to last-good with last-good's own guest policy: the guest SSID comes
// back with its chains, never served open (fail closed).
func TestRollbackKeepsGuestPolicy(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, guestHome())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	*now += time.Minute
	// what Apply records before applyPlans when the next one then fails
	bad := guestHome()
	bad.Guest = nil
	a.mu.Lock()
	a.desired = bad
	a.mu.Unlock()
	n := len(f.log)
	if err := a.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(f.log[n:], "\n")
	if !f.up("rai2") {
		t.Fatalf("guest SSID not back:\n%s", got)
	}
	if strings.Contains(got, "ebtables -X UDECO-GIN") || strings.Contains(got, "ebtables -D FORWARD -i rai2 -j UDECO-GIN") {
		t.Errorf("guest chains removed while the guest SSID is up:\n%s", got)
	}
	*now += time.Minute
	n = len(f.log)
	a.Tick(ctx)
	if strings.Contains(strings.Join(f.log[n:], "\n"), "ebtables -X UDECO-GIN") {
		t.Errorf("Tick removed the guest chains")
	}
}

// A rollback during uplink isolation brings back last-good isolated (what
// Verify checks), so the health check passes instead of rolling back,
// restarting both radios, again and again for the whole outage.
func TestRollbackWhileIsolated(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	ctx := context.Background()
	d := home()
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	*now += time.Minute
	if err := a.SetUplinkDown(ctx, true); err != nil {
		t.Fatal(err)
	}
	*now += time.Minute
	if err := a.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	// "Example Network" (ra0, rai0) stays; the others stay down
	for _, ifc := range []string{"ra1", "ra2", "rai1"} {
		if f.up(ifc) {
			t.Errorf("%s up after a rollback while isolated", ifc)
		}
	}
	*now += time.Minute
	if err := a.Verify(ctx, d); err != nil {
		t.Errorf("verify after the rollback: %v", err)
	}
	// the uplink comes back: everything returns
	*now += time.Minute
	if err := a.SetUplinkDown(ctx, false); err != nil {
		t.Fatal(err)
	}
	for _, ifc := range []string{"ra0", "ra1", "rai0", "rai1"} {
		if !f.up(ifc) {
			t.Errorf("%s down after the uplink came back", ifc)
		}
	}
}
