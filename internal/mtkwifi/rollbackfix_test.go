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

// A planned restart that leaves 52-64 (a channel and width change in one
// push) is no radar: the DFS follow-up state goes with the restart.
func TestDFSPlannedRestartNoRadar(t *testing.T) {
	f := newFakeDev(t)
	a, now := dfsApplier(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, dfsHome(36))
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	f.na = 36
	*now += time.Minute
	p, _ = a.Plan(ctx, dfsHome(52))
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	*now += 2 * time.Minute
	a.Tick(ctx)
	if f.na != 52 || !a.OnDFS() {
		t.Fatalf("on %d", f.na)
	}
	d := dfsHome(149)
	r := d.Radios["na"]
	r.Width = 40
	d.Radios["na"] = r
	n := len(f.log)
	p, _ = a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if len(restarts(f.log[n:])) == 0 {
		t.Fatal("no restart: the test needs one")
	}
	f.na = 149 // the driver came up on the profile's channel
	for i := 0; i < 4; i++ {
		*now += time.Minute
		a.Tick(ctx)
	}
	if ev := a.TakeRadar(); len(ev) != 0 {
		t.Errorf("a planned restart reported as radar: %+v", ev)
	}
	if a.inNOP(52) {
		t.Error("52 in a NOP after a planned restart")
	}
}

// probeRun probes the gate before each command.
type probeRun struct {
	*fakeDev
	before func(cmd string)
}

func (p probeRun) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if p.before != nil {
		p.before(name + " " + strings.Join(args, " "))
	}
	return p.fakeDev.Run(ctx, name, args...)
}

// Tick's live DFS changes (the region, the channel move with its CSA and
// CAC) hold the RestartGate's write side and start the quiet time before
// the driver restarts its BSSes: no collector read runs meanwhile.
func TestDFSTickHoldsGate(t *testing.T) {
	f := newFakeDev(t)
	now := new(time.Duration)
	*now = time.Hour
	pr := &probeRun{fakeDev: f}
	a := New(Options{Root: f.root, Run: pr, RunDir: "/tmp/udeco", StateDir: "/state", Uplink: "eth0.4.1", DFS: true,
		VerifyTimeout: time.Millisecond, sleep: func(context.Context, time.Duration) error { return nil },
		mono: func() time.Duration { return *now }})
	ctx := context.Background()
	p, _ := a.Plan(ctx, dfsHome(52))
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	f.na = 36 // the restart came up off 52: Tick moves it live
	*now += 2 * time.Minute
	var seen []string
	pr.before = func(cmd string) {
		if !strings.HasPrefix(cmd, "iwpriv rai0 set Channel=") && !strings.HasPrefix(cmd, "iwpriv rai0 set CountryRegionABand=") {
			return
		}
		done, ok := a.DriverRead()
		if ok {
			done()
			seen = append(seen, cmd+": a driver read was let through")
		}
		if !a.settling() {
			seen = append(seen, cmd+": not quiet")
		}
	}
	a.Tick(ctx)
	if f.na != 52 {
		t.Fatalf("Tick did not move to 52 (on %d)", f.na)
	}
	if len(seen) > 0 {
		t.Errorf("Tick's DFS step:\n%s", strings.Join(seen, "\n"))
	}
	// the gate opens again: a read after the quiet time runs
	*now += 2 * time.Minute
	if done, ok := a.DriverRead(); !ok {
		t.Error("gate left closed")
	} else {
		done()
	}
}

// Unauthorising a guest inside a restart's settle time takes its RETURN
// rule out at once but leaves the disconnect (live iwpriv) to the first
// Tick after the settle time; re-authorised meanwhile, it is never sent.
func TestGuestUnauthoriseSettleGuard(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, guestHome())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if !a.settling() {
		t.Fatal("not settling after the apply's restart")
	}
	n := len(f.log)
	if err := a.UnauthorizeGuest(ctx, "aa:bb:cc:00:00:09"); err != nil {
		t.Fatal(err)
	}
	if err := a.UnauthorizeGuest(ctx, "aa:bb:cc:00:00:0a"); err != nil {
		t.Fatal(err)
	}
	a.AuthorizeGuest(ctx, "aa:bb:cc:00:00:0a")
	if c := cmdsFrom(f, n, "iwpriv"); len(c) > 0 {
		t.Errorf("live iwpriv inside the settle time: %v", c)
	}
	*now += time.Minute
	n = len(f.log)
	a.Tick(ctx)
	if c := cmdsFrom(f, n, "iwpriv rai2 set DisConnectSta=AA:BB:CC:00:00:09"); len(c) != 1 {
		t.Errorf("deferred disconnect not sent: %v", f.log[n:])
	}
	if c := cmdsFrom(f, n, "iwpriv rai2 set DisConnectSta=AA:BB:CC:00:00:0A"); len(c) != 0 {
		t.Errorf("re-authorised guest disconnected: %v", c)
	}
	n = len(f.log)
	a.Tick(ctx)
	if c := cmdsFrom(f, n, "iwpriv rai2 set DisConnectSta"); len(c) != 0 {
		t.Errorf("disconnect sent twice: %v", c)
	}
}

// parpOff inside a settle time sends no hs_flag (the hand-back's radio
// restarts clear it anyway); outside one it does.
func TestParpOffSettleGuard(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	ctx := context.Background()
	a.parpFlag = map[string]bool{"rai0": true}
	a.quietFor(time.Minute)
	n := len(f.log)
	a.parpOff(ctx)
	if c := cmdsFrom(f, n, "iwpriv"); len(c) > 0 {
		t.Errorf("hs_flag inside the settle time: %v", c)
	}
	*now += 2 * time.Minute
	a.parpFlag = map[string]bool{"rai0": true}
	n = len(f.log)
	a.parpOff(ctx)
	if c := cmdsFrom(f, n, "iwpriv rai0 set hs_flag=0"); len(c) != 1 {
		t.Errorf("hs_flag=0 not sent outside the settle time: %v", f.log[n:])
	}
}

// A controller kick inside a settle time is sent after it (live iwpriv).
func TestKickSettleGuard(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, home())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	n := len(f.log)
	if err := a.Kick(ctx, "aa:bb:cc:00:00:09"); err != nil {
		t.Fatal(err)
	}
	if c := cmdsFrom(f, n, "iwpriv"); len(c) > 0 {
		t.Errorf("kick inside the settle time: %v", c)
	}
	*now += time.Minute
	n = len(f.log)
	a.Tick(ctx)
	if c := cmdsFrom(f, n, "iwpriv ra0 set DisConnectSta=AA:BB:CC:00:00:09"); len(c) != 1 {
		t.Errorf("deferred kick not sent: %v", f.log[n:])
	}
}

// A burst is a burst whatever the flush timing: 5 Deletes on rai1 100 ms
// apart, flushed every 250 ms (Run's tick), release nothing; the early
// ones being dropped must not make the tail look like single leaves. The
// kernel log's 2.4 GHz Del Sta lines (AnyNG) are burst-checked too.
func TestEventsBurstTail(t *testing.T) {
	for _, ifc := range []string{"rai1", AnyNG} {
		busy := false
		e, ck := newTestEvents(&busy)
		var got []string
		next := ck.t.Add(250 * time.Millisecond)
		for i := 0; i < 5; i++ {
			e.handle(DrvEvent{Kind: DrvDelete, Ifname: ifc, MAC: "02:00:00:00:00:0" + string(rune('1'+i))})
			ck.t = ck.t.Add(100 * time.Millisecond)
			if !ck.t.Before(next) {
				e.flush()
				next = next.Add(250 * time.Millisecond)
			}
		}
		for i := 0; i < 12; i++ {
			ck.t = ck.t.Add(250 * time.Millisecond)
			e.flush()
		}
		evs, _ := e.Take()
		for _, ev := range evs {
			got = append(got, ev.MAC)
		}
		if len(got) != 0 {
			t.Errorf("%s: burst tail released: %v", ifc, got)
		}
	}
	// three on one BSS within a second are leaves
	busy := false
	e, ck := newTestEvents(&busy)
	for i := 0; i < 3; i++ {
		e.handle(DrvEvent{Kind: DrvDelete, Ifname: "rai1", MAC: "02:00:00:00:00:0" + string(rune('1'+i))})
		ck.t = ck.t.Add(100 * time.Millisecond)
	}
	for i := 0; i < 8; i++ {
		ck.t = ck.t.Add(250 * time.Millisecond)
		e.flush()
	}
	if evs, _ := e.Take(); len(evs) != 3 {
		t.Errorf("three leaves: %v", evs)
	}
}
