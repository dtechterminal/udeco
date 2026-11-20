// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"errors"
	"testing"
)

// The uplink-loss hold: every BSS the agent serves goes BSS down (no radio
// restart, hostapd keeps running); while it holds, Plan and Tick neither
// raise them nor report drift, a full apply leaves them down and Verify
// wants them down; lifting it raises them again. A hand-back forgets it.
func TestSSIDsDown(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	if err := a.SSIDsDown(ctx, true); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("before takeover: %v", err)
	}
	d := twoSSIDs()
	applyOK(t, a, d)
	served := []string{"wl02", "wl03", "wl12"}
	bss := func(want string) {
		t.Helper()
		for _, v := range served {
			if got := f.state[v+" bss"]; got != want {
				t.Errorf("%s bss %q, want %q", v, got, want)
			}
		}
	}
	f.reset()
	if err := a.SSIDsDown(ctx, true); err != nil {
		t.Fatal(err)
	}
	bss("down")
	if f.called("wl -i wl0 down") || f.called("wl -i wl1 down") {
		t.Errorf("radio restarted: %v", f.mutating())
	}
	if !a.SSIDsHeld() {
		t.Error("not held")
	}
	if p, err := a.Plan(ctx, d); err != nil || !p.Empty() {
		t.Fatalf("plan while held: %v\n%s", err, p)
	}
	if r, err := a.Tick(ctx); err != nil || len(r.Foreign) != 0 || r.Steps != 0 {
		t.Fatalf("tick while held: %+v %v", r, err)
	}
	bss("down")
	if err := a.Verify(ctx, d); err != nil {
		t.Fatalf("verify while held: %v", err)
	}
	// a full apply (hostapd restarted) while held keeps them down
	d2 := twoSSIDs()
	d2.SSIDs[1].Passphrase = "another-passphrase-2"
	if p := applyOK(t, a, d2); p.Empty() {
		t.Fatal("no apply")
	}
	bss("down")
	// lifted
	f.reset()
	if err := a.SSIDsDown(ctx, false); err != nil {
		t.Fatal(err)
	}
	bss("up")
	if a.SSIDsHeld() {
		t.Error("still held")
	}
	if p, _ := a.Plan(ctx, d2); !p.Empty() {
		t.Fatalf("plan after the hold:\n%s", p)
	}
	if err := a.Verify(ctx, d2); err != nil {
		t.Fatal(err)
	}
	// a hand-back forgets it
	if err := a.SSIDsDown(ctx, true); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	_ = a.handback(ctx)
	a.mu.Unlock()
	if a.SSIDsHeld() {
		t.Error("held after the hand-back")
	}
}
