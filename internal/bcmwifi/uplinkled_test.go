// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

const (
	connLost   = `ubus call leds conn {"state":"ap-lost"}`
	connOnline = `ubus call leds conn {"state":"online"}`
	ledLit     = `ubus call leds off {"state":"done"}`
	ledDark    = `ubus call leds off {"state":"off"}`
)

// ledCalls is the leds daemon calls made since the last reset, in order.
func ledCalls(f *fakeDev) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if c[0] == "ubus" {
			out = append(out, strings.Join(c, " "))
		}
	}
	return out
}

// lastIndex is the index of the last call containing sub (-1: none).
func lastIndex(f *fakeDev, sub string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := -1
	for i, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), sub) {
			n = i
		}
	}
	return n
}

func wantLED(t *testing.T, f *fakeDev, what string, want ...string) {
	t.Helper()
	if got := ledCalls(f); !reflect.DeepEqual(got, want) {
		t.Errorf("%s: leds calls %q, want %q", what, got, want)
	}
	f.reset()
}

// The uplink-loss hold shows on the LED as TP-Link's own "lost the uplink"
// signal (conn ap-lost: red blink, read on the Hallway X20 2026-11-20), the
// closest the daemon has to a U6's fast blink; lifting it puts conn back to
// online. LED on during the hold keeps the red blink, locate blinks green
// over it and leaves it, and with the LED off the conn state changes under
// the "off" event without lighting the LED.
func TestUplinkLossLED(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	applyOK(t, a, twoSSIDs())
	f.reset()
	if err := a.SSIDsDown(ctx, true); err != nil {
		t.Fatal(err)
	}
	if i, j := lastIndex(f, "bss down"), lastIndex(f, "ap-lost"); j < i {
		t.Errorf("ap-lost (%d) before the last bss down (%d)", j, i)
	}
	wantLED(t, f, "hold on", connLost)
	if err := a.LED(ctx, LEDOn); err != nil {
		t.Fatal(err)
	}
	wantLED(t, f, "LED on during the hold", connLost, ledLit)
	for _, m := range []string{LEDLocate, LEDLocateOff} {
		if err := a.LED(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	wantLED(t, f, "locate during the hold", ledLit, `ubus call leds zigbee {"state":"identifying"}`,
		`ubus call leds zigbee {"state":"done"}`, ledLit)
	if err := a.SSIDsDown(ctx, false); err != nil {
		t.Fatal(err)
	}
	if i, j := lastIndex(f, "bss up"), lastIndex(f, "online"); j < i {
		t.Errorf("online (%d) before the last bss up (%d)", j, i)
	}
	wantLED(t, f, "hold lifted", connOnline)
	if err := a.LED(ctx, LEDOn); err != nil {
		t.Fatal(err)
	}
	wantLED(t, f, "LED on after the hold", connOnline, ledLit)

	// LED off: conn changes under the "off" event, which stays dark
	if err := a.LED(ctx, LEDOff); err != nil {
		t.Fatal(err)
	}
	f.reset()
	if err := a.SSIDsDown(ctx, true); err != nil {
		t.Fatal(err)
	}
	wantLED(t, f, "hold on, LED off", connLost)
	for _, m := range []string{LEDLocate, LEDLocateOff} {
		if err := a.LED(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	wantLED(t, f, "locate during the hold, LED off", ledLit, `ubus call leds zigbee {"state":"identifying"}`,
		`ubus call leds zigbee {"state":"done"}`, ledDark)
	if err := a.SSIDsDown(ctx, false); err != nil {
		t.Fatal(err)
	}
	wantLED(t, f, "hold lifted, LED off", connOnline)
}

// A failed leds call is logged and never fails the hold or its lifting; a
// failed change of the SSIDs leaves the LED alone; a conn online that
// failed at the lifting is put right by the next LED on, the hand-back or
// the agent's stop.
func TestUplinkLossLEDFailure(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	applyOK(t, a, twoSSIDs())
	conn := func(argv []string) bool { return len(argv) >= 4 && argv[0] == "ubus" && argv[3] == "conn" }
	f.failOn = conn
	f.reset()
	if err := a.SSIDsDown(ctx, true); err != nil {
		t.Fatalf("hold with a failing leds call: %v", err)
	}
	if !a.SSIDsHeld() || f.state["wl02 bss"] != "down" {
		t.Error("hold not taken")
	}
	f.reset()
	if err := a.SSIDsDown(ctx, false); err != nil {
		t.Fatalf("lift with a failing leds call: %v", err)
	}
	if a.SSIDsHeld() || f.state["wl02 bss"] != "up" {
		t.Error("hold not lifted")
	}
	f.failOn = nil
	f.reset()
	a.ReleaseLED(ctx)
	wantLED(t, f, "stop after a failed online", connOnline)
	a.ReleaseLED(ctx)
	wantLED(t, f, "stop again")

	// the SSIDs do not change: neither does the LED
	f.failOn = func(argv []string) bool {
		return len(argv) == 5 && argv[2] == "wl12" && argv[3] == "bss" && argv[4] == "down"
	}
	if err := a.SSIDsDown(ctx, true); err == nil {
		t.Fatal("no error")
	}
	wantLED(t, f, "failed hold")
	f.failOn = nil
	if err := a.SSIDsDown(ctx, true); err != nil {
		t.Fatal(err)
	}
	f.reset()
	f.failOn = func(argv []string) bool {
		return len(argv) == 5 && argv[2] == "wl12" && argv[3] == "bss" && argv[4] == "up"
	}
	if err := a.SSIDsDown(ctx, false); err == nil {
		t.Fatal("no error")
	}
	wantLED(t, f, "failed lift")
	f.failOn = nil
}

// The hand-back and the agent's stop leave conn online; without a hold
// neither touches the LED.
func TestUplinkLossLEDRelease(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	applyOK(t, a, twoSSIDs())
	f.reset()
	a.ReleaseLED(ctx)
	wantLED(t, f, "stop without a hold")
	if err := a.SSIDsDown(ctx, true); err != nil {
		t.Fatal(err)
	}
	f.reset()
	a.ReleaseLED(ctx)
	wantLED(t, f, "stop during the hold", connOnline)
	if !a.SSIDsHeld() {
		t.Error("the stop lifted the hold")
	}
	a.mu.Lock()
	_ = a.handback(ctx)
	a.mu.Unlock()
	wantLED(t, f, "hand-back after the stop")
	if err := a.SSIDsDown(ctx, true); err == nil {
		t.Fatal("hold taken after the hand-back") // ErrNotOwned
	}
	applyOK(t, a, twoSSIDs())
	if err := a.SSIDsDown(ctx, true); err != nil {
		t.Fatal(err)
	}
	f.reset()
	a.mu.Lock()
	_ = a.handback(ctx)
	a.mu.Unlock()
	if ledCalls(f)[0] != connOnline || len(ledCalls(f)) != 1 {
		t.Errorf("hand-back during the hold: leds calls %q", ledCalls(f))
	}
}

// Dry-run: logged, nothing called.
func TestUplinkLossLEDDryRun(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	applyOK(t, a, twoSSIDs())
	a.o.DryRun = true
	f.reset()
	if err := a.SSIDsDown(ctx, true); err != nil {
		t.Fatal(err)
	}
	wantLED(t, f, "dry-run")
}
