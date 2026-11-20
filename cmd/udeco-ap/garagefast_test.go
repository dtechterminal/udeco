// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// tickCollector counts the readings the watchdog tick asks for.
type tickCollector struct {
	collector
	mu    sync.Mutex
	reads int
	err   error
}

func (c *tickCollector) Collect(context.Context) (*apstate.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if c.err != nil {
		return nil, c.err
	}
	return &apstate.Snapshot{Time: time.Unix(1_800_000_000+int64(c.reads), 0)}, nil
}

type stuckWifi struct {
	wifiApplier
	mu    sync.Mutex
	snaps []*apstate.Snapshot
	kick  []string
}

func (w *stuckWifi) KickStuck(_ context.Context, s *apstate.Snapshot) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.snaps = append(w.snaps, s)
	return w.kick
}

func (w *stuckWifi) calls() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.snaps)
}

func tickAgent(cfg *Config) (*agent, *tickCollector, *stuckWifi) {
	col := &tickCollector{}
	w := &stuckWifi{}
	a := &agent{cfg: cfg, o: options{col: col}, t: timing{watchdogEvery: 5 * time.Millisecond}}
	a.t.fill()
	a.wifi = w
	a.takeover.Store(true)
	return a, col, w
}

// TestGarageWatchdogTick: on the Garage, the downlink watchdog runs on a
// fresh reading of its own between informs; it does not on the Deco, with
// the watchdog off, in observe mode, or when the reading fails.
func TestGarageWatchdogTick(t *testing.T) {
	ctx := context.Background()
	off := false
	for _, tc := range []struct {
		name string
		cfg  *Config
		obs  bool
		err  error
		want bool
	}{
		{"garage", &Config{Platform: PlatformJio, Takeover: true}, false, nil, true},
		{"deco", &Config{Takeover: true}, false, nil, false},
		{"watchdog off", &Config{Platform: PlatformJio, Takeover: true, DownlinkWatchdog: &off}, false, nil, false},
		{"observe", &Config{Platform: PlatformJio, Takeover: true}, true, nil, false},
		{"failed reading", &Config{Platform: PlatformJio, Takeover: true}, false, errors.New("klog"), false},
	} {
		a, col, w := tickAgent(tc.cfg)
		col.err = tc.err
		if tc.obs {
			a.takeover.Store(false)
		}
		if a.garageWatchdogOn() {
			a.garageWatchdogTick(ctx)
		}
		if got := w.calls() == 1; got != tc.want {
			t.Errorf("%s: watchdog ran %v, want %v", tc.name, got, tc.want)
		}
		if tc.want && w.snaps[0] == nil {
			t.Errorf("%s: no reading", tc.name)
		}
	}
	// a kick is an event, as from an inform's reading
	a, _, w := tickAgent(&Config{Platform: PlatformJio, Takeover: true})
	var logged []string
	a.events = &eventLog{clock: time.Now, logf: func(f string, v ...any) { logged = append(logged, fmt.Sprintf(f, v...)) }}
	w.kick = []string{"fc:3c:d7:31:00:cd"}
	a.garageWatchdogTick(ctx)
	if w.calls() != 1 || !strings.Contains(strings.Join(logged, "\n"), "downlink watchdog: fc:3c:d7:31:00:cd") {
		t.Fatalf("watchdog calls %d, logged %q", w.calls(), logged)
	}
}

// TestWaitInformTicks: while the agent waits for the next inform, the
// Garage watchdog ticks; the wait still ends at its timer, and on the Deco
// nothing ticks.
func TestWaitInformTicks(t *testing.T) {
	a, _, w := tickAgent(&Config{Platform: PlatformJio, Takeover: true})
	start := time.Now()
	if !a.waitInform(context.Background(), 60*time.Millisecond) {
		t.Fatal("wait ended as if ctx were done")
	}
	if el := time.Since(start); el < 60*time.Millisecond {
		t.Errorf("wait ended after %s, before its timer", el)
	}
	if n := w.calls(); n < 3 {
		t.Errorf("watchdog ran %d times in a 60 ms wait at a 5 ms tick", n)
	}
	d, _, dw := tickAgent(&Config{Takeover: true})
	d.waitInform(context.Background(), 20*time.Millisecond)
	if dw.calls() != 0 {
		t.Errorf("the Deco ran the watchdog %d times", dw.calls())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if a.waitInform(ctx, time.Hour) {
		t.Error("a done ctx did not end the wait")
	}
}

// TestInformEveryConfig: inform_every_s is 5-60 seconds, absent is off.
func TestInformEveryConfig(t *testing.T) {
	if d := (&Config{}).informEvery(); d != 0 {
		t.Errorf("absent: %s, want 0 (off)", d)
	}
	if d := (&Config{InformEveryS: 10}).informEvery(); d != 10*time.Second {
		t.Errorf("10: %s", d)
	}
	for v, ok := range map[int]bool{0: true, 4: false, 5: true, 10: true, 60: true, 61: false, -1: false} {
		if err := informEveryKey.check(v); (err == nil) != ok {
			t.Errorf("%d: err %v", v, err)
		}
	}
}
