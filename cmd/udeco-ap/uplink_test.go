// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/mtkwifi"
)

// holdWifi has bcmwifi's uplink-loss hold.
type holdWifi struct {
	*fakeWifi
	mu  *sync.Mutex
	err *error
}

func (w holdWifi) SSIDsDown(ctx context.Context, down bool) error {
	if down {
		w.rec.add("ssids-down")
	} else {
		w.rec.add("ssids-up")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return *w.err
}

// upUnit drives uplinkPass with its own clock and carrier.
type upUnit struct {
	t       *testing.T
	h       *harness
	now     time.Time
	carrier bool
	mu      sync.Mutex
	err     error
}

func newUpUnit(t *testing.T, mod func(*Config)) *upUnit {
	u := &upUnit{t: t, carrier: true, now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	u.h = newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		if mod != nil {
			mod(c)
		}
		o.carrier = func(dev string) (bool, bool) {
			if dev != "eth1" {
				return false, false
			}
			return u.carrier, true
		}
	})
	u.h.a.wifi = holdWifi{fakeWifi: u.h.wifi, mu: &u.mu, err: &u.err}
	u.h.a.policy.Store(&wifiPolicy{})
	u.h.a.topo.uplinkName.Store("eth1")
	return u
}

// step runs one pass per second for d with the carrier as given, and
// returns the hold calls made.
func (u *upUnit) step(d time.Duration, carrier bool) []string {
	u.carrier = carrier
	before := len(u.h.rec.list())
	for e := time.Duration(0); e < d; e += time.Second {
		u.now = u.now.Add(time.Second)
		u.h.a.uplinkPass(u.now)
		for {
			select {
			case j := <-u.h.a.jobs:
				j.fn(context.Background())
				continue
			default:
			}
			break
		}
	}
	var out []string
	for _, c := range u.h.rec.list()[before:] {
		if strings.HasPrefix(c, "ssids-") {
			out = append(out, c)
		}
	}
	return out
}

func wantCalls(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s: calls %v, want %v", what, got, want)
	}
}

// The tracked uplink port without carrier for 5 s: every SSID goes down
// (one call, logged and kept as an event); back with carrier for 10 s: up
// again. A carrier that comes back for less than that changes nothing.
func TestUplinkLoss(t *testing.T) {
	u := newUpUnit(t, nil)
	wantCalls(t, "steady", u.step(30*time.Second, true))
	wantCalls(t, "4 s lost", u.step(4*time.Second, false))
	wantCalls(t, "5 s lost", u.step(time.Second, false), "ssids-down")
	wantCalls(t, "still lost", u.step(time.Minute, false))
	wantCalls(t, "short return", u.step(9*time.Second, true))
	wantCalls(t, "lost again", u.step(20*time.Second, false))
	wantCalls(t, "9 s back", u.step(9*time.Second, true))
	wantCalls(t, "10 s back", u.step(time.Second, true), "ssids-up")
	wantCalls(t, "stays up", u.step(time.Minute, true))
	logs := u.h.logs.all()
	if !strings.Contains(logs, "EVENT: uplink eth1 lost") || !strings.Contains(logs, "EVENT: uplink eth1 back") {
		t.Fatalf("no events:\n%s", logs)
	}
}

// Never during a Wi-Fi apply or rollback, nor while a takeover hold (a
// TP-Link rebuild or upgrade) stands: the change waits for its end.
func TestUplinkLossWaits(t *testing.T) {
	u := newUpUnit(t, nil)
	u.h.a.wifiBusy.Store(true)
	wantCalls(t, "apply", u.step(20*time.Second, false))
	u.h.a.wifiBusy.Store(false)
	u.h.a.scanHold.Store("TP-Link wifi rebuild")
	wantCalls(t, "hold", u.step(20*time.Second, false))
	u.h.a.scanHold.Store("")
	wantCalls(t, "free", u.step(time.Second, false), "ssids-down")
	// a failed call is retried
	u.mu.Lock()
	u.err = errors.New("wl: boom")
	u.mu.Unlock()
	wantCalls(t, "failing", u.step(10*time.Second, true), "ssids-up")
	u.mu.Lock()
	u.err = nil
	u.mu.Unlock()
	wantCalls(t, "retried", u.step(uplinkRetry+time.Second, true), "ssids-up")
	wantCalls(t, "done", u.step(time.Minute, true))
}

// Outside takeover, before the Wi-Fi is live, without a tracked uplink or
// a readable carrier: nothing. A drop to observe mode forgets the hold
// (the hand-back put TP-Link's BSSes back).
func TestUplinkLossQuiet(t *testing.T) {
	u := newUpUnit(t, nil)
	u.h.a.topo.uplinkName.Store("eth0") // carrier unreadable
	wantCalls(t, "unreadable", u.step(30*time.Second, false))
	u.h.a.topo.uplinkName.Store("")
	wantCalls(t, "no uplink", u.step(30*time.Second, false))
	u.h.a.topo.uplinkName.Store("eth1")
	// the first readable pass starts the run: 5 s after it
	wantCalls(t, "lost", u.step(6*time.Second, false), "ssids-down")
	u.h.a.policy.Store(nil)
	wantCalls(t, "observe", u.step(30*time.Second, false))
	u.h.a.policy.Store(&wifiPolicy{})
	wantCalls(t, "live again, still lost", u.step(6*time.Second, false), "ssids-down")
}

// uplink_gateway_down: the gateway unanswered for 60 s takes the SSIDs down
// with the carrier up; an answer and 10 s of carrier bring them back. Off
// (the default), the gateway does not count.
func TestUplinkGatewayDown(t *testing.T) {
	u := newUpUnit(t, func(c *Config) { c.UplinkGatewayDown = true })
	u.h.a.upl.gwFail.Store(u.now.UnixNano())
	wantCalls(t, "59 s", u.step(59*time.Second, true))
	wantCalls(t, "60 s", u.step(time.Second, true), "ssids-down")
	u.h.a.upl.gwFail.Store(0)
	wantCalls(t, "answered", u.step(time.Second, true), "ssids-up")

	u = newUpUnit(t, nil)
	u.h.a.upl.gwFail.Store(u.now.UnixNano())
	wantCalls(t, "option off", u.step(5*time.Minute, true))
}

type upProber struct {
	mu  sync.Mutex
	err error
	dst []string
}

func (p *upProber) Probe(ctx context.Context, dst net.IP, size int, timeout time.Duration) (time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dst = append(p.dst, dst.String())
	return time.Millisecond, p.err
}

// The gateway probe: the first unanswered echo of a run starts the clock,
// an answer or no known gateway stops it.
func TestUplinkGatewayProbe(t *testing.T) {
	u := newUpUnit(t, func(c *Config) { c.UplinkGatewayDown = true })
	p := &upProber{err: errors.New("no echo reply")}
	u.h.a.topo.gwIP.Store("192.168.1.1")
	t0 := u.now
	u.h.a.gwProbe(context.Background(), p, t0)
	u.h.a.gwProbe(context.Background(), p, t0.Add(5*time.Second))
	if got := u.h.a.upl.gwFail.Load(); got != t0.UnixNano() {
		t.Fatalf("first failure %v", time.Unix(0, got))
	}
	p.err = nil
	u.h.a.gwProbe(context.Background(), p, t0.Add(10*time.Second))
	if got := u.h.a.upl.gwFail.Load(); got != 0 {
		t.Fatalf("answered: %d", got)
	}
	p.err = errors.New("no echo reply")
	u.h.a.topo.gwIP.Store("")
	u.h.a.gwProbe(context.Background(), p, t0.Add(15*time.Second))
	if got := u.h.a.upl.gwFail.Load(); got != 0 || len(p.dst) != 3 || p.dst[0] != "192.168.1.1" {
		t.Fatalf("no gateway: %d %v", got, p.dst)
	}
}

// The keys: uplink_ssid_down (default on) and uplink_gateway_down (default
// off, needs the first); takeover only; not on the Garage (jio-mtk).
func TestUplinkConfig(t *testing.T) {
	f, tr := false, true
	base := func() Config {
		return Config{InformURL: "http://192.168.1.10:8080/inform", ConsoleIP: "192.168.1.10", Model: "UAL6",
			SSHDPort: 2222, Log: "stderr", Takeover: true}
	}
	c := base()
	if err := c.validate(); err != nil || !c.uplinkSSIDDown() || c.UplinkGatewayDown {
		t.Fatalf("defaults: %v %v %v", err, c.uplinkSSIDDown(), c.UplinkGatewayDown)
	}
	c.UplinkSSIDDown = &f
	if err := c.validate(); err != nil || c.uplinkSSIDDown() {
		t.Fatalf("off: %v", err)
	}
	c.UplinkGatewayDown = true
	if err := c.validate(); err == nil {
		t.Error("uplink_gateway_down without uplink_ssid_down accepted")
	}
	c = base()
	c.Takeover = false
	c.UplinkSSIDDown = &tr
	if err := c.validate(); err == nil {
		t.Error("uplink_ssid_down without takeover accepted")
	}
	c = base()
	c.Platform, c.Model = PlatformJio, "U7LT"
	c.UplinkGatewayDown = true
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "uplink_gateway_down") {
		t.Errorf("jio: %v", err)
	}
}

// releaseWifi has bcmwifi's ReleaseLED.
type releaseWifi struct{ *fakeWifi }

func (w releaseWifi) ReleaseLED(ctx context.Context) {
	if ctx.Err() != nil {
		w.rec.add("led-release:cancelled")
		return
	}
	w.rec.add("led-release")
}

// The agent's stop leaves no uplink-loss blink behind (bcmwifi ReleaseLED,
// with a context SIGTERM did not cancel), after the worker has finished;
// the Garage's backend has no such LED and nothing changes there.
func TestUplinkLEDReleasedAtStop(t *testing.T) {
	var h *harness
	h = newHarness(t, func(c *Config, o *options) {
		c.Takeover = true
		o.newWifi = func(bo bcmwifi.Options) wifiApplier { h.built++; return releaseWifi{h.wifi} }
	})
	h.start()
	eventually(t, "enforce", func() bool { return h.rec.count("enforce") > 0 })
	if h.rec.index("led-release") >= 0 {
		t.Fatal("released while running")
	}
	h.stop()
	if h.rec.index("led-release") < 0 {
		t.Fatalf("not released at the stop: %v", h.rec.list())
	}
	// the Garage's uplink-loss hold blinks its LED red too (mtkwifi
	// uplinkLED): the stop releases it the same way
	if _, ok := any((*mtkwifi.Applier)(nil)).(ledReleaser); !ok {
		t.Error("the jio-mtk backend has no release: its red blink would outlive the agent")
	}
}
