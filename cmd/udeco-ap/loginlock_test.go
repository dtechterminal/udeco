// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/decosys"
	"github.com/dtechterminal/udeco/internal/translate"
)

// lockSys is fakeSys with the login lock: each call is recorded as
// lock:true / lock:false; fail, when set, answers it.
type lockSys struct {
	*fakeSys
	mu   *sync.Mutex
	fail *func(on bool) error
}

func newLockSys(f *fakeSys) lockSys {
	var fn func(bool) error
	return lockSys{fakeSys: f, mu: &sync.Mutex{}, fail: &fn}
}

func (s lockSys) LoginLock(ctx context.Context, on bool) error {
	s.rec.add(fmt.Sprintf("lock:%v", on))
	s.mu.Lock()
	defer s.mu.Unlock()
	if *s.fail != nil {
		return (*s.fail)(on)
	}
	return nil
}

func (s lockSys) setFail(fn func(on bool) error) {
	s.mu.Lock()
	*s.fail = fn
	s.mu.Unlock()
}

func sshdOf(cfg string) *translate.SSHDIntent { return translate.SSHD(translate.ParseCfg(cfg)) }

// The lock decision: locked only in takeover, adopted, with the Device
// SSH switch known and off, and a controller reply younger than the
// fail-open window.
func TestLockDecision(t *testing.T) {
	t0 := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	ok := lockInputs{takeover: true, adopted: true, sshd: sshdOf(sshdOffCfg), lastReply: t0, now: t0.Add(time.Minute), failOpen: 10 * time.Minute}
	for _, c := range []struct {
		name string
		mod  func(*lockInputs)
		want bool
		why  string
	}{
		{"all hold", func(*lockInputs) {}, true, "Device SSH off and controller answering"},
		{"observe", func(i *lockInputs) { i.takeover = false }, false, "observe mode"},
		{"not adopted", func(i *lockInputs) { i.adopted = false }, false, "not adopted"},
		{"no sshd section", func(i *lockInputs) { i.sshd = nil }, false, "Device SSH setting not known"},
		{"Device SSH on", func(i *lockInputs) { i.sshd = sshdOf(sshdOnCfg) }, false, "Device SSH on"},
		{"no reply since start", func(i *lockInputs) { i.lastReply = time.Time{} }, false, "no controller reply since the agent started"},
		{"9m59s of silence", func(i *lockInputs) { i.now = t0.Add(10*time.Minute - time.Second) }, true, "Device SSH off and controller answering"},
		{"10m of silence", func(i *lockInputs) { i.now = t0.Add(10 * time.Minute) }, false, "controller silent 10m"},
		{"an hour of silence", func(i *lockInputs) { i.now = t0.Add(time.Hour) }, false, "controller silent 10m"},
		{"2m window, 119s", func(i *lockInputs) { i.failOpen, i.now = 2*time.Minute, t0.Add(119*time.Second) }, true, "Device SSH off and controller answering"},
		{"2m window, 120s", func(i *lockInputs) { i.failOpen, i.now = 2*time.Minute, t0.Add(120*time.Second) }, false, "controller silent 2m"},
		{"90s window", func(i *lockInputs) { i.failOpen, i.now = 90*time.Second, t0.Add(90*time.Second) }, false, "controller silent 90s"},
	} {
		in := ok
		c.mod(&in)
		got, why := lockDecision(in)
		if got != c.want || why != c.why {
			t.Errorf("%s: %v %q, want %v %q", c.name, got, why, c.want, c.why)
		}
	}
}

// lockAgent is an agent with only what the lock uses: a takeover with
// apply configuration, a recording lock and a settable clock.
func lockAgent(t *testing.T) (*agent, lockSys, *logBuf, *time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	logs := &logBuf{}
	cfg := &Config{Takeover: true, Apply: true}
	a := &agent{cfg: cfg, o: options{now: func() time.Time { return now }, logf: logs.logf}}
	a.events = &eventLog{clock: a.o.now, logf: a.logf}
	s := newLockSys(&fakeSys{rec: &recorder{}})
	a.sys = s
	a.takeover.Store(true)
	return a, s, logs, &now
}

func expectCalls(t *testing.T, s lockSys, want ...string) {
	t.Helper()
	got := s.rec.list()
	s.rec.mu.Lock()
	s.rec.calls = nil
	s.rec.mu.Unlock()
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("calls %v, want %v", got, want)
	}
}

func lastIndex(r *recorder, c string) int {
	l := r.list()
	for i := len(l) - 1; i >= 0; i-- {
		if l[i] == c {
			return i
		}
	}
	return -1
}

func eventCount(logs *logBuf, ev string) int { return strings.Count(logs.all(), "EVENT: "+ev) }

// The lock follows the decision: installed on the transition to locked and
// re-asserted at every tick, removed on each way out, one event per
// transition, and never re-run by the loop while nothing changed.
func TestLoginLockTransitions(t *testing.T) {
	a, s, logs, now := lockAgent(t)
	ctx := context.Background()
	t0 := *now

	a.lockEval(ctx, false) // the first look clears whatever a crash left
	expectCalls(t, s, "lock:false")
	a.lockEval(ctx, true)
	expectCalls(t, s)

	a.lockFromCfg(true, sshdOf(sshdOffCfg))
	a.lockEval(ctx, false) // no reply yet: open
	expectCalls(t, s)
	a.lockAnswered(t0)
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:true")
	if eventCount(logs, "LOGIN LOCKED: Device SSH off and controller answering") != 1 {
		t.Errorf("no LOCKED event:\n%s", logs.all())
	}
	a.lockEval(ctx, false)
	expectCalls(t, s)
	a.lockEval(ctx, true) // the tick re-asserts it
	expectCalls(t, s, "lock:true")

	*now = t0.Add(10*time.Minute - time.Second)
	a.lockEval(ctx, false)
	expectCalls(t, s)
	*now = t0.Add(10 * time.Minute)
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:false")
	if eventCount(logs, "LOGIN OPEN: controller silent 10m") != 1 {
		t.Errorf("no fail-open event:\n%s", logs.all())
	}
	a.lockEval(ctx, true) // open: the tick does not touch iptables
	expectCalls(t, s)

	a.lockAnswered(*now)
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:true")
	a.lockFromCfg(true, sshdOf(sshdOnCfg))
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:false")
	if eventCount(logs, "LOGIN OPEN: Device SSH on") != 1 {
		t.Errorf("no Device SSH on event:\n%s", logs.all())
	}

	a.lockFromCfg(true, sshdOf(sshdOffCfg))
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:true")
	a.lockFromCfg(false, nil) // forgotten by the controller
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:false")
	if eventCount(logs, "LOGIN OPEN: not adopted") != 1 {
		t.Errorf("no not-adopted event:\n%s", logs.all())
	}

	a.lockFromCfg(true, sshdOf(sshdOffCfg))
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:true")
	a.takeover.Store(false)
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:false")
	if eventCount(logs, "LOGIN OPEN: observe mode") != 1 {
		t.Errorf("no observe event:\n%s", logs.all())
	}
	if n := strings.Count(logs.all(), "EVENT: LOGIN LOCKED"); n != 4 {
		t.Errorf("%d LOCKED events, want 4:\n%s", n, logs.all())
	}
}

// A lock that cannot be installed leaves the unit open: no LOCKED event,
// the error logged once, the next tick tries again; a re-assert that fails
// while locked is a transition to open.
func TestLoginLockFailOpen(t *testing.T) {
	a, s, logs, now := lockAgent(t)
	ctx := context.Background()
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:false")
	s.setFail(func(on bool) error {
		if on {
			return errors.New("decosys: login lock: iptables -A UDECO-LOCK: exit status 1: left open")
		}
		return nil
	})
	a.lockFromCfg(true, sshdOf(sshdOffCfg))
	a.lockAnswered(*now)
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:true")
	a.lockEval(ctx, false) // the loop does not hammer it
	expectCalls(t, s)
	a.lockEval(ctx, true) // the tick retries
	expectCalls(t, s, "lock:true")
	if strings.Contains(logs.all(), "LOGIN LOCKED") {
		t.Errorf("LOCKED although the lock failed:\n%s", logs.all())
	}
	if n := strings.Count(logs.all(), "left open"); n != 1 {
		t.Errorf("error logged %d times, want once:\n%s", n, logs.all())
	}

	s.setFail(nil)
	a.lockEval(ctx, true)
	expectCalls(t, s, "lock:true")
	if eventCount(logs, "LOGIN LOCKED: Device SSH off and controller answering") != 1 {
		t.Fatalf("no LOCKED event once it worked:\n%s", logs.all())
	}
	s.setFail(func(on bool) error {
		if on {
			return decosys.ErrNoIptables
		}
		return nil
	})
	a.lockEval(ctx, true)
	expectCalls(t, s, "lock:true")
	if eventCount(logs, "LOGIN OPEN: lock failed") != 1 {
		t.Errorf("no fail-open event:\n%s", logs.all())
	}

	// a removal that fails is retried at each look until it works
	s.setFail(func(on bool) error { return errors.New("iptables -D: exit status 4") })
	a.lockFromCfg(true, sshdOf(sshdOnCfg))
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:false")
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:false")
	s.setFail(nil)
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:false")
	a.lockEval(ctx, false)
	expectCalls(t, s)
}

// The agent's stop removes the lock (its own context: the run's is gone).
func TestLoginLockReleaseAtStop(t *testing.T) {
	a, s, logs, now := lockAgent(t)
	a.lockFromCfg(true, sshdOf(sshdOffCfg))
	a.lockAnswered(*now)
	a.lockEval(context.Background(), false)
	expectCalls(t, s, "lock:true")
	a.lockRelease("agent stop")
	expectCalls(t, s, "lock:false")
	if eventCount(logs, "LOGIN OPEN: agent stop") != 1 {
		t.Errorf("no stop event:\n%s", logs.all())
	}
	a.lockRelease("agent stop") // nothing locked: removed again, no event
	if eventCount(logs, "LOGIN OPEN: agent stop") != 1 {
		t.Errorf("a second stop event:\n%s", logs.all())
	}
}

// Opted out ("login_lock": false), apply off, or observe configuration:
// iptables is never touched.
func TestLoginLockOff(t *testing.T) {
	off := false
	for _, cfg := range []*Config{{Takeover: true, Apply: true, LoginLock: &off}, {Takeover: true}, {}} {
		a, s, _, now := lockAgent(t)
		a.cfg = cfg
		a.lockFromCfg(true, sshdOf(sshdOffCfg))
		a.lockAnswered(*now)
		a.lockEval(context.Background(), false)
		a.lockEval(context.Background(), true)
		a.lockRelease("agent stop")
		expectCalls(t, s)
	}
}

// The whole path, with the fake controller: Device SSH off locks once a
// reply decodes, on opens it again, off locks again, and the agent's stop
// opens it; each transition is in events.log.
func TestLoginLockFollowsDeviceSSH(t *testing.T) {
	stdLog(t)
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	s := newLockSys(h.sys)
	h.a.o.newSys = func(decosys.Options) sysManager { return s }
	h.ctl.stamp = 1_700_000_000_000 // a real controller's replies carry its time
	h.ctl.queue(adoptReply, cfgReplyVersion(usersCfg+sshdOffCfg, "00000000000000c1"))
	h.start()
	eventually(t, "locked", func() bool { return h.rec.index("lock:true") >= 0 })
	h.ctl.queue(cfgReplyVersion(usersCfg+sshdOnCfg, "00000000000000c2"))
	eventually(t, "opened", func() bool { return lastIndex(h.rec, "lock:false") > lastIndex(h.rec, "lock:true") })
	n := h.rec.count("lock:true")
	h.ctl.queue(cfgReplyVersion(usersCfg+sshdOffCfg, "00000000000000c3"))
	eventually(t, "locked again", func() bool { return h.rec.count("lock:true") > n })
	h.stop()
	calls := h.rec.list()
	if lastIndex(h.rec, "lock:true") > lastIndex(h.rec, "lock:false") {
		t.Errorf("the stop left it locked: %v", calls)
	}
	ev, _ := os.ReadFile(filepath.Join(h.root, "tp_data/udeco", eventsFile))
	for _, want := range []string{"LOGIN LOCKED: Device SSH off and controller answering", "LOGIN OPEN: Device SSH on", "LOGIN OPEN: agent stop"} {
		if !strings.Contains(string(ev), want) {
			t.Errorf("events.log lacks %q:\n%s", want, ev)
		}
	}
}

// The hand-back to TP-Link opens the lock (before Restore) and nothing
// locks it again in observe mode.
func TestLoginLockHandBack(t *testing.T) {
	stdLog(t)
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	s := newLockSys(h.sys)
	h.a.o.newSys = func(decosys.Options) sysManager { return s }
	h.ctl.stamp = 1_700_000_000_000 // a real controller's replies carry its time
	h.ctl.queue(adoptReply, cfgReplyVersion(usersCfg+sshdOffCfg, "00000000000000c1"))
	h.start()
	eventually(t, "locked", func() bool { return h.rec.index("lock:true") >= 0 })
	h.a.submit("drop", func(ctx context.Context) { h.a.dropToObserve(ctx, "test") })
	eventually(t, "restore", func() bool { return h.rec.index("restore") >= 0 })
	n := h.ctl.count()
	eventually(t, "informs after the drop", func() bool { return h.ctl.count() > n+2 })
	h.stop()
	calls := h.rec.list()
	r := h.rec.index("restore")
	locked := lastIndex(h.rec, "lock:true")
	if locked > r {
		t.Errorf("locked after the hand-back: %v", calls)
	}
	if i := slices.Index(calls[locked:], "lock:false"); i < 0 || locked+i > r {
		t.Errorf("not unlocked before Restore: %v", calls)
	}
	ev, _ := os.ReadFile(filepath.Join(h.root, "tp_data/udeco", eventsFile))
	if !strings.Contains(string(ev), "LOGIN OPEN: hand-back") {
		t.Errorf("events.log lacks the hand-back:\n%s", ev)
	}
}

func TestLoginLockConfig(t *testing.T) {
	base := `"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1"`
	for _, c := range []struct {
		js       string
		on       bool
		failOpen time.Duration
	}{
		{`{` + base + `,"takeover":true,"apply":true}`, true, 10 * time.Minute},
		{`{` + base + `,"takeover":true,"apply":true,"platform":"jio-mtk","model":"U7LT"}`, true, 10 * time.Minute},
		{`{` + base + `,"takeover":true,"apply":true,"login_lock":false}`, false, 10 * time.Minute},
		{`{` + base + `,"takeover":true}`, false, 10 * time.Minute},
		{`{` + base + `}`, false, 10 * time.Minute},
		{`{` + base + `,"takeover":true,"apply":true,"login_lock_failopen_s":60}`, true, time.Minute},
		{`{` + base + `,"takeover":true,"apply":true,"login_lock":true,"login_lock_failopen_s":3600}`, true, time.Hour},
	} {
		cfg, err := parseConfig([]byte(c.js))
		if err != nil {
			t.Errorf("%s: %v", c.js, err)
			continue
		}
		if cfg.loginLock() != c.on || cfg.loginLockFailOpen() != c.failOpen {
			t.Errorf("%s: on %v failopen %s", c.js, cfg.loginLock(), cfg.loginLockFailOpen())
		}
	}
	for _, js := range []string{
		`{` + base + `,"takeover":true,"apply":true,"login_lock_failopen_s":59}`,
		`{` + base + `,"takeover":true,"apply":true,"login_lock_failopen_s":3601}`,
		`{` + base + `,"takeover":true,"login_lock":true}`,
		`{` + base + `,"login_lock":true}`,
		`{` + base + `,"takeover":true,"apply":true,"login_lock":false,"login_lock_failopen_s":300}`,
	} {
		if _, err := parseConfig([]byte(js)); err == nil {
			t.Errorf("%s: want an error", js)
		}
	}
}
