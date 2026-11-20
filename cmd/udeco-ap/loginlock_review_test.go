// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
	"github.com/antoniocosta/unifi-openwrt/internal/inform"
	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
	"github.com/antoniocosta/unifi-openwrt/internal/unit"
)

// stamped is a noop reply with the controller's time (ms).
func stamped(ms int64) []byte {
	return []byte(`{"_type":"noop","interval":10,"server_time_in_utc":"` + strconv.FormatInt(ms, 10) + `"}`)
}

// A reply counts as the controller answering only when its
// server_time_in_utc is later than every one counted before: a replayed
// reply (the same or an older time) and one without a time do not.
func TestLockReplyFreshness(t *testing.T) {
	a, s, _, now := lockAgent(t)
	ctx := context.Background()
	t0 := *now
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:false")
	a.lockFromCfg(true, sshdOf(sshdOffCfg))
	if !a.lockReply(stamped(1_000_000), *now) {
		t.Fatal("the first reply did not count")
	}
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:true")

	*now = t0.Add(9 * time.Minute)
	for _, p := range [][]byte{stamped(1_000_000), stamped(999_999), []byte(`{"_type":"noop","interval":10}`)} {
		if a.lockReply(p, *now) {
			t.Errorf("%s counted", p)
		}
	}
	*now = t0.Add(10 * time.Minute)
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:false") // replays kept nothing alive
	if !a.lockReply(stamped(1_600_000), *now) {
		t.Fatal("a later reply did not count")
	}
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:true")

	// a Device SSH change that came with a replayed reply is not taken
	a.lockReply(stamped(1_500_000), *now)
	a.lockFromCfg(true, sshdOf(sshdOnCfg))
	a.lockEval(ctx, false)
	expectCalls(t, s)
	// the same change with a fresh reply is
	a.lockReply(stamped(1_700_000), *now)
	a.lockFromCfg(true, sshdOf(sshdOnCfg))
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:false")
}

// lockClock is a wall clock the test can move forward.
type lockClock struct{ off atomic.Int64 }

func (c *lockClock) now() time.Time       { return time.Now().Add(time.Duration(c.off.Load())) }
func (c *lockClock) jump(d time.Duration) { c.off.Add(int64(d)) }

// forgedFrames are CBC frames made without the key (random IV and
// payload) that still decode with key: about 1 in 256 random frames has
// valid padding.
func forgedFrames(t *testing.T, key string, n int) [][]byte {
	t.Helper()
	mac, _ := net.ParseMAC(unitMAC)
	rng := mrand.New(mrand.NewPCG(1, 2))
	var out [][]byte
	for tries := 0; len(out) < n && tries < 1_000_000; tries++ {
		b := make([]byte, inform.HeaderLen+32)
		binary.BigEndian.PutUint32(b[0:4], inform.Magic)
		copy(b[8:14], mac)
		binary.BigEndian.PutUint16(b[14:16], inform.FlagEncrypted)
		binary.BigEndian.PutUint32(b[32:36], inform.DataVersion)
		binary.BigEndian.PutUint32(b[36:40], 32)
		for i := 16; i < len(b); i++ {
			if i < 32 || i >= inform.HeaderLen {
				b[i] = byte(rng.Uint32())
			}
		}
		if _, _, err := inform.Decode(b, key); err == nil {
			out = append(out, b)
		}
	}
	if len(out) < n {
		t.Fatalf("only %d forged frames decode", len(out))
	}
	return out
}

// A forged reply that decodes (CBC has no authentication) but is not a
// reply the agent can handle does not keep the controller "answering":
// after 10 minutes of real silence the lock opens.
func TestLoginLockForgedReplyNotCounted(t *testing.T) {
	stdLog(t)
	clk := &lockClock{}
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true; o.now = clk.now })
	s := newLockSys(h.sys)
	h.a.o.newSys = func(decosys.Options) sysManager { return s }
	h.ctl.stamp = 1_700_000_000_000
	h.ctl.queue(adoptReply, cfgReplyVersion(usersCfg+sshdOffCfg, "00000000000000c1"))
	h.start()
	eventually(t, "locked", func() bool { return h.rec.index("lock:true") >= 0 })
	frames := forgedFrames(t, testKey, 20)
	h.ctl.mu.Lock()
	h.ctl.onRaw = func() { clk.jump(11 * time.Minute) } // only forged frames answer from here on
	h.ctl.mu.Unlock()
	h.ctl.sendRaw(frames...)
	eventually(t, "opened after 10 minutes of real silence", func() bool {
		return lastIndex(h.rec, "lock:false") > lastIndex(h.rec, "lock:true")
	})
	h.stop()
	ev, _ := os.ReadFile(filepath.Join(h.root, "tp_data/udeco", eventsFile))
	if !strings.Contains(string(ev), "LOGIN OPEN: controller silent 10m") {
		t.Errorf("events.log lacks the fail-open:\n%s", ev)
	}
}

// A replayed reply (sealed by the real controller earlier, sent again by
// someone on the path) does not open the lock with its old Device SSH on.
func TestLoginLockReplayIgnored(t *testing.T) {
	stdLog(t)
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	s := newLockSys(h.sys)
	h.a.o.newSys = func(decosys.Options) sysManager { return s }
	h.ctl.stamp = 1_700_000_000_000
	h.ctl.queue(adoptReply, cfgReplyVersion(usersCfg+sshdOnCfg, "00000000000000c1"))
	h.start()
	eventually(t, "c1 sent", func() bool { return len(h.ctl.sentFrames()) >= 3 })
	c1 := h.ctl.sentFrames()[1]
	if _, p, err := inform.Decode(c1, testKey); err != nil || !strings.Contains(string(p), "00000000000000c1") {
		t.Fatalf("frame 1 is not c1: %v %s", err, p)
	}
	h.ctl.queue(cfgReplyVersion(usersCfg+sshdOffCfg, "00000000000000c2"))
	eventually(t, "locked", func() bool { return h.rec.index("lock:true") >= 0 })
	h.ctl.sendRaw(c1)
	n := h.ctl.count()
	eventually(t, "replay and noops answered", func() bool { return h.ctl.count() > n+5 })
	h.stop()
	calls := h.rec.list()
	after := calls[h.rec.index("lock:true"):]
	if i := slices.Index(after, "lock:false"); i < len(after)-1 {
		t.Errorf("the replay opened the lock before the stop: %v", calls)
	}
	ev, _ := os.ReadFile(filepath.Join(h.root, "tp_data/udeco", eventsFile))
	if strings.Contains(string(ev), "LOGIN OPEN: Device SSH on") {
		t.Errorf("the replay opened the lock:\n%s", ev)
	}
	if !strings.Contains(h.logs.all(), "login lock: a Device SSH change from a reply that is not newer") {
		t.Errorf("the ignored change is not logged:\n%s", h.logs.all())
	}
}

// The agent's stop opens the lock as soon as the inform loop ends, not
// after every background job has returned: a job that hangs must not keep
// root logins closed with nothing left to fail open.
func TestLoginLockReleasedBeforeBackgroundWait(t *testing.T) {
	stdLog(t)
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	s := newLockSys(h.sys)
	h.a.o.newSys = func(decosys.Options) sysManager { return s }
	h.ctl.stamp = 1_700_000_000_000
	h.ctl.queue(adoptReply, cfgReplyVersion(usersCfg+sshdOffCfg, "00000000000000c1"))
	h.start()
	eventually(t, "locked", func() bool { return h.rec.index("lock:true") >= 0 })
	hold := make(chan struct{})
	h.a.bg.Add(1)
	go func() { <-hold; h.a.bg.Done() }()
	h.cancel()
	eventually(t, "opened while a job hangs", func() bool {
		return lastIndex(h.rec, "lock:false") > lastIndex(h.rec, "lock:true")
	})
	close(hold)
	h.stop()
	if lastIndex(h.rec, "lock:true") > lastIndex(h.rec, "lock:false") {
		t.Errorf("locked again after the stop: %v", h.rec.list())
	}
}

// After the stop's release nothing locks again: a tick still running
// cannot put the lock back.
func TestLockStopIsFinal(t *testing.T) {
	a, s, logs, now := lockAgent(t)
	ctx := context.Background()
	a.lockFromCfg(true, sshdOf(sshdOffCfg))
	a.lockAnswered(*now)
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:true")
	a.lockStop()
	expectCalls(t, s, "lock:false")
	a.lockEval(ctx, true)
	a.lockEval(ctx, false)
	expectCalls(t, s)
	if eventCount(logs, "LOGIN OPEN: agent stop") != 1 {
		t.Errorf("no stop event:\n%s", logs.all())
	}
}

// A lock that could not be re-checked but was left exactly as it was
// (decosys.ErrLockUnchanged) is still locked: no LOGIN OPEN, retried at
// the next tick.
func TestLoginLockUnchangedKeepsState(t *testing.T) {
	a, s, logs, now := lockAgent(t)
	ctx := context.Background()
	a.lockFromCfg(true, sshdOf(sshdOffCfg))
	a.lockAnswered(*now)
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:true")
	s.setFail(func(on bool) error {
		return fmt.Errorf("login lock: iptables -S UDECO-LOCK: busy (%w)", decosys.ErrLockUnchanged)
	})
	a.lockEval(ctx, true)
	expectCalls(t, s, "lock:true")
	if strings.Contains(logs.all(), "LOGIN OPEN") {
		t.Errorf("an unchanged lock reported open:\n%s", logs.all())
	}
	s.setFail(nil)
	a.lockEval(ctx, true)
	expectCalls(t, s, "lock:true")
	if n := strings.Count(logs.all(), "EVENT: LOGIN LOCKED"); n != 1 {
		t.Errorf("%d LOCKED events, want 1:\n%s", n, logs.all())
	}
	// the decision to open still opens it
	a.lockFromCfg(true, sshdOf(sshdOnCfg))
	a.lockEval(ctx, false)
	expectCalls(t, s, "lock:false")
}

// The Deco launcher removes a lock left behind even when it then cannot
// start an agent (no binary, or a deployed gz that does not check out).
func TestDeployLauncherUnlocksBeforeEarlyExits(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	unlock := lockRemoval(true)
	for _, c := range []string{"no binary", "gz without its md5"} {
		root := t.TempDir()
		dir := filepath.Join(root, unit.DecoDir)
		bin := filepath.Join(root, "bin")
		for _, d := range []string{dir, filepath.Dir(filepath.Join(root, unit.RAMDir)), bin} {
			os.MkdirAll(d, 0o755)
		}
		log := filepath.Join(root, "calls")
		os.WriteFile(filepath.Join(bin, "pidof"), []byte("#!/bin/sh\nexit 1\n"), 0o755)
		os.WriteFile(filepath.Join(bin, "logger"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
		fakeIptables(t, bin, log)
		if c == "gz without its md5" {
			os.WriteFile(filepath.Join(dir, "udeco-ap.gz"), []byte("not gzip"), 0o644)
		}
		script := filepath.Join(root, "start.sh")
		os.WriteFile(script, []byte(launcher(t, root)), 0o755)
		cmd := exec.Command(sh, script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		cmd.CombinedOutput()
		if got, _ := os.ReadFile(log); string(got) != unlock {
			t.Errorf("%s: calls:\n%s\nwant:\n%s", c, got, unlock)
		}
	}
}

// The Garage launcher's loop removes the lock first, before anything that
// can skip the start (the gunzip that waits and retries).
func TestJioStartUnlocksFirst(t *testing.T) {
	b := repotest.Read(t, jioStart)
	i := strings.LastIndex(b, "while [ -f $D/start.sh ]; do\n")
	if i < 0 {
		t.Fatal("no supervisor loop in deploy/jio-start.sh")
	}
	for _, l := range strings.Split(b[i:], "\n")[1:] {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if l != "unlock" {
			t.Errorf("the loop's first statement is %q, not unlock", l)
		}
		break
	}
}
