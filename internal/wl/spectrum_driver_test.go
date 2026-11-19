// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Scan-driver safety tests (review of the REV2 runner): paths where a
// failure of the device or of the exec must not push the radio into a worse
// scan shape or drop a protection the band already decided on.

// failScan makes one `wl scan -c ch` call fail with fail(ctx); every other
// call goes to the replay.
type failScan struct {
	*replay
	ch   int
	fail func(ctx context.Context) error
	done bool
}

func (f *failScan) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	if cmd, ok := strings.CutPrefix(key, "wl -i "+f.radio+" "); ok && !f.done &&
		strings.HasPrefix(cmd, "scan ") && scanChannel(cmd) == f.ch {
		f.done = true
		f.mu.Lock()
		f.calls = append(f.calls, key)
		f.mu.Unlock()
		return nil, f.fail(ctx)
	}
	return f.replay.Run(ctx, name, args...)
}

// TestScanCallNotAnswerIsNotFallback: a `wl scan -c` that is killed at the
// per-call timeout (ExecRunner reports "signal: killed") or that cannot be
// started (fork/exec) is not wl rejecting the -c syntax (§3.3 trigger: "exits
// non-zero, not Busy"). It must not switch the radio to the whole-band sweep
// (about 80 % off-channel duty, remembered until restart); the band fails
// and scanabort is sent, because the killed call may have started a scan.
func TestScanCallNotAnswerIsNotFallback(t *testing.T) {
	cases := []struct {
		name string
		fail func(ctx context.Context) error
	}{
		{"killed at the call timeout", func(ctx context.Context) error {
			<-ctx.Done()
			return errors.New("signal: killed") // what exec reports, without ctx.Err()
		}},
		{"fork failed", func(context.Context) error {
			return &fs.PathError{Op: "fork/exec", Path: "/usr/sbin/wl", Err: syscall.EAGAIN}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := synthReplay("ng", nil)
			c := newSpecCollector(t, r)
			c.opt.Run = &failScan{replay: r, ch: 2, fail: tc.fail}
			c.opt.CallTimeout = 30 * time.Millisecond
			s := spectrumOf(t, c, "ng")
			res, err := s.Run(context.Background(), SpectrumRequest{SkipGate: true})
			if err == nil || res.Rows != nil {
				t.Fatalf("err %v rows %v", err, res.Rows)
			}
			if s.sweepMode() || res.Diag.Fallback != "" || res.Diag.Mode == ModeSweep {
				t.Errorf("radio switched to the sweep: mode %q fallback %q", res.Diag.Mode, res.Diag.Fallback)
			}
			for _, sc := range r.scans() {
				if scanChannel(sc) == 0 {
					t.Errorf("sweep call %q after a call that wl never answered", sc)
				}
			}
			if r.count("scanabort") != 1 || !res.Status.Abnormal {
				t.Errorf("scanabort %d, abnormal %v", r.count("scanabort"), res.Status.Abnormal)
			}
		})
	}
	// the §3.3 trigger itself is unchanged: wl exiting non-zero on -c (hex
	// on .205) still falls back (TestMeasureSpectrumHexRejectedFallsBack)
}

// TestGateFailureAfterDeferralKeepsSlowPlan: the gate measured our own
// airtime above AirtimeMax and deferred; when the next measurement fails
// (cca_get_stats and the chanim_stats us fallback both error), the band
// must not run at the full-duty HomeGap: the load it already saw is the
// best evidence it has (§8.1, BusyHomeGap).
func TestGateFailureAfterDeferralKeepsSlowPlan(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	r.cca = strings.Repeat("9   1004  500 50% High    100 10% Low      0  0% Low    4003\n", 5)
	r.base.set("wl -i wl0 chanim_stats us", response{err: errors.New("exit status 1: wl: Unsupported")})
	c := newSpecCollector(t, r)
	c.sleep = func(ctx context.Context, d time.Duration) error {
		if d == 20*time.Second { // the first deferral: the source then goes away
			r.mu.Lock()
			r.cca = ""
			r.mu.Unlock()
		}
		return r.clk.Sleep(ctx, d)
	}
	res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{})
	if err != nil {
		t.Fatal(err)
	}
	d := res.Diag
	if d.Defers != 1 || d.HomeGap != time.Second {
		t.Errorf("defers %d, home gap %v (notes %v)", d.Defers, d.HomeGap, d.Notes)
	}
	for i := 1; i < len(r.scanAt); i++ {
		if gap := r.scanAt[i].Sub(r.readyAt[i-1]); gap < time.Second {
			t.Errorf("call %d: home gap %v after a deferral for load", i+1, gap)
		}
	}

	// no deferral before the failure: scanning without the gate keeps the
	// normal plan, as before
	r = t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	r.cca = ""
	r.base.set("wl -i wl0 chanim_stats us", response{err: errors.New("exit status 1: wl: Unsupported")})
	c = newSpecCollector(t, r)
	res, err = spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{})
	if err != nil || res.Diag.HomeGap != 400*time.Millisecond || res.Diag.Defers != 0 {
		t.Errorf("no load seen: err %v gap %v defers %d", err, res.Diag.HomeGap, res.Diag.Defers)
	}
}
