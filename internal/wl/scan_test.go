// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestScan(t *testing.T) {
	c, fr, _ := newTestCollector(t)
	fr.set("wl -i wl0 scan", response{})
	fr.set("wl -i wl0 scanresults",
		response{err: errors.New("wl: Not Ready")},
		response{err: errors.New("wl: Busy")},
		response{out: string(fixture(t, "wl_-i_wl0_scanresults_populated.txt"))})
	res, err := c.Scan(context.Background(), "ng")
	if err != nil {
		t.Fatal(err)
	}
	// neighbours only: spectrum_table rows come from the spectrum runner
	if res.Band != "ng" || len(res.BSS) != 25 || res.Spectrum != nil || res.Time.IsZero() {
		t.Errorf("result: band %s, %d BSS, %d spectrum rows", res.Band, len(res.BSS), len(res.Spectrum))
	}
	var scans, polls int
	for _, call := range fr.callList() {
		switch call {
		case "wl -i wl0 scan":
			scans++
		case "wl -i wl0 scanresults":
			polls++
		}
		if strings.Contains(call, "wl1 scan") {
			t.Errorf("scanned the other radio: %s", call)
		}
	}
	if scans != 1 || polls != 3 {
		t.Errorf("%d scans, %d polls", scans, polls)
	}

	// 5 GHz: the radio is found by band; no chanim fixture with results is
	// needed for the BSS list
	fr.set("wl -i wl1 scan", response{})
	fr.set("wl -i wl1 scanresults", response{out: "SSID: \"x\"\nMode: Managed\tRSSI: -50 dBm\tChannel: 36/80\nBSSID: 00:11:22:33:44:55\tCapability: ESS\n"})
	fr.set("wl -i wl1 chanim_stats all", response{err: errors.New("wl: Unsupported")})
	res, err = c.Scan(context.Background(), "na")
	if err != nil || len(res.BSS) != 1 || res.BSS[0].Channel != 36 || res.Spectrum != nil {
		t.Errorf("na scan: %+v, %v", res, err)
	}

	if _, err := c.Scan(context.Background(), "6e"); err == nil {
		t.Error("6e scan accepted")
	}
}

// TestScanHoldsHomeChanspec: while the legacy scan runs, Collect's
// current-channel reads report the chanspec read before the scan (`wl
// chanspec` shows the scan channel mid-scan [M T7]) and run no live read;
// afterwards they read live again.
func TestScanHoldsHomeChanspec(t *testing.T) {
	c, fr, _ := newTestCollector(t)
	fr.set("wl -i wl0 chanspec", response{out: "2l (0x1804)\n"}, response{out: "1 (0x1001)\n"})
	fr.set("wl -i wl0 scan", response{})
	fr.set("wl -i wl0 scanresults", response{err: errors.New("wl: Not Ready")}, response{out: ""})
	var during []radioCurrent
	c.sleep = func(ctx context.Context, d time.Duration) error {
		during = append(during, c.readCurrent(ctx, "wl0"))
		return ctx.Err()
	}
	if _, err := c.Scan(context.Background(), "ng"); err != nil {
		t.Fatal(err)
	}
	if len(during) == 0 {
		t.Fatal("no poll")
	}
	for _, rc := range during {
		if !rc.inBand || !strings.HasPrefix(string(rc.chanspec), "2l") {
			t.Errorf("during the scan: inBand %v chanspec %q", rc.inBand, rc.chanspec)
		}
	}
	if rc := c.readCurrent(context.Background(), "wl0"); rc.inBand || !strings.HasPrefix(string(rc.chanspec), "1 ") {
		t.Errorf("after the scan: inBand %v chanspec %q", rc.inBand, rc.chanspec)
	}
	// one scan at a time: a cancelled wait for a running spectrum band
	// never starts the scan
	if err := c.scanMu.LockCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	n := len(fr.callList())
	if _, err := c.Scan(ctx, "ng"); err == nil || len(fr.callList()) != n {
		t.Errorf("scan ran while the lock was held: %v", err)
	}
	c.scanMu.Unlock()
}

func TestScanFailures(t *testing.T) {
	c, fr, _ := newTestCollector(t)
	// the scan request itself fails
	fr.set("wl -i wl0 scan", response{err: errors.New("wl: Busy")})
	if _, err := c.Scan(context.Background(), "ng"); err == nil {
		t.Error("failed scan accepted")
	}
	// results never come: "Not Found" until the deadline = nothing found
	fr.set("wl -i wl0 scan", response{})
	fr.set("wl -i wl0 scanresults", response{err: errors.New("wl: Not Found")})
	polls := 0
	c.sleep = func(ctx context.Context, d time.Duration) error {
		polls++
		if polls > 3 {
			return context.DeadlineExceeded
		}
		return ctx.Err()
	}
	res, err := c.Scan(context.Background(), "ng")
	if err != nil || len(res.BSS) != 0 {
		t.Errorf("empty scan: %+v, %v", res, err)
	}
	// still "Not Ready" at the deadline is an error
	fr.set("wl -i wl0 scanresults", response{err: errors.New("wl: Not Ready")})
	polls = 0
	if _, err := c.Scan(context.Background(), "ng"); err == nil {
		t.Error("timed-out scan accepted")
	}
	// any other error ends the scan at once
	fr.set("wl -i wl0 scanresults", response{err: errors.New("wl: Bad Argument")})
	polls = 0
	if _, err := c.Scan(context.Background(), "ng"); err == nil || polls != 1 {
		t.Errorf("err %v after %d polls", err, polls)
	}
}

func TestExecRunner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	out, err := ExecRunner{}.Run(context.Background(), "sh", "-c", "echo out; echo 'wl: Not Ready' >&2; exit 1")
	if err == nil || !strings.Contains(err.Error(), "wl: Not Ready") || string(out) != "out\n" {
		t.Errorf("out %q, err %v", out, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := (ExecRunner{}).Run(ctx, "sleep", "5"); err == nil || time.Since(start) > 3*time.Second {
		t.Errorf("timeout not honoured: %v after %v", err, time.Since(start))
	}
}

func TestWLRejectsBadInterface(t *testing.T) {
	c, fr, _ := newTestCollector(t)
	for _, bad := range []string{"", "-x", "wl0;reboot", "a b", strings.Repeat("w", 16)} {
		if _, err := c.wl(context.Background(), bad, "bss"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if n := len(fr.callList()); n != 0 {
		t.Errorf("%d calls ran", n)
	}
}

func TestCallTimeout(t *testing.T) {
	block := runnerFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	c := New(Options{Root: t.TempDir(), Run: block, CallTimeout: 20 * time.Millisecond})
	start := time.Now()
	if _, err := c.wl(context.Background(), "wl0", "bss"); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Errorf("err %v after %v", err, time.Since(start))
	}
}

type runnerFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

func (f runnerFunc) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f(ctx, name, args...)
}

// HomeScan listens passively on the radio's own control channel only (the
// call form checked on .205: `wl -i wl1 scan -t passive -p 110 -c 40` while
// the radio sat on 40u), never a full scan.
func TestHomeScan(t *testing.T) {
	c, fr, _ := newTestCollector(t)
	fr.set("wl -i wl0 chanspec", response{out: "9 (0x1009)\n"})
	fr.set("wl -i wl0 scan -t passive -p 110 -c 9", response{})
	fr.set("wl -i wl0 scanresults", response{out: string(fixture(t, "wl_-i_wl0_scanresults_populated.txt"))})
	res, err := c.HomeScan(context.Background(), "ng")
	if err != nil {
		t.Fatal(err)
	}
	if res.Band != "ng" || len(res.BSS) == 0 {
		t.Fatalf("result %+v", res)
	}
	for _, call := range fr.callList() {
		if call == "wl -i wl0 scan" || strings.Contains(call, "wl1 scan") {
			t.Errorf("left the home channel: %s", call)
		}
	}

	// a chanspec it cannot read: no scan at all
	c2, fr2, _ := newTestCollector(t)
	fr2.set("wl -i wl0 chanspec", response{out: "garbage\n"})
	if _, err := c2.HomeScan(context.Background(), "ng"); err == nil {
		t.Error("unreadable chanspec: no error")
	}
	for _, call := range fr2.callList() {
		if strings.HasPrefix(call, "wl -i wl0 scan") {
			t.Errorf("scanned without a home channel: %s", call)
		}
	}
}
