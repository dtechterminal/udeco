// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRunWhileAnotherScanReturnsResult: a Run that gives up waiting for the
// scan lock (another scan holds it, ctx ends) still returns a result whose
// Status carries the radio's table, like every other failure of Run, and
// does not mark the radio abnormal (the band never started, §7 "skipped:
// already in progress").
func TestRunWhileAnotherScanReturnsResult(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	c := newSpecCollector(t, r)
	s := spectrumOf(t, c, "ng")
	good, err := s.Run(context.Background(), SpectrumRequest{SkipGate: true})
	if err != nil {
		t.Fatal(err)
	}

	c.scanMu.Lock() // a scan (Scan or another band) is running
	defer c.scanMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	res, err := s.Run(ctx, SpectrumRequest{SkipGate: true})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if res == nil {
		t.Fatal("nil result: callers reading res.Status on failure would panic")
	}
	if res.Rows != nil || res.Status.Abnormal || len(res.Status.Rows[20]) != 11 || !res.Status.TableTime.Equal(good.Status.TableTime) {
		t.Errorf("status %+v", res.Status)
	}
	if res.Diag.Err == "" || res.Radio != "wl0" || res.Band != "ng" {
		t.Errorf("diag %+v", res.Diag)
	}
}

// TestRunRowsDoNotAliasTable: the rows Run returns are the caller's; changing
// them must not change the table the runner keeps for later informs.
func TestRunRowsDoNotAliasTable(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	c := newSpecCollector(t, r)
	s := spectrumOf(t, c, "ng")
	res, err := s.Run(context.Background(), SpectrumRequest{SkipGate: true})
	if err != nil {
		t.Fatal(err)
	}
	res.Rows[20][0].Utilization = 99
	res.Rows[40] = nil
	st := s.Status()
	if st.Rows[20][0].Utilization == 99 {
		t.Error("runner table changed through the returned rows")
	}
	if _, ok := st.Rows[40]; ok {
		t.Error("runner table gained a width through the returned map")
	}
}
