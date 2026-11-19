// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

import (
	"testing"
	"time"
)

func TestSatisfaction(t *testing.T) {
	// sub-scores, as in UAP firmware 6.8.2
	for _, c := range []struct{ kbps, avail, want int }{
		{866700, 100, 100}, {866700, 15, 99}, {100000, 100, 98}, {12000, 100, 84}, {6000, 100, 71}, {500, 100, 0},
	} {
		if got := phyScore(c.kbps, c.avail, true); got != c.want {
			t.Errorf("phy %d kbps avail %d: %d, want %d", c.kbps, c.avail, got, c.want)
		}
	}
	if phyScore(6000, 100, false) != 100 {
		t.Error("2.4 GHz clients always score 100 on PHY rate")
	}
	for _, c := range []struct {
		r, a int64
		want int
	}{{5, 20, 100}, {10, 100, 100}, {50, 100, 88}, {67, 100, 79}, {100, 100, 62}} {
		if got := retryScore(c.r, c.a); got != c.want {
			t.Errorf("retries %d/%d: %d, want %d", c.r, c.a, got, c.want)
		}
	}
	// a slow 5 GHz client: real score below 60, reported 60, anomaly bit 2
	satStates = map[string]*satState{}
	t0 := time.Unix(1000, 0)
	st := Station{MAC: "aa", TxRate: 500}
	r := staSatisfaction(st, true, 100, t0)
	if r.Real != 0 || r.Reported != 60 || r.Anomalies != anomalyPHYRate {
		t.Errorf("slow client: %+v", r)
	}
	// within the cycle the result stands; later cycles average
	st.TxRate = 866700
	if r2 := staSatisfaction(st, true, 100, t0.Add(time.Second)); r2 != r {
		t.Errorf("same cycle: %+v", r2)
	}
	if r3 := staSatisfaction(st, true, 100, t0.Add(6*time.Second)); r3.Real != 50 || r3.Now != 100 || r3.Reported != 60 {
		t.Errorf("second cycle: %+v", r3)
	}
	// heavy retries in one cycle
	st2 := Station{MAC: "bb", TxRate: 866700}
	staSatisfaction(st2, true, 100, t0)
	st2.TxPackets, st2.TxRetries = 100, 100 // 100 retries of 200 attempts = 50 %
	if r := staSatisfaction(st2, true, 100, t0.Add(6*time.Second)); r.Now != 88 || r.Real != 94 {
		t.Errorf("retries: %+v", r)
	}
}
