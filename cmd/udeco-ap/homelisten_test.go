// SPDX-License-Identifier: GPL-2.0-or-later
package main

import (
	"context"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
)

type homeCol struct {
	collector
	calls []string
}

func (h *homeCol) HomeScan(ctx context.Context, band string) (*apstate.ScanResult, error) {
	h.calls = append(h.calls, band)
	return &apstate.ScanResult{Band: band, Time: time.Now(), BSS: []apstate.BSS{{BSSID: "11:22:33:44:55:77", SSID: "n", Channel: 40}}}, nil
}

// The listen keeps scan_table fed and stays out of the way of controller
// scans and blocked periods.
func TestHomeListenRound(t *testing.T) {
	h := &homeCol{}
	a := &agent{scans: newScanner()}
	a.o.col = h
	a.takeover.Store(true)
	a.homeListenRound(context.Background(), map[string]string{})
	if len(h.calls) != 2 || len(a.scans.results["na"].BSS) != 1 || len(a.scans.results["ng"].BSS) != 1 {
		t.Fatalf("calls %v results %+v", h.calls, a.scans.results)
	}

	h.calls = nil
	a.scans.begin("spectrum-scan", false, true)
	a.homeListenRound(context.Background(), map[string]string{})
	a.scans.end()
	if len(h.calls) != 0 {
		t.Errorf("listened during a controller scan: %v", h.calls)
	}

	a.wifiBusy.Store(true)
	a.homeListenRound(context.Background(), map[string]string{})
	a.wifiBusy.Store(false)
	if len(h.calls) != 0 {
		t.Errorf("listened during a Wi-Fi apply: %v", h.calls)
	}
}
