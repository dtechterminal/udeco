// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// The MT7603 reports no own receive airtime: it is estimated from the
// stations' byte counters and rates.
func TestRxAirtime(t *testing.T) {
	stas := []sta{
		{Station: apstate.Station{MAC: "a", RxRate: 72000}},  // 72 Mbit/s
		{Station: apstate.Station{MAC: "b", RxRate: 144000}}, // 144 Mbit/s
		{Station: apstate.Station{MAC: "c", RxRate: 65000}},  // new: no last counts
		{Station: apstate.Station{MAC: "d", RxRate: 0}},      // no rate
		{Station: apstate.Station{MAC: "e", RxRate: 72000}},  // counters went down
	}
	last := map[string]staCount{"a": {rxBytes: 1000}, "b": {rxBytes: 0}, "d": {rxBytes: 0}, "e": {rxBytes: 9e6}}
	next := map[string]staCount{"a": {rxBytes: 1000 + 900_000}, "b": {rxBytes: 1_800_000}, "c": {rxBytes: 5e6},
		"d": {rxBytes: 5e6}, "e": {rxBytes: 10}}
	// a: 900 kB = 7.2 Mbit at 72 Mbit/s = 0.1 s; b: 14.4 Mbit at 144 = 0.1 s;
	// over 10 s: 0.02 s a second = 20000 µs
	if got := rxAirtime(stas, last, next, 10*time.Second); got != 20000 {
		t.Errorf("rxAirtime = %d, want 20000", got)
	}
	if got := rxAirtime(stas, last, next, 0); got != 0 {
		t.Errorf("dt 0: %d", got)
	}
	// more than the air holds is capped at one second a second
	if got := rxAirtime(stas, last, next, time.Millisecond); got != 1_000_000 {
		t.Errorf("cap: %d", got)
	}
}

func TestWithRxAir(t *testing.T) {
	b := &busySample{busy: 74060, tx: 8782}
	if got := withRxAir(b, 20000); got.rx != 20000 || b.rx != 0 {
		t.Errorf("filled %+v, original %+v", got, b)
	}
	// never more than the busy time leaves after own tx
	if got := withRxAir(b, 900000); got.rx != 74060-8782 {
		t.Errorf("capped: %+v", got)
	}
	// the driver's own figure wins; no reading stays none
	if got := withRxAir(&busySample{busy: 10, rx: 3}, 5); got.rx != 3 {
		t.Errorf("driver rx: %+v", got)
	}
	if withRxAir(nil, 5) != nil {
		t.Error("nil busy")
	}
	if got := withRxAir(b, 0); got != b {
		t.Error("no estimate: changed")
	}
}
