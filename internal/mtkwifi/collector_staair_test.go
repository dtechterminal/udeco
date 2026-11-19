// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"fmt"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// The MT7603 reports no own airtime: its transmit and receive time are
// estimated from the stations' byte counters and rates.
func TestStaAirtime(t *testing.T) {
	stas := []sta{
		{Station: apstate.Station{MAC: "a", TxRate: 72000, RxRate: 72000}},   // 72 Mbit/s
		{Station: apstate.Station{MAC: "b", TxRate: 144000, RxRate: 144000}}, // 144 Mbit/s
		{Station: apstate.Station{MAC: "c", TxRate: 65000, RxRate: 65000}},   // new: no last counts
		{Station: apstate.Station{MAC: "d"}},                                 // no rate
		{Station: apstate.Station{MAC: "e", TxRate: 72000, RxRate: 72000}},   // counters went down
	}
	last := map[string]staCount{"a": {txBytes: 0, rxBytes: 1000}, "b": {rxBytes: 0, txBytes: 500}, "d": {}, "e": {txBytes: 9e6, rxBytes: 9e6}}
	next := map[string]staCount{
		"a": {txBytes: 1_800_000, rxBytes: 1000 + 900_000}, // tx 14.4 Mbit at 72 = 0.2 s; rx 7.2 Mbit = 0.1 s
		"b": {txBytes: 500, rxBytes: 1_800_000},            // tx idle; rx 14.4 Mbit at 144 = 0.1 s
		"c": {txBytes: 5e6, rxBytes: 5e6}, "d": {txBytes: 5e6, rxBytes: 5e6}, "e": {txBytes: 10, rxBytes: 10}}
	// over 10 s: tx 0.02 s a second, rx 0.02 s a second
	if tx, rx := staAirtime(stas, last, next, 10*time.Second); tx != 20000 || rx != 20000 {
		t.Errorf("staAirtime = tx %d rx %d, want 20000 and 20000", tx, rx)
	}
	if tx, rx := staAirtime(stas, last, next, 0); tx != 0 || rx != 0 {
		t.Errorf("dt 0: %d %d", tx, rx)
	}
	// more than the air holds is capped at one second a second
	if tx, rx := staAirtime(stas, last, next, time.Millisecond); tx != 1_000_000 || rx != 1_000_000 {
		t.Errorf("cap: %d %d", tx, rx)
	}
}

func TestWithStaAir(t *testing.T) {
	// MT7603: the driver gives busy time only; both are filled
	b := &busySample{busy: 456849}
	if got := withStaAir(b, 100000, 50000); *got != (busySample{busy: 456849, tx: 100000, rx: 50000}) || *b != (busySample{busy: 456849}) {
		t.Errorf("filled %+v, original %+v", got, b)
	}
	// more than the busy time: both scaled down to it, in proportion
	if got := withStaAir(&busySample{busy: 250000}, 500000, 500000); *got != (busySample{busy: 250000, tx: 125000, rx: 125000}) {
		t.Errorf("capped: %+v", got)
	}
	if got := withStaAir(&busySample{busy: 300000}, 600000, 300000); *got != (busySample{busy: 300000, tx: 200000, rx: 100000}) {
		t.Errorf("capped in proportion: %+v", got)
	}
	// MT7663: its own transmit time stands; only rx is filled, within
	// what the busy time leaves after it
	if got := withStaAir(&busySample{busy: 74060, tx: 8782}, 999, 20000); *got != (busySample{busy: 74060, tx: 8782, rx: 20000}) {
		t.Errorf("driver tx: %+v", got)
	}
	if got := withStaAir(&busySample{busy: 74060, tx: 8782}, 0, 900000); got.rx != 74060-8782 || got.tx != 8782 {
		t.Errorf("rx capped after the driver's tx: %+v", got)
	}
	// the driver's own figures win; no reading stays none
	if got := withStaAir(&busySample{busy: 10, tx: 2, rx: 3}, 5, 5); *got != (busySample{busy: 10, tx: 2, rx: 3}) {
		t.Errorf("driver tx and rx: %+v", got)
	}
	if withStaAir(nil, 5, 5) != nil {
		t.Error("nil busy")
	}
	if got := withStaAir(b, 0, 0); got != b {
		t.Error("no estimate: changed")
	}
}

// staCountText is a `show stacountinfo` table (stacountinfo_ra0.klog's
// layout) with fc:3c:d7:31:00:cd's byte counters.
func staCountText(txBytes, rxBytes int64) string {
	return "MAC                AID TxPackets   RxPackets   TxBytes     RxBytes     TP(Tx)      TP(Rx)      \n" +
		fmt.Sprintf("FC:3C:D7:31:00:CD  1   386         413         %-11d %-11d 0Mbps       0Mbps       \n", txBytes, rxBytes) +
		"C0:F8:53:17:23:A7  2   120         93          11664       12589       11664125890Mbps       0Mbps       \n"
}

// TestCollectStaAirtime: the 2.4 GHz inform's own airtime (cu_self_tx,
// cu_self_rx) is the station-counter estimate, within the busy time.
func TestCollectStaAirtime(t *testing.T) {
	r := newMibRig(t)
	d := r.d
	// fc:3c:d7:31:00:cd is at 72 Mbit/s (macDump)
	d.prints["ra0 stacountinfo"] = staCountText(1000, 1000)
	r.after(0)
	// 10 s on: it sent 72 Mbit (1 s: 10 %) and received 36 Mbit (5 %);
	// busy 45.7 % (the real block over 10 s)
	d.prints["ra0 stacountinfo"] = staCountText(1000+9_000_000, 1000+4_500_000)
	s1 := r.after(10 * time.Second)
	s2 := r.after(2 * time.Second)
	r.wantCU("estimate within the busy time", s1, s2, 46, 10, 5)

	// 10 s on (12 s since the last counts and ask): 432 Mbit each way is
	// 6 s, 50 % each, past the 25 % busy time: both scaled to 12.5 %
	d.prints["ra0 stacountinfo"] = staCountText(1000+9_000_000+54_000_000, 1000+4_500_000+54_000_000)
	d.prints["ra0 mibinfo"] = withPrimCCA(t, "0x2dc6c0")
	s3 := r.after(10 * time.Second)
	r.wantCU("estimate capped by the busy time", s2, s3, 25, 13, 13)
}
