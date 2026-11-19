// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// mibBlockText is a `show mibinfo` busy-time block as the MT7603 prints it
// (mibinfo_ra0.klog), with other values.
func mibBlockText(busy, tx, rx, idle string) string {
	return " Channel busy time Threshold = 600000\n" +
		" One sec channel busy time = " + busy + "\n" +
		" One sec primary channel busy time = 21600\n" +
		" One sec My Tx Airtime = " + tx + "\n" +
		" One sec My Rx Airtime = " + rx + "\n" +
		" IPI Idle time = " + idle + "\n" +
		"MIB Status Control=0x0\nCCA_NAV_Tx_Time=0x0\n"
}

func TestParseMibInfo(t *testing.T) {
	b, ok := parseMibInfo(fixture(t, "mibinfo_ra0.klog"))
	if !ok || b != (mibBlock{busySample{busy: 74060, tx: 8782, rx: 0}, 1042235167}) {
		t.Errorf("mibinfo = %+v, %v", b, ok)
	}
	// the newest block counts, not an older call's
	two := mibBlockText("1000", "10", "0", "5") + "noise\n" + mibBlockText("250000", "40000", "7", "6")
	if b, ok := parseMibInfo(two); !ok || b != (mibBlock{busySample{busy: 250000, tx: 40000, rx: 7}, 6}) {
		t.Errorf("two blocks: %+v, %v", b, ok)
	}
	// printk level prefixes
	pre := "<4>" + strings.ReplaceAll(strings.TrimSuffix(mibBlockText("5000", "100", "0", "9"), "\n"), "\n", "\n<4>")
	if b, ok := parseMibInfo(pre); !ok || b.busy != 5000 || b.tx != 100 {
		t.Errorf("prefixed block: %+v, %v", b, ok)
	}
	// own airtime past the busy time: busy is at least tx + rx
	if b, _ := parseMibInfo(mibBlockText("100", "300", "50", "1")); b.busy != 350 {
		t.Errorf("busy %d, want 350", b.busy)
	}
	// a block cut before its Tx line, or no block at all: no reading
	cut := " One sec channel busy time = 74060\n One sec primary channel busy time = 21600\nMIB Status Control=0x0\n One sec My Tx Airtime = 5\n"
	if _, ok := parseMibInfo(cut); ok {
		t.Error("a block without its Tx airtime gave a reading")
	}
	if _, ok := parseMibInfo(fixture(t, "stacountinfo_ra0.klog")); ok {
		t.Error("a log without the block gave a reading")
	}
}

// TestMibBusyStale: only a block the request printed is taken.
func TestMibBusyStale(t *testing.T) {
	pad := strings.Repeat("x\n", 200)
	old := mibBlockText("1000", "10", "0", "5")
	fresh := mibBlockText("250000", "40000", "0", "6")
	before := pad + old

	// the ring is full and rolling: after has lost before's start, but its
	// end is found
	after := before[100:] + fresh
	added, anchored := newLogAnchored(before, after)
	if b := mibBusy(added, anchored, before); !anchored || b == nil || b.busy != 250000 {
		t.Errorf("rolled ring: anchored %v, %+v", anchored, b)
	}
	// the driver printed nothing: no reading, not the older block
	added, anchored = newLogAnchored(before, before[100:])
	if b := mibBusy(added, anchored, before); !anchored || b != nil {
		t.Errorf("nothing printed: anchored %v, %+v", anchored, b)
	}
	// before's end is gone (not anchored) and the newest block is the one
	// before already ended in: an older call's, not taken
	if b := mibBusy(old, false, before); b != nil {
		t.Errorf("unanchored stale block taken: %+v", b)
	}
	// not anchored, a block that changed (the idle time grew): taken
	if b := mibBusy(old+fresh, false, before); b == nil || b.busy != 250000 {
		t.Errorf("unanchored new block: %+v", b)
	}
	// not anchored, before held no block: the only one is taken
	if b := mibBusy(old, false, pad); b == nil || b.busy != 1000 {
		t.Errorf("only block: %+v", b)
	}
}

// gateFunc is a RestartGate.
type gateFunc func() (func(), bool)

func (g gateFunc) DriverRead() (func(), bool) { return g() }

// TestCollectMibInfo: the 2.4 GHz radio's busy time comes from `show
// mibinfo`, asked after its station-table reads, at most every
// mibInterval, never while the radio is down or the restart gate is shut.
func TestCollectMibInfo(t *testing.T) {
	d := newKlogDev(t) // ra0 up, rai0 down
	d.prints["ra0 stainfo"] = macDump
	d.prints["ra0 stacountinfo"] = fixture(t, "stacountinfo_ra0.klog")
	d.prints["ra0 mibinfo"] = fixture(t, "mibinfo_ra0.klog")
	ck := &clock{t: time.Unix(1_000_000, 0)}
	c := newTestCollector(d, ck, false)
	ctx := context.Background()
	collect := func() *apstate.Radio {
		t.Helper()
		s, err := c.Collect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return radioOf(s, "ng")
	}
	mibCalls := func() int {
		n := 0
		for _, l := range d.iwpriv() {
			if l == "iwpriv ra0 show mibinfo" {
				n++
			}
		}
		return n
	}

	collect()
	want := []string{"iwpriv ra0 show stainfo", "iwpriv ra0 show stacountinfo", "iwpriv ra0 show mibinfo"}
	if got := d.iwpriv(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("first Collect ran %v, want %v (mibinfo last, rai0 down: never)", got, want)
	}
	// 1 s at 74060 µs/s busy, 8782 µs/s own transmit: cu_total 7 %,
	// cu_self_tx 1 % (apstate rounds), cu_self_rx 0
	ck.t = ck.t.Add(time.Second)
	if sv := collect().Survey; sv != (apstate.Survey{Active: 1000, Busy: 74, Tx: 8, Rx: 0}) {
		t.Errorf("ng survey %+v, want active 1000 busy 74 tx 8", sv)
	}

	// the station table is read again past CacheTTL; mibinfo is not (6 s
	// since it was asked) and its last reading stands
	d.prints["ra0 mibinfo"] = mibBlockText("300000", "100000", "0", "1042999999")
	ck.t = ck.t.Add(defaultCacheTTL)
	sv := collect().Survey
	if n := len(d.iwpriv()); n != 5 || mibCalls() != 1 {
		t.Errorf("within mibInterval: %v", d.iwpriv())
	}
	if sv.Active != 6000 || sv.Busy != 444 {
		t.Errorf("ng survey %+v, want active 6000 busy 444 (the old rate)", sv)
	}
	// Invalidate does not shorten mibInterval
	c.Invalidate()
	ck.t = ck.t.Add(time.Second)
	collect()
	if mibCalls() != 1 {
		t.Errorf("Invalidate asked mibinfo again within mibInterval")
	}
	// the next station-table read past mibInterval (16 s) asks again, and
	// the new rate integrates from there
	ck.t = ck.t.Add(defaultCacheTTL - time.Second)
	collect() // 11 s: the 7 s reading is still cached
	ck.t = ck.t.Add(defaultCacheTTL)
	before := collect().Survey
	if mibCalls() != 2 {
		t.Fatalf("after mibInterval: %d mibinfo calls, want 2 (%v)", mibCalls(), d.iwpriv())
	}
	ck.t = ck.t.Add(time.Second)
	after := collect().Survey
	if db, dt := after.Busy-before.Busy, after.Tx-before.Tx; db != 300 || dt != 100 {
		t.Errorf("new reading: +%d ms busy, +%d ms tx in 1 s, want 300 and 100", db, dt)
	}

	// the driver prints nothing: the log still holds both older blocks,
	// neither is taken
	d.prints["ra0 mibinfo"] = ""
	ck.t = ck.t.Add(mibInterval)
	if sv := collect().Survey; sv != (apstate.Survey{}) || mibCalls() != 3 {
		t.Errorf("stale log: survey %+v after %d mibinfo calls", sv, mibCalls())
	}

	// a radio that is down is never asked, and its reading is not carried
	// over the gap; back up, mibinfo waits for mibInterval
	d.prints["ra0 mibinfo"] = fixture(t, "mibinfo_ra0.klog")
	ck.t = ck.t.Add(mibInterval)
	collect() // asked: 4
	d.setUp("ra0", false)
	n := len(d.iwpriv())
	ck.t = ck.t.Add(mibInterval)
	collect()
	if got := d.iwpriv()[n:]; len(got) != 0 {
		t.Errorf("down radio asked: %v", got)
	}
	d.setUp("ra0", true)
	ck.t = ck.t.Add(time.Second)
	if sv := collect().Survey; mibCalls() != 5 || sv.Busy != 0 {
		// 11 s since the last ask: asked again at once
		t.Errorf("back up: %d mibinfo calls, survey %+v", mibCalls(), sv)
	}
	d.setUp("ra0", false)
	collect()
	d.setUp("ra0", true)
	ck.t = ck.t.Add(defaultCacheTTL)
	if sv := collect().Survey; mibCalls() != 5 || sv != (apstate.Survey{}) {
		t.Errorf("back up within mibInterval: %d mibinfo calls, survey %+v", mibCalls(), sv)
	}

	// the restart gate is shut: nothing is asked
	c.FollowRestarts(gateFunc(func() (func(), bool) { return nil, false }))
	n = len(d.iwpriv())
	ck.t = ck.t.Add(time.Minute)
	collect()
	if got := d.iwpriv()[n:]; len(got) != 0 {
		t.Errorf("shut gate: %v", got)
	}
	// open again: read, and the gate is held across the mibinfo request
	held := false
	c.FollowRestarts(gateFunc(func() (func(), bool) {
		held = true
		return func() { held = false }, true
	}))
	var during []bool
	d.hook = func(cmd string) {
		if cmd == "iwpriv ra0 show mibinfo" {
			during = append(during, held)
		}
	}
	ck.t = ck.t.Add(time.Second)
	collect()
	if len(during) != 1 || !during[0] || held {
		t.Errorf("mibinfo under the gate: %v, still held %v", during, held)
	}
}
