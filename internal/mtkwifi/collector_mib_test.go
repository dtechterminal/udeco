// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// mibFixture is what one `iwpriv ra0 show mibinfo` added to the MT7603's
// kernel log (2026-11-20, read over telnet: CRLF made LF, the driver's tab
// indents arrive as spaces), verbatim and whole: the MIB counter sections
// and the per-BSS rows (it printed no per-WCID rows), and one unrelated
// "BA - Send ADDBA request" line another part of the driver logged
// meanwhile. Its Prim CCA Time is 0x45b5af (4568495 µs).
func mibFixture(t *testing.T) string {
	t.Helper()
	return fixture(t, "mibinfo_ra0_added.klog")
}

// withPrimCCA is the fixture with another Prim CCA Time.
func withPrimCCA(t *testing.T, hex string) string {
	t.Helper()
	s := mibFixture(t)
	if !strings.Contains(s, "Prim CCA Time=0x45b5af\n") {
		t.Fatal("fixture: no Prim CCA Time=0x45b5af line")
	}
	return strings.Replace(s, "Prim CCA Time=0x45b5af\n", "Prim CCA Time="+hex+"\n", 1)
}

func TestParseMibInfo(t *testing.T) {
	if v, ok := parseMibInfo(mibFixture(t)); !ok || v != 0x45b5af {
		t.Errorf("fixture: %#x, %v, want 0x45b5af", v, ok)
	}
	// the driver's own tab indents, as on the console
	tabs := strings.ReplaceAll(mibFixture(t), "        ", "\t")
	if v, ok := parseMibInfo(tabs); !ok || v != 0x45b5af {
		t.Errorf("tab-indented: %#x, %v", v, ok)
	}
	// the last block counts (Sec CCA Time and Prim ED Time are not read)
	two := mibFixture(t) + withPrimCCA(t, "0x12f89c")
	if v, ok := parseMibInfo(two); !ok || v != 0x12f89c {
		t.Errorf("two blocks: %#x, %v, want 0x12f89c", v, ok)
	}
	// printk level prefixes
	pre := "<4>" + strings.ReplaceAll(strings.TrimSuffix(mibFixture(t), "\n"), "\n", "\n<4>")
	if v, ok := parseMibInfo(pre); !ok || v != 0x45b5af {
		t.Errorf("prefixed: %#x, %v", v, ok)
	}
	// no block: the station counters, or the MT7663's bgndscaninfo (whose
	// "One sec" lines are not the MT7603's)
	for _, f := range []string{"stacountinfo_ra0.klog", "bgndscaninfo_rai0.klog"} {
		if v, ok := parseMibInfo(fixture(t, f)); ok {
			t.Errorf("%s gave %#x", f, v)
		}
	}
}

// TestMibBusy: Prim CCA Time is µs of primary-channel busy since the last
// read (which cleared it), so the busy time is it over the time since.
func TestMibBusy(t *testing.T) {
	fx := mibFixture(t)
	for _, c := range []struct {
		name     string
		added    string
		anchored bool
		elapsed  time.Duration
		want     int64 // -1: no reading
	}{
		{"10 s", fx, true, 10 * time.Second, 456849},          // 4568495 µs / 10 s
		{"60 s", fx, true, time.Minute, 76141},                // the longest gap taken
		{"2 s, capped", fx, true, 2 * time.Second, 1_000_000}, // more than the air holds
		{"measured on the unit", withPrimCCA(t, "0x40423"), true, 1070 * time.Millisecond, 245984},
		{"first ask", fx, true, 0, -1},
		{"clock went back", fx, true, -time.Second, -1},
		{"over 60 s", fx, true, time.Minute + time.Second, -1},
		{"not anchored", fx, false, 10 * time.Second, -1},
		{"saturated", withPrimCCA(t, "0xffffff"), true, 10 * time.Second, -1},
		{"nothing printed", "", true, 10 * time.Second, -1},
	} {
		b := mibBusy(c.added, c.anchored, c.elapsed)
		switch {
		case c.want < 0 && b != nil:
			t.Errorf("%s: %+v, want no reading", c.name, *b)
		case c.want >= 0 && (b == nil || *b != busySample{busy: c.want}):
			t.Errorf("%s: %+v, want busy %d", c.name, b, c.want)
		}
	}
}

// gateFunc is a RestartGate.
type gateFunc func() (func(), bool)

func (g gateFunc) DriverRead() (func(), bool) { return g() }

// informCU is the channel use an inform from prev to cur reports for the
// band (radio_table_stats cu_total, cu_self_tx, cu_self_rx), and whether
// it reports any.
func informCU(t *testing.T, prev, cur *apstate.Snapshot, band string) (total, selfTx, selfRx int, ok bool) {
	t.Helper()
	f := cur.Fields(prev, apstate.CfgInfo{}, nil)
	for _, rs := range f["radio_table_stats"].([]map[string]any) {
		if rs["radio"] != band {
			continue
		}
		v, ok := rs["cu_total"]
		if !ok {
			return 0, 0, 0, false
		}
		return v.(int), rs["cu_self_tx"].(int), rs["cu_self_rx"].(int), true
	}
	t.Fatalf("no %s radio in the inform", band)
	return 0, 0, 0, false
}

// mibRig is a collector on a fake 2.4 GHz radio (rai0 down) and a fake
// clock, counting the `show mibinfo` asks.
type mibRig struct {
	t  *testing.T
	d  *klogDev
	ck *clock
	c  *Collector
}

func newMibRig(t *testing.T) *mibRig {
	d := newKlogDev(t) // ra0 up, rai0 down
	d.prints["ra0 stainfo"] = macDump
	d.prints["ra0 stacountinfo"] = fixture(t, "stacountinfo_ra0.klog")
	d.prints["ra0 mibinfo"] = mibFixture(t)
	ck := &clock{t: time.Unix(1_000_000, 0)}
	return &mibRig{t: t, d: d, ck: ck, c: newTestCollector(d, ck, false)}
}

// after moves the clock on by dt and collects.
func (r *mibRig) after(dt time.Duration) *apstate.Snapshot {
	r.t.Helper()
	r.ck.t = r.ck.t.Add(dt)
	s, err := r.c.Collect(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

// busy is the radio's last `show mibinfo` reading (nil: none).
func (r *mibRig) busy() *busySample {
	if m := r.c.mib["ra0"]; m != nil {
		return m.busy
	}
	return nil
}

func (r *mibRig) asks() int {
	n := 0
	for _, l := range r.d.iwpriv() {
		if l == "iwpriv ra0 show mibinfo" {
			n++
		}
	}
	return n
}

// wantCU checks the 2.4 GHz channel use an inform from prev to cur
// reports (want -1: none, the cu_* keys left out).
func (r *mibRig) wantCU(what string, prev, cur *apstate.Snapshot, total, tx, rx int) {
	r.t.Helper()
	cu, ctx, crx, ok := informCU(r.t, prev, cur, "ng")
	switch {
	case total < 0 && ok:
		r.t.Errorf("%s: cu_total %d reported, want none", what, cu)
	case total >= 0 && (!ok || cu != total || ctx != tx || crx != rx):
		r.t.Errorf("%s: cu_total %d cu_self_tx %d cu_self_rx %d (reported %v), want %d %d %d", what, cu, ctx, crx, ok, total, tx, rx)
	}
}

// TestCollectMibInfo: the 2.4 GHz radio's busy time is Prim CCA Time over
// the time since the previous `show mibinfo` ask, which is asked after the
// station-table reads, at most every mibInterval, never while the radio is
// down or the restart gate is shut; every ask clears the counter, so every
// ask counts as the next one's start, whatever it answered.
func TestCollectMibInfo(t *testing.T) {
	r := newMibRig(t)
	d := r.d

	s0 := r.after(0)
	want := []string{"iwpriv ra0 show stainfo", "iwpriv ra0 show stacountinfo", "iwpriv ra0 show mibinfo"}
	if got := d.iwpriv(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("first Collect ran %v, want %v (mibinfo last, rai0 down: never)", got, want)
	}
	if !radioOf(s0, "ng").NoSurvey || r.busy() != nil {
		t.Errorf("first ask: no previous one, but channel use reported (%+v)", r.busy())
	}
	// 10 s on: 0x45b5af µs in 10 s is 45.7 % busy; the first reading
	// measures no interval yet
	s1 := r.after(10 * time.Second)
	if b := r.busy(); r.asks() != 2 || !radioOf(s1, "ng").NoSurvey || b == nil || *b != (busySample{busy: 456849}) {
		t.Errorf("second ask: %d asks, NoSurvey %v, reading %+v", r.asks(), radioOf(s1, "ng").NoSurvey, b)
	}
	// 2 s on (Invalidate re-reads the station table, not mibinfo): the
	// reading integrates; nothing estimates own airtime (the station
	// counters did not move)
	r.c.Invalidate()
	s2 := r.after(2 * time.Second)
	if r.asks() != 2 {
		t.Errorf("Invalidate shortened mibInterval: %d asks", r.asks())
	}
	r.wantCU("2 s at the 10 s reading", s1, s2, 46, 0, 0)
	// 10 s on: asked again, 12 s since the last ask: 3000000 µs is 25 %
	d.prints["ra0 mibinfo"] = withPrimCCA(t, "0x2dc6c0")
	s3 := r.after(10 * time.Second)
	if r.asks() != 3 {
		t.Fatalf("after mibInterval: %d asks, want 3 (%v)", r.asks(), d.iwpriv())
	}
	r.wantCU("10 s at the 12 s reading", s2, s3, 25, 0, 0)

	// an empty answer: no reading, nothing reported, the counters stand;
	// but it was asked (the driver cleared the counter), so the next
	// reading's interval starts there: 10 s (45.7 %), not 20 s (22.8 %)
	d.prints["ra0 mibinfo"] = ""
	s4 := r.after(mibInterval)
	if g := radioOf(s4, "ng"); r.asks() != 4 || !g.NoSurvey || r.busy() != nil || g.Survey != radioOf(s3, "ng").Survey {
		t.Errorf("empty answer: %d asks, NoSurvey %v, survey %+v (want %+v)", r.asks(), g.NoSurvey, g.Survey, radioOf(s3, "ng").Survey)
	}
	r.wantCU("over an empty answer", s3, s4, -1, 0, 0)
	d.prints["ra0 mibinfo"] = mibFixture(t)
	s5 := r.after(mibInterval)
	r.wantCU("first reading after the gap", s4, s5, -1, 0, 0)
	s6 := r.after(time.Second)
	r.wantCU("after an empty answer", s5, s6, 46, 0, 0)
	// an inform spanning the gap takes the measured seconds only
	r.wantCU("spanning the gap", s1, s6, 30, 0, 0) // 2 s at 45.7 %, 10 at 25, 1 at 45.7

	// not anchored (the log was cleared under the request: what it holds
	// may be someone else's block): no reading, but it counts as asked
	d.hook = func(cmd string) {
		if cmd == "iwpriv ra0 show mibinfo" {
			d.log.Reset()
		}
	}
	s7 := r.after(mibInterval)
	d.hook = nil
	if r.asks() != 6 || !radioOf(s7, "ng").NoSurvey || r.busy() != nil {
		t.Errorf("not anchored: %d asks, NoSurvey %v", r.asks(), radioOf(s7, "ng").NoSurvey)
	}
	r.after(mibInterval)
	s8 := r.after(time.Second)
	r.wantCU("after an unanchored answer", s7, s8, 46, 0, 0)

	// saturated (24 bits): no reading
	d.prints["ra0 mibinfo"] = withPrimCCA(t, "0xffffff")
	if s := r.after(mibInterval); r.asks() != 8 || !radioOf(s, "ng").NoSurvey || r.busy() != nil {
		t.Errorf("saturated: %d asks, NoSurvey %v", r.asks(), radioOf(s, "ng").NoSurvey)
	}
	// over 60 s since the last ask: no reading; the next one is again
	d.prints["ra0 mibinfo"] = mibFixture(t)
	if s := r.after(61 * time.Second); r.asks() != 9 || !radioOf(s, "ng").NoSurvey || r.busy() != nil {
		t.Errorf("61 s since the last ask: %d asks, NoSurvey %v", r.asks(), radioOf(s, "ng").NoSurvey)
	}
	s9 := r.after(mibInterval)
	s10 := r.after(time.Second)
	r.wantCU("after a long gap", s9, s10, 46, 0, 0)

	// a radio that is down is never asked, and its reading is not carried
	// over the gap; back up, mibinfo waits for mibInterval, and the first
	// ask after the radio was down gives no reading (no previous ask)
	d.setUp("ra0", false)
	n := len(d.iwpriv())
	if s := r.after(mibInterval); !radioOf(s, "ng").NoSurvey {
		t.Error("down radio reported channel use")
	}
	if got := d.iwpriv()[n:]; len(got) != 0 {
		t.Errorf("down radio asked: %v", got)
	}
	d.setUp("ra0", true)
	if s := r.after(time.Second); r.asks() != 11 || !radioOf(s, "ng").NoSurvey || r.busy() != nil {
		// 11 s since the last ask: asked at once, but down since: no reading
		t.Errorf("back up: %d asks, NoSurvey %v", r.asks(), radioOf(s, "ng").NoSurvey)
	}
	d.setUp("ra0", false)
	r.after(0)
	d.setUp("ra0", true)
	if s := r.after(defaultCacheTTL); r.asks() != 11 || !radioOf(s, "ng").NoSurvey {
		t.Errorf("back up within mibInterval: %d asks, NoSurvey %v", r.asks(), radioOf(s, "ng").NoSurvey)
	}
	if s := r.after(defaultCacheTTL); r.asks() != 12 || !radioOf(s, "ng").NoSurvey || r.busy() != nil {
		t.Errorf("first ask after a second down: %d asks, NoSurvey %v", r.asks(), radioOf(s, "ng").NoSurvey)
	}
	s11 := r.after(mibInterval)
	s12 := r.after(time.Second)
	if r.asks() != 13 {
		t.Errorf("%d asks, want 13", r.asks())
	}
	r.wantCU("after the radio was down", s11, s12, 46, 0, 0)

	// the restart gate is shut: nothing is asked, and the first ask after
	// it (a radio restart may have reset the counters) gives no reading
	r.c.FollowRestarts(gateFunc(func() (func(), bool) { return nil, false }))
	n = len(d.iwpriv())
	r.c.Invalidate()
	r.after(time.Second)
	if got := d.iwpriv()[n:]; len(got) != 0 {
		t.Errorf("shut gate: %v", got)
	}
	// open again: read, and the gate is held across the mibinfo request
	held := false
	r.c.FollowRestarts(gateFunc(func() (func(), bool) {
		held = true
		return func() { held = false }, true
	}))
	var during []bool
	d.hook = func(cmd string) {
		if cmd == "iwpriv ra0 show mibinfo" {
			during = append(during, held)
		}
	}
	if s := r.after(mibInterval); len(during) != 1 || !during[0] || held || !radioOf(s, "ng").NoSurvey || r.busy() != nil {
		t.Errorf("mibinfo under the gate: %v, still held %v; after the shut gate NoSurvey %v", during, held, radioOf(s, "ng").NoSurvey)
	}
}

// TestRestartGapReportsNoSurvey: a radio's busy time from before it went
// down is not carried over the gap, also while the restart gate keeps the
// old reading standing for the settle time; the channel use is left out of
// the informs until a new reading has measured an interval.
func TestRestartGapReportsNoSurvey(t *testing.T) {
	d := newKlogDev(t)
	d.setUp("rai0", true)
	d.prints["ra0 stainfo"] = macDump
	d.prints["ra0 mibinfo"] = mibFixture(t)
	d.prints["rai0 stainfo"] = "<4>MAC                MODE  AID  BSS PSM WMM MIMOPS RSSI0/1/2/3         PhMd        BW       MCS         SGI      STBC      Idle   Rate      QosMap\n<4>sta_cnt=0\n"
	d.prints["rai0 bgndscaninfo"] = fixture(t, "bgndscaninfo_rai0.klog")
	ck := &clock{t: time.Unix(1_000_000, 0)}
	c := newTestCollector(d, ck, false)
	collect := func() *apstate.Snapshot {
		t.Helper()
		s, err := c.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	bands := []string{"ng", "na"}

	// 2.4 GHz: asked at 0 s (no reading) and 10 s; both measured at 11 s
	collect()
	ck.t = ck.t.Add(mibInterval)
	collect()
	ck.t = ck.t.Add(time.Second)
	s1 := collect()
	for _, b := range bands {
		if r := radioOf(s1, b); r.NoSurvey || r.Survey.Active == 0 {
			t.Fatalf("%s before the restart: NoSurvey %v, survey %+v", b, r.NoSurvey, r.Survey)
		}
	}

	// the applier restarts both radios: down, then up behind a shut gate
	d.setUp("ra0", false)
	d.setUp("rai0", false)
	ck.t = ck.t.Add(time.Second)
	down := collect()
	d.setUp("ra0", true)
	d.setUp("rai0", true)
	c.FollowRestarts(gateFunc(func() (func(), bool) { return nil, false }))
	ck.t = ck.t.Add(time.Second)
	settle1 := collect()
	ck.t = ck.t.Add(time.Second)
	settle2 := collect()
	for _, b := range bands {
		for name, s := range map[string]*apstate.Snapshot{"down": down, "settle 1": settle1, "settle 2": settle2} {
			if r := radioOf(s, b); !r.NoSurvey || r.Survey != radioOf(s1, b).Survey {
				t.Errorf("%s %s: NoSurvey %v, survey %+v (want %+v, nothing integrated)", b, name, r.NoSurvey, r.Survey, radioOf(s1, b).Survey)
			}
		}
		if cu, _, _, ok := informCU(t, settle1, settle2, b); ok {
			t.Errorf("%s inform in the settle time reported cu_total %d (the old channel's)", b, cu)
		}
	}

	// the gate opens: read again; each band reports once a new reading has
	// measured an interval (2.4 GHz: the first ask after the restart has no
	// previous one, the next comes mibInterval later)
	c.FollowRestarts(gateFunc(func() (func(), bool) { return func() {}, true }))
	var last *apstate.Snapshot
	for range 20 {
		ck.t = ck.t.Add(time.Second)
		last = collect()
	}
	for _, b := range bands {
		r := radioOf(last, b)
		if r.NoSurvey || r.Survey.Active <= radioOf(s1, b).Survey.Active {
			t.Errorf("%s after the settle time: NoSurvey %v, survey %+v (want more than %+v)", b, r.NoSurvey, r.Survey, radioOf(s1, b).Survey)
		}
	}
	if cu, tx, _, ok := informCU(t, s1, last, "ng"); !ok || cu != 46 || tx != 0 {
		t.Errorf("ng inform spanning the restart: cu_total %d cu_self_tx %d (reported %v), want 46 and 0", cu, tx, ok)
	}
}
