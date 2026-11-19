// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// t9Section returns one "## <command>" section of t9_wl1_dfs_in.txt (reads
// on .205 under country IN, 2026-11-19).
func t9Section(t *testing.T, cmd string) string {
	t.Helper()
	text := string(fixture(t, "spectrum/t9_wl1_dfs_in.txt"))
	_, rest, ok := strings.Cut(text, "## "+cmd+"\n")
	if !ok {
		t.Fatalf("t9: no section %q", cmd)
	}
	if i := strings.Index(rest, "\n## "); i >= 0 {
		rest = rest[:i+1]
	}
	return rest
}

// dfsReplay is wl1 as it was on .205 under IN: home 40u, chanspecs and
// chan_info from t9, the chanim records of t9 to start from. A call on 36,
// 44 or 48 writes a fresh record (and rewrites the home record, 40), UNII-3
// and 52/60/64 stay all-zero placeholders, and ch56 is decided by on56
// (occurrence -> record, write); nil = never rewritten.
func dfsReplay(t *testing.T, on56 func(occ int) (chanimRecord, bool), dfsFresh bool) *replay {
	t.Helper()
	r := newReplay("wl1", "na")
	r.chanspecs, r.noise = []string{strings.TrimSpace(t9Section(t, "wl -i wl1 chanspec"))}, strings.TrimSpace(t9Section(t, "wl -i wl1 noise"))
	r.base.set("wl -i wl1 chanspecs", response{out: t9Section(t, "wl -i wl1 chanspecs")})
	r.base.set("wl -i wl1 chan_info", response{out: t9Section(t, "wl -i wl1 chan_info")})
	recs, ok := parseChanimRecords([]byte(t9Section(t, "wl -i wl1 chanim_stats all")), "na")
	if !ok || len(recs) != 13 {
		t.Fatalf("t9 chanim: %d records", len(recs))
	}
	r.recs = recs
	fresh := func(ch, n int) chanimRecord {
		return chanimRecord{CS: 0xd000 | uint16(ch), Channel: ch, Glitch: 60 + n, BadPLCP: 8, Noise: -101, Obss: 1, Nocat: 1, Nopkt: 1}
	}
	r.onScan = func(r *replay, ch, occ int) error {
		if ch == 40 {
			return nil // the home control call writes nothing [M T8]
		}
		r.recs[40] = chanimRecord{CS: 0xd028, Channel: 40, Glitch: 200 + r.n, Noise: -97, TxDur: 4, Obss: 3, Nocat: 1, Nopkt: 1}
		switch {
		case ch == 36 || ch == 44 || ch == 48:
			r.recs[ch] = fresh(ch, r.n)
		case ch == 56 && !dfsFresh:
			if on56 == nil {
				return nil
			}
			if rec, write := on56(occ); write {
				r.recs[56] = rec
			}
		case ch >= 52 && ch <= 64 && dfsFresh:
			r.recs[ch] = fresh(ch, r.n)
		case ch >= 52 && ch <= 64:
			r.recs[ch] = chanimRecord{CS: 0xd000 | uint16(ch), Channel: ch, Noise: -100 - r.n%2}
		default: // UNII-3: placeholders [M T1]
			r.recs[ch] = chanimRecord{CS: 0xd000 | uint16(ch), Channel: ch, Noise: -100 - r.n%2}
		}
		return nil
	}
	return r
}

// dwellOf is the -p value of a scan command.
func dwellOf(cmd string) string {
	f := strings.Fields(cmd)
	for i := range f {
		if f[i] == "-p" && i+1 < len(f) {
			return f[i+1]
		}
	}
	return ""
}

// TestDFSStaleIsUnheardNotIncomplete replays the 03:30 spectrum-scan of
// 2026-11-19 on .205 (country IN, home 40u): ch56's record changes in pass 1
// and is never rewritten again, so pass 2 and its retry find it STALE. That
// stopped the band (ErrIncomplete "20 MHz rows [56]") and left 5 GHz with no
// table. A passive (DFS) channel no call refreshed is now unmeasured for the
// band: the 36-48 rows are sent, abnormal stays false.
func TestDFSStaleIsUnheardNotIncomplete(t *testing.T) {
	r := dfsReplay(t, func(occ int) (chanimRecord, bool) {
		return chanimRecord{CS: 0xd038, Channel: 56, Noise: -100, Obss: 1}, occ == 0
	}, false)
	r.recs[56] = chanimRecord{CS: 0xd038, Channel: 56, Noise: -101} // a placeholder before the band
	c := newSpecCollector(t, r)
	s := spectrumOf(t, c, "na")
	res, err := s.Run(context.Background(), SpectrumRequest{Widths: manualTestWidths, Manual: true, SkipGate: true})
	if err != nil {
		t.Fatalf("%v; notes %v", err, res.Diag.Notes)
	}
	d := res.Diag
	if !reflect.DeepEqual(d.Widths, []int{20, 40}) {
		t.Errorf("widths %v (IN lists no 80 MHz chanspec on .205)", d.Widths)
	}
	if !reflect.DeepEqual(d.Passive, []int{52, 56, 60, 64}) || !reflect.DeepEqual(d.Unheard, []int{56}) {
		t.Errorf("passive %v unheard %v", d.Passive, d.Unheard)
	}
	if !reflect.DeepEqual(d.Unmeasured, []int{52, 60, 64, 149, 153, 157, 161, 165}) {
		t.Errorf("sticky %v", d.Unmeasured)
	}
	chans, _, _ := rowsSummary(res.Rows[20])
	if !reflect.DeepEqual(chans, []int{36, 40, 44, 48}) {
		t.Errorf("na/20 rows %v", chans)
	}
	chans, _, _ = rowsSummary(res.Rows[40])
	if !reflect.DeepEqual(chans, []int{36, 44}) {
		t.Errorf("na/40 rows %v", chans)
	}
	if !reflect.DeepEqual(d.Omitted, map[int][]int{20: {52, 56, 60, 64, 149, 153, 157, 161, 165}, 40: {52, 60, 149, 157}}) {
		t.Errorf("omitted %v", d.Omitted)
	}
	if st := channelStat(d, 56); st.Class != ClassUnmeasured || st.Stale != 1 || st.Samples != 1 {
		t.Errorf("ch56 %+v", st)
	}
	if res.Status.Abnormal || res.Status.TableTime.IsZero() {
		t.Errorf("status %+v", res.Status)
	}
	// 56: pass 1, pass 2 (reversed) and its retry at the end of the pass;
	// the other passive channels were ZERO in pass 1 and are not called again
	var got []int
	for _, sc := range r.scans() {
		got = append(got, scanChannel(sc))
		if !strings.Contains(sc, "-t passive") {
			t.Errorf("not passive: %q", sc)
		}
		want := "110"
		if ch := scanChannel(sc); ch >= 52 && ch <= 64 {
			want = "200"
		}
		if dwellOf(sc) != want {
			t.Errorf("%q: dwell %s, want %s", sc, dwellOf(sc), want)
		}
	}
	if !reflect.DeepEqual(got, []int{36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165, 56, 48, 44, 40, 36, 56}) {
		t.Errorf("calls %v", got)
	}
	if n := r.count("scanabort"); n != 0 {
		t.Errorf("%d scanabort", n)
	}
}

// manualTestWidths are a manual spectrum-scan's widths (cmd/udeco-ap).
var manualTestWidths = []int{20, 40, 80}

// TestDFSStaleInPass1DoesNotStopTheBand: a passive channel never rewritten
// at all (STALE in pass 1 and after its retry) is unheard; the fallback
// trigger skips it like a ZERO channel, and the band still succeeds.
func TestDFSStaleInPass1DoesNotStopTheBand(t *testing.T) {
	r := dfsReplay(t, nil, false)
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "na").Run(context.Background(), SpectrumRequest{Widths: []int{20}, SkipGate: true})
	if err != nil {
		t.Fatalf("%v; notes %v", err, res.Diag.Notes)
	}
	if res.Diag.Mode != ModeChunked || res.Diag.Fallback != "" || !reflect.DeepEqual(res.Diag.Unheard, []int{56}) {
		t.Errorf("mode %s fallback %q unheard %v", res.Diag.Mode, res.Diag.Fallback, res.Diag.Unheard)
	}
	if chans, _, _ := rowsSummary(res.Rows[20]); !reflect.DeepEqual(chans, []int{36, 40, 44, 48}) {
		t.Errorf("rows %v", chans)
	}
	// unheard is for this band only: the next band calls 56 again
	before := 0
	for _, sc := range r.scans() {
		if scanChannel(sc) == 56 {
			before++
		}
	}
	if _, err := spectrumOf(t, c, "na").Run(context.Background(), SpectrumRequest{Widths: []int{20}, SkipGate: true}); err != nil {
		t.Fatal(err)
	}
	after := 0
	for _, sc := range r.scans() {
		if scanChannel(sc) == 56 {
			after++
		}
	}
	if after <= before {
		t.Errorf("ch56 not called in the next band (%d calls, then %d)", before, after)
	}
}

// TestDFSMeasuredWithLongerDwell: when the 200 ms passive calls do refresh
// the DFS records, 52-64 get rows like any other channel.
func TestDFSMeasuredWithLongerDwell(t *testing.T) {
	r := dfsReplay(t, nil, true)
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "na").Run(context.Background(), SpectrumRequest{Widths: manualTestWidths, SkipGate: true})
	if err != nil {
		t.Fatalf("%v; notes %v", err, res.Diag.Notes)
	}
	if chans, _, _ := rowsSummary(res.Rows[20]); !reflect.DeepEqual(chans, []int{36, 40, 44, 48, 52, 56, 60, 64}) {
		t.Errorf("na/20 rows %v", chans)
	}
	if chans, _, _ := rowsSummary(res.Rows[40]); !reflect.DeepEqual(chans, []int{36, 44, 52, 60}) {
		t.Errorf("na/40 rows %v", chans)
	}
	if len(res.Diag.Unheard) != 0 {
		t.Errorf("unheard %v", res.Diag.Unheard)
	}
}

// TestDFSNonPassiveStaleStillMissing: the rule is for passive channels
// only. A STALE non-passive channel (44 here) still makes its rows fail the
// band, as §3.2 says.
func TestDFSNonPassiveStaleStillMissing(t *testing.T) {
	r := dfsReplay(t, nil, true)
	inner := r.onScan
	r.onScan = func(r *replay, ch, occ int) error {
		if ch == 44 && occ > 0 {
			return nil // pass 2 and its retry leave 44's record as it was
		}
		return inner(r, ch, occ)
	}
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "na").Run(context.Background(), SpectrumRequest{Widths: []int{20}, SkipGate: true})
	if err == nil || !strings.Contains(err.Error(), "[44]") || res.Rows != nil {
		t.Fatalf("err %v rows %v", err, res.Rows)
	}
	if !res.Status.Abnormal {
		t.Error("abnormal not set")
	}
}

func TestParseChanInfo(t *testing.T) {
	got, ok := parseChanInfo([]byte(t9Section(t, "wl -i wl1 chan_info")), "na")
	if !ok {
		t.Fatal("not parsed")
	}
	var passive []int
	for ch, p := range got {
		if p {
			passive = append(passive, ch)
		}
	}
	if len(got) != 13 || !reflect.DeepEqual(sortedKeys(got), []int{52, 56, 60, 64}) {
		t.Errorf("%d channels, passive %v", len(got), passive)
	}
	if _, ok := parseChanInfo([]byte(t9Section(t, "wl -i wl1 chan_info")), "ng"); ok {
		t.Error("5 GHz lines read as 2.4 GHz")
	}
	if _, ok := parseChanInfo([]byte("wl: Unsupported\n"), "na"); ok {
		t.Error("junk parsed")
	}
}

// TestPassiveFallbackWithoutChanInfo: no `wl chan_info` answer -> 52-144
// are the passive channels (caps.DFS's rule); the US fixtures have none.
func TestPassiveFallbackWithoutChanInfo(t *testing.T) {
	r := dfsReplay(t, nil, true)
	r.base.set("wl -i wl1 chan_info", response{err: errors.New("wl: Unsupported")})
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "na").Run(context.Background(), SpectrumRequest{Widths: []int{20}, SkipGate: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Diag.Passive, []int{52, 56, 60, 64}) {
		t.Errorf("passive %v", res.Diag.Passive)
	}
}
