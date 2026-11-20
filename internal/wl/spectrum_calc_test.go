// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/apstate"
)

// The captures in testdata/spectrum are kept as taken (README.md there);
// these helpers cut them up in memory.

// chanimBlocks returns every "--- chanim_stats all" block of a capture, in
// file order, as the text `wl chanim_stats all` printed.
func chanimBlocks(t *testing.T, name string) []string {
	t.Helper()
	var out []string
	var cur *strings.Builder
	for line := range strings.Lines(string(fixture(t, "spectrum/"+name))) {
		if strings.HasPrefix(line, "--- chanim_stats all") {
			if cur != nil {
				out = append(out, cur.String())
			}
			cur = &strings.Builder{}
			continue
		}
		if cur == nil {
			continue
		}
		ln := strings.TrimRight(line, "\n")
		if strings.HasPrefix(ln, "version:") || strings.HasPrefix(ln, "CHAN ") || strings.HasPrefix(ln, "Stats during") ||
			strings.HasPrefix(ln, " chanspec:") || strings.HasPrefix(ln, "\t") {
			cur.WriteString(line)
			continue
		}
		out = append(out, cur.String())
		cur = nil
	}
	if cur != nil {
		out = append(out, cur.String())
	}
	return out
}

// ccaSections returns the `wl cca_get_stats` outputs of a T5 capture.
func ccaSections(t *testing.T, name string) []string {
	t.Helper()
	var out []string
	var cur *strings.Builder
	for line := range strings.Lines(string(fixture(t, "spectrum/"+name))) {
		switch {
		case strings.HasPrefix(line, "--- cca_get_stats"):
			cur = &strings.Builder{}
		case cur == nil:
		case strings.HasPrefix(line, "P t=") || strings.HasPrefix(line, "CCA ") || strings.HasPrefix(line, "---"):
			out = append(out, cur.String())
			cur = nil
		default:
			cur.WriteString(line)
		}
	}
	return out
}

func recs(t *testing.T, text, band string) map[int]chanimRecord {
	t.Helper()
	m, ok := parseChanimRecords([]byte(text), band)
	if !ok {
		t.Fatalf("chanim block not parsed:\n%s", text)
	}
	return m
}

func TestParseChanimRecords(t *testing.T) {
	e5 := recs(t, chanimBlocks(t, "e5_wl0_passive_p200.txt")[0], "ng")
	if len(e5) != 11 {
		t.Fatalf("e5: %d records", len(e5))
	}
	want := chanimRecord{CS: 0x1009, Channel: 9, Glitch: e5[9].Glitch, BadPLCP: e5[9].BadPLCP, Noise: -71, TxDur: 58, Inbss: 1, Obss: 12, Nocat: 7, Nopkt: 10}
	if e5[9] != want {
		t.Errorf("e5 ch9 = %+v, want %+v", e5[9], want)
	}
	// wl1 before any scan: "version: 3" and nothing else [M t0]
	t0 := chanimBlocks(t, "t0_baseline.txt")
	if m, ok := parseChanimRecords([]byte(t0[1]), "na"); !ok || len(m) != 0 {
		t.Errorf("t0 wl1: %d records, ok %v", len(m), ok)
	}
	// the header with no records (t5)
	if m, ok := parseChanimRecords([]byte("version: 3 \nCHAN Interference Measurement:\nStats during last scan:\n\n"), "ng"); !ok || len(m) != 0 {
		t.Errorf("header only: %d records, ok %v", len(m), ok)
	}
	if _, ok := parseChanimRecords([]byte("wl: Unsupported\n"), "ng"); ok {
		t.Error("garbage accepted")
	}
	// band filter: wl1's 9 records are 5 GHz
	t1 := chanimBlocks(t, "t1_wl1_passive_p110_r1.txt")
	if n := len(recs(t, t1[1], "na")); n != 9 {
		t.Errorf("t1 r1 na: %d records", n)
	}
	if n := len(recs(t, t1[1], "ng")); n != 0 {
		t.Errorf("t1 r1 as ng: %d records", n)
	}
}

func TestClassifyRecord(t *testing.T) {
	// T1 r2: 0xd0a1 (161) moved only in noise (-100 -> -101): ZERO, not OK
	b := chanimBlocks(t, "t1_wl1_passive_p110_r2.txt")
	pre, post := recs(t, b[0], "na"), recs(t, b[1], "na")
	if pre[161].Noise == post[161].Noise || pre[161].same(post[161]) {
		t.Fatalf("fixture changed: 161 %+v -> %+v", pre[161], post[161])
	}
	if got := classifyRecord(pre[161], post[161], true, true); got != classZero {
		t.Errorf("161 noise-only change: %s, want zero", got)
	}
	if got := classifyRecord(pre[36], post[36], true, true); got != classOK {
		t.Errorf("36: %s", got)
	}
	if got := classifyRecord(pre[36], pre[36], true, true); got != classStale {
		t.Errorf("unchanged 36: %s", got)
	}
	if got := classifyRecord(chanimRecord{}, chanimRecord{}, false, false); got != classStale {
		t.Errorf("absent: %s", got)
	}
	if got := classifyRecord(chanimRecord{}, pre[36], false, true); got != classOK {
		t.Errorf("new record: %s", got)
	}
	// T2: the near-empty 149 record (glitch 8, nopkt 1) passes both rules
	s := chanimBlocks(t, "t2_wl1_single.txt")
	if r := recs(t, s[3], "na")[149]; r.Glitch != 8 || r.zero() || classifyRecord(recs(t, s[2], "na")[149], r, true, true) != classOK {
		t.Errorf("t2 -c 149 record %+v", r)
	}
}

func TestHomeRewriteZeroShape(t *testing.T) {
	// T2: `-c 157` left the home control record 0xd028 all-zero except
	// noise; such a rewrite must not count towards H
	b := chanimBlocks(t, "t2_wl1_unii3_single.txt")
	found := false
	for i := 0; i+1 < len(b); i += 2 {
		pre, post := recs(t, b[i], "na"), recs(t, b[i+1], "na")
		if !pre[40].same(post[40]) && post[40].zero() {
			found = true
		}
	}
	if !found {
		t.Error("no all-zero home rewrite in t2_wl1_unii3_single.txt")
	}
}

func TestChannelUtil(t *testing.T) {
	e5 := recs(t, chanimBlocks(t, "e5_wl0_passive_p200.txt")[0], "ng")
	e6 := recs(t, chanimBlocks(t, "e6_wl0_passive_nop_r2.txt")[0], "ng")
	for ch, want := range map[int]int{9: 29, 1: 30, 5: 3} {
		if got, _ := meanUtil([]chanimRecord{e5[ch]}); got != want {
			t.Errorf("e5 ch%d u = %d, want %d", ch, got, want)
		}
	}
	// (29+44)/2 = 36.5 -> 37 with math.Round (model.py printed 36)
	for ch, want := range map[int]int{9: 37, 1: 28} {
		if got, _ := meanUtil([]chanimRecord{e5[ch], e6[ch]}); got != want {
			t.Errorf("e5+e6 ch%d u = %d, want %d", ch, got, want)
		}
	}
	if _, ok := meanUtil(nil); ok {
		t.Error("no records gave a value")
	}
}

func TestBSSPower(t *testing.T) {
	near := func(got, want float64) bool { return math.Abs(got-want) < 0.05 }
	b20 := apstate.BSS{Channel: 1, Width: 20, Freq: 2412, CenterFreq: 2412, Signal: -65}
	if p, ok := bssPower(b20, 2, "ng"); !ok || !near(p, -66.25) {
		t.Errorf("20 MHz -65 on 1 into 2: %.2f %v", p, ok)
	}
	if _, ok := bssPower(b20, 6, "ng"); ok {
		t.Error("ch1 BSS reached ch6")
	}
	// 40 MHz at -50 on 0x1907 (9u: control 9, centre 7)
	cs, _ := decodeChanspec(0x1907)
	b40 := apstate.BSS{Channel: cs.Control, Width: 40, Freq: chanFreq(cs.Control, "ng"), CenterFreq: chanFreq(cs.Center, "ng"), Signal: -50}
	for ch, want := range map[int]float64{5: -53.01, 6: -53.01, 7: -53.01, 8: -53.01, 9: -50, 3: -56.02, 11: -56.02} {
		if p, ok := bssPower(b40, ch, "ng"); !ok || !near(p, want) {
			t.Errorf("40 MHz into ch%d: %.2f %v, want %.2f", ch, p, ok, want)
		}
	}
	if _, ok := bssPower(b40, 1, "ng"); ok {
		t.Error("0x1907 BSS reached ch1")
	}
	// 80 MHz sibling on 0xe12a (40/80) at -72: primary 40 full, others -6 dB
	cs, _ = decodeChanspec(0xe12a)
	b80 := apstate.BSS{Channel: cs.Control, Width: 80, Freq: chanFreq(cs.Control, "na"), CenterFreq: chanFreq(cs.Center, "na"), Signal: -72}
	for ch, want := range map[int]float64{40: -72, 36: -78.02, 44: -78.02, 48: -78.02} {
		if p, ok := bssPower(b80, ch, "na"); !ok || !near(p, want) {
			t.Errorf("80 MHz into ch%d: %.2f %v", ch, p, ok)
		}
	}
	if _, ok := bssPower(b80, 149, "na"); ok {
		t.Error("36 block BSS reached 149")
	}
}

func TestChannelInterference(t *testing.T) {
	e5 := recs(t, chanimBlocks(t, "e5_wl0_passive_p200.txt")[0], "ng")
	bss := parseScanResults(fixture(t, "spectrum/e5_wl0_passive_p200.txt"), "ng")
	if len(bss) != 24 {
		t.Fatalf("e5: %d BSS", len(bss))
	}
	var noises []float64
	for ch, r := range e5 {
		if ch != 9 {
			noises = append(noises, float64(r.Noise))
		}
	}
	base, _ := median(noises)
	const nhome = -97
	got := map[int]int{}
	for ch := 1; ch <= 11; ch++ {
		p, ok, _ := peakBSS(bss, ch, "ng")
		ne, neOK := elevatedNoise([]chanimRecord{e5[ch]}, ch == 9, nhome, base, true)
		got[ch] = interferenceDBm(nhome, p, ok, ne, neOK)
	}
	// §11.5 with the primary-channel rule: ch9 -50
	for ch, want := range map[int]int{1: -65, 2: -59, 5: -53, 9: -50, 11: -56} {
		if got[ch] != want {
			t.Errorf("e5 ch%d interference %d, want %d", ch, got[ch], want)
		}
	}

	// N_elev against the band's chanim baseline B
	rec := func(noise, tx int) chanimRecord { return chanimRecord{Glitch: 100, Noise: noise, TxDur: tx, Obss: 5} }
	cases := []struct {
		name string
		recs []chanimRecord
		home bool
		want int
	}{
		{"no BSS, quiet", []chanimRecord{rec(-105, 0)}, false, -97},
		{"-80 in both passes, B -100", []chanimRecord{rec(-80, 0), rec(-80, 0)}, false, -77},
		{"-80 in one pass only", []chanimRecord{rec(-80, 0), rec(-100, 0)}, false, -97},
		{"txdur 58, noise -71 (e5 home)", []chanimRecord{rec(-71, 58)}, false, -97},
		{"home control channel", []chanimRecord{rec(-71, 0)}, true, -97},
		{"under B+10", []chanimRecord{rec(-91, 0)}, false, -97},
	}
	for _, tc := range cases {
		ne, ok := elevatedNoise(tc.recs, tc.home, nhome, -100, true)
		if got := interferenceDBm(nhome, 0, false, ne, ok); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
	if got := interferenceDBm(-97, -10, true, 0, false); got != -20 {
		t.Errorf("clamp high: %d", got)
	}
}

// specsOf parses a `wl chanspecs` fixture.
func specsOf(t *testing.T, name string) []chanspec {
	t.Helper()
	return parseChanspecs(fixture(t, name))
}

func TestBuildRows(t *testing.T) {
	ng, na := specsOf(t, "wl_-i_wl0_chanspecs.txt"), specsOf(t, "wl_-i_wl1_chanspecs.txt")
	vals := func(chs []int, class string) map[int]chanValue {
		m := map[int]chanValue{}
		for _, ch := range chs {
			m[ch] = chanValue{Class: class, Util: ch % 7, Interf: -90 + ch%5}
		}
		return m
	}
	ngCh := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	naCh := []int{36, 40, 44, 48, 149, 153, 157, 161, 165}

	rows, _, err := buildRows(vals(ngCh, ClassMeasured), blocksFor(ng, "ng", 20), "ng")
	if err != nil || len(rows) != 11 || rows[0].CenterFreq != 2412 || rows[10].CenterFreq != 2462 || rows[10].Channel != 11 {
		t.Fatalf("ng/20: %v %+v", err, rows)
	}
	v := vals(ngCh, ClassMeasured)
	rows, _, err = buildRows(v, blocksFor(ng, "ng", 40), "ng")
	if err != nil || len(rows) != 7 {
		t.Fatalf("ng/40: %v %d rows", err, len(rows))
	}
	for i, r := range rows {
		c := i + 1
		if r.Channel != c || r.CenterFreq != 2417+5*c || r.Width != 40 ||
			r.Utilization != max(v[c].Util, v[c+4].Util) || r.Interference != max(v[c].Interf, v[c+4].Interf) {
			t.Errorf("ng/40 row %d: %+v", i, r)
		}
	}

	rows, _, err = buildRows(vals(naCh, ClassMeasured), blocksFor(na, "na", 80), "na")
	got := map[int]int{}
	for _, r := range rows {
		got[r.Channel] = r.CenterFreq
	}
	if err != nil || !reflect.DeepEqual(got, map[int]int{36: 5210, 149: 5775}) || rows[0].Channel != 36 {
		t.Errorf("na/80: %v %+v", err, rows)
	}
	rows, _, err = buildRows(vals(naCh, ClassMeasured), blocksFor(na, "na", 20), "na")
	if err != nil || len(rows) != 9 || rows[8].Channel != 165 || rows[8].CenterFreq != 5825 {
		t.Errorf("na/20: %v %+v", err, rows)
	}
	rows, _, err = buildRows(vals(naCh, ClassMeasured), blocksFor(na, "na", 40), "na")
	if err != nil || len(rows) != 4 || rows[1].Channel != 44 || rows[1].CenterFreq != 5230 {
		t.Errorf("na/40: %v %+v", err, rows)
	}

	// a missing part fails the band; an unmeasured one drops its block
	m := vals(naCh, ClassMeasured)
	m[44] = chanValue{Class: ClassMissing}
	if _, _, err := buildRows(m, blocksFor(na, "na", 80), "na"); !errors.Is(err, ErrIncomplete) {
		t.Errorf("missing 44 at 80: %v", err)
	}
	m = vals(naCh, ClassMeasured)
	for _, ch := range []int{149, 153, 157, 161, 165} {
		m[ch] = chanValue{Class: ClassUnmeasured}
	}
	m[161] = chanValue{Class: ClassMissing} // not needed: its block is omitted anyway
	rows, omitted, err := buildRows(m, blocksFor(na, "na", 80), "na")
	if err != nil || len(rows) != 1 || rows[0].Channel != 36 || !reflect.DeepEqual(omitted, []int{149}) {
		t.Errorf("unmeasured UNII-3 at 80: %v %+v omitted %v", err, rows, omitted)
	}
	if _, _, err := buildRows(vals(naCh, ClassUnmeasured), blocksFor(na, "na", 20), "na"); !errors.Is(err, ErrNoRows) {
		t.Errorf("all unmeasured: %v", err)
	}
}

func TestClampWidth(t *testing.T) {
	ng, na := specsOf(t, "wl_-i_wl0_chanspecs.txt"), specsOf(t, "wl_-i_wl1_chanspecs.txt")
	nw, aw := radioWidths(ng, "ng"), radioWidths(na, "na")
	if !reflect.DeepEqual(nw, []int{20, 40}) || !reflect.DeepEqual(aw, []int{20, 40, 80}) {
		t.Fatalf("widths %v %v", nw, aw)
	}
	for _, tc := range []struct {
		req  int
		ws   []int
		want int
	}{{160, aw, 80}, {320, aw, 80}, {80, nw, 40}, {0, aw, 20}, {-5, nw, 20}, {30, aw, 20}, {40, aw, 40}, {20, nw, 20}} {
		if got := clampWidth(tc.req, tc.ws); got != tc.want {
			t.Errorf("clamp %d in %v = %d, want %d", tc.req, tc.ws, got, tc.want)
		}
	}
}

func TestSpectrumRowJSON(t *testing.T) {
	b, err := json.Marshal([]SpectrumRow{{Channel: 36, Width: 80, CenterFreq: 5210, Interference: -72, Utilization: 8}})
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"channel":36,"width":80,"center_freq":5210,"total_samples":0,"interference":-72,"utilization":8,"perf_index":0,"interference_type":[],"other_bss_count":0}]`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
	if e := (SpectrumRow{Channel: 1, Width: 20, CenterFreq: 2412, Utilization: 3, Interference: -60}).Entry(); e != (apstate.SpectrumEntry{Channel: 1, Width: 20, CenterFreq: 2412, Utilization: 3, Interference: -60}) {
		t.Errorf("entry %+v", e)
	}
}

func TestOwnFromCCAGetStats(t *testing.T) {
	v := ccaSections(t, "t5_cca_variants.txt")
	if len(v) != 4 {
		t.Fatalf("%d cca sections", len(v))
	}
	near := func(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
	// wl0 -c 0 -s 5 -i: ibss 8, 9, 5, 5, 6 % -> 0.066
	if own, ok := ownFromCCA([]byte(v[0]), 9); !ok || !near(own, 0.066) {
		t.Errorf("wl0: %v %v", own, ok)
	}
	if _, ok := ownFromCCA([]byte(v[0]), 6); ok {
		t.Error("wl0 rows used for another channel")
	}
	// wl0 -c 1: rc 255 "Only 1 channel input", no row
	if _, ok := ownFromCCA([]byte(v[1]), 9); ok {
		t.Error("rc 255 text gave a value")
	}
	// wl1 -c 0 -i: ibss 2, 1, 1, 1, 1 % on ch40
	if own, ok := ownFromCCA([]byte(v[2]), 40); !ok || !near(own, 0.012) {
		t.Errorf("wl1: %v %v", own, ok)
	}
	// summary only (no -i): 6 %
	s := ccaSections(t, "t5_wl0_cca_get_stats.txt")
	if own, ok := ownFromCCA([]byte(s[0]), 9); !ok || !near(own, 0.06) {
		t.Errorf("summary: %v %v", own, ok)
	}
}
