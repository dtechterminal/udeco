// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/dtechterminal/udeco/internal/apstate"
)

// Pure helpers of the spectrum measurement (docs/deco/spectrum-design.md
// §3.2 classes, §4 field formulas, §5 blocks, §6 rows). Nothing here runs a
// command; spectrum.go feeds them.

// chanimRecord is one 20 MHz record of `wl chanim_stats all` ("Stats during
// last scan"): the counters and cca_* shares (%) the driver kept for that
// channel.
type chanimRecord struct {
	CS                               uint16
	Channel                          int
	Glitch, BadPLCP, Noise           int
	TxDur, Inbss, Obss, Nocat, Nopkt int
}

// zero reports the placeholder shape (§3.2 ZERO): crsglitch 0, bad plcp 0
// and every cca field 0. Noise is ignored: placeholders move it by 1 dB
// (T1 r2, 0xd0a1 -100 -> -101).
func (r chanimRecord) zero() bool {
	return r.Glitch == 0 && r.BadPLCP == 0 &&
		r.TxDur == 0 && r.Inbss == 0 && r.Obss == 0 && r.Nocat == 0 && r.Nopkt == 0
}

// same reports whether two records agree in all eight fields (§3.2 STALE).
func (r chanimRecord) same(o chanimRecord) bool {
	return r.Glitch == o.Glitch && r.BadPLCP == o.BadPLCP && r.Noise == o.Noise &&
		r.TxDur == o.TxDur && r.Inbss == o.Inbss && r.Obss == o.Obss && r.Nocat == o.Nocat && r.Nopkt == o.Nopkt
}

// util is u_p(c) of §4.1: obss + nocat + nopkt, clamped to 0..100. Our own
// txdur and inbss are left out.
func (r chanimRecord) util() int { return min(100, max(0, r.Obss+r.Nocat+r.Nopkt)) }

// parseChanimRecords reads `wl chanim_stats all` into the band's 20 MHz
// records by channel. ok is false when the text has no "version:" line
// (not chanim output at all). "version: 3" alone (wl1 before any scan, t0)
// and the header without records (t5) are ok with no records.
//
//	chanspec: 0x1001 crsglitch cnt: 365 bad plcp: 0 noise: -107
//		 cca_txdur: 0 cca_inbss: 0 cca_obss:11 cca_nocat: 2 cca_nopkt: 4
func parseChanimRecords(b []byte, band string) (map[int]chanimRecord, bool) {
	out := map[int]chanimRecord{}
	ok := false
	var cur *chanimRecord
	for line := range strings.Lines(string(b)) {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "version:") {
			ok = true
			continue
		}
		kv := colonPairs(line)
		if v, has := kv["chanspec"]; has {
			cur = nil
			n, err := strconv.ParseUint(v, 0, 16)
			if err != nil {
				continue
			}
			cs, good := decodeChanspec(uint16(n))
			if !good || cs.Width != 20 || cs.Band != band {
				continue
			}
			r := chanimRecord{CS: uint16(n), Channel: cs.Control}
			if !atoiAll(kv, map[string]*int{"crsglitch cnt": &r.Glitch, "bad plcp": &r.BadPLCP, "noise": &r.Noise}) {
				continue
			}
			cur = &r
			continue
		}
		if cur == nil {
			continue
		}
		if _, has := kv["cca_txdur"]; has {
			r := *cur
			cur = nil
			if atoiAll(kv, map[string]*int{"cca_txdur": &r.TxDur, "cca_inbss": &r.Inbss, "cca_obss": &r.Obss, "cca_nocat": &r.Nocat, "cca_nopkt": &r.Nopkt}) {
				out[r.Channel] = r
			}
		}
	}
	return out, ok
}

// atoiAll parses every named value of kv into its target; false if any is
// missing or not an integer.
func atoiAll(kv map[string]string, dst map[string]*int) bool {
	for k, p := range dst {
		v, ok := kv[k]
		if !ok {
			return false
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return false
		}
		*p = n
	}
	return true
}

// recordClass is the verdict on one call's record for its channel (§3.2
// step 4).
type recordClass string

const (
	classOK    recordClass = "ok"
	classZero  recordClass = "zero"
	classStale recordClass = "stale"
	classHome  recordClass = "home" // the home control call: never classified
	// classUnheard is a passive (DFS) channel still STALE after its
	// retry: unmeasured for this band only, never "missing".
	classUnheard recordClass = "unheard"
)

// parseChanInfo reads `wl chan_info` ("Channel 52\t5G Band, RADAR
// Sensitive, Passive" per line) into the band's channels -> passive. ok is
// false when no line of the band was found.
func parseChanInfo(b []byte, band string) (map[int]bool, bool) {
	out := map[int]bool{}
	for line := range strings.Lines(string(b)) {
		rest, found := strings.CutPrefix(strings.TrimSpace(line), "Channel ")
		if !found {
			continue
		}
		num, flags, _ := strings.Cut(rest, "\t")
		if i := strings.IndexAny(num, " ,"); i >= 0 {
			num, flags = num[:i], num[i:]+flags
		}
		ch, err := strconv.Atoi(strings.TrimSpace(num))
		if err != nil || ch <= 0 {
			continue
		}
		if (band == "na") != (ch > 14) {
			continue
		}
		out[ch] = strings.Contains(flags, "Passive") || strings.Contains(flags, "RADAR")
	}
	return out, len(out) > 0
}

// sortedKeys lists a set's true members in ascending order (nil if none).
func sortedKeys(m map[int]bool) []int {
	var out []int
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Ints(out)
	return out
}

// classifyRecord applies ZERO before STALE before OK. before/after are the
// snapshots around the call; present is whether after has the record.
func classifyRecord(before, after chanimRecord, hadBefore, present bool) recordClass {
	switch {
	case present && after.zero():
		return classZero
	case !present, hadBefore && after.same(before):
		return classStale
	default:
		return classOK
	}
}

// Channel classes after a band (§3.2 "after the last call").
const (
	ClassMeasured   = "measured"
	ClassUnmeasured = "unmeasured"
	ClassMissing    = "missing"
)

// meanUtil is u(c) of §4.1: math.Round of the mean of the records' util.
// ok is false for no records.
func meanUtil(recs []chanimRecord) (int, bool) {
	if len(recs) == 0 {
		return 0, false
	}
	sum := 0
	for _, r := range recs {
		sum += r.util()
	}
	return int(math.Round(float64(sum) / float64(len(recs)))), true
}

// bssPower is P_b(c) of §4.2 (REV2 form): the full beacon RSSI on the BSS's
// primary channel, else its RSSI spread evenly over its width and scaled by
// the overlap with the 20 MHz span of channel ch. ok is false when the BSS
// does not overlap ch.
func bssPower(b apstate.BSS, ch int, band string) (float64, bool) {
	if b.Channel == ch {
		return float64(b.Signal), true
	}
	w := float64(b.Width)
	if w <= 0 {
		w = 20
	}
	fc := float64(b.CenterFreq)
	if fc == 0 {
		fc = float64(b.Freq)
	}
	if fc == 0 {
		return 0, false
	}
	f := float64(chanFreq(ch, band))
	ov := math.Min(fc+w/2, f+10) - math.Max(fc-w/2, f-10)
	if ov <= 0 {
		return 0, false
	}
	return float64(b.Signal) + 10*math.Log10(ov/w), true
}

// peakBSS is P_bss(c): the strongest P_b(c) over bss, and the number of BSSes
// whose control channel is ch (n_ctl, diagnostics only).
func peakBSS(bss []apstate.BSS, ch int, band string) (p float64, ok bool, nctl int) {
	for _, b := range bss {
		if b.Channel == ch {
			nctl++
		}
		if v, has := bssPower(b, ch, band); has && (!ok || v > p) {
			p, ok = v, true
		}
	}
	return p, ok, nctl
}

// median of xs (mean of the middle two for an even count); ok false if empty.
func median(xs []float64) (float64, bool) {
	if len(xs) == 0 {
		return 0, false
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2], true
	}
	return (s[n/2-1] + s[n/2]) / 2, true
}

// elevatedNoise is N_elev(c) of §4.2 (REV2): relative to the band's chanim
// baseline B, only for a channel other than the home control channel whose
// OK records all have txdur + inbss <= 2, and only when min noise >= B + 10.
func elevatedNoise(recs []chanimRecord, home bool, nhome, base float64, haveBase bool) (float64, bool) {
	if home || !haveBase || len(recs) == 0 {
		return 0, false
	}
	m := recs[0].Noise
	for _, r := range recs {
		if r.TxDur+r.Inbss > 2 {
			return 0, false
		}
		m = min(m, r.Noise)
	}
	if float64(m) < base+10 {
		return 0, false
	}
	return nhome + (float64(m) - base), true
}

// interferenceDBm is §4.2's final value: clamp(round(max(Nhome, P_bss,
// N_elev)), -110, -20).
func interferenceDBm(nhome, pbss float64, havePBSS bool, nelev float64, haveNElev bool) int {
	v := nhome
	if havePBSS {
		v = math.Max(v, pbss)
	}
	if haveNElev {
		v = math.Max(v, nelev)
	}
	return min(-20, max(-110, int(math.Round(v))))
}

// SpectrumRow is one spectrum_table row as the controller expects it: all
// nine keys, in the order of a real AP's rftable file (CE §3).
// InterferenceType always marshals as [] (never null); OtherBSS, PerfIndex
// and TotalSamples are 0 as on a real AP's nightly path (§4.3-4.5).
type SpectrumRow struct {
	Channel          int      `json:"channel"`
	Width            int      `json:"width"`
	CenterFreq       int      `json:"center_freq"`
	TotalSamples     int      `json:"total_samples"`
	Interference     int      `json:"interference"`
	Utilization      int      `json:"utilization"`
	PerfIndex        int      `json:"perf_index"`
	InterferenceType []string `json:"interference_type"`
	OtherBSS         int      `json:"other_bss_count"`
}

// MarshalJSON keeps interference_type an array even when it is nil.
func (r SpectrumRow) MarshalJSON() ([]byte, error) {
	type plain SpectrumRow
	p := plain(r)
	if p.InterferenceType == nil {
		p.InterferenceType = []string{}
	}
	return json.Marshal(p)
}

// Entry is the row in the shape of apstate.SpectrumEntry (five keys), for
// code that still builds spectrum_table through apstate.SpectrumRows.
func (r SpectrumRow) Entry() apstate.SpectrumEntry {
	return apstate.SpectrumEntry{Channel: r.Channel, Width: r.Width, CenterFreq: r.CenterFreq,
		Utilization: r.Utilization, Interference: r.Interference}
}

// block is one 20/40/80/160 MHz row candidate: its centre channel and its
// 20 MHz parts, lowest first.
type block struct {
	Center, Width int
	Parts         []int
}

// blockParts lists the 20 MHz channels of a block of width w centred on
// centre (2.4 GHz 40 MHz centre 3 -> 1, 5; 5 GHz 80 MHz centre 42 -> 36..48).
func blockParts(centre, w int) []int {
	n := max(1, w/20)
	lo := centre - (w/10 - 2)
	if w <= 20 {
		lo = centre
	}
	parts := make([]int, n)
	for k := range parts {
		parts[k] = lo + 4*k
	}
	return parts
}

// blocksFor returns the radio's blocks of width w from its chanspec list,
// one per centre, ascending by lowest part.
func blocksFor(specs []chanspec, band string, w int) []block {
	seen := map[int]bool{}
	var out []block
	for _, cs := range specs {
		if cs.Band != band || cs.Width != w || seen[cs.Center] {
			continue
		}
		seen[cs.Center] = true
		out = append(out, block{Center: cs.Center, Width: w, Parts: blockParts(cs.Center, w)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Parts[0] < out[j].Parts[0] })
	return out
}

// radioWidths lists the widths the chanspec list offers on band, ascending.
func radioWidths(specs []chanspec, band string) []int {
	seen := map[int]bool{}
	var out []int
	for _, cs := range specs {
		if cs.Band == band && !seen[cs.Width] {
			seen[cs.Width] = true
			out = append(out, cs.Width)
		}
	}
	sort.Ints(out)
	return out
}

// clampWidth is §6.2: the widest width the radio has that is <= req; a
// request below 20 (or one no width fits) becomes 20.
func clampWidth(req int, widths []int) int {
	w := 20
	if req < 20 {
		return w
	}
	for _, x := range widths {
		if x <= req && x > w {
			w = x
		}
	}
	return w
}

// chanValue is what row building needs of one 20 MHz channel.
type chanValue struct {
	Class        string
	Util, Interf int
}

// buildRows is §5/§6 for one width: a row per block whose every part is
// measured (utilization and interference = max of the parts). A block with
// an unmeasured part (or a part the radio does not list at 20 MHz) has no
// row and is reported in omitted (by lowest channel); a block that needs a
// missing part makes the band fail (ErrIncomplete); no row at all is
// ErrNoRows. Rows are ascending by channel.
func buildRows(vals map[int]chanValue, blocks []block, band string) (rows []SpectrumRow, omitted []int, err error) {
	var missing []int
	for _, bl := range blocks {
		skip, miss := false, false
		u, in := 0, math.MinInt
		for _, p := range bl.Parts {
			v, ok := vals[p]
			switch {
			case !ok || v.Class == ClassUnmeasured:
				skip = true
			case v.Class == ClassMissing:
				miss = true
			default:
				u, in = max(u, v.Util), max(in, v.Interf)
			}
		}
		switch {
		case skip:
			omitted = append(omitted, bl.Parts[0])
		case miss:
			missing = append(missing, bl.Parts[0])
		default:
			rows = append(rows, SpectrumRow{Channel: bl.Parts[0], Width: bl.Width,
				CenterFreq: chanFreq(bl.Center, band), Utilization: u, Interference: in,
				InterferenceType: []string{}})
		}
	}
	if len(missing) > 0 {
		return nil, omitted, &incompleteError{width: blocksWidth(blocks), blocks: missing}
	}
	if len(rows) == 0 {
		return nil, omitted, ErrNoRows
	}
	return rows, omitted, nil
}

func blocksWidth(bs []block) int {
	if len(bs) == 0 {
		return 0
	}
	return bs[0].Width
}

// ccaRow is one row of `wl cca_get_stats`: a channel and its ibss / obss /
// interf shares (%) over Dur ms.
type ccaRow struct {
	Chan, Dur          int
	Ibss, Obss, Interf int
}

// parseCCAGetStats reads `wl cca_get_stats -c 0 -s N [-i]`: the per-second
// rows (with -i) and the "Summaries:" rows (T5):
//
//	chan dur      ibss           obss           interf       time
//	9   1004   84  8% Low     270 26% High      9  0% Low    4003
//	Summaries:
//	chan dur      ibss           obss             interf     num seconds
//	9   1004       7% Low         26% High         1% Low    5
func parseCCAGetStats(b []byte) (rows, summary []ccaRow) {
	inSummary := false
	for line := range strings.Lines(string(b)) {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "Summaries") {
			inSummary = true
			continue
		}
		f := strings.Fields(t)
		if len(f) < 5 {
			continue
		}
		ch, err1 := strconv.Atoi(f[0])
		dur, err2 := strconv.Atoi(f[1])
		if err1 != nil || err2 != nil {
			continue
		}
		var pct []int
		for _, tok := range f[2:] {
			if v, ok := strings.CutSuffix(tok, "%"); ok {
				n, err := strconv.Atoi(v)
				if err != nil {
					break
				}
				pct = append(pct, n)
			}
		}
		if len(pct) < 3 {
			continue
		}
		r := ccaRow{Chan: ch, Dur: dur, Ibss: pct[0], Obss: pct[1], Interf: pct[2]}
		if inSummary {
			summary = append(summary, r)
		} else {
			rows = append(rows, r)
		}
	}
	return rows, summary
}

// ownFromCCA is the airtime gate input of §8.1 (REV2): the mean ibss share
// of the home control channel's per-second rows as a fraction, else its
// summary row. ok is false when neither has the channel.
func ownFromCCA(b []byte, homeControl int) (float64, bool) {
	rows, sum := parseCCAGetStats(b)
	n, total := 0, 0
	for _, r := range rows {
		if r.Chan == homeControl {
			n++
			total += r.Ibss
		}
	}
	if n > 0 {
		return float64(total) / float64(n) / 100, true
	}
	for _, r := range sum {
		if r.Chan == homeControl {
			return float64(r.Ibss) / 100, true
		}
	}
	return 0, false
}
