// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// offsetSeries reads series_chanim_stats_us_offsets.txt: three samples, 2 s
// apart, of both radios after a radio re-init (counters carry ±2^32
// offsets; wl1's total_tm is close to 2^64).
func offsetSeries(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	var radio string
	var buf strings.Builder
	flush := func() {
		if radio != "" {
			out[radio] = append(out[radio], buf.String())
		}
		buf.Reset()
	}
	for line := range strings.Lines(string(fixture(t, "series_chanim_stats_us_offsets.txt"))) {
		switch {
		case strings.HasPrefix(line, "# "):
			flush()
			radio = strings.TrimSpace(line[2:])
		case len(strings.Fields(line)) == 1 && !strings.Contains(line, ":"):
			flush() // a timestamp line between samples
			radio = ""
		default:
			buf.WriteString(line)
		}
	}
	flush()
	return out
}

func TestSurveyModularDeltas(t *testing.T) {
	series := offsetSeries(t)
	if len(series["wl0"]) != 3 || len(series["wl1"]) != 3 {
		t.Fatalf("series: %d/%d samples", len(series["wl0"]), len(series["wl1"]))
	}
	t0 := time.Unix(1795018074, 0)
	for _, tc := range []struct {
		radio string
		want  []apstate.Survey
	}{
		// wl0 0x1007: Δtotal 2008000 µs each; busy = Δbusy_tm + Δtx
		{"wl0", []apstate.Survey{
			{},
			{Active: 2008, Busy: (292454 + 324317) / 1000, Rx: 132738 / 1000, Tx: 324317 / 1000},
			{Active: 4016, Busy: (292454 + 324317 + 513363 + 306668) / 1000, Rx: (132738 + 337406) / 1000, Tx: (324317 + 306668) / 1000},
		}},
		// wl1 0xd028: total_tm ≈ 2^64 − 4.3e9 (a negative offset)
		{"wl1", []apstate.Survey{
			{},
			{Active: 2008, Busy: (102014 + 42311) / 1000, Rx: 1, Tx: 42},
			{Active: 4016, Busy: (102014 + 42311 + 163712 + 90917) / 1000, Rx: (1128 + 942) / 1000, Tx: (42311 + 90917) / 1000},
		}},
	} {
		var s surveyState
		for i, out := range series[tc.radio] {
			row, ok := parseChanimUs([]byte(out))
			if !ok {
				t.Fatalf("%s sample %d does not parse", tc.radio, i)
			}
			got := s.update(row, t0.Add(time.Duration(2*i)*time.Second))
			if got != tc.want[i] {
				t.Errorf("%s sample %d: %+v, want %+v", tc.radio, i, got, tc.want[i])
			}
		}
	}
}

func TestSurveyResets(t *testing.T) {
	t0 := time.Unix(0, 0)
	var s surveyState
	row := chanimRow{Key: 0x1007, Tx: 10, Inbss: 10, Busy: 10, Total: 1_000_000}
	s.update(row, t0)

	// across 2^64: the u64 difference is still the real one
	near := chanimRow{Key: 0x1007, Tx: ^uint64(0) - 99, Inbss: 5, Busy: ^uint64(0), Total: ^uint64(0) - 499_999}
	s = surveyState{}
	s.update(near, t0)
	next := near
	next.Tx += 200_000      // wraps
	next.Busy += 300_000    // wraps
	next.Total += 1_000_000 // wraps
	next.Inbss += 100_000
	got := s.update(next, t0.Add(time.Second))
	if got != (apstate.Survey{Active: 1000, Busy: 500, Rx: 100, Tx: 200}) {
		t.Errorf("wrap: %+v", got)
	}

	// a new offset (radio re-init) shows up as an impossible delta: re-baseline
	jump := next
	jump.Total += 1_000_000
	jump.Busy += 1 << 32
	if got2 := s.update(jump, t0.Add(2*time.Second)); got2 != got {
		t.Errorf("jump counted: %+v", got2)
	}
	after := jump
	after.Total += 1_000_000
	after.Busy += 100_000
	if got3 := s.update(after, t0.Add(3*time.Second)); got3.Active != 2000 || got3.Busy != 600 {
		t.Errorf("after re-baseline: %+v", got3)
	}

	// total_tm far ahead of wall time: re-baseline
	far := after
	far.Total += 1_000_000_000
	if got4 := s.update(far, t0.Add(4*time.Second)); got4.Active != 2000 {
		t.Errorf("far jump counted: %+v", got4)
	}

	// channel change: new baseline, nothing added, never decreasing
	moved := chanimRow{Key: 0x1002, Total: 5}
	if got5 := s.update(moved, t0.Add(5*time.Second)); got5.Active != 2000 {
		t.Errorf("channel change: %+v", got5)
	}

	// total_tm unchanged (1 s steps): keep the baseline, report the same
	same := moved
	same.Busy += 10_000
	if got6 := s.update(same, t0.Add(5500*time.Millisecond)); got6.Active != 2000 {
		t.Errorf("unchanged total: %+v", got6)
	}
	later := same
	later.Total += 1_000_000
	if got7 := s.update(later, t0.Add(6*time.Second)); got7.Active != 3000 || got7.Busy != 610 {
		t.Errorf("later: %+v", got7)
	}
}

// TestSurveyLongGapOffset: after a long pause between samples, a radio
// re-init that adds +2^32 µs to every counter (same primary channel) must
// not be taken as real airtime.
func TestSurveyLongGapOffset(t *testing.T) {
	t0 := time.Unix(0, 0)
	var s surveyState
	base := chanimRow{Key: 0x1007, Tx: 1_000_000, Inbss: 1_000_000, Busy: 2_000_000, Total: 10_000_000}
	s.update(base, t0)
	gap := 80 * time.Minute
	const off = 1 << 32
	real := uint64(gap.Microseconds())
	jumped := chanimRow{Key: 0x1007, Tx: base.Tx + off + real/10, Inbss: base.Inbss + off + real/10,
		Busy: base.Busy + off + real/5, Total: base.Total + off + real}
	if got := s.update(jumped, t0.Add(gap)); got != (apstate.Survey{}) {
		t.Errorf("offset jump after %v counted: %+v", gap, got)
	}
	// the next real interval counts again from the new baseline
	next := jumped
	next.Total += 10_000_000
	next.Busy += 2_000_000
	if got := s.update(next, t0.Add(gap+10*time.Second)); got.Active != 10_000 || got.Busy != 2_000 {
		t.Errorf("after re-baseline: %+v", got)
	}
}
