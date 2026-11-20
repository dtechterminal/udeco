// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
)

// fakeBackend is a SpectrumBackend of another driver (internal/mtkwifi).
type fakeBackend struct {
	rows   map[int][]SpectrumRow
	err    error
	listed []SpectrumBlock
	phases []SpectrumPhase
	reqs   []SpectrumRequest
}

func (f *fakeBackend) Measure(ctx context.Context, req SpectrumRequest, phase func(SpectrumPhase)) (map[int][]SpectrumRow, SpectrumDiag, error) {
	f.reqs = append(f.reqs, req)
	phase(PhaseScanning)
	return copyRows(f.rows), SpectrumDiag{Mode: "offchan", HomeControl: 6, HomeWidth: 20}, f.err
}

func (f *fakeBackend) Listed(context.Context) ([]SpectrumBlock, error) { return f.listed, nil }

// A runner made with NewSpectrumRunner keeps its table, phase and abnormal
// flag exactly as a wl runner does: a good band replaces the table, a
// failed one keeps it and sets abnormal, the next good one clears it.
func TestExternalSpectrumRunner(t *testing.T) {
	good := map[int][]SpectrumRow{20: {{Channel: 1, Width: 20, CenterFreq: 2412, Utilization: 12, Interference: -70}}}
	b := &fakeBackend{rows: good}
	s := NewSpectrumRunner("ra0", "ng", b)
	if s.Radio() != "ra0" || s.Status().Band != "ng" || s.Status().Phase != PhaseIdle {
		t.Fatalf("new runner: %+v", s.Status())
	}
	var seen []SpectrumPhase
	res, err := s.Run(context.Background(), SpectrumRequest{Widths: []int{20}, OnPhase: func(p SpectrumPhase) { seen = append(seen, p) }})
	if err != nil || !reflect.DeepEqual(res.Rows, good) {
		t.Fatalf("Run: %v, rows %v", err, res.Rows)
	}
	if !reflect.DeepEqual(seen, []SpectrumPhase{PhaseScanning, PhaseIdle}) {
		t.Errorf("phases %v", seen)
	}
	st := s.Status()
	if st.Abnormal || st.TableTime.IsZero() || !reflect.DeepEqual(st.Rows, good) || res.Diag.Radio != "ra0" || res.Diag.Band != "ng" || res.Diag.Done.IsZero() {
		t.Errorf("after a good band: %+v, diag %+v", st, res.Diag)
	}
	t0 := st.TableTime

	b.err, b.rows = ErrIncomplete, nil
	res, err = s.Run(context.Background(), SpectrumRequest{})
	if !errors.Is(err, ErrIncomplete) || res.Rows != nil || res.Diag.Err == "" {
		t.Errorf("failed band: %v, rows %v, diag err %q", err, res.Rows, res.Diag.Err)
	}
	if st := s.Status(); !st.Abnormal || !st.TableTime.Equal(t0) || !reflect.DeepEqual(st.Rows, good) {
		t.Errorf("a failed band changed the table or kept abnormal off: %+v", st)
	}
	// a backend that says success with no row is no table either
	b.err, b.rows = nil, map[int][]SpectrumRow{20: nil}
	if _, err = s.Run(context.Background(), SpectrumRequest{}); !errors.Is(err, ErrNoRows) {
		t.Errorf("no rows: %v", err)
	}
	b.rows = good
	if _, err = s.Run(context.Background(), SpectrumRequest{}); err != nil || s.Status().Abnormal {
		t.Errorf("next good band: %v, %+v", err, s.Status())
	}
	// a skipped radio leaves abnormal as it was
	b.err = ErrRadioSkipped
	s.Run(context.Background(), SpectrumRequest{})
	if s.Status().Abnormal {
		t.Error("a skipped radio set abnormal")
	}
}

// FitRestored on an external runner keeps the restored rows the backend
// lists now (channel, width and centre).
func TestExternalFitRestored(t *testing.T) {
	b := &fakeBackend{listed: []SpectrumBlock{{Channel: 1, Width: 20, CenterFreq: 2412}, {Channel: 6, Width: 20, CenterFreq: 2437},
		{Channel: 1, Width: 40, CenterFreq: 2422}}}
	s := NewSpectrumRunner("ra0", "ng", b)
	saved := map[int][]SpectrumRow{
		20: {{Channel: 1, Width: 20, CenterFreq: 2412}, {Channel: 6, Width: 20, CenterFreq: 2437}, {Channel: 13, Width: 20, CenterFreq: 2472}},
		40: {{Channel: 1, Width: 40, CenterFreq: 2422}, {Channel: 9, Width: 40, CenterFreq: 2462}},
	}
	if !s.RestoreTable(saved, time.Now().Add(-time.Hour)) {
		t.Fatal("not restored")
	}
	kept, dropped, err := s.FitRestored(context.Background())
	if err != nil || kept != 3 || dropped != 2 {
		t.Fatalf("fit: kept %d dropped %d, %v", kept, dropped, err)
	}
	if rows := s.Status().Rows; len(rows[20]) != 2 || len(rows[40]) != 1 {
		t.Errorf("rows after the fit %v", rows)
	}
	// nothing listed at 20 MHz: kept, and said
	b.listed = nil
	if _, _, err := s.FitRestored(context.Background()); err == nil {
		t.Error("no 20 MHz channel listed: no error")
	}
}

// BuildSpectrumRows is §5/§6 for a driver that measures 20 MHz channels
// itself: a 40 MHz block is the max of its two parts, a block with an
// unmeasured part has no row, one with a missing part fails the band.
func TestBuildSpectrumRows(t *testing.T) {
	vals := map[int]SpectrumChannel{
		1: {Class: ClassMeasured, Util: 10, Interference: -80},
		5: {Class: ClassMeasured, Util: 30, Interference: -60},
		2: {Class: ClassUnmeasured},
		6: {Class: ClassMeasured, Util: 5, Interference: -95},
	}
	rows, omitted, err := BuildSpectrumRows("ng", 40, []int{1, 2}, vals)
	want := []SpectrumRow{{Channel: 1, Width: 40, CenterFreq: 2422, Utilization: 30, Interference: -60, InterferenceType: []string{}}}
	if err != nil || !reflect.DeepEqual(rows, want) || !reflect.DeepEqual(omitted, []int{2}) {
		t.Errorf("40 MHz: %v %v %v", rows, omitted, err)
	}
	rows, _, err = BuildSpectrumRows("ng", 20, []int{1, 5, 6}, vals)
	if err != nil || len(rows) != 3 || rows[2].CenterFreq != 2437 || rows[1].Utilization != 30 {
		t.Errorf("20 MHz: %v %v", rows, err)
	}
	vals[5] = SpectrumChannel{Class: ClassMissing}
	if _, _, err = BuildSpectrumRows("ng", 40, []int{1}, vals); !errors.Is(err, ErrIncomplete) {
		t.Errorf("missing part: %v", err)
	}
	if _, _, err = BuildSpectrumRows("ng", 20, []int{2}, vals); !errors.Is(err, ErrNoRows) {
		t.Errorf("no row: %v", err)
	}
	if got := ClampWidth(80, []int{20, 40}); got != 40 {
		t.Errorf("ClampWidth(80) = %d", got)
	}
}

// NeighbourInterference is §4.2 without N_elev: the strongest neighbour
// level on the channel, else the noise floor.
func TestNeighbourInterference(t *testing.T) {
	bss := []apstate.BSS{
		{Channel: 1, Freq: 2412, Width: 40, CenterFreq: 2422, Signal: -60},
		{Channel: 11, Freq: 2462, Width: 20, CenterFreq: 2462, Signal: -70},
	}
	if v, n := NeighbourInterference(-95, bss, 1, "ng"); v != -60 || n != 1 {
		t.Errorf("ch1: %d (%d control)", v, n)
	}
	// ch 5 is the 40 MHz BSS's secondary: -60 - 3 dB
	if v, _ := NeighbourInterference(-95, bss, 5, "ng"); v != -63 {
		t.Errorf("ch5: %d", v)
	}
	// 2.4 GHz channels overlap: ch 8 (2437-2457 MHz) gets 5 MHz of each
	if v, _ := NeighbourInterference(-95, bss, 8, "ng"); v != -69 {
		t.Errorf("ch8: %d, want -60 + 10 log(5/40)", v)
	}
	if v, n := NeighbourInterference(-95, bss[:1], 9, "ng"); v != -95 || n != 0 {
		t.Errorf("ch9 (nothing overlaps): %d", v)
	}
}
