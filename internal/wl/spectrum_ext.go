// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"context"
	"fmt"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// Spectrum runners of other drivers. A SpectrumRunner made by
// NewSpectrumRunner measures through a SpectrumBackend instead of `wl
// scan`: internal/mtkwifi's MT7603 off-channel sweep (ApOffChanScan). The
// runner keeps what is common to every driver, exactly as for a wl radio:
// the table and its time, the phase, the abnormal flag, RestoreTable,
// ClearTable and FitRestored (through the backend's Listed). cmd/udeco-ap
// drives both kinds the same way (quick-scan, spectrum-scan, the inform
// fields, EVT_AP_QuickScanEvent, the saved tables).

// SpectrumBackend measures one radio's band for an external runner.
type SpectrumBackend interface {
	// Measure runs one band. On success rows holds the rows of each
	// clamped width (Diag.Widths); on failure rows are ignored. diag is
	// returned either way (the runner sets Radio and Band, and Started and
	// Done when left zero). phase is called with PhasePending or
	// PhaseScanning as the band moves on (PhaseIdle is the runner's, at
	// the end). Errors as for Run: ErrRadioSkipped leaves abnormal as it
	// was; any other error sets it and keeps the old table.
	Measure(ctx context.Context, req SpectrumRequest, phase func(SpectrumPhase)) (rows map[int][]SpectrumRow, diag SpectrumDiag, err error)
	// Listed is every row the radio could have now (FitRestored): its
	// lowest 20 MHz channel, width and centre frequency.
	Listed(ctx context.Context) ([]SpectrumBlock, error)
}

// SpectrumBlock is a row the radio can have: its lowest 20 MHz channel, its
// width and its centre frequency.
type SpectrumBlock struct {
	Channel, Width, CenterFreq int
}

// NewSpectrumRunner returns a runner of radio on band ("ng", "na") that
// measures through b. The caller keeps one per radio (the runner holds the
// radio's table).
func NewSpectrumRunner(radio, band string, b SpectrumBackend) *SpectrumRunner {
	return &SpectrumRunner{ext: b, radio: radio, band: band, phase: PhaseIdle, sticky: map[int]bool{}}
}

// runExt is Run through the backend.
func (s *SpectrumRunner) runExt(ctx context.Context, req SpectrumRequest) (*SpectrumResult, error) {
	start := time.Now()
	rows, d, err := s.ext.Measure(ctx, req, func(p SpectrumPhase) { s.setPhase(p, req.Manual, req.OnPhase) })
	d.Radio, d.Band = s.radio, s.band
	if d.Started.IsZero() {
		d.Started = start
	}
	if d.Done.IsZero() {
		d.Done = time.Now()
	}
	if err == nil && countRows(rows) == 0 {
		err = ErrNoRows
	}
	if err != nil {
		rows = nil
		d.Err = err.Error()
	}
	s.finish(rows, d.Done, err, req.OnPhase)
	return &SpectrumResult{Radio: s.radio, Band: s.band, Rows: rows, Status: s.Status(), Diag: d}, err
}

func countRows(rows map[int][]SpectrumRow) int {
	n := 0
	for _, rs := range rows {
		n += len(rs)
	}
	return n
}

// listedBlocks is what FitRestored keeps rows of: the backend's list, or
// for a wl radio the blocks of its chanspec list.
func (s *SpectrumRunner) listedBlocks(ctx context.Context) ([]SpectrumBlock, error) {
	if s.ext != nil {
		return s.ext.Listed(ctx)
	}
	st, err := s.c.static(ctx)
	if err != nil {
		return nil, err
	}
	var specs []chanspec
	for _, r := range st.radios {
		if r.name == s.radio {
			specs = r.specs
		}
	}
	var out []SpectrumBlock
	for _, w := range []int{20, 40, 80, 160} {
		for _, bl := range blocksFor(specs, s.band, w) {
			out = append(out, SpectrumBlock{Channel: bl.Parts[0], Width: w, CenterFreq: chanFreq(bl.Center, s.band)})
		}
	}
	return out, nil
}

// SpectrumChannel is one 20 MHz channel's measurement for
// BuildSpectrumRows: Class is ClassMeasured (Util, Interference set),
// ClassUnmeasured (no row, nor any block containing it; the band goes on)
// or ClassMissing (a block that needs it fails the band).
type SpectrumChannel struct {
	Class              string
	Util, Interference int
}

// BuildSpectrumRows builds the rows of width w (§5, §6) for the blocks
// whose lowest 20 MHz channels are lows: utilization and interference are
// the max of the block's parts; a block with an unmeasured part, or a part
// vals does not hold, has no row and is listed in omitted; a block with a
// missing part makes the band fail (ErrIncomplete); no row at all is
// ErrNoRows.
func BuildSpectrumRows(band string, w int, lows []int, vals map[int]SpectrumChannel) (rows []SpectrumRow, omitted []int, err error) {
	cv := make(map[int]chanValue, len(vals))
	for ch, v := range vals {
		cv[ch] = chanValue{Class: v.Class, Util: v.Util, Interf: v.Interference}
	}
	blocks := make([]block, 0, len(lows))
	for _, lo := range lows {
		centre := lo
		if w > 20 {
			centre = lo + (w/10 - 2)
		}
		blocks = append(blocks, block{Center: centre, Width: w, Parts: blockParts(centre, w)})
	}
	return buildRows(cv, blocks, band)
}

// ClampWidth is §6.2: the widest of widths at most req; 20 for a request
// below 20 or one no width fits.
func ClampWidth(req int, widths []int) int { return clampWidth(req, widths) }

// NeighbourInterference is §4.2's interference of 20 MHz channel ch from
// neighbour beacons only (no N_elev: a driver without per-channel noise
// records): clamp(round(max(nhome, P_bss(ch))), -110, -20), and the number
// of BSSes whose control channel is ch.
func NeighbourInterference(nhome float64, bss []apstate.BSS, ch int, band string) (dBm, ctlBSS int) {
	pb, ok, n := peakBSS(bss, ch, band)
	return interferenceDBm(nhome, pb, ok, 0, false), n
}

// errNoListed: the radio lists no 20 MHz channel (FitRestored).
func errNoListed(radio, band string) error {
	return fmt.Errorf("%s: no %s channel listed", radio, band)
}
