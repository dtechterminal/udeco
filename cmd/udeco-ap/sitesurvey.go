// SPDX-License-Identifier: GPL-2.0-or-later

package main

// The controller's spectrum commands for a band without a spectrum runner
// (platform jio-mtk: mtkwifi.Collector.SpectrumBySurvey; with site_survey
// both bands have one, run as the Deco's in spectrum.go: the MT7603's
// off-channel sweep, mtkwifi offchan.go, and the MT7663's Channel_Info
// visits, offchan5.go; without site_survey neither has).
//
// With site_survey on (mtkwifi FreshScan), `cmd quick-scan` (nightly, one
// band per command) of a band without a runner runs the driver's site
// survey of the band instead, the same path as `cmd scan`
// (scanner.neighbourScan), and reports scan_table only; so does `cmd
// spectrum-scan` (the Environment page's button: 5 GHz, then 2.4 GHz) when
// no band has a runner. When one band has a runner, the spectrum-scan runs
// as on the Deco (spectrum.go: tables cleared, spectrum_scanning) and the
// band without one is surveyed in its turn. A survey alone sends nothing
// of the spectrum path:
//
//   - no spectrum_scanning true (the controller sets it itself when it
//     sends spectrum-scan; the next inform's false ends it);
//   - no spectrum_table, and no EVT_AP_QuickScanEvent, which would stamp
//     spectrum_scan_timestamp for a table that does not exist.
//
// A quick-scan's survey does hold quickscan_scanning true while it runs, as
// the spectrum runner's quick-scan: the controller sets that flag itself
// when it sends the command, and the first inform without it ends the
// controller's quick-scan (it then saves only non-empty spectrum tables:
// none here) and sends the next band (CE §2.1, §5). Without the flag that
// was the inform right after the command, so the second band arrived
// mid-survey and was dropped as already in progress.
//
// With site_survey off, the commands scan nothing (RF_SCAN is not claimed
// then, so the controller should not send them) and the agent logs why.
//
// Safety on the unit (the survey takes the radio off its channel for a few
// seconds): the survey runs only on a controller command, never on a
// timer; one scan of any kind at a time (scanner.begin, and the
// collector's scan lock against its own cached-survey reads); never while
// an apply or rollback runs or the worker holds the scans (scanBlock,
// checked again before each band); never during a radio restart or its
// settle time (mtkwifi's restart gate: Scan returns ErrRadioRestart and
// holds the gate's read side for the whole survey, so a restart waits
// for it); and never on a radio that is down (mtkwifi: ErrRadioDown, the
// driver not asked).

import (
	"context"
	"fmt"
)

// spectrumBySurvey: noRunner says the collector has no spectrum runner for
// band; on says its spectrum commands run the neighbour survey instead
// (site_survey). A collector that does not say (wl) has runners.
func (a *agent) spectrumBySurvey(band string) (noRunner, on bool) {
	s, ok := a.o.col.(interface {
		SpectrumBySurvey(band string) (noRunner, bySurvey bool)
	})
	if !ok {
		return false, false
	}
	return s.SpectrumBySurvey(band)
}

// surveyForSpectrum answers spectrum command what (loop goroutine) with
// the neighbour survey of bands when on, else with nothing. A quick-scan's
// survey holds quickscan_scanning true while it runs (sitesurvey.go top).
func (a *agent) surveyForSpectrum(ctx context.Context, what string, bands []string, on bool) {
	if !on {
		a.logf("%s: no spectrum runner on this unit and site_survey is off: nothing scanned", what)
		return
	}
	quick := what == "quick-scan"
	flags := "no scanning flags"
	if quick {
		flags = "quickscan_scanning until it ends"
	}
	a.neighbourScan(ctx, neighbourJob{what: what, bands: bands, quick: quick,
		note: fmt.Sprintf("%s: no spectrum runner on this unit: neighbour site survey of %v instead "+
			"(scan_table only; no spectrum_table, %s, no EVT_AP_QuickScanEvent)", what, bands, flags)})
}
