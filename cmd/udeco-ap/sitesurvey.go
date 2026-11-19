// SPDX-License-Identifier: GPL-2.0-or-later

package main

// The controller's spectrum commands on a collector without a spectrum
// runner (platform jio-mtk: mtkwifi.Collector.Spectrum is ErrUnsupported).
//
// With site_survey on (mtkwifi FreshScan), `cmd spectrum-scan` (the
// Environment page's button: 5 GHz, then 2.4 GHz) and `cmd quick-scan`
// (nightly, one band per command) run the driver's site survey of their
// band(s) instead, the same path as `cmd scan` (scanner.neighbourScan),
// and report scan_table only. Nothing of the spectrum path is sent:
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

// spectrumBySurvey: ok says the collector has no spectrum runner; on says
// its spectrum commands run the neighbour survey instead (site_survey).
func (a *agent) spectrumBySurvey() (ok, on bool) {
	s, ok := a.o.col.(interface{ SpectrumBySurvey() bool })
	if !ok {
		return false, false
	}
	return true, s.SpectrumBySurvey()
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
