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
//   - no spectrum_scanning or quickscan_scanning true: on its true -> false
//     the controller would store the (empty) spectrum table of the run;
//   - no spectrum_table, and no EVT_AP_QuickScanEvent, which would stamp
//     spectrum_scan_timestamp for a table that does not exist.
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

import "context"

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
// the neighbour survey of bands when on, else with nothing.
func (a *agent) surveyForSpectrum(ctx context.Context, what string, bands []string, on bool) {
	if !on {
		a.logf("%s: no spectrum runner on this unit and site_survey is off: nothing scanned", what)
		return
	}
	a.logf("%s: no spectrum runner on this unit: neighbour site survey of %v instead "+
		"(scan_table only; no spectrum_table, no scanning flags, no EVT_AP_QuickScanEvent)", what, bands)
	a.neighbourScan(ctx, what, bands)
}
