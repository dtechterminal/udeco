// SPDX-License-Identifier: GPL-2.0-or-later

package main

// The controller's spectrum commands in takeover mode
// (docs/deco/spectrum-design.md §3.5, §7; spectrum-controller-
// expectations.md §2, §5), run by internal/wl's per-radio SpectrumRunner:
//
//   - `cmd quick-scan` {scan-band, scan-bw}: one band per command, rows at
//     the requested width (clamped by the runner). The old table stays
//     until the new one is complete. When the band ends, whatever the
//     result, the agent informs at once: the controller sends the next band
//     only after it has the finished report (CE §2.1, §5).
//   - `cmd spectrum-scan`: every radio's table is cleared first (the real
//     AP resets each rftable to {}), then 5 GHz and 2.4 GHz are measured
//     once each with rows at every width the radio lists (20/40/80).
//
// A band that ends with a table queues its EVT_AP_QuickScanEvent (scan.go):
// the controller stores spectrum results and stamps spectrum_scan_timestamp
// only on that event (or at the end of a quick-scan). A band that fails
// sends none, as the real AP's ubntquickscan writes no table then; on a
// spectrum-scan the other band's table and event still go out (the real AP
// runs one ubntquickscan per radio, so one radio failing leaves the other's
// result standing).
//
// Observe mode runs neither (actions.go logs them only) and does not claim
// RF_SCAN. The tables live in the runners; the last good one per band is
// also kept on flash so it survives a restart or reboot (specsave.go).
//
// A band without a spectrum runner runs neither: with site_survey its
// neighbour survey runs instead (sitesurvey.go). On jio-mtk with
// site_survey the MT7603 (2.4 GHz) has a runner (mtkwifi offchan.go) and
// the MT7663 (5 GHz) has none: a quick-scan of 5 GHz surveys, and a
// spectrum-scan surveys 5 GHz and measures 2.4 GHz, as one spectrum-scan
// (spectrum_scanning, the tables cleared first).

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/rf"
	"github.com/dtechterminal/udeco/internal/wl"
)

// manualWidths are the widths of a manual spectrum-scan (ubntquickscan -a,
// "all supported bandwidths"); the runner clamps each to what the radio
// lists, so 2.4 GHz gets 20 and 40.
var manualWidths = []int{20, 40, 80}

// spectrumRequest is a band request with what the last reading tells
// (loop goroutine): our own BSSIDs, left out of the neighbour power, and
// the uplink (a wl* uplink skips its radio).
func (a *agent) spectrumRequest(widths []int, manual bool) wl.SpectrumRequest {
	req := wl.SpectrumRequest{Widths: widths, Manual: manual, Plan: a.o.spectrumPlan}
	// before every wl scan call: a band that is running when the agent
	// drops to observe, a TP-Link upgrade or rebuild starts, or an apply
	// begins stops at the next call (old table kept, abnormal)
	req.Guard = func(context.Context, wl.ScanStep) error {
		if why := a.scanBlock(); why != "" {
			return errors.New(why)
		}
		return nil
	}
	if s := a.prev; s != nil {
		req.Uplink = s.UplinkName
		for _, r := range s.Radios {
			if r.BSSID != "" {
				req.OwnBSSIDs = append(req.OwnBSSIDs, r.BSSID)
			}
			for _, v := range r.VAPs {
				if v.BSSID != "" {
					req.OwnBSSIDs = append(req.OwnBSSIDs, v.BSSID)
				}
			}
		}
	}
	return req
}

// quickScan is `cmd quick-scan` for one band (loop goroutine; the band runs
// in the background).
func (a *agent) quickScan(ctx context.Context, band string, bw int) {
	what := fmt.Sprintf("quick-scan %s %d MHz", band, bw)
	if a.shed.Load() {
		a.logf("[quick-scan] %s: skipped, memory is low (R4)", what)
		return
	}
	if why := a.scanBlock(); why != "" {
		a.logf("[quick-scan] %s: skipped, %s", what, why)
		return
	}
	if noRunner, on := a.spectrumBySurvey(band); noRunner {
		a.surveyForSpectrum(ctx, "quick-scan", []string{band}, on)
		return
	}
	if busy, ok := a.scans.begin(what, true, false); !ok {
		a.logf("[quick-scan] skipped: already in progress (%s)", busy)
		return
	}
	req := a.spectrumRequest([]int{bw}, false)
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		defer a.wakeLoop() // the finished table (or the failure) at once
		defer a.scans.end()
		a.spectrumBand(ctx, band, req, what)
	}()
	a.wakeLoop() // quickscan_scanning
}

// bands5GFirst are the unit's bands with 5 GHz first: the order a real AP
// runs a spectrum scan in.
func bands5GFirst() []string {
	b := rf.Bands()
	slices.Reverse(b)
	return b
}

// spectrumScan is `cmd spectrum-scan` (loop goroutine; the scan runs in the
// background).
func (a *agent) spectrumScan(ctx context.Context) {
	const what = "spectrum-scan"
	if a.shed.Load() {
		a.logf("%s: skipped, memory is low (R4)", what)
		return
	}
	if why := a.scanBlock(); why != "" {
		a.logf("%s: skipped, %s", what, why)
		return
	}
	bands := bands5GFirst()
	// how each band runs: its spectrum runner, else the neighbour survey
	// (site_survey), else nothing
	var runners, surveys []string
	for _, band := range bands {
		switch noRunner, on := a.spectrumBySurvey(band); {
		case !noRunner:
			runners = append(runners, band)
		case on:
			surveys = append(surveys, band)
		}
	}
	if len(runners) == 0 {
		// no spectrum table can come: the survey alone, with no spectrum
		// flags (sitesurvey.go), or nothing
		if len(surveys) > 0 {
			a.surveyForSpectrum(ctx, what, surveys, true)
		} else {
			a.surveyForSpectrum(ctx, what, bands, false)
		}
		return
	}
	if busy, ok := a.scans.begin(what, false, true); !ok {
		a.logf("%s: skipped: already in progress (%s)", what, busy)
		return
	}
	req := a.spectrumRequest(manualWidths, true)
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		defer a.wakeLoop()
		defer a.scans.end()
		// the real spectrum_scan resets every rftable to {} first (CE §2.2);
		// a saved table not restored yet goes too, and the copy on flash
		// follows (specsave.go)
		a.scans.dropEvents()
		a.scans.dropSaved()
		for _, band := range runners {
			if r, err := a.o.col.Spectrum(ctx, band); err == nil {
				r.ClearTable()
				a.scans.addRunner(band, r)
			}
		}
		a.saveSpectrum()
		a.wakeLoop() // spectrum_scanning, tables cleared
		for _, band := range bands {
			if ctx.Err() != nil {
				return
			}
			if why := a.scanBlock(); why != "" {
				a.logf("%s %s: not started, %s", what, band, why)
				return
			}
			switch {
			case slices.Contains(runners, band):
				a.spectrumBand(ctx, band, req, what+" "+band)
			case slices.Contains(surveys, band):
				// a band without a runner (jio-mtk 5 GHz): its neighbours only
				a.logf("%s %s: no spectrum runner for this band: neighbour site survey instead (scan_table only)", what, band)
				a.scans.surveyBand(ctx, a.o.col, what, band, a.t.scanTO, a.logf)
			default:
				a.logf("%s %s: no spectrum runner for this band and site_survey is off: not scanned", what, band)
			}
			a.wakeLoop()
		}
	}()
	a.wakeLoop()
}

// spectrumBand runs one band on its radio and logs the outcome. The
// runner keeps the table and the abnormal flag the informs report; the
// neighbours it heard refresh scan_table.
func (a *agent) spectrumBand(ctx context.Context, band string, req wl.SpectrumRequest, what string) {
	r, err := a.o.col.Spectrum(ctx, band)
	if err != nil {
		a.logf("%s: %v", what, err)
		return
	}
	a.scans.addRunner(band, r)
	// the gate (up to 60 s) plus the band's Budget (45 s) must fit
	bctx, cancel := context.WithTimeout(ctx, a.t.spectrumTO)
	defer cancel()
	t0 := time.Now()
	res, err := r.Run(bctx, req)
	if res == nil {
		a.logf("%s: %v", what, err)
		return
	}
	d := res.Diag
	if len(d.BSS) > 0 {
		a.scans.addBSS(band, apstate.ScanResult{Band: band, Time: d.Done, BSS: d.BSS})
	}
	took := time.Since(t0).Round(100 * time.Millisecond)
	extra := ""
	if len(d.Unmeasured) > 0 {
		extra += fmt.Sprintf(", unmeasured %v", d.Unmeasured)
	}
	if d.Fallback != "" {
		extra += ", fallback: " + d.Fallback
	}
	for _, dd := range d.Drops {
		extra += fmt.Sprintf(", client %s left %s (scan-caused %v, background %d)", dd.OUI, dd.Vif, dd.ScanCaused, dd.Background)
	}
	if len(d.Notes) > 0 {
		extra += "; " + strings.Join(d.Notes, "; ")
	}
	if len(d.Unheard) > 0 {
		extra += fmt.Sprintf(", passive channels not heard %v", d.Unheard)
	}
	switch {
	case err == nil:
		n := 0
		for _, rows := range res.Rows {
			n += len(rows)
		}
		a.logf("%s: %d rows at %v MHz on %s in %s (%s, %d calls, %d neighbours%s)",
			what, n, d.Widths, r.Radio(), took, d.Mode, len(d.Calls), len(d.BSS), extra)
		if row, ok := eventRow(res.Rows, d.HomeControl, d.HomeWidth); ok {
			a.scans.queueEvent(band, row)
		}
		a.saveSpectrum() // the new table on flash (specsave.go)
	case errors.Is(err, wl.ErrRadioSkipped):
		a.logf("%s: %v (table left as it was)%s", what, err, extra)
	default:
		// why each visit that counted for nothing was not trusted
		for _, cd := range d.Calls {
			if cd.Err != "" {
				retry := ""
				if cd.Retry {
					retry = " (retry)"
				}
				extra += fmt.Sprintf("; ch %d%s: %s", cd.Channel, retry, cd.Err)
			}
		}
		a.logf("%s: %v after %s (the previous table stays; spectrum_scanning_abnormal)%s", what, err, took, extra)
	}
}

// eventRow is the row EVT_AP_QuickScanEvent carries: the block of the
// radio's own channel (ubntquickscan reads the radio's current frequency
// for it) at the widest measured width up to the operating width, else the
// own channel's 20 MHz row, else the first row of the narrowest width. The
// controller upserts it into the table by channel and width, so it is
// always one of the table's own rows. ok is false without rows.
func eventRow(rows map[int][]wl.SpectrumRow, ctl, homeWidth int) (wl.SpectrumRow, bool) {
	ws := make([]int, 0, len(rows))
	for w, rs := range rows {
		if len(rs) > 0 {
			ws = append(ws, w)
		}
	}
	if len(ws) == 0 {
		return wl.SpectrumRow{}, false
	}
	slices.Sort(ws)
	covers := func(r wl.SpectrumRow) bool {
		n := max(1, r.Width/20)
		return ctl >= r.Channel && ctl <= r.Channel+4*(n-1) && (ctl-r.Channel)%4 == 0
	}
	for i := len(ws) - 1; i >= 0; i-- {
		if ws[i] > max(homeWidth, 20) {
			continue
		}
		for _, r := range rows[ws[i]] {
			if covers(r) {
				return r, true
			}
		}
	}
	return rows[ws[0]][0], true
}

// scanBlock says why no scan may run now ("" = one may): observe mode (no
// scans at all, spectrum-design §10), a TP-Link upgrade or Wi-Fi rebuild in
// flight (the worker's hold at its last tick), or an apply or rollback of
// ours that is running. Any goroutine.
func (a *agent) scanBlock() string {
	if !a.takeover.Load() {
		return "observe mode"
	}
	if a.wifiBusy.Load() {
		return "a Wi-Fi apply or rollback is running"
	}
	if h, _ := a.scanHold.Load().(string); h != "" {
		return h
	}
	return ""
}

// wifiChange runs an apply or rollback (worker) with wifiBusy set, so no
// scan starts or goes on while it changes the radios.
func (a *agent) wifiChange(fn func() error) error {
	a.wifiBusy.Store(true)
	defer a.wifiBusy.Store(false)
	return fn()
}
