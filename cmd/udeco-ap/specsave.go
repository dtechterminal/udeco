// SPDX-License-Identifier: GPL-2.0-or-later

package main

// The last good spectrum table of each band survives an agent restart and a
// reboot (2026-11-20: the release deploy of 2026-11-19 restarted every
// agent, the informs stopped carrying spectrum_table and the AP's
// Environment section stayed empty until the next scan).
//
// Saved: filepath.Join(base, wifiStateSub, spectrumFile), on the Deco
// /tp_data/udeco/state/spectrum.json (ubifs flash, mounted sync), on the
// JioFiber (Garage) /flash2/udeco/state/spectrum.json, one small
// versioned JSON file (spectrumSave: model, and per band the radio, the
// wall-clock time the table was measured and its rows; about 1.5 kB for a
// quick-scan of both bands, under 6 kB for a manual all-widths scan). It is
// written (tmp + rename, 0600) only when a band gets a new good table and
// when a manual spectrum-scan clears the tables first (CE §2.2: the saved
// copy follows, cleared, then each new table), and only when the bytes
// differ from what the file holds. A failed band leaves the table, and so
// the file, as it was (CE §6). A failed write is logged; the table stays in
// memory.
//
// Restored: read at start (setup, when RF_SCAN is claimed: takeover on the
// Deco, takeover with site_survey on jio-mtk) and put into
// the band's spectrum runner (wl.SpectrumRunner.RestoreTable) at the next
// inform that finds no Wi-Fi apply or rollback running; from then on it is
// reported exactly as a live table: spectrum_table rows and
// spectrum_table_time = the true age from the saved wall-clock time, until
// a new band replaces it or a spectrum-scan clears it. Checked first: a
// file of another version or model, or that does not parse, is dropped
// whole; a band whose radio is not the unit's radio for that band now
// (another radio layout), whose rows do not belong to the band, or that was
// measured more than spectrumMaxAge ago is dropped. While the clock is not
// set yet (before device.ClockSane: a Deco reads 2025-09-12 until NTP,
// interference-audit X9) the table is held, not dropped, and re-checked at
// every inform; once the clock is set, a table measured after it is
// dropped (saved under a clock that ran ahead: its true age is unknown). A
// band measured since the start always wins over a saved one.
//
// Fitted to the radio: a live band builds its rows only from what `wl
// chanspecs` lists (widths and channels), so of a restored table only the
// rows the radio lists now are kept (wl.SpectrumRunner.FitRestored; CE §4:
// no rows for channels the unit cannot use), and a table with none left is
// dropped. The caps are cached until an apply or a tick repair reads them
// again, and a driver country set before the restart is applied only by
// the first apply after it, so the fit runs again at every inform while a
// restored table is reported (no wl call unless the caps were dropped);
// the saved copy follows a change. Until that apply a table measured under
// the old country is reported as fitted to the old channel list, for the
// few informs before the controller's first configuration.
//
// No EVT_AP_QuickScanEvent for a restored table: the event means "a scan
// just ended" and would add a fake one. What the controller then does with
// the table (Network 11.1.50 decompiled, docs/deco/spectrum-controller-
// expectations.md §5 "VERIFIED 2026-11-19", agent-design.md "Storing on the
// controller"): every inform's non-empty spectrum_table, sent while no
// quick-scan is in progress, replaces the copy the controller keeps in its
// in-memory radio_table_stats, and spectrum_table_time (an age) becomes the
// epoch now - age, so the restored table shows the time it was measured.
// The controller writes spectrum results to its database only on
// EVT_AP_QuickScanEvent (which also stamps spectrum_scan_timestamp = now and
// upserts the event's row) or on a quickscan_scanning true -> false
// transition. The agent never sends the event for a restored table, so in
// the usual case it lives in the controller's in-memory copy only,
// refreshed by every inform (also after a controller restart). The
// transition, though, is the controller's own state: it sets
// quickscan_scanning true itself when it sends `cmd quick-scan` (and times
// it out after 10 min). So when a quick-scan the controller sent does not
// end with a new table of ours, the next inform without quickscan_scanning
// carrying the restored table ends that quick-scan, and the controller
// saves the restored table (with its true measurement time from
// spectrum_table_time) to its database as that quick-scan's result. That
// happens when the agent restarts while a quick-scan runs (a deploy during
// Radio AI's nightly run), or when the restarted agent skips the
// controller's quick-scan (memory shedding, a Wi-Fi apply such as the
// startup one, a scan hold, another scan running: quickScan returns
// without a table). INFERENCE: a real AP's controller does the same with
// the rftable file the AP keeps (CE §6: a failed quick-scan leaves the
// previous table, and the same transition then saves it). UNVERIFIED (not in the decompile notes):
// whether that transition save also stamps spectrum_scan_timestamp, and so
// whether Radio AI's prescan (which waits for that timestamp, freshData)
// takes the restored table as a fresh scan. Without the transition,
// spectrum_scan_timestamp keeps what the database had and the prescan does
// not take it. UNVERIFIED on the units: that the Environment section
// (stat/spectrum-scan, built from radio_table_stats) shows the in-memory
// copy before the next scan saves one.
//
// Neighbour results (scan_table) are neither saved nor restored. keepSeen
// keeps a missed neighbour 10 min, and the home listen (homelisten.go)
// refills the own-channel neighbours within homeListenEvery (1 min) of the
// start, so a restored list would matter for about a minute; a reboot
// outlasts keepSeen anyway; and the list changes at almost every listen
// (signal, age), so keeping it on flash would mean a write a minute.
//
// jio-mtk: only the 2.4 GHz band has a runner (the MT7603's off-channel
// sweep, with site_survey), so only its table is saved and restored; a
// saved table of a band that has no runner now (site_survey turned off
// since) is dropped at the first inform, and the file follows at the next
// write. Without site_survey RF_SCAN is not claimed and nothing is loaded.
// Observe mode runs no scans and claims no RF_SCAN: nothing is loaded
// either, and a file left from takeover stays as it is.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

const (
	spectrumFile    = "spectrum.json"    // under the state directory (flash)
	spectrumVersion = 1                  // spectrumSave.Version
	spectrumMaxAge  = 7 * 24 * time.Hour // an older saved table is dropped
)

// spectrumSave is the file: the unit's model and the last good table per
// band ("ng", "na").
type spectrumSave struct {
	Version int                    `json:"version"`
	Model   string                 `json:"model"`
	Bands   map[string]*savedTable `json:"bands"`
}

// savedTable is one band's table: the radio that measured it, when (wall
// clock) and its rows by width.
type savedTable struct {
	Radio string                   `json:"radio"`
	Time  time.Time                `json:"time"`
	Rows  map[int][]wl.SpectrumRow `json:"rows"`
}

func (a *agent) spectrumPath() string {
	return a.dev(filepath.Join(a.o.base, wifiStateSub, spectrumFile))
}

// loadSpectrum reads the saved tables at start (RF_SCAN claimed); the
// next informs restore them (restoreSpectrum).
func (a *agent) loadSpectrum() {
	if a.o.base == "" { // a bare agent in a unit test: no flash
		return
	}
	p := a.spectrumPath()
	b, err := os.ReadFile(p)
	if err != nil {
		if !os.IsNotExist(err) {
			a.logf("spectrum: reading the saved tables %s: %v (none restored)", p, err)
		}
		return
	}
	tables, dropped, err := parseSpectrumSave(b, a.cfg.Model)
	if err != nil {
		a.logf("spectrum: saved tables in %s dropped: %v", p, err)
	}
	for _, band := range slices.Sorted(maps.Keys(dropped)) {
		a.logf("spectrum: saved %s table dropped: %s", band, dropped[band])
	}
	a.scans.loadSaved(tables, b)
}

// parseSpectrumSave checks a saved file: the whole of it (err: version,
// model, JSON) and each band (dropped, by band, with the reason).
func parseSpectrumSave(b []byte, model string) (tables map[string]*savedTable, dropped map[string]string, err error) {
	var s spectrumSave
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, nil, fmt.Errorf("unparsable: %v", err)
	}
	if s.Version != spectrumVersion {
		return nil, nil, fmt.Errorf("version %d, this agent reads %d", s.Version, spectrumVersion)
	}
	if s.Model != model {
		return nil, nil, fmt.Errorf("saved on another model (%q, this unit is %q)", s.Model, model)
	}
	tables, dropped = map[string]*savedTable{}, map[string]string{}
	for band, t := range s.Bands {
		switch {
		case band != "ng" && band != "na":
			dropped[band] = "not a band this agent scans"
		case t == nil || t.Radio == "" || t.Time.IsZero():
			dropped[band] = "no radio or no time"
		default:
			if err := checkSavedRows(band, t.Rows); err != nil {
				dropped[band] = err.Error()
				continue
			}
			tables[band] = t
		}
	}
	return tables, dropped, nil
}

// checkSavedRows: rows of band at a width the runner builds, each row in
// its width's list and in the band.
func checkSavedRows(band string, rows map[int][]wl.SpectrumRow) error {
	lo, hi := 2400, 2500
	if band == "na" {
		lo, hi = 4900, 5925
	}
	n := 0
	for w, rs := range rows {
		if !slices.Contains([]int{20, 40, 80, 160}, w) {
			return fmt.Errorf("rows at %d MHz", w)
		}
		for _, r := range rs {
			if r.Width != w || r.Channel <= 0 || r.CenterFreq < lo || r.CenterFreq > hi {
				return fmt.Errorf("row ch %d %d MHz at %d MHz under %d MHz is not a %s row", r.Channel, r.Width, r.CenterFreq, w, band)
			}
			n++
		}
	}
	if n == 0 {
		return fmt.Errorf("no rows")
	}
	return nil
}

// restoreSpectrum puts the saved tables back into their runners, once each
// is plausible at now, and fits every restored table to the channels the
// radio lists now (loop goroutine, every inform; nothing to do once they
// are all restored or dropped and no restored table is left). Nothing is
// done while a Wi-Fi apply or rollback runs: the radios' channel lists are
// in flux then.
func (a *agent) restoreSpectrum(ctx context.Context, now time.Time) {
	if a.wifiBusy.Load() {
		return
	}
	for _, band := range a.scans.savedBands() {
		t := a.scans.savedTable(band)
		if t == nil {
			continue
		}
		if now.Before(device.ClockSane) {
			// the clock is not set yet (a Deco reads 2025-09-12 until NTP,
			// interference-audit X9): no age can be told; held, not dropped
			if a.specNoted[band] != "held" {
				a.logf("spectrum: the saved %s table (measured %s) is held until the clock is set (now %s)",
					band, t.Time.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
				a.noteSpectrum(band, "held")
			}
			continue
		}
		if t.Time.After(now) {
			// the clock is set and the table is from its future: it was
			// saved under a clock that ran ahead, so its true age is unknown
			// (holding it until the clock passes would report it as fresh)
			a.scans.forgetSaved(band, t)
			a.logf("spectrum: saved %s table dropped: measured %s, after the current time %s",
				band, t.Time.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
			continue
		}
		if age := now.Sub(t.Time); age > spectrumMaxAge {
			a.scans.forgetSaved(band, t)
			a.logf("spectrum: saved %s table dropped: measured %s ago, older than 7 days", band, age.Round(time.Minute))
			continue
		}
		if noRunner, _ := a.spectrumBySurvey(band); noRunner {
			// jio-mtk: the band has no runner (5 GHz; or site_survey
			// turned off since the table was saved)
			a.scans.forgetSaved(band, t)
			a.logf("spectrum: saved %s table dropped: this unit has no spectrum runner for the band now", band)
			continue
		}
		r, err := a.o.col.Spectrum(ctx, band)
		if err != nil {
			if a.specNoted[band] != err.Error() {
				a.logf("spectrum: saved %s table not restored yet: %v (retried at the next inform)", band, err)
				a.noteSpectrum(band, err.Error())
			}
			continue
		}
		if r.Radio() != t.Radio {
			a.scans.forgetSaved(band, t)
			a.logf("spectrum: saved %s table dropped: measured on radio %s, the unit's is %s", band, t.Radio, r.Radio())
			continue
		}
		n := 0
		for _, rs := range t.Rows {
			n += len(rs)
		}
		switch a.scans.restore(band, t, r) {
		case restoredOK:
			a.logf("spectrum: restored the %s table measured %s ago on %s (%d rows; reported as measured, no EVT_AP_QuickScanEvent)",
				band, now.Sub(t.Time).Round(time.Second), r.Radio(), n)
		case restoredNewer:
			a.logf("spectrum: saved %s table not restored: %s has a newer table", band, r.Radio())
		}
	}
	a.fitRestored(ctx)
}

// fitRestored drops the rows of each restored table that the radio does
// not list now (wl.SpectrumRunner.FitRestored): a live band never builds
// them, and a table saved under another country or width cap may hold them
// (CE §4: no rows for channels the unit cannot use). It runs at every
// inform while a restored table is reported, since the caps are read again
// after each apply (a driver country applied after the restart); the saved
// copy follows a change.
func (a *agent) fitRestored(ctx context.Context) {
	changed := false
	for _, band := range bands5GFirst() {
		r := a.scans.runner(band)
		if r == nil {
			continue
		}
		kept, dropped, err := r.FitRestored(ctx)
		key := "fit " + band
		switch {
		case err != nil:
			if a.specNoted[key] != err.Error() {
				a.logf("spectrum: restored %s table not checked against the radio's channels: %v (kept; retried at the next inform)", band, err)
				a.noteSpectrum(key, err.Error())
			}
		case dropped > 0 && kept == 0:
			a.logf("spectrum: restored %s table dropped: none of its %d row(s) is listed by the radio now", band, dropped)
			changed = true
		case dropped > 0:
			a.logf("spectrum: restored %s table: %d row(s) the radio does not list now dropped (%d kept)", band, dropped, kept)
			changed = true
		}
	}
	if changed {
		a.saveSpectrum()
	}
}

func (a *agent) noteSpectrum(band, s string) {
	if a.specNoted == nil {
		a.specNoted = map[string]string{}
	}
	a.specNoted[band] = s
}

// saveSpectrum writes the tables to flash when they changed (the band
// goroutine of a spectrum command, after a new good table or a clear).
func (a *agent) saveSpectrum() {
	if a.o.base == "" {
		return
	}
	sc := a.scans
	sc.saveMu.Lock()
	defer sc.saveMu.Unlock()
	s := sc.saveState(a.cfg.Model)
	if len(s.Bands) == 0 && sc.savedJSON == nil { // nothing saved, nothing to save
		return
	}
	b, err := json.Marshal(s)
	if err != nil || bytes.Equal(b, sc.savedJSON) {
		return
	}
	p := a.spectrumPath()
	tmp := p + ".tmp"
	err = os.MkdirAll(filepath.Dir(p), 0o700)
	if err == nil {
		err = os.WriteFile(tmp, b, 0o600)
	}
	if err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil {
		os.Remove(tmp)
		a.logf("spectrum: saving the tables to %s: %v (kept in memory; a restart would start without them)", p, err)
		return
	}
	sc.savedJSON = b
}

// loadSaved keeps the tables read at start until they are restored, and
// the file's bytes (savedJSON: what is on flash).
func (sc *scanner) loadSaved(tables map[string]*savedTable, file []byte) {
	sc.mu.Lock()
	sc.saved = tables
	sc.mu.Unlock()
	sc.saveMu.Lock()
	sc.savedJSON = file
	sc.saveMu.Unlock()
}

// savedBands lists the bands with a saved table not restored yet.
func (sc *scanner) savedBands() []string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if len(sc.saved) == 0 {
		return nil
	}
	out := make([]string, 0, len(sc.saved))
	for b := range sc.saved {
		out = append(out, b)
	}
	sort.Strings(out)
	return out
}

// runner is band's spectrum runner, once a command or a restore used it.
func (sc *scanner) runner(band string) *wl.SpectrumRunner {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.runners[band]
}

func (sc *scanner) savedTable(band string) *savedTable {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.saved[band]
}

// forgetSaved drops band's saved table if it is still t.
func (sc *scanner) forgetSaved(band string, t *savedTable) {
	sc.mu.Lock()
	if sc.saved[band] == t {
		delete(sc.saved, band)
	}
	sc.mu.Unlock()
}

// dropSaved forgets every table not restored yet: a spectrum-scan clears
// all tables first, saved ones included.
func (sc *scanner) dropSaved() {
	sc.mu.Lock()
	sc.saved = nil
	sc.mu.Unlock()
}

const (
	restoredGone  = iota // dropped meanwhile (a spectrum-scan cleared it)
	restoredOK           // in the runner, reported from now on
	restoredNewer        // the runner has a table measured since
)

// restore puts band's saved table t into r and keeps r for the informs.
func (sc *scanner) restore(band string, t *savedTable, r *wl.SpectrumRunner) int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.saved[band] != t {
		return restoredGone
	}
	delete(sc.saved, band)
	if !r.RestoreTable(t.Rows, t.Time) {
		return restoredNewer
	}
	sc.runners[band] = r
	return restoredOK
}

// saveState is what the file should hold: each runner's table, and the
// saved tables still waiting to be restored (held for the clock) for bands
// without one.
func (sc *scanner) saveState(model string) spectrumSave {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	s := spectrumSave{Version: spectrumVersion, Model: model, Bands: map[string]*savedTable{}}
	for band, t := range sc.saved {
		s.Bands[band] = t
	}
	for band, r := range sc.runners {
		st := r.Status()
		if len(st.Rows) == 0 || st.TableTime.IsZero() {
			continue
		}
		// measured (or restored) since: a held saved table is older
		delete(sc.saved, band)
		s.Bands[band] = &savedTable{Radio: st.Radio, Time: st.TableTime.UTC(), Rows: st.Rows}
	}
	return s
}
