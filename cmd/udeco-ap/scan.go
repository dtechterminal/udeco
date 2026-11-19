// SPDX-License-Identifier: GPL-2.0-or-later

package main

// RF scans for the controller's commands (docs/deco/spectrum-design.md §3,
// §7; docs/deco/spectrum-controller-expectations.md, CE):
//   - `cmd scan`: the neighbour scan (wl.Collector.Scan), reported per
//     radio_table row as scan_table only (CE §2.3, design §3.6);
//   - `cmd quick-scan` (nightly, one band per command) and `cmd
//     spectrum-scan` (manual, every width): the spectrum runner
//     (wl.SpectrumRunner, spectrum.go), reported per radio_table row as
//     spectrum_table (all nine keys of wl.SpectrumRow), spectrum_table_time
//     (age in seconds) and spectrum_scanning_abnormal, with the top-level
//     spectrum_scanning (true only while a spectrum-scan runs) and
//     quickscan_scanning (sent, true, only while a quick-scan runs).
//
// One scan of any kind runs at a time; a command that arrives meanwhile is
// skipped and logged, as mcad does ("[quick-scan] skipped: already in
// progress"). The neighbours a spectrum band hears refresh scan_table too.
//
// After every band with a table, the real AP's ubntquickscan sends
// EVT_AP_QuickScanEvent (mca-custom-alert.sh: event_string, radio,
// radio_name, channel, width, center_freq, interference, utilization).
// Network 11.1 stores spectrum results only on that event (it sets
// spectrum_scan_timestamp and saves radio_table_stats; Radio AI's prescan
// waits for that timestamp) or when a quickscan_scanning true -> false
// transition ends a quick-scan; a manual spectrum-scan has no such
// transition, so without the event its table lived only in the
// controller's memory, with no timestamp. The agent sends the event as the
// controller reads it (inform_as_notif, notif_reason "event",
// notif_payload) in the inform after the one that carried the band's new
// table, so the table the event saves is the new one.
//
// scan_table rows carry both key sets (docs/deco/spectrum-controller-
// expectations.md §7): the controller-documented ones (apstate.ScanTable:
// is_unifi and serialno for neighbours that are LAN devices, age in s) and
// the real U6 Pro's (is_ubnt, ap_name, noise, rssi_age). rssi follows the
// U6 Pro, verified on all 17 rows of its mca-dump: rssi = signal - noise,
// with noise = the radio's noise floor (wl noise via the collector), or -95
// when the collector has none, which gives the old signal + 95. rssi_age is
// age x 10 (the U6 Pro's pairs 15/151, 18/186: deciseconds, an inference).

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

// keepSeen: a neighbour missed by one scan stays listed this long.
const keepSeen = 10 * time.Minute

type scanner struct {
	mu      sync.Mutex
	running string // what runs ("" = nothing): one scan of any kind at a time
	quick   bool   // a quick-scan band runs (quickscan_scanning)
	manual  bool   // a spectrum-scan runs (spectrum_scanning)
	results map[string]apstate.ScanResult
	runners map[string]*wl.SpectrumRunner // by band, once a spectrum command used them
	events  []*scanEvent                  // EVT_AP_QuickScanEvent still to send, at most one per band
	saved   map[string]*savedTable        // tables saved before the restart, not restored yet (specsave.go)

	saveMu    sync.Mutex // one write of the saved tables at a time
	savedJSON []byte     // under saveMu: what the file on flash holds (nil = no file)
}

// scanEvent is the EVT_AP_QuickScanEvent of a band that ended with a table.
type scanEvent struct {
	band  string
	row   wl.SpectrumRow // the row the event carries (eventRow)
	stage int            // evQueued -> evOffered -> evDue
	sent  bool           // attached to the inform in flight
	stuck bool           // due, but the inform in flight has no radio_table name for its band
	tries int            // informs it went out with (or could not go out with) that got no good answer
}

const (
	evQueued  = iota // waiting for an inform that carries the band's table
	evOffered        // the inform in flight carries the table
	evDue            // that inform was answered: send the event next
)

// eventTries: an event whose inform got no good answer this often is dropped.
const eventTries = 3

func newScanner() *scanner {
	return &scanner{results: map[string]apstate.ScanResult{}, runners: map[string]*wl.SpectrumRunner{}}
}

// begin marks what as running; it returns what already runs instead (and
// changes nothing) when a scan is in progress.
func (sc *scanner) begin(what string, quick, manual bool) (busy string, ok bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.running != "" {
		return sc.running, false
	}
	sc.running, sc.quick, sc.manual = what, quick, manual
	return "", true
}

// busy reports whether a controller scan (neighbour, quick or spectrum)
// runs.
func (sc *scanner) busy() bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.running != ""
}

// end marks the running scan finished.
func (sc *scanner) end() {
	sc.mu.Lock()
	sc.running, sc.quick, sc.manual = "", false, false
	sc.mu.Unlock()
}

// addRunner keeps a band's spectrum runner for the informs.
func (sc *scanner) addRunner(band string, r *wl.SpectrumRunner) {
	sc.mu.Lock()
	sc.runners[band] = r
	sc.mu.Unlock()
}

// queueEvent queues band's EVT_AP_QuickScanEvent (replacing an older one).
func (sc *scanner) queueEvent(band string, row wl.SpectrumRow) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.events = slices.DeleteFunc(sc.events, func(e *scanEvent) bool { return e.band == band })
	sc.events = append(sc.events, &scanEvent{band: band, row: row})
}

// dropEvents forgets the events not sent yet (a spectrum-scan clears the
// tables they were about).
func (sc *scanner) dropEvents() {
	sc.mu.Lock()
	sc.events = nil
	sc.mu.Unlock()
}

// informed is told how the inform merge built went (good = answered). It
// moves the events on and reports whether one is now due (the loop then
// informs again at once) and which ones went out.
func (sc *scanner) informed(good bool) (due bool, sent []string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	keep := sc.events[:0]
	for _, e := range sc.events {
		switch {
		case e.stuck:
			// due but not attachable (its radio is missing from
			// radio_table): a try, so a radio that stays missing does
			// not keep the loop informing every immediateWait
			e.stuck = false
			if e.tries++; e.tries >= eventTries {
				continue
			}
		case e.sent:
			e.sent = false
			if good {
				sent = append(sent, fmt.Sprintf("%s ch %d/%d MHz", e.band, e.row.Channel, e.row.Width))
				continue
			}
			if e.tries++; e.tries >= eventTries {
				continue
			}
		case e.stage == evOffered && good:
			e.stage = evDue
		case e.stage == evOffered:
			e.stage = evQueued
		}
		due = due || e.stage == evDue
		keep = append(keep, e)
	}
	clear(sc.events[len(keep):])
	sc.events = keep
	return due, sent
}

// addBSS folds a scan's neighbour list into scan_table (KeepSeen).
func (sc *scanner) addBSS(band string, res apstate.ScanResult) {
	sc.mu.Lock()
	sc.results[band] = apstate.KeepSeen(sc.results[band], res, keepSeen)
	sc.mu.Unlock()
}

// neighbourScan is `cmd scan`: bands one after the other in the background,
// scan_table only; done runs when it finishes. A band starts only while
// blocked returns "" (agent.scanBlock). It returns false (and never calls
// done) when a scan is already running.
func (sc *scanner) neighbourScan(ctx context.Context, col collector, bands []string, perBand time.Duration,
	logf func(string, ...any), blocked func() string, done func()) (busy string, ok bool) {
	if busy, ok := sc.begin("scan", false, false); !ok {
		return busy, false
	}
	go func() {
		defer done()
		defer sc.end()
		for _, band := range bands {
			if why := blocked(); why != "" {
				logf("scan %s: not started, %s", band, why)
				return
			}
			bctx, cancel := context.WithTimeout(ctx, perBand)
			t0 := time.Now()
			res, err := col.Scan(bctx, band)
			cancel()
			if err != nil {
				logf("scan %s: %v", band, err)
				continue
			}
			// neighbours only: a legacy ScanResult.Spectrum is never
			// reported (spectrum_table comes from the spectrum runner)
			sc.addBSS(band, apstate.ScanResult{Band: res.Band, Time: res.Time, BSS: res.BSS})
			logf("scan %s: %d networks in %s", band, len(res.BSS), time.Since(t0).Round(100*time.Millisecond))
		}
	}()
	return "", true
}

// merge adds the scan state to the inform fields.
func (sc *scanner) merge(f map[string]any, s *apstate.Snapshot, info apstate.CfgInfo, now time.Time) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	f["spectrum_scanning"] = sc.manual
	if sc.quick {
		f["quickscan_scanning"] = true
	} else {
		delete(f, "quickscan_scanning") // the real AP omits it at rest (CE §5)
	}
	rows, _ := f["radio_table"].([]map[string]any)
	if len(rows) == 0 {
		sc.attachEvent(f, nil, nil) // a due event cannot go out with this inform
		return
	}
	own := map[string]bool{}
	for _, r := range s.Radios {
		if r.BSSID != "" {
			own[r.BSSID] = true
		}
		for _, v := range r.VAPs {
			own[v.BSSID] = true
		}
	}
	site := map[string]bool{}
	for ssid := range info.IDs {
		site[ssid] = true
	}
	noise := map[string]int{}
	for _, r := range s.Radios {
		if r.Noise < 0 {
			noise[r.Band] = r.Noise
		}
	}
	names, tables := map[string]string{}, map[string]bool{}
	for _, row := range rows {
		band, _ := row["radio"].(string)
		if name, _ := row["name"].(string); name != "" {
			names[band] = name
		}
		delete(row, "spectrum_table")
		delete(row, "spectrum_table_time")
		row["spectrum_scanning_abnormal"] = false
		if res, ok := sc.results[band]; ok {
			row["scan_table"] = u6ScanRows(apstate.ScanTable(res, now, own, site, s.ARP), noise[band])
		}
		r := sc.runners[band]
		if r == nil {
			continue
		}
		st := r.Status()
		row["spectrum_scanning_abnormal"] = st.Abnormal
		// absent until the first good scan, and after a manual scan
		// cleared it (design §7); a failed scan keeps the old table and
		// its growing age (CE §6)
		if table := spectrumRows(st.Rows); len(table) > 0 && !st.TableTime.IsZero() {
			row["spectrum_table"] = table
			row["spectrum_table_time"] = st.Age(now)
			tables[band] = true
		}
	}
	sc.attachEvent(f, names, tables)
}

// attachEvent moves a queued event to evOffered when this inform carries
// its band's table in a way the controller takes it, and makes this inform
// the notification of the first due event (one per inform). Network
// ignores an inform's spectrum_table while that same inform says
// quickscan_scanning (DRUVu: the cached quick-scan state is set from the
// inform before radio_table is read), so such an inform is no carrier.
func (sc *scanner) attachEvent(f map[string]any, names map[string]string, tables map[string]bool) {
	attached := false
	taken := f["quickscan_scanning"] != true
	for _, e := range sc.events {
		switch {
		case e.stage == evQueued && tables[e.band] && taken:
			e.stage = evOffered
		case e.stage == evDue && names[e.band] == "":
			e.stuck = true
		case e.stage == evDue && !attached:
			f["inform_as_notif"] = true
			f["notif_reason"] = "event"
			f["notif_payload"] = quickScanEvent(e.band, names[e.band], e.row)
			e.sent, attached = true, true
		}
	}
}

// quickScanEvent is ubntquickscan's mca-custom-alert payload (strings
// "event_string", "radio", "radio_name"; numbers for the rest).
func quickScanEvent(band, name string, r wl.SpectrumRow) map[string]any {
	return map[string]any{
		"event_string": "EVT_AP_QuickScanEvent", "radio": band, "radio_name": name,
		"channel": r.Channel, "width": r.Width, "center_freq": r.CenterFreq,
		"interference": r.Interference, "utilization": r.Utilization,
	}
}

// spectrumRows flattens a table by width (ascending) into inform rows with
// the nine keys a real AP sends (CE §3).
func spectrumRows(t map[int][]wl.SpectrumRow) []map[string]any {
	ws := make([]int, 0, len(t))
	for w := range t {
		ws = append(ws, w)
	}
	slices.Sort(ws)
	var out []map[string]any
	for _, w := range ws {
		for _, r := range t[w] {
			it := r.InterferenceType
			if it == nil {
				it = []string{}
			}
			out = append(out, map[string]any{
				"channel": r.Channel, "width": r.Width, "center_freq": r.CenterFreq,
				"total_samples": r.TotalSamples, "interference": r.Interference, "utilization": r.Utilization,
				"perf_index": r.PerfIndex, "interference_type": it, "other_bss_count": r.OtherBSS,
			})
		}
	}
	return out
}

// defaultNoise stands in for an unknown radio noise floor (dBm).
const defaultNoise = -95

// u6ScanRows adds the U6 Pro's scan_table keys and its rssi convention to
// apstate.ScanTable rows (noise 0 = unknown).
func u6ScanRows(rows []map[string]any, noise int) []map[string]any {
	if noise >= 0 {
		noise = defaultNoise
	}
	for _, r := range rows {
		sig, _ := r["signal"].(int)
		age, _ := r["age"].(int)
		uni, _ := r["is_unifi"].(bool)
		r["is_ubnt"] = uni
		r["ap_name"] = ""
		r["noise"] = noise
		r["rssi"] = max(0, sig-noise)
		r["rssi_age"] = age * 10
	}
	return rows
}
