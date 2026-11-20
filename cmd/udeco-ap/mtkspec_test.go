// SPDX-License-Identifier: GPL-2.0-or-later

package main

// jio-mtk with site_survey: the MT7603's off-channel sweep is the 2.4 GHz
// band's spectrum runner (mtkwifi offchan.go), run and reported as the
// Deco's; 5 GHz keeps the neighbour survey (sitesurvey.go).

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/wl"
)

// sweepBackend stands in for the MT7603 sweep: 2.4 GHz rows 1..11 at 20
// MHz and 1..7 at 40; hold, when set, keeps the band running until closed.
type sweepBackend struct {
	mu     sync.Mutex
	runs   int
	widths [][]int
	hold   chan struct{}
	rec    *recorder
}

func (b *sweepBackend) Measure(ctx context.Context, req wl.SpectrumRequest, phase func(wl.SpectrumPhase)) (map[int][]wl.SpectrumRow, wl.SpectrumDiag, error) {
	b.rec.add("sweep:ng")
	b.mu.Lock()
	b.runs++
	b.widths = append(b.widths, req.Widths)
	hold := b.hold
	b.mu.Unlock()
	phase(wl.PhaseScanning)
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, wl.SpectrumDiag{}, ctx.Err()
		}
	}
	if err := req.Guard(ctx, wl.ScanStep{Radio: "ra0", Mode: "offchan", Call: 1, Channel: 1}); err != nil {
		return nil, wl.SpectrumDiag{}, err
	}
	rows := map[int][]wl.SpectrumRow{}
	d := wl.SpectrumDiag{Mode: "offchan", HomeControl: 6, HomeWidth: 20}
	for _, w := range req.Widths {
		w = wl.ClampWidth(w, []int{20, 40})
		if rows[w] != nil {
			continue
		}
		d.Widths = append(d.Widths, w)
		n, off := 11, 0
		if w == 40 {
			n, off = 7, 10
		}
		for ch := 1; ch <= n; ch++ {
			rows[w] = append(rows[w], wl.SpectrumRow{Channel: ch, Width: w, CenterFreq: 2407 + 5*ch + off,
				Utilization: 2 * ch, Interference: -90 + ch, InterferenceType: []string{}})
		}
	}
	return rows, d, nil
}

func (b *sweepBackend) Listed(context.Context) ([]wl.SpectrumBlock, error) {
	var out []wl.SpectrumBlock
	for ch := 1; ch <= 11; ch++ {
		out = append(out, wl.SpectrumBlock{Channel: ch, Width: 20, CenterFreq: 2407 + 5*ch})
	}
	return out, nil
}

// mtkCol is the jio-mtk collector with site_survey: a runner on ng (the
// sweep), the survey on na.
type mtkCol struct {
	surveyCol
	ng *wl.SpectrumRunner
}

func (c mtkCol) Spectrum(ctx context.Context, band string) (*wl.SpectrumRunner, error) {
	if band == "ng" {
		return c.ng, nil
	}
	c.rec.add("spectrum:" + band)
	return nil, errors.New("mtkwifi: not supported on this unit")
}

func (c mtkCol) SpectrumBySurvey(band string) (noRunner, bySurvey bool) {
	return band != "ng", band != "ng"
}

func mtkHarness(t *testing.T, before ...func(root string)) (*harness, *sweepBackend) {
	t.Helper()
	b := &sweepBackend{}
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Platform, c.Model, c.SiteSurvey = true, PlatformJio, "U7LT", true
		fc := o.col.(*fakeCol)
		b.rec = fc.rec
		o.col = mtkCol{surveyCol: surveyCol{fakeCol: fc, on: true}, ng: wl.NewSpectrumRunner("ra0", "ng", b)}
		for _, f := range before {
			f(o.root) // ahead of the agent's start (setup loads the saved tables)
		}
	})
	return h, b
}

// event is the EVT_AP_QuickScanEvent payload of an inform, nil if none.
func eventOf(m map[string]any) map[string]any {
	if m["inform_as_notif"] != true {
		return nil
	}
	p, _ := m["notif_payload"].(map[string]any)
	return p
}

// A quick-scan of 2.4 GHz runs the sweep as the Deco's runner: the
// controller's flag held while it runs, the band's table at the asked
// width, EVT_AP_QuickScanEvent, and the table saved on flash.
func TestMTKQuickScanSweep(t *testing.T) {
	h, b := mtkHarness(t)
	b.hold = make(chan struct{})
	h.ctl.queue(adoptReply, `{"_type":"cmd","cmd":"quick-scan","scan-band":0,"scan-bw":40}`)
	h.start()
	eventually(t, "the sweep running", func() bool { return h.rec.count("sweep:ng") == 1 })
	n := h.ctl.count()
	eventually(t, "informs while it runs", func() bool { return h.ctl.count() > n+1 })
	if m := h.ctl.last(); m["quickscan_scanning"] != true || m["spectrum_scanning"] == true {
		t.Errorf("while the sweep runs: quickscan_scanning %v spectrum_scanning %v", m["quickscan_scanning"], m["spectrum_scanning"])
	}
	close(b.hold)
	var ev map[string]any
	eventually(t, "the event", func() bool {
		for _, m := range h.ctl.all() {
			if p := eventOf(m); p != nil {
				ev = p
				return true
			}
		}
		return false
	})
	h.stop()
	if ev["radio"] != "ng" || ev["event_string"] != "EVT_AP_QuickScanEvent" || num(ev["width"]) != 40 {
		t.Errorf("event %v", ev)
	}
	var table []any
	for _, m := range h.ctl.all() {
		if m["radio_table"] == nil {
			continue
		}
		if tb, ok := radioRow(t, m, "ng")["spectrum_table"].([]any); ok {
			table = tb
		}
	}
	if len(table) != 7 || num(table[0].(map[string]any)["width"]) != 40 {
		t.Errorf("ng spectrum_table %v", table)
	}
	raw, err := os.ReadFile(savedFilePath(h.root))
	if err != nil {
		t.Fatalf("not saved on flash: %v", err)
	}
	var s spectrumSave
	if err := json.Unmarshal(raw, &s); err != nil || s.Bands["ng"] == nil || s.Bands["ng"].Radio != "ra0" || len(s.Bands["ng"].Rows[40]) != 7 {
		t.Errorf("saved %s (%v)", raw, err)
	}
	if h.rec.count("scan:ng") != 0 {
		t.Error("the 2.4 GHz quick-scan ran the neighbour survey as well")
	}
}

// A quick-scan of 5 GHz (no runner on the MT7663) keeps the survey.
func TestMTKQuickScanFiveGHzSurvey(t *testing.T) {
	h, b := mtkHarness(t)
	h.ctl.queue(adoptReply, `{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":80}`)
	h.start()
	eventually(t, "the na survey", func() bool { return surveyed(t, h) && !h.a.scans.busy() })
	h.stop()
	if b.runs != 0 || h.rec.count("scan:na") != 1 {
		t.Errorf("sweeps %d, calls %v", b.runs, h.rec.list())
	}
	if !strings.Contains(h.logs.all(), "quick-scan: no spectrum runner on this unit: neighbour site survey of [na]") {
		t.Errorf("log %q", h.logs.all())
	}
}

// The Environment page's spectrum-scan: the tables cleared first,
// spectrum_scanning while it runs, the 5 GHz survey, then the 2.4 GHz
// sweep at every width; the ng table and its event, no na table.
func TestMTKSpectrumScan(t *testing.T) {
	h, b := mtkHarness(t)
	b.hold = make(chan struct{})
	h.ctl.queue(adoptReply, `{"_type":"cmd","cmd":"spectrum-scan","spectrum-cfg":"","infinite":false}`)
	h.start()
	eventually(t, "the sweep running", func() bool { return h.rec.count("sweep:ng") == 1 })
	n := h.ctl.count()
	eventually(t, "informs while it runs", func() bool { return h.ctl.count() > n+1 })
	if m := h.ctl.last(); m["spectrum_scanning"] != true {
		t.Errorf("spectrum_scanning %v while the spectrum-scan runs", m["spectrum_scanning"])
	}
	close(b.hold)
	eventually(t, "the event", func() bool {
		for _, m := range h.ctl.all() {
			if eventOf(m) != nil {
				return true
			}
		}
		return false
	})
	eventually(t, "the scan ended", func() bool { return !h.a.scans.busy() && h.ctl.last()["spectrum_scanning"] == false })
	h.stop()
	calls := strings.Join(h.rec.list(), " ")
	if i, j := strings.Index(calls, "scan:na"), strings.Index(calls, "sweep:ng"); i < 0 || j < 0 || i > j {
		t.Errorf("order: %s", calls)
	}
	if len(b.widths) != 1 || len(b.widths[0]) != 3 {
		t.Errorf("sweep widths %v, want all (20, 40, 80)", b.widths)
	}
	m := h.ctl.last()
	ng, _ := radioRow(t, m, "ng")["spectrum_table"].([]any)
	if len(ng) != 18 {
		t.Errorf("ng table %d rows, want 11 + 7", len(ng))
	}
	if _, ok := radioRow(t, m, "na")["spectrum_table"]; ok {
		t.Error("na has a spectrum_table")
	}
	if !surveyed(t, h) {
		t.Error("na survey not reported")
	}
}

// The saved 2.4 GHz table comes back after a restart on jio-mtk too.
func TestMTKSpectrumRestored(t *testing.T) {
	at := time.Now().Add(-time.Hour).UTC()
	h, _ := mtkHarness(t, func(root string) {
		writeSaved(t, root, map[string]any{"version": 1, "model": "U7LT", "bands": map[string]any{
			"ng": map[string]any{"radio": "ra0", "time": at.Format(time.RFC3339Nano), "rows": map[string]any{
				"20": []map[string]any{{"channel": 1, "width": 20, "center_freq": 2412, "total_samples": 0, "interference": -70,
					"utilization": 12, "perf_index": 0, "interference_type": []string{}, "other_bss_count": 0}}}},
			// a 5 GHz table (saved by another layout): no runner, dropped
			"na": savedNA("U7LT", "rai0", at)["bands"].(map[string]any)["na"]}})
	})
	h.ctl.queue(adoptReply)
	h.start()
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(h.logs.all())
		}
	})
	eventually(t, "the restored ng table", func() bool {
		m := h.ctl.last()
		if m == nil || m["radio_table"] == nil {
			return false
		}
		tb, _ := radioRow(t, m, "ng")["spectrum_table"].([]any)
		return len(tb) == 1
	})
	h.stop()
	if !strings.Contains(h.logs.all(), "saved na table dropped: this unit has no spectrum runner") {
		t.Errorf("na table not dropped: %q", h.logs.all())
	}
}
