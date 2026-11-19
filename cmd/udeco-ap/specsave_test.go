// SPDX-License-Identifier: GPL-2.0-or-later

package main

// The last good spectrum table per band survives an agent restart and a
// reboot (specsave.go): saved under the state directory when it changes,
// restored at start and reported as a live table, checked first.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

// savedFilePath is the saved tables' file on the test unit.
func savedFilePath(root string) string {
	return filepath.Join(root, "tp_data/udeco", wifiStateSub, spectrumFile)
}

// writeSaved writes a saved-tables file (v is marshalled unless a string).
func writeSaved(t *testing.T, root string, v any) {
	t.Helper()
	b, ok := v.(string)
	if !ok {
		j, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		b = string(j)
	}
	p := savedFilePath(root)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
		t.Fatal(err)
	}
}

// savedNA is a saved file with one 5 GHz table (wl1, two 80 MHz rows)
// measured at at.
func savedNA(model, radio string, at time.Time) map[string]any {
	return map[string]any{"version": 1, "model": model, "bands": map[string]any{
		"na": map[string]any{"radio": radio, "time": at.UTC().Format(time.RFC3339Nano), "rows": map[string]any{
			"80": []map[string]any{
				{"channel": 36, "width": 80, "center_freq": 5210, "total_samples": 0, "interference": -81, "utilization": 12,
					"perf_index": 0, "interference_type": []string{}, "other_bss_count": 0},
				{"channel": 149, "width": 80, "center_freq": 5775, "total_samples": 0, "interference": -88, "utilization": 3,
					"perf_index": 0, "interference_type": []string{}, "other_bss_count": 0},
			}}}}}
}

// informRows is a bare inform's radio_table for merge.
func informRows() map[string]any {
	return map[string]any{"radio_table": []map[string]any{{"radio": "ng", "name": "wifi0"}, {"radio": "na", "name": "wifi1"}}}
}

func mergedRow(f map[string]any, band string) map[string]any {
	for _, r := range f["radio_table"].([]map[string]any) {
		if r["radio"] == band {
			return r
		}
	}
	return nil
}

// TestSpectrumRestoreChecks: a good saved table comes back as a live one
// (rows as saved, spectrum_table_time = the true age from its saved time);
// one older than 7 days, from another model or radio layout, with a row
// outside its band, of another version, or unparsable is dropped; one from
// the future (the clock not set yet) is held until the clock has passed it.
func TestSpectrumRestoreChecks(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name string
		file any
		want bool   // restored
		log  string // in the log
	}{
		{"good", savedNA("UAL6", "wl1", now.Add(-2*time.Hour)), true, "spectrum: restored the na table"},
		{"older than 7 days", savedNA("UAL6", "wl1", now.Add(-8*24*time.Hour)), false, "older than 7 days"},
		{"another model", savedNA("UAL5", "wl1", now.Add(-time.Hour)), false, "another model"},
		{"another radio layout", savedNA("UAL6", "wl0", now.Add(-time.Hour)), false, "radio wl0, the unit's is wl1"},
		{"row outside the band", func() any {
			m := savedNA("UAL6", "wl1", now.Add(-time.Hour))
			m["bands"].(map[string]any)["na"].(map[string]any)["rows"].(map[string]any)["80"].([]map[string]any)[0]["center_freq"] = 2412
			return m
		}(), false, "not a na row"},
		{"another version", func() any { m := savedNA("UAL6", "wl1", now.Add(-time.Hour)); m["version"] = 2; return m }(), false, "version 2"},
		{"unparsable", `{"version":1,"bands":`, false, "unparsable"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, _ := u6proSystemCfg(t)
			e := newE2E(t, cfg, true)
			writeSaved(t, e.unit.root, c.file)
			e.a.loadSpectrum()
			e.a.restoreSpectrum(context.Background(), now)
			f := informRows()
			e.a.scans.merge(f, &apstate.Snapshot{}, apstate.CfgInfo{}, now)
			na := mergedRow(f, "na")
			table, _ := na["spectrum_table"].([]map[string]any)
			if got := len(table) > 0; got != c.want {
				t.Fatalf("restored %v, want %v (row %v)", got, c.want, na)
			}
			if c.want {
				if len(table) != 2 || table[0]["channel"] != 36 || table[0]["utilization"] != 12 || table[1]["interference"] != -88 {
					t.Errorf("rows %v", table)
				}
				if age, _ := na["spectrum_table_time"].(int); age < 7200 || age > 7205 {
					t.Errorf("spectrum_table_time %v, want the 2 h since it was measured", na["spectrum_table_time"])
				}
				if _, ok := mergedRow(f, "ng")["spectrum_table"]; ok {
					t.Error("a 2.4 GHz table nobody saved")
				}
			}
			if logs := e.logs.all(); !strings.Contains(logs, c.log) {
				t.Errorf("log lacks %q:\n%s", c.log, logs)
			}
			// no event for a restored table: it was not measured now
			if f["inform_as_notif"] != nil || len(e.a.scans.events) != 0 {
				t.Errorf("an event for a restored table: %v %v", f["notif_payload"], e.a.scans.events)
			}
		})
	}

	t.Run("future: held until the clock passes it", func(t *testing.T) {
		cfg, _ := u6proSystemCfg(t)
		e := newE2E(t, cfg, true)
		at := now.Add(time.Hour)
		writeSaved(t, e.unit.root, savedNA("UAL6", "wl1", at))
		e.a.loadSpectrum()
		for range 3 { // every inform re-checks; logged once
			e.a.restoreSpectrum(context.Background(), now)
		}
		f := informRows()
		e.a.scans.merge(f, &apstate.Snapshot{}, apstate.CfgInfo{}, now)
		if _, ok := mergedRow(f, "na")["spectrum_table"]; ok {
			t.Fatal("a table from the future was reported")
		}
		if n := strings.Count(e.logs.all(), "held until the clock"); n != 1 {
			t.Errorf("%d hold logs, want 1:\n%s", n, e.logs.all())
		}
		// the clock is set: 2 h later than the boot clock, 1 h after the table
		later := now.Add(2 * time.Hour)
		e.a.restoreSpectrum(context.Background(), later)
		f = informRows()
		e.a.scans.merge(f, &apstate.Snapshot{}, apstate.CfgInfo{}, later)
		if age, _ := mergedRow(f, "na")["spectrum_table_time"].(int); len(tableOf2(f, "na")) != 2 || age < 3600 || age > 3605 {
			t.Errorf("after the clock was set: row %v", mergedRow(f, "na"))
		}
	})
}

func tableOf2(f map[string]any, band string) []map[string]any {
	t, _ := mergedRow(f, band)["spectrum_table"].([]map[string]any)
	return t
}

// TestSpectrumSaveOnChange: the file is written when a band's table
// changes and not otherwise (flash); a cleared table leaves the file; a
// band held for the clock stays in the file when another band is saved.
func TestSpectrumSaveOnChange(t *testing.T) {
	cfg, _ := u6proSystemCfg(t)
	e := newE2E(t, cfg, true)
	now := time.Now()
	// 5 GHz held: saved with a clock ahead of this one
	ahead := now.Add(time.Hour)
	writeSaved(t, e.unit.root, savedNA("UAL6", "wl1", ahead))
	e.a.loadSpectrum()
	e.a.restoreSpectrum(context.Background(), now)

	r, err := e.a.o.col.Spectrum(context.Background(), "ng")
	if err != nil {
		t.Fatal(err)
	}
	at := now.Add(-time.Minute)
	if !r.RestoreTable(map[int][]wl.SpectrumRow{20: {{Channel: 1, Width: 20, CenterFreq: 2412, Utilization: 4, Interference: -90}}}, at) {
		t.Fatal("no table")
	}
	e.a.scans.addRunner("ng", r)
	e.a.saveSpectrum()

	p := savedFilePath(e.unit.root)
	read := func() (v struct {
		Version int    `json:"version"`
		Model   string `json:"model"`
		Bands   map[string]struct {
			Radio string                   `json:"radio"`
			Time  time.Time                `json:"time"`
			Rows  map[int][]wl.SpectrumRow `json:"rows"`
		} `json:"bands"`
	}) {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("%v: %s", err, b)
		}
		return v
	}
	v := read()
	if v.Version != 1 || v.Model != "UAL6" || len(v.Bands) != 2 || v.Bands["ng"].Radio != "wl0" ||
		!v.Bands["ng"].Time.Equal(at) || v.Bands["ng"].Rows[20][0].Utilization != 4 ||
		v.Bands["na"].Radio != "wl1" || !v.Bands["na"].Time.Equal(ahead) {
		t.Fatalf("saved %+v", v)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v %v", st.Mode(), err)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp file left: %v", err)
	}

	// unchanged: not written again
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	os.Chtimes(p, old, old)
	e.a.saveSpectrum()
	if st, _ := os.Stat(p); !st.ModTime().Equal(old) {
		t.Error("the file was rewritten without a change")
	}

	// a spectrum-scan clears every table (and what was held): the saved
	// copy follows
	e.a.scans.dropSaved()
	r.ClearTable()
	e.a.saveSpectrum()
	if v := read(); len(v.Bands) != 0 {
		t.Errorf("after the clear: %+v", v.Bands)
	}
	// and the held table is not restored any more
	e.a.restoreSpectrum(context.Background(), ahead.Add(time.Minute))
	if na, err := e.a.o.col.Spectrum(context.Background(), "na"); err != nil || na.Status().Rows != nil {
		t.Errorf("the cleared held table came back: %v %v", na.Status().Rows, err)
	}
}

// TestSpectrumRestoreNoOp: jio-mtk has no spectrum runners and observe mode
// runs no scans: neither reads, restores nor writes the saved tables.
func TestSpectrumRestoreNoOp(t *testing.T) {
	for _, c := range []struct {
		name string
		mod  func(*Config, *options)
	}{
		{"jio-mtk", func(c *Config, o *options) { c.Platform, c.Model, c.Takeover = PlatformJio, "U7LT", true }},
		{"observe", func(c *Config, o *options) { c.Takeover = false }},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, c.mod)
			want := savedNA(h.cfg.Model, "wl1", time.Now().Add(-time.Hour))
			writeSaved(t, h.root, want)
			before, _ := os.ReadFile(savedFilePath(h.root))
			h.start()
			eventually(t, "a few informs", func() bool { return h.ctl.count() >= 3 })
			h.stop()
			if h.rec.index("spectrum:na") >= 0 || h.rec.index("spectrum:ng") >= 0 {
				t.Errorf("spectrum runners asked for: %v", h.rec.list())
			}
			if after, _ := os.ReadFile(savedFilePath(h.root)); string(after) != string(before) {
				t.Errorf("file changed: %s", after)
			}
			if logs := h.logs.all(); strings.Contains(logs, "spectrum: ") {
				t.Errorf("spectrum restore logged:\n%s", logs)
			}
			if m := h.ctl.last(); tableOf(m, "na") != nil {
				t.Errorf("a table reported: %v", tableOf(m, "na"))
			}
		})
	}
}
