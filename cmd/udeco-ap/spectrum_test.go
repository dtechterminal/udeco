// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/models"
	"github.com/dtechterminal/udeco/internal/wl"
)

// spectrumKeys are the nine keys of every real spectrum_table row (CE §3).
var spectrumKeys = []string{"center_freq", "channel", "interference", "interference_type", "other_bss_count",
	"perf_index", "total_samples", "utilization", "width"}

func TestSpectrumRowsNineKeys(t *testing.T) {
	rows := spectrumRows(map[int][]wl.SpectrumRow{
		80: {{Channel: 36, Width: 80, CenterFreq: 5210, Utilization: 5, Interference: -72}},
		20: {{Channel: 36, Width: 20, CenterFreq: 5180, Utilization: 2, Interference: -78}},
	})
	if len(rows) != 2 || rows[0]["width"] != 20 || rows[1]["width"] != 80 {
		t.Fatalf("rows %v", rows)
	}
	for _, r := range rows {
		var keys []string
		for k := range r {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if !slices.Equal(keys, spectrumKeys) {
			t.Errorf("keys %v", keys)
		}
		if it, ok := r["interference_type"].([]string); !ok || it == nil {
			t.Errorf("interference_type %#v, want []", r["interference_type"])
		}
	}
}

// The health check waits for a running scan (WithoutScan) for at least
// 120 s by default; a wait that runs out is not a failed check: no
// rollback however long the scans last, and checks resume after.
func TestHealthWaitsForScan(t *testing.T) {
	var def timing
	def.fill()
	if def.healthWait < 120*time.Second || def.spectrumTO < 105*time.Second {
		t.Errorf("health wait %v, spectrum band %v", def.healthWait, def.spectrumTO)
	}
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		o.t.enforceEvery = 5 * time.Millisecond
		o.t.healthWait = 5 * time.Millisecond
	})
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	eventually(t, "apply and a health check", func() bool { return h.rec.index("apply") >= 0 && h.rec.count("verify") > 0 })
	h.col.mu.Lock()
	h.col.scanBusy = true
	h.col.mu.Unlock()
	h.wifi.mu.Lock()
	h.wifi.verify = &bcmwifi.VerifyError{Problems: []string{"would fail if it ran"}}
	h.wifi.mu.Unlock()
	n := h.rec.count("verify")
	eventually(t, "several skipped checks", func() bool { return h.rec.count("withoutscan:busy") >= 4 })
	if h.rec.count("verify") > n+1 || h.rec.index("rollback") >= 0 {
		t.Fatalf("checked or rolled back while a scan ran: %v", h.rec.list())
	}
	if !strings.Contains(h.logs.all(), "health check skipped: a scan was still running") {
		t.Error("no log of the skipped check")
	}
	h.wifi.mu.Lock()
	h.wifi.verify = nil
	h.wifi.mu.Unlock()
	h.col.mu.Lock()
	h.col.scanBusy = false
	h.col.mu.Unlock()
	m := h.rec.count("verify")
	eventually(t, "checks resume", func() bool { return h.rec.count("verify") > m })
	h.stop()
	if h.rec.index("rollback") >= 0 || !h.a.takeover.Load() {
		t.Errorf("rolled back: %v", h.rec.list())
	}
}

// A quick-scan for a band the unit lacks scans nothing and touches no
// table.
func TestQuickScan6GHz(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover = true })
	h.ctl.queue(adoptReply, `{"_type":"cmd","cmd":"quick-scan","scan-band":2,"scan-bw":160}`)
	h.start()
	eventually(t, "6 GHz refused", func() bool { return strings.Contains(h.logs.all(), "no 6 GHz radio") })
	h.stop()
	if h.rec.index("spectrum:6e") >= 0 {
		t.Errorf("6 GHz scanned: %v", h.rec.list())
	}
}

// A drop to observe (hand-back) stops the scans, so the next informs no
// longer claim RF_SCAN (wifi_caps bit 4); takeover claimed it. The same
// holds for every other bit that needs the agent to own Wi-Fi.
func TestDropToObserveClearsRFScan(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover = true })
	h.start()
	eventually(t, "RF_SCAN claimed in takeover", func() bool {
		m := h.ctl.last()
		return m != nil && int(num(m["wifi_caps"]))&models.WifiCapRFScan != 0
	})
	// the other takeover features too (they need the agent to own Wi-Fi)
	if m := h.ctl.last(); int(num(m["wifi_caps"]))&(models.WifiCapLockAP|models.WifiCapWPAPSKFile) == 0 ||
		int(num(m["fw_caps"]))&models.FWCapRadiusFilter == 0 || int(num(m["fw3_caps"]))&models.FW3CapMulticastInspect == 0 {
		t.Errorf("takeover features not claimed: wifi %v fw %v fw3 %v", m["wifi_caps"], m["fw_caps"], m["fw3_caps"])
	}
	h.a.submit("drop", func(ctx context.Context) { h.a.dropToObserve(ctx, "test") })
	eventually(t, "RF_SCAN no longer claimed", func() bool {
		m := h.ctl.last()
		return m != nil && int(num(m["wifi_caps"]))&models.WifiCapRFScan == 0
	})
	h.stop()
	m := h.ctl.last()
	if int(num(m["wifi_caps"]))&models.DecoAgentTakeoverWifiCaps != 0 || m["wifi_caps2"] != nil ||
		int(num(m["fw_caps"]))&models.DecoAgentTakeoverFWCaps != 0 || int(num(m["fw3_caps"]))&models.DecoAgentTakeoverFW3Caps != 0 {
		t.Errorf("takeover bits still claimed in observe: wifi %v wifi2 %v fw %v fw3 %v", m["wifi_caps"], m["wifi_caps2"], m["fw_caps"], m["fw3_caps"])
	}
	// what works in both modes stays
	if int(num(m["fw_caps"]))&models.FWCapSyslogEncryption == 0 || int(num(m["fw3_caps"]))&models.FW3CapPathMonitoring == 0 {
		t.Errorf("both-mode bits dropped: fw %v fw3 %v", m["fw_caps"], m["fw3_caps"])
	}
	if h.a.takeover.Load() {
		t.Error("still in takeover")
	}
}

// TestEventRow: the event names the block of the radio's own channel at the
// widest measured width up to the operating one, always a row of the table.
func TestEventRow(t *testing.T) {
	row := func(ch, w, cf int) wl.SpectrumRow { return wl.SpectrumRow{Channel: ch, Width: w, CenterFreq: cf} }
	manual := map[int][]wl.SpectrumRow{ // .205 under IN after the DFS fix: home 40u
		20: {row(36, 20, 5180), row(40, 20, 5200), row(44, 20, 5220), row(48, 20, 5240)},
		40: {row(36, 40, 5190), row(44, 40, 5230)},
	}
	for _, c := range []struct {
		name          string
		rows          map[int][]wl.SpectrumRow
		ctl, width    int
		wantCh, wantW int
	}{
		{"home 40u: its 40 MHz block", manual, 40, 40, 36, 40},
		{"home 44/80, table up to 40", manual, 44, 80, 44, 40},
		{"home 40 at 20 MHz", manual, 40, 20, 40, 20},
		{"quick-scan 80 only", map[int][]wl.SpectrumRow{80: {row(36, 80, 5210), row(149, 80, 5775)}}, 44, 80, 36, 80},
		{"home 9u, 2.4 GHz 20 MHz rows", map[int][]wl.SpectrumRow{20: {row(1, 20, 2412), row(9, 20, 2452)}}, 9, 40, 9, 20},
		{"home 9u, 40 MHz block 5", map[int][]wl.SpectrumRow{20: {row(9, 20, 2452)}, 40: {row(1, 40, 2422), row(5, 40, 2442)}}, 9, 40, 5, 40},
		{"home channel without a row", map[int][]wl.SpectrumRow{20: {row(36, 20, 5180)}, 40: {row(36, 40, 5190)}}, 149, 80, 36, 20},
	} {
		got, ok := eventRow(c.rows, c.ctl, c.width)
		if !ok || got.Channel != c.wantCh || got.Width != c.wantW {
			t.Errorf("%s: %+v %v, want %d/%d", c.name, got, ok, c.wantCh, c.wantW)
		}
	}
	if _, ok := eventRow(map[int][]wl.SpectrumRow{20: nil}, 36, 20); ok {
		t.Error("an event without rows")
	}
}

// TestScanEventStages: an event goes out in the inform after one that
// carried its band's table and was answered; an unanswered carrier is
// redone; an unanswered event is sent again, at most eventTries times; one
// event per inform; a newer band's event replaces an older unsent one.
func TestScanEventStages(t *testing.T) {
	sc := newScanner()
	names := map[string]string{"na": "wifi1", "ng": "wifi0"}
	inform := func(tables ...string) map[string]any {
		f := map[string]any{}
		tb := map[string]bool{}
		for _, b := range tables {
			tb[b] = true
		}
		sc.mu.Lock()
		sc.attachEvent(f, names, tb)
		sc.mu.Unlock()
		return f
	}
	sc.queueEvent("na", wl.SpectrumRow{Channel: 36, Width: 80, CenterFreq: 5210, Utilization: 4, Interference: -72})
	if f := inform(); f["inform_as_notif"] != nil {
		t.Fatal("event before any inform carried the table")
	}
	if due, _ := sc.informed(true); due {
		t.Fatal("due without a carried table")
	}
	inform("na")
	if due, _ := sc.informed(false); due { // the carrier got no answer
		t.Fatal("due after an unanswered carrier")
	}
	inform("na")
	if due, _ := sc.informed(true); !due {
		t.Fatal("not due after an answered carrier")
	}
	f := inform("na")
	p, _ := f["notif_payload"].(map[string]any)
	if f["inform_as_notif"] != true || f["notif_reason"] != "event" || p["radio_name"] != "wifi1" || p["channel"] != 36 || p["center_freq"] != 5210 {
		t.Fatalf("event inform %v", f)
	}
	// unanswered: sent again, then dropped after eventTries
	for i := 1; i < eventTries; i++ {
		if due, sent := sc.informed(false); !due || len(sent) != 0 {
			t.Fatalf("try %d: due %v sent %v", i, due, sent)
		}
		if f := inform("na"); f["inform_as_notif"] != true {
			t.Fatalf("try %d: not resent", i)
		}
	}
	if due, _ := sc.informed(false); due || len(sc.events) != 0 {
		t.Fatalf("kept after %d unanswered tries: %d events", eventTries, len(sc.events))
	}
	// two due events: one per inform; the answer removes the one sent
	sc.queueEvent("na", wl.SpectrumRow{Channel: 36, Width: 20})
	sc.queueEvent("ng", wl.SpectrumRow{Channel: 6, Width: 20})
	sc.queueEvent("ng", wl.SpectrumRow{Channel: 9, Width: 20}) // replaces ch 6
	inform("na", "ng")
	sc.informed(true)
	f1 := inform("na", "ng")
	if _, sent := sc.informed(true); len(sent) != 1 || sent[0] != "na ch 36/20 MHz" {
		t.Fatalf("first sent %v", sent)
	}
	f2 := inform("na", "ng")
	due, sent := sc.informed(true)
	if due || len(sent) != 1 || sent[0] != "ng ch 9/20 MHz" || f1["notif_payload"].(map[string]any)["radio"] != "na" || f2["notif_payload"].(map[string]any)["radio"] != "ng" {
		t.Fatalf("second: due %v sent %v", due, sent)
	}
	// a spectrum-scan drops what was not sent
	sc.queueEvent("na", wl.SpectrumRow{Channel: 36, Width: 20})
	sc.dropEvents()
	inform("na")
	if due, _ := sc.informed(true); due {
		t.Fatal("a dropped event became due")
	}
}

// TestScanEventNotOfferedWhileQuickScanning: Network ignores an inform's
// spectrum_table while that inform says quickscan_scanning (DRUVu: the
// cached quick-scan state is set from the inform before radio_table is
// read), so such an inform does not count as the one that carried the
// band's table; the event waits for one the controller takes.
func TestScanEventNotOfferedWhileQuickScanning(t *testing.T) {
	sc := newScanner()
	names := map[string]string{"na": "wifi1"}
	sc.queueEvent("na", wl.SpectrumRow{Channel: 36, Width: 80})
	f := map[string]any{"quickscan_scanning": true}
	sc.mu.Lock()
	sc.attachEvent(f, names, map[string]bool{"na": true})
	sc.mu.Unlock()
	if due, _ := sc.informed(true); due {
		t.Fatal("due after a carrier the controller ignores (quickscan_scanning true)")
	}
	f = map[string]any{}
	sc.mu.Lock()
	sc.attachEvent(f, names, map[string]bool{"na": true})
	sc.mu.Unlock()
	if due, _ := sc.informed(true); !due {
		t.Fatal("not due after a carrier the controller takes")
	}
}

// TestScanEventWithoutRadioRowIsDropped: a due event whose band has no
// radio_table name (or an inform with no radio_table at all) cannot be
// attached; it must not keep the loop informing every immediateWait
// forever: it counts as a try and is dropped after eventTries.
func TestScanEventWithoutRadioRowIsDropped(t *testing.T) {
	sc := newScanner()
	sc.queueEvent("na", wl.SpectrumRow{Channel: 36, Width: 20})
	sc.mu.Lock()
	sc.attachEvent(map[string]any{}, map[string]string{"na": "wifi1"}, map[string]bool{"na": true})
	sc.mu.Unlock()
	if due, _ := sc.informed(true); !due {
		t.Fatal("not due")
	}
	for i := 0; i < 10; i++ {
		f := map[string]any{} // no radio_table: merge returns early
		if i%2 == 1 {
			f["radio_table"] = []map[string]any{{"radio": "ng", "name": "wifi0"}}
		}
		sc.merge(f, &apstate.Snapshot{}, apstate.CfgInfo{}, time.Now())
		if f["inform_as_notif"] != nil {
			t.Fatalf("inform %d: event attached without its radio's name", i)
		}
		due, _ := sc.informed(true)
		if !due {
			if i+1 > eventTries {
				t.Fatalf("dropped only after %d informs, want %d", i+1, eventTries)
			}
			if len(sc.events) != 0 {
				t.Fatalf("not due but kept: %d events", len(sc.events))
			}
			return
		}
	}
	t.Fatal("still due after 10 informs that could not carry it: the loop informs every immediateWait")
}
