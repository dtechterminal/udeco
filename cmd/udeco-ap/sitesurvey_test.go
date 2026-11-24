// SPDX-License-Identifier: GPL-2.0-or-later

package main

// site_survey (platform jio-mtk): the controller's scan commands run the
// MediaTek driver's site survey; the spectrum commands, which have no
// runner on that unit, run it for their band(s) and report scan_table only.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/mtkwifi"
)

func TestSiteSurveyConfig(t *testing.T) {
	jio := `{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1","takeover":true,"platform":"jio-mtk","model":"UHDIW"`
	c, err := parseConfig([]byte(jio + `}`))
	if err != nil || c.SiteSurvey {
		t.Fatalf("default: %v, site_survey %v", err, c != nil && c.SiteSurvey)
	}
	if c, err = parseConfig([]byte(jio + `,"site_survey":true}`)); err != nil || !c.SiteSurvey {
		t.Fatalf("jio-mtk with site_survey: %v", err)
	}
	// the Deco scans with wl whatever the key says: accepted, ignored (and
	// logged at start, TestSiteSurveyWiring)
	deco := `{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1","takeover":true,"site_survey":true}`
	if _, err = parseConfig([]byte(deco)); err != nil {
		t.Fatalf("Deco with site_survey: %v", err)
	}
	// observe mode runs no scans and claims no RF_SCAN: refused, as the
	// other takeover-only keys, rather than accepted and logged as on
	observe := strings.Replace(jio, `"takeover":true`, `"takeover":false`, 1)
	if _, err = parseConfig([]byte(observe + `,"site_survey":true}`)); err == nil || !strings.Contains(err.Error(), "site_survey needs takeover") {
		t.Errorf("site_survey without takeover: %v", err)
	}
	if _, err = parseConfig([]byte(jio + `,"site_survey":"yes"}`)); err == nil {
		t.Error("site_survey \"yes\" accepted")
	}
}

// site_survey reaches mtkwifi.CollectorOptions.FreshScan on jio-mtk (the
// collector then supports Scan, so RF_SCAN is claimed); on the Deco it is
// ignored with a log line.
func TestSiteSurveyWiring(t *testing.T) {
	for _, on := range []bool{false, true} {
		h := newHarness(t, func(c *Config, o *options) {
			c.Takeover, c.Platform, c.Model, c.SiteSurvey = true, PlatformJio, "U7LT", on
			o.col = nil // the real mtkwifi collector
		})
		col, ok := h.a.o.col.(*mtkwifi.Collector)
		if !ok {
			t.Fatalf("jio-mtk collector %T", h.a.o.col)
		}
		// with site_survey the MT7603 (ng) sweeps and the MT7663 (na)
		// visits (offchan5.go): neither band falls back to the survey
		if col.ScanSupported() != on || noRunner(col, "na") == on || bySurvey(col, "na") || noRunner(col, "ng") == on {
			t.Errorf("site_survey %v: ScanSupported %v, na no runner %v by survey %v, ng no runner %v",
				on, col.ScanSupported(), noRunner(col, "na"), bySurvey(col, "na"), noRunner(col, "ng"))
		}
		if got := strings.Contains(h.logs.all(), "site_survey: on"); got != on {
			t.Errorf("site_survey %v: start log %q", on, h.logs.all())
		}
	}
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.SiteSurvey = true, true })
	if !strings.Contains(h.logs.all(), "site_survey: ignored") {
		t.Errorf("Deco with site_survey: no log line: %q", h.logs.all())
	}
}

// surveyCol is a collector without a spectrum runner (jio-mtk) whose
// spectrum commands run the neighbour survey when on.
type surveyCol struct {
	*fakeCol
	on bool
}

func (c surveyCol) ScanSupported() bool                               { return c.on }
func (c surveyCol) SpectrumBySurvey(string) (noRunner, bySurvey bool) { return true, c.on }

// informs is every inform the controller got so far.
func (c *ctl) all() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]any(nil), c.informs...)
}

// noSpectrumState: no inform claimed a spectrum run (spectrum_scanning
// true; quickscan_scanning true too unless quick, the quick-scan survey,
// which holds it while it runs: TestQuickScanSurveyHoldsFlag), carried a
// spectrum_table or an EVT_AP_QuickScanEvent.
func noSpectrumState(t *testing.T, h *harness, quick bool) {
	t.Helper()
	for i, m := range h.ctl.all() {
		if m["spectrum_scanning"] == true || (m["quickscan_scanning"] != nil && !(quick && m["quickscan_scanning"] == true)) {
			t.Errorf("inform %d: spectrum_scanning %v quickscan_scanning %v", i, m["spectrum_scanning"], m["quickscan_scanning"])
		}
		if m["notif_payload"] != nil || m["inform_as_notif"] != nil {
			t.Errorf("inform %d: notification %v", i, m["notif_payload"])
		}
		rows, _ := m["radio_table"].([]any)
		for _, r := range rows {
			if rr, _ := r.(map[string]any); rr["spectrum_table"] != nil {
				t.Errorf("inform %d: %s spectrum_table %v", i, rr["radio"], rr["spectrum_table"])
			}
		}
	}
}

// surveyed: the na scan_table carries the survey's neighbour.
func surveyed(t *testing.T, h *harness) bool {
	m := h.ctl.last()
	if m == nil || m["radio_table"] == nil {
		return false
	}
	rows, _ := radioRow(t, m, "na")["scan_table"].([]any)
	for _, r := range rows {
		if r.(map[string]any)["bssid"] == "11:22:33:44:55:66" {
			return true
		}
	}
	return false
}

// With site_survey on, quick-scan (one band) and spectrum-scan (both, 5
// GHz first) run the neighbour survey and report scan_table only.
func TestSpectrumCommandsRunSurvey(t *testing.T) {
	for _, tc := range []struct {
		cmd, log string
		want     []string
		quick    bool
	}{
		{`{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":40}`, "quick-scan", []string{"scan:na"}, true},
		{`{"_type":"cmd","cmd":"spectrum-scan","spectrum-cfg":"","infinite":false}`, "spectrum-scan", []string{"scan:na", "scan:ng"}, false},
	} {
		h := newHarness(t, func(c *Config, o *options) {
			c.Takeover = true
			o.col = surveyCol{fakeCol: o.col.(*fakeCol), on: true}
		})
		h.ctl.queue(adoptReply, tc.cmd)
		h.start()
		eventually(t, tc.log+" survey reported", func() bool { return surveyed(t, h) })
		eventually(t, tc.log+" survey ended", func() bool { return !h.a.scans.busy() })
		n := h.ctl.count()
		eventually(t, "an inform after the survey", func() bool { return h.ctl.count() > n+1 })
		h.stop()
		var scans []string
		for _, c := range h.rec.list() {
			if strings.HasPrefix(c, "scan:") || strings.HasPrefix(c, "spectrum:") {
				scans = append(scans, c)
			}
		}
		if strings.Join(scans, " ") != strings.Join(tc.want, " ") {
			t.Errorf("%s: ran %v, want %v", tc.log, scans, tc.want)
		}
		if !strings.Contains(h.logs.all(), tc.log+": no spectrum runner on this unit: neighbour site survey") {
			t.Errorf("%s: no log of the survey instead: %q", tc.log, h.logs.all())
		}
		noSpectrumState(t, h, tc.quick)
	}
}

// With site_survey off, the spectrum commands scan nothing and say so;
// no inform claims a spectrum run.
func TestSpectrumCommandsWithoutSurvey(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover = true
		o.col = surveyCol{fakeCol: o.col.(*fakeCol), on: false}
	})
	h.ctl.queue(adoptReply,
		`{"_type":"cmd","cmd":"quick-scan","scan-band":0,"scan-bw":20}`,
		`{"_type":"cmd","cmd":"spectrum-scan","spectrum-cfg":"","infinite":false}`)
	h.start()
	eventually(t, "both refused", func() bool { return strings.Count(h.logs.all(), "site_survey is off") >= 2 })
	n := h.ctl.count()
	eventually(t, "an inform after", func() bool { return h.ctl.count() > n+1 })
	h.stop()
	for _, c := range h.rec.list() {
		if strings.HasPrefix(c, "scan:") || strings.HasPrefix(c, "spectrum:") {
			t.Errorf("ran %s: %v", c, h.rec.list())
		}
	}
	noSpectrumState(t, h, false)
}

// An apply or rollback running (scanBlock) refuses the survey a spectrum
// command would run, as every other scan.
func TestSpectrumSurveyBlocked(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover = true
		o.col = surveyCol{fakeCol: o.col.(*fakeCol), on: true}
	})
	h.a.wifiBusy.Store(true)
	h.ctl.queue(adoptReply,
		`{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":20}`,
		`{"_type":"cmd","cmd":"spectrum-scan","spectrum-cfg":"","infinite":false}`)
	h.start()
	eventually(t, "both refused", func() bool {
		return strings.Count(h.logs.all(), "skipped, a Wi-Fi apply or rollback is running") >= 2
	})
	h.stop()
	for _, c := range h.rec.list() {
		if strings.HasPrefix(c, "scan:") || strings.HasPrefix(c, "spectrum:") {
			t.Errorf("ran %s during an apply: %v", c, h.rec.list())
		}
	}
	noSpectrumState(t, h, false)
}

// blockSurvey is a surveying collector whose Scan holds until released, as
// the driver's survey takes seconds.
type blockSurvey struct {
	surveyCol
	started chan string
	release chan struct{}
}

func (c blockSurvey) Scan(ctx context.Context, band string) (*apstate.ScanResult, error) {
	c.started <- band
	select {
	case <-c.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return c.fakeCol.Scan(ctx, band)
}

// The nightly quick-scan is one command per band, and the controller sends
// the next band once the AP has reported the finished one (CE §2.1; it
// sets quickscan_scanning true itself when it sends the command, and an
// inform without it ends the quick-scan, CE §5). So the survey a quick-scan
// runs instead holds quickscan_scanning true until it has ended, as the
// spectrum runner's quick-scan does: an inform without it while the survey
// runs would end the controller's quick-scan at once, and the next band
// would arrive mid-survey and be dropped. A band that does arrive
// mid-survey is refused by name, without claiming a survey of it.
func TestQuickScanSurveyHoldsFlag(t *testing.T) {
	col := blockSurvey{started: make(chan string, 4), release: make(chan struct{})}
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover = true
		col.surveyCol = surveyCol{fakeCol: o.col.(*fakeCol), on: true}
		o.col = col
	})
	var once sync.Once
	release := func() { once.Do(func() { close(col.release) }) }
	t.Cleanup(release)
	h.ctl.queue(adoptReply, `{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":80}`)
	h.start()
	select {
	case b := <-col.started:
		if b != "na" {
			t.Fatalf("surveyed %s, want na", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no survey started")
	}
	n := h.ctl.count()
	eventually(t, "informs while the survey runs", func() bool { return h.ctl.count() > n+1 })
	// a controller that does not wait: band 0 arrives mid-survey
	h.ctl.queue(`{"_type":"cmd","cmd":"quick-scan","scan-band":0,"scan-bw":20}`)
	eventually(t, "the mid-survey band refused", func() bool {
		return strings.Contains(h.logs.all(), "quick-scan ng: skipped: already in progress (quick-scan na)")
	})
	if strings.Contains(h.logs.all(), "site survey of [ng]") {
		t.Errorf("claims a survey of ng that never ran: %q", h.logs.all())
	}
	during := h.ctl.all()
	release()
	eventually(t, "the finished survey reported, the quick-scan ended", func() bool {
		m := h.ctl.last()
		_, flag := m["quickscan_scanning"]
		return !h.a.scans.busy() && !flag && surveyed(t, h)
	})
	// the informs from the command on (the first carried the adoption
	// reply's answer, the second the command's) until the release
	for i, m := range during[2:] {
		if m["quickscan_scanning"] != true {
			t.Errorf("inform %d during the na survey: quickscan_scanning %v: ends the controller's quick-scan early", i+2, m["quickscan_scanning"])
		}
	}
	// the controller now sends the next band: it is surveyed
	h.ctl.queue(`{"_type":"cmd","cmd":"quick-scan","scan-band":0,"scan-bw":20}`)
	select {
	case b := <-col.started:
		if b != "ng" {
			t.Errorf("surveyed %s, want ng", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the next band was not surveyed")
	}
	eventually(t, "the ng survey ended", func() bool { return !h.a.scans.busy() })
	h.stop()
	noSpectrumState(t, h, true)
}

func noRunner(c interface {
	SpectrumBySurvey(string) (bool, bool)
}, band string) bool {
	n, _ := c.SpectrumBySurvey(band)
	return n
}

func bySurvey(c interface {
	SpectrumBySurvey(string) (bool, bool)
}, band string) bool {
	_, b := c.SpectrumBySurvey(band)
	return b
}
