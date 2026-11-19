// SPDX-License-Identifier: GPL-2.0-or-later

package main

// End-to-end spectrum: the real agent, the real wl collector and spectrum
// runner, the .205 captures for every getter, and synthetic answers for the
// scan calls themselves (specFake), against the in-process controller. The
// controller sequences the nightly quick-scan as Network does (CE §2.1): 5
// GHz first, the 2.4 GHz command only after the finished 5 GHz table came
// back, then a manual spectrum-scan.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

// specFake answers the spectrum runner's `wl` calls for wl0 (home control
// channel 2, capture "2l (0x1804)") and wl1 (44, "44/80 (0xe22a)"): each
// `scan -c <n>` off the home control channel refreshes channel n's chanim
// record and the home control record, as the .205 measurements showed
// (spectrum-design §3.2, T2); `scanresults` is ready at the first poll with
// one neighbour on n.
type specFake struct {
	mu     sync.Mutex
	radios map[string]*specRadio
	scans  []string // "wl1 36", in order
	aborts int
	hold   func(radio string) // called (unlocked) before a scan is served
	frozen map[string]int     // radio -> a channel whose record no scan refreshes
}

type specRadio struct {
	band    string
	home    int
	n       int
	glitch  map[int]int // per channel: bumped on every refresh
	pending int         // the -c channel of the scan in flight (-1 none)
}

func newSpecFake() *specFake {
	return &specFake{radios: map[string]*specRadio{
		"wl0": {band: "ng", home: 2, glitch: map[int]int{}, pending: -1},
		"wl1": {band: "na", home: 44, glitch: map[int]int{}, pending: -1},
	}}
}

func (r *specRadio) cs(ch int) int {
	if r.band == "ng" {
		return 0x1000 | ch
	}
	return 0xd000 | ch
}

func (r *specRadio) chanim() string {
	var b strings.Builder
	b.WriteString("version: 3 \nCHAN Interference Measurement:\nStats during last scan:\n")
	chs := make([]int, 0, len(r.glitch))
	for ch := range r.glitch {
		chs = append(chs, ch)
	}
	sort.Ints(chs)
	for _, ch := range chs {
		fmt.Fprintf(&b, " chanspec: 0x%04x crsglitch cnt: %d bad plcp: 1 noise: -97\n\t cca_txdur: 0 cca_inbss: 0 cca_obss:%d cca_nocat: 1 cca_nopkt: 1\n",
			r.cs(ch), r.glitch[ch], ch%17)
	}
	return b.String() + "\n"
}

// serve answers a spectrum call; ok is false for anything else (the
// captures answer it).
func (f *specFake) serve(args []string) (out []byte, err error, ok bool) {
	if len(args) < 3 || args[0] != "-i" {
		return nil, nil, false
	}
	name := args[1]
	f.mu.Lock()
	r := f.radios[name]
	f.mu.Unlock()
	if r == nil {
		return nil, nil, false
	}
	cmd := strings.Join(args[2:], " ")
	if strings.HasPrefix(cmd, "scan ") && f.hold != nil {
		f.hold(name)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.HasPrefix(cmd, "scan "):
		ch := 0
		if i := slices.Index(args, "-c"); i > 0 && i+1 < len(args) {
			ch, _ = strconv.Atoi(args[i+1])
		}
		if ch == 0 {
			return nil, errors.New("e2e: sweeps are not faked"), true
		}
		f.scans = append(f.scans, fmt.Sprintf("%s %d", name, ch))
		r.n++
		if ch != r.home {
			if fc, ok := f.frozen[name]; !ok || fc != ch {
				r.glitch[ch] = 100 + r.n
			} else if _, ok := r.glitch[ch]; !ok {
				r.glitch[ch] = 100 // one record, never rewritten (STALE)
			}
			r.glitch[r.home] = 300 + r.n
		}
		r.pending = ch
		return nil, nil, true
	case cmd == "scanresults":
		ch := r.pending
		if ch < 0 {
			return nil, errors.New("wl: Not Found"), true
		}
		r.pending = -1
		return fmt.Appendf(nil, "SSID: \"nb%d\"\nMode: Managed\tRSSI: -%d dBm\tSNR: 0 dB\tnoise: -95 dBm\nBSSID: 02:00:00:00:%02x:01\tCapability: ESS\n\tChanspec: %d (0x%04x)\n\n",
			ch, 60+ch%20, ch, ch, r.cs(ch)), nil, true
	case cmd == "chanim_stats all":
		return []byte(r.chanim()), nil, true
	case cmd == "scanabort":
		f.aborts++
		r.pending = -1
		return nil, nil, true
	}
	return nil, nil, false
}

func (f *specFake) scanList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.scans)
}

// fastPlan is the runner's plan with the waits cut to milliseconds and no
// airtime gate; everything else (passes, MinHome, client guard) as built.
func fastPlan() *wl.ScanPlan {
	p := wl.DefaultScanPlan()
	p.Dwell, p.Poll, p.HomeGap, p.StaleReread, p.BusyRetry, p.SweepGap = time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond
	p.GateTries = 0
	return &p
}

// tableOf is a radio row's spectrum_table, nil when absent.
func tableOf(m map[string]any, band string) []map[string]any {
	rs, _ := m["radio_table"].([]any)
	for _, r := range rs {
		row, _ := r.(map[string]any)
		if row["radio"] != band {
			continue
		}
		t, ok := row["spectrum_table"].([]any)
		if !ok {
			return nil
		}
		out := make([]map[string]any, 0, len(t))
		for _, x := range t {
			out = append(out, x.(map[string]any))
		}
		return out
	}
	return nil
}

func radioField(m map[string]any, band, key string) any {
	rs, _ := m["radio_table"].([]any)
	for _, r := range rs {
		if row, _ := r.(map[string]any); row["radio"] == band {
			return row[key]
		}
	}
	return nil
}

func widthsOf(rows []map[string]any) []int {
	var ws []int
	for _, r := range rows {
		if w := int(num(r["width"])); !slices.Contains(ws, w) {
			ws = append(ws, w)
		}
	}
	slices.Sort(ws)
	return ws
}

// TestE2ESpectrum: quick-scan band 1 (80 MHz) then band 0 (20 MHz), each
// answered by an inform carrying that radio's rows (nine keys each, a fresh
// spectrum_table_time, quickscan_scanning shown while it ran and absent
// after); then a manual spectrum-scan that clears both tables first and
// returns rows at every width the radios list.
func TestE2ESpectrum(t *testing.T) {
	cfg, _ := u6proSystemCfg(t)
	e := newE2E(t, cfg, true, func(c *Config, o *options) { o.spectrumPlan = fastPlan() })
	sf := newSpecFake()
	e.unit.spec = sf

	quickSeen, clearedSeen := make(chan struct{}), make(chan struct{})
	var held sync.Map
	sf.hold = func(radio string) {
		// the first scan of each phase waits until the controller has seen
		// the state that phase must report while it runs
		wait := map[string]chan struct{}{"wl1-quick": quickSeen, "wl1-manual": clearedSeen}
		e.ctl.mu.Lock()
		phase := map[bool]string{true: "manual", false: "quick"}[e.ctlStep >= 3]
		e.ctl.mu.Unlock()
		ch, ok := wait[radio+"-"+phase]
		if _, done := held.LoadOrStore(radio+"-"+phase, true); !ok || done {
			return
		}
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
		}
	}

	var naQuick, ngQuick, final map[string]any
	dupSent := false
	e.ctl.reply = func(in e2eInform) string {
		m := in.payload
		_, quick := m["quickscan_scanning"]
		switch e.ctlStep {
		case 0:
			if !in.live() {
				return ""
			}
			e.ctlStep = 1
			return `{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":80}`
		case 1:
			if m["quickscan_scanning"] == true && m["spectrum_scanning"] == false {
				if !dupSent {
					// a second command while the band runs is skipped
					// (mcad: "[quick-scan] skipped: already in progress");
					// the band is released at the next inform, after the
					// agent has handled this reply
					dupSent = true
					return `{"_type":"cmd","cmd":"quick-scan","scan-band":0,"scan-bw":20}`
				}
				closeOnce(quickSeen)
			}
			if !quick && tableOf(m, "na") != nil {
				naQuick, e.ctlStep = m, 2
				return `{"_type":"cmd","cmd":"quick-scan","scan-band":0,"scan-bw":20}`
			}
		case 2:
			if !quick && tableOf(m, "ng") != nil {
				ngQuick, e.ctlStep = m, 3
				return `{"_type":"cmd","cmd":"spectrum-scan","spectrum-cfg":"","infinite":false}`
			}
		case 3:
			if m["spectrum_scanning"] == true && tableOf(m, "na") == nil && tableOf(m, "ng") == nil {
				closeOnce(clearedSeen)
				e.ctlStep = 4
			}
		case 4:
			if m["spectrum_scanning"] == false && len(widthsOf(tableOf(m, "ng"))) > 1 {
				final, e.ctlStep = m, 5
			}
		}
		return ""
	}
	e.adopt()
	eventually(t, "the manual spectrum-scan reported", func() bool {
		e.ctl.mu.Lock()
		defer e.ctl.mu.Unlock()
		return e.ctlStep == 5
	})
	e.stop()

	checkRows := func(rows []map[string]any, what string) {
		t.Helper()
		for _, r := range rows {
			var keys []string
			for k := range r {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if !slices.Equal(keys, spectrumKeys) {
				t.Errorf("%s: row keys %v", what, keys)
			}
			if it, ok := r["interference_type"].([]any); !ok || len(it) != 0 {
				t.Errorf("%s: interference_type %v", what, r["interference_type"])
			}
			if num(r["interference"]) >= 0 || num(r["utilization"]) < 0 || num(r["utilization"]) > 100 {
				t.Errorf("%s: row %v", what, r)
			}
		}
	}

	// 5 GHz quick-scan: 80 MHz blocks 36 and 149 only (wl chanspecs), and
	// no 2.4 GHz table yet
	na := tableOf(naQuick, "na")
	checkRows(na, "na quick-scan")
	var chans []int
	for _, r := range na {
		chans = append(chans, int(num(r["channel"])))
	}
	if !slices.Equal(chans, []int{36, 149}) || !slices.Equal(widthsOf(na), []int{80}) || num(na[0]["center_freq"]) != 5210 {
		t.Errorf("na quick-scan rows %v", na)
	}
	if tableOf(naQuick, "ng") != nil || num(radioField(naQuick, "na", "spectrum_table_time")) > 5 ||
		radioField(naQuick, "na", "spectrum_scanning_abnormal") != false {
		t.Errorf("na quick-scan inform: ng %v time %v abnormal %v", tableOf(naQuick, "ng"),
			radioField(naQuick, "na", "spectrum_table_time"), radioField(naQuick, "na", "spectrum_scanning_abnormal"))
	}
	// 2.4 GHz quick-scan: 20 MHz rows, one per channel; the 5 GHz table
	// is still there
	ng := tableOf(ngQuick, "ng")
	checkRows(ng, "ng quick-scan")
	if len(ng) < 11 || !slices.Equal(widthsOf(ng), []int{20}) || tableOf(ngQuick, "na") == nil {
		t.Errorf("ng quick-scan rows %v", ng)
	}
	// manual: every width the radio lists
	checkRows(tableOf(final, "na"), "na manual")
	checkRows(tableOf(final, "ng"), "ng manual")
	if w := widthsOf(tableOf(final, "na")); !slices.Equal(w, []int{20, 40, 80}) {
		t.Errorf("na manual widths %v", w)
	}
	if w := widthsOf(tableOf(final, "ng")); !slices.Equal(w, []int{20, 40}) {
		t.Errorf("ng manual widths %v", w)
	}
	if _, ok := final["quickscan_scanning"]; ok {
		t.Error("quickscan_scanning at rest")
	}
	// order: the 5 GHz band of each command first, decimal -c channels, no
	// scanabort (every band finished)
	sc := sf.scanList()
	if len(sc) == 0 || !strings.HasPrefix(sc[0], "wl1 ") || sf.aborts != 0 {
		t.Errorf("scans %v, %d scanabort", sc, sf.aborts)
	}
	first0 := slices.IndexFunc(sc, func(s string) bool { return strings.HasPrefix(s, "wl0 ") })
	if first0 < 0 || slices.ContainsFunc(sc[:first0], func(s string) bool { return !strings.HasPrefix(s, "wl1 ") }) {
		t.Errorf("2.4 GHz scanned before the 5 GHz table was reported: %v", sc)
	}
	logs := e.logs.all()
	for _, want := range []string{"[quick-scan] skipped: already in progress (quick-scan na 80 MHz)", "quick-scan na 80 MHz: 2 rows at [80] MHz on wl1", "quick-scan ng 20 MHz:", "spectrum-scan na:", "spectrum-scan ng:"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %q", want)
		}
	}
}

func closeOnce(c chan struct{}) {
	select {
	case <-c:
	default:
		close(c)
	}
}

// TestE2EQuickScanInformsAtOnce: the controller sends the next band only
// after it has the finished table (CE §2.1), so the agent informs as soon as
// a band ends rather than at its next interval. Here the controller sets a
// 60 s interval: only the band's own inform can bring the table in time.
func TestE2EQuickScanInformsAtOnce(t *testing.T) {
	cfg, _ := u6proSystemCfg(t)
	e := newE2E(t, cfg, true, func(c *Config, o *options) { o.spectrumPlan = fastPlan() })
	e.unit.spec = newSpecFake()
	e.ctl.reply = func(in e2eInform) string {
		if !in.live() {
			return "" // a 1 s noop: the provisioning's apply is still running
		}
		switch e.ctlStep {
		case 0:
			e.ctlStep = 1
			return `{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":80}`
		case 1:
			if _, quick := in.payload["quickscan_scanning"]; !quick && tableOf(in.payload, "na") != nil {
				e.ctlStep = 2
			}
		}
		return `{"_type":"noop","interval":60}`
	}
	e.adopt()
	eventually(t, "the 5 GHz table without waiting for the interval", func() bool {
		e.ctl.mu.Lock()
		defer e.ctl.mu.Unlock()
		return e.ctlStep == 2
	})
	e.stop()
}

// TestE2EQuickScanEvent: Network 11.1 stores a scan only on
// EVT_AP_QuickScanEvent (spectrum_scan_timestamp, radio_table_stats) or at
// the end of a quick-scan; a manual spectrum-scan has only the event. After
// every band with a table the agent sends the event as the controller reads
// it (inform_as_notif, notif_reason "event", notif_payload with the
// ubntquickscan keys), in the inform right after the one that carried the
// table, even with a 60 s interval; the controller answers notif informs
// with a noop and sends commands only on regular informs, as Network does.
func TestE2EQuickScanEvent(t *testing.T) {
	cfg, _ := u6proSystemCfg(t)
	e := newE2E(t, cfg, true, func(c *Config, o *options) { o.spectrumPlan = fastPlan() })
	e.unit.spec = newSpecFake()
	e.ctl.reply = func(in e2eInform) string {
		if in.payload["inform_as_notif"] == true {
			// Network answers a plain noop; the 1 s interval only lets
			// this script go on without waiting the 60 s
			return `{"_type":"noop","interval":1}`
		}
		if !in.live() {
			return ""
		}
		switch e.ctlStep {
		case 0:
			e.ctlStep = 1
			return `{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":80}`
		case 2:
			e.ctlStep = 3
			return `{"_type":"cmd","cmd":"spectrum-scan","spectrum-cfg":"","infinite":false}`
		}
		return `{"_type":"noop","interval":60}`
	}
	notifs := func() (out []int) {
		for i, in := range e.ctl.snapshot() {
			if in.payload["inform_as_notif"] == true {
				out = append(out, i)
			}
		}
		return out
	}
	e.ctl.hook = func(in e2eInform) {
		if in.payload["inform_as_notif"] == true && e.ctlStep == 1 {
			e.ctlStep = 2
		}
	}
	e.adopt()
	// wait for the three events; on a timeout the inform sequence is logged
	deadline := time.Now().Add(5 * time.Second)
	for len(notifs()) < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(notifs()) < 3 {
		for i, in := range e.ctl.snapshot() {
			_, q := in.payload["quickscan_scanning"]
			t.Logf("inform %d notif=%v quick=%v manual=%v na=%d ng=%d", i, in.payload["inform_as_notif"], q, in.payload["spectrum_scanning"], len(tableOf(in.payload, "na")), len(tableOf(in.payload, "ng")))
		}
	}
	time.Sleep(300 * time.Millisecond) // no further event may follow
	e.stop()

	all := e.ctl.snapshot()
	idx := notifs()
	if len(idx) != 3 {
		t.Fatalf("%d event informs, want 3 (quick-scan na, spectrum-scan na and ng)", len(idx))
	}
	var bands []string
	for _, i := range idx {
		ev := all[i].payload
		p, _ := ev["notif_payload"].(map[string]any)
		if ev["notif_reason"] != "event" || p["event_string"] != "EVT_AP_QuickScanEvent" {
			t.Fatalf("inform %d: notif_reason %v payload %v", i, ev["notif_reason"], p)
		}
		var keys []string
		for k := range p {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if !slices.Equal(keys, []string{"center_freq", "channel", "event_string", "interference", "radio", "radio_name", "utilization", "width"}) {
			t.Errorf("payload keys %v", keys)
		}
		band, _ := p["radio"].(string)
		bands = append(bands, band)
		// radio_name is that radio's name in radio_table
		if name := radioField(ev, band, "name"); name == nil || p["radio_name"] != name {
			t.Errorf("radio_name %v, radio_table has %v", p["radio_name"], name)
		}
		// the inform just before carried the band's table, with the row
		// the event names
		prev := all[i-1].payload
		if prev["inform_as_notif"] == true {
			t.Errorf("inform %d: two event informs in a row", i)
		}
		// Network ignores a spectrum_table sent with quickscan_scanning
		if prev["quickscan_scanning"] == true {
			t.Errorf("inform %d: the carrier said quickscan_scanning, its table was not taken", i)
		}
		found := false
		for _, r := range tableOf(prev, band) {
			if num(r["channel"]) == num(p["channel"]) && num(r["width"]) == num(p["width"]) &&
				num(r["center_freq"]) == num(p["center_freq"]) && num(r["utilization"]) == num(p["utilization"]) &&
				num(r["interference"]) == num(p["interference"]) {
				found = true
			}
		}
		if !found {
			t.Errorf("event %v: no such row in the %s table of the inform before it", p, band)
		}
		// a full inform: the controller reads model, version and the rest
		// before it dispatches the event
		if all[i].payload["model"] == nil || all[i].payload["mac"] == nil {
			t.Errorf("event inform lacks model/mac")
		}
	}
	if !slices.Equal(bands, []string{"na", "na", "ng"}) {
		t.Errorf("event bands %v", bands)
	}
	// quick-scan na at 80 MHz, home 44/80: the 36-48 block
	p := all[idx[0]].payload["notif_payload"].(map[string]any)
	if num(p["channel"]) != 36 || num(p["width"]) != 80 || num(p["center_freq"]) != 5210 {
		t.Errorf("quick-scan event row %v", p)
	}
	if logs := e.logs.all(); !strings.Contains(logs, "spectrum: EVT_AP_QuickScanEvent sent (na ch 36/80 MHz)") {
		t.Error("no log of the sent event")
	}
}

// TestE2ESpectrumScanPartial: a manual spectrum-scan whose 5 GHz band fails
// (a non-passive channel, 48, never refreshed: ErrIncomplete) still reports
// and stores the 2.4 GHz result. As on the real AP (one ubntquickscan per
// radio, rftable reset to {} first), the failed radio keeps no table and
// sends no event; it reports spectrum_scanning_abnormal; the other radio's
// table and its EVT_AP_QuickScanEvent go out.
func TestE2ESpectrumScanPartial(t *testing.T) {
	cfg, _ := u6proSystemCfg(t)
	e := newE2E(t, cfg, true, func(c *Config, o *options) { o.spectrumPlan = fastPlan() })
	sf := newSpecFake()
	sf.frozen = map[string]int{"wl1": 48}
	e.unit.spec = sf
	e.ctl.reply = func(in e2eInform) string {
		if in.payload["inform_as_notif"] == true {
			return `{"_type":"noop","interval":1}`
		}
		if e.ctlStep == 0 && in.live() {
			e.ctlStep = 1
			return `{"_type":"cmd","cmd":"spectrum-scan","spectrum-cfg":"","infinite":false}`
		}
		return ""
	}
	notif := func(in e2eInform) bool { return in.payload["inform_as_notif"] == true }
	// a 5 GHz table saved before a restart: restored at start, then
	// cleared by the spectrum-scan like a measured one
	writeSaved(t, e.unit.root, savedNA("UAL6", "wl1", time.Now().Add(-time.Hour)))
	e.adopt()
	eventually(t, "the 2.4 GHz event", func() bool { return e.ctl.countWhere(notif) >= 1 })
	time.Sleep(300 * time.Millisecond)
	e.stop()

	all := e.ctl.snapshot()
	var events []map[string]any
	for _, in := range all {
		if notif(in) {
			events = append(events, in.payload["notif_payload"].(map[string]any))
		}
	}
	if len(events) != 1 || events[0]["radio"] != "ng" {
		t.Fatalf("events %v, want one for ng", events)
	}
	last := all[len(all)-1].payload
	if tableOf(last, "na") != nil || radioField(last, "na", "spectrum_scanning_abnormal") != true {
		t.Errorf("na: table %v abnormal %v", tableOf(last, "na"), radioField(last, "na", "spectrum_scanning_abnormal"))
	}
	if len(tableOf(last, "ng")) == 0 || radioField(last, "ng", "spectrum_scanning_abnormal") != false || last["spectrum_scanning"] != false {
		t.Errorf("ng: table %d rows abnormal %v scanning %v", len(tableOf(last, "ng")), radioField(last, "ng", "spectrum_scanning_abnormal"), last["spectrum_scanning"])
	}
	if logs := e.logs.all(); !strings.Contains(logs, "spectrum-scan na: wl: spectrum scan missed channels") || strings.Contains(logs, "EVT_AP_QuickScanEvent sent (na") ||
		!strings.Contains(logs, "spectrum: restored the na table") {
		t.Errorf("logs:\n%s", logs)
	}
	// the restored table was reported before the scan cleared it
	if !slices.ContainsFunc(all, func(in e2eInform) bool { return len(tableOf(in.payload, "na")) == 2 }) {
		t.Error("the restored 5 GHz table was never reported")
	}
	// the saved copy follows: the cleared 5 GHz table is gone (its band
	// failed), the new 2.4 GHz one is there
	var saved struct {
		Bands map[string]struct {
			Radio string                   `json:"radio"`
			Rows  map[int][]wl.SpectrumRow `json:"rows"`
		} `json:"bands"`
	}
	b, err := os.ReadFile(savedFilePath(e.unit.root))
	if err == nil {
		err = json.Unmarshal(b, &saved)
	}
	if _, na := saved.Bands["na"]; err != nil || na || saved.Bands["ng"].Radio != "wl0" || len(saved.Bands["ng"].Rows[40]) == 0 {
		t.Errorf("saved after the spectrum-scan: %v %s", err, b)
	}
}

// TestE2ESpectrumSurvivesRestart: a quick-scan's 5 GHz table is saved under
// the state directory; a restarted agent reports it from its first inform
// as the live table it was (same rows, spectrum_table_time = the true age),
// without scanning, without an EVT_AP_QuickScanEvent and without writing
// the file again.
func TestE2ESpectrumSurvivesRestart(t *testing.T) {
	cfg, _ := u6proSystemCfg(t)
	e := newE2E(t, cfg, true, func(c *Config, o *options) { o.spectrumPlan = fastPlan() })
	sf := newSpecFake()
	e.unit.spec = sf
	e.ctl.reply = func(in e2eInform) string {
		if in.payload["inform_as_notif"] == true {
			return `{"_type":"noop","interval":1}`
		}
		if e.ctlStep == 0 && in.live() {
			e.ctlStep = 1
			return `{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":80}`
		}
		return ""
	}
	notif := func(in e2eInform) bool { return in.payload["inform_as_notif"] == true }
	e.adopt()
	eventually(t, "the 5 GHz event", func() bool { return e.ctl.countWhere(notif) >= 1 })
	e.stop()
	var measured []map[string]any
	for _, in := range e.ctl.snapshot() {
		if tb := tableOf(in.payload, "na"); tb != nil {
			measured = tb
		}
	}
	if len(measured) != 2 {
		t.Fatalf("quick-scan table %v", measured)
	}

	// what is on flash
	p := savedFilePath(e.unit.root)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err := json.Unmarshal(b, &saved); err != nil {
		t.Fatal(err)
	}
	bands, _ := saved["bands"].(map[string]any)
	na, _ := bands["na"].(map[string]any)
	if saved["version"] != 1.0 || saved["model"] != "UAL6" || len(bands) != 1 || na["radio"] != "wl1" {
		t.Fatalf("saved %s", b)
	}
	// two hours pass before the restart
	at, err := time.Parse(time.RFC3339Nano, na["time"].(string))
	if err != nil || time.Since(at) > time.Minute {
		t.Fatalf("saved time %v %v", na["time"], err)
	}
	na["time"] = at.Add(-2 * time.Hour).Format(time.RFC3339Nano)
	writeSaved(t, e.unit.root, saved)
	before, _ := os.ReadFile(p)

	n, scans := len(e.ctl.snapshot()), len(sf.scanList())
	e.rebuild()
	e.ctl.reply = func(e2eInform) string { return "" }
	e.start()
	eventually(t, "informs of the restarted agent", func() bool { return len(e.ctl.snapshot()) >= n+5 })
	e.stop()

	after := e.ctl.snapshot()[n:]
	first := -1
	for i, in := range after {
		if in.key != "device" { // the restored table rides every inform from the first
			continue
		}
		if first < 0 {
			first = i
			tb := tableOf(in.payload, "na")
			if len(tb) != len(measured) {
				t.Fatalf("first inform after the restart: na table %v", tb)
			}
			for j := range tb {
				for _, k := range spectrumKeys {
					if a, b := tb[j][k], measured[j][k]; k != "interference_type" && a != b {
						t.Errorf("row %d %s: %v, measured %v", j, k, a, b)
					}
				}
			}
			if age := num(radioField(in.payload, "na", "spectrum_table_time")); age < 7200 || age > 7230 {
				t.Errorf("spectrum_table_time %v, want the 2 h since it was measured", age)
			}
			if tableOf(in.payload, "ng") != nil {
				t.Error("a 2.4 GHz table nobody measured")
			}
		}
		if notif(in) {
			t.Errorf("inform %d: an event for the restored table: %v", n+i, in.payload["notif_payload"])
		}
	}
	if first < 0 {
		t.Fatal("no inform after the restart")
	}
	if len(sf.scanList()) != scans {
		t.Errorf("scanned after the restart: %v", sf.scanList()[scans:])
	}
	if now, _ := os.ReadFile(p); string(now) != string(before) {
		t.Errorf("the file was written again:\n%s\n%s", before, now)
	}
}
