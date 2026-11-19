// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// Fixtures in testdata were read on the JCOW414 (2026-11-19, read-only):
// get_site_survey of both radios (neighbours' SSIDs and BSSIDs replaced,
// columns kept), and the kernel log after `show stacountinfo` (ra0) and
// `show bgndscaninfo` (rai0), with the lines around them.

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseSiteSurvey(t *testing.T) {
	now := time.Unix(1000, 0)
	ng := parseSiteSurvey(surveyRows(fixture(t, "site_survey_ra0.txt")), "ng", now)
	if len(ng) != 16 {
		t.Fatalf("ng: %d rows, want 16", len(ng))
	}
	want := map[int]apstate.BSS{
		0:  {BSSID: "02:00:5e:01:ba:75", SSID: "Neighbour00", Channel: 1, Freq: 2412, Width: 40, CenterFreq: 2422, Signal: -67, Security: "Open"},
		1:  {BSSID: "02:00:5e:02:64:e9", SSID: "Neighbour01", Channel: 1, Freq: 2412, Width: 40, CenterFreq: 2422, Signal: -89, Security: "WPA2-Personal (TKIP/AES/CCMP)"},
		5:  {BSSID: "ba:a7:b9:3e:17:04", SSID: "Example Network", Channel: 1, Freq: 2412, Width: 20, CenterFreq: 2412, Signal: -70, Security: "WPA2-Personal (TKIP/AES/CCMP)"},
		12: {BSSID: "02:00:5e:0a:de:0e", SSID: "Neighbour08", Channel: 10, Freq: 2457, Width: 40, CenterFreq: 2447, Signal: -95, Security: "WPA2-Personal (TKIP/AES/CCMP)"},
		14: {BSSID: "02:00:5e:0c:c7:29", SSID: "Nbr_Quote'$", Channel: 11, Freq: 2462, Width: 20, CenterFreq: 2462, Signal: -60, Security: "WPA2-Personal (TKIP/AES/CCMP)"},
	}
	check := func(band string, got []apstate.BSS, want map[int]apstate.BSS) {
		for i, w := range want {
			w.Seen = now
			if got[i] != w {
				t.Errorf("%s row %d = %+v, want %+v", band, i, got[i], w)
			}
		}
	}
	check("ng", ng, want)

	na := parseSiteSurvey(surveyRows(fixture(t, "site_survey_rai0.txt")), "na", now)
	if len(na) != 16 {
		t.Fatalf("na: %d rows, want 16", len(na))
	}
	check("na", na, map[int]apstate.BSS{
		// W-Mode runs into the RSSI ("-9811a/n/ac"); MDId columns follow
		0: {BSSID: "ae:a7:b9:3e:15:f9", SSID: "Example Network", Channel: 36, Freq: 5180, Width: 40, CenterFreq: 5190, Signal: -98, Security: "WPA2+WPA3-Personal (AES/CCMP)"},
		1: {BSSID: "54:af:97:74:f4:39", SSID: "ORCHID_5", Channel: 36, Freq: 5180, Width: 20, CenterFreq: 5180, Signal: -70, Security: "WPA2-Personal (AES/CCMP)"},
		2: {BSSID: "02:00:5e:01:9f:be", SSID: "Neighbour00", Channel: 44, Freq: 5220, Width: 40, CenterFreq: 5230, Signal: -100, Security: "WPA2-Personal (TKIP/AES/CCMP)"},
		// a hidden network: empty SSID
		6:  {BSSID: "02:00:5e:05:db:2d", SSID: "", Channel: 48, Freq: 5240, Width: 40, CenterFreq: 5230, Signal: -88, Security: "WPA2-Personal (AES/CCMP)"},
		9:  {BSSID: "be:a7:b9:3e:17:06", SSID: "olive#", Channel: 149, Freq: 5745, Width: 40, CenterFreq: 5755, Signal: -89, Security: "WPA2+WPA3-Personal (AES/CCMP)"},
		15: {BSSID: "02:00:5e:0b:90:6f", SSID: "Neighbour05", Channel: 157, Freq: 5785, Width: 40, CenterFreq: 5795, Signal: -99, Security: "WPA2-Personal (AES/CCMP)"},
	})
	if got := parseSiteSurvey(surveyRows("ra0       get_site_survey:\nTotal=0  \n"), "ng", now); len(got) != 0 {
		t.Errorf("empty survey parsed %d rows", len(got))
	}
}

func TestSurveySec(t *testing.T) {
	for in, want := range map[string]string{
		"OPEN/NONE":             "Open",
		"OPEN/WEP":              "WEP",
		"WPA2PSK/AES":           "WPA2-Personal (AES/CCMP)",
		"WPAPSK/TKIP":           "WPA-Personal (TKIP)",
		"WPA3PSK/AES":           "WPA3-Personal (AES/CCMP)",
		"WPA2PSKWPA3PSK/AES":    "WPA2+WPA3-Personal (AES/CCMP)",
		"WPA1WPA2/TKIPAES":      "WPA2-Enterprise (TKIP/AES/CCMP)",
		"WPA2/AES":              "WPA2-Enterprise (AES/CCMP)",
		"OWE/AES":               "Open (OWE)",
		"WPAPSKWPA2PSK/TKIPAES": "WPA2-Personal (TKIP/AES/CCMP)",
		// the MT7603 (mt7603eap.ko has no WPA3/SAE names, only "UNKNOW")
		// prints an AKM it does not know as UNKNOW: a WPA cipher still
		// means a protected network, never an open one
		"UNKNOW/AES":     "WPA2-Personal (AES/CCMP)",
		"UNKNOW/TKIPAES": "WPA2-Personal (TKIP/AES/CCMP)",
		"UNKNOW/NONE":    "Open",
	} {
		if got := apstate.SecurityLabel(surveySec(in)); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

func TestParseStaCount(t *testing.T) {
	got := parseStaCount(fixture(t, "stacountinfo_ra0.klog"))
	if len(got) != 3 {
		t.Fatalf("%d rows, want 3: %+v", len(got), got)
	}
	if n := got["fc:3c:d7:31:00:cd"]; n != (staCount{txPkts: 333, rxPkts: 355, txBytes: 20824, rxBytes: 75899}) {
		t.Errorf("fc:3c:d7:31:00:cd = %+v", n)
	}
	// %ld on a 32-bit CPU: past 2^31 it prints negative
	wrap := "<4>MAC                AID TxPackets   RxPackets   TxBytes     RxBytes     TP(Tx)      TP(Rx)\n" +
		"<4>AA:BB:CC:DD:EE:FF  1   5           6           -2          7           0Mbps 0Mbps\n"
	if n := parseStaCount(wrap)["aa:bb:cc:dd:ee:ff"]; n.txBytes != 1<<32-2 || n.rxBytes != 7 {
		t.Errorf("wrapped row = %+v", n)
	}
	if got := parseStaCount(macDump); got != nil {
		t.Errorf("station table parsed as counters: %+v", got)
	}
}

func TestParseBgndScanInfo(t *testing.T) {
	b, ok := parseBgndScanInfo(fixture(t, "bgndscaninfo_rai0.klog"))
	if !ok || b != (busySample{busy: 5996, tx: 4818, rx: 0}) {
		t.Errorf("bgndscaninfo = %+v, %v", b, ok)
	}
	if _, ok := parseBgndScanInfo(fixture(t, "stacountinfo_ra0.klog")); ok {
		t.Error("a log without the block gave a reading")
	}
}

// ---------------------------------------------------------- fake driver

// klogDev is fakeDev plus the driver's kernel-log and survey output.
type klogDev struct {
	*fakeDev
	log    strings.Builder
	prints map[string]string // "<iface> <show arg>" -> what the driver logs
	survey map[string]string // iface -> get_site_survey stdout
	next   map[string]string // iface -> the survey after `set SiteSurvey=1`
	reads  int               // get_site_survey calls since the last set
	after  int               // reads before next takes over
}

func newKlogDev(t *testing.T) *klogDev {
	d := &klogDev{fakeDev: newFakeDev(t), prints: map[string]string{}, survey: map[string]string{}, next: map[string]string{}}
	d.log.WriteString("<4>boot\n")
	for f, v := range map[string]string{"uptime": "8207736.85 23118767.65", "loadavg": "0.10 0.20 0.30 1/80 999",
		"stat": "cpu  100 0 100 800 0 0 0 0 0 0", "meminfo": "MemTotal: 125000 kB\nMemFree: 20000 kB"} {
		p := filepath.Join(d.root, "proc", f)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(v+"\n"), 0o644)
	}
	return d
}

func (d *klogDev) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name != "iwpriv" {
		return d.fakeDev.Run(ctx, name, args...)
	}
	d.fakeDev.log = append(d.fakeDev.log, name+" "+strings.Join(args, " "))
	switch args[1] {
	case "show":
		d.log.WriteString(d.prints[args[0]+" "+args[2]])
	case "get_site_survey":
		d.reads++
		if n, ok := d.next[args[0]]; ok && d.reads > d.after {
			d.survey[args[0]] = n
			delete(d.next, args[0])
		}
		return []byte(d.survey[args[0]]), nil
	case "set":
		d.reads = 0
	}
	return nil, nil
}

func (d *klogDev) iwpriv() []string {
	var out []string
	for _, l := range d.fakeDev.log {
		if strings.HasPrefix(l, "iwpriv ") {
			out = append(out, l)
		}
	}
	return out
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// mono is the clock as a monotonic reading (the applier's settle time).
func (c *clock) mono() time.Duration { return c.t.Sub(time.Unix(0, 0)) }

func newTestCollector(d *klogDev, ck *clock, fresh bool) *Collector {
	return NewCollector(CollectorOptions{Root: d.root, Run: d, FreshScan: fresh, now: ck.now,
		klog:  func() ([]byte, error) { return []byte(d.log.String()), nil },
		sleep: func(ctx context.Context, dt time.Duration) error { ck.t = ck.t.Add(dt); return ctx.Err() }})
}

func writeSys(t *testing.T, root, dev, file, v string) {
	t.Helper()
	p := filepath.Join(root, "sys/class/net", dev, file)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(v+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func radioOf(s *apstate.Snapshot, band string) *apstate.Radio {
	for i := range s.Radios {
		if s.Radios[i].Band == band {
			return &s.Radios[i]
		}
	}
	return nil
}

func TestCollectCachesDriverReads(t *testing.T) {
	d := newKlogDev(t)
	d.setUp("rai0", true)
	d.prints["ra0 stainfo"] = macDump
	d.prints["ra0 stacountinfo"] = fixture(t, "stacountinfo_ra0.klog")
	d.prints["rai0 stainfo"] = "<4>Dump MacTable entries info, EntType=0x20001\n<4>MAC                MODE  AID  BSS PSM WMM MIMOPS RSSI0/1/2/3         PhMd        BW       MCS         SGI      STBC      Idle   Rate      QosMap\n<4>sta_cnt=0\n"
	d.prints["rai0 bgndscaninfo"] = fixture(t, "bgndscaninfo_rai0.klog")
	ck := &clock{t: time.Unix(1_000_000, 0)}
	c := newTestCollector(d, ck, false)
	ctx := context.Background()

	s, err := c.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reads := d.iwpriv()
	if len(reads) != 4 { // ra0 stainfo, stacountinfo; rai0 stainfo, bgndscaninfo
		t.Fatalf("first Collect ran %v", reads)
	}
	ng := radioOf(s, "ng")
	var all []apstate.Station
	for _, v := range ng.VAPs {
		all = append(all, v.Stations...)
	}
	if len(all) != 3 {
		t.Fatalf("%d stations, want 3", len(all))
	}
	byMAC := map[string]apstate.Station{}
	for _, st := range all {
		byMAC[st.MAC] = st
	}
	if st := byMAC["fc:3c:d7:31:00:cd"]; st.TxPackets != 333 || st.RxPackets != 355 || st.TxBytes != 20824 || st.RxBytes != 75899 || st.Signal != -49 {
		t.Errorf("fc:3c:d7:31:00:cd = %+v", st)
	}
	if st := byMAC["96:97:74:02:d6:8b"]; st.TxPackets != 0 || st.TxRetries != 0 {
		t.Errorf("a station without counters got some: %+v", st)
	}
	if ng.Survey != (apstate.Survey{}) {
		t.Errorf("2.4 GHz survey %+v: the MT7603 has no busy time", ng.Survey)
	}

	// 1 s later: the driver is not asked again, sysfs is read again
	writeSys(t, d.root, "ra0", "statistics/tx_bytes", "777")
	ck.t = ck.t.Add(time.Second)
	if s, err = c.Collect(ctx); err != nil {
		t.Fatal(err)
	}
	if got := d.iwpriv(); len(got) != 4 {
		t.Errorf("Collect within the cache time ran %v", got[4:])
	}
	if v := radioOf(s, "ng").VAPs[0]; v.Stats["tx_bytes"] != 777 || len(v.Stations) == 0 {
		t.Errorf("cached Collect: ra0 tx_bytes %d, %d stations", v.Stats["tx_bytes"], len(v.Stations))
	}
	// the 5 GHz busy time integrates over the second: 5996 µs/s busy,
	// 4818 µs/s own transmit
	if sv := radioOf(s, "na").Survey; sv.Active != 1000 || sv.Busy != 5 || sv.Tx != 4 || sv.Rx != 0 {
		t.Errorf("na survey %+v, want active 1000 busy 5 tx 4", sv)
	}

	// past the cache time: read again
	ck.t = ck.t.Add(defaultCacheTTL)
	if _, err = c.Collect(ctx); err != nil {
		t.Fatal(err)
	}
	if got := d.iwpriv(); len(got) != 8 {
		t.Errorf("Collect after the cache time: %d iwpriv calls, want 8", len(got))
	}
	// Invalidate (after an apply): read again at once
	c.Invalidate()
	ck.t = ck.t.Add(time.Second)
	if _, err = c.Collect(ctx); err != nil {
		t.Fatal(err)
	}
	if got := d.iwpriv(); len(got) != 12 {
		t.Errorf("Collect after Invalidate: %d iwpriv calls, want 12", len(got))
	}
	// the counters reading fails: the stations keep their last counts (a
	// drop to 0 would count all their traffic again)
	d.prints["ra0 stacountinfo"] = ""
	c.Invalidate()
	ck.t = ck.t.Add(time.Second)
	if s, err = c.Collect(ctx); err != nil {
		t.Fatal(err)
	}
	for _, v := range radioOf(s, "ng").VAPs {
		for _, st := range v.Stations {
			if st.MAC == "fc:3c:d7:31:00:cd" && (st.TxBytes != 20824 || st.RxPackets != 355) {
				t.Errorf("counters after a missed reading: %+v", st)
			}
		}
	}
	if got := d.iwpriv(); len(got) != 16 {
		t.Fatalf("%d iwpriv calls, want 16", len(got))
	}
	// a site survey runs: the last reading stands
	c.scanning.Store(true)
	ck.t = ck.t.Add(time.Minute)
	if _, err = c.Collect(ctx); err != nil {
		t.Fatal(err)
	}
	c.scanning.Store(false)
	if got := d.iwpriv(); len(got) != 16 {
		t.Errorf("Collect during a survey asked the driver: %v", got[16:])
	}
}

func TestHomeScanCachedSurvey(t *testing.T) {
	d := newKlogDev(t)
	table := fixture(t, "site_survey_rai0.txt")
	d.survey["rai0"] = table
	d.setUp("rai0", true)
	ck := &clock{t: time.Unix(1_000_000, 0)}
	c := newTestCollector(d, ck, false)
	ctx := context.Background()

	scan := func() *apstate.ScanResult {
		t.Helper()
		r, err := c.HomeScan(ctx, "na")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// the table found at start is of unknown age: not reported
	if r := scan(); len(r.BSS) != 0 {
		t.Errorf("baseline survey reported: %d rows", len(r.BSS))
	}
	ck.t = ck.t.Add(time.Minute)
	if r := scan(); len(r.BSS) != 0 {
		t.Errorf("unchanged baseline reported: %d rows", len(r.BSS))
	}
	// the driver scanned (the 5 GHz radio restarted): seen now
	d.survey["rai0"] = strings.Replace(table, "-70      50 ", "-71      48 ", 1)
	ck.t = ck.t.Add(time.Minute)
	changed := ck.t
	r := scan()
	if len(r.BSS) != 16 || !r.BSS[0].Seen.Equal(changed) || r.Band != "na" {
		t.Fatalf("changed survey: %d rows, seen %v", len(r.BSS), r.BSS[0].Seen)
	}
	// unchanged: same rows, still seen when the change was
	ck.t = ck.t.Add(3 * time.Minute)
	if r := scan(); len(r.BSS) != 16 || !r.BSS[1].Seen.Equal(changed) || r.BSS[1].Signal != -71 {
		t.Errorf("unchanged survey: %d rows, row 1 %+v", len(r.BSS), r.BSS[1])
	}
	ck.t = changed.Add(surveyKeep)
	if r := scan(); len(r.BSS) != 0 {
		t.Errorf("survey older than %v still reported", surveyKeep)
	}
	for _, l := range d.iwpriv() {
		if strings.Contains(l, " set ") {
			t.Errorf("HomeScan started a scan: %s", l)
		}
	}
	// without FreshScan there is no Scan, and RF_SCAN is not claimed
	if _, err := c.Scan(ctx, "na"); !errors.Is(err, ErrUnsupported) || c.ScanSupported() {
		t.Errorf("Scan without FreshScan: %v, supported %v", err, c.ScanSupported())
	}
}

func TestFreshScan(t *testing.T) {
	d := newKlogDev(t)
	old := fixture(t, "site_survey_ra0.txt")
	d.survey["ra0"] = old
	d.next["ra0"] = strings.Replace(old, "-67      57 ", "-66      59 ", 1)
	d.after = 3 // the driver is still scanning for the first reads
	ck := &clock{t: time.Unix(1_000_000, 0)}
	c := newTestCollector(d, ck, true)
	ctx := context.Background()
	if !c.ScanSupported() {
		t.Fatal("FreshScan collector does not support Scan")
	}
	r, err := c.Scan(ctx, "ng")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.BSS) != 16 || r.BSS[0].Signal != -66 || !r.BSS[0].Seen.Equal(ck.t) || !r.Time.Equal(ck.t) {
		t.Fatalf("scan: %d rows, first %+v at %v", len(r.BSS), r.BSS[0], r.Time)
	}
	calls := d.iwpriv()
	if calls[0] != "iwpriv ra0 get_site_survey" || calls[1] != "iwpriv ra0 set SiteSurvey=1" {
		t.Errorf("scan ran %v", calls)
	}
	// the home listen right after reports the scan's rows
	ck.t = ck.t.Add(time.Minute)
	if h, err := c.HomeScan(ctx, "ng"); err != nil || len(h.BSS) != 16 || !h.BSS[0].Seen.Equal(r.Time) {
		t.Errorf("home listen after a scan: %v, %+v", err, h)
	}

	// the table never changes: no result once ctx ends
	d.next = map[string]string{}
	tctx, cancel := context.WithCancel(ctx)
	n := 0
	c.o.sleep = func(context.Context, time.Duration) error {
		if n++; n > 10 {
			cancel()
			return tctx.Err()
		}
		return nil
	}
	if _, err := c.Scan(tctx, "ng"); err == nil || !strings.Contains(err.Error(), "no new site survey") {
		t.Errorf("unchanged survey: %v", err)
	}
	// WithoutScan runs once no survey runs
	ran := false
	if err := c.WithoutScan(ctx, func(context.Context) error { ran = true; return nil }); err != nil || !ran {
		t.Errorf("WithoutScan: %v, ran %v", err, ran)
	}
}

// TestHomeScanSkipsDownRadio: a radio whose interfaces are down (off, or
// serving nothing) is not asked for its site survey; HomeScan gives no
// rows and Scan refuses.
func TestHomeScanSkipsDownRadio(t *testing.T) {
	d := newKlogDev(t)
	d.survey["rai0"] = fixture(t, "site_survey_rai0.txt")
	ck := &clock{t: time.Unix(1_000_000, 0)}
	c := newTestCollector(d, ck, true)
	ctx := context.Background()
	if r, err := c.HomeScan(ctx, "na"); err != nil || len(r.BSS) != 0 {
		t.Errorf("HomeScan of a down radio: %v, %v", r, err)
	}
	sctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if _, err := c.Scan(sctx, "na"); err == nil {
		t.Error("Scan of a down radio started")
	}
	if got := d.iwpriv(); len(got) > 0 {
		t.Errorf("driver asked about a down radio: %d commands, first %q", len(got), got[0])
	}
}
