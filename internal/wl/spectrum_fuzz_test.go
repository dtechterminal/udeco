// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Fuzz tests of the parsers the spectrum runner feeds with device output
// (`wl chanim_stats all`, `wl scanresults`, `wl cca_get_stats`, `wl
// chanim_stats us`, `wl assoclist`). Seeds are the real captures in
// testdata/spectrum, whole and cut at their "--- " markers. `go test` runs the
// seeds only; `go test -fuzz=FuzzParseChanimRecords ./internal/wl` explores.

// spectrumSeeds returns every capture in testdata/spectrum, whole and cut
// into its "--- ..." sections.
func spectrumSeeds(f *testing.F) []string {
	f.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "spectrum", "*.txt"))
	if err != nil || len(files) == 0 {
		f.Fatalf("no spectrum captures: %v", err)
	}
	var out []string
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		out = append(out, string(b))
		for _, sec := range strings.Split(string(b), "\n--- ") {
			if _, body, ok := strings.Cut(sec, "\n"); ok {
				out = append(out, body)
			}
		}
	}
	return out
}

func FuzzParseChanimRecords(f *testing.F) {
	for _, s := range spectrumSeeds(f) {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Add("version: 3 \n", true)
	f.Add(" chanspec: 0x1001 crsglitch cnt: 1 bad plcp: 0 noise: -90\n\t cca_txdur: 0 cca_inbss: 0 cca_obss:-5 cca_nocat: 200 cca_nopkt: 0\n", true)
	f.Fuzz(func(t *testing.T, text string, ng bool) {
		band := "na"
		if ng {
			band = "ng"
		}
		m, ok := parseChanimRecords([]byte(text), band)
		hasVersion := false
		for line := range strings.Lines(text) {
			if strings.HasPrefix(strings.TrimSpace(line), "version:") {
				hasVersion = true
			}
		}
		if ok != hasVersion {
			t.Fatalf("ok %v, version line %v", ok, hasVersion)
		}
		for ch, r := range m {
			cs, good := decodeChanspec(r.CS)
			if ch != r.Channel || !good || cs.Width != 20 || cs.Band != band || cs.Control != ch {
				t.Fatalf("record %d: %+v decodes to %+v (%v)", ch, r, cs, good)
			}
			if u := r.util(); u < 0 || u > 100 {
				t.Fatalf("util %d", u)
			}
			if c := classifyRecord(r, r, true, true); c != classZero && c != classStale {
				t.Fatalf("an unchanged record classed %s", c)
			}
			if c := classifyRecord(r, r, false, false); c != classStale {
				t.Fatalf("an absent record classed %s", c)
			}
		}
		// what was parsed survives a render and a re-parse unchanged
		again, ok2 := parseChanimRecords([]byte(renderRecords(m)), band)
		if !ok2 || len(again) != len(m) {
			t.Fatalf("re-parse: ok %v, %d records, want %d", ok2, len(again), len(m))
		}
		for ch, r := range m {
			if again[ch] != r {
				t.Fatalf("re-parse ch%d: %+v, want %+v", ch, again[ch], r)
			}
		}
	})
}

// renderRecords prints records in the device's `chanim_stats all` format.
func renderRecords(m map[int]chanimRecord) string {
	chs := make([]int, 0, len(m))
	for ch := range m {
		chs = append(chs, ch)
	}
	sort.Ints(chs)
	var b strings.Builder
	b.WriteString("version: 3 \nCHAN Interference Measurement:\nStats during last scan:\n")
	for _, ch := range chs {
		x := m[ch]
		fmt.Fprintf(&b, " chanspec: 0x%04x crsglitch cnt: %d bad plcp: %d noise: %d\n\t cca_txdur: %d cca_inbss: %d cca_obss:%d cca_nocat: %d cca_nopkt: %d\n",
			x.CS, x.Glitch, x.BadPLCP, x.Noise, x.TxDur, x.Inbss, x.Obss, x.Nocat, x.Nopkt)
	}
	return b.String()
}

func FuzzParseScanResults(f *testing.F) {
	for _, s := range spectrumSeeds(f) {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Add("SSID: \"\"\nMode: Managed\tRSSI: -50 dBm\tChannel: 9u\nBSSID: 00:11:22:33:44:55\tCapability: ESS\n", true)
	f.Add("SSID: \"x\"\nMode: Managed\tRSSI: -60 dBm\tChannel: 36/80\nBSSID: 00:11:22:33:44:55\n\tChanspec: 5GHz channel 42 80MHz (0xe22a)\n", false)
	f.Fuzz(func(t *testing.T, text string, ng bool) {
		band, chans := "na", []int{36, 40, 44, 48, 52, 100, 149, 153, 157, 161, 165}
		if ng {
			band, chans = "ng", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
		}
		list := parseScanResults([]byte(text), band)
		for _, b := range list {
			if b.BSSID == "" || b.BSSID != strings.ToLower(b.BSSID) {
				t.Fatalf("BSSID %q", b.BSSID)
			}
			if _, err := NormMAC(b.BSSID); err != nil {
				t.Fatalf("BSSID %q: %v", b.BSSID, err)
			}
			if !validSecurityLabel(b.Security) {
				t.Fatalf("security %q", b.Security)
			}
		}
		// whatever the scan text says, the interference of a channel stays
		// a finite dBm in the controller's range
		for _, ch := range chans {
			p, ok, _ := peakBSS(list, ch, band)
			if ok && (math.IsNaN(p) || math.IsInf(p, 0)) {
				t.Fatalf("ch%d: P_bss %v", ch, p)
			}
			if v := interferenceDBm(-95, p, ok, 0, false); v < -110 || v > -20 {
				t.Fatalf("ch%d: interference %d", ch, v)
			}
		}
	})
}

func FuzzParseCCAAndUs(f *testing.F) {
	for _, s := range spectrumSeeds(f) {
		f.Add(s, 9)
	}
	f.Add("9   1004   84  8% Low     270 26% High      9  0% Low    4003\nSummaries:\n9   1004       7% Low         26% High         1% Low    5\n", 9)
	f.Add("chanspec  tx  inbss  obss  nocat  nopkt  doze  txop  goodtx  badtx  total_tm  busy_tm  pri20  sec20  sec40\n0x1907 1 2 3 4 5 6 7 8 9 10 11 12 13 14\n", 9)
	f.Add("assoclist 8C:BF:EA:1D:BA:74\nassoclist zz\nassoclist\n", 1)
	f.Fuzz(func(t *testing.T, text string, ch int) {
		b := []byte(text)
		parseCCAGetStats(b)
		if own, ok := ownFromCCA(b, ch); ok && (math.IsNaN(own) || math.IsInf(own, 0)) {
			t.Fatalf("own airtime %v", own)
		}
		parseChanimUs(b)
		for _, m := range ParseAssoclist(text) {
			if _, err := NormMAC(m); err != nil || m != strings.ToLower(m) {
				t.Fatalf("assoclist MAC %q", m)
			}
		}
	})
}

// validSecurityLabel: a label the controller's security enum matches by
// prefix (apstate.SecurityLabel), or the WPA1 forms it shows as is.
func validSecurityLabel(s string) bool {
	for _, p := range []string{"WPA2+WPA3-Personal", "WPA2-Enterprise+WPA3-Enterprise", "WPA2-Personal",
		"WPA3-Personal", "WPA2-Enterprise", "WPA3-Enterprise", "WPA-Personal", "WPA-Enterprise", "WEP", "Open"} {
		if s == p || strings.HasPrefix(s, p+" (") && strings.HasSuffix(s, ")") {
			return true
		}
	}
	return false
}
