// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// Neighbour scan from the driver's site survey (`iwpriv <radio>
// get_site_survey`, stdout, read-only). The driver keeps the table of its
// last scan and prints it unchanged until the next one: on the unit two
// reads 10 minutes apart were byte for byte the same, RSSI included
// (2026-11-19). A scan runs when the 5 GHz radio starts (AutoChannelSelect=3
// picks the channel), on `set SiteSurvey`, and never on its own otherwise.
// So the table's age is unknown, and a row is reported as seen when the
// table was first seen to change:
//
//   - HomeScan (every minute, never off-channel) reads the cached table. The
//     first table after the agent starts is a baseline of unknown age and is
//     not reported; a changed table is reported as seen now, an unchanged
//     one with that first sighting (its age grows, the controller lists rows
//     younger than 30 s only), and nothing once that is surveyKeep old.
//   - Scan (a controller command only: `cmd scan`, and spectrum-scan and
//     quick-scan of a band without a spectrum runner: SpectrumBySurvey)
//     starts a fresh survey when FreshScan is set, else it is unsupported.
//     The MT7603's off-channel sweep (offchan.go) runs one after its
//     visits (freshSurvey).

// surveyKeep: how long an unchanged cached survey is still reported.
const surveyKeep = 10 * time.Minute

// surveySeen is a band's last survey table and when it was first seen.
type surveySeen struct {
	table string // the rows as printed
	at    time.Time
	bss   []apstate.BSS
}

// scanPoll: how often a fresh survey's table is read; scanSettle: how long
// it must stay the same to count as finished. Not measured on the unit: a
// driver that clears its table when the survey starts and refills it
// channel by channel could hold a partial table for scanSettle on quiet
// passive (DFS) channels, so Scan would end, and release the restart gate,
// before the radio is back on its channel. Log get_site_survey every
// 250 ms through one 5 GHz survey before site_survey goes on (README).
const (
	scanPoll   = 500 * time.Millisecond
	scanSettle = 2 * time.Second
)

func (c *Collector) mainOf(band string) (string, error) {
	for _, rd := range c.o.Layout {
		if rd.Band == band {
			return rd.Ifaces[0], nil
		}
	}
	return "", fmt.Errorf("mtkwifi: no radio for band %q", band)
}

// readSurvey prints the driver's cached survey of the radio.
func (c *Collector) readSurvey(ctx context.Context, main string) (string, error) {
	out, err := c.o.Run.Run(ctx, "iwpriv", main, "get_site_survey")
	if err != nil {
		return "", fmt.Errorf("iwpriv %s get_site_survey: %w", main, err)
	}
	return surveyRows(string(out)), nil
}

// surveyRows is the survey output from its column header on (the table
// the fingerprint compares); "" when there is none.
func surveyRows(out string) string {
	if !strings.HasPrefix(out, "No ") {
		i := strings.Index(out, "\nNo ")
		if i < 0 {
			return ""
		}
		out = out[i+1:]
	}
	return strings.TrimRight(out, " \r\n")
}

// HomeScan reports the driver's cached site survey of the band's radio
// (see the top of this file); it never starts a scan.
func (c *Collector) HomeScan(ctx context.Context, band string) (*apstate.ScanResult, error) {
	main, err := c.mainOf(band)
	if err != nil {
		return nil, err
	}
	if err := c.lockScan(ctx); err != nil {
		return nil, err
	}
	defer c.unlockScan()
	done, ok := c.driverRead()
	if !ok {
		// a radio restart: the last survey as it stands, no driver read
		// (restartgate.go)
		return c.lastSurvey(band, c.o.now()), nil
	}
	if !c.isUp(main) {
		// the radio is off or serves nothing: its driver is not asked
		// (as Collect), and it reports no neighbours
		done()
		return &apstate.ScanResult{Band: band, Time: c.o.now()}, nil
	}
	table, err := c.readSurvey(ctx, main)
	done()
	if err != nil {
		return nil, err
	}
	now := c.o.now()
	res := &apstate.ScanResult{Band: band, Time: now}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.seen[band]
	switch {
	case s == nil:
		// the baseline: printed by a scan of unknown age
		c.seen[band] = &surveySeen{table: table}
		return res, nil
	case s.table != table:
		s.table, s.at, s.bss = table, now, parseSiteSurvey(table, band, now)
	}
	if !s.at.IsZero() && now.Sub(s.at) < surveyKeep {
		res.BSS = append([]apstate.BSS(nil), s.bss...)
	}
	return res, nil
}

// lastSurvey is HomeScan's answer from the band's last survey table,
// without reading the driver.
func (c *Collector) lastSurvey(band string, now time.Time) *apstate.ScanResult {
	res := &apstate.ScanResult{Band: band, Time: now}
	c.mu.Lock()
	defer c.mu.Unlock()
	if s := c.seen[band]; s != nil && !s.at.IsZero() && now.Sub(s.at) < surveyKeep {
		res.BSS = append([]apstate.BSS(nil), s.bss...)
	}
	return res
}

// Scan runs a fresh site survey of the band's radio (the controller's `cmd
// scan`; FreshScan only): `iwpriv <radio> set SiteSurvey=1`, then the table
// is read every scanPoll until it differs from the one before the scan and
// has stayed the same for scanSettle. The radio leaves its channel while
// the driver scans; Collect keeps its last reading meanwhile, and the next
// `show mibinfo` ask after it gives no busy time (mibGap).
func (c *Collector) Scan(ctx context.Context, band string) (*apstate.ScanResult, error) {
	if !c.o.FreshScan {
		return nil, ErrUnsupported
	}
	main, err := c.mainOf(band)
	if err != nil {
		return nil, err
	}
	if err := c.lockScan(ctx); err != nil {
		return nil, err
	}
	defer c.unlockScan()
	return c.freshSurvey(ctx, band, main)
}

// freshSurvey is Scan's survey of radio main; the caller holds the scan
// lock (Scan, or the off-channel sweep after its visits).
func (c *Collector) freshSurvey(ctx context.Context, band, main string) (*apstate.ScanResult, error) {
	// held through the scan: a radio restart waits for it to end
	done, ok := c.driverRead()
	if !ok {
		return nil, ErrRadioRestart
	}
	defer done()
	if !c.isUp(main) {
		return nil, ErrRadioDown
	}
	before, err := c.readSurvey(ctx, main)
	if err != nil {
		return nil, err
	}
	c.startScanning()
	defer c.scanning.Store(false)
	// run before scanning ends: the next `show mibinfo` ask would measure
	// Prim CCA Time over an interval that held the scan, off the channel
	defer c.mibGap(main)
	if _, err := c.o.Run.Run(ctx, "iwpriv", main, "set", "SiteSurvey=1"); err != nil {
		return nil, fmt.Errorf("iwpriv %s set SiteSurvey=1: %w", main, err)
	}
	last, since := before, time.Time{}
	for {
		if err := c.o.sleep(ctx, scanPoll); err != nil {
			if last != before {
				break // the newest table, as far as it got
			}
			return nil, fmt.Errorf("iwpriv %s: no new site survey: %w", main, err)
		}
		t, err := c.readSurvey(ctx, main)
		if err != nil {
			return nil, err
		}
		now := c.o.now()
		if t != last {
			last, since = t, now
			continue
		}
		if last != before && now.Sub(since) >= scanSettle {
			break
		}
	}
	now := c.o.now()
	bss := parseSiteSurvey(last, band, now)
	c.mu.Lock()
	c.seen[band] = &surveySeen{table: last, at: now, bss: bss}
	c.mu.Unlock()
	return &apstate.ScanResult{Band: band, Time: now, BSS: append([]apstate.BSS(nil), bss...)}, nil
}

// startScanning sets scanning once no Collect is reading the driver: one
// that has already passed reading's check (it holds c.mu throughout) would
// still ask `show mibinfo`, whose read-clear of Prim CCA Time would land in
// the scan (in an off-channel visit's dwell: a busy time too low, trusted).
// From here on no Collect asks the driver until scanning ends.
func (c *Collector) startScanning() {
	c.mu.Lock()
	c.scanning.Store(true)
	c.mu.Unlock()
}

// ownUplink is our stations' receive airtime (µs a second) from the
// radio's last reading, when it is fresh and was not invalidated by an
// apply (0: none).
func (c *Collector) ownUplink(main string, now time.Time) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	rr := c.cache[main]
	if rr == nil || rr.stale || now.Sub(rr.at) < 0 || now.Sub(rr.at) > ownAirKeep {
		return 0
	}
	return max(rr.staRx, 0)
}

// mibGap: the radio left its channel (a site survey) since its last `show
// mibinfo` ask, so the next ask has no previous one to measure from
// (mibReading.gap); the reading from before stands until then.
func (c *Collector) mibGap(main string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if m := c.mib[main]; m != nil {
		m.gap = true
	}
}

// SpectrumBySurvey says how the controller's spectrum commands
// (spectrum-scan, quick-scan) run for band: noRunner when Spectrum has no
// runner for it (the MT7663, or no FreshScan); the agent then runs Scan of
// the band instead when bySurvey (FreshScan), and nothing otherwise.
func (c *Collector) SpectrumBySurvey(band string) (noRunner, bySurvey bool) {
	rd, ok := c.radioDef(band)
	noRunner = !c.o.FreshScan || !ok || rd.Spectrum != SpectrumOffChan
	return noRunner, noRunner && c.o.FreshScan
}

// ErrRadioDown: Scan of a radio whose interfaces are down (off, or no SSID
// served on it); the driver is not asked.
var ErrRadioDown = errors.New("mtkwifi: the radio is down: no site survey")

// surveyTail is a survey row from the BSSID on: BSSID, Security, RSSI,
// Signal(%), W-Mode (on the MT7663 run together with the RSSI again:
// "-9811a/n/ac"), ExtCH.
var surveyTail = regexp.MustCompile(`(?:^|\s)([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(\S+)\s+(-?\d+)\s+\d+\s+(\S+)\s+(ABOVE|BELOW|NONE)\b`)

// parseSiteSurvey reads `get_site_survey` (2026-11-19, both drivers):
//
//	No  Ch  SSID                             BSSID               Security               RSSI     Siganl(%)W-Mode  ExtCH  NT ...
//	5   1   Example Network                  ba:a7:b9:3e:17:04   WPA2PSK/TKIPAES        -70      50       11b/g/n NONE   In ...
//
// The SSID is padded to its column and may hold spaces (or be empty for a
// hidden network): it is the text from the SSID column to the row's last
// BSSID-shaped field that the rest of the row follows. The width is the HT
// one (ExtCH ABOVE/BELOW: 40 MHz); the survey does not print a VHT width.
func parseSiteSurvey(table, band string, seen time.Time) []apstate.BSS {
	var out []apstate.BSS
	ssidCol := -1
	have := map[string]bool{}
	for _, l := range strings.Split(table, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.HasPrefix(l, "No ") && strings.Contains(l, "BSSID") {
			ssidCol = strings.Index(l, "SSID")
			continue
		}
		if ssidCol < 0 || len(l) <= ssidCol {
			continue
		}
		head := strings.Fields(l[:ssidCol])
		if len(head) != 2 {
			continue
		}
		ch, err := strconv.Atoi(head[1])
		if err != nil || ch <= 0 {
			continue
		}
		rest := l[ssidCol:]
		all := surveyTail.FindAllStringSubmatchIndex(rest, -1)
		if len(all) == 0 {
			continue
		}
		m := all[len(all)-1]
		g := func(i int) string { return rest[m[2*i]:m[2*i+1]] }
		bssid := strings.ToLower(g(1))
		if have[bssid] {
			continue
		}
		ref := 2412
		if band == "na" || ch > 14 {
			ref = 5180
		}
		b := apstate.BSS{BSSID: bssid, SSID: strings.TrimRight(rest[:m[2]], " "), Channel: ch,
			Freq: apstate.ChannelFreq(ch, ref), Width: 20, Seen: seen}
		b.CenterFreq = b.Freq
		switch g(5) {
		case "ABOVE":
			b.Width, b.CenterFreq = 40, b.Freq+10
		case "BELOW":
			b.Width, b.CenterFreq = 40, b.Freq-10
		}
		b.Signal, _ = strconv.Atoi(g(3))
		b.Security = apstate.SecurityLabel(surveySec(g(2)))
		have[bssid] = true
		out = append(out, b)
	}
	return out
}

// surveyAuth: the driver's AuthMode names, longest first (an entry is the
// names run together: "WPAPSKWPA2PSK", "WPA2PSKWPA3PSK", "WPA1WPA2").
var surveyAuth = []string{"WPA2PSK", "WPA3PSK", "WPAPSK", "WPA3-192", "WPANONE", "WEPAUTO", "SHARED",
	"WPA1", "WPA2", "WPA3", "WPA", "OPEN", "OWE"}

// surveySec reads the Security column, "<auth>/<cipher>":
// "WPAPSKWPA2PSK/TKIPAES", "WPA2PSKWPA3PSK/AES", "OPEN/NONE", "OPEN/WEP".
func surveySec(s string) apstate.SecInfo {
	auth, cipher, _ := strings.Cut(strings.ToUpper(s), "/")
	var si apstate.SecInfo
	for auth != "" {
		k := ""
		for _, t := range surveyAuth {
			if strings.HasPrefix(auth, t) {
				k = t
				break
			}
		}
		if k == "" {
			break
		}
		auth = auth[len(k):]
		switch k {
		case "WPAPSK":
			si.WPA, si.AKMs = true, append(si.AKMs, "PSK")
		case "WPA2PSK":
			si.RSN, si.AKMs = true, append(si.AKMs, "PSK")
		case "WPA3PSK":
			si.RSN, si.AKMs = true, append(si.AKMs, "SAE")
		case "WPA", "WPA1":
			si.WPA, si.AKMs = true, append(si.AKMs, "802.1X")
		case "WPA2":
			si.RSN, si.AKMs = true, append(si.AKMs, "802.1X")
		case "WPA3", "WPA3-192":
			si.RSN, si.AKMs = true, append(si.AKMs, "802.1X-SHA256")
		case "OWE":
			si.RSN, si.AKMs = true, append(si.AKMs, "OWE")
		case "SHARED", "WEPAUTO":
			si.Privacy = true
		}
	}
	switch cipher {
	case "", "NONE":
	case "WEP":
		si.Privacy = true
	case "TKIPAES":
		si.Ciphers = []string{"TKIP", "AES"}
	default:
		si.Ciphers = []string{cipher}
	}
	// a WPA cipher with an AKM the driver does not name ("UNKNOW/AES": the
	// MT7603 has no SAE name) is a protected network: an RSN element
	// without a readable AKM, never Open
	if len(si.Ciphers) > 0 && !si.WPA && !si.RSN {
		si.RSN = true
	}
	if si.WPA || si.RSN {
		si.Privacy = true
	}
	return si
}
