// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
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
//   - Scan (the controller's `cmd scan` only) starts a fresh survey when
//     FreshScan is set, else it is unsupported.

// surveyKeep: how long an unchanged cached survey is still reported.
const surveyKeep = 10 * time.Minute

// surveySeen is a band's last survey table and when it was first seen.
type surveySeen struct {
	table string // the rows as printed
	at    time.Time
	bss   []apstate.BSS
}

// scanPoll: how often a fresh survey's table is read; scanSettle: how long
// it must stay the same to count as finished.
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
	table, err := c.readSurvey(ctx, main)
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

// Scan runs a fresh site survey of the band's radio (the controller's `cmd
// scan`; FreshScan only): `iwpriv <radio> set SiteSurvey=1`, then the table
// is read every scanPoll until it differs from the one before the scan and
// has stayed the same for scanSettle. The radio leaves its channel while
// the driver scans; Collect keeps its last reading meanwhile.
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
	before, err := c.readSurvey(ctx, main)
	if err != nil {
		return nil, err
	}
	c.scanning.Store(true)
	defer c.scanning.Store(false)
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
	if si.WPA || si.RSN {
		si.Privacy = true
	}
	return si
}
