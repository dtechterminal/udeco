// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/rf"
	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

// chanspec is a parsed Broadcom chanspec: control channel and width.
type chanspec struct {
	Ctrl  int
	Width int // 20, 40, 80, 160
}

// String renders c the way wl accepts it: "6", "1l", "6u", "36/80".
func (c chanspec) String() string {
	switch c.Width {
	case 40:
		if c.Ctrl <= 14 {
			if c.Ctrl <= 5 {
				return fmt.Sprintf("%dl", c.Ctrl)
			}
			return fmt.Sprintf("%du", c.Ctrl)
		}
		// 5 GHz 40 MHz pairs are 36+40, 44+48, ..., 149+153, 157+161: the
		// lower channel of a pair has an odd 20 MHz index.
		idx := c.Ctrl / 4
		if c.Ctrl >= 149 {
			idx = (c.Ctrl - 1) / 4
		}
		if idx%2 == 1 {
			return fmt.Sprintf("%dl", c.Ctrl)
		}
		return fmt.Sprintf("%du", c.Ctrl)
	case 80, 160:
		return fmt.Sprintf("%d/%d", c.Ctrl, c.Width)
	}
	return strconv.Itoa(c.Ctrl)
}

// parseChanspec reads wl's chanspec output, e.g. "44/80 (0xe22a)", "2l
// (0x1804)", "6 (0x1006)".
func parseChanspec(s string) (chanspec, error) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return chanspec{}, fmt.Errorf("empty chanspec")
	}
	// the first field is the text form, the rest its hex form
	ch, width, err := wl.ParseChanspecText(f[0])
	if err != nil {
		return chanspec{}, fmt.Errorf("chanspec %q: %w", f[0], err)
	}
	return chanspec{Ctrl: ch, Width: width}, nil
}

// maxWidth is the widest channel bcmwifi sets, in MHz: a wider one the
// controller asks for runs at this width, with a note (radioNotes).
const maxWidth = 80

// DefaultWidth is the channel width in MHz of a radio the controller gives
// none: 20 on 2.4 GHz, 80 on 5 GHz (0 for a band this unit has not).
func DefaultWidth(band string) int {
	return map[string]int{"ng": 20, "na": maxWidth}[band]
}

// desiredChanspec returns the chanspec to set for r on band, given the live
// one. ok=false means keep the live chanspec. Notes report clamps.
//
// bc, when not nil, is the driver's channel list for the country that will
// be in force (wl.Caps from `wl chanspecs`): a channel outside it is never
// set (the driver would refuse it, or the apply would fail verification and
// roll back). Such a channel falls back to auto (the live channel), and a
// width the channel does not allow is narrowed (80 -> 40 -> 20), with a note.
func desiredChanspec(band string, r Radio, live chanspec, bc *wl.BandCaps) (c chanspec, ok bool, notes []string) {
	width := r.Width
	switch {
	case width == 0:
		width = DefaultWidth(band)
	case width > maxWidth:
		width = maxWidth
	}
	if band == "ng" && width > 40 {
		width = 40
	}
	ch := r.Channel
	if ch == 0 {
		// Auto: acsd2 is stopped and the agent does no channel selection, so
		// keep the live channel and apply only an explicit width change.
		if r.Width == 0 || live.Ctrl == 0 || live.Width == width {
			return live, false, nil
		}
		ch = live.Ctrl
	}
	switch band {
	case "ng":
		if ch < 1 || ch > 13 {
			return live, false, []string{fmt.Sprintf("radio ng: channel %d invalid, keeping %s", ch, live)}
		}
	case "na":
		valid := ch >= 36 && ch <= 144 && ch%4 == 0 || ch >= 149 && ch <= 177 && (ch-149)%4 == 0
		if !valid {
			return live, false, []string{fmt.Sprintf("radio na: channel %d invalid, keeping %s", ch, live)}
		}
		if rf.Only20MHz(band, ch) && width > 20 {
			notes = append(notes, "radio na: channel 165 is 20 MHz only")
			width = 20
		}
	}
	if bc != nil && len(bc.Channels) > 0 {
		allowed := func(w int) bool {
			if bc.MaxListedWidth > 0 && w > bc.MaxListedWidth {
				return true // not listable at the bw_cap the caps were read at (wl.BandCaps.MaxListedWidth)
			}
			return slices.Contains(bc.Channels[w], ch)
		}
		if dfsChannel(band, ch) && !bc.DFS || !allowed(20) {
			if r.Channel == 0 { // the live channel itself is not listed: leave it
				return live, false, append(notes, fmt.Sprintf("radio %s: live channel %d is not in the driver's channel list, left as it is", band, ch))
			}
			notes = append(notes, fmt.Sprintf("radio %s: channel %d is not allowed by the driver in this country: auto", band, ch))
			auto := r
			auto.Channel = 0
			c, ok, n := desiredChanspec(band, auto, live, bc)
			return c, ok, append(notes, n...)
		}
		if w := width; !allowed(w) {
			for w > 20 && !allowed(w) {
				w /= 2
			}
			notes = append(notes, fmt.Sprintf("radio %s: channel %d is not allowed at %d MHz here: %d MHz", band, ch, width, w))
			width = w
		}
	}
	c = chanspec{Ctrl: ch, Width: width}
	return c, c != live, notes
}

// dfsChannel reports a 5 GHz DFS channel (52-144).
func dfsChannel(band string, ch int) bool { return rf.IsDFS(band, ch) }

// bwCap is the wl bw_cap bitmap allowing up to width.
func bwCap(width int) int { return wl.BWCap(width) }

// bandArg is wl's band argument for band: every radio that is not the
// 2.4 GHz one is the 5 GHz one.
func bandArg(band string) string {
	if band == rf.Band2G {
		return rf.Legacy(rf.Band2G)
	}
	return rf.Legacy(rf.Band5G)
}

// parseTargetMax reads "Maximum Tx Power Target (chanspec:0xe22a):\t23.50  23.50".
func parseTargetMax(s string) float64 {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return 0
	}
	best := 0.0
	for _, f := range strings.Fields(s[i+1:]) {
		if v, err := strconv.ParseFloat(f, 64); err == nil && v > best {
			best = v
		}
	}
	return best
}

// countryRev is TP-Link's regrev per country (tplink_brcm.sh COUNTRYCODE_*).
// Other countries are set without a rev, letting the driver choose.
//
// IN/288: the driver's IN/0 table has no 80 MHz chanspec at all (verified
// on .205 2026-11-19, the reason for the driver_country override); IN/288
// is the India table with 80 MHz and the DFS band. The Bedroom X20 took
// `wl country IN/288` with the radio down (2026-11-20: "IN (IN/288)
// INDIA", 80 MHz blocks 36/52/100/116/132/149). A driver that refuses it
// gets countryFallback.
var countryRev = map[string]int{"US": 0, "CA": 2, "JP": 0, "KR": 1, "AU": 8, "DE": 0, "IN": 288}

// countryFallback is set (without a rev: the driver picks one) when the
// driver refuses countryRev's rev for the country.
var countryFallback = map[string]string{"IN": "IN"}

// NormCountry is a driver country code as wl takes it: two-letter codes
// in upper case, Broadcom's '#' tables ("#a") as they are, since wl tells
// "#a" and "#A" apart.
func NormCountry(cc string) string {
	cc = strings.TrimSpace(cc)
	if strings.HasPrefix(cc, "#") {
		return cc
	}
	return strings.ToUpper(cc)
}

// NoRadarCountry: a driver country that marks no 5 GHz channel radar-
// sensitive. Under Broadcom's all-channels table "#a" the X20 offers
// 52-144 with Wi-Fi 6 rates at 23.5 dBm, but `wl chan_info 100` reads
// only "5G Band" (IN/288: "RADAR Sensitive, Passive"), so the driver runs
// no CAC and no in-service monitoring there: dfs_status stayed IDLE on
// 100/80 (Bedroom and Owner's Room, 2026-11-20).
func NoRadarCountry(cc string) bool { return cc == "#a" }

// ValidCountry reports whether cc, as a config gives it (spaces around it
// do not count), is a driver country the agent sets: a two-letter code in
// either case, or a '#' table it knows (NoRadarCountry; "#A" is another
// table to wl, and not one of them).
func ValidCountry(cc string) bool {
	cc = strings.TrimSpace(cc)
	if NoRadarCountry(cc) {
		return true
	}
	return len(cc) == 2 && strings.IndexFunc(cc, func(r rune) bool { return (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') }) < 0
}

// weatherRadar: a 5 GHz chanspec that covers 5600-5650 MHz (channels
// 120-128), the band weather radars use. Refused under a NoRadarCountry.
func weatherRadar(cs chanspec) bool {
	for _, ch := range subChannels(cs) {
		if ch >= 120 && ch <= 128 {
			return true
		}
	}
	return false
}

// country is a parsed wl country: code and rev (-1 = unknown).
type country struct {
	Code string
	Rev  int
}

// parseCountry reads "US (US/0) UNITED STATES".
func parseCountry(s string) country {
	code, rev := wl.ParseCountry(s)
	return country{Code: code, Rev: rev}
}

// countryArg is the wl country argument for code, and whether live already
// matches it.
func countryArg(code string, live country) (arg string, same bool) {
	code = NormCountry(code)
	if rev, ok := countryRev[code]; ok {
		return fmt.Sprintf("%s/%d", code, rev), live.Code == code && live.Rev == rev
	}
	return code, live.Code == code
}

// parseIntOut reads the first token of a wl getter as an int ("128 (0x80)",
// "0x7", "0").
func parseIntOut(s string) (int, error) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0, fmt.Errorf("empty")
	}
	v, err := strconv.ParseInt(f[0], 0, 64)
	return int(v), err
}
