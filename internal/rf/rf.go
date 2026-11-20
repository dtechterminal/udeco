// SPDX-License-Identifier: GPL-2.0-or-later

// Package rf holds the radio facts every backend shares: UniFi's band
// names, channel and frequency arithmetic, the 5 GHz channel blocks, the
// DFS range, the 20 MHz operating classes and the stand-in noise floor. It imports nothing from this
// module, so any package may use it, and it is the one place these facts
// are written down. A vendor's own limits (the channels a driver or a
// country allows, a chip's 2.4 GHz 40 MHz sideband rule, the MediaTek
// unit's DFS subset) stay with that backend.
package rf

import (
	"slices"
	"strings"
)

// UniFi's band names: a radio_table row's "radio", system_cfg's
// stamgr.N.radio, the keys of every per-band map in this module.
const (
	Band2G = "ng"
	Band5G = "na"
	Band6G = "6e"
)

// Bands are the bands of the units the agent runs on, in the order radios
// are planned, listed and reported: 2.4 GHz first. Each call returns a new
// slice.
func Bands() []string { return []string{Band2G, Band5G} }

// legacy pairs a band with its older name: OpenWrt's UCI band, `wl`'s band
// argument, a system_cfg per-band key.
var legacy = []struct{ band, old string }{
	{Band2G, "2g"},
	{Band5G, "5g"},
	{Band6G, "6g"},
}

// Legacy is band's older name (ng -> 2g, na -> 5g, 6e -> 6g); "" for
// anything else.
func Legacy(band string) string {
	for _, l := range legacy {
		if l.band == band {
			return l.old
		}
	}
	return ""
}

// FromLegacy is the reverse of Legacy (2g -> ng, 5g -> na, 6g -> 6e); ""
// for anything else.
func FromLegacy(old string) string {
	for _, l := range legacy {
		if l.old == old {
			return l.band
		}
	}
	return ""
}

// Norm is the band a loosely written name means: ng or na for the names
// and aliases of 2.4 and 5 GHz in any case, with spaces around them
// ignored; "" for anything else (6 GHz included: no unit here has it).
func Norm(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case Band2G, "2g", "2.4g", "2ghz", "2.4ghz":
		return Band2G
	case Band5G, "5g", "5ghz":
		return Band5G
	}
	return ""
}

// IsDFS reports a 5 GHz channel in the DFS range (52-144). Which of them
// a unit may use is its driver's and country's matter.
func IsDFS(band string, ch int) bool { return band == Band5G && ch >= 52 && ch <= 144 }

// ChanFreq is the centre frequency in MHz of 20 MHz channel ch: on 2.4 GHz
// 2407 + 5*ch (channel 14 is 2484), on any other band 5000 + 5*ch.
func ChanFreq(band string, ch int) int {
	if band == Band2G {
		if ch == 14 {
			return 2484
		}
		return 2407 + 5*ch
	}
	return 5000 + 5*ch
}

// blocks5G lists the first (lowest) 20 MHz channel of every 5 GHz block of
// a width.
var blocks5G = map[int][]int{
	40:  {36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157, 165, 173},
	80:  {36, 52, 100, 116, 132, 149, 165},
	160: {36, 100, 149},
}

// Blocks5G are the first channels of the 5 GHz blocks of width MHz (40,
// 80 or 160; nil for any other width). Each call returns a new slice.
func Blocks5G(width int) []int { return slices.Clone(blocks5G[width]) }

// BlockStart is the first channel of the 5 GHz block of width MHz that
// holds channel ch, from the Blocks5G table: 0 when no block of that width
// holds it.
func BlockStart(ch, width int) int {
	for _, f := range blocks5G[width] {
		if ch >= f && ch < f+width/5 {
			return f
		}
	}
	return 0
}

// SubChannels are the 20 MHz channels of the 5 GHz block of width MHz
// around channel ch, lowest first, by arithmetic: blocks are aligned from
// channel 36, and from 149 for the upper band. A width below 20 counts as
// 20. Unlike BlockStart it answers for any channel; for a channel in a
// Blocks5G block the two agree (rf_test.go).
func SubChannels(ch, width int) []int {
	if width < 20 {
		width = 20
	}
	n := width / 20
	base := 36
	if ch >= 149 {
		base = 149
	}
	first := ch - (ch-base)%(n*4)
	out := make([]int, n)
	for i := range out {
		out[i] = first + 4*i
	}
	return out
}

// Only20MHz reports a channel served at 20 MHz only: 5 GHz channel 165
// (its wider blocks reach into 5.9 GHz, which no unit here uses).
func Only20MHz(band string, ch int) bool { return band == Band5G && ch == 165 }

// NonOverlap24 are the 2.4 GHz channels automatic channel selection
// chooses from: the three that do not overlap. Each call returns a new
// slice.
func NonOverlap24() []int { return []int{1, 6, 11} }

// opClasses20 are the IEEE 802.11 global operating classes of the 20 MHz
// primary channels (802.11-2020 Annex E, Table E-4): each class's band,
// first and last channel, all channels between them 5 MHz * step apart.
// Where two classes list a channel (149-161 are in both 124 and 125), the
// first row, the one made for them, wins.
var opClasses20 = []struct {
	band                     string
	class, first, last, step int
}{
	{Band2G, 81, 1, 13, 1},
	{Band2G, 82, 14, 14, 1},
	{Band5G, 115, 36, 48, 4},
	{Band5G, 118, 52, 64, 4},
	{Band5G, 121, 100, 144, 4},
	{Band5G, 124, 149, 161, 4},
	{Band5G, 125, 165, 177, 4},
}

// OpClass is the global operating class of 20 MHz primary channel ch on
// band, as an 802.11k neighbour report and an 802.11v BSS transition
// request's candidate list carry it: 2.4 GHz 1-13 81, 14 82; 5 GHz 36-48
// 115, 52-64 118, 100-144 121, 149-161 124, 165-177 125. 0 for any other
// channel (none of these classes has it, or band is not ng or na).
func OpClass(band string, ch int) int {
	for _, c := range opClasses20 {
		if c.band == band && ch >= c.first && ch <= c.last && (ch-c.first)%c.step == 0 {
			return c.class
		}
	}
	return 0
}

// ChanBand is the band a primary channel number lies in when no band is
// known (a scanned BSS, a frequency's channel): 1-14 ng, 32-177 na, ""
// for anything else. No unit here has a 6 GHz radio, whose channel
// numbers would overlap these.
func ChanBand(ch int) string {
	switch {
	case ch >= 1 && ch <= 14:
		return Band2G
	case ch >= 32 && ch <= 177:
		return Band5G
	}
	return ""
}

// NoiseFloorDBm stands in for a noise floor no driver reading gives. The
// controller's RSSI is signal minus noise, so a signal of NoiseFloorDBm or
// less is inaudible.
const NoiseFloorDBm = -95
