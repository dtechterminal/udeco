// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// Auto channel (docs/deco/features/auto-channel.md). A radio the
// controller leaves on auto gets one channel picked when a provision
// restarts a radio anyway (the takeover at boot, a channel, width or
// country change): never periodically, and never a restart of its own
// (TP-Link's acsd2 is stopped, and bcmwifi keeps the live channel of an
// auto radio). The pick holds for the agent's run.
//
// Candidates are the driver's channels for the radio's width in the
// country (wl.Caps, the static list when the caps are for another
// country), on 2.4 GHz only 1, 6 and 11, on 5 GHz no DFS channel (a CAC
// and radar moves are for a channel the controller chose), never one in
// the controller's radio.N.blklst. Each is scored by the neighbours its
// span overlaps (signal above -95 dBm, louder counts more, from the last
// neighbour scan) plus the spectrum table's utilization of its 20 MHz
// channels (the live table, else the one saved on flash); the lowest
// wins, a tie keeps the live channel, then the lowest channel.

// staticChannels are the candidates without usable caps.
var staticChannels = map[string][]int{"ng": {1, 6, 11}, "na": {36, 40, 44, 48, 149, 153, 157, 161}}

// pickChannel picks band's channel (0 with a note when none qualifies).
func pickChannel(band string, allowed []int, blocked map[int]bool, width int, bss []apstate.BSS, util map[int]int, cur int) (int, string) {
	var cand []int
	for _, ch := range allowed {
		switch {
		case blocked[ch]:
		case band == "ng" && ch != 1 && ch != 6 && ch != 11:
		case band == "na" && ch >= 52 && ch <= 144:
		default:
			cand = append(cand, ch)
		}
	}
	slices.Sort(cand)
	cand = slices.Compact(cand)
	if len(cand) == 0 {
		return 0, fmt.Sprintf("auto channel: no %s channel left (allowed %v, blocked %v): the live one kept", band, allowed, keys(blocked))
	}
	if band == "ng" || width < 20 {
		width = 20
	}
	best, bestScore := 0, 0
	var why string
	for _, ch := range cand {
		lo, hi := span(band, ch, width)
		score := 0
		for _, b := range bss {
			if b.Signal <= -95 {
				continue
			}
			w, cf := b.Width, b.CenterFreq
			if w == 0 {
				w = 20
			}
			if cf == 0 {
				cf = b.Freq
			}
			if cf-w/2 < hi && cf+w/2 > lo {
				score += b.Signal + 95
			}
		}
		for _, c := range sub20(band, ch, width) {
			score += util[c]
		}
		if best == 0 || score < bestScore || score == bestScore && ch == cur {
			best, bestScore = ch, score
			why = fmt.Sprintf("auto channel %s: %d (score %d of %d candidates)", band, ch, score, len(cand))
		}
	}
	return best, why
}

// span is the frequency range (MHz) a channel of width covers.
func span(band string, ch, width int) (lo, hi int) {
	if band == "ng" {
		f := 2407 + 5*ch
		return f - 10, f + 10
	}
	s := sub20(band, ch, width)
	return 5000 + 5*s[0] - 10, 5000 + 5*s[len(s)-1] + 10
}

// sub20 are the 20 MHz channels a 5 GHz channel of width covers (blocks
// aligned from 36 and 149); 2.4 GHz: the channel itself.
func sub20(band string, ch, width int) []int {
	if band == "ng" || width <= 20 {
		return []int{ch}
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

func keys(m map[int]bool) []int {
	var out []int
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// channelData is the band's neighbours from the last scan and its 20 MHz
// utilization from the spectrum table (live, else the saved one).
func (sc *scanner) channelData(band string) ([]apstate.BSS, map[int]int) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	var bss []apstate.BSS
	if res, ok := sc.results[band]; ok {
		bss = res.BSS
	}
	util := map[int]int{}
	if r := sc.runners[band]; r != nil {
		if st := r.Status(); !st.TableTime.IsZero() {
			for _, row := range st.Rows[20] {
				util[row.Channel] = row.Utilization
			}
			return bss, util
		}
	}
	if t := sc.saved[band]; t != nil {
		for _, row := range t.Rows[20] {
			util[row.Channel] = row.Utilization
		}
	}
	return bss, util
}

// autoChannels gives each enabled auto radio of d its picked channel
// (kept from an earlier pick while it still qualifies). Worker goroutine.
func (a *agent) autoChannels(ctx context.Context, d bcmwifi.Desired, in translate.Intent) (bcmwifi.Desired, []string) {
	if a.cfg.jio() {
		return d, nil
	}
	caps, err := a.o.col.Caps(ctx)
	usable := err == nil && (d.Country == "" || strings.EqualFold(caps.Country, d.Country))
	var notes []string
	out := d
	out.Radios = map[string]bcmwifi.Radio{}
	for band, r := range d.Radios {
		out.Radios[band] = r
		if !r.Enabled || r.Channel != 0 {
			continue
		}
		width := r.Width
		if width == 0 {
			width = map[string]int{"ng": 20, "na": 80}[band]
		}
		allowed := staticChannels[band]
		if b, ok := caps.Bands[band]; usable && ok {
			if l := b.Channels[width]; len(l) > 0 {
				allowed = l
			} else if l := b.Channels[20]; len(l) > 0 {
				allowed = l
			}
		}
		blocked := map[int]bool{}
		for _, c := range in.Radios[band].Blocked {
			blocked[c] = true
		}
		if ch := a.autoPick[band]; ch != 0 && slices.Contains(allowed, ch) && !blocked[ch] {
			r.Channel = ch
			out.Radios[band] = r
			continue
		}
		bss, util := a.scans.channelData(band)
		cur := 0
		if lc, ok := a.wifi.(interface{ LiveChannel(string) int }); ok {
			cur = lc.LiveChannel(band)
		}
		ch, why := pickChannel(band, allowed, blocked, width, bss, util, cur)
		notes = append(notes, why)
		if ch == 0 {
			continue
		}
		if a.autoPick == nil {
			a.autoPick = map[string]int{}
		}
		a.autoPick[band] = ch
		r.Channel = ch
		out.Radios[band] = r
	}
	return out, notes
}
