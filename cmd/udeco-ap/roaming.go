// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Roaming Assistant, done by the agent (docs/deco/features/
// roaming-assistant.md). The controller turns it on per WLAN and band
// (system_cfg wireless.N.btm_disassoc.status=enabled, .threshold=<dBm>;
// translate.WLANIntent.RoamAssist -> bcmwifi.SSID.RoamAssist), and a UAP
// does it in its driver (btm_disassoc / btm_dis_thld). Here the inform loop
// watches each reading: a station on such a BSS whose signal stays below the
// threshold for roamBelow readings in a row gets one 802.11v BSS Transition
// Management request with Disassociation Imminent and a disassociation
// timer (bcmwifi.RoamAssist), naming as candidates the same SSID's other
// BSSes on this AP (the other band) and the BSSes with that SSID the
// unit's scans heard (the site's other APs). A station that does not
// advertise BSS transition, or one with no candidate to go to, is left
// alone. Rate-limited per station; takeover mode only (hostapd is ours).

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

const (
	roamBelow        = 2               // readings in a row below the threshold before a request
	roamEvery        = 5 * time.Minute // at most one request per station this often
	roamPerRead      = 2               // requests per reading at most
	roamDisassocTBTT = 100             // disassociation timer: 100 beacon intervals, about 10 s
	roamScanCands    = 4               // candidates taken from the scans at most
)

// roamer is bcmwifi's Roaming Assistant primitive.
type roamer interface {
	RoamAssist(ctx context.Context, r bcmwifi.RoamRequest) error
}

// roamState belongs to the inform loop.
type roamState struct {
	below map[string]int       // station MAC -> readings in a row below its threshold
	last  map[string]time.Time // station MAC -> last request (or decision to leave it alone)
}

// roamPolicy is the live Wi-Fi's Roaming Assistant thresholds by
// "SSID|band" (enabled SSIDs on the bands they broadcast on).
func roamPolicy(d bcmwifi.Desired) map[string]int {
	out := map[string]int{}
	for _, s := range d.SSIDs {
		if !s.Enabled || s.SSID == "" {
			continue
		}
		for _, b := range s.Bands {
			if t, ok := s.RoamAssist[b]; ok && t < 0 {
				out[s.SSID+"|"+b] = t
			}
		}
	}
	return out
}

type roamCand struct {
	vif, mac       string
	signal, thresh int
	band           string
	to             []bcmwifi.Neighbor
}

// roamReading looks at one reading and asks the worker to send Roaming
// Assistant requests to the stations that qualify (loop goroutine).
func (a *agent) roamReading(s *apstate.Snapshot, now time.Time) {
	st := &a.roam
	if st.below == nil {
		st.below, st.last = map[string]int{}, map[string]time.Time{}
	}
	for m, t := range st.last {
		if now.Sub(t) > roamEvery {
			delete(st.last, m)
		}
	}
	pol := a.policy.Load()
	rr, ok := a.wifi.(roamer)
	if !a.takeover.Load() || a.shed.Load() || pol == nil || len(pol.roam) == 0 || !ok {
		clear(st.below)
		return
	}
	own := map[string]bool{}
	ess := map[string][]bcmwifi.Neighbor{} // SSID -> this AP's BSSes of it
	for _, r := range s.Radios {
		if r.BSSID != "" {
			own[strings.ToLower(r.BSSID)] = true
		}
		for _, v := range r.VAPs {
			if v.BSSID == "" {
				continue
			}
			own[strings.ToLower(v.BSSID)] = true
			if v.SSID != "" && r.Channel > 0 {
				ess[v.SSID] = append(ess[v.SSID], bcmwifi.Neighbor{BSSID: v.BSSID, Band: vapBand(r, v), Channel: r.Channel})
			}
		}
	}
	seen := map[string]bool{}
	var cs []roamCand
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			band := vapBand(r, v)
			th, on := pol.roam[v.SSID+"|"+band]
			if !on || v.Iface == "" {
				continue
			}
			for _, c := range v.Stations {
				if c.Signal == 0 {
					continue // no reading
				}
				seen[c.MAC] = true
				if c.Signal >= th {
					delete(st.below, c.MAC)
					continue
				}
				st.below[c.MAC]++
				if _, recent := st.last[c.MAC]; recent || st.below[c.MAC] < roamBelow {
					continue
				}
				var to []bcmwifi.Neighbor
				for _, o := range ess[v.SSID] {
					if !strings.EqualFold(o.BSSID, v.BSSID) {
						to = append(to, o)
					}
				}
				to = append(to, a.scans.sameESS(v.SSID, own, roamScanCands)...)
				cs = append(cs, roamCand{v.Iface, c.MAC, c.Signal, th, band, to})
			}
		}
	}
	for m := range st.below {
		if !seen[m] {
			delete(st.below, m) // gone, or no reading: start over
		}
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].signal < cs[j].signal }) // weakest first
	for i, c := range cs {
		if i == roamPerRead {
			break
		}
		st.last[c.mac] = now
		delete(st.below, c.mac)
		if a.steer.last != nil {
			// no band steering back onto the band it is leaving for a while
			a.steer.last[c.mac] = now
		}
		if len(c.to) == 0 {
			a.logf("roaming assistant: %s at %d dBm (threshold %d) on %s: no other BSS of its SSID known, left alone", c.mac, c.signal, c.thresh, c.vif)
			continue
		}
		req := bcmwifi.RoamRequest{Vif: c.vif, MAC: c.mac, Candidates: c.to, DisassocTBTT: roamDisassocTBTT}
		a.submit("roam "+c.mac, func(ctx context.Context) {
			err := rr.RoamAssist(ctx, req)
			switch {
			case errors.Is(err, bcmwifi.ErrNoBTM):
				a.logf("roaming assistant: %s at %d dBm on %s does not support BSS transition: left alone", c.mac, c.signal, c.vif)
			case err != nil:
				a.logf("roaming assistant %s: %v", c.mac, err)
			default:
				a.logf("roaming assistant: asked %s (%d dBm < %d dBm on %s) to move to %s", c.mac, c.signal, c.thresh, c.band, neighborList(c.to))
			}
		})
	}
}

// sameESS returns up to max BSSes with this SSID that the scans heard and
// that are not this AP's own, strongest first.
func (sc *scanner) sameESS(ssid string, own map[string]bool, max int) []bcmwifi.Neighbor {
	if sc == nil || ssid == "" {
		return nil
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	type heard struct {
		n      bcmwifi.Neighbor
		signal int
	}
	var hs []heard
	got := map[string]bool{}
	for band, res := range sc.results {
		for _, b := range res.BSS {
			m := strings.ToLower(b.BSSID)
			if b.SSID != ssid || own[m] || got[m] || b.Channel <= 0 {
				continue
			}
			got[m] = true
			bb := res.Band
			if bb == "" {
				bb = band
			}
			hs = append(hs, heard{bcmwifi.Neighbor{BSSID: b.BSSID, Band: bb, Channel: b.Channel}, b.Signal})
		}
	}
	sort.Slice(hs, func(i, j int) bool {
		if hs[i].signal != hs[j].signal {
			return hs[i].signal > hs[j].signal
		}
		return hs[i].n.BSSID < hs[j].n.BSSID
	})
	var out []bcmwifi.Neighbor
	for i, h := range hs {
		if i == max {
			break
		}
		out = append(out, h.n)
	}
	return out
}

func neighborList(ns []bcmwifi.Neighbor) string {
	var p []string
	for _, n := range ns {
		p = append(p, fmt.Sprintf("%s (%s ch %d)", n.BSSID, n.Band, n.Channel))
	}
	return strings.Join(p, ", ")
}

var _ roamer = (*bcmwifi.Applier)(nil)
