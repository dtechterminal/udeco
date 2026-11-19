// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Roaming Assistant, done by the agent (docs/deco/features/
// roaming-assistant.md). The controller turns it on per WLAN and band
// (system_cfg wireless.N.btm_disassoc.status=enabled, .threshold=<dBm>;
// translate.WLANIntent.RoamAssist -> bcmwifi.SSID.RoamAssist), and a UAP
// does it in its driver (btm_disassoc / btm_dis_thld: an 802.11v BSS
// Transition Management request with Disassociation Imminent to a client
// below the threshold). Here the inform loop watches each reading:
//
//   - a client on such a BSS qualifies once its signal has stayed below the
//     threshold for roamBelow readings in a row and at least
//     timing.roamSustain (one weak reading is noise, not a client at the
//     edge);
//   - the candidates are BSSes of the same SSID on OTHER APs that this
//     unit's scans heard within roamCandAge at the threshold plus
//     roamCandMargin or better (an AP this unit hears well is near enough
//     that a client at this unit's edge may well hear it better). Never one
//     of this unit's own BSSes, on any band: asking a client at -76 dBm on
//     the 5 GHz BSS to move to the same unit's 2.4 GHz BSS (live,
//     2026-11-19) only had the disassociation timer drop it, and it came
//     straight back to the 5 GHz BSS every few minutes;
//   - no candidate: no request, and the client is never disassociated;
//     logged once per client per roamNoCandLog;
//   - a candidate: one request (bcmwifi.RoamAssist, which also refuses a
//     client that does not advertise BSS transition). The client is not
//     asked again for roamHold. Still (or again) on the same BSS
//     roamJudge after the request and within roamReturn: it ignored the
//     request or the move did not hold, and the wait doubles each time up
//     to roamHoldMax; away for roamReturn: the backoff ends.
//
// At most roamPerRead requests per reading, weakest first; takeover mode
// only (hostapd is ours), not while memory is short.

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
	roamBelow        = 3                // readings in a row below the threshold, at least
	roamSustain      = time.Minute      // and below it for this long (timing.roamSustain)
	roamHold         = 10 * time.Minute // no second request to a client within this
	roamHoldMax      = 2 * time.Hour    // the longest wait after requests that did not help
	roamJudge        = time.Minute      // on the same BSS this long after a request: it did not move (timer ~10 s)
	roamReturn       = 30 * time.Minute // back on the same BSS within this: the move did not hold
	roamPerRead      = 2                // requests per reading at most
	roamDisassocTBTT = 100              // disassociation timer: 100 beacon intervals, about 10 s
	roamScanCands    = 4                // candidates taken from the scans at most
	roamCandMargin   = 10               // dB above the threshold a candidate must be heard at, at least
	roamCandAge      = 15 * time.Minute // scan sightings older than this are no candidates
	roamNoCandLog    = time.Hour        // "no candidate" logged once per client this often
	roamForget       = time.Hour        // a client's record goes when unseen this long (and not held)
)

// roamer is bcmwifi's Roaming Assistant primitive.
type roamer interface {
	RoamAssist(ctx context.Context, r bcmwifi.RoamRequest) error
}

// roamClient is one client's Roaming Assistant record.
type roamClient struct {
	since  time.Time // first reading of the current run below its threshold (zero: none)
	n      int       // readings in a row below its threshold
	seen   time.Time // last reading with it on this unit
	asked  time.Time // last request (zero: none)
	vif    string    // the BSS it was asked to leave
	left   bool      // a reading after the request did not have it on vif
	judged bool      // the last request's outcome is counted
	fails  int       // requests in a row it ignored or came back from
	hold   time.Time // no request before this
	noCand time.Time // "no candidate" last logged
}

// roamState belongs to the inform loop.
type roamState struct {
	c map[string]*roamClient // client MAC -> record
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
	weak           time.Duration // below the threshold this long
	to             []roamHeard
}

// ownBSS reports whether a BSSID is this unit's: one of the reading's
// radio or BSS addresses, or one of them with another first octet (the
// X20 derives its BSSIDs as locally administered variants, e.g.
// aa:a7:b9:3e:15:f8 and ba:a7:b9:3e:15:f8).
type ownBSS map[string]bool

func ownBSSes(s *apstate.Snapshot) ownBSS {
	own := ownBSS{}
	add := func(b string) {
		if b = strings.ToLower(b); len(b) == 17 {
			own[b], own["*"+b[2:]] = true, true
		}
	}
	add(s.MAC)
	for _, r := range s.Radios {
		add(r.BSSID)
		for _, v := range r.VAPs {
			add(v.BSSID)
		}
	}
	return own
}

func (o ownBSS) has(b string) bool {
	b = strings.ToLower(b)
	return o[b] || len(b) == 17 && o["*"+b[2:]]
}

// roamReading looks at one reading and asks the worker to send Roaming
// Assistant requests to the clients that qualify (loop goroutine).
func (a *agent) roamReading(s *apstate.Snapshot, now time.Time) {
	st := &a.roam
	if st.c == nil {
		st.c = map[string]*roamClient{}
	}
	where := map[string]string{} // client MAC -> the BSS it is on now
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			for _, c := range v.Stations {
				where[strings.ToLower(c.MAC)] = v.Iface
			}
		}
	}
	for m, c := range st.c {
		vif, here := where[m]
		if here {
			c.seen = now
		}
		a.roamJudge(m, c, vif, here, now)
		if !here && now.Sub(c.seen) > roamForget && !now.Before(c.hold) {
			delete(st.c, m)
		}
	}
	pol := a.policy.Load()
	rr, ok := a.wifi.(roamer)
	if !a.takeover.Load() || a.shed.Load() || pol == nil || len(pol.roam) == 0 || !ok {
		for _, c := range st.c {
			c.since, c.n = time.Time{}, 0
		}
		return
	}
	own := ownBSSes(s)
	weak := map[string]bool{}
	var cs []roamCand
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			band := vapBand(r, v)
			th, on := pol.roam[v.SSID+"|"+band]
			if !on || v.Iface == "" {
				continue
			}
			for _, sta := range v.Stations {
				m := strings.ToLower(sta.MAC)
				if sta.Signal == 0 || sta.Signal >= th {
					continue // no reading, or strong enough: the run ends below
				}
				weak[m] = true
				c := st.c[m]
				if c == nil {
					c = &roamClient{seen: now}
					st.c[m] = c
				}
				if c.since.IsZero() {
					c.since = now
				}
				c.n++
				if c.n < roamBelow || now.Sub(c.since) < a.t.roamSustain || now.Before(c.hold) {
					continue
				}
				to := a.scans.sameESS(v.SSID, own, th+roamCandMargin, now, roamScanCands)
				if len(to) == 0 {
					if c.noCand.IsZero() || now.Sub(c.noCand) >= roamNoCandLog {
						c.noCand = now
						a.logf("roaming assistant: %s at %d dBm (threshold %d) on %s: no other AP with %q heard at %d dBm or better: left alone",
							m, sta.Signal, th, v.Iface, v.SSID, th+roamCandMargin)
					}
					continue
				}
				cs = append(cs, roamCand{v.Iface, m, sta.Signal, th, band, now.Sub(c.since), to})
			}
		}
	}
	for m, c := range st.c {
		if !weak[m] {
			c.since, c.n = time.Time{}, 0 // strong again, gone, or no reading: start over
		}
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].signal < cs[j].signal }) // weakest first
	for i, c := range cs {
		if i == roamPerRead {
			break
		}
		rc := st.c[c.mac]
		rc.asked, rc.vif, rc.left, rc.judged = now, c.vif, false, false
		rc.hold = now.Add(roamHold)
		rc.since, rc.n = time.Time{}, 0
		if a.steer.last != nil {
			// no band steering back onto the band it is leaving for a while
			a.steer.last[c.mac] = now
		}
		var to []bcmwifi.Neighbor
		for _, h := range c.to {
			to = append(to, h.n)
		}
		req := bcmwifi.RoamRequest{Vif: c.vif, MAC: c.mac, Candidates: to, DisassocTBTT: roamDisassocTBTT}
		a.submit("roam "+c.mac, func(ctx context.Context) {
			err := rr.RoamAssist(ctx, req)
			switch {
			case errors.Is(err, bcmwifi.ErrNoBTM):
				a.logf("roaming assistant: %s at %d dBm on %s does not support BSS transition: left alone", c.mac, c.signal, c.vif)
			case errors.Is(err, bcmwifi.ErrNoCandidate):
				a.logf("roaming assistant: %s at %d dBm on %s: no usable candidate: left alone", c.mac, c.signal, c.vif)
			case err != nil:
				a.logf("roaming assistant %s: %v", c.mac, err)
			default:
				a.logf("roaming assistant: asked %s (%d dBm < %d dBm on %s %s for %s) to move to %s",
					c.mac, c.signal, c.thresh, c.band, c.vif, c.weak.Round(time.Second), heardList(c.to))
			}
		})
	}
}

// roamJudge counts the outcome of a client's last request: on the same BSS
// roamJudge after it (it ignored the request, or came back) doubles the
// wait for the next one; away for roamReturn ends the backoff.
func (a *agent) roamJudge(mac string, c *roamClient, vif string, here bool, now time.Time) {
	if c.asked.IsZero() || c.judged {
		return
	}
	since := now.Sub(c.asked)
	if !here || vif != c.vif {
		c.left = true
		if since >= roamReturn {
			c.judged, c.fails = true, 0
		}
		return
	}
	if since < roamJudge {
		return
	}
	c.judged = true
	if since >= roamReturn {
		c.fails = 0 // back on it, but long after: the move held
		return
	}
	c.fails++
	c.hold = c.asked.Add(min(roamHold<<min(c.fails, 8), roamHoldMax))
	what := "stayed on"
	if c.left {
		what = "came back to"
	}
	a.logf("roaming assistant: %s %s %s after the request: next one not before %s", mac, what, vif, c.hold.Format(time.TimeOnly))
}

// roamHeard is a candidate and how loud this unit heard it.
type roamHeard struct {
	n      bcmwifi.Neighbor
	signal int
}

// sameESS returns up to max BSSes with this SSID, not this unit's own, that
// the scans heard at minSignal dBm or better within roamCandAge,
// strongest first.
func (sc *scanner) sameESS(ssid string, own ownBSS, minSignal int, now time.Time, max int) []roamHeard {
	if sc == nil || ssid == "" {
		return nil
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	var hs []roamHeard
	got := map[string]bool{}
	for band, res := range sc.results {
		for _, b := range res.BSS {
			m := strings.ToLower(b.BSSID)
			seen := b.Seen
			if seen.IsZero() {
				seen = res.Time
			}
			if b.SSID != ssid || own.has(m) || got[m] || b.Channel <= 0 || b.Signal == 0 || b.Signal < minSignal ||
				now.Sub(seen) > roamCandAge {
				continue
			}
			got[m] = true
			bb := res.Band
			if bb == "" {
				bb = band
			}
			hs = append(hs, roamHeard{bcmwifi.Neighbor{BSSID: b.BSSID, Band: bb, Channel: b.Channel}, b.Signal})
		}
	}
	sort.Slice(hs, func(i, j int) bool {
		if hs[i].signal != hs[j].signal {
			return hs[i].signal > hs[j].signal
		}
		return hs[i].n.BSSID < hs[j].n.BSSID
	})
	if len(hs) > max {
		hs = hs[:max]
	}
	return hs
}

func heardList(hs []roamHeard) string {
	var p []string
	for _, h := range hs {
		p = append(p, fmt.Sprintf("%s (%s ch %d, heard at %d dBm)", h.n.BSSID, h.n.Band, h.n.Channel, h.signal))
	}
	return strings.Join(p, ", ")
}

var _ roamer = (*bcmwifi.Applier)(nil)
