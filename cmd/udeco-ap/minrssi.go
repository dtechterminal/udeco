// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Minimum RSSI for connected clients (docs/deco/features/min-rssi.md).
//
// The controller sends a radio's minimum RSSI as stamgr.N.minrssi
// (translate.RadioIntent.MinRSSI -> bcmwifi.Radio.MinRSSI). A UniFi AP's
// station manager (stamgr) drops a client that stays below it. On the
// Deco, hostapd's rssi_reject_assoc_rssi (written by bcmwifi) is most
// likely never checked: association runs in the driver (driver SME), not
// through hostapd's handle_assoc. So the inform loop does it:
//
//   - a client of a BSS on a band with a minimum qualifies after
//     minRSSIBelow readings in a row below it (a stale reading, the last
//     one again, is no new look and does not count);
//   - first it is asked to leave: an 802.11v BSS transition request with
//     Disassociation Imminent (bcmwifi.RoamAssist, minRSSIDisassocTBTT),
//     naming the other APs of the SSID this unit's scans heard at the
//     minimum or better (never this unit's own BSSes);
//   - still (or again) on that BSS minRSSIKickAfter later, or when there
//     was no candidate, or the client does not do BSS transition: it is
//     kicked with a short ban on that BSS (bcmwifi.TempDeny: the driver MAC
//     filter, which also hides the BSS from its probes, and a deauth), and
//     the ban is lifted after minRSSIBan; an allow-list SSID cannot take a
//     ban, so it gets a plain kick;
//   - then it is left alone for minRSSIHold;
//   - its sta_leave carries assoc_status 16 (KICKED_DUE_TO_MIN_RSSI), as a
//     U6's does (staevents.go).
//
// Takeover mode only, not while memory is short; at most minRSSIPerRead
// actions per reading.

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

const (
	minRSSIBelow        = 3                // readings in a row below the minimum
	minRSSIKickAfter    = 20 * time.Second // still there this long after the request: kicked
	minRSSIBan          = 30 * time.Second // the kicked client's ban on that BSS
	minRSSIHold         = 2 * time.Minute  // no second action on a client within this
	minRSSIPerRead      = 2                // actions per reading at most
	minRSSIDisassocTBTT = 50               // disassociation timer: about 5 s
)

// tempDenier is bcmwifi's per-BSS ban (bcmwifi.TempDeny): a zero until
// lifts it.
type tempDenier interface {
	TempDeny(ctx context.Context, vif, mac string, until time.Time) error
}

var _ tempDenier = (*bcmwifi.Applier)(nil)

// minRSSIClient is one client's record.
type minRSSIClient struct {
	n     int       // readings in a row below the minimum
	vif   string    // the BSS it was asked to leave
	asked time.Time // the request (zero: none pending)
	kick  bool      // the request was refused: kick at the next look
	hold  time.Time // nothing before this
}

// tempBan is a ban to lift.
type tempBan struct {
	vif, mac string
	until    time.Time
}

// minRSSIState belongs to the inform loop, but for refused.
type minRSSIState struct {
	c    map[string]*minRSSIClient
	bans []tempBan

	mu      sync.Mutex
	refused []string // clients whose request bcmwifi refused (worker -> loop)
}

// minRSSIReading looks at one reading (loop goroutine).
func (a *agent) minRSSIReading(s *apstate.Snapshot, now time.Time) {
	st := &a.minr
	if st.c == nil {
		st.c = map[string]*minRSSIClient{}
	}
	td, canBan := a.wifi.(tempDenier)
	// bans that ended (a drop to observe mode: TP-Link's filters are back)
	keep := st.bans[:0]
	for _, b := range st.bans {
		if now.Before(b.until) {
			keep = append(keep, b)
			continue
		}
		if canBan && a.takeover.Load() {
			a.submit("unban "+b.mac, func(ctx context.Context) {
				if err := td.TempDeny(ctx, b.vif, b.mac, time.Time{}); err != nil && !errors.Is(err, bcmwifi.ErrNotOwned) && !errors.Is(err, bcmwifi.ErrAllowList) {
					a.logf("minimum RSSI: lifting the ban of %s on %s: %v", b.mac, b.vif, err)
				}
			})
		}
	}
	st.bans = keep
	st.mu.Lock()
	refused := st.refused
	st.refused = nil
	st.mu.Unlock()
	for _, m := range refused {
		if c := st.c[m]; c != nil && !c.asked.IsZero() {
			c.kick = true
		}
	}
	pol := a.policy.Load()
	if a.stale {
		return
	}
	if !a.takeover.Load() || a.shed.Load() || pol == nil || len(pol.minRSSI) == 0 || a.wifi == nil {
		clear(st.c)
		return
	}
	rr, canRoam := a.wifi.(roamer)
	own := ownBSSes(s)
	type cand struct {
		vif, ssid, mac string
		signal, th     int
	}
	var cs []cand
	seen := map[string]bool{}
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			th, on := pol.minRSSI[vapBand(r, v)]
			for _, sta := range v.Stations {
				m := strings.ToLower(sta.MAC)
				seen[m] = true
				c := st.c[m]
				if !on || v.Iface == "" || sta.Signal == 0 || sta.Signal >= th {
					if c != nil {
						c.n, c.asked, c.kick = 0, time.Time{}, false
					}
					continue
				}
				if c == nil {
					c = &minRSSIClient{}
					st.c[m] = c
				}
				c.n++
				if c.n >= minRSSIBelow && !now.Before(c.hold) {
					cs = append(cs, cand{v.Iface, v.SSID, m, sta.Signal, th})
				}
			}
		}
	}
	for m, c := range st.c {
		if !seen[m] && now.After(c.hold) {
			delete(st.c, m)
		}
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].signal < cs[j].signal }) // weakest first
	for i, k := range cs {
		if i == minRSSIPerRead {
			break
		}
		c := st.c[k.mac]
		pending := !c.asked.IsZero() && c.vif == k.vif
		if pending && !c.kick && now.Sub(c.asked) < minRSSIKickAfter {
			continue // asked to leave: give it the time
		}
		if !pending {
			var to []bcmwifi.Neighbor
			for _, h := range a.scans.sameESS(k.ssid, own, k.th, now, roamScanCands) {
				to = append(to, h.n)
			}
			if canRoam && len(to) > 0 {
				c.vif, c.asked, c.kick = k.vif, now, false
				a.sta.hint(k.mac, staLeaveMinRSSI, now.Add(staHintFor))
				a.logf("minimum RSSI: %s at %d dBm (minimum %d dBm) on %s: asked to move to %s", k.mac, k.signal, k.th, k.vif, neighborList(to))
				req := bcmwifi.RoamRequest{Vif: k.vif, MAC: k.mac, Candidates: to, DisassocTBTT: minRSSIDisassocTBTT}
				a.submit("min-rssi "+k.mac, func(ctx context.Context) {
					if err := rr.RoamAssist(ctx, req); err != nil {
						st.mu.Lock()
						st.refused = append(st.refused, req.MAC)
						st.mu.Unlock()
					}
				})
				continue
			}
		}
		// the kick, with a short ban on that BSS
		c.asked, c.kick, c.n, c.hold = time.Time{}, false, 0, now.Add(minRSSIHold)
		a.sta.hint(k.mac, staLeaveMinRSSI, now.Add(staHintFor))
		until := now.Add(minRSSIBan)
		a.logf("minimum RSSI: %s at %d dBm (minimum %d dBm) on %s: disconnected, kept off %s for %s", k.mac, k.signal, k.th, k.vif, k.vif, minRSSIBan)
		if canBan {
			st.bans = append(st.bans, tempBan{k.vif, k.mac, until})
		}
		vif, mac := k.vif, k.mac
		a.submit("min-rssi kick "+mac, func(ctx context.Context) {
			if canBan {
				err := td.TempDeny(ctx, vif, mac, until)
				if err == nil {
					return
				}
				if !errors.Is(err, bcmwifi.ErrAllowList) {
					a.logf("minimum RSSI: ban of %s on %s: %v (kicked without a ban)", mac, vif, err)
				}
			}
			if err := a.wifi.Kick(ctx, mac); err != nil {
				a.logf("minimum RSSI: kick %s: %v", mac, err)
			}
		})
	}
}

func neighborList(ns []bcmwifi.Neighbor) string {
	var p []string
	for _, n := range ns {
		p = append(p, n.BSSID)
	}
	return strings.Join(p, ", ")
}
