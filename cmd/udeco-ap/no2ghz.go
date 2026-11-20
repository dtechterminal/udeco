// SPDX-License-Identifier: GPL-2.0-or-later

package main

// "Restrict high-performance clients to 5 GHz" (docs/deco/features/
// no2ghz.md). The controller sends wireless.N.no2ghz_oui=enabled on a
// WLAN's 2.4 GHz VAP (translate.WLANIntent.No2GHz -> bcmwifi.SSID.No2GHz
// -> wifiPolicy.no2ghz). A UAP's driver then keeps dual-band clients off
// the 2.4 GHz twin of the SSID; its client list and its six numeric
// parameters are not known, so the agent does it its own way, and never
// refuses a client it has no evidence can use 5 GHz:
//
//   - a client of such an SSID on the 2.4 GHz BSS qualifies when this unit
//     saw it on the SSID's 5 GHz BSS within no2ghzRecent at no2ghzMin5 or
//     better (the 5 GHz minimum RSSI plus 5 dB when one is set), and its
//     2.4 GHz signal is at least no2ghzMin24 (a client far away on 2.4 GHz
//     would not hold 5 GHz);
//   - it gets an 802.11v BSS transition request naming the 5 GHz BSS
//     (SteerToBand), at most once per no2ghzEvery, whatever the band
//     steering mode;
//   - still on the 2.4 GHz BSS no2ghzJudge later, never having moved
//     meanwhile: it ignored the request, and it is kept off the 2.4 GHz BSS
//     for no2ghzDeny (bcmwifi.TempDeny: the driver MAC filter, which also
//     hides that BSS from its probes, and a deauth), at most once per
//     no2ghzDenyEvery, so a client for which 5 GHz does not work in
//     practice is let back and left there; an allow-list SSID cannot take
//     the ban (logged once);
//   - a client the Roaming Assistant or band steering asked lately is left
//     to them, and a request here holds band steering off the client.
//
// Takeover mode only, not while memory is short, never on a stale reading.

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

const (
	no2ghzRecent    = time.Hour        // a 5 GHz sighting this recent counts
	no2ghzMin5      = -65              // dBm on 5 GHz at least (UniFi's default 30 - 95)
	no2ghzMin24     = -79              // dBm on 2.4 GHz at least (UniFi's default 16 - 95)
	no2ghzEvery     = 10 * time.Minute // one request per client at most this often
	no2ghzJudge     = time.Minute      // still on 2.4 GHz this long after a request: ignored
	no2ghzDeny      = time.Minute      // how long an ignoring client is kept off 2.4 GHz
	no2ghzDenyEvery = time.Hour        // one such ban per client at most this often
	no2ghzPerRead   = 2                // actions per reading at most
)

// no2ghzClient is one client's record.
type no2ghzClient struct {
	at5     time.Time // last seen on a 5 GHz BSS
	sig5    int       // its signal there
	ssid5   string    // that BSS's SSID
	asked   time.Time // the last request (zero: none)
	vif     string    // the 2.4 GHz BSS it was asked to leave
	moved   bool      // seen on 5 GHz since the request
	judged  bool      // the request's outcome is counted
	denied  time.Time // the last ban
	allowed bool      // "allow list: no ban" logged
}

type no2ghzState struct {
	c    map[string]*no2ghzClient
	bans []tempBan
}

// no2ghzReading looks at one reading (loop goroutine).
func (a *agent) no2ghzReading(s *apstate.Snapshot, now time.Time) {
	st := &a.no2
	if st.c == nil {
		st.c = map[string]*no2ghzClient{}
	}
	td, canBan := a.wifi.(tempDenier)
	keep := st.bans[:0]
	for _, b := range st.bans {
		if now.Before(b.until) {
			keep = append(keep, b)
			continue
		}
		if canBan && a.takeover.Load() {
			a.submit("no2ghz unban "+b.mac, func(ctx context.Context) {
				if err := td.TempDeny(ctx, b.vif, b.mac, time.Time{}); err != nil && !errors.Is(err, bcmwifi.ErrNotOwned) && !errors.Is(err, bcmwifi.ErrAllowList) {
					a.logf("restrict to 5 GHz: letting %s back on %s: %v", b.mac, b.vif, err)
				}
			})
		}
	}
	st.bans = keep
	if a.stale {
		return
	}
	// 5 GHz sightings, and the SSIDs' 5 GHz BSSes
	five := map[string]bssRef{}
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			if vapBand(r, v) != "na" {
				continue
			}
			if _, ok := five[v.SSID]; !ok && v.SSID != "" && v.BSSID != "" {
				five[v.SSID] = bssRef{bssid: v.BSSID, channel: r.Channel}
			}
			for _, sta := range v.Stations {
				m := strings.ToLower(sta.MAC)
				c := st.c[m]
				if c == nil {
					c = &no2ghzClient{}
					st.c[m] = c
				}
				if sta.Signal != 0 {
					c.at5, c.sig5, c.ssid5 = now, sta.Signal, v.SSID
				}
				if !c.asked.IsZero() {
					c.moved = true
				}
			}
		}
	}
	for m, c := range st.c {
		if now.Sub(c.at5) > no2ghzRecent && now.Sub(c.asked) > no2ghzEvery && now.Sub(c.denied) > no2ghzDenyEvery {
			delete(st.c, m)
		}
	}
	pol := a.policy.Load()
	sr, canSteer := a.wifi.(steerer)
	if !a.takeover.Load() || a.shed.Load() || pol == nil || len(pol.no2ghz) == 0 || !canSteer {
		return
	}
	min5, min24 := no2ghzMin5, no2ghzMin24
	if m, ok := pol.minRSSI["na"]; ok {
		min5 = m + 5
	}
	if m, ok := pol.minRSSI["ng"]; ok {
		min24 = max(min24, m+5)
	}
	if a.steer.last == nil {
		a.steer.seen5, a.steer.last = map[string]time.Time{}, map[string]time.Time{}
	}
	type cand struct {
		vif, mac string
		signal   int
		to       bssRef
		ban      bool
	}
	var cs []cand
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			to, paired := five[v.SSID]
			if vapBand(r, v) != "ng" || !pol.no2ghz[v.SSID] || !paired || v.Iface == "" {
				continue
			}
			for _, sta := range v.Stations {
				m := strings.ToLower(sta.MAC)
				c := st.c[m]
				if c == nil || c.at5.IsZero() || c.ssid5 != v.SSID || now.Sub(c.at5) >= no2ghzRecent || c.sig5 < min5 ||
					sta.Signal == 0 || sta.Signal < min24 {
					continue // no evidence it can use 5 GHz here: never refused
				}
				if t, ok := a.steer.last[m]; ok && now.Sub(t) < steerEvery && (c.asked.IsZero() || t.After(c.asked)) {
					continue // band steering or the Roaming Assistant asked it lately
				}
				switch {
				case !c.asked.IsZero() && !c.judged && c.vif == v.Iface && now.Sub(c.asked) >= no2ghzJudge:
					c.judged = true
					if !c.moved && now.Sub(c.denied) >= no2ghzDenyEvery && canBan {
						cs = append(cs, cand{v.Iface, m, sta.Signal, to, true})
					}
				case c.asked.IsZero() || now.Sub(c.asked) >= no2ghzEvery:
					cs = append(cs, cand{v.Iface, m, sta.Signal, to, false})
				}
			}
		}
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].signal > cs[j].signal })
	for i, k := range cs {
		if i == no2ghzPerRead {
			break
		}
		c := st.c[k.mac]
		if !k.ban {
			c.asked, c.vif, c.moved, c.judged = now, k.vif, false, false
			a.steer.last[k.mac] = now // band steering need not ask as well
			a.submit("no2ghz "+k.mac, func(ctx context.Context) {
				if err := sr.SteerToBand(ctx, k.vif, k.mac, k.to.bssid); err != nil {
					a.logf("restrict to 5 GHz: %s -> %s: %v", k.mac, k.to.bssid, err)
					return
				}
				a.logf("restrict to 5 GHz: asked %s (%d dBm on 2.4 GHz %s, %d dBm on 5 GHz lately) to move to %s (channel %d)",
					k.mac, k.signal, k.vif, c.sig5, k.to.bssid, k.to.channel)
			})
			continue
		}
		c.denied = now
		until := now.Add(no2ghzDeny)
		st.bans = append(st.bans, tempBan{k.vif, k.mac, until})
		logAllow := !c.allowed
		a.submit("no2ghz ban "+k.mac, func(ctx context.Context) {
			err := td.TempDeny(ctx, k.vif, k.mac, until)
			switch {
			case err == nil:
				a.logf("restrict to 5 GHz: %s ignored the request: kept off %s for %s", k.mac, k.vif, no2ghzDeny)
			case errors.Is(err, bcmwifi.ErrAllowList):
				if logAllow {
					a.logf("restrict to 5 GHz: %s stays on %s: the SSID has an allow list, so no ban", k.mac, k.vif)
				}
			default:
				a.logf("restrict to 5 GHz: ban of %s on %s: %v", k.mac, k.vif, err)
			}
		})
		c.allowed = true
	}
}
