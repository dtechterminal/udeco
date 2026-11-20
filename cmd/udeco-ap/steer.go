// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Band steering, done by the agent (the Deco has no Broadcom bsd/wbd, and a
// UniFi AP steers on its own: device-capabilities.md). When the controller
// turned band steering on for the 2.4 GHz radio, a client that is on a
// 2.4 GHz SSID with a strong signal, has been seen on 5 GHz before (so it is
// dual-band), and whose SSID is also broadcast on 5 GHz, gets an 802.11v
// BSS transition request naming the 5 GHz BSS. Rate-limited per client;
// "equal" mode (translate.BandSteerEqual) only steers while 5 GHz has fewer
// clients than 2.4 GHz.

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

const (
	steerMinSignal = -60              // dBm on 2.4 GHz: strong enough that the 5 GHz link should hold
	steerEvery     = 10 * time.Minute // at most one request per client this often
	steerDualBand  = 24 * time.Hour   // a client seen on 5 GHz this recently is dual-band
	steerPerRead   = 2                // requests per reading at most
)

// wifiPolicy is what the inform loop needs of the live Wi-Fi.
type wifiPolicy struct {
	steer map[string]string // band -> band steering mode (translate.BandSteerPrefer5G, BandSteerEqual)
	roam  map[string]int    // "SSID|band" -> Roaming Assistant threshold, dBm (roaming.go)
	// minRSSI: band -> the controller's minimum RSSI, dBm (minrssi.go)
	minRSSI map[string]int
	// no2ghz: the SSIDs with "restrict to 5 GHz" that broadcast on both
	// bands (no2ghz.go)
	no2ghz map[string]bool
	// sae: the WPA3-only SSIDs (an association there is SAE when the
	// agent serves WPA3, staconn.go authAlgo)
	sae map[string]bool
}

func policyFrom(d bcmwifi.Desired) *wifiPolicy {
	p := &wifiPolicy{steer: map[string]string{}, roam: roamPolicy(d), minRSSI: map[string]int{}, no2ghz: map[string]bool{}, sae: map[string]bool{}}
	for _, s := range d.SSIDs {
		if s.Enabled && s.Security == bcmwifi.SecWPA3 {
			p.sae[s.SSID] = true
		}
		if s.Enabled && s.No2GHz && s.SSID != "" && slices.Contains(s.Bands, "ng") && slices.Contains(s.Bands, "na") {
			p.no2ghz[s.SSID] = true
		}
	}
	for band, r := range d.Radios {
		if r.Enabled && r.BandSteer != "" && r.BandSteer != translate.BandSteerOff {
			p.steer[band] = r.BandSteer
		}
		if r.Enabled && r.MinRSSI < 0 {
			p.minRSSI[band] = r.MinRSSI
		}
	}
	return p
}

// steerState belongs to the inform loop.
type steerState struct {
	seen5 map[string]time.Time // client MAC -> last seen on 5 GHz
	last  map[string]time.Time // client MAC -> last steering request
}

type bssRef struct {
	bssid   string
	channel int
}

// steerReading looks at one reading and asks the worker to steer the
// clients that qualify (loop goroutine).
func (a *agent) steerReading(s *apstate.Snapshot, now time.Time) {
	st := &a.steer
	if st.seen5 == nil {
		st.seen5, st.last = map[string]time.Time{}, map[string]time.Time{}
	}
	five := map[string]bssRef{} // SSID -> a 5 GHz BSS
	var n2, n5 int
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			switch vapBand(r, v) {
			case "na":
				n5 += len(v.Stations)
				for _, c := range v.Stations {
					st.seen5[c.MAC] = now
				}
				if _, ok := five[v.SSID]; !ok && v.SSID != "" && v.BSSID != "" {
					five[v.SSID] = bssRef{bssid: v.BSSID, channel: r.Channel}
				}
			case "ng":
				n2 += len(v.Stations)
			}
		}
	}
	for m, t := range st.seen5 {
		if now.Sub(t) > steerDualBand {
			delete(st.seen5, m)
		}
	}
	for m, t := range st.last {
		if now.Sub(t) > steerEvery {
			delete(st.last, m)
		}
	}
	if !a.takeover.Load() || a.shed.Load() {
		return
	}
	pol := a.policy.Load()
	if pol == nil || pol.steer["ng"] == "" {
		return
	}
	sr, ok := a.wifi.(steerer)
	if !ok {
		return
	}
	if pol.steer["ng"] == translate.BandSteerEqual && n5 >= n2 {
		return
	}
	type cand struct {
		vif, mac string
		signal   int
		to       bssRef
	}
	var cs []cand
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			to, ok := five[v.SSID]
			if vapBand(r, v) != "ng" || !ok {
				continue
			}
			for _, c := range v.Stations {
				_, recent := st.last[c.MAC]
				_, dual := st.seen5[c.MAC]
				if c.Signal != 0 && c.Signal >= steerMinSignal && dual && !recent && v.Iface != "" {
					cs = append(cs, cand{v.Iface, c.MAC, c.Signal, to})
				}
			}
		}
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].signal > cs[j].signal })
	for i, c := range cs {
		if i == steerPerRead {
			break
		}
		st.last[c.mac] = now
		a.submit("steer "+c.mac, func(ctx context.Context) {
			if err := sr.SteerToBand(ctx, c.vif, c.mac, c.to.bssid); err != nil {
				a.logf("band steering %s -> %s: %v", c.mac, c.to.bssid, err)
				return
			}
			a.logf("band steering: asked %s (%d dBm on 2.4 GHz) to move to %s (channel %d)", c.mac, c.signal, c.to.bssid, c.to.channel)
		})
	}
}

// vapBand is the VAP's band, else its radio's.
func vapBand(r, v apstate.Radio) string {
	if v.Band != "" {
		return v.Band
	}
	return r.Band
}
