// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// Minimum RSSI for associated stations. The U6's stamgr disconnects a
// station whose signal stays below the radio's minrssi for
// minrssi_conseq_fails checks in a row. The drivers here refuse weak
// association requests (AssocReqRssiThres, live.go) but their own kick
// (KickStaRssiLow) has no grace period, so the agent does the kick: a
// station of a served BSS read below the threshold in minRSSIConseq
// readings in a row, at least minRSSIGap apart (a cached reading never
// counts twice), is sent DisConnectSta on its BSS. It is then left alone
// for a back-off (kickBackoff, doubled at each kick within
// kickBackoffMax of the last, up to kickBackoffMax), so a station that
// comes straight back is not kicked in a loop.
const (
	minRSSIConseq  = 3
	minRSSIGap     = 5 * time.Second
	kickBackoff    = 30 * time.Second
	kickBackoffMax = 10 * time.Minute
)

type weakSta struct {
	n       int       // readings in a row below the threshold
	last    time.Time // the last one counted
	until   time.Time // no kick before
	backoff time.Duration
}

// KickWeak disconnects the stations of s that stayed below their radio's
// minimum RSSI (RadioPlan.MinRSSI) and returns their MACs (lower case).
// It never waits: while the applier changes the radios, or a restart
// settles, it does nothing (the readings of that time do not count).
func (a *Applier) KickWeak(ctx context.Context, s *apstate.Snapshot) []string {
	if s == nil || !a.mu.TryLock() {
		return nil
	}
	defer a.mu.Unlock()
	if a.live == nil || a.settling() {
		return nil
	}
	if a.weak == nil {
		a.weak = map[string]*weakSta{}
	}
	now := s.Time
	served := map[string]int{} // netdev -> its radio's threshold
	for _, rd := range a.o.Layout {
		rp := a.live[rd.Band]
		if !rp.On || rp.MinRSSI == 0 {
			continue
		}
		for i := range rp.BSS {
			served[a.ifaceOf(rd, rp, i)] = rp.MinRSSI
		}
	}
	var kicked []string
	seen := map[string]bool{}
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			thr, ok := served[v.Iface]
			if !ok {
				continue
			}
			for _, st := range v.Stations {
				mac := strings.ToLower(st.MAC)
				if mac == "" || st.Signal == 0 {
					continue
				}
				seen[mac] = true
				w := a.weak[mac]
				if w == nil {
					w = &weakSta{}
					a.weak[mac] = w
				}
				if st.Signal >= thr {
					w.n = 0
					continue
				}
				if w.n > 0 && now.Sub(w.last) < minRSSIGap {
					continue
				}
				w.n++
				w.last = now
				if w.n < minRSSIConseq || now.Before(w.until) {
					continue
				}
				if err := a.run(ctx, "iwpriv", v.Iface, "set", "DisConnectSta="+strings.ToUpper(mac)); err != nil {
					a.o.Logf("mtkwifi: minimum RSSI: disconnecting %s from %s: %v", mac, v.Iface, err)
					continue
				}
				a.o.Logf("mtkwifi: minimum RSSI: %s on %s at %d dBm, below %d dBm for %d readings: disconnected",
					mac, v.Iface, st.Signal, thr, w.n)
				switch {
				case w.backoff == 0 || now.After(w.until.Add(kickBackoffMax)):
					w.backoff = kickBackoff
				default:
					w.backoff = min(2*w.backoff, kickBackoffMax)
				}
				w.n, w.until = 0, now.Add(w.backoff)
				kicked = append(kicked, mac)
			}
		}
	}
	for mac, w := range a.weak {
		if !seen[mac] && now.After(w.until.Add(kickBackoffMax)) && now.Sub(w.last) > kickBackoffMax {
			delete(a.weak, mac)
		}
	}
	return kicked
}
