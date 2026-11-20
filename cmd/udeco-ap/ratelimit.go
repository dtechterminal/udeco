// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Per-client speed limits (docs/deco/features/client-rate-limit.md).
//
// UniFi Network sends a client's user-group limit to the AP the client is
// on as cmd rate-update, not in system_cfg. The session keeps the list in
// state.json (device.State.ClientRates); the agent hands the whole list to
// bcmwifi, which shapes each listed station on whichever SSID vif of this
// unit it is associated on, with the same tc trees as the SSID-wide limits
// (bcmwifi/shape.go). The list is handed over on each rate-update, at
// startup, and when a listed client (re)joins (rateJoins), so the limit is
// in place within one inform interval of the association rather than at
// the next 60 s Tick.

import (
	"context"
	"sort"
	"strings"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// clientShaper is bcmwifi's per-client speed limits. Optional: a Wi-Fi
// backend without it (jio-mtk) logs the cmd as not supported.
type clientShaper interface {
	SetClientRates(ctx context.Context, rates map[string]bcmwifi.RateLimit) (int, error)
}

var _ clientShaper = (*bcmwifi.Applier)(nil)

// clientRates copies the session's per-client limits for bcmwifi (loop
// goroutine).
func (a *agent) clientRates() map[string]bcmwifi.RateLimit {
	m := make(map[string]bcmwifi.RateLimit, len(a.x.S.ClientRates))
	for mac, r := range a.x.S.ClientRates {
		m[mac] = bcmwifi.RateLimit{DownKbps: r.DownKbps, UpKbps: r.UpKbps}
	}
	return m
}

// pushClientRates queues a job that applies the session's whole list (loop
// goroutine). Without a backend that shapes per client (jio-mtk) it logs,
// once, that the controller's limits are not applied.
func (a *agent) pushClientRates(why string) {
	cs, ok := a.wifi.(clientShaper)
	if !ok {
		if len(a.x.S.ClientRates) > 0 && !a.rateNoted {
			a.rateNoted = true
			p := a.cfg.Platform
			if p == "" {
				p = "deco"
			}
			a.logf("per-client speed limits (%s): not supported on platform %s; not applied", why, p)
		}
		return
	}
	rates := a.clientRates()
	a.submit("client rate limits ("+why+")", func(ctx context.Context) {
		n, err := cs.SetClientRates(ctx, rates)
		switch {
		case err != nil:
			a.logf("per-client speed limits (%s): %v (retried at the next tick)", why, err)
		case n > 0:
			a.logf("per-client speed limits (%s): %d client(s) changed, %d limit(s) known", why, n, len(rates))
		}
	})
}

// rateJoins hands the list over again when a client with a limit shows up
// on this unit (associated, re-associated or moved to another SSID) since
// the last reading (loop goroutine). Nothing is queued in observe mode or
// while no client has a limit.
func (a *agent) rateJoins(f map[string]any) {
	if len(a.x.S.ClientRates) == 0 {
		a.rateSeen = nil
		return
	}
	cur := map[string]bool{}
	var came []string
	vaps, _ := f["vap_table"].([]map[string]any)
	for _, v := range vaps {
		name, _ := v["name"].(string)
		stas, _ := v["sta_table"].([]map[string]any)
		for _, s := range stas {
			mac, _ := s["mac"].(string)
			mac = strings.ToLower(mac)
			if _, ok := a.x.S.ClientRates[mac]; !ok {
				continue
			}
			key := mac + "@" + name
			cur[key] = true
			if !a.rateSeen[key] {
				came = append(came, mac)
			}
		}
	}
	first := a.rateSeen == nil
	a.rateSeen = cur
	if first || len(came) == 0 || !a.takeover.Load() {
		return // the first reading: startup has handed the list over
	}
	sort.Strings(came)
	a.pushClientRates("joined " + strings.Join(came, " "))
}
