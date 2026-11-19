// SPDX-License-Identifier: GPL-2.0-or-later
package main

import (
	"context"
	"time"
)

// homeListenEvery: how often each radio listens on its own channel. A U6 Pro
// refreshes the neighbours on its own channels about once a minute, and the
// UniFi neighbour list shows only recently seen networks: without this the
// list empties a few minutes after the last RF scan (seen 2026-11-19).
const homeListenEvery = time.Minute

// homeListenTimeout bounds one band's listen (110 ms dwell plus the
// scanresults poll).
const homeListenTimeout = 5 * time.Second

// startHomeListen keeps scan_table fresh between RF scans with a passive
// listen on each radio's own channel (wl.Collector.HomeScan): the radio
// never leaves its channel. A band is skipped while a controller scan runs or
// while scans are blocked (Wi-Fi apply, hold); the collector's scan lock
// makes a spectrum or neighbour scan wait for a listen in progress.
func (a *agent) startHomeListen(ctx context.Context) {
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		t := time.NewTicker(homeListenEvery)
		defer t.Stop()
		lastErr := map[string]string{}
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			a.homeListenRound(ctx, lastErr)
		}
	}()
}

// homeListenRound listens once on each band's own channel. lastErr keeps
// the last error per band, so a repeating one is logged once.
func (a *agent) homeListenRound(ctx context.Context, lastErr map[string]string) {
	for _, band := range []string{"ng", "na"} {
		if a.scanBlock() != "" || a.scans.busy() {
			return
		}
		bctx, cancel := context.WithTimeout(ctx, homeListenTimeout)
		res, err := a.o.col.HomeScan(bctx, band)
		cancel()
		if err != nil {
			if ctx.Err() == nil && err.Error() != lastErr[band] {
				lastErr[band] = err.Error()
				a.logf("home listen %s: %v (further identical errors not logged)", band, err)
			}
			continue
		}
		lastErr[band] = ""
		a.scans.addBSS(band, *res)
	}
}
