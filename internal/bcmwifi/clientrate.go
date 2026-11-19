// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"encoding/json"
	"path"
	"sort"
)

// Per-client speed limits set by the controller for one station
// (docs/deco/features/client-rate-limit.md).
//
// UniFi Network sends a client's user-group limit as a devmgr command,
// not in system_cfg: {"cmd":"rate-update","mac":..,"dl_max":..,"ul_max":..}
// in kbit/s, -1 = no limit that way. The agent keeps the list (its session
// state, so it survives restarts and reboots) and hands the whole of it to
// SetClientRates. Here it is folded into the same per-station tc trees the
// SSID-wide limits use (shape.go): a station with an entry, associated on
// any SSID vif of this unit, gets the entry's limit in each direction the
// entry limits, and the SSID's limit (if any) in the other. Nothing else
// changes: the trees, ids, IFBs, checks and flow-cache flushes are the
// SSID-wide ones. TP-Link's backhaul vif (wlN1) and the wired uplink are
// never shaped.

// clientRatesPath keeps the list for this boot, so an agent restart shapes
// at its first Tick before the agent has handed the list over again.
func (a *Applier) clientRatesPath() string { return path.Join(a.o.RunDir, "client-rates.json") }

// loadClientRates returns the per-client limits, reading RunDir on first use.
// Callers hold a.mu.
func (a *Applier) loadClientRates() map[string]RateLimit {
	if a.clientRates == nil {
		m := map[string]RateLimit{}
		if b, err := a.readFile(a.clientRatesPath()); err == nil {
			var raw map[string]RateLimit
			if json.Unmarshal(b, &raw) == nil {
				m = normClientRates(raw)
			}
		}
		a.clientRates = m
	}
	return a.clientRates
}

// normClientRates drops bad MACs and directions without a positive limit,
// and stations left with no limit at all.
func normClientRates(in map[string]RateLimit) map[string]RateLimit {
	out := map[string]RateLimit{}
	for mac, r := range in {
		m := normMAC(mac)
		if m == "" {
			continue
		}
		r.DownKbps, r.UpKbps = max(r.DownKbps, 0), max(r.UpKbps, 0)
		if r.DownKbps == 0 && r.UpKbps == 0 {
			continue
		}
		out[m] = r
	}
	return out
}

// SetClientRates replaces the per-client limits (MAC -> kbit/s, 0 = that
// direction not limited by the station's own entry) and brings the tc trees
// in line at once. It returns the number of stations whose limit was added,
// changed or removed (their flows are flushed). When the agent does not own
// Wi-Fi the list is only stored and every tree is removed, as SyncRateLimits
// does.
func (a *Applier) SetClientRates(ctx context.Context, rates map[string]RateLimit) (int, error) {
	m := normClientRates(rates)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.o.DryRun {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		a.o.Logf("bcmwifi dry-run: per-client limits for %v", keys)
	} else {
		b, _ := json.MarshalIndent(m, "", " ")
		if err := writeFileAtomic(a.fsPath(a.clientRatesPath()), b, 0o644); err != nil {
			return 0, err
		}
	}
	a.clientRates = m
	d := a.current()
	if d == nil {
		return a.syncShaping(ctx, nil)
	}
	return a.syncShaping(ctx, a.layout(*d))
}
