// SPDX-License-Identifier: GPL-2.0-or-later

package main

// The Broadcom flow cache (docs/deco/features/client-rate-limit.md).
//
// bcmwifi turns the flow cache off while any tc limit is built (accelerated
// flows bypass tc) and back on when none is, and its hand-back to TP-Link
// turns it on whoever turned it off. What is left to the agent are the
// paths where bcmwifi does not shape any more: an observe-mode start after
// a takeover run that left the cache off (it crashed, or was stopped with
// limits set), and the drop to observe (a safety net: the hand-back before
// it already turned the cache on). A plain stop (SIGTERM) leaves the cache
// as it is, like the rest of Wi-Fi: the tc trees stay built and only hold
// while the cache is off; the next start decides again, and a reboot turns
// the cache back on. jio-mtk has no flow cache; its speed limiter (the
// udeco_rl module, mtkwifi ratelimit.go) takes the same two paths:
// removeRateLimiter.

import (
	"context"
	"os"
	"path/filepath"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/mtkwifi"
)

// flowCacheRestorer is bcmwifi's RestoreFlowCache. Optional: mtkwifi has
// none.
type flowCacheRestorer interface {
	RestoreFlowCache(ctx context.Context) error
}

var _ flowCacheRestorer = (*bcmwifi.Applier)(nil)

// restoreFlowCache turns the flow cache back on through w when bcmwifi
// recorded that the agent turned it off (it runs nothing otherwise).
func (a *agent) restoreFlowCache(ctx context.Context, w wifiApplier) {
	if a.cfg.jio() {
		a.removeRateLimiter(ctx)
		return
	}
	if w == nil {
		return
	}
	r, ok := w.(flowCacheRestorer)
	if !ok {
		return
	}
	if err := r.RestoreFlowCache(ctx); err != nil {
		a.logf("flow cache: %v (reboot the unit to turn it back on)", err)
	}
}

// observeFlowCacheRestore is the observe-mode start's part: it builds a
// bcmwifi handle for that alone and only when an earlier takeover run's
// record (RunDir/fc-off) is there; nothing else on the unit changes.
func (a *agent) observeFlowCacheRestore(ctx context.Context) {
	if a.cfg.jio() {
		a.removeRateLimiter(ctx)
		return
	}
	if _, err := os.Stat(a.dev(filepath.Join(a.o.runDir, bcmwifi.FlowCacheOffFile))); err != nil {
		return
	}
	a.event("observe mode: turning the flow cache an earlier takeover run turned off (for its rate limits) back on")
	w := a.o.newWifi(bcmwifi.Options{Root: a.o.root, Run: a.o.run, StateDir: filepath.Join(a.o.base, wifiStateSub),
		RunDir: a.o.runDir, Logf: a.logf})
	a.restoreFlowCache(ctx, w)
}

// removeRateLimiter (jio-mtk) removes a udeco_rl module a takeover run
// left loaded (it crashed, or was stopped with limits set): observe mode
// polices nothing. Nothing runs without the module.
func (a *agent) removeRateLimiter(ctx context.Context) {
	if err := mtkwifi.RemoveRateLimiter(ctx, a.o.root, a.o.run, a.logf); err != nil {
		a.logf("speed limits: removing udeco_rl: %v (reboot the unit to remove it)", err)
	}
}
