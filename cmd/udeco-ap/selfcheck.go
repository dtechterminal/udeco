// SPDX-License-Identifier: GPL-2.0-or-later

package main

// The takeover self-check (interference-audit R10, topology-and-tplink-
// scrub.md requirement 5). decosys reports every piece of TP-Link state it
// found back (Report.Foreign: re-stopped services, the 192.168.0.1 alias,
// a DHCP server, the reset handler, the boot hook, crond, apsd, imsnoop,
// work_mode, ...) and keeps cumulative counts; bcmwifi.Tick reports driver
// MAC filters, WDS peers, unbridged vifs and the like. The worker logs each
// finding as it comes, puts the loud ones in the event ring (at most once
// an hour each, R13), and every selfCheck interval logs one summary line
// with the counts and the R4 memory figures when anything changed.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dtechterminal/udeco/internal/decosys"
)

// loudKinds are the findings that also go to the event ring on flash: what
// breaks the LAN or the agent's persistence, as opposed to a service that
// was simply stopped again.
var loudKinds = map[string]bool{
	decosys.KindAddr: true, decosys.KindDHCPD: true, decosys.KindButton: true,
	decosys.WatchSmartIP: true, decosys.WatchProcess: true, decosys.WatchHook: true,
	decosys.WatchCrond: true, decosys.WatchWorkMode: true, decosys.WatchUnitIP: true,
}

// eventEvery bounds how often one finding reaches the event ring.
const eventEvery = time.Hour

// foreign logs decosys's findings of one Enforce (worker).
func (a *agent) foreign(fs []decosys.Finding) {
	w := &a.worker
	now := a.o.now()
	for _, f := range fs {
		a.logf("decosys: foreign: %s", f)
		if !loudKinds[f.Kind] {
			continue
		}
		key := f.String()
		if t, ok := w.evented[key]; ok && now.Sub(t) < eventEvery && now.After(t) {
			continue
		}
		if w.evented == nil {
			w.evented = map[string]time.Time{}
		}
		w.evented[key] = now
		a.event("FOREIGN STATE: " + key)
	}
	for k, t := range w.evented {
		if now.Sub(t) > eventEvery {
			delete(w.evented, k)
		}
	}
}

// selfCheck logs the R10 summary every t.selfCheck when it changed
// (worker, after each tick).
func (a *agent) selfCheck() {
	w := &a.worker
	now := time.Now()
	if !w.checked.IsZero() && now.Sub(w.checked) < a.t.selfCheck {
		return
	}
	w.checked = now
	counts := a.sys.Counts()
	for k, v := range w.counts {
		counts[k] += v
	}
	sum := summary(counts)
	if sum == w.lastSum {
		return
	}
	w.lastSum = sum
	mem := "memory not read yet"
	if r := a.res.Load(); r != nil {
		mem = fmt.Sprintf("agent VmRSS %d kB, MemAvailable %d kB, /tmp+/etc %d kB", r.RSSKB, r.AvailKB, r.RAMfsKB)
	}
	a.logf("self-check: foreign state since start: %s; %s", sum, mem)
}

// summary renders counts as "k=v k=v" in key order ("none" when empty).
func summary(counts map[string]int) string {
	var keys []string
	for k, v := range counts {
		if v > 0 {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return "none"
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%d", k, counts[k])
	}
	return b.String()
}
