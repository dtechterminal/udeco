// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// DFS on the MT7663 (Options.DFS, agent config dfs; off by default until
// the region check of docs/deco/features/garage-parity.md passed on the
// unit). The vendor profile's CountryRegionABand 10 has no DFS channel;
// region 0 adds 52-64, the only DFS channels of the driver's IN table
// (100-144 are not in it and stay refused).
//
//   - The driver caches its channel list: only `iwpriv rai0 set
//     CountryRegionABand=N` rebuilds it, so the region goes live, and the
//     profile is kept in step for the next restart. The radio's channel
//     must be in the active region at every moment: going to 52-64 the
//     region is set first, then the channel; coming back the channel
//     first, then the vendor's region, and only when no channel is in its
//     non-occupancy period (a rebuild could wipe the driver's NOP).
//   - `set Channel=<52-64>` sends a CSA, restarts the BSSes and runs a
//     65 s CAC with the radio silent: a channel change into or out of
//     52-64 is no profile restart (change), and the agent keeps away from
//     the driver for dfsQuiet after it (no SSID reads, no live settings,
//     no rollback for a silent radio, no off-channel scan: the collector
//     refuses 5 GHz scans while on a DFS channel).
//   - Radar is the driver's: it leaves the channel (CSA, a random new
//     one; another CAC on a DFS one) and keeps it out for 30 minutes. The
//     agent sees the radio on another channel than the one it set, reports
//     EVT_AP_RadarDetected (TakeRadar), keeps the channel (all of 52-64 at
//     80 MHz) out for nopHold, writes the channel the driver chose into
//     the profile meanwhile, and then goes back. A move the driver refused
//     (the radio still on the channel it was on: a NOP from before the
//     agent started) is no radar; the channel is out for nopHold too.
//   - Never touched: IEEE80211H, RDRegion, DfsEnable, DfsZeroWait, nor any
//     of the driver's DFS test commands.

var chansDFS = []int{52, 56, 60, 64}

func isDFS(ch int) bool { return ch >= 52 && ch <= 64 && ch%4 == 0 }

const (
	dfsQuiet = 90 * time.Second     // CAC 65 s and the BSSes' restart
	nopHold  = 1860 * time.Second   // the driver's NOP (1800 s) and a margin
	dfsAlt   = 36                   // a channel of every region, to leave 52-64 for automatic
	regionA  = "CountryRegionABand" // the driver's 5 GHz region key
	vendorA  = "10"                 // the JCOW414's region when its profile has none
	dfsRegA  = "0"                  // 36-64, 149-165
)

// RadarEvent is a radar detection on the 5 GHz radio (EVT_AP_RadarDetected).
type RadarEvent struct {
	Channel int // the channel the radar was on
	MovedTo int // the channel the driver moved to
	Freq    int // Channel's MHz
	At      time.Time
}

type dfsState struct {
	region0 bool                  // the driver's region is dfsRegA (set or found)
	on      int                   // the DFS channel the radio was taken to or found on
	pending bool                  // the move to on is not seen yet
	from    int                   // the channel before that move
	moved   int                   // the channel the driver chose after a radar
	nop     map[int]time.Duration // channel -> end of its NOP (Options.mono)
	mu      sync.Mutex            // radar, read by the agent without a.mu
	radar   []RadarEvent
}

var chanLineRE = regexp.MustCompile(`Channel[=:](\d+)`)

// channelOf is the radio's channel as iwconfig shows it (0: unknown).
func (a *Applier) channelOf(ctx context.Context, ifc string) int {
	out, err := a.o.Run.Run(ctx, "iwconfig", ifc)
	if err != nil {
		return 0
	}
	m := chanLineRE.FindSubmatch(out)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n
}

// quietFor keeps the driver reads and the live settings off for d.
func (a *Applier) quietFor(d time.Duration) {
	until := int64(a.o.mono() + d)
	for {
		cur := a.quietUntil.Load()
		if cur >= until || a.quietUntil.CompareAndSwap(cur, until) {
			return
		}
	}
}

// dfsRadio is the radio the agent may take to 52-64 (nil: none).
func (a *Applier) dfsRadio() *RadioDef {
	if !a.o.DFS {
		return nil
	}
	for i := range a.o.Layout {
		if a.o.Layout[i].DFS {
			return &a.o.Layout[i]
		}
	}
	return nil
}

func (a *Applier) inNOP(ch int) bool {
	end, ok := a.dfs.nop[ch]
	return ok && a.o.mono() < end
}

func (a *Applier) nopPending() bool {
	for ch := range a.dfs.nop {
		if a.inNOP(ch) {
			return true
		}
	}
	return false
}

// dfsProfilePlan is rp as the profile gets it: while rp's DFS channel is
// out (a radar), the channel the driver moved to.
func (a *Applier) dfsProfilePlan(rd RadioDef, rp RadioPlan) RadioPlan {
	if rd.DFS && isDFS(rp.Channel) && a.inNOP(rp.Channel) && a.dfs.moved != 0 {
		rp.Channel = a.dfs.moved
	}
	return rp
}

func (a *Applier) writeProfile(rd RadioDef, rp RadioPlan) error {
	base, err := a.baseline(rd)
	if err != nil {
		return err
	}
	return writeFile(a.dev(rd.Dat), profile(base, rd, a.dfsProfilePlan(rd, rp)), 0o600)
}

func (a *Applier) vendorRegion(rd RadioDef) string {
	if base, err := a.baseline(rd); err == nil {
		if v, ok := getKey(base, regionA); ok && v != "" {
			return v
		}
	}
	return vendorA
}

// dfsLive: a change of rd from c to w is only a channel move into or out
// of 52-64, which goes live (dfsStep), not through a restart.
func (a *Applier) dfsLive(base []byte, rd RadioDef, c, w RadioPlan) bool {
	if !rd.DFS || !a.o.DFS || !c.On || !w.On || c.Channel == w.Channel || c.Channel == 0 || w.Channel == 0 ||
		!isDFS(c.Channel) && !isDFS(w.Channel) {
		return false
	}
	cc := w
	cc.Channel = c.Channel
	return restartKey(base, rd, c) == restartKey(base, rd, cc)
}

// dfsStep moves the radio to its planned channel and follows radar
// (a.mu held; Apply and Tick, never within a settle time).
func (a *Applier) dfsStep(ctx context.Context) {
	rd := a.dfsRadio()
	if rd == nil || a.live == nil || a.settling() || a.o.DryRun {
		return
	}
	rp := a.live[rd.Band]
	main := rd.Ifaces[0]
	if !rp.On || !a.isUp(main) {
		return
	}
	cur := a.channelOf(ctx, main)
	if cur == 0 {
		return
	}
	if a.dfs.nop == nil {
		a.dfs.nop = map[int]time.Duration{}
	}
	if isDFS(cur) {
		a.dfs.region0 = true // only region 0 has it
	}
	want := rp.Channel
	if a.dfs.on != 0 && cur != a.dfs.on {
		if a.dfs.pending && cur == a.dfs.from {
			a.o.Logf("mtkwifi: %s: the driver did not move to channel %d (in its non-occupancy period?): staying on %d for now", rd.Band, a.dfs.on, cur)
			a.dfs.nop[a.dfs.on] = a.o.mono() + nopHold
		} else {
			a.radarSeen(rd, rp, a.dfs.on, cur)
		}
		a.dfs.on, a.dfs.pending = 0, false
		if isDFS(cur) {
			a.dfs.on = cur // the driver's CAC there; radar may move it again
		}
		return
	}
	if cur == want || want == 0 && !isDFS(cur) {
		a.dfs.pending = false
		a.dfs.on = 0
		if isDFS(cur) {
			a.dfs.on = cur
		}
		if !isDFS(cur) && a.dfs.region0 && !a.nopPending() {
			if err := a.run(ctx, "iwpriv", main, "set", regionA+"="+a.vendorRegion(*rd)); err != nil {
				a.o.Logf("mtkwifi: %s: region back: %v", rd.Band, err)
				return
			}
			a.dfs.region0 = false
		}
		return
	}
	if isDFS(want) {
		if a.inNOP(want) {
			return // where the driver put the radio, until the NOP ends
		}
		if !a.dfs.region0 {
			if err := a.run(ctx, "iwpriv", main, "set", regionA+"="+dfsRegA); err != nil {
				a.o.Logf("mtkwifi: %s: region %s refused (a region lock?): channel %d not served: %v", rd.Band, dfsRegA, want, err)
				a.dfs.nop[want] = a.o.mono() + nopHold
				return
			}
			a.dfs.region0 = true
		}
		if err := a.run(ctx, "iwpriv", main, "set", "Channel="+strconv.Itoa(want)); err != nil {
			a.o.Logf("mtkwifi: %s: channel %d: %v", rd.Band, want, err)
			return
		}
		a.dfs.on, a.dfs.pending, a.dfs.from, a.dfs.moved = want, true, cur, 0
		a.quietFor(dfsQuiet)
		if err := a.writeProfile(*rd, rp); err != nil {
			a.o.Logf("mtkwifi: %s: profile: %v", rd.Band, err)
		}
		a.o.Logf("mtkwifi: %s: channel %d (DFS): channel availability check, the radio is silent for about 65 s", rd.Band, want)
		return
	}
	// the plan is off 52-64: leave them (the channel first, then the region)
	if !isDFS(cur) && !a.dfs.region0 {
		return // not a DFS matter
	}
	to := want
	if to == 0 {
		to = dfsAlt // automatic: a channel of the vendor's region until the next restart
	}
	if isDFS(cur) {
		if err := a.run(ctx, "iwpriv", main, "set", "Channel="+strconv.Itoa(to)); err != nil {
			a.o.Logf("mtkwifi: %s: channel %d: %v", rd.Band, to, err)
			return
		}
		a.quietFor(a.o.Settle)
	}
	a.dfs.on, a.dfs.pending = 0, false
	if a.dfs.region0 && !a.nopPending() {
		if err := a.run(ctx, "iwpriv", main, "set", regionA+"="+a.vendorRegion(*rd)); err != nil {
			a.o.Logf("mtkwifi: %s: region back: %v", rd.Band, err)
			return
		}
		a.dfs.region0 = false
	}
}

// radarSeen records a radar on ch (the radio now on to).
func (a *Applier) radarSeen(rd *RadioDef, rp RadioPlan, ch, to int) {
	end := a.o.mono() + nopHold
	out := []int{ch}
	switch {
	case rp.Width >= 80:
		out = chansDFS
	case rp.Width == 40:
		out = []int{ch &^ 4, ch&^4 + 4} // 52/56, 60/64
		if (ch/4)%2 == 0 {
			out = []int{ch - 4, ch}
		}
	}
	for _, c := range out {
		a.dfs.nop[c] = end
	}
	a.dfs.moved = to
	if err := a.writeProfile(*rd, rp); err != nil {
		a.o.Logf("mtkwifi: %s: profile: %v", rd.Band, err)
	}
	a.o.Logf("mtkwifi: %s: radar on channel %d: the driver moved the radio to %d; back after %s", rd.Band, ch, to, nopHold)
	a.dfs.mu.Lock()
	if len(a.dfs.radar) < 16 {
		a.dfs.radar = append(a.dfs.radar, RadarEvent{Channel: ch, MovedTo: to, Freq: 5000 + 5*ch, At: time.Now()})
	}
	a.dfs.mu.Unlock()
}

// TakeRadar returns the radar detections since the last call.
func (a *Applier) TakeRadar() []RadarEvent {
	a.dfs.mu.Lock()
	defer a.dfs.mu.Unlock()
	out := a.dfs.radar
	a.dfs.radar = nil
	return out
}

// OnDFS: the 5 GHz radio is on a DFS channel (as last seen).
func (a *Applier) OnDFS() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dfs.on != 0
}
