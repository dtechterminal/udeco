// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/rf"
)

// DFS on the 5 GHz radio (docs/deco/features/dfs.md). A U6 Pro serves the
// controller's DFS channel: it runs the channel availability check (CAC)
// before beaconing, follows the driver off the channel when radar is
// found (EVT_AP_RadarDetected), and goes back at 02:00 (the controller's
// cron job `syswrapper.sh dfs-reset`) unless the channel is still in its
// non-occupancy period. Here the X20's wl.ko does the radar part itself
// once 802.11h is on (`wl spect 1`, parity.go), and the agent:
//
//   - turns 802.11h on in the radio down that sets a DFS chanspec, before
//     the chanspec (and in every radio down after, parity.go);
//   - writes a non-DFS channel in hostapd's conf: wl owns the channel, and
//     hostapd must not run a CAC of its own over nl80211 (hostapd.go);
//   - tolerates the CAC (`wl dfs_status` PRE-ISM, about 60 s, longer on
//     the weather channels) in Verify, and leaves the radio alone in Tick
//     meanwhile;
//   - sees a radar move: the live channel is not the wanted DFS one and
//     `wl chan_info` lists the wanted channel as "Temporarily Out of
//     Service" (the driver's non-occupancy list). It keeps the driver's
//     channel instead of moving back, queues a RadarEvent (Tick reports
//     it once) and notes it in every plan;
//   - DFSReset puts the wanted DFS channel back once it is out of the
//     non-occupancy list (the next apply sets it).
//
// The output formats of dfs_status and chan_info are from the Broadcom wl
// utility's source, not read on an X20 (unverified on hardware).

// RadarEvent is a radar move Tick reports once.
type RadarEvent struct {
	Band    string // "na"
	Radio   string // primary netdev
	Channel int    // the DFS control channel left
	FreqMHz int
	From    string // wanted chanspec
	To      string // the driver's chanspec
	At      time.Time
}

// dfsMove is a radar move the agent follows.
type dfsMove struct {
	From, To chanspec
	At       time.Time
}

// parseDFSStatus reports a channel availability check in progress in
// `wl dfs_status` ("state PRE-ISM Channel Availability Check(CAC) ...").
func parseDFSStatus(s string) bool {
	l := strings.ToLower(s)
	if strings.Contains(l, "in-service monitoring") && !strings.Contains(l, "pre-ism") {
		return false
	}
	return strings.Contains(l, "pre-ism") || strings.Contains(l, "(cac)") || strings.Contains(l, "channel availability check")
}

// parseNOP reads the channels `wl chan_info` lists as out of service
// (radar found: the non-occupancy period).
func parseNOP(s string) map[int]bool {
	m := map[int]bool{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.EqualFold(f[0], "channel") || !strings.Contains(strings.ToLower(line), "out of service") {
			continue
		}
		if ch, err := strconv.Atoi(strings.Trim(f[1], ":,")); err == nil {
			m[ch] = true
		}
	}
	return m
}

// inCAC: the radio is in a channel availability check (never for a radio
// whose dfs_status cannot be read).
func (a *Applier) inCAC(ctx context.Context, p string) bool {
	out, err := a.wlGet(ctx, p, "dfs_status")
	return err == nil && parseDFSStatus(out)
}

// nopOf lists the 20 MHz channels of cs in the radio's non-occupancy list
// (nil when chan_info cannot be read).
func (a *Applier) nopOf(ctx context.Context, p string, cs chanspec) []int {
	out, err := a.wlGet(ctx, p, "chan_info")
	if err != nil {
		return nil
	}
	nop := parseNOP(out)
	var hit []int
	for _, ch := range subChannels(cs) {
		if nop[ch] {
			hit = append(hit, ch)
		}
	}
	return hit
}

// subChannels are the 20 MHz channels a 5 GHz chanspec covers.
func subChannels(cs chanspec) []int { return rf.SubChannels(cs.Ctrl, cs.Width) }

func (cs chanspec) dfs() bool {
	for _, ch := range subChannels(cs) {
		if dfsChannel("na", ch) {
			return true
		}
	}
	return false
}

// followRadar decides, for a 5 GHz radio whose wanted chanspec want is a
// DFS one and differs from the live one, whether the driver moved off it
// for radar. moved: keep the live chanspec. Called with a.mu held.
func (a *Applier) followRadar(ctx context.Context, p string, want, live chanspec) (moved bool, note string) {
	if m, ok := a.dfsMoved[p]; ok {
		if m.From == want {
			return true, fmt.Sprintf("radar on %s at %s: on the driver's %s until the controller's dfs-reset", m.From, m.At.Format("15:04"), live)
		}
		delete(a.dfsMoved, p) // the controller asked for another channel
	}
	hit := a.nopOf(ctx, p, want)
	if len(hit) == 0 {
		return false, ""
	}
	now := a.now()
	if a.dfsMoved == nil {
		a.dfsMoved = map[string]dfsMove{}
	}
	a.dfsMoved[p] = dfsMove{From: want, To: live, At: now}
	a.radarQ = append(a.radarQ, RadarEvent{Band: "na", Radio: p, Channel: want.Ctrl, FreqMHz: rf.ChanFreq(rf.Band5G, want.Ctrl),
		From: want.String(), To: live.String(), At: now})
	a.o.Logf("bcmwifi: radar: %s left %s for %s (channels %v out of service)", p, want, live, hit)
	return true, fmt.Sprintf("radar on %s (channels %v out of service): on the driver's %s", want, hit, live)
}

// DFSReset is the controller's nightly dfs-reset (U6 syswrapper.sh
// dfs_reset): a radio the agent left on the driver's channel after radar
// goes back to the wanted DFS channel at the next apply, unless that
// channel is still in the non-occupancy period. It reports whether any
// radio goes back (the caller then applies).
func (a *Applier) DFSReset(ctx context.Context) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	back := false
	for p, m := range a.dfsMoved {
		if hit := a.nopOf(ctx, p, m.From); len(hit) > 0 {
			a.o.Logf("bcmwifi: dfs-reset: %s still out of service on %v, wait for the next one", m.From, hit)
			continue
		}
		a.o.Logf("bcmwifi: dfs-reset: %s back to %s", p, m.From)
		delete(a.dfsMoved, p)
		back = true
	}
	return back
}

// takeRadar pops the queued radar events. Called with a.mu held.
func (a *Applier) takeRadar() []RadarEvent {
	q := a.radarQ
	a.radarQ = nil
	return q
}
