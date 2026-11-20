// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Radio-wide driver settings a real UniFi U6 Pro applies by default
// (docs/reference/u6pro/config-apply/sysinit radio.conf and wireless.conf),
// mapped onto the X20's Broadcom wl.ko (docs/deco/features/radio-parity.md):
//
//   - BSS Load element (U6 qbssload 1 unless the controller sends
//     qbssload=disabled): `wl bssload 1`. Per radio in this driver, settable
//     with the radio up (iovar flags 0); off when any SSID of the radio has
//     it off (radioBSSLoad).
//   - Implicit beamforming off (U6 implicitbf 0): `wl txbf_imp 0`, live
//     (iovar flags 0).
//   - No vendor VHT on 2.4 GHz (U6 vht_11ng 0): `wl vht_features 0x6`, TP-Link's
//     0x7 without bit 0x1 (VHT rates in the 2.4 GHz band). 2.4 GHz only.
//   - RX-chain and radio power save off (U6 ant_ps_on 0):
//     `wl rxchain_pwrsave_enable 0`, `wl radio_pwrsave_enable 0` (both
//     already 0 on all three units, 2026-11-20: written for parity).
//   - Glitch-based receiver desense off (U6 ani_enable 0): the interference
//     mitigation mode without bit 0x1, interference_override back to -1
//     (auto); Options.KeepDesense (config rx_desense) leaves TP-Link's.
//
// The ones marked live are set with the radio up whenever they differ (the
// plan's live steps, Tick re-asserts them). The others are written only
// inside a radio down/up the plan makes anyway, as TWT (twt.go): the
// radioProfile of a PHY change, a full reconcile's dwds/rrm cycle, Tick's
// dwds repair. A radio that reads otherwise is noted until then; nothing
// restarts a radio for these alone. The hand-back puts back what the
// baseline read (TP-Link's values when it has none).

// driverIovar is one radio-wide driver setting the agent holds.
type driverIovar struct {
	name   string
	want   int
	live   bool   // the driver takes it with the radio up
	tplink string // TP-Link's value, restored when the baseline lacks one ("" = none known: left alone)
}

// TP-Link's values (tplink_brcm.sh wifi_features_set; read on the Bedroom
// Deco 2026-11-20).
const (
	tplinkBSSLoad   = "0"
	tplinkTxbfImp   = "1"
	tplinkVHTng     = "0x7"
	interferenceIov = "interference"
	interfOverIov   = "interference_override"
)

// tplinkFallback are TP-Link's values of the settings driverIovars does not
// list (live-facts 2026-11-20: interference mode 361 on both radios of the
// three Decos, interference_override -1), restored when the baseline lacks
// them. spect has none: the hand-back leaves it unless the baseline (or its
// backfill, backfillBaseline) read it.
var tplinkFallback = map[string]string{interferenceIov: "361", interfOverIov: "-1"}

// desenseBit is the Broadcom interference mitigation mode's receiver
// desense (glitch based) bit; the X20 runs mode 361 =
// desense|preempt|lpd|hw obss|mclip (2026-11-20).
const desenseBit = 0x1

// driverIovars are the settings for one radio. bssload is the radio's BSS
// Load state (radioBSSLoad). Interference mitigation is not listed: its
// wanted value depends on the live one (interferenceWant).
func driverIovars(band string, bssload bool) []driverIovar {
	l := []driverIovar{
		{name: "bssload", want: b2i(bssload), live: true, tplink: tplinkBSSLoad},
		// live: iovar flags 0; it re-evaluates every SCB (deco-crosscheck
		// l2uf-misc C)
		{name: "txbf_imp", want: 0, live: true, tplink: tplinkTxbfImp},
	}
	if band == "ng" {
		l = append(l, driverIovar{name: "vht_features", want: 0x6, tplink: tplinkVHTng})
	}
	if band == "na" {
		// 802.11h spectrum management (U6 doth 1): the driver's DFS (radar
		// detection, CAC) and TPC (dfs.go). TP-Link's value is the
		// baseline's; none known without one.
		l = append(l, driverIovar{name: "spect", want: 1})
	}
	return append(l,
		driverIovar{name: "rxchain_pwrsave_enable", want: 0, tplink: "0"},
		driverIovar{name: "radio_pwrsave_enable", want: 0, tplink: "0"})
}

// allDriverIovars are the names the baseline captures for band.
func allDriverIovars(band string) []string {
	var out []string
	for _, d := range driverIovars(band, true) {
		out = append(out, d.name)
	}
	return append(out, interfOverIov, interferenceIov)
}

// radioBSSLoad: whether the radio advertises the BSS Load element, and a
// note when an SSID on it asked otherwise. The element is per radio in this
// driver (the bssload iovar). As deco-crosscheck bssload specifies, it is
// on only when no SSID served on the radio has the controller's
// qbssload=disabled (the default: wireless.N.qbssload absent), and on for a
// radio that serves none. One SSID that turns it off (an enhanced-IoT
// WLAN) turns it off for the radio; when other SSIDs share the radio, a
// note says they lose it too.
func radioBSSLoad(rl *radioLayout) (bool, string) {
	var off, on []string
	for _, u := range rl.Used {
		if u.SSID.NoBSSLoad {
			off = append(off, u.SSID.ID)
		} else {
			on = append(on, u.SSID.ID)
		}
	}
	switch {
	case len(off) == 0:
		return true, ""
	case len(on) == 0:
		return false, ""
	}
	return false, fmt.Sprintf("ssid %s: the controller turned the BSS Load element off (qbssload disabled); Broadcom BSS Load is radio-wide, so ssid %s on the same radio goes without it too",
		strings.Join(off, ","), strings.Join(on, ","))
}

// unread marks an iovar that could not be read (interference_override may
// read -1, its "auto").
const unread = -1 << 30

// readDriver reads the radio's driver settings (unread when a getter fails).
func (a *Applier) readDriver(ctx context.Context, primary, band string) map[string]int {
	m := map[string]int{}
	for _, n := range allDriverIovars(band) {
		out, err := a.wlGet(ctx, primary, n)
		v := unread
		if err == nil {
			switch n {
			case interferenceIov:
				if x, ok := parseInterference(out); ok {
					v = x
				}
			case interfOverIov:
				if x, ok := parseInterferenceOverride(out); ok {
					v = x
				}
			default:
				if x, err := parseIntOut(out); err == nil && x >= 0 {
					v = x
				}
			}
		}
		m[n] = v
	}
	return m
}

// parseInterference reads `wl interference`: the mode number. The X20
// (wl 17.10.121.39) prints "Mode = 361. Following ACI modes are enabled:"
// and a bit list; "Mode 361", "mode: 360" and a bare "361" are read too.
// Anything else is unreadable (left alone).
func parseInterference(s string) (int, bool) {
	n, ok := parseModeNum(s)
	return n, ok && n >= 0
}

// parseInterferenceOverride reads `wl interference_override`, which the
// X20 prints as "Mode = -1. Following ACI modes :\nInterference override
// disabled." (-1 is off); a bare number is read too.
func parseInterferenceOverride(s string) (int, bool) {
	if n, err := parseIntOut(s); err == nil {
		return n, true
	}
	return parseModeNum(s)
}

// parseModeNum finds the number after "mode" (optionally "mode:", "mode
// =", "(mode"), else a leading number.
func parseModeNum(s string) (int, bool) {
	num := func(w string) (int, bool) {
		n, err := strconv.ParseInt(strings.Trim(w, "():,."), 0, 32)
		return int(n), err == nil
	}
	f := strings.Fields(strings.ToLower(s))
	for i, w := range f {
		if strings.TrimRight(strings.TrimLeft(w, "("), ":=") != "mode" {
			continue
		}
		j := i + 1
		if j < len(f) && (f[j] == "=" || f[j] == ":") {
			j++
		}
		if j < len(f) {
			if n, ok := num(f[j]); ok {
				return n, true
			}
		}
	}
	if len(f) > 0 {
		return num(f[0])
	}
	return 0, false
}

// driverPlan is what one radio's driver settings need.
type driverPlan struct {
	profile []Step // every setting at its wanted value (radioProfile, radio down)
	down    []Step // the radio-down ones that differ (ride along a radio down/up)
	live    []Step // the live ones that differ (run with the radio up)
	diff    []string
}

// planDriver compares the radio's live driver settings with the wanted
// ones. An unreadable setting is left out of down and live (it is still in
// the profile, which is optional step by step).
//
// keepDesense (Options.KeepDesense, config rx_desense) leaves TP-Link's
// interference mitigation, and puts the receiver desense back on a radio
// that reads without it (an earlier run without the opt-out cleared it):
// baseMode, the baseline's mode, when it has the bit, else the live mode
// with the bit. Live, no restart.
func planDriver(p, band string, live map[string]int, bssload, keepDesense bool, baseMode int) driverPlan {
	var dp driverPlan
	set := func(name string, v int) Step {
		return optStep("U6 parity "+name, "wl", "-i", p, name, fmtIovar(name, v))
	}
	for _, d := range driverIovars(band, bssload) {
		dp.profile = append(dp.profile, set(d.name, d.want))
		lv, ok := live[d.name]
		if !ok || lv == unread || lv == d.want {
			continue
		}
		dp.diff = append(dp.diff, fmt.Sprintf("%s %s -> %s", d.name, fmtIovar(d.name, lv), fmtIovar(d.name, d.want)))
		if d.live {
			dp.live = append(dp.live, set(d.name, d.want))
		} else {
			dp.down = append(dp.down, set(d.name, d.want))
		}
	}
	if keepDesense {
		if m, ok := live[interferenceIov]; ok && m != unread && m&desenseBit == 0 {
			w := m | desenseBit
			if baseMode != unread && baseMode&desenseBit != 0 {
				w = baseMode
			}
			dp.diff = append(dp.diff, fmt.Sprintf("interference mode %d -> %d (rx_desense: receiver desense back on)", m, w))
			dp.live = append(dp.live, optStep("rx_desense: interference (desense on)", "wl", "-i", p, interferenceIov, itoa(w)))
		}
		return dp
	}
	// Interference mitigation applies live (SET_INTERFERENCE_MODE suspends
	// the MAC and re-runs the noise mode; a radio that is down answers
	// NOTUP), so it is never part of the profile.
	if ov, ok := live[interfOverIov]; ok && ov != unread && ov != -1 {
		dp.diff = append(dp.diff, fmt.Sprintf("%s %d -> -1", interfOverIov, ov))
		dp.live = append(dp.live, optStep("U6 parity "+interfOverIov, "wl", "-i", p, interfOverIov, "-1"))
	}
	if m, ok := live[interferenceIov]; ok && m != unread && m&desenseBit != 0 {
		w := m &^ desenseBit
		dp.diff = append(dp.diff, fmt.Sprintf("interference mode %d -> %d (receiver desense off)", m, w))
		dp.live = append(dp.live, optStep("U6 parity interference (desense off)", "wl", "-i", p, interferenceIov, itoa(w)))
	}
	return dp
}

// fmtIovar prints a value the way the plan writes it (vht_features in hex).
func fmtIovar(name string, v int) string {
	if name == "vht_features" {
		return fmt.Sprintf("0x%x", v)
	}
	return itoa(v)
}

// driverStatus is a radio's driver-parity line in the plan notes and
// Tick's log. downSet: the radio-down settings are written in this plan.
func driverStatus(dp driverPlan, downSet bool) string {
	if len(dp.diff) == 0 {
		return "driver settings as a U6 Pro"
	}
	s := "driver settings to a U6 Pro's: " + strings.Join(dp.diff, ", ")
	switch {
	case len(dp.down) == 0:
		return s + " (live)"
	case downSet:
		return s + " (live, or inside this plan's radio down/up)"
	}
	return s + "; the radio-down ones at the next radio down/up (a channel, country or hostapd change, a dwds repair, the next boot), never by a restart of their own"
}

// driverRestore are the steps that put TP-Link's driver settings back on
// a radio the agent lets go: the baseline's values, else TP-Link's known
// ones. down need the radio down, live run after it is up. Settings that
// already match, or cannot be read, are left alone.
func (a *Applier) driverRestore(ctx context.Context, p, band string, br *baseRadio) (down, live []Step) {
	have := map[string]string{}
	if br != nil {
		for _, io := range br.Iovars {
			have[io[0]] = io[1]
		}
	}
	tp := map[string]driverIovar{}
	for _, d := range driverIovars(band, true) {
		tp[d.name] = d
	}
	cur := a.readDriver(ctx, p, band)
	for _, n := range allDriverIovars(band) {
		want, ok := have[n]
		if !ok {
			want = tp[n].tplink
		}
		if want == "" {
			want = tplinkFallback[n]
		}
		if want == "" {
			continue
		}
		w, err := strconv.ParseInt(want, 0, 32)
		if err != nil || cur[n] == unread || cur[n] == int(w) {
			continue
		}
		s := optStep("restore TP-Link "+n, "wl", "-i", p, n, want)
		if d, listed := tp[n]; listed && !d.live {
			down = append(down, s)
		} else {
			live = append(live, s)
		}
	}
	return down, live
}

// captureDriver reads the radio's driver settings for the baseline.
func (a *Applier) captureDriver(ctx context.Context, p, band string) [][2]string {
	var out [][2]string
	cur := a.readDriver(ctx, p, band)
	for _, n := range allDriverIovars(band) {
		if v := cur[n]; v != unread {
			out = append(out, [2]string{n, fmtIovar(n, v)})
		}
	}
	return out
}

// baseDriver is the baseline's value of a radio-wide driver setting
// (unread when there is none).
func (a *Applier) baseDriver(primary, name string) int {
	b, err := a.loadBaseline()
	if err != nil || b == nil {
		return unread
	}
	for _, r := range b.Radios {
		if r.Primary != primary {
			continue
		}
		for _, io := range r.Iovars {
			if io[0] == name {
				if v, err := strconv.ParseInt(io[1], 0, 32); err == nil {
					return int(v)
				}
			}
		}
	}
	return unread
}

// backfillBaseline completes a baseline an older agent captured without the
// radio-wide driver settings (a unit upgraded in place, still in takeover:
// Apply captures a baseline only when there is none). The older agent never
// changed these settings, so what the radio reads before this agent's first
// change is TP-Link's. Run once per process, before the first Apply or Tick
// changes anything; called with a.mu held.
func (a *Applier) backfillBaseline(ctx context.Context) {
	if a.backfilled {
		return
	}
	a.backfilled = true
	b, err := a.loadBaseline()
	if err != nil || b == nil {
		return
	}
	changed := false
	for i := range b.Radios {
		r := &b.Radios[i]
		if len(r.Iovars) > 0 || !a.netdevExists(r.Primary) {
			continue
		}
		if r.Iovars = a.captureDriver(ctx, r.Primary, r.Band); len(r.Iovars) > 0 {
			changed = true
			a.o.Logf("bcmwifi: baseline: %s driver settings recorded as TP-Link left them (an older agent's baseline lacked them)", r.Primary)
		}
	}
	if !changed {
		return
	}
	data, err := json.MarshalIndent(b, "", " ")
	if err == nil {
		err = writeFileAtomic(a.fsPath(a.baselinePath()), data, 0o600)
	}
	if err != nil {
		a.o.Logf("bcmwifi: baseline: backfill of driver settings failed: %v", err)
	}
}
