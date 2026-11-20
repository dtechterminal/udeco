// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
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
//     with the radio up (iovar flags 0); on when any SSID of the radio wants
//     it (bssload).
//   - Implicit beamforming off (U6 implicitbf 0): `wl txbf_imp 0`.
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
		{name: "txbf_imp", want: 0, tplink: tplinkTxbfImp},
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
// driver (the bssload iovar), so it is on when any SSID served on the radio
// wants it (the controller's default: wireless.N.qbssload absent), and on
// for a radio that serves none.
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
	return true, fmt.Sprintf("ssid %s: the controller turned the BSS Load element off (qbssload disabled), but it is radio-wide here and ssid %s on the same radio wants it: advertised",
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
			default:
				if x, err := parseIntOut(out); err == nil && (x >= 0 || n == interfOverIov) {
					v = x
				}
			}
		}
		m[n] = v
	}
	return m
}

// parseInterference reads `wl interference`: the mode number, written
// "Mode 361 ...", "mode 361", or a bare "361". The exact wording on the
// X20 is not captured; anything else is unreadable (left alone).
func parseInterference(s string) (int, bool) {
	f := strings.Fields(strings.ToLower(s))
	for i, w := range f {
		if strings.TrimRight(w, ":=") == "mode" && i+1 < len(f) {
			if n, err := strconv.ParseInt(strings.Trim(f[i+1], "():,"), 0, 32); err == nil && n >= 0 {
				return int(n), true
			}
		}
		if strings.HasPrefix(w, "(mode") && i+1 < len(f) {
			if n, err := strconv.ParseInt(strings.Trim(f[i+1], "():,"), 0, 32); err == nil && n >= 0 {
				return int(n), true
			}
		}
	}
	if len(f) > 0 {
		if n, err := strconv.ParseInt(strings.Trim(f[0], "():,"), 0, 32); err == nil && n >= 0 {
			return int(n), true
		}
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
func planDriver(p, band string, live map[string]int, bssload, keepDesense bool) driverPlan {
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
