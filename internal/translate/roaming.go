// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"strconv"
	"strings"
)

// Roaming Assistant (docs/deco/features/roaming-assistant.md).
//
// Network 11.1.50 (com.ubnt.service.config.ubntconf assisted-roaming config
// factory, called once per VAP by the AP system_cfg generator) writes, only
// when the device claims wifi_caps2 0x20 (com.ubnt.data device
// supportsAssistedRoaming), only on a 5 GHz or 6 GHz VAP, never on a WDS or
// element-adopt VAP, and only when the WLAN has roaming_assistant_na_enabled
// (roaming_assistant_6e_enabled):
//
//	wireless.N.btm_disassoc.status=enabled
//	wireless.N.btm_disassoc.threshold=<RSSI dBm>
//
// The threshold is the WLAN's roaming_assistant_na_rssi (UI range -60..-80,
// default -75) or roaming_assistant_6e_rssi (-70..-90, default -88). When
// the feature is off nothing is written (a real UAP's own template may still
// carry status=disabled). A UAP turns this into its driver's btm_disassoc 1
// and btm_dis_thld <threshold> (ubntbox strings, docs/reference/u6pro).

// The thresholds taken as sent; anything outside falls back to the
// controller's default for the band (a UI value is always inside).
const (
	RoamAssistMinDBm = -95
	RoamAssistMaxDBm = -40
)

// roamAssistDefault is the controller's default threshold per band
// (QdjEeOBh: -75 on 5 GHz, -88 on 6 GHz).
var roamAssistDefault = map[string]int{"na": -75, "6e": -88}

// roamAssist reads a VAP's Roaming Assistant: on, and its RSSI threshold in
// dBm. A Roaming Assistant on a WLAN without BSS transition (802.11v) is
// left off: the assistant works through BSS Transition Management requests,
// which a station need not act on from a BSS that does not advertise BSS
// transition, and its disassociation timer would then only disconnect it.
func roamAssist(cfg Cfg, w, band string, bssTransition bool, note func(string, ...any)) (int, bool) {
	if cfg[w+"btm_disassoc.status"] != "enabled" {
		return 0, false
	}
	if !bssTransition {
		note("roaming assistant needs BSS transition (802.11v), which is off for this WLAN: roaming assistant off")
		return 0, false
	}
	v := strings.TrimSpace(cfg[w+"btm_disassoc.threshold"])
	t, err := strconv.Atoi(v)
	if err == nil && t >= RoamAssistMinDBm && t <= RoamAssistMaxDBm {
		return t, true
	}
	d, ok := roamAssistDefault[band]
	if !ok {
		d = roamAssistDefault["na"]
	}
	if len(v) > 8 {
		v = v[:8] + "..."
	}
	note("roaming assistant threshold %q not recognised: %d dBm", v, d)
	return d, true
}

// mergeBandInts folds one band's values into a WLAN's per-band map.
func mergeBandInts(dst, src map[string]int) map[string]int {
	for k, v := range src {
		if dst == nil {
			dst = map[string]int{}
		}
		dst[k] = v
	}
	return dst
}
