// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

// hostapd's interface= vif per radio (the "anchor"): the one vif that
// survives a hostapd exit, used as the agent's hidden placeholder BSS.
//
// TP-Link lays the radios out differently on the mesh master and on a
// satellite (read on .241 and .205, 2026-11-19):
//   - satellite: the primary wlN is the backhaul STA; TP-Link's hostapd
//     (/tmp/wlN.1_hapd.conf) has interface=wlN1 and creates wlN2.. itself;
//   - master: the primary wlN is an AP; TP-Link's hostapd
//     (/tmp/wlN_hapd.conf) has interface=wlN and creates wlN1 (its hidden
//     backhaul BSS) and wlN2.. itself, so wlN1 is gone the moment that
//     hostapd stops.
// An agent that always used wlN1 failed its first apply on the master
// ("wl01 does not exist"). The anchor is therefore learned from the
// hostapd that runs (TP-Link's before the takeover, the agent's after it,
// TP-Link's again after a reboot); with none known it is wlN1 when that
// exists (a satellite), else wlN.

// apResetSteps prepare a primary for a hostapd whose interface= is the
// primary itself (the master). After any hostapd on it has exited (it sets
// the netdev back to STATION on the way out), the driver refuses the
// primary's wpa_cap iovar, so the next hostapd fails "Beacon set failed:
// -1 (Operation not permitted)" (dmesg: "wl_validate_wpa2ie: Set wpa_cap
// for preauth error -1"), TP-Link's own hostapd included. The primary also
// keeps mfp=1 from WPA3 BSSes. Toggling AP mode with the radio down clears
// it (verified on .241, 2026-11-19: wpa_cap set failed in every radio
// state until wl ap 0 / wl ap 1, then TP-Link's hostapd came up). The up
// runs whatever happens.
func apResetSteps(p string, optional bool) []Step {
	mk := cmdStep
	if optional {
		mk = optStep
	}
	return []Step{
		mk("radio "+p+" down for AP reset", "wl", "-i", p, "down"),
		mk("AP reset "+p+": ap 0", "wl", "-i", p, "ap", "0"),
		mk("AP reset "+p+": ap 1", "wl", "-i", p, "ap", "1"),
		optStep("AP reset "+p+": mfp 0", "wl", "-i", p, "mfp", "0"),
		optStep("radio "+p+" up after AP reset", "wl", "-i", p, "up"),
	}
}

// learnAnchor records iface as primary's anchor when it is one of the
// radio's own vifs.
func (a *Applier) learnAnchor(primary, iface string) {
	if a.anchors == nil {
		a.anchors = map[string]string{}
	}
	if iface == primary || iface == primary+"1" {
		a.anchors[primary] = iface
	}
}

// anchor is primary's hostapd interface= vif.
func (a *Applier) anchor(primary string) string { return a.anchorWith(primary, a.vifKnown) }

func (a *Applier) anchorWith(primary string, known func(string) bool) string {
	if v := a.anchors[primary]; v != "" {
		return v
	}
	// the hostapd running now says it: the agent's own, else TP-Link's
	// (on the master wlN1 exists while TP-Link's runs, so existence alone
	// would pick the wrong vif)
	if a.o.Run != nil {
		if _, ours := a.ourHostapd(primary); ours {
			var h hapdProc
			h.hapdConf(a, confPath(a.o.RunDir, primary))
			a.learnAnchor(primary, h.Iface)
		} else if tp, ok := a.tplinkHostapd(primary); ok {
			a.learnAnchor(primary, tp.Iface)
		}
		if v := a.anchors[primary]; v != "" {
			return v
		}
	}
	if known(primary + "1") {
		return primary + "1"
	}
	return primary
}
