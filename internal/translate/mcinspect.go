// SPDX-License-Identifier: GPL-2.0-or-later

package translate

// MulticastInspect returns the devnames of the VAPs the controller wants
// multicast inspection on: wireless.N.multicast.inspect. The controller
// (Network 11.1.50, the AP system.cfg generator) writes it on every WLAN,
// "true" for a non-service WLAN when the AP claims fw3_caps 0x80
// (supportsMulticastInspect) and "false" otherwise. A disabled WLAN is left
// out (its VAP does not beacon).
func MulticastInspect(cfg Cfg) map[string]bool {
	out := map[string]bool{}
	for _, n := range indices(cfg, "wireless") {
		w := "wireless." + n + "."
		d := cfg[w+"devname"]
		if d == "" || cfg[w+"status"] == "disabled" || !isOn(cfg[w+"multicast.inspect"]) {
			continue
		}
		out[d] = true
	}
	return out
}
