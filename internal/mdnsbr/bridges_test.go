// SPDX-License-Identifier: GPL-2.0-or-later

package mdnsbr

import "testing"

// The local bridges are bcmwifi's: br-lan for the untagged LAN (VLAN 1
// here) and unit.VLANBridge for VLANs 2-4094, in that spelling only.
func TestLocalBridgeNames(t *testing.T) {
	for vlan, want := range map[int]string{0: "br-lan", 1: "br-lan", 2: "br-v2", 20: "br-v20", 4094: "br-v4094"} {
		if got := LocalBridge(vlan); got != want {
			t.Errorf("LocalBridge(%d) = %q, want %q", vlan, got, want)
		}
	}
	for name, want := range map[string]int{"br-lan": 1, "br-v2": 2, "br-v20": 20, "br-v4094": 4094} {
		if got, ok := localVLAN(name); !ok || got != want {
			t.Errorf("localVLAN(%q) = %d, %v, want %d", name, got, ok, want)
		}
	}
	for _, name := range []string{"", "br-v", "br-v0", "br-v1", "br-v4095", "br-v02", "br-v+2", "br-v-2", "br-v2x",
		"br-v 2", "xbr-v2", "bdg2", "br-lan0", "br-v99999999999999999999"} {
		if got, ok := localVLAN(name); ok {
			t.Errorf("localVLAN(%q) = %d, want no local bridge", name, got)
		}
	}
}
