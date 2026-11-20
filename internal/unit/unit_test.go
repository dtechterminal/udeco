// SPDX-License-Identifier: GPL-2.0-or-later

package unit

import "testing"

// The paths installed units have: a changed value strands an install. The
// deploy scripts write them out too (cmd/udeco-ap TestUnitLayout).
func TestInstallPaths(t *testing.T) {
	for _, c := range [][2]string{
		{DecoDir, "/tp_data/udeco"}, {JioDir, "/flash2/udeco"}, {RunDir, "/tmp/udeco"}, {RAMDir, "/tmp/udeco-bin"},
		{ConfigFile, "udeco-ap.json"}, {Launcher, "start.sh"}, {StateSub, "state"},
	} {
		if c[0] != c[1] {
			t.Errorf("%q, want %q", c[0], c[1])
		}
	}
}

func TestBridgeNames(t *testing.T) {
	if LANBridge != "br-lan" || JioLANBridge != "bdg2" || VLANBridgePrefix != "br-v" {
		t.Errorf("bridges %q %q %q", LANBridge, JioLANBridge, VLANBridgePrefix)
	}
	for vid, want := range map[int]string{1: "br-v1", 20: "br-v20", 4094: "br-v4094", 0: "br-v0"} {
		if got := VLANBridge(vid); got != want {
			t.Errorf("VLANBridge(%d) = %q, want %q", vid, got, want)
		}
		if got, ok := ParseVLANBridge(want); !ok || got != vid {
			t.Errorf("ParseVLANBridge(%q) = %d, %v", want, got, ok)
		}
	}
}

func TestParseVLANBridge(t *testing.T) {
	for name, want := range map[string]int{"br-v7": 7, "br-v0020": 20, "br-v99999": 99999} {
		if got, ok := ParseVLANBridge(name); !ok || got != want {
			t.Errorf("ParseVLANBridge(%q) = %d, %v, want %d", name, got, ok, want)
		}
	}
	for _, name := range []string{"", "br-v", "br-lan", "bdg2", "br-v+5", "br-v-5", "br-v5x", "br-v 5", "xbr-v5",
		"br-vx", "br-v5.1", "BR-V5", "br-v99999999999999999999999"} {
		if got, ok := ParseVLANBridge(name); ok {
			t.Errorf("ParseVLANBridge(%q) = %d, want not a VLAN bridge", name, got)
		}
	}
}
