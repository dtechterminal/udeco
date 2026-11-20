// SPDX-License-Identifier: GPL-2.0-or-later

package jioports

import (
	"os"
	"path/filepath"
	"testing"
)

// The VLAN bridges are the applier's br-v<vid> (unit.VLANBridge): what a
// port's place is matched against, and what is read back.
func TestVLANBridgeNames(t *testing.T) {
	for _, c := range []struct {
		br     string
		native int
		want   bool
	}{
		{"", -1, true}, {"bdg2", -1, false},
		{"bdg2", 0, true}, {"br-v0", 0, false}, {"", 0, false},
		{"br-v6", 6, true}, {"br-v06", 6, false}, {"br-v7", 6, false}, {"bdg2", 6, false}, {"", 6, false},
	} {
		if got := matchBridge(c.br, c.native, "bdg2"); got != c.want {
			t.Errorf("matchBridge(%q, %d) = %v", c.br, c.native, got)
		}
	}
	for name, want := range map[string]string{"br-v6": "6", "br-v4094": "4094", "br-v12345": "12345", "br-v06": "06",
		"br-v": "", "br-vlan": "", "bdg2": "", "xbr-v6": "", "br-v6 ": "", "br-v-6": ""} {
		got := ""
		if m := vlanBrRE.FindStringSubmatch(name); m != nil {
			got = m[1]
		}
		if got != want {
			t.Errorf("vlanBrRE on %q = %q, want %q", name, got, want)
		}
	}
}

// VLANMACs finds a port's native VLAN bridge among /sys/class/net/br-v*,
// and takes only names that are a VLAN bridge's.
func TestVLANMACsBridges(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{
		"sys/class/net/br-v20/brif/" + Untagged(2),
		"sys/class/net/br-vlan/brif/" + Untagged(3), // br-v*, but no VLAN bridge
		"sys/class/net/bdg2/brif/" + Untagged(1),
	} {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if rows, ok := VLANMACs(root, 2); !ok || len(rows) != 0 {
		t.Errorf("port 2 in br-v20: %v, %v", rows, ok)
	}
	for _, phys := range []int{1, 3, 4} {
		if rows, ok := VLANMACs(root, phys); ok || rows != nil {
			t.Errorf("port %d is in no VLAN bridge: %v, %v", phys, rows, ok)
		}
	}
}
