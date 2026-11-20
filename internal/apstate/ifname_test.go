// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

import "testing"

// IfNameChars: 1 to 15 characters of [A-Za-z0-9._-], whatever the first.
// internal/wl, internal/bcmwifi and upstream's openwrt package hold their validators
// to the same answers (each had its own copy of this loop or pattern).
func TestIfNameChars(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		// the supported units' names
		{"wl0", true}, {"wl1.2", true}, {"eth0.4.1", true}, {"br-lan", true}, {"ra0", true}, {"rai0", true},
		{"apcli0", true}, {"phy0-ap0", true}, {"bdg2", true}, {"ifb1", true}, {"wds0.1.1", true},
		{"a", true}, {"Z", true}, {"0", true},
		// any first character of the set
		{"-x", true}, {".x", true}, {"_x", true}, {"-", true}, {"..", true},
		// length
		{"abcdefghijklmno", true}, {"abcdefghijklmnop", false}, {"", false},
		// anything else
		{"wl0 ", false}, {" wl0", false}, {"wl0\n", false}, {"wl\t0", false}, {"wl/0", false}, {"wl0;id", false},
		{"wl$0", false}, {"wl0'", false}, {"wl\"0", false}, {"wl:0", false}, {"wl,0", false}, {"wl+0", false},
		{"wl\x000", false}, {"wlé0", false}, {"wl\xff0", false}, {"$(id)", false}, {"`id`", false},
	} {
		if got := IfNameChars(c.in); got != c.want {
			t.Errorf("IfNameChars(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
