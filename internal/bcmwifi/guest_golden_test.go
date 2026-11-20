// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
)

// The portal ports as --ip-dport takes them: consecutive ports fold into
// one range, each run where the list first names one of its ports.
func TestPortRanges(t *testing.T) {
	if want := []string{"8880:8882", "8843"}; !slices.Equal(portalPorts, want) || !slices.Equal(portRanges(device.PortalHostPorts()), want) {
		t.Errorf("portal ports %q, want %q", portalPorts, want)
	}
	for _, c := range []struct {
		in   []int
		want []string
	}{
		{nil, nil},
		{[]int{80}, []string{"80"}},
		{[]int{80, 443}, []string{"80", "443"}},
		{[]int{443, 80}, []string{"443", "80"}},
		{[]int{8880, 8881, 8882, 8843}, []string{"8880:8882", "8843"}},
		{[]int{8843, 8882, 8880, 8881}, []string{"8843", "8880:8882"}},
		{[]int{5, 3, 4, 4, 9}, []string{"3:5", "9"}},
	} {
		if got := portRanges(c.in); !slices.Equal(got, c.want) {
			t.Errorf("portRanges(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The guest chains' rules as they were rendered when the portal ports
// were written here ("8880:8882", "8843"): the ports now come from
// internal/device (PortalHostPorts), and the rules must not change by a
// byte, order included.
func TestGuestRulesGolden(t *testing.T) {
	for name, portal := range map[string]bool{"guest_rules.txt": false, "guest_rules_portal.txt": true} {
		r, notes := normalizeGuest(guestDesired(portal).Guest)
		if r == nil {
			t.Fatalf("%s: no rules (%v)", name, notes)
		}
		in, out := r.render()
		var b strings.Builder
		for _, rule := range in {
			b.WriteString("-A " + GuestChainIn + " " + strings.Join(rule, " ") + "\n")
		}
		for _, rule := range out {
			b.WriteString("-A " + GuestChainOut + " " + strings.Join(rule, " ") + "\n")
		}
		gold := filepath.Join("testdata", "golden", name)
		if *update {
			if err := os.WriteFile(gold, []byte(b.String()), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(gold)
		if err != nil {
			t.Fatalf("%v (run go test -update)", err)
		}
		if b.String() != string(want) {
			t.Errorf("differs from %s:\n--- got\n%s\n--- want\n%s", gold, b.String(), want)
		}
	}
}
