// SPDX-License-Identifier: GPL-2.0-or-later

package openwrt

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

var update = flag.Bool("update", false, "rewrite golden files")

// golden compares got with testdata/golden/<name> (go test -update
// rewrites the file).
func golden(t *testing.T, name, got string) {
	t.Helper()
	gold := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(gold), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(gold, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(gold)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if got != string(want) {
		t.Errorf("differs from %s:\n--- got\n%s\n--- want\n%s", gold, got, want)
	}
}

// The guest rules as they were rendered when the portal ports were
// written into them: every port now comes from internal/device
// (PortalPort, PortalHostPorts) and from localRedirectPort, and the text
// must not change by a byte.
func TestGuestRulesGolden(t *testing.T) {
	plain := translate.Guest{Restricted: []string{"192.168.0.0/16", "10.0.0.0/8"}, PreAllow: []string{"192.168.1.9"}}
	portal := plain
	portal.Portal, portal.PortalURL, portal.PortalHost = true, "http://192.168.1.1:8880/guest/s/default/", "192.168.1.1"
	for _, c := range []struct {
		name  string
		g     translate.Guest
		brMAC string
	}{
		{"guest_plain.nft", plain, "08:55:66:77:00:01"},
		{"guest_plain_no_forwarder.nft", plain, ""},
		{"guest_portal.nft", portal, "08:55:66:77:00:01"},
		{"guest_portal_no_forwarder.nft", portal, ""},
	} {
		rs, err := guestRuleset([]string{"phy0-ap2", "phy1-ap2"}, c.g, []string{"192.168.1.53", "192.168.1.1"}, c.brMAC)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		golden(t, c.name, rs)
	}
	golden(t, "guest_forwarder_portal.sh", guestForwarder("192.168.1.2", portalStart(portal.PortalURL)))
	golden(t, "guest_forwarder.sh", guestForwarder("192.168.1.2", portalStop))
}
