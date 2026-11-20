// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"reflect"
	"testing"
)

// TestGuestEbtables: the exported guest rules are bcmwifi's own (the same
// fail-closed chains on another platform), nil for an unusable policy.
func TestGuestEbtables(t *testing.T) {
	g := &GuestPolicy{GatewayMAC: "00:11:22:33:44:55", GatewayIP: "192.168.0.1", Portal: true, PortalHost: "192.168.0.2"}
	r := GuestEbtables(g)
	if r == nil || !r.Portal {
		t.Fatalf("rules %+v", r)
	}
	n, _ := normalizeGuest(g)
	in, out := n.render()
	if !reflect.DeepEqual(r.In, in) || !reflect.DeepEqual(r.Out, out) {
		t.Errorf("rules differ from bcmwifi's")
	}
	if r.ChainIn != chainGuestIn || r.ChainOut != chainGuestOut || r.ChainAuth != chainGuestAuth {
		t.Errorf("chains %s %s %s", r.ChainIn, r.ChainOut, r.ChainAuth)
	}
	if GuestEbtables(&GuestPolicy{GatewayIP: "192.168.0.1"}) != nil || GuestEbtables(nil) != nil {
		t.Error("rules for a policy without a gateway MAC")
	}
}
