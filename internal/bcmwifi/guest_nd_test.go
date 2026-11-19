// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"strings"
	"testing"
)

// ndFrame is an ICMPv6 frame from a guest, as UDECO-GIN sees it.
type ndFrame struct {
	dstMAC    string // "" = multicast
	icmpType  string // ebtables name of the ICMPv6 type
	multicast bool
}

// firstTarget walks the rendered UDECO-GIN rules the way ebtables would for
// an ICMPv6 frame and returns the first matching rule's target. Only the
// matches an IPv6 ICMP frame can hit are modelled; a rule with any other
// match (IPv4 fields, ports, ARP, EAPOL) does not match.
func firstTarget(t *testing.T, rules [][]string, f ndFrame) string {
	t.Helper()
	for _, r := range rules {
		match, target := true, ""
		for i := 0; i < len(r); i++ {
			arg := func() string {
				i++
				if i >= len(r) {
					t.Fatalf("rule %v: option without value", r)
				}
				return r[i]
			}
			switch r[i] {
			case "-p":
				match = match && arg() == "IPv6"
			case "-d":
				v := arg()
				if v == "!" {
					match = match && f.dstMAC != arg()
				} else if v == "Multicast" {
					match = match && f.multicast
				} else {
					match = match && f.dstMAC == v
				}
			case "--ip6-proto":
				match = match && arg() == "58"
			case "--ip6-icmp-type":
				match = match && arg() == f.icmpType
			case "--ip6-dst":
				arg()
				match = false // only fc00::/7 here; the frames below are not ULA
			case "-j":
				target = arg()
			default:
				match = false
				if strings.HasPrefix(r[i], "-") && i+1 < len(r) {
					i++
				}
			}
		}
		if match {
			return target
		}
	}
	return "DROP (policy)"
}

// A guest must not become the LAN's IPv6 router (rogue RA to ff02::1 or to
// the gateway), redirect hosts, or poison neighbour caches with an
// unsolicited multicast NA; neighbour solicitations and NAs to the gateway
// still work, so the guest's IPv6 does.
func TestGuestRouterAdvertisementsDropped(t *testing.T) {
	r, notes := normalizeGuest(&GuestPolicy{GatewayMAC: gwMAC, GatewayIP: gwIP})
	if r == nil {
		t.Fatal(notes)
	}
	in, _ := r.render()
	for _, c := range []struct {
		name string
		f    ndFrame
		want string
	}{
		{"RA to all nodes", ndFrame{multicast: true, icmpType: "router-advertisement"}, "DROP"},
		{"RA to the gateway", ndFrame{dstMAC: gwMAC, icmpType: "router-advertisement"}, "DROP"},
		{"redirect to all nodes", ndFrame{multicast: true, icmpType: "redirect"}, "DROP"},
		{"unsolicited NA to all nodes", ndFrame{multicast: true, icmpType: "neighbour-advertisement"}, "DROP"},
		{"NS to a solicited-node group", ndFrame{multicast: true, icmpType: "neighbour-solicitation"}, "ACCEPT"},
		{"RS to all routers", ndFrame{multicast: true, icmpType: "router-solicitation"}, "ACCEPT"},
		{"NA to the gateway", ndFrame{dstMAC: gwMAC, icmpType: "neighbour-advertisement"}, "ACCEPT"},
	} {
		if got := firstTarget(t, in, c.f); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}
