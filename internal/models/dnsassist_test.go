package models

import (
	"reflect"
	"testing"
)

// fw3CapDNSAssistance is the controller's supportsDnsAssistance()
// (XCfthFC.hasFirmware3Capability(8)). It is deliberately not a constant in
// agent.go: the Deco cannot do DNS assistance.
//
// With the bit, the controller sends, per VAP whose WLAN has
// dns_assistance_mode auto|manual: wireless.N.dns_cache.status=enabled,
// wireless.N.dns_bypass.status=enabled and (manual only)
// wireless.N.dns_bypass.servers=<ip>[,<ip>]. A UAP hands these to its
// ui_dns_cache / ui_dns_bypass kernel modules, which rewrite the bridged
// DNS traffic of the VAP's clients. The X20 kernel has no
// CONFIG_BRIDGE_NETFILTER and no ebtables dnat/redirect/snat target (neither
// in the kernel config nor as a userspace extension), so bridged client DNS
// cannot be diverted or rewritten by ebtables or iptables; a broute "route"
// decision only hands the frame to ip_rcv, which drops it as
// PACKET_OTHERHOST (its destination MAC is the gateway's).
const fw3CapDNSAssistance = 0x8

// No profile claims DNS assistance, whatever features are on: a wrong bit
// makes the controller send dns_cache/dns_bypass sections nothing applies,
// and offers "DNS Assistance" as working on this AP.
func TestDecoAgentNeverClaimsDNSAssistance(t *testing.T) {
	m, ok := Lookup("UAL6")
	if !ok {
		t.Fatal("UAL6 not in the catalogue")
	}
	var all DecoAgentFeatures
	v := reflect.ValueOf(&all).Elem()
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() == reflect.Bool {
			v.Field(i).SetBool(true)
		}
	}
	for name, f := range map[string]DecoAgentFeatures{"observe": {}, "every feature": all} {
		p, ok := DecoAgentProfileWith(m, nil, f)
		if !ok {
			t.Fatalf("%s: UAL6 refused", name)
		}
		if p.FW3Caps&fw3CapDNSAssistance != 0 {
			t.Errorf("%s: fw3_caps %#x claims DNS assistance (0x8)", name, p.FW3Caps)
		}
	}
	if DecoAgentFW3Caps&fw3CapDNSAssistance != 0 || DecoAgentTakeoverFW3Caps&fw3CapDNSAssistance != 0 {
		t.Error("a fw3_caps constant includes DNS assistance (0x8)")
	}
}
