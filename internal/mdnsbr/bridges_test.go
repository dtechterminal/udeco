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

// On the JCOW414 (Env.LANBridge bdg2) the untagged LAN is bdg2, br-lan is
// no bridge of this unit, an idle MediaTek BSS slot or AP-client netdev in
// a bridge is never tapped as a wired port, and a VLAN without a bridge is
// reached tagged on the uplink device the agent names.
func TestPlanJioBridges(t *testing.T) {
	c := Config{Enabled: true,
		Proxies: []Proxy{{Dst: "br0", Srcs: []string{"br0.7"}}},
		Filters: []Filter{{VLAN: 1, VAPs: []string{"rai0"}, Services: []string{"_airplay._tcp"}},
			{VLAN: 7, Allow: true, VAPs: []string{"rai0"}}}}
	env := Env{VAPs: map[string]string{"rai0": "rai0"}, Vifs: map[string]bool{"rai0": true}, Guest: map[string]bool{},
		Bridges: map[string][]string{"bdg2": {"eth0.1.1", "eth0.4.1", "rai0", "rai1", "ra2", "apclii0", "wds0"},
			"br-lan": {"eth9"}}, Uplink: "eth0.4", LANBridge: "bdg2"}
	p, notes := BuildPlan(c, env)
	var got []string
	for _, x := range p.Ports {
		got = append(got, x.Key())
	}
	want := []string{"eth0.1.1", "eth0.4.1", "rai0", Port{Name: "eth0.4", VID: 7, VLAN: 7}.Key()}
	if len(got) != len(want) {
		t.Fatalf("ports %v, want %v (notes %v)", got, want, notes)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ports %v, want %v", got, want)
			break
		}
	}
	if _, ok := p.Own["rai0"]; !ok {
		t.Errorf("rai0 not intercepted: %+v", p.Own)
	}
	for _, x := range []string{"ra0", "ra3", "rai0", "rai3", "apcli0", "apclii0", "wds1", "wdsi0", "wl12"} {
		if !wifiPort(x) {
			t.Errorf("wifiPort(%q) false", x)
		}
	}
	for _, x := range []string{"eth0.1.1", "eth0.4", "rax", "radio0", "br-v3", "bdg2"} {
		if wifiPort(x) {
			t.Errorf("wifiPort(%q) true", x)
		}
	}
}
