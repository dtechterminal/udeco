// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

// R21: a plan that changes the datapath ends with one flow-cache flush; an
// empty plan has none.
func TestPlanFlushesFlowCache(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	p := applyOK(t, a, twoSSIDs())
	last := p.Steps[len(p.Steps)-1]
	if strings.Join(last.Argv, " ") != "fc flush" || !last.Optional {
		t.Errorf("last step %s", last)
	}
	n := 0
	for _, s := range p.Steps {
		if len(s.Argv) > 0 && s.Argv[0] == "fc" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d flushes in one plan", n)
	}
	if p, _ := a.Plan(ctx, twoSSIDs()); !p.Empty() {
		t.Errorf("idle plan:\n%s", p)
	}
	// VLAN removal is a datapath change too.
	d := twoSSIDs()
	d.SSIDs = d.SSIDs[1:]
	p2, _ := a.Plan(ctx, d)
	stepIndex(t, p2, "brctl delbr br-v20")
	if s := p2.Steps[len(p2.Steps)-1]; strings.Join(s.Argv, " ") != "fc flush" {
		t.Errorf("VLAN removal plan ends with %s", s)
	}
}

// R21: block and unblock flush the station's flows.
func TestSetBlockedFlushesFlows(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	applyOK(t, a, twoSSIDs())
	f.reset()
	if err := a.SetBlocked(ctx, []string{sta1}); err != nil {
		t.Fatal(err)
	}
	if !f.called("fc flush --mac " + sta1) {
		t.Error("block did not flush")
	}
	f.reset()
	if err := a.SetBlocked(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if !f.called("fc flush --mac " + sta1) {
		t.Error("unblock did not flush")
	}
}

func TestFlushFlows(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	var logs []string
	a.o.Logf = func(format string, args ...any) { logs = append(logs, format) }
	f.write("/proc/fcache/brlist", "Broadcom Packet Flow Cache v4.0\nFlowObject idle tx_dev\n\n"+
		"0xd0f9e180@000258    0:     0  1:  116 0x00100092 000007 114 (null) (null) WPHY 0 6 <192.168.000.227:54286> <043.206.053.063:05223> 0x0000ffff 0x0000ffff 0 0 0x00000000 0 <02:00:00:00:00:a1> <1e:6a:1b:c5:04:c2> eth1\n")
	for _, c := range []struct {
		s    FlowScope
		argv string
	}{
		{FlowScope{}, "fc flush"},
		{FlowScope{If: "eth0"}, "fc flush --if eth0"},
		{FlowScope{MAC: strings.ToUpper(sta1)}, "fc flush --mac " + sta1},
	} {
		f.reset()
		if err := a.FlushFlows(ctx, c.s); err != nil {
			t.Fatal(err)
		}
		if m := f.mutating(); len(m) != 1 || strings.Join(m[0], " ") != c.argv {
			t.Errorf("%+v ran %v", c.s, m)
		}
	}
	if a.cachedFlows(FlowScope{MAC: sta1}) != 1 || a.cachedFlows(FlowScope{If: "eth1"}) != 1 || a.cachedFlows(FlowScope{MAC: sta2}) != 0 {
		t.Error("brlist count")
	}
	if !strings.Contains(strings.Join(logs, "\n"), "still in the flow cache") {
		t.Error("remaining flows not logged")
	}
	if err := a.FlushFlows(ctx, FlowScope{If: "eth0; reboot"}); err == nil {
		t.Error("bad interface accepted")
	}
	f.failOn = func(argv []string) bool { return argv[0] == "fc" }
	if err := a.FlushFlows(ctx, FlowScope{}); err == nil {
		t.Error("fc failure not reported")
	}
}

// R25: a VLAN device and its bridge get IPv6 disabled before link up.
func TestVLANDevicesWithoutIPv6(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	p := applyOK(t, a, twoSSIDs())
	put := stepIndex(t, p, "echo 1 > /proc/sys/net/ipv6/conf/eth1.20/disable_ipv6")
	if put < stepIndex(t, p, "ip link add link eth1 name eth1.20") || put > stepIndex(t, p, "ip link set eth1.20 up") {
		t.Error("disable_ipv6 not between create and link up")
	}
	brPut := stepIndex(t, p, "echo 1 > /proc/sys/net/ipv6/conf/br-v20/disable_ipv6")
	if brPut > stepIndex(t, p, "ip link set br-v20 up") {
		t.Error("bridge IPv6 disabled after link up")
	}
	for _, dev := range []string{"eth1.20", "br-v20"} {
		b, _ := os.ReadFile(f.path("/proc/sys/net/ipv6/conf/" + dev + "/disable_ipv6"))
		if strings.TrimSpace(string(b)) != "1" {
			t.Errorf("%s disable_ipv6 = %q", dev, b)
		}
	}
	// Re-enabled by something else: put back without recreating anything.
	f.write("/proc/sys/net/ipv6/conf/br-v20/disable_ipv6", "0\n")
	p2, _ := a.Plan(context.Background(), twoSSIDs())
	if len(p2.Steps) != 1 || p2.Steps[0].Kind != StepPut {
		t.Errorf("plan:\n%s", p2)
	}
}

func TestSteerToBand(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	if err := a.SteerToBand(ctx, "wl02", sta1, "02:00:00:00:00:01"); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("before takeover: %v", err)
	}
	applyOK(t, a, twoSSIDs())
	target, err := a.bssid(ctx, "wl12")
	if err != nil {
		t.Fatal(err)
	}
	f.reset()
	if err := a.SteerToBand(ctx, "wl02", strings.ToUpper(sta1), strings.ToUpper(target)); err != nil {
		t.Fatal(err)
	}
	// wl1 runs 44/80: operating class 115, BSSID info 0x18af (VHT), PHY 9.
	want := "hostapd_cli -p /var/run/udeco-hostapd -i wl02 bss_tm_req " + sta1 + " pref=1 abridged=1 neighbor=" + target + ",6319,115,44,9"
	if !f.called(want) {
		t.Errorf("missing %q in %v", want, f.mutating())
	}
	src, _ := a.bssid(ctx, "wl02")
	for _, c := range []struct{ vif, mac, bssid string }{
		{"wl05", sta1, target},              // not served
		{"wl02", sta1, src},                 // own BSS
		{"wl02", sta1, "02:00:00:00:99:99"}, // not ours
		{"wl02", "x", target},               // bad MAC
	} {
		if err := a.SteerToBand(ctx, c.vif, c.mac, c.bssid); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	for _, c := range []struct {
		band           string
		ch             int
		info, opc, phy int
	}{{"ng", 6, 0x08af, 81, 7}, {"na", 36, 0x18af, 115, 9}, {"na", 100, 0x18af, 121, 9}, {"na", 149, 0x18af, 125, 9}} {
		i, o, p := neighborInfo(c.band, c.ch)
		if i != c.info || o != c.opc || p != c.phy {
			t.Errorf("%s %d: %x %d %d", c.band, c.ch, i, o, p)
		}
	}
}

// The agent's uplink tracking moved the uplink (R9/D7): the VLAN bridges
// follow, and the old port's VLAN device leaves them, so br-v20 never
// bridges eth0 and eth1. Then the flow cache is flushed (R21).
func TestSetUplinkMovesVLANs(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	applyOK(t, a, twoSSIDs()) // uplink eth1: the only br-lan eth port with carrier
	a.SetUplink("eth0; reboot")
	a.SetUplink("eth0")
	p, err := a.Plan(context.Background(), twoSSIDs())
	if err != nil {
		t.Fatal(err)
	}
	add := stepIndex(t, p, "ip link add link eth0 name eth0.20 type vlan id 20")
	attach := stepIndex(t, p, "eth0.20")
	detach := stepIndex(t, p, "detach eth1.20")
	del := stepIndex(t, p, "ip link del eth1.20")
	flush := stepIndex(t, p, "fc flush")
	if !(add <= attach && detach < del && del < flush && attach < flush) {
		t.Errorf("order add %d attach %d detach %d del %d flush %d:\n%s", add, attach, detach, del, flush, p)
	}
	if p.disruptive {
		t.Error("an uplink move restarts hostapd")
	}
	if err := a.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got := a.bridgePorts("br-v20"); !slices.Contains(got, "eth0.20") || slices.Contains(got, "eth1.20") {
		t.Errorf("br-v20 ports %v", got)
	}
}
