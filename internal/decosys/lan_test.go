package decosys

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// The agent builds the Manager before it has read the unit (R1 phase 1)
// and hands it the LAN later: the fence then gains :22 from the LAN, and
// the address watch protects the new lease.
func TestSetLAN(t *testing.T) {
	u := newUnit(t, "205")
	u.rm("usr/sbin/ip6tables")
	r := newFakeRun()
	freshIngress(r)
	m := New(Options{Root: u.root, Run: r, ControllerIP: "192.168.0.1", ConsoleIP: "192.168.0.1"})
	if err := m.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	r.take()
	l := LAN{GatewayIP: "192.168.0.1", LANCIDR: "192.168.0.0/24", UnitIP: "192.168.0.205"}
	if !m.SetLAN(l) {
		t.Fatal("SetLAN reported no change")
	}
	if m.SetLAN(l) {
		t.Error("SetLAN with the same values reported a change")
	}
	if err := m.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.take(), ipt+" -w -A UDECO-IN -s 192.168.0.0/24 -p tcp -m tcp --dport 22 -j ACCEPT") {
		t.Error(":22 from the new LAN not added")
	}
	if m.Counts()["ingress"] != 0 {
		t.Errorf("a LAN change counted as a re-insert: %v", m.Counts())
	}

	// a new lease: the watch keeps it; the old one, inside LANCIDR, is not
	// deleted either (it could be the newer lease of a DHCP change the
	// agent has not seen yet: deleting it could cut the unit off)
	_, wr, wm := watchUnit(t)
	wm.SetLAN(LAN{GatewayIP: "192.168.0.1", LANCIDR: "192.168.0.0/24", UnitIP: "192.168.0.77"})
	wr.on(addrShow, ipLine("192.168.0.205/24")+ipLine("192.168.0.77/24"), nil)
	if _, err := wm.Enforce(context.Background()); err != nil {
		t.Fatal(err)
	}
	var dels []string
	for _, c := range wr.take() {
		if strings.Contains(c, " addr del ") {
			dels = append(dels, c)
		}
	}
	if len(dels) != 0 {
		t.Errorf("deletes %q, want none inside the LAN", dels)
	}
}

// InFlight reads the same markers as Manager.Guard, without a Runner.
func TestInFlight(t *testing.T) {
	u := newUnit(t, "205")
	u.setProcs(map[int][]string{1: {"/sbin/procd"}})
	g, err := InFlight(u.root)
	if err != nil || g.Hold() {
		t.Fatalf("quiet unit: %+v %v", g, err)
	}
	u.setProcs(map[int][]string{1: {"/sbin/procd"}, 9: {"nvrammanager", "-u", "/tmp/fw.bin"}})
	u.write("tmp/firmware_upgrade_flag", "1")
	if g, err = InFlight(u.root); err != nil || len(g.Upgrade) != 2 {
		t.Fatalf("upgrade: %+v %v", g, err)
	}
	u.setProcs(map[int][]string{9: {"/bin/sh", "/etc/rc.common", "/etc/rc.d/S99zzz", "boot"}})
	u.rm("tmp/firmware_upgrade_flag")
	if g, err = InFlight(u.root); err != nil || len(g.Boot) != 1 || len(g.Upgrade) != 0 {
		t.Fatalf("boot chain: %+v %v", g, err)
	}
}
