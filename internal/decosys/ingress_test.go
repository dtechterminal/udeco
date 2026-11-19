package decosys

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// tplinkInput is 'iptables -S INPUT' as read on 192.168.0.205 (2026-11-18).
const tplinkInput = `-P INPUT DROP
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j syn_flood
-A INPUT -j input_rule
-A INPUT -j input
-A INPUT -j input_expolicy
`

var ingressHead = []string{
	"-A UDECO-IN -i lo -j ACCEPT",
	"-A UDECO-IN -p tcp -m tcp --dport 20001 -j DROP",
	"-A UDECO-IN -p tcp -m tcp --dport 20002 -j DROP",
	"-A UDECO-IN -p tcp -m tcp --dport 20003 -j DROP",
	"-A UDECO-IN -p tcp -m tcp --dport 80 -j DROP",
	"-A UDECO-IN -p tcp -m tcp --dport 443 -j DROP",
	"-A UDECO-IN -p udp -m udp --dport 20002 -j DROP",
	"-A UDECO-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
}

func ingressManager(u *unit, r Runner, mgmt ...string) *Manager {
	return New(Options{Root: u.root, Run: r, ControllerIP: "192.168.0.1", GatewayIP: "192.168.0.1",
		LANCIDR: "192.168.0.0/24", ConsoleIP: "192.168.0.1", MgmtSources: mgmt})
}

// freshIngress answers as a unit with no UDECO-IN chain yet.
func freshIngress(r *fakeRun) {
	for _, b := range []string{ipt, ip6t} {
		r.on(b+" -w -S UDECO-IN", "", errExit1)
		r.on(b+" -w -S INPUT", tplinkInput, nil)
	}
}

func installCmds(bin string, rules []string) []string {
	want := []string{bin + " -w -S UDECO-IN", bin + " -w -N UDECO-IN"}
	want = append(want, prefixed(bin, rules)...)
	return append(want, bin+" -w -S INPUT", bin+" -w -I INPUT 1 -j UDECO-IN")
}

// Default (no management list): TP-Link's ports are dropped, :22 is
// accepted from the LAN and never dropped, :2222 only from the console.
func TestIngressDefault(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	freshIngress(r)
	if err := ingressManager(u, r).Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	v4 := append(slices.Clone(ingressHead),
		"-A UDECO-IN -s 192.168.0.0/24 -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A UDECO-IN -s 192.168.0.1/32 -p tcp -m tcp --dport 2222 -j ACCEPT",
		"-A UDECO-IN -p tcp -m tcp --dport 2222 -j DROP")
	v6 := append(slices.Clone(ingressHead), "-A UDECO-IN -p tcp -m tcp --dport 2222 -j DROP")
	calls := r.take()
	diff(t, calls, append(installCmds(ipt, v4), installCmds(ip6t, v6)...))
	for _, c := range calls {
		if strings.Contains(c, "--dport 22 -j DROP") {
			t.Errorf("default fence drops :22: %q", c)
		}
	}
}

// An explicit list is the only :22 source, per family, then :22 is dropped.
func TestIngressExplicitManagement(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	freshIngress(r)
	m := ingressManager(u, r, "192.168.0.10", "fd00::/64", "10.8.0.0/24", "192.168.0.10/32")
	m.o.SSHDPort = 2200
	if err := m.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	v4 := append(slices.Clone(ingressHead),
		"-A UDECO-IN -s 192.168.0.10/32 -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A UDECO-IN -s 10.8.0.0/24 -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A UDECO-IN -p tcp -m tcp --dport 22 -j DROP",
		"-A UDECO-IN -s 192.168.0.1/32 -p tcp -m tcp --dport 2200 -j ACCEPT",
		"-A UDECO-IN -p tcp -m tcp --dport 2200 -j DROP")
	v6 := append(slices.Clone(ingressHead),
		"-A UDECO-IN -s fd00::/64 -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A UDECO-IN -p tcp -m tcp --dport 22 -j DROP",
		"-A UDECO-IN -p tcp -m tcp --dport 2200 -j DROP")
	diff(t, r.take(), append(installCmds(ipt, v4), installCmds(ip6t, v6)...))
}

// A management entry or console address that does not parse changes
// nothing: no half-built fence, no :22 drop.
func TestIngressBadConfigChangesNothing(t *testing.T) {
	for _, o := range []Options{
		{MgmtSources: []string{"192.168.0.300"}},
		{MgmtSources: []string{"192.168.0.10", "mac-mini"}},
		{ConsoleIP: "fd00::1"},
		{LANCIDR: "bogus"},
	} {
		u := newUnit(t, "205")
		r := newFakeRun()
		o.Root, o.Run = u.root, r
		if err := New(o).Ingress(context.Background(), true); err == nil {
			t.Errorf("%+v: want error", o)
		}
		diff(t, r.take(), nil)
	}
}

// A failed append stops the rest, so the :22 drop never lands without the
// :22 accept in front of it.
func TestIngressFailsOpen(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	freshIngress(r)
	r.on(ipt+" -w -A UDECO-IN -s 192.168.0.10/32 -p tcp -m tcp --dport 22 -j ACCEPT", "", errExit1)
	err := ingressManager(u, r, "192.168.0.10").Ingress(context.Background(), true)
	if err == nil {
		t.Fatal("want the append error")
	}
	for _, c := range r.take() {
		if strings.HasPrefix(c, ipt+" ") && (strings.Contains(c, "--dport 22 -j DROP") || strings.Contains(c, "-I INPUT")) {
			t.Errorf("after a failed accept, ran %q", c)
		}
	}
}

// A correct fence costs two reads per family and changes nothing.
func TestIngressIdempotent(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	v4 := append(slices.Clone(ingressHead),
		"-A UDECO-IN -s 192.168.0.0/24 -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A UDECO-IN -s 192.168.0.1/32 -p tcp -m tcp --dport 2222 -j ACCEPT",
		"-A UDECO-IN -p tcp -m tcp --dport 2222 -j DROP")
	v6 := append(slices.Clone(ingressHead), "-A UDECO-IN -p tcp -m tcp --dport 2222 -j DROP")
	input := strings.Replace(tplinkInput, "-P INPUT DROP\n", "-P INPUT DROP\n-A INPUT -j UDECO-IN\n", 1)
	r.on(ipt+" -w -S UDECO-IN", "-N UDECO-IN\n"+strings.Join(v4, "\n")+"\n", nil)
	r.on(ip6t+" -w -S UDECO-IN", "-N UDECO-IN\n"+strings.Join(v6, "\n")+"\n", nil)
	r.on(ipt+" -w -S INPUT", input, nil)
	r.on(ip6t+" -w -S INPUT", input, nil)
	m := ingressManager(u, r)
	if err := m.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{ipt + " -w -S UDECO-IN", ipt + " -w -S INPUT", ip6t + " -w -S UDECO-IN", ip6t + " -w -S INPUT"})
	if c := m.Counts()["ingress"]; c != 0 {
		t.Errorf("ingress re-inserts = %d, want 0", c)
	}
}

// A jump that is no longer first (something inserted ahead of it) or is
// duplicated is put back first without ever unhooking the chain, and the
// repair is counted.
func TestIngressJumpKeptFirst(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	freshIngress(r)
	u.rm("usr/sbin/ip6tables")
	m := ingressManager(u, r)
	if err := m.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	r.take()
	v4 := append(slices.Clone(ingressHead),
		"-A UDECO-IN -s 192.168.0.0/24 -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A UDECO-IN -s 192.168.0.1/32 -p tcp -m tcp --dport 2222 -j ACCEPT",
		"-A UDECO-IN -p tcp -m tcp --dport 2222 -j DROP")
	r.set(ipt+" -w -S UDECO-IN", "-N UDECO-IN\n"+strings.Join(v4, "\n")+"\n", nil)
	r.set(ipt+" -w -S INPUT", `-P INPUT DROP
-A INPUT -j zone_block
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -j UDECO-IN
-A INPUT -i lo -j ACCEPT
-A INPUT -j UDECO-IN
`, nil)
	if err := m.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{
		ipt + " -w -S UDECO-IN", ipt + " -w -S INPUT",
		ipt + " -w -I INPUT 1 -j UDECO-IN",
		ipt + " -w -D INPUT 6", ipt + " -w -D INPUT 4",
	})
	if c := m.Counts()["ingress"]; c != 1 {
		t.Errorf("ingress re-inserts = %d, want 1", c)
	}
}

// While a firmware upgrade is in flight the fence is not touched: cutting
// the master's :20001 session would abort the image transfer.
func TestIngressHoldsDuringUpgrade(t *testing.T) {
	u := newUnit(t, "205")
	u.setProcs(map[int][]string{1: {"/sbin/procd"}, 77: {"/bin/sh", "/usr/bin/upgrade", "/tmp/fw.bin"}})
	r := newFakeRun()
	freshIngress(r)
	if err := ingressManager(u, r).Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), nil)
}

func TestIngressOff(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	r.on(ipt+" -w -C INPUT -j UDECO-IN", "", nil)
	r.on(ipt+" -w -C INPUT -j UDECO-IN", "", errExit1)
	r.on(ip6t+" -w -C INPUT -j UDECO-IN", "", errExit1)
	r.on(ip6t+" -w -S UDECO-IN", "", errExit1)
	if err := ingressManager(u, r).Ingress(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{
		ipt + " -w -C INPUT -j UDECO-IN", ipt + " -w -D INPUT -j UDECO-IN",
		ipt + " -w -C INPUT -j UDECO-IN", ipt + " -w -S UDECO-IN",
		ipt + " -w -F UDECO-IN", ipt + " -w -X UDECO-IN",
		ip6t + " -w -C INPUT -j UDECO-IN", ip6t + " -w -S UDECO-IN",
	})
}

// An egress jump that disappears after the first install (a firewall
// restart, audit X6) is re-inserted and counted.
func TestEgressReinsertCounted(t *testing.T) {
	u := newUnit(t, "205")
	u.rm("usr/sbin/ip6tables")
	r := newFakeRun()
	r.on(ipt+" -w -S UDECO-OUT", "", errExit1)
	r.on(ipt+" -w -C OUTPUT -j UDECO-OUT", "", errExit1)
	m := newManager(u, r, false)
	if err := m.Egress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if c := m.Counts()["egress"]; c != 0 {
		t.Fatalf("first install counted as re-insert: %d", c)
	}
	r.set(ipt+" -w -S UDECO-OUT", "-N UDECO-OUT\n"+strings.Join(wantRules4, "\n")+"\n", nil)
	r.set(ipt+" -w -C OUTPUT -j UDECO-OUT", "", errExit1)
	if err := m.Egress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if c := m.Counts()["egress"]; c != 1 {
		t.Errorf("egress re-inserts = %d, want 1", c)
	}
}

// rm deletes a file from the fake root.
func (u *unit) rm(p string) {
	u.t.Helper()
	if err := os.Remove(filepath.Join(u.root, p)); err != nil {
		u.t.Fatal(err)
	}
}

// Phase 1 runs before the LAN is known; the rules that follow once it is
// are a configuration change, not drift, and are not counted.
func TestIngressConfigChangeNotCounted(t *testing.T) {
	u := newUnit(t, "205")
	u.rm("usr/sbin/ip6tables")
	r := newFakeRun()
	freshIngress(r)
	m := New(Options{Root: u.root, Run: r, ConsoleIP: "192.168.0.1"})
	if err := m.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.take() {
		if strings.Contains(c, "--dport 22 ") {
			t.Errorf("phase-1 fence without a LAN touches :22: %q", c)
		}
	}
	phase1 := append(slices.Clone(ingressHead),
		"-A UDECO-IN -s 192.168.0.1/32 -p tcp -m tcp --dport 2222 -j ACCEPT",
		"-A UDECO-IN -p tcp -m tcp --dport 2222 -j DROP")
	r.set(ipt+" -w -S UDECO-IN", "-N UDECO-IN\n"+strings.Join(phase1, "\n")+"\n", nil)
	r.set(ipt+" -w -S INPUT", "-P INPUT DROP\n-A INPUT -j UDECO-IN\n", nil)
	m.o.LANCIDR = "192.168.0.0/24"
	if err := m.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.take(), ipt+" -w -A UDECO-IN -s 192.168.0.0/24 -p tcp -m tcp --dport 22 -j ACCEPT") {
		t.Error(":22 from the LAN not added")
	}
	if c := m.Counts()["ingress"]; c != 0 {
		t.Errorf("config change counted as %d re-insert(s)", c)
	}
}
