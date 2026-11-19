package decosys

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	ipt  = "/usr/sbin/iptables"
	ip6t = "/usr/sbin/ip6tables"
)

var (
	wantRules4 = []string{
		"-A UDECO-OUT -o lo -j RETURN",
		"-A UDECO-OUT -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"-A UDECO-OUT -d 192.168.0.0/24 -j RETURN",
		"-A UDECO-OUT -d 255.255.255.255/32 -j RETURN",
		"-A UDECO-OUT -d 224.0.0.0/4 -j RETURN",
		"-A UDECO-OUT -j DROP",
	}
	wantRules6 = []string{
		"-A UDECO-OUT -o lo -j RETURN",
		"-A UDECO-OUT -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"-A UDECO-OUT -d fe80::/10 -j RETURN",
		"-A UDECO-OUT -d ff02::/16 -j RETURN",
		"-A UDECO-OUT -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j RETURN",
		"-A UDECO-OUT -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j RETURN",
		"-A UDECO-OUT -j DROP",
	}
)

func prefixed(bin string, rules []string) []string {
	var out []string
	for _, r := range rules {
		out = append(out, bin+" -w "+r)
	}
	return out
}

func TestEgressOnFresh(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	for _, b := range []string{ipt, ip6t} {
		r.on(b+" -w -S UDECO-OUT", "", errExit1)
		r.on(b+" -w -C OUTPUT -j UDECO-OUT", "", errExit1)
	}
	if err := newManager(u, r, false).Egress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, f := range []struct {
		bin   string
		rules []string
	}{{ipt, wantRules4}, {ip6t, wantRules6}} {
		want = append(want, f.bin+" -w -S UDECO-OUT", f.bin+" -w -N UDECO-OUT")
		want = append(want, prefixed(f.bin, f.rules)...)
		want = append(want, f.bin+" -w -C OUTPUT -j UDECO-OUT", f.bin+" -w -I OUTPUT 1 -j UDECO-OUT")
	}
	diff(t, r.take(), want)
}

func TestEgressOnIdempotent(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	r.on(ipt+" -w -S UDECO-OUT", "-N UDECO-OUT\n"+strings.Join(wantRules4, "\n")+"\n", nil)
	// iptables prints the implicit icmp6 match; either spelling is accepted.
	v6 := strings.ReplaceAll(strings.Join(wantRules6, "\n"), "-p ipv6-icmp -m icmp6", "-p ipv6-icmp")
	r.on(ip6t+" -w -S UDECO-OUT", "-N UDECO-OUT\n"+v6+"\n", nil)
	if err := newManager(u, r, false).Egress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{
		ipt + " -w -S UDECO-OUT", ipt + " -w -C OUTPUT -j UDECO-OUT",
		ip6t + " -w -S UDECO-OUT", ip6t + " -w -C OUTPUT -j UDECO-OUT",
	})
}

func TestEgressRepairsDrift(t *testing.T) {
	u := newUnit(t, "205")
	os.Remove(filepath.Join(u.root, "usr/sbin/ip6tables"))
	r := newFakeRun()
	r.on(ipt+" -w -S UDECO-OUT", "-N UDECO-OUT\n-A UDECO-OUT -j DROP\n", nil)
	m := New(Options{Root: u.root, Run: r, ControllerIP: "10.9.9.9", GatewayIP: "192.168.0.1", LANCIDR: "192.168.0.205/24"})
	if err := m.Egress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	rules := append(append([]string{}, wantRules4[:5]...), "-A UDECO-OUT -d 10.9.9.9/32 -j RETURN", "-A UDECO-OUT -j DROP")
	want := append([]string{ipt + " -w -S UDECO-OUT", ipt + " -w -F UDECO-OUT"}, prefixed(ipt, rules)...)
	want = append(want, ipt+" -w -C OUTPUT -j UDECO-OUT")
	diff(t, r.take(), want)
}

func TestEgressOff(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	r.on(ipt+" -w -C OUTPUT -j UDECO-OUT", "", nil)
	r.on(ipt+" -w -C OUTPUT -j UDECO-OUT", "", errExit1)
	r.on(ip6t+" -w -C OUTPUT -j UDECO-OUT", "", errExit1)
	r.on(ip6t+" -w -S UDECO-OUT", "", errExit1)
	if err := newManager(u, r, false).Egress(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{
		ipt + " -w -C OUTPUT -j UDECO-OUT", ipt + " -w -D OUTPUT -j UDECO-OUT",
		ipt + " -w -C OUTPUT -j UDECO-OUT", ipt + " -w -S UDECO-OUT",
		ipt + " -w -F UDECO-OUT", ipt + " -w -X UDECO-OUT",
		ip6t + " -w -C OUTPUT -j UDECO-OUT", ip6t + " -w -S UDECO-OUT",
	})
}

func TestEgressRefusesWithoutLAN(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	for _, lan := range []string{"", "192.168.0.1", "fd00::/64"} {
		m := New(Options{Root: u.root, Run: r, LANCIDR: lan})
		if err := m.Egress(context.Background(), true); err == nil {
			t.Errorf("LANCIDR %q: want error", lan)
		}
	}
	diff(t, r.take(), nil)
}

func TestEgressDryRun(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	for _, b := range []string{ipt, ip6t} {
		r.on(b+" -w -S UDECO-OUT", "", errExit1)
		r.on(b+" -w -C OUTPUT -j UDECO-OUT", "", errExit1)
	}
	if err := newManager(u, r, true).Egress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.take() {
		if !strings.Contains(c, " -S ") && !strings.Contains(c, " -C ") {
			t.Errorf("dry run executed %q", c)
		}
	}
}
