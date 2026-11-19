// SPDX-License-Identifier: GPL-2.0-or-later

package decosys

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEgressAllowTCP(t *testing.T) {
	u := newUnit(t, "205")
	os.Remove(filepath.Join(u.root, "usr/sbin/ip6tables"))
	r := newFakeRun()
	r.on(ipt+" -w -S UDECO-OUT", "-N UDECO-OUT\n"+strings.Join(wantRules4, "\n")+"\n", nil)
	m := New(Options{Root: u.root, Run: r, GatewayIP: "192.168.0.1", LANCIDR: "192.168.0.205/24"})
	// on the LAN (no rule), off the LAN (twice), garbage, IPv6: ignored
	if !m.SetEgressAllowTCP([]string{"192.168.0.9:2083", "203.0.113.7:2083", "203.0.113.7:2083", "x", "[2001:db8::1]:2083", "203.0.113.8:0"}) {
		t.Fatal("first list: no change reported")
	}
	if m.SetEgressAllowTCP([]string{"203.0.113.7:2083", "192.168.0.9:2083"}) {
		t.Fatal("the same list reported as a change")
	}
	if err := m.Egress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	rules := append(append([]string{}, wantRules4[:5]...), "-A UDECO-OUT -d 203.0.113.7/32 -p tcp --dport 2083 -j RETURN", "-A UDECO-OUT -j DROP")
	want := append([]string{ipt + " -w -S UDECO-OUT", ipt + " -w -F UDECO-OUT"}, prefixed(ipt, rules)...)
	want = append(want, ipt+" -w -C OUTPUT -j UDECO-OUT")
	diff(t, r.take(), want)

	// as iptables -S prints it (with the implicit -m tcp): nothing to do
	printed := append(append([]string{}, wantRules4[:5]...), "-A UDECO-OUT -d 203.0.113.7/32 -p tcp -m tcp --dport 2083 -j RETURN", "-A UDECO-OUT -j DROP")
	r.set(ipt+" -w -S UDECO-OUT", "-N UDECO-OUT\n"+strings.Join(printed, "\n")+"\n", nil)
	if err := m.Egress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{ipt + " -w -S UDECO-OUT", ipt + " -w -C OUTPUT -j UDECO-OUT"})

	// cleared: back to the LAN-only chain
	if !m.SetEgressAllowTCP(nil) {
		t.Fatal("clear: no change reported")
	}
}
