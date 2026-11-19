// SPDX-License-Identifier: GPL-2.0-or-later

package decosys

import (
	"context"
	"slices"
	"testing"
)

// Site SSH logins on: SSHDPort is also accepted from the LAN (the :22
// sources), IPv4 only; off again: back to the console only.
func TestIngressSiteSSH(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	freshIngress(r)
	m := ingressManager(u, r)
	if !m.SetSiteSSH(true) || m.SetSiteSSH(true) {
		t.Fatal("SetSiteSSH change report")
	}
	if err := m.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	v4 := append(slices.Clone(ingressHead),
		"-A UDECO-IN -s 192.168.0.0/24 -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A UDECO-IN -s 192.168.0.1/32 -p tcp -m tcp --dport 2222 -j ACCEPT",
		"-A UDECO-IN -s 192.168.0.0/24 -p tcp -m tcp --dport 2222 -j ACCEPT",
		"-A UDECO-IN -p tcp -m tcp --dport 2222 -j DROP")
	v6 := append(slices.Clone(ingressHead), "-A UDECO-IN -p tcp -m tcp --dport 2222 -j DROP")
	diff(t, r.take(), append(installCmds(ipt, v4), installCmds(ip6t, v6)...))

	// explicit management sources are the site sources too
	r2 := newFakeRun()
	freshIngress(r2)
	m2 := ingressManager(u, r2, "192.168.0.10", "fd00::/64")
	m2.SetSiteSSH(true)
	if err := m2.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	v4 = append(slices.Clone(ingressHead),
		"-A UDECO-IN -s 192.168.0.10/32 -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A UDECO-IN -p tcp -m tcp --dport 22 -j DROP",
		"-A UDECO-IN -s 192.168.0.1/32 -p tcp -m tcp --dport 2222 -j ACCEPT",
		"-A UDECO-IN -s 192.168.0.10/32 -p tcp -m tcp --dport 2222 -j ACCEPT",
		"-A UDECO-IN -p tcp -m tcp --dport 2222 -j DROP")
	v6 = append(slices.Clone(ingressHead),
		"-A UDECO-IN -s fd00::/64 -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A UDECO-IN -p tcp -m tcp --dport 22 -j DROP",
		"-A UDECO-IN -p tcp -m tcp --dport 2222 -j DROP")
	diff(t, r2.take(), append(installCmds(ipt, v4), installCmds(ip6t, v6)...))

	// off: the rules are what they were without it
	if !m.SetSiteSSH(false) {
		t.Fatal("SetSiteSSH(false) reported no change")
	}
	rules, err := m.ingressRules(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if slices.Equal(r, []string{"-s", "192.168.0.0/24", "-p", "tcp", "-m", "tcp", "--dport", "2222", "-j", "ACCEPT"}) {
			t.Error("site rule kept after SetSiteSSH(false)")
		}
	}
}
