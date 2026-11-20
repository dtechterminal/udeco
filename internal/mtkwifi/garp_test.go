// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"net"
	"testing"
)

// TestAnnounceStation: a station's gratuitous ARP goes out on the uplink
// port (a VLAN SSID's: its VLAN device), from the station's MAC; an
// unserved netdev or a dry run sends nothing.
func TestAnnounceStation(t *testing.T) {
	f := newFakeDev(t)
	a, _ := clocked(f)
	type sent struct {
		dev   string
		frame []byte
	}
	var out []sent
	a.o.sendFrame = func(dev string, b []byte) error { out = append(out, sent{dev, b}); return nil }
	ctx := context.Background()
	p, _ := a.Plan(ctx, home())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("192.168.0.77")
	if err := a.AnnounceStation(ctx, "rai0", "AA:BB:CC:DD:EE:01", ip); err != nil {
		t.Fatal(err)
	}
	if err := a.AnnounceStation(ctx, "rai1", "aa:bb:cc:dd:ee:02", net.ParseIP("10.3.0.9")); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].dev != "eth0.4.1" || out[1].dev != "eth0.4.3" {
		t.Fatalf("sent %+v", out)
	}
	g, ok := parseARP(out[0].frame)
	if !ok || g.op != 1 || !g.bcast || g.sha.String() != "aa:bb:cc:dd:ee:01" || g.src.String() != "aa:bb:cc:dd:ee:01" ||
		!g.spa.Equal(ip) || !g.tpa.Equal(ip) {
		t.Errorf("GARP %+v", g)
	}
	if err := a.AnnounceStation(ctx, "ra3", "aa:bb:cc:dd:ee:01", ip); err == nil {
		t.Error("announced on an unserved BSS")
	}
	if err := a.AnnounceStation(ctx, "rai0", "aa:bb:cc:dd:ee:01", net.ParseIP("fe80::1")); err == nil {
		t.Error("announced an IPv6 address")
	}
	a.o.DryRun = true
	a.AnnounceStation(ctx, "rai0", "aa:bb:cc:dd:ee:01", ip)
	if len(out) != 2 {
		t.Error("dry run sent")
	}
}
