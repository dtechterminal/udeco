// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/hapdmon"
	"github.com/dtechterminal/udeco/internal/stasnoop"
)

type garpRig struct {
	h    *harness
	mu   sync.Mutex
	sent []string // ifname
	now  time.Time
}

// newGarpRig: wl12 in br-lan with eth1 and wl02; wl13 in br-vlan20 with
// eth1.20; the station's address known from its DHCP ACK.
func newGarpRig(t *testing.T, mod func(*Config)) *garpRig {
	g := &garpRig{now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	g.h = newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		if mod != nil {
			mod(c)
		}
		o.garpSend = func(ifname string, frame []byte) error {
			if o, ok := stasnoop.Parse(frame, false); !ok || o.Kind != stasnoop.ARPRequest || o.SrcIP != o.DstIP || o.Src != cSta {
				t.Errorf("frame %+v", o)
			}
			g.mu.Lock()
			g.sent = append(g.sent, ifname)
			g.mu.Unlock()
			return nil
		}
	})
	root := g.h.root
	for br, ports := range map[string][]string{"br-lan": {"eth1", "wl12", "wl02"}, "br-vlan20": {"eth1.20", "wl13"}} {
		for _, p := range ports {
			os.MkdirAll(filepath.Join(root, "sys/class/net", br, "brif", p), 0o755)
			os.MkdirAll(filepath.Join(root, "sys/class/net", p, "brport"), 0o755)
			os.Symlink(filepath.Join("..", "..", br), filepath.Join(root, "sys/class/net", p, "brport", "bridge"))
		}
	}
	g.h.a.conn = &connState{t: newConnTracker()}
	return g
}

func (g *garpRig) connected(vif string) []string {
	g.mu.Lock()
	n := len(g.sent)
	g.mu.Unlock()
	g.h.a.assocGARP(hapdmon.Event{Vif: vif, MAC: cSta, Kind: hapdmon.Connected, At: g.now}, g.now, nil)
	g.mu.Lock()
	defer g.mu.Unlock()
	out := append([]string{}, g.sent[n:]...)
	sort.Strings(out)
	return out
}

// An authorized station whose address is known gets one gratuitous ARP on
// each wired port of its bridge (not on the Wi-Fi ones), at most once per
// garpEvery.
func TestAssocGARP(t *testing.T) {
	g := newGarpRig(t, nil)
	if got := g.connected("wl12"); len(got) != 0 {
		t.Fatalf("address unknown, yet sent on %v", got)
	}
	g.h.a.conn.t.setIP(cSta, cIP, "br-lan", g.now)
	if got := g.connected("wl12"); len(got) != 1 || got[0] != "eth1" {
		t.Fatalf("sent on %v", got)
	}
	g.now = g.now.Add(garpEvery / 2)
	if got := g.connected("wl12"); len(got) != 0 {
		t.Fatalf("not rate-limited: %v", got)
	}
	g.now = g.now.Add(garpEvery)
	g.h.a.conn.t.setIP(cSta, cIP, "br-vlan20", g.now)
	if got := g.connected("wl13"); len(got) != 1 || got[0] != "eth1.20" {
		t.Fatalf("VLAN bridge: sent on %v", got)
	}
	// the reading's ARP table (the AP's own, br-lan) is a source too
	g.h.a.conn.t.forgetIP(cSta)
	g.now = g.now.Add(garpEvery)
	g.h.a.assocGARP(hapdmon.Event{Vif: "wl12", MAC: cSta, Kind: hapdmon.Connected, At: g.now}, g.now, map[string]string{cSta: cIP})
	if len(g.sent) != 3 {
		t.Fatalf("ARP table: %v", g.sent)
	}
}

// Only for an authorization (never a disconnect or a PSK mismatch), not
// with assoc_garp false, not outside takeover.
func TestAssocGARPQuiet(t *testing.T) {
	g := newGarpRig(t, nil)
	g.h.a.conn.t.setIP(cSta, cIP, "br-lan", g.now)
	for _, k := range []hapdmon.Kind{hapdmon.Disconnected, hapdmon.PSKMismatch, hapdmon.EAPSuccess} {
		g.h.a.assocGARP(hapdmon.Event{Vif: "wl12", MAC: cSta, Kind: k, At: g.now}, g.now, nil)
	}
	if len(g.sent) != 0 {
		t.Fatalf("sent %v", g.sent)
	}
	g.h.a.takeover.Store(false)
	if got := g.connected("wl12"); len(got) != 0 {
		t.Fatalf("observe: %v", got)
	}
	f := false
	g = newGarpRig(t, func(c *Config) { c.AssocGARP = &f })
	g.h.a.conn.t.setIP(cSta, cIP, "br-lan", g.now)
	if got := g.connected("wl12"); len(got) != 0 {
		t.Fatalf("off: %v", got)
	}
}

// An address learnt on another bridge (the station was on the guest VLAN,
// now on the main SSID) is never announced: it would put a guest address
// into the LAN, or a LAN one into a VLAN.
func TestAssocGARPOtherBridge(t *testing.T) {
	g := newGarpRig(t, nil)
	g.h.a.conn.t.setIP(cSta, "192.168.20.7", "br-vlan20", g.now)
	if got := g.connected("wl12"); len(got) != 0 {
		t.Fatalf("address from br-vlan20 announced on br-lan: %v", got)
	}
	if got := g.connected("wl13"); len(got) != 1 || got[0] != "eth1.20" {
		t.Fatalf("same bridge: %v", got)
	}
}

// The GARP goes out when hostapd reports the authorization (the socket
// event), not at the next reading up to an inform interval later.
func TestAssocGARPOnEvent(t *testing.T) {
	g := newGarpRig(t, nil)
	g.h.a.conn.t.setIP(cSta, cIP, "br-lan", time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.h.a.startGARP(ctx)
	g.h.a.onHapdEvent(hapdmon.Event{Vif: "wl12", MAC: cSta, Kind: hapdmon.Connected, At: time.Now()})
	eventually(t, "a GARP on eth1", func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		return len(g.sent) == 1 && g.sent[0] == "eth1"
	})
}
