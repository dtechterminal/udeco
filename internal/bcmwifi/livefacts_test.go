// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// Tests for the live facts F1-F7 read on the Deco X20 at .205 (2026-11-19),
// which the fake models: a hostapd's exit deletes its bss= vifs, its start
// needs an existing interface= and a bssid= per bss=, creates the bss= vifs
// (BSS down, not bridged) after -B returns and sets every BSS down, fails
// with proxy_arp on a vif it creates, and a failed start removes its -P
// pid file. These use only the exported API, so they also run against the
// code before the fix (where they fail as the unit did).

// F7, apply side: the takeover lowered wl02 after TP-Link's hostapd had
// exited and deleted it ("wl driver adapter not found"), and rolled back.
func TestLiveTakeoverApplies(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatalf("Apply = %v", err)
	}
	if err := a.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	for vif, want := range map[string]string{"wl01": "down", "wl02": "up", "wl03": "up", "wl11": "down", "wl12": "up"} {
		if got := f.state[vif+" bss"]; got != want {
			t.Errorf("%s bss %q, want %q", vif, got, want)
		}
	}
	for vif, br := range map[string]string{"wl01": "", "wl02": "br-lan", "wl03": "br-v20", "wl11": "", "wl12": "br-lan"} {
		if got := f.bridgeOf(vif); got != br {
			t.Errorf("%s bridge %q, want %q", vif, got, br)
		}
	}
	for _, pid := range []int{10510, 10912} {
		if f.procs[pid] != nil {
			t.Errorf("TP-Link hostapd %d still runs", pid)
		}
	}
	// Our hostapd serves the placeholder wlN1 as interface= and the SSIDs
	// as bss=.
	for _, h := range f.procs {
		if !h.ours || h.iface != "wl01" && h.iface != "wl11" {
			t.Errorf("hostapd %v: interface=%s ours=%t", h.argv, h.iface, h.ours)
		}
	}
	if f.state["wl02 ssid"] != "Example Network" || f.state["wl03 ssid"] != "EXN IOT" {
		t.Errorf("ssids wl02=%q wl03=%q", f.state["wl02 ssid"], f.state["wl03 ssid"])
	}
}

// F7, hand-back side: an apply that fails on wl0 (after TP-Link's wl0
// hostapd stopped, before wl1's did) must not restart wl1's (a second
// hostapd with the same -P fails and deletes the running one's pid file),
// must leave wl1's vifs alone, and must bring wl0's vifs up and bridged
// after the restart (TP-Link's hostapd leaves them BSS down, unbridged).
func TestLiveHandbackAfterPartialTakeover(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	f.failOn = func(argv []string) bool { return strings.Join(argv, " ") == "wl -i wl0 chanspec 6" }
	p, err := a.Plan(ctx, twoSSIDs())
	if err != nil {
		t.Fatal(err)
	}
	err = a.Apply(ctx, p)
	if err == nil || !strings.Contains(err.Error(), "rolled back") || strings.Contains(err.Error(), "rollback:") {
		t.Fatalf("Apply = %v, want a clean hand-back", err)
	}
	f.failOn = nil
	if f.called("hostapd -B -P /tmp/wl1.1_hapd.pid /tmp/wl1.1_hapd.conf") {
		t.Error("TP-Link hostapd on wl1 restarted though it never stopped")
	}
	if b, err := os.ReadFile(f.path("/tmp/wl1.1_hapd.pid")); err != nil || strings.TrimSpace(string(b)) != "10912" || f.procs[10912] == nil {
		t.Errorf("wl1's TP-Link hostapd or pid file lost: %q %v", b, err)
	}
	for _, c := range []string{"wl -i wl12 bss down", "wl -i wl11 bss down", "brctl delif br-lan wl12"} {
		if f.called(c) {
			t.Errorf("hand-back touched the running radio: %q", c)
		}
	}
	if !f.called("hostapd -B -P /tmp/wl0.1_hapd.pid /tmp/wl0.1_hapd.conf") {
		t.Fatal("TP-Link hostapd on wl0 not restarted")
	}
	for vif, want := range map[string]string{"wl01": "up", "wl02": "up", "wl03": "down", "wl12": "up", "wl13": "up"} {
		if got := f.state[vif+" bss"]; got != want {
			t.Errorf("%s bss %q, want %q", vif, got, want)
		}
	}
	for vif, br := range map[string]string{"wl01": "", "wl02": "br-lan", "wl03": "", "wl12": "br-lan", "wl13": "br-lan"} {
		if got := f.bridgeOf(vif); got != br {
			t.Errorf("%s bridge %q, want %q", vif, got, br)
		}
	}
	// The recreated wl02 has TP-Link's driver state again.
	if f.state["wl02 rrm"] != "0x33" || f.state["wl02 macmode"] != "1" || strings.Join(f.maclist["wl02"], " ") != strings.Join(tplinkDeny, " ") {
		t.Errorf("wl02 rrm %q macmode %q list %v", f.state["wl02 rrm"], f.state["wl02 macmode"], f.maclist["wl02"])
	}
}

// F7 aftermath: TP-Link's hostapd runs but its pid file is gone. Plan must
// still see (and stop) it, and a hand-back must not start a second one but
// rewrite the pid file.
func TestLiveTPLinkPidFileLost(t *testing.T) {
	ctx := context.Background()
	t.Run("takeover", func(t *testing.T) {
		f := newFakeDev(t)
		a := newTestApplier(f, false)
		_ = os.Remove(f.path("/tmp/wl1.1_hapd.pid"))
		d := twoSSIDs()
		p, err := a.Plan(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Apply(ctx, p); err != nil {
			t.Fatalf("Apply = %v", err)
		}
		if f.procs[10912] != nil {
			t.Error("TP-Link hostapd on wl1 not stopped")
		}
		if err := a.Verify(ctx, d); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("handback", func(t *testing.T) {
		f := newFakeDev(t)
		a := newTestApplier(f, false)
		f.killProc(10510, true)
		_ = os.Remove(f.path("/tmp/wl1.1_hapd.pid"))
		if err := a.Rollback(ctx); !errors.Is(err, ErrNoBaseline) {
			t.Fatalf("Rollback = %v", err)
		}
		if f.called("hostapd -B -P /tmp/wl1.1_hapd.pid /tmp/wl1.1_hapd.conf") {
			t.Error("a second TP-Link hostapd started on wl1")
		}
		if b, err := os.ReadFile(f.path("/tmp/wl1.1_hapd.pid")); err != nil || strings.TrimSpace(string(b)) != "10912" {
			t.Errorf("pid file %q %v, want 10912", b, err)
		}
		if f.procs[10912] == nil || !f.called("hostapd -B -P /tmp/wl0.1_hapd.pid /tmp/wl0.1_hapd.conf") {
			t.Error("wl0 not restarted or wl1 lost")
		}
	})
}

// F5: proxy_arp in the conf kills hostapd on a vif it creates. An isolated
// SSID asking for proxy ARP gets the bridge port's proxyarp_wifi instead.
func TestLiveProxyARPOnBridgePort(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	d.SSIDs[0].ProxyARP = true // b-iot: isolated, VLAN 20, wl03
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatalf("Apply = %v", err)
	}
	conf, _ := os.ReadFile(f.path("/tmp/udeco/hapd-wl0.conf"))
	if strings.Contains(string(conf), "proxy_arp") {
		t.Error("conf sets proxy_arp")
	}
	if b, _ := os.ReadFile(f.path("/sys/class/net/wl03/brport/proxyarp_wifi")); strings.TrimSpace(string(b)) != "1" {
		t.Errorf("wl03 proxyarp_wifi %q, want 1", b)
	}
	if b, _ := os.ReadFile(f.path("/sys/class/net/wl02/brport/proxyarp_wifi")); strings.TrimSpace(string(b)) != "0" {
		t.Errorf("wl02 proxyarp_wifi %q, want 0", b)
	}
	// A U6 Pro answers ARP for stations on a non-isolated SSID too
	// (aaa.conf proxyarp 1 with l2_isolation disabled): the bridge port's
	// proxyarp_wifi has no isolation precondition, applied live.
	d.SSIDs[1].ProxyARP = true // a-main: not isolated, br-lan, wl02/wl12
	pn, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pn.String(), "hostapd") || strings.Contains(strings.Join(pn.Notes, "\n"), "proxy ARP needs client isolation") {
		t.Fatalf("plan:\n%s", pn)
	}
	if err := a.Apply(ctx, pn); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"wl02", "wl12"} {
		if b, _ := os.ReadFile(f.path("/sys/class/net/" + v + "/brport/proxyarp_wifi")); strings.TrimSpace(string(b)) != "1" {
			t.Errorf("%s proxyarp_wifi %q on the non-isolated SSID, want 1", v, b)
		}
	}
	d.SSIDs[1].ProxyARP = false
	if p, _ := a.Plan(ctx, d); len(p.Steps) == 0 {
		t.Fatal("turning it off again plans nothing")
	} else if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if p, _ := a.Plan(ctx, d); !p.Empty() {
		t.Fatalf("second plan:\n%s", p)
	}
	// Off again: fixed live, hostapd kept (proxy ARP is not in its conf).
	d.SSIDs[0].ProxyARP = false
	p2, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p2.String(), "hostapd") || len(p2.Steps) == 0 {
		t.Fatalf("plan:\n%s", p2)
	}
	if err := a.Apply(ctx, p2); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(f.path("/sys/class/net/wl03/brport/proxyarp_wifi")); strings.TrimSpace(string(b)) != "0" {
		t.Errorf("wl03 proxyarp_wifi %q after turning it off", b)
	}
}

// A hand-back when TP-Link's hostapd runs on every radio restarts nothing
// and is no error.
func TestLiveHandbackNothingToRestart(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	p, _ := a.Plan(ctx, twoSSIDs())
	f.failOn = func(argv []string) bool { return argv[0] == "ip" } // fail before any radio
	if err := a.Apply(ctx, p); err == nil || strings.Contains(err.Error(), "rollback:") {
		t.Fatalf("Apply = %v, want a failure with a clean hand-back", err)
	}
	f.failOn = nil
	if f.called("hostapd -B") {
		t.Error("a TP-Link hostapd was restarted though both still ran")
	}
	if f.procs[10510] == nil || f.procs[10912] == nil {
		t.Error("TP-Link hostapd stopped")
	}
	for _, v := range []string{"wl02", "wl12", "wl13"} {
		if f.state[v+" bss"] != "up" || f.bridgeOf(v) != "br-lan" {
			t.Errorf("%s bss %q bridge %q", v, f.state[v+" bss"], f.bridgeOf(v))
		}
	}
}
