// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

const guestMAC = "02:00:00:00:00:a2"

// The controller's authorize-guest / unauthorize-guest reach bcmwifi; an
// authorisation that runs out is withdrawn by the agent (the controller
// sends nothing at expiry); after a restart the session's unexpired guests
// are authorised again (bcmwifi keeps its list on ramfs only).
func TestGuestAuthorisation(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	end := time.Now().Add(1500 * time.Millisecond).Unix()
	h.ctl.queue(adoptReply,
		fmt.Sprintf(`{"_type":"cmd","cmd":"authorize-guest","mac":"%s","end":%d}`, guestMAC, end),
		`{"_type":"cmd","cmd":"authorize-guest","mac":"02:00:00:00:00:b3","minutes":600}`,
		`{"_type":"cmd","cmd":"unauthorize-guest","mac":"02:00:00:00:00:b3"}`)
	h.start()
	eventually(t, "authorised", func() bool { return h.rec.index("guest-auth:"+guestMAC) >= 0 })
	eventually(t, "unauthorised by the controller", func() bool { return h.rec.index("guest-unauth:02:00:00:00:00:b3") >= 0 })
	deadline := time.Now().Add(5 * time.Second)
	for h.rec.index("guest-unauth:"+guestMAC) < 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if h.rec.index("guest-unauth:"+guestMAC) < 0 {
		t.Fatal("expired guest not unauthorised")
	}
	h.ctl.queue(fmt.Sprintf(`{"_type":"cmd","cmd":"authorize-guest","mac":"%s","minutes":60}`, guestMAC))
	eventually(t, "authorised again", func() bool { return h.rec.count("guest-auth:"+guestMAC) == 2 })
	h.stop()

	// a restart (reboot: bcmwifi's list is gone) re-authorises it
	h2 := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true; o.root = h.root })
	h2.start()
	eventually(t, "re-authorised at start", func() bool { return h2.rec.index("guest-auth:"+guestMAC) >= 0 })
	h2.stop()
	if h2.rec.index("guest-auth:02:00:00:00:00:b3") >= 0 {
		t.Error("an unauthorised guest was authorised again")
	}
}

// Observe mode changes nothing for guests.
func TestGuestAuthorisationObserve(t *testing.T) {
	h := newHarness(t, nil)
	h.ctl.queue(adoptReply, fmt.Sprintf(`{"_type":"cmd","cmd":"authorize-guest","mac":"%s","minutes":60}`, guestMAC))
	h.start()
	eventually(t, "replies used", func() bool { return h.ctl.pending() == 0 && h.ctl.count() > 3 })
	h.stop()
	for _, c := range h.rec.list() {
		if strings.HasPrefix(c, "guest-") {
			t.Errorf("observe mode: %s", c)
		}
	}
}

// guestPolicy: a guest SSID gets the controller's ranges and portal plus
// the gateway the unit sees; without the gateway's MAC there is no policy
// (bcmwifi then does not serve the guest SSID).
func TestGuestPolicy(t *testing.T) {
	d := bcmwifi.Desired{SSIDs: []bcmwifi.SSID{{ID: "g", SSID: "guest", Enabled: true, Guest: true}}}
	g := translate.Guest{Restricted: []string{"10.0.0.0/8"}, PreAllow: []string{"192.168.0.10"}, Portal: true, PortalHost: "192.168.0.1"}
	p, notes := guestPolicy(d, g, gwMAC, "192.168.0.1")
	if p == nil || p.GatewayMAC != gwMAC || p.GatewayIP != "192.168.0.1" || !slices.Equal(p.Restricted, g.Restricted) ||
		!slices.Equal(p.PreAllow, g.PreAllow) || !p.Portal || p.PortalHost != "192.168.0.1" || len(notes) != 1 {
		t.Errorf("policy %+v notes %q", p, notes)
	}
	g.PortalHost = "unifi.example" // a name is never resolved
	if p, _ := guestPolicy(d, g, gwMAC, "192.168.0.1"); p == nil || p.PortalHost != "" {
		t.Errorf("portal host name kept: %+v", p)
	}
	if p, notes := guestPolicy(d, g, "", "192.168.0.1"); p != nil || len(notes) != 1 {
		t.Errorf("no gateway MAC: %+v %q", p, notes)
	}
	d.SSIDs[0].Guest = false
	if p, notes := guestPolicy(d, g, gwMAC, "192.168.0.1"); p != nil || notes != nil {
		t.Errorf("no guest SSID: %+v %q", p, notes)
	}
}

// A guest WLAN in system_cfg reaches bcmwifi with the isolation policy
// built from the controller's ipsets and the gateway the unit reads.
func TestProvisionGuestPolicy(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	cfg := testCfg + "aaa.1.is_guest=true\naaa.1.devname=wifi1ap1\nwireless.1.is_guest=true\n" +
		"ipset.1.name=guest_restricted\nipset.1.entry.1.value=10.0.0.0/8\n"
	h.ctl.queue(adoptReply, provisionReply(cfg))
	h.start()
	eventually(t, "plan", func() bool { return h.rec.index("plan") >= 0 })
	h.stop()
	h.wifi.mu.Lock()
	d := h.wifi.desired[0]
	h.wifi.mu.Unlock()
	if len(d.SSIDs) != 1 || !d.SSIDs[0].Guest {
		t.Fatalf("SSIDs %+v", d.SSIDs)
	}
	if d.Guest == nil || d.Guest.GatewayMAC != gwMAC || d.Guest.GatewayIP != "192.168.0.1" || !slices.Equal(d.Guest.Restricted, []string{"10.0.0.0/8"}) {
		t.Errorf("guest policy %+v", d.Guest)
	}
}

// guestSta is the authorized flag the inform carries for the test station
// (on wifi1ap1); ok=false while the row is not there yet.
func guestSta(m map[string]any) (authorized, isGuest, ok bool) {
	vaps, _ := m["vap_table"].([]any)
	for _, v := range vaps {
		vap, _ := v.(map[string]any)
		stas, _ := vap["sta_table"].([]any)
		for _, s := range stas {
			row, _ := s.(map[string]any)
			if row["mac"] == staMAC {
				a, _ := row["authorized"].(bool)
				g, _ := vap["is_guest"].(bool)
				return a, g, true
			}
		}
	}
	return false, false, false
}

// A guest's sta_table row carries the portal state the controller set
// (docs/internals.md "VAPs and clients": authorized, guests): with the
// portal on it is false until authorize-guest and true after it; with no
// portal every associated guest is authorised. Without this the controller
// shows every guest as unauthorised whatever it sent.
func TestGuestAuthorizedInInform(t *testing.T) {
	guestCfg := testCfg + "aaa.1.is_guest=true\naaa.1.devname=wifi1ap1\nwireless.1.is_guest=true\n"
	portal := guestCfg + "redirector.status=enabled\nredirector.url=http://192.168.0.1:8880/guest/s/default/\n"

	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	h.ctl.queue(adoptReply, provisionReply(portal))
	h.start()
	eventually(t, "guest row before authorize-guest", func() bool {
		_, g, ok := guestSta(h.ctl.last())
		return ok && g && h.ctl.pending() == 0
	})
	if a, _, _ := guestSta(h.ctl.last()); a {
		t.Error("portal on: guest reported authorised before authorize-guest")
	}
	h.ctl.queue(fmt.Sprintf(`{"_type":"cmd","cmd":"authorize-guest","mac":"%s","minutes":60}`, staMAC))
	eventually(t, "authorised in the inform", func() bool { a, _, ok := guestSta(h.ctl.last()); return ok && a })
	h.ctl.queue(fmt.Sprintf(`{"_type":"cmd","cmd":"unauthorize-guest","mac":"%s"}`, staMAC))
	eventually(t, "unauthorised in the inform", func() bool { a, _, ok := guestSta(h.ctl.last()); return ok && !a })
	h.stop()

	h2 := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	h2.ctl.queue(adoptReply, provisionReply(guestCfg))
	h2.start()
	eventually(t, "no portal: guest authorised", func() bool {
		a, g, ok := guestSta(h2.ctl.last())
		return ok && g && a
	})
	h2.stop()
}
