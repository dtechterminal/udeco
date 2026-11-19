// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"fmt"
	"strings"
	"testing"
)

// fixtureVifs is the stock X20 set: wl0/wl1 plus wlN1..wlN6.
func fixtureVifs(n string) bool { return len(n) <= 4 && n[:2] == "wl" && (len(n) == 3 || n[3] <= '6') }

func vifsOf(rl *radioLayout) map[string]string {
	m := map[string]string{}
	for _, u := range rl.Used {
		m[u.SSID.ID] = u.Vif
	}
	return m
}

// With R23 lifted, wlN2..wlN6 carry SSIDs by WLAN id. wlN1 never does: it
// is hostapd's interface= placeholder, the one vif that survives hostapd's
// exit (F2/F4). The primary itself is never used.
func TestPlacementNeverUsesPlaceholder(t *testing.T) {
	d := Desired{Radios: map[string]Radio{"ng": {Enabled: true}, "na": {Enabled: false}}}
	for i := 0; i < 7; i++ {
		d.SSIDs = append(d.SSIDs, SSID{ID: fmt.Sprintf("w%d", i), SSID: fmt.Sprintf("S%d", i), Bands: []string{"ng", "na"}, Enabled: true, Security: SecOpen})
	}
	d.SSIDs = append(d.SSIDs, SSID{ID: "x", SSID: "Owe", Bands: []string{"ng"}, Enabled: true, Security: SecOWE})
	l := planLayout(d, fixtureVifs, layoutOpts{anyVifOnLAN: true})
	got := vifsOf(l.radio("ng"))
	want := map[string]string{"w0": "wl02", "w1": "wl03", "w2": "wl04", "w3": "wl05", "w4": "wl06"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("ng placement %v, want %v", got, want)
	}
	if len(l.radio("na").Used) != 0 {
		t.Error("SSIDs placed on a disabled radio")
	}
	notes := strings.Join(l.Notes, "\n")
	for _, w := range []string{"ssid w5: no free vif on ng (wl02..7 in use)", "ssid w6: no free vif on ng (wl02..7 in use)", "OWE is not supported", "radio na disabled"} {
		if !strings.Contains(notes, w) {
			t.Errorf("notes lack %q:\n%s", w, notes)
		}
	}
}

// R23: br-lan SSIDs only on the TP-Link-typed wlN2/wlN3; VLAN SSIDs take the
// rest (never wlN1). Placement is stable by WLAN id whatever the input order.
func TestPlacementR23NativeVifs(t *testing.T) {
	d := Desired{Radios: map[string]Radio{"ng": {Enabled: true}}}
	add := func(id string, vlan int) {
		d.SSIDs = append(d.SSIDs, SSID{ID: id, SSID: "S-" + id, Bands: []string{"ng"}, Enabled: true, Security: SecOpen, VLAN: vlan})
	}
	add("v4", 14)
	add("n2", 0)
	add("v0", 10)
	add("n0", 0)
	add("v1", 11)
	add("n1", 0)
	add("v2", 12)
	add("v3", 13)
	add("v5", 15)
	l := planLayout(d, fixtureVifs, layoutOpts{})
	got := vifsOf(l.radio("ng"))
	want := map[string]string{"n0": "wl02", "n1": "wl03", "v0": "wl04", "v1": "wl05", "v2": "wl06"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("placement %v, want %v", got, want)
	}
	notes := strings.Join(l.Notes, "\n")
	if !strings.Contains(notes, "ssid n2: no br-lan vif left on ng (R23") {
		t.Errorf("no R23 note for the 3rd br-lan SSID:\n%s", notes)
	}
	if !strings.Contains(notes, "ssid v3: no free vif") || !strings.Contains(notes, "ssid v4: no free vif") || !strings.Contains(notes, "ssid v5: no free vif") {
		t.Errorf("no note for the unplaced VLAN SSIDs:\n%s", notes)
	}
	if fmt.Sprint(l.VLANs) != "[10 11 12]" {
		t.Errorf("VLANs %v", l.VLANs)
	}
}

func TestPlacementRefusesVLAN491AndUnisolatedGuests(t *testing.T) {
	d := Desired{Radios: map[string]Radio{"ng": {Enabled: true}}, SSIDs: []SSID{
		{ID: "a", SSID: "IPTV", Bands: []string{"ng"}, Enabled: true, Security: SecOpen, VLAN: 491},
		{ID: "b", SSID: "Guest", Bands: []string{"ng"}, Enabled: true, Security: SecOpen, Guest: true},
	}}
	l := planLayout(d, fixtureVifs, layoutOpts{})
	if len(l.radio("ng").Used) != 0 {
		t.Fatalf("placed %+v", l.radio("ng").Used)
	}
	notes := strings.Join(l.Notes, "\n")
	for _, w := range []string{"ssid a: VLAN 491 collides", "ssid b: guest network without a usable guest policy"} {
		if !strings.Contains(notes, w) {
			t.Errorf("notes lack %q:\n%s", w, notes)
		}
	}
	// With a usable policy the guest SSID is served.
	l = planLayout(d, fixtureVifs, layoutOpts{guestOK: true})
	if got := vifsOf(l.radio("ng")); got["b"] != "wl02" {
		t.Errorf("guest placement %v", got)
	}
	if fmt.Sprint(l.guestVifs()) != "[wl02]" {
		t.Errorf("guestVifs %v", l.guestVifs())
	}
}

// A radio without its wlN1 cannot run hostapd (interface= must exist, F4):
// nothing is placed there.
func TestPlacementNeedsPlaceholderVif(t *testing.T) {
	d := Desired{Radios: map[string]Radio{"ng": {Enabled: true}}, SSIDs: []SSID{{ID: "a", SSID: "A", Bands: []string{"ng"}, Enabled: true, Security: SecOpen}}}
	l := planLayout(d, func(n string) bool { return n != "wl01" && fixtureVifs(n) }, layoutOpts{})
	if len(l.radio("ng").Used) != 0 {
		t.Fatalf("placed %+v without wl01", l.radio("ng").Used)
	}
	if !strings.Contains(strings.Join(l.Notes, "\n"), "wl01 missing (hostapd's interface= vif)") {
		t.Errorf("notes %v", l.Notes)
	}
}
