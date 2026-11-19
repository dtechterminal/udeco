// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

// roamWifi is fakeWifi with bcmwifi's Roaming Assistant primitive.
type roamWifi struct{ *fakeWifi }

func (w roamWifi) RoamAssist(ctx context.Context, r bcmwifi.RoamRequest) error {
	var to []string
	for _, n := range r.Candidates {
		to = append(to, fmt.Sprintf("%s/%s/%d", n.BSSID, n.Band, n.Channel))
	}
	w.rec.add(fmt.Sprintf("roam:%s@%s->%s t=%d", r.MAC, r.Vif, strings.Join(to, ","), r.DisassocTBTT))
	return nil
}

// roamAssistCfg: WLAN "net" on both bands with 802.11v, and the Roaming
// Assistant on its 5 GHz VAP exactly as Network 11.1.50 writes it.
func roamAssistCfg(extra ...string) string {
	return "radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght20\nradio.2.phyname=wifi1\nradio.2.ieee_mode=11acvht80\n" +
		"wireless.1.ssid=net\nwireless.1.id=w1\nwireless.1.parent=wifi1\nwireless.1.devname=wifi1ap1\n" +
		"wireless.2.ssid=net\nwireless.2.id=w1\nwireless.2.parent=wifi0\nwireless.2.devname=wifi0ap1\n" +
		"aaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\naaa.1.wpa.psk=" + fakePSK + "\naaa.1.bss_transition=enabled\n" +
		"aaa.2.wpa=2\naaa.2.wpa.key.1.mgmt=WPA-PSK\naaa.2.wpa.psk=" + fakePSK + "\naaa.2.bss_transition=enabled\n" +
		strings.Join(extra, "\n") + "\n"
}

// roamHarness: takeover with a backend that has the primitive; the
// station's 5 GHz signal comes from *signal.
func roamHarness(t *testing.T, mu *sync.Mutex, signal *int) *harness {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	rw := roamWifi{h.wifi}
	h.a.o.newWifi = func(bcmwifi.Options) wifiApplier { h.built++; return rw }
	h.col.snap = func() *apstate.Snapshot {
		mu.Lock()
		defer mu.Unlock()
		s := testSnapshot()
		s.Radios[1].VAPs[0].Stations[0].Signal = *signal
		s.Radios[0].VAPs = []apstate.Radio{{Iface: "wl02", Band: "ng", SSID: "net", BSSID: "b2:a7:b9:00:00:02"}}
		return s
	}
	h.a.scans.addBSS("na", apstate.ScanResult{Band: "na", Time: time.Now(), BSS: []apstate.BSS{
		{BSSID: "b2:a7:b9:00:00:07", SSID: "net", Channel: 36, Signal: -20},  // our own: never a candidate
		{BSSID: "aa:00:00:00:00:01", SSID: "net", Channel: 149, Signal: -60}, // a sibling AP
		{BSSID: "aa:00:00:00:00:09", SSID: "other", Channel: 44, Signal: -40},
	}})
	return h
}

// A station below the controller's threshold on the 5 GHz BSS gets one
// BSS transition request (disassociation timer set) naming the SSID's
// 2.4 GHz BSS and the sibling heard by a scan; then it is rate-limited.
func TestRoamingAssistant(t *testing.T) {
	var mu sync.Mutex
	signal := -60
	h := roamHarness(t, &mu, &signal)
	h.ctl.queue(adoptReply, provisionReply(roamAssistCfg("wireless.1.btm_disassoc.status=enabled", "wireless.1.btm_disassoc.threshold=-75")))
	h.start()
	eventually(t, "provisioned", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c1" })
	time.Sleep(50 * time.Millisecond) // readings above the threshold: nothing
	if c := roamCalls(h); len(c) != 0 {
		t.Fatalf("roamed a station above the threshold: %v", c)
	}
	mu.Lock()
	signal = -80
	mu.Unlock()
	want := "roam:" + staMAC + "@wl12->b2:a7:b9:00:00:02/ng/6,aa:00:00:00:00:01/na/149 t=100"
	eventually(t, "roaming assistant request", func() bool { return h.rec.index(want) >= 0 })
	time.Sleep(50 * time.Millisecond) // more weak readings: rate-limited
	h.stop()
	if c := roamCalls(h); len(c) != 1 {
		t.Errorf("requests %v (want 1 per %s)", c, roamEvery)
	}
}

// Without the controller's btm_disassoc nothing is sent, however weak.
func TestRoamingAssistantOff(t *testing.T) {
	for name, cfg := range map[string]string{
		"not sent": roamAssistCfg(),
		"disabled": roamAssistCfg("wireless.1.btm_disassoc.status=disabled"),
		// on 5 GHz but the WLAN has no 802.11v: translate leaves it off
		"no 802.11v": roamAssistCfg("wireless.1.btm_disassoc.status=enabled", "wireless.1.btm_disassoc.threshold=-75",
			"aaa.1.bss_transition=disabled"),
	} {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			signal := -85
			h := roamHarness(t, &mu, &signal)
			h.ctl.queue(adoptReply, provisionReply(cfg))
			h.start()
			eventually(t, "provisioned", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c1" })
			time.Sleep(80 * time.Millisecond)
			h.stop()
			if c := roamCalls(h); len(c) != 0 {
				t.Errorf("roamed: %v", c)
			}
		})
	}
}

// Observe mode owns no hostapd: nothing is sent.
func TestRoamingAssistantObserve(t *testing.T) {
	var mu sync.Mutex
	signal := -85
	h := roamHarness(t, &mu, &signal)
	h.a.takeover.Store(false)
	h.ctl.queue(adoptReply, provisionReply(roamAssistCfg("wireless.1.btm_disassoc.status=enabled", "wireless.1.btm_disassoc.threshold=-75")))
	h.start()
	time.Sleep(100 * time.Millisecond)
	h.stop()
	if c := roamCalls(h); len(c) != 0 {
		t.Errorf("roamed in observe mode: %v", c)
	}
}

func TestRoamPolicy(t *testing.T) {
	d := bcmwifi.Desired{SSIDs: []bcmwifi.SSID{
		{SSID: "net", Enabled: true, Bands: []string{"ng", "na"}, RoamAssist: map[string]int{"na": -72}},
		{SSID: "off", Enabled: false, Bands: []string{"na"}, RoamAssist: map[string]int{"na": -72}},
		{SSID: "gone", Enabled: true, Bands: []string{"ng"}, RoamAssist: map[string]int{"na": -72}}, // na not broadcast
	}}
	got := roamPolicy(d)
	if len(got) != 1 || got["net|na"] != -72 {
		t.Errorf("policy %v", got)
	}
}

func roamCalls(h *harness) []string {
	var out []string
	for _, c := range h.rec.list() {
		if strings.HasPrefix(c, "roam:") {
			out = append(out, c)
		}
	}
	return out
}
