// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

// banWifi is roamWifi with bcmwifi's per-BSS ban primitive.
type banWifi struct {
	roamWifi
	banErr error
}

func (w banWifi) TempDeny(ctx context.Context, vif, mac string, until time.Time) error {
	if until.IsZero() {
		w.rec.add(fmt.Sprintf("unban:%s@%s", mac, vif))
	} else {
		w.rec.add(fmt.Sprintf("ban:%s@%s", mac, vif))
	}
	return w.banErr
}

func (w banWifi) Kick(ctx context.Context, mac string) error {
	w.rec.add("kick:" + mac)
	return nil
}

// minUnit drives clientsReading with its own clock: the Bedroom unit, WLAN
// "net" on wl02/wl12, minimum RSSI -80 dBm on 5 GHz.
type minUnit struct {
	*roamUnit
}

func newMinUnit(t *testing.T, w banWifi) *minUnit {
	u := newRoamUnit(t)
	w.roamWifi = roamWifi{fakeWifi: u.h.wifi, err: w.err}
	u.h.a.wifi = w
	u.h.a.policy.Store(&wifiPolicy{steer: map[string]string{}, roam: map[string]int{}, minRSSI: map[string]int{"na": -80}})
	return &minUnit{u}
}

func (u *minUnit) reading(stale bool, bss string, signal int) []string {
	u.now = u.now.Add(10 * time.Second)
	s := testSnapshot()
	s.Radios[0].VAPs = []apstate.Radio{{Iface: "wl02", Band: "ng", SSID: "net", BSSID: "aa:a7:b9:3e:15:f8"}}
	s.Radios[1].VAPs[0].BSSID = "ba:a7:b9:3e:15:f8"
	s.Radios[1].VAPs[0].Stations = nil
	ph := apstate.Station{MAC: roamPhone, Signal: signal}
	switch bss {
	case "wl12":
		s.Radios[1].VAPs[0].Stations = []apstate.Station{ph}
	case "wl02":
		s.Radios[0].VAPs[0].Stations = []apstate.Station{ph}
	}
	before := len(u.h.rec.list())
	u.h.a.stale = stale
	u.h.a.clientsReading(s, u.now)
	for {
		select {
		case j := <-u.h.a.jobs:
			j.fn(context.Background())
			continue
		default:
		}
		break
	}
	return u.h.rec.list()[before:]
}

// A station below the controller's minimum RSSI for minRSSIBelow readings
// in a row is first asked to leave (BSS transition request, disassociation
// imminent) when another AP of the SSID is heard; still there
// minRSSIKickAfter later, it is kicked with a short ban on that BSS, which
// is lifted after minRSSIBan. Its leave carries assoc_status 16.
func TestMinRSSIKick(t *testing.T) {
	u := newMinUnit(t, banWifi{})
	sib := apstate.BSS{BSSID: "02:00:00:00:77:01", SSID: "net", Channel: 149, Signal: -70}
	var got []string
	for i := 0; i < minRSSIBelow; i++ {
		u.heard(0, sib)
		got = append(got, u.reading(false, "wl12", -85)...)
	}
	want := fmt.Sprintf("roam:%s@wl12->02:00:00:00:77:01/na/149 t=%d", roamPhone, minRSSIDisassocTBTT)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("calls %v, want [%s]", got, want)
	}
	if st := u.h.a.sta.leaveStatus(roamPhone, u.now); st != staLeaveMinRSSI {
		t.Errorf("leave status %d after the request", st)
	}
	got = nil
	for d := time.Duration(0); d < minRSSIKickAfter; d += 10 * time.Second {
		got = append(got, u.reading(false, "wl12", -86)...)
	}
	if len(got) != 1 || got[0] != "ban:"+roamPhone+"@wl12" {
		t.Fatalf("calls %v, want the ban", got)
	}
	got = nil
	for d := time.Duration(0); d < minRSSIBan; d += 10 * time.Second {
		got = append(got, u.reading(false, "", 0)...)
	}
	if len(got) != 1 || got[0] != "unban:"+roamPhone+"@wl12" {
		t.Fatalf("calls %v, want the ban lifted", got)
	}
	if !strings.Contains(u.h.logs.all(), "minimum RSSI") {
		t.Errorf("not logged:\n%s", u.h.logs.all())
	}
}

// No other AP heard (or no BSS transition support): straight to the kick.
// An allow-list SSID cannot take a ban: a plain kick then.
func TestMinRSSINoCandidate(t *testing.T) {
	u := newMinUnit(t, banWifi{})
	var got []string
	for i := 0; i < minRSSIBelow; i++ {
		got = append(got, u.reading(false, "wl12", -85)...)
	}
	if len(got) != 1 || got[0] != "ban:"+roamPhone+"@wl12" {
		t.Fatalf("calls %v", got)
	}
	u = newMinUnit(t, banWifi{roamWifi: roamWifi{err: bcmwifi.ErrNoBTM}})
	u.heard(0, apstate.BSS{BSSID: "02:00:00:00:77:01", SSID: "net", Channel: 149, Signal: -70})
	got = nil
	for i := 0; i < minRSSIBelow+1; i++ {
		got = append(got, u.reading(false, "wl12", -85)...)
	}
	if len(got) != 2 || !strings.HasPrefix(got[0], "roam:") || got[1] != "ban:"+roamPhone+"@wl12" {
		t.Fatalf("no BTM: calls %v", got)
	}
	u = newMinUnit(t, banWifi{banErr: bcmwifi.ErrAllowList})
	got = nil
	for i := 0; i < minRSSIBelow; i++ {
		got = append(got, u.reading(false, "wl12", -85)...)
	}
	if len(got) != 2 || got[1] != "kick:"+roamPhone {
		t.Fatalf("allow list: calls %v", got)
	}
}

// Readings at or above the threshold, without a signal, or stale (the last
// reading again) never count; nor does a band without a minimum; and
// nothing happens outside takeover.
func TestMinRSSIQuiet(t *testing.T) {
	u := newMinUnit(t, banWifi{})
	for i := 0; i < 20; i++ {
		sig, bss, stale := -80, "wl12", false
		switch i % 4 {
		case 1:
			sig = 0
		case 2:
			sig, bss = -90, "wl02" // 2.4 GHz has no minimum
		case 3:
			sig, stale = -90, true
		}
		if got := u.reading(stale, bss, sig); len(got) != 0 {
			t.Fatalf("reading %d: %v", i, got)
		}
	}
	u.h.a.takeover.Store(false)
	for i := 0; i < 5; i++ {
		if got := u.reading(false, "wl12", -90); len(got) != 0 {
			t.Fatalf("observe mode: %v", got)
		}
	}
}

// The leave after a minimum RSSI kick carries assoc_status 16
// (KICKED_DUE_TO_MIN_RSSI), the leave after a Roaming Assistant request
// 8192; any other leave 0. A hint is used once and runs out.
func TestStaLeaveStatus(t *testing.T) {
	const a, b, c = "aa:bb:cc:00:03:01", "aa:bb:cc:00:03:02", "aa:bb:cc:00:03:03"
	t0 := time.Date(2026, 11, 20, 11, 0, 0, 0, time.UTC)
	var e staEvents
	e.observe(staReading(100, map[string][][2]any{"wifi1ap1": {{a, -82}, {b, -77}, {c, -60}}}), nil)
	e.hint(a, staLeaveMinRSSI, t0.Add(staHintFor))
	e.hint(b, staLeaveRoamAssist, t0.Add(staHintFor))
	e.clock = func() time.Time { return t0.Add(10 * time.Second) }
	e.observe(staReading(110, map[string][][2]any{"wifi1ap1": {}}), nil)
	got := map[string]any{}
	for _, ev := range e.queue {
		got[ev["mac"].(string)] = ev["assoc_status"]
	}
	if got[a] != staLeaveMinRSSI || got[b] != staLeaveRoamAssist || got[c] != 0 {
		t.Fatalf("assoc_status %v", got)
	}
	if st := e.leaveStatus(a, t0); st != 0 {
		t.Errorf("hint used twice: %d", st)
	}
	e.hint(a, staLeaveMinRSSI, t0)
	if st := e.leaveStatus(a, t0.Add(time.Second)); st != 0 {
		t.Errorf("hint past its end: %d", st)
	}
}

// The policy carries each enabled radio's minimum RSSI.
func TestMinRSSIPolicy(t *testing.T) {
	p := policyFrom(bcmwifi.Desired{Radios: map[string]bcmwifi.Radio{
		"ng": {Enabled: true}, "na": {Enabled: true, MinRSSI: -78},
	}})
	if len(p.minRSSI) != 1 || p.minRSSI["na"] != -78 {
		t.Fatalf("%v", p.minRSSI)
	}
	p = policyFrom(bcmwifi.Desired{Radios: map[string]bcmwifi.Radio{"na": {MinRSSI: -78}}})
	if len(p.minRSSI) != 0 {
		t.Fatalf("disabled radio: %v", p.minRSSI)
	}
}
