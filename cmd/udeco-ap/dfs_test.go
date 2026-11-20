// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// A radar move bcmwifi's Tick reports goes to the controller as a U6 Pro's
// EVT_AP_RadarDetected notification, one per move.
func TestRadarEvent(t *testing.T) {
	a := &agent{o: options{logf: t.Logf}}
	a.radarIn([]bcmwifi.RadarEvent{{Band: "na", Radio: "wl1", Channel: 100, FreqMHz: 5500, From: "100/80", To: "36/80"}})
	evs := a.radarOut()
	if len(evs) != 1 || len(a.radarOut()) != 0 {
		t.Fatalf("queue %+v", evs)
	}
	p := radarPayload(evs[0].Band, evs[0].Channel, evs[0].FreqMHz, "wifi1")
	want := map[string]any{"event_string": "EVT_AP_RadarDetected", "radio": "na", "radio_name": "wifi1", "channel": 100, "freq": 5500}
	for k, v := range want {
		if p[k] != v {
			t.Errorf("%s = %v, want %v", k, p[k], v)
		}
	}
	var sta staEvents
	sta.push(p)
	f := map[string]any{}
	sta.attach(f)
	if f["inform_as_notif"] != true || f["notif_reason"] != "event" {
		t.Errorf("not a notification: %v", f)
	}
}

// dfs-reset runs once a day at the controller's time, never before it.
func TestDFSResetDue(t *testing.T) {
	at := translate.DailyTime{Hour: 2, Minute: 0}
	day := func(h, m int) time.Time { return time.Date(2026, 11, 20, h, m, 0, 0, time.Local) }
	for _, c := range []struct {
		now, last time.Time
		want      bool
	}{
		{day(1, 59), time.Time{}, false},
		{day(2, 0), time.Time{}, false}, // the agent's start is no reset
		{day(2, 0), day(1, 59), true},
		{day(2, 1), day(2, 0), false},
		{day(23, 0), day(2, 0), false},
		{day(2, 0).Add(24 * time.Hour), day(2, 0), true},
		{day(9, 0), day(1, 0), true}, // the agent was down at 02:00: catches up
	} {
		if got := dfsResetDue(c.now, at, c.last); got != c.want {
			t.Errorf("now %s last %s: %v", c.now.Format("02 15:04"), c.last.Format("02 15:04"), got)
		}
	}
}
