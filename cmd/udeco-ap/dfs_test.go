// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/models"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// A radar move bcmwifi's Tick reports goes to the controller as a U6 Pro's
// EVT_AP_RadarDetected notification, one per move, naming the radio as
// the inform's radio_table does (the Garage's: TestGarageRadar).
func TestRadarEvent(t *testing.T) {
	a := &agent{o: options{logf: t.Logf}}
	a.x = radioSession(radioNamesMediaTek)
	a.renameRadios()
	a.radarIn([]bcmwifi.RadarEvent{{Band: "na", Radio: "wl1", Channel: 100, FreqMHz: 5500, From: "100/80", To: "36/80"}})
	a.radarEvents()
	if len(a.radarOut()) != 0 || len(a.sta.queue) != 1 {
		t.Fatalf("queue %+v", a.sta.queue)
	}
	p := a.sta.queue[0]
	want := map[string]any{"event_string": "EVT_AP_RadarDetected", "radio": "na", "radio_name": radioTableName(t, a, "na"), "channel": 100, "freq": 5500}
	if !reflect.DeepEqual(p, want) || p["radio_name"] != models.RadioNameMTK5G {
		t.Errorf("payload %v, want %v", p, want)
	}
	f := map[string]any{}
	a.sta.attach(f)
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
