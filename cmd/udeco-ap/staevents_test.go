// SPDX-License-Identifier: GPL-2.0-or-later

package main

import "testing"

func staReading(up int64, vaps map[string][][2]any) map[string]any {
	var vt []map[string]any
	for name, stas := range vaps {
		var st []map[string]any
		for _, s := range stas {
			st = append(st, map[string]any{"mac": s[0], "signal": s[1], "rssi": 40})
		}
		vt = append(vt, map[string]any{"name": name, "sta_table": st})
	}
	return map[string]any{"uptime": up, "vap_table": vt}
}

func TestStaEvents(t *testing.T) {
	var e staEvents
	// startup: clients already there get no event
	e.observe(staReading(100, map[string][][2]any{"rai1": {{"A6:7B:63:9F:25:40", -60}}, "ra0": {{"f4:cf:a2:1e:72:64", -70}}}))
	if len(e.queue) != 0 {
		t.Fatalf("seed queued %v", e.queue)
	}
	// the Pixel leaves rai1, a new client joins ra0, the inverter stays
	e.observe(staReading(110, map[string][][2]any{"rai1": {}, "ra0": {{"f4:cf:a2:1e:72:64", -71}, {"c8:5c:cc:d1:2e:c7", -55}}}))
	if len(e.queue) != 2 {
		t.Fatalf("queue %v", e.queue)
	}
	l, a := e.queue[0], e.queue[1]
	if l["message_type"] != "STA_ASSOC_TRACKER" || l["event_type"] != "sta_leave" || l["mac"] != "a6:7b:63:9f:25:40" ||
		l["vap"] != "rai1" || l["avg_rssi"] != -60 || l["last_seen"] != int64(100) {
		t.Fatalf("leave %v", l)
	}
	if a["event_type"] != "association" || a["mac"] != "c8:5c:cc:d1:2e:c7" || a["vap"] != "ra0" ||
		a["auth_rssi"] != -55 || a["assoc_status"] != 0 || a["last_seen"] != int64(110) {
		t.Fatalf("association %v", a)
	}

	// one event per inform, never on a spectrum notification, kept when the
	// inform failed
	f := map[string]any{"inform_as_notif": true, "notif_reason": "event", "notif_payload": "spectrum"}
	e.attach(f)
	if f["notif_payload"] != "spectrum" {
		t.Fatalf("overwrote a spectrum event: %v", f)
	}
	if s, more := e.informed(true); s != nil || !more {
		t.Fatalf("informed after spectrum: %v %v", s, more)
	}
	f = map[string]any{}
	e.attach(f)
	if f["inform_as_notif"] != true || f["notif_reason"] != "event" || f["notif_payload"].(map[string]any)["event_type"] != "sta_leave" {
		t.Fatalf("attach %v", f)
	}
	if s, _ := e.informed(false); s != nil || len(e.queue) != 2 {
		t.Fatalf("failed inform dropped the event: %v %d", s, len(e.queue))
	}
	e.attach(map[string]any{})
	if s, more := e.informed(true); s == nil || s["event_type"] != "sta_leave" || !more {
		t.Fatalf("sent %v more %v", s, more)
	}
	e.attach(map[string]any{})
	if s, more := e.informed(true); s == nil || s["event_type"] != "association" || more {
		t.Fatalf("sent %v more %v", s, more)
	}
	f = map[string]any{}
	e.attach(f)
	if f["inform_as_notif"] != nil {
		t.Fatalf("empty queue attached %v", f)
	}

	// a client moving between VAPs of this AP: leave on the old one, then
	// association on the new one
	e.observe(staReading(120, map[string][][2]any{"rai0": {{"f4:cf:a2:1e:72:64", -65}}, "ra0": {{"c8:5c:cc:d1:2e:c7", -55}}}))
	if len(e.queue) != 2 || e.queue[0]["event_type"] != "sta_leave" || e.queue[0]["vap"] != "ra0" ||
		e.queue[1]["event_type"] != "association" || e.queue[1]["vap"] != "rai0" {
		t.Fatalf("move %v", e.queue)
	}
}

func TestStaEventsRename(t *testing.T) {
	var e staEvents
	e.observe(staReading(1, map[string][][2]any{"wifi1": {{"a6:7b:63:9f:25:40", -60}}, "wifi0": {{"f4:cf:a2:1e:72:64", -70}}}))
	// the controller renamed the VAPs: same clients, new names
	e.observe(staReading(2, map[string][][2]any{"rai1": {{"a6:7b:63:9f:25:40", -60}}, "ra0": {{"f4:cf:a2:1e:72:64", -70}}}))
	// a VAP missing from one reading (an apply): no events either way
	e.observe(staReading(3, map[string][][2]any{"rai1": {{"a6:7b:63:9f:25:40", -60}}}))
	e.observe(staReading(4, map[string][][2]any{"rai1": {{"a6:7b:63:9f:25:40", -60}}, "ra0": {{"f4:cf:a2:1e:72:64", -70}}}))
	if len(e.queue) != 0 {
		t.Fatalf("rename or a missing VAP made events: %v", e.queue)
	}
	// a real leave after that is still reported
	e.observe(staReading(5, map[string][][2]any{"rai1": {}, "ra0": {{"f4:cf:a2:1e:72:64", -70}}}))
	if len(e.queue) != 1 || e.queue[0]["event_type"] != "sta_leave" || e.queue[0]["vap"] != "rai1" {
		t.Fatalf("leave after rename: %v", e.queue)
	}
}

func TestStaEventsQueueBound(t *testing.T) {
	var e staEvents
	e.observe(staReading(1, nil))
	for i := 0; i < staQueueMax+10; i++ {
		e.push(map[string]any{"n": i})
	}
	if len(e.queue) != staQueueMax || e.dropped != 10 || e.queue[0]["n"] != 10 {
		t.Fatalf("len %d dropped %d first %v", len(e.queue), e.dropped, e.queue[0])
	}
	e.attach(map[string]any{})
	e.push(map[string]any{"n": "new"})
	if e.queue[0]["n"] != 10 {
		t.Fatalf("dropped the event on the wire: %v", e.queue[0])
	}
}
