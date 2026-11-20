// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/hapdmon"
)

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
	e.observe(staReading(100, map[string][][2]any{"rai1": {{"A6:7B:63:9F:25:40", -60}}, "ra0": {{"f4:cf:a2:1e:72:64", -70}}}), nil)
	if len(e.queue) != 0 {
		t.Fatalf("seed queued %v", e.queue)
	}
	// the Pixel leaves rai1, a new client joins ra0, the inverter stays
	e.observe(staReading(110, map[string][][2]any{"rai1": {}, "ra0": {{"f4:cf:a2:1e:72:64", -71}, {"c8:5c:cc:d1:2e:c7", -55}}}), nil)
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
	e.observe(staReading(120, map[string][][2]any{"rai0": {{"f4:cf:a2:1e:72:64", -65}}, "ra0": {{"c8:5c:cc:d1:2e:c7", -55}}}), nil)
	if len(e.queue) != 2 || e.queue[0]["event_type"] != "sta_leave" || e.queue[0]["vap"] != "ra0" ||
		e.queue[1]["event_type"] != "association" || e.queue[1]["vap"] != "rai0" {
		t.Fatalf("move %v", e.queue)
	}
}

func TestStaEventsRename(t *testing.T) {
	var e staEvents
	e.observe(staReading(1, map[string][][2]any{"wifi1": {{"a6:7b:63:9f:25:40", -60}}, "wifi0": {{"f4:cf:a2:1e:72:64", -70}}}), nil)
	// the controller renamed the VAPs: same clients, new names
	e.observe(staReading(2, map[string][][2]any{"rai1": {{"a6:7b:63:9f:25:40", -60}}, "ra0": {{"f4:cf:a2:1e:72:64", -70}}}), nil)
	// a VAP missing from one reading (an apply): no events either way
	e.observe(staReading(3, map[string][][2]any{"rai1": {{"a6:7b:63:9f:25:40", -60}}}), nil)
	e.observe(staReading(4, map[string][][2]any{"rai1": {{"a6:7b:63:9f:25:40", -60}}, "ra0": {{"f4:cf:a2:1e:72:64", -70}}}), nil)
	if len(e.queue) != 0 {
		t.Fatalf("rename or a missing VAP made events: %v", e.queue)
	}
	// a real leave after that is still reported
	e.observe(staReading(5, map[string][][2]any{"rai1": {}, "ra0": {{"f4:cf:a2:1e:72:64", -70}}}), nil)
	if len(e.queue) != 1 || e.queue[0]["event_type"] != "sta_leave" || e.queue[0]["vap"] != "rai1" {
		t.Fatalf("leave after rename: %v", e.queue)
	}
}

func TestStaEventsQueueBound(t *testing.T) {
	var e staEvents
	e.observe(staReading(1, nil), nil)
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

// staLive builds a hostapd monitor event.
func staLive(vif, mac string, k hapdmon.Kind, at time.Time) hapdmon.Event {
	return hapdmon.Event{Vif: vif, MAC: mac, Kind: k, At: at}
}

// The hostapd socket reports what two readings cannot see: the iPhone on
// the Bedroom unit's 5 GHz BSS disassociated and associated again between
// two readings (live 2026-11-19, 22:58:40). The controller gets the leave,
// then the association, once each, in that order; the reading that follows
// adds nothing.
func TestStaEventsLiveQuickReconnect(t *testing.T) {
	const iphone, other = "d2:f7:e5:58:6f:89", "a6:7b:00:00:00:01"
	t0 := time.Date(2026, 11, 19, 22, 58, 30, 0, time.UTC)
	vifs := map[string]string{"wl12": "wifi1ap1", "wl02": "wifi0ap1"}
	since := map[string]time.Time{"wl12": t0.Add(-time.Minute)} // wl02 has no socket
	var e staEvents
	e.observe(staReading(100, map[string][][2]any{"wifi1ap1": {{iphone, -76}}, "wifi0ap1": {{other, -50}}}),
		&staFeed{read: t0, now: t0, since: since, vifs: vifs})
	if len(e.queue) != 0 {
		t.Fatalf("seed queued %v", e.queue)
	}
	t1 := t0.Add(10 * time.Second)
	e.observe(staReading(110, map[string][][2]any{"wifi1ap1": {{iphone, -70}}, "wifi0ap1": {{other, -50}}}),
		&staFeed{read: t1, now: t1, since: since, vifs: vifs, evs: []hapdmon.Event{
			staLive("wl12", iphone, hapdmon.Disconnected, t0.Add(4*time.Second)),
			staLive("wl12", iphone, hapdmon.Connected, t0.Add(4*time.Second)),
		}})
	if len(e.queue) != 2 {
		t.Fatalf("queue %v", e.queue)
	}
	l, a := e.queue[0], e.queue[1]
	if l["event_type"] != "sta_leave" || l["mac"] != iphone || l["vap"] != "wifi1ap1" || l["avg_rssi"] != -76 || l["last_seen"] != int64(104) {
		t.Errorf("leave %v", l)
	}
	if a["event_type"] != "association" || a["mac"] != iphone || a["vap"] != "wifi1ap1" || a["auth_rssi"] != -70 ||
		a["assoc_status"] != 0 || a["last_seen"] != int64(104) {
		t.Errorf("association %v", a)
	}
	// the next reading agrees: nothing more
	t2 := t1.Add(10 * time.Second)
	e.observe(staReading(120, map[string][][2]any{"wifi1ap1": {{iphone, -71}}, "wifi0ap1": {{other, -50}}}),
		&staFeed{read: t2, now: t2, since: since, vifs: vifs})
	if len(e.queue) != 2 {
		t.Fatalf("reported twice: %v", e.queue)
	}
	// an event after the reading started waits for the next reading (the
	// reading may or may not show it yet), and is reported once
	t3 := t2.Add(10 * time.Second)
	e.observe(staReading(130, map[string][][2]any{"wifi1ap1": {{iphone, -71}}, "wifi0ap1": {{other, -50}}}),
		&staFeed{read: t3, now: t3.Add(time.Second), since: since, vifs: vifs, evs: []hapdmon.Event{
			staLive("wl12", iphone, hapdmon.Disconnected, t3.Add(500*time.Millisecond)),
		}})
	if len(e.queue) != 2 {
		t.Fatalf("an event newer than the reading was used: %v", e.queue)
	}
	t4 := t3.Add(10 * time.Second)
	e.observe(staReading(140, map[string][][2]any{"wifi1ap1": {}, "wifi0ap1": {{other, -50}}}),
		&staFeed{read: t4, now: t4, since: since, vifs: vifs})
	if len(e.queue) != 3 || e.queue[2]["event_type"] != "sta_leave" || e.queue[2]["last_seen"] != int64(130) {
		t.Fatalf("held leave %v", e.queue)
	}
	t5 := t4.Add(10 * time.Second)
	e.observe(staReading(150, map[string][][2]any{"wifi1ap1": {}, "wifi0ap1": {{other, -50}}}),
		&staFeed{read: t5, now: t5, since: since, vifs: vifs})
	if len(e.queue) != 3 {
		t.Fatalf("leave reported twice: %v", e.queue)
	}

	// a BSS without a socket keeps the reading diff, and its events (none
	// should come) are not used
	t6 := t5.Add(10 * time.Second)
	e.observe(staReading(160, map[string][][2]any{"wifi1ap1": {}, "wifi0ap1": {}}),
		&staFeed{read: t6, now: t6, since: since, vifs: vifs, evs: []hapdmon.Event{
			staLive("wl02", other, hapdmon.Disconnected, t5.Add(time.Second)),
		}})
	if len(e.queue) != 4 || e.queue[3]["event_type"] != "sta_leave" || e.queue[3]["mac"] != other || e.queue[3]["last_seen"] != int64(150) {
		t.Fatalf("fallback leave %v", e.queue)
	}
}

// A CONNECTED for a station the agent has on that BSS already means the
// drop between went unseen: still a leave, then an association. A
// DISCONNECTED for a station not on that BSS (told already) is nothing.
func TestStaEventsLiveMissedDrop(t *testing.T) {
	const sta = "aa:bb:cc:00:00:09"
	t0 := time.Date(2026, 11, 19, 23, 0, 0, 0, time.UTC)
	vifs := map[string]string{"wl12": "wifi1ap1", "wl02": "wifi0ap1"}
	since := map[string]time.Time{"wl12": t0.Add(-time.Minute), "wl02": t0.Add(-time.Minute)}
	var e staEvents
	e.observe(staReading(100, map[string][][2]any{"wifi1ap1": {{sta, -60}}, "wifi0ap1": {}}), &staFeed{read: t0, now: t0, since: since, vifs: vifs})
	t1 := t0.Add(10 * time.Second)
	e.observe(staReading(110, map[string][][2]any{"wifi1ap1": {{sta, -61}}, "wifi0ap1": {}}),
		&staFeed{read: t1, now: t1, since: since, vifs: vifs, evs: []hapdmon.Event{
			staLive("wl02", sta, hapdmon.Disconnected, t0.Add(time.Second)),
			staLive("wl12", sta, hapdmon.Connected, t0.Add(2*time.Second)),
		}})
	if len(e.queue) != 2 || e.queue[0]["event_type"] != "sta_leave" || e.queue[1]["event_type"] != "association" ||
		e.queue[1]["auth_rssi"] != -61 {
		t.Fatalf("queue %v", e.queue)
	}
	// it moves to the 2.4 GHz BSS: leave on 5 GHz, association on 2.4 GHz,
	// whatever order the two sockets' events came in
	t2 := t1.Add(10 * time.Second)
	e.observe(staReading(120, map[string][][2]any{"wifi1ap1": {}, "wifi0ap1": {{sta, -50}}}),
		&staFeed{read: t2, now: t2, since: since, vifs: vifs, evs: []hapdmon.Event{
			staLive("wl02", sta, hapdmon.Connected, t1.Add(time.Second)),
			staLive("wl12", sta, hapdmon.Disconnected, t1.Add(time.Second)),
		}})
	if len(e.queue) != 4 || e.queue[2]["event_type"] != "sta_leave" || e.queue[2]["vap"] != "wifi1ap1" ||
		e.queue[3]["event_type"] != "association" || e.queue[3]["vap"] != "wifi0ap1" || e.queue[3]["auth_rssi"] != -50 {
		t.Fatalf("move %v", e.queue)
	}
}

// A socket that missed an event (hostapd restarted between readings,
// a datagram lost) is caught up by the reading, but only once the
// reading has disagreed for staSettle readings in a row: a station in the
// association list that has not finished its handshake yet is no
// association.
func TestStaEventsLiveReconcile(t *testing.T) {
	const a1, a2 = "aa:bb:cc:00:00:0a", "aa:bb:cc:00:00:0b"
	t0 := time.Date(2026, 11, 19, 23, 0, 0, 0, time.UTC)
	vifs := map[string]string{"wl12": "wifi1ap1"}
	since := map[string]time.Time{"wl12": t0.Add(-time.Minute)}
	var e staEvents
	e.observe(staReading(100, map[string][][2]any{"wifi1ap1": {{a1, -60}}}), &staFeed{read: t0, now: t0, since: since, vifs: vifs})
	for i := 1; i < staSettle; i++ {
		ti := t0.Add(time.Duration(i) * 10 * time.Second)
		e.observe(staReading(100+int64(i)*10, map[string][][2]any{"wifi1ap1": {{a2, -65}}}), &staFeed{read: ti, now: ti, since: since, vifs: vifs})
		if len(e.queue) != 0 {
			t.Fatalf("reading %d: reconciled too early: %v", i, e.queue)
		}
	}
	ti := t0.Add(time.Duration(staSettle) * 10 * time.Second)
	e.observe(staReading(100+int64(staSettle)*10, map[string][][2]any{"wifi1ap1": {{a2, -65}}}), &staFeed{read: ti, now: ti, since: since, vifs: vifs})
	if len(e.queue) != 2 {
		t.Fatalf("queue %v", e.queue)
	}
	got := map[string]string{}
	for _, ev := range e.queue {
		got[ev["mac"].(string)] = ev["event_type"].(string)
	}
	if got[a1] != "sta_leave" || got[a2] != "association" {
		t.Fatalf("reconciled %v", e.queue)
	}
}

func TestStaVifNames(t *testing.T) {
	s := testSnapshot()
	s.Radios[0].VAPs = []apstate.Radio{{Iface: "wl02", BSSID: "AA:A7:B9:3E:15:F8"}, {Iface: "wl03"}}
	f := map[string]any{"vap_table": []map[string]any{
		{"name": "wifi1ap1", "bssid": "b2:a7:b9:00:00:07"},
		{"name": "wifi0ap1", "bssid": "aa:a7:b9:3e:15:f8"},
	}}
	got := staVifNames(s, f)
	if len(got) != 2 || got["wl12"] != "wifi1ap1" || got["wl02"] != "wifi0ap1" {
		t.Fatalf("vif names %v", got)
	}
}

// fakeStaMon is a hostapd socket monitor that has had wl12 attached for
// long and hands over events once armed.
type fakeStaMon struct {
	mu  sync.Mutex
	evs []hapdmon.Event
}

func (m *fakeStaMon) Take() ([]hapdmon.Event, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.evs
	m.evs = nil
	return e, 0
}

func (m *fakeStaMon) Attached() map[string]time.Time {
	return map[string]time.Time{"wl12": time.Unix(1, 0)}
}

// End to end: a quick reconnect hostapd reports between two readings
// reaches the controller as a sta_leave and then an association, each in
// a notification inform of its own.
func TestStaEventsFromHostapd(t *testing.T) {
	mon := &fakeStaMon{}
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true; o.staMon = mon })
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	defer h.stop()
	eventually(t, "provisioned", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c1" })
	n := h.ctl.count()
	eventually(t, "two more informs", func() bool { return h.ctl.count() >= n+2 })
	at := time.Now()
	mon.mu.Lock()
	mon.evs = []hapdmon.Event{
		{Vif: "wl12", MAC: staMAC, Kind: hapdmon.Disconnected, At: at},
		{Vif: "wl12", MAC: staMAC, Kind: hapdmon.Connected, At: at},
	}
	mon.mu.Unlock()
	var got []map[string]any
	eventually(t, "both events", func() bool {
		got = got[:0]
		for _, m := range h.ctl.all() {
			if p, ok := m["notif_payload"].(map[string]any); ok && p["message_type"] == staTracker {
				got = append(got, p)
			}
		}
		return len(got) >= 2
	})
	if len(got) != 2 || got[0]["event_type"] != "sta_leave" || got[1]["event_type"] != "association" ||
		got[0]["mac"] != staMAC || got[1]["mac"] != staMAC || got[0]["vap"] == "" || got[0]["vap"] != got[1]["vap"] ||
		got[1]["auth_rssi"] != float64(-55) {
		t.Fatalf("events %v", got)
	}
}

// A BSS's first covered reading takes the reading before it as the
// baseline: the socket events held from that reading's collection window
// were already in its vap_table (and its diff), so they are not told a
// second time. Every way a socket comes to be attached (the agent starts,
// a re-attach after a missed PONG, hostapd restarting with a new socket)
// gives no event of its own; an event after that reading was taken still
// counts, once.
func TestStaEventsAttachNoSpurious(t *testing.T) {
	const a, x, y, z = "aa:bb:cc:00:01:0a", "aa:bb:cc:00:01:0b", "aa:bb:cc:00:01:0c", "aa:bb:cc:00:01:0d"
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	vifs := map[string]string{"wl12": "wifi1ap1"}
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * 10 * time.Second) }
	read := func(e *staEvents, i int, since time.Time, stas [][2]any, evs ...hapdmon.Event) {
		t.Helper()
		e.observe(staReading(100+int64(i)*10, map[string][][2]any{"wifi1ap1": stas}),
			// the reading takes 2 s: the events in it were in its window
			&staFeed{read: at(i), now: at(i).Add(2 * time.Second), since: map[string]time.Time{"wl12": since}, vifs: vifs, evs: evs})
	}
	count := func(e *staEvents, mac, kind string) int {
		n := 0
		for _, ev := range e.queue {
			if ev["mac"] == mac && ev["event_type"] == kind {
				n++
			}
		}
		return n
	}

	t.Run("agent start", func(t *testing.T) {
		var e staEvents
		since := t0.Add(-time.Minute)
		// x joins and y leaves while the seeding reading is taken; it
		// shows both
		read(&e, 0, since, [][2]any{{a, -60}, {x, -61}},
			staLive("wl12", x, hapdmon.Connected, at(0).Add(time.Second)),
			staLive("wl12", y, hapdmon.Disconnected, at(0).Add(500*time.Millisecond)))
		// z joins after the seeding reading was taken
		read(&e, 1, since, [][2]any{{a, -60}, {x, -61}, {z, -62}},
			staLive("wl12", z, hapdmon.Connected, at(0).Add(3*time.Second)))
		for i := 2; i < 6; i++ {
			read(&e, i, since, [][2]any{{a, -60}, {x, -61}, {z, -62}})
		}
		if len(e.queue) != 1 || count(&e, z, staEvAssoc) != 1 {
			t.Fatalf("queue %v, want z's association only", e.queue)
		}
	})

	t.Run("re-attach after a missed PONG", func(t *testing.T) {
		var e staEvents
		read(&e, 0, t0.Add(-time.Minute), [][2]any{{a, -60}})
		read(&e, 1, t0.Add(-time.Minute), [][2]any{{a, -60}})
		// attached again between readings 1 and 2: reading 2 is the
		// diff's, and x joins while it is taken
		since := at(1).Add(5 * time.Second)
		read(&e, 2, since, [][2]any{{a, -60}, {x, -61}}, staLive("wl12", x, hapdmon.Connected, at(2).Add(time.Second)))
		for i := 3; i < 7; i++ {
			read(&e, i, since, [][2]any{{a, -60}, {x, -61}})
		}
		if len(e.queue) != 1 || count(&e, x, staEvAssoc) != 1 {
			t.Fatalf("queue %v, want x's association once", e.queue)
		}
	})

	t.Run("hostapd restart", func(t *testing.T) {
		var e staEvents
		read(&e, 0, t0.Add(-time.Minute), [][2]any{{a, -60}, {y, -63}})
		read(&e, 1, t0.Add(-time.Minute), [][2]any{{a, -60}, {y, -63}})
		// hostapd restarted with a new socket, attached again before
		// reading 2; while reading 2 is taken y leaves and x joins, and
		// after it was taken a leaves
		since := at(1).Add(5 * time.Second)
		read(&e, 2, since, [][2]any{{a, -60}, {x, -61}},
			staLive("wl12", y, hapdmon.Disconnected, at(2).Add(500*time.Millisecond)),
			staLive("wl12", x, hapdmon.Connected, at(2).Add(time.Second)),
			staLive("wl12", a, hapdmon.Disconnected, at(2).Add(3*time.Second)))
		for i := 3; i < 7; i++ {
			read(&e, i, since, [][2]any{{x, -61}})
		}
		if len(e.queue) != 3 || count(&e, y, staEvLeave) != 1 || count(&e, x, staEvAssoc) != 1 || count(&e, a, staEvLeave) != 1 {
			t.Fatalf("queue %v, want y's leave, x's association, a's leave, once each", e.queue)
		}
	})
}

// scriptCol is fakeCol whose readings follow a script by call number.
type scriptCol struct {
	*fakeCol
	mu sync.Mutex
	n  int
	fn func(n int) (*apstate.Snapshot, error)
}

func (c *scriptCol) Collect(ctx context.Context) (*apstate.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return c.fn(c.n)
}

func (c *scriptCol) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// A reading that fails reports the last one again; it is no new look at
// the stations. Its socket events wait for the next real reading, and the
// stale vap_table neither counts toward reconciling nor reports a station
// a second time.
func TestStaEventsStaleReading(t *testing.T) {
	const x = "aa:bb:cc:00:02:0b"
	mon := &fakeStaMon{}
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true; o.staMon = mon })
	// 1 the first reading, 2 seeds, 3 covers wl12; x joins while 4 is
	// taken (the reading shows it, its CONNECTED comes after the reading
	// started); 5-9 fail; 10 on read again
	col := &scriptCol{fakeCol: h.col, fn: func(n int) (*apstate.Snapshot, error) {
		s := testSnapshot()
		switch {
		case n >= 5 && n <= 9:
			return nil, errors.New("wl: timeout")
		case n == 4:
			mon.mu.Lock()
			mon.evs = []hapdmon.Event{{Vif: "wl12", MAC: x, Kind: hapdmon.Connected, At: time.Now()}}
			mon.mu.Unlock()
			fallthrough
		case n > 4:
			s.Radios[1].VAPs[0].Stations = append(s.Radios[1].VAPs[0].Stations, apstate.Station{MAC: x, Signal: -61})
		}
		return s, nil
	}}
	h.a.o.col = col
	h.start()
	eventually(t, "readings", func() bool { return col.calls() >= 10+staSettle+1 })
	h.stop()
	var got []string
	for _, ev := range h.a.sta.queue {
		got = append(got, ev["event_type"].(string)+" "+ev["mac"].(string))
	}
	if len(got) != 1 || got[0] != "association "+x {
		t.Fatalf("events %v, want x's association once", got)
	}
}

// A covered BSS's events held from the previous reading's collection
// window are not replayed for a station that reading's diff (an uncovered
// BSS of the same unit) already moved: the diff told the outcome (review
// finding, TestProbeCrossVapWindow). x joins the covered wl12 and moves to
// wl02, whose socket was just attached again, while reading 1 is taken;
// reading 1 shows x on wl02. The controller hears one association on
// wifi0ap1 and nothing else.
func TestStaEventsCrossVapWindow(t *testing.T) {
	const x = "aa:bb:cc:00:02:01"
	t0 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * 10 * time.Second) }
	vifs := map[string]string{"wl12": "wifi1ap1", "wl02": "wifi0ap1"}
	since := map[string]time.Time{"wl12": t0.Add(-time.Hour)} // wl02 is not covered
	var e staEvents
	read := func(i int, on string, evs ...hapdmon.Event) {
		vaps := map[string][][2]any{"wifi1ap1": {}, "wifi0ap1": {}}
		if on != "" {
			vaps[on] = [][2]any{{x, -60}}
		}
		e.observe(staReading(100+int64(i)*10, vaps), &staFeed{read: at(i), now: at(i).Add(2 * time.Second), since: since, vifs: vifs, evs: evs})
	}
	read(0, "")
	read(1, "wifi0ap1",
		staLive("wl12", x, hapdmon.Connected, at(1).Add(300*time.Millisecond)),
		staLive("wl12", x, hapdmon.Disconnected, at(1).Add(800*time.Millisecond)))
	for i := 2; i < 6; i++ {
		read(i, "wifi0ap1")
	}
	var got []string
	for _, ev := range e.queue {
		got = append(got, ev["event_type"].(string)+" "+ev["vap"].(string))
	}
	if len(got) != 1 || got[0] != "association wifi0ap1" {
		t.Fatalf("events %v, want [association wifi0ap1]", got)
	}
}
