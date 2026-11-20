// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/hapdmon"
)

// Station events (STA_ASSOC_TRACKER), as a UniFi AP sends them.
//
// A client that leaves is not dropped by the controller when it is missing
// from vap_table: Network keeps it online on its last AP until its own
// timeout (about 5 minutes, seen live 2026-11-19). A real AP reports the
// moment with a notification inform (inform_as_notif, notif_reason
// "event") whose notif_payload has message_type "STA_ASSOC_TRACKER" and an
// event_type (devmgr.w.a.aoKmBacf: association, success, failure,
// sta_leave, sta_roam). The handlers read:
//   - sta_leave (PfwtrEhZ -> staManager disconnect): mac, vap (a vap_table
//     name of this AP), avg_rssi (dBm, stored as the client's signal when
//     non-zero), last_seen (in the inform's uptime: the event time is
//     received - (uptime - last_seen)). Ignored when the controller already
//     has the client on another AP or BSS, so a late leave after a roam is
//     harmless.
//   - association (roaming detector fxANyGCMTypmL): mac, vap, auth_rssi
//     (dBm; an association without it is ignored), auth_algo ("ft" marks a
//     fast transition), assoc_status. A leave on one AP and an association
//     on another make a roam in the client's history.
//
// success/failure/soft failure/fixup carry the connection timings; they
// come from staconn.go (sta_snoop), not from here.
//
// A notification inform's stats are not processed (devmgr.l.mMObEXELV
// returns after the notification), so each event goes in an extra inform
// right after the reading that found it (immediateWait apart), never in
// place of the regular one, and one per inform.
//
// Where the events come from. Two readings of vap_table cannot see a
// station that disassociates and associates again between them (live on
// the Bedroom unit, 2026-11-19: "wl12: STA d2:f7:... disassociated" and
// "associated" in the same second, nothing reached the controller). So in
// takeover mode on the Deco the agent attaches to each BSS's hostapd
// control socket (internal/hapdmon: AP-STA-CONNECTED, AP-STA-DISCONNECTED)
// and a BSS whose socket has been attached since before the previous
// reading is "covered":
//   - its socket events, in the order received, make the events: a
//     DISCONNECTED for a station the agent has on that BSS is a sta_leave;
//     a CONNECTED is an association, after a sta_leave on the BSS it was on
//     before (the same BSS too: a reconnect is a real drop). avg_rssi is the
//     signal of the last reading that had it, auth_rssi the signal of this
//     reading (else the last one's), last_seen the event's own time.
//   - only events from before the reading started are used; later ones wait
//     for the next reading, so a reading taken while a station came or went
//     never reports it a second time.
//   - the reading diff is not used, but a reading that disagrees with the
//     socket's account staSettle readings in a row (an event lost while
//     hostapd restarted) wins.
//   - a BSS's first covered reading (the agent started, the socket was
//     attached again after a missed PONG or a hostapd restart) builds on
//     the reading before it, which used the diff: that reading was taken
//     after it started, so a station it already shows on the BSS is no
//     association again for a CONNECTED from while it was taken.
//   - likewise a station whose place the previous reading's diff set or
//     removed (it moved to or from a BSS that is not covered): that
//     reading's outcome holds, and a covered BSS's events from its
//     collection window are not replayed after it.
//
// A BSS that is not covered (no socket, just attached, the Garage) keeps
// the reading diff below.
const (
	staTracker  = "STA_ASSOC_TRACKER"
	staQueueMax = 128 // events waiting at most; older ones are dropped (counted)
	staHeldMax  = 256 // socket events newer than the reading, kept for the next one
	staEvLeave  = "sta_leave"
	staEvAssoc  = "association"
	staCarry    = 120 // s a vanished VAP's clients stay on record
	staSettle   = 3   // readings in a row a covered VAP must disagree with its socket
)

type staSeen struct {
	vap      string
	signal   int
	lastSeen int64
}

type staEvents struct {
	// prev is where each client is, as the controller was told (the last
	// reading, the socket events since)
	prev    map[string]staSeen
	seeded  bool
	queue   []map[string]any
	offered bool // queue[0] rides the inform being sent
	dropped int
	held    []hapdmon.Event // socket events from after the last reading started
	read    time.Time       // when the last reading started (zero: no socket feed)
	taken   time.Time       // when the last reading had been taken (its feed's now)
	cov     map[string]bool // the VAPs the last reading covered
	odd     map[string]int  // "mac|vap|+/-": readings in a row a covered VAP disagreed
	// moved: the stations whose place the last reading's diff set or
	// removed (an uncovered BSS): their covered events from that reading's
	// collection window are in its outcome already
	moved map[string]bool
	// hints: why a station is expected to leave (the agent asked it to or
	// kicked it): its next sta_leave carries that assoc_status
	hints map[string]staHint
	at    time.Time        // this reading's time (the feed's, else clock)
	clock func() time.Time // nil = time.Now
}

// staHint is a sta_leave's assoc_status for a while.
type staHint struct {
	status int
	until  time.Time
}

// assoc_status of a sta_leave, as a U6 sends them and the controller reads
// them (WifiConnectivity triggeredByMinimalRssi / triggeredByRoamingAssistant).
const (
	staLeaveMinRSSI    = 16   // KICKED_DUE_TO_MIN_RSSI: the minimum RSSI kick (minrssi.go)
	staLeaveRoamAssist = 8192 // left after a Roaming Assistant request (roaming.go)
	staHintFor         = 2 * time.Minute
)

// hint makes mac's next sta_leave until until carry status.
func (e *staEvents) hint(mac string, status int, until time.Time) {
	if e.hints == nil {
		e.hints = map[string]staHint{}
	}
	e.hints[strings.ToLower(mac)] = staHint{status, until}
}

// unhint drops mac's hint (the request it was for was never sent).
func (e *staEvents) unhint(mac string) { delete(e.hints, strings.ToLower(mac)) }

// leaveStatus is the assoc_status of mac's sta_leave at now (the hint is
// used once).
func (e *staEvents) leaveStatus(mac string, now time.Time) int {
	h, ok := e.hints[mac]
	if !ok {
		return 0
	}
	delete(e.hints, mac)
	if now.After(h.until) {
		return 0
	}
	return h.status
}

// staFeed is the hostapd socket's part of one reading (nil: none).
type staFeed struct {
	read  time.Time            // when the reading started: older events are in it
	now   time.Time            // when the reading's uptime was taken
	since map[string]time.Time // BSS interface -> its socket attached since
	vifs  map[string]string    // BSS interface -> vap_table name, this reading
	evs   []hapdmon.Event      // new socket events, in the order received
}

// observe takes this reading's vap_table (and the socket events, when there
// is a feed) and queues the events. The first reading only seeds (clients
// already associated when the agent starts get no association event).
func (e *staEvents) observe(f map[string]any, feed *staFeed) {
	if feed != nil {
		e.at = feed.now
	} else if e.clock != nil {
		e.at = e.clock()
	} else {
		e.at = time.Now()
	}
	for m, h := range e.hints {
		if e.at.After(h.until) {
			delete(e.hints, m)
		}
	}
	up, _ := toInt64(f["uptime"])
	cur := map[string]staSeen{}
	names := map[string]bool{}
	vaps, _ := f["vap_table"].([]map[string]any)
	for _, v := range vaps {
		name, _ := v["name"].(string)
		names[name] = true
		stas, _ := v["sta_table"].([]map[string]any)
		for _, s := range stas {
			mac, _ := s["mac"].(string)
			if mac == "" || name == "" {
				continue
			}
			sig, _ := toInt64(s["signal"])
			cur[strings.ToLower(mac)] = staSeen{vap: name, signal: int(sig), lastSeen: up}
		}
	}
	var evs []hapdmon.Event
	covered, fresh := map[string]bool{}, map[string]bool{}
	var taken time.Time
	if feed != nil {
		// events from before the reading started are in it; the others
		// wait for the next one
		var later []hapdmon.Event
		for _, ev := range append(e.held, feed.evs...) {
			if ev.At.Before(feed.read) {
				evs = append(evs, ev)
			} else {
				later = append(later, ev)
			}
		}
		if n := len(later) - staHeldMax; n > 0 {
			later, e.dropped = later[n:], e.dropped+n
		}
		e.held = later
		for vif, since := range feed.since {
			if n := feed.vifs[vif]; n != "" && names[n] && !e.read.IsZero() && !since.IsZero() && !since.After(e.read) {
				covered[n] = true
			}
		}
		// a VAP covered for the first time builds on the last reading,
		// which used the diff and showed what happened while it was taken
		for n := range covered {
			if !e.cov[n] {
				fresh[n] = true
			}
		}
		taken = e.taken
		e.read, e.taken, e.cov = feed.read, feed.now, covered
	}
	if !e.seeded {
		e.prev, e.seeded = cur, true
		return
	}
	if e.prev == nil {
		e.prev = map[string]staSeen{}
	}
	// the covered BSSes' socket events
	touched := map[string]bool{}
	for _, ev := range evs {
		vap := feed.vifs[ev.Vif]
		if !covered[vap] || ev.Kind != hapdmon.Connected && ev.Kind != hapdmon.Disconnected {
			continue // the other kinds feed the connection timings (staconn.go)
		}
		touched[ev.MAC] = true
		if p, ok := e.prev[ev.MAC]; ok && p.vap == vap && ev.Kind == hapdmon.Connected && fresh[vap] && ev.At.Before(taken) {
			continue // the last reading (the diff's) had it there already
		}
		if e.moved[ev.MAC] && ev.At.Before(taken) {
			continue // the last reading's diff told where it ended up
		}
		e.live(ev, vap, names, cur, up-int64(feed.now.Sub(ev.At).Round(time.Second)/time.Second))
	}
	// the other BSSes: the reading diff. A client counts as gone from a VAP
	// only while that VAP is still in the reading: a VAP that vanished was
	// renamed (the controller's devnames after adoption or a new
	// system_cfg) or is down for a moment (an apply), and its clients are
	// no events. Likewise a client found on a new VAP whose old one
	// vanished moved with the rename.
	var gone, came []string
	for mac, p := range e.prev {
		if c, ok := cur[mac]; (!ok || c.vap != p.vap) && names[p.vap] && !covered[p.vap] {
			gone = append(gone, mac)
		}
	}
	sort.Strings(gone)
	moved := map[string]bool{}
	for _, mac := range gone {
		p := e.prev[mac]
		e.leave(mac, p, p.lastSeen)
		delete(e.prev, mac)
		moved[mac] = true
	}
	for mac, c := range cur {
		if covered[c.vap] {
			continue
		}
		if p, ok := e.prev[mac]; !ok || p.vap != c.vap && names[p.vap] {
			came = append(came, mac)
		} else {
			e.prev[mac] = c
		}
	}
	sort.Strings(came)
	for _, mac := range came {
		c := cur[mac]
		if p, ok := e.prev[mac]; ok {
			e.leave(mac, p, p.lastSeen) // it was on a covered BSS, whose socket has not said so yet
		}
		e.assoc(mac, c)
		e.prev[mac] = c
		moved[mac] = true
	}
	e.moved = moved
	e.reconcile(cur, names, covered, touched)
	// clients of a VAP missing from this reading stay on record for a
	// while, so the VAP's return is no wave of associations
	for mac, p := range e.prev {
		if !names[p.vap] && up-p.lastSeen >= staCarry {
			delete(e.prev, mac)
		}
	}
}

// live applies one socket event of a covered VAP; at is its time in the
// reading's uptime.
func (e *staEvents) live(ev hapdmon.Event, vap string, names map[string]bool, cur map[string]staSeen, at int64) {
	p, had := e.prev[ev.MAC]
	switch ev.Kind {
	case hapdmon.Disconnected:
		if had && p.vap == vap {
			e.leave(ev.MAC, p, at)
			delete(e.prev, ev.MAC)
		}
	case hapdmon.Connected:
		if had && names[p.vap] {
			e.leave(ev.MAC, p, at)
		}
		s := staSeen{vap: vap, signal: p.signal, lastSeen: at}
		if c, ok := cur[ev.MAC]; ok && c.signal != 0 {
			s.signal = c.signal
		}
		e.assoc(ev.MAC, s)
		e.prev[ev.MAC] = s
	}
}

// reconcile compares the covered VAPs with the reading: their clients get
// this reading's signal, and a disagreement that lasts staSettle readings
// (with no socket event for the client meanwhile) becomes the events the
// socket missed.
func (e *staEvents) reconcile(cur map[string]staSeen, names, covered, touched map[string]bool) {
	if e.odd == nil {
		e.odd = map[string]int{}
	}
	odd := map[string]bool{}
	settled := func(k string) bool {
		odd[k] = true
		e.odd[k]++
		if e.odd[k] < staSettle {
			return false
		}
		delete(e.odd, k)
		return true
	}
	var came, gone []string
	for mac, c := range cur {
		if !covered[c.vap] {
			continue
		}
		if p, ok := e.prev[mac]; ok && (p.vap == c.vap || !names[p.vap]) {
			e.prev[mac] = c
		} else if !touched[mac] {
			came = append(came, mac)
		}
	}
	for mac, p := range e.prev {
		if _, ok := cur[mac]; !ok && covered[p.vap] && !touched[mac] {
			gone = append(gone, mac)
		}
	}
	sort.Strings(came)
	sort.Strings(gone)
	for _, mac := range gone {
		if p := e.prev[mac]; settled(mac + "|" + p.vap + "|-") {
			e.leave(mac, p, p.lastSeen)
			delete(e.prev, mac)
		}
	}
	for _, mac := range came {
		c := cur[mac]
		if !settled(mac + "|" + c.vap + "|+") {
			continue
		}
		if p, ok := e.prev[mac]; ok {
			e.leave(mac, p, p.lastSeen)
		}
		e.assoc(mac, c)
		e.prev[mac] = c
	}
	for k := range e.odd {
		if !odd[k] {
			delete(e.odd, k)
		}
	}
}

func (e *staEvents) leave(mac string, p staSeen, at int64) {
	e.push(map[string]any{
		"message_type": staTracker, "event_type": staEvLeave,
		"mac": mac, "vap": p.vap, "avg_rssi": p.signal, "last_seen": at,
		"assoc_status": e.leaveStatus(mac, e.at),
	})
}

func (e *staEvents) assoc(mac string, c staSeen) {
	e.push(map[string]any{
		"message_type": staTracker, "event_type": staEvAssoc,
		"mac": mac, "vap": c.vap, "auth_rssi": c.signal, "assoc_status": 0,
		"last_seen": c.lastSeen,
	})
}

// staVifNames maps this reading's BSS interfaces (wl12) to their vap_table
// names (wifi1ap1), through the BSSID both carry.
func staVifNames(s *apstate.Snapshot, f map[string]any) map[string]string {
	byBSSID := map[string]string{}
	vaps, _ := f["vap_table"].([]map[string]any)
	for _, v := range vaps {
		name, _ := v["name"].(string)
		b, _ := v["bssid"].(string)
		if name != "" && b != "" {
			byBSSID[strings.ToLower(b)] = name
		}
	}
	out := map[string]string{}
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			if n := byBSSID[strings.ToLower(v.BSSID)]; n != "" && v.Iface != "" && v.BSSID != "" {
				out[v.Iface] = n
			}
		}
	}
	return out
}

func (e *staEvents) push(ev map[string]any) {
	if len(e.queue) >= staQueueMax {
		start := 0
		if e.offered {
			start = 1 // never drop the one on the wire
		}
		if start < len(e.queue) {
			e.queue = append(e.queue[:start], e.queue[start+1:]...)
			e.dropped++
		}
	}
	e.queue = append(e.queue, ev)
}

// attach makes f the notification for the oldest queued event, unless f is
// already another notification (a spectrum event) or carries no event.
func (e *staEvents) attach(f map[string]any) {
	e.offered = false
	if len(e.queue) == 0 || f["inform_as_notif"] == true {
		return
	}
	f["inform_as_notif"] = true
	f["notif_reason"] = "event"
	f["notif_payload"] = e.queue[0]
	e.offered = true
}

// informed reports the inform's outcome: the offered event is done when
// the controller answered. It returns the event sent (nil when none) and
// whether more are waiting.
func (e *staEvents) informed(good bool) (sent map[string]any, more bool) {
	if e.offered && good {
		sent, e.queue = e.queue[0], e.queue[1:]
	}
	e.offered = false
	return sent, len(e.queue) > 0
}

// staSource is the hostapd socket monitor (hapdmon.Monitor).
type staSource interface {
	Take() ([]hapdmon.Event, int)
	Attached() map[string]time.Time
}

// startStaMonitor follows the station events on the control sockets of the
// agent's hostapd (takeover on the Deco: bcmwifi.CtrlDir, one socket per
// BSS it serves). The Garage runs no hostapd and keeps the reading diff.
func (a *agent) startStaMonitor(ctx context.Context) {
	if a.cfg.jio() {
		return
	}
	if a.o.staMon != nil {
		a.hapd = a.o.staMon
		return
	}
	m := hapdmon.New(hapdmon.Options{Dir: a.dev(bcmwifi.CtrlDir), LocalDir: a.dev(a.o.runDir),
		Want: bcmwifi.ServedVif, Logf: a.logf})
	a.hapd = m
	a.bg.Add(1)
	go func() { defer a.bg.Done(); m.Run(ctx) }()
}

// staFeed hands the socket events since the last reading to staEvents
// (loop goroutine).
func (a *agent) staFeed(s *apstate.Snapshot, f map[string]any) *staFeed {
	if a.hapd == nil {
		return nil
	}
	evs, dropped := a.hapd.Take()
	if dropped > 0 {
		a.logf("hostapd events: %d dropped (more than the monitor keeps)", dropped)
	}
	return &staFeed{read: a.readAt, now: time.Now(), since: a.hapd.Attached(), vifs: staVifNames(s, f), evs: evs}
}
