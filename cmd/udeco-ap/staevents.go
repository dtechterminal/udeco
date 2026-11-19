// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"sort"
	"strings"
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
// success/failure carry connection timings (assoc/auth/wpa/ip deltas) the
// agent does not measure; they are not sent rather than sent as zeros.
//
// A notification inform's stats are not processed (devmgr.l.mMObEXELV
// returns after the notification), so each event goes in an extra inform
// right after the reading that found it (immediateWait apart), never in
// place of the regular one, and one per inform.
const (
	staTracker  = "STA_ASSOC_TRACKER"
	staQueueMax = 64 // events waiting at most; older ones are dropped
	staEvLeave  = "sta_leave"
	staEvAssoc  = "association"
	staCarry    = 120 // s a vanished VAP's clients stay on record
)

type staSeen struct {
	vap      string
	signal   int
	lastSeen int64
}

type staEvents struct {
	prev    map[string]staSeen
	seeded  bool
	queue   []map[string]any
	offered bool // queue[0] rides the inform being sent
	dropped int
}

// observe diffs this reading's vap_table against the last one and queues
// the events. The first reading only seeds (clients already associated
// when the agent starts get no association event).
func (e *staEvents) observe(f map[string]any) {
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
	if !e.seeded {
		e.prev, e.seeded = cur, true
		return
	}
	// A client counts as gone from a VAP only while that VAP is still in
	// the reading: a VAP that vanished was renamed (the controller's
	// devnames after adoption or a new system_cfg) or is down for a moment
	// (an apply), and its clients are no events. Likewise a client found
	// on a new VAP whose old one vanished moved with the rename.
	var gone, came []string
	for mac, p := range e.prev {
		if c, ok := cur[mac]; (!ok || c.vap != p.vap) && names[p.vap] {
			gone = append(gone, mac)
		}
	}
	for mac, c := range cur {
		if p, ok := e.prev[mac]; !ok || p.vap != c.vap && names[p.vap] {
			came = append(came, mac)
		}
	}
	sort.Strings(gone)
	sort.Strings(came)
	for _, mac := range gone {
		p := e.prev[mac]
		e.push(map[string]any{
			"message_type": staTracker, "event_type": staEvLeave,
			"mac": mac, "vap": p.vap, "avg_rssi": p.signal, "last_seen": p.lastSeen,
		})
	}
	for _, mac := range came {
		c := cur[mac]
		e.push(map[string]any{
			"message_type": staTracker, "event_type": staEvAssoc,
			"mac": mac, "vap": c.vap, "auth_rssi": c.signal, "assoc_status": 0,
			"last_seen": c.lastSeen,
		})
	}
	// clients of a VAP missing from this reading stay on record for a
	// while, so the VAP's return is no wave of associations
	for mac, p := range e.prev {
		if _, ok := cur[mac]; !ok && !names[p.vap] && up-p.lastSeen < staCarry {
			cur[mac] = p
		}
	}
	e.prev = cur
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
