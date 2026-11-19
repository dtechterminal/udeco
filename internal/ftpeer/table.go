// SPDX-License-Identifier: GPL-2.0-or-later

package ftpeer

import (
	"sort"
	"time"
)

// Verdict is what Receive did with a frame.
type Verdict int

// Verdicts. Everything but Accepted leaves the table as it was.
const (
	Accepted    Verdict = iota
	NotOurs             // not an announcement frame (EtherType/group/magic)
	Own                 // sent by this unit
	RateLimited         // over the per-source or global rate
	Malformed           // bad layout or holder
	UnknownKey          // a key this unit does not serve on that bridge
	AuthFailed          // HMAC wrong
	Replayed            // not newer than the last frame of that unit and key
)

var verdictNames = [...]string{"accepted", "not ours", "own", "rate limited", "malformed", "unknown key", "auth failed", "replayed"}

func (v Verdict) String() string {
	if int(v) < len(verdictNames) {
		return verdictNames[v]
	}
	return "?"
}

// Rate limits: each source may send a burst of srcBurst frames and srcRate
// per second after that; all sources together globalBurst / globalRate.
// One unit sends one frame per WLAN per bridge every interval, plus one
// answer when it hears a unit it did not know.
const (
	srcRate     = 2.0
	srcBurst    = 12.0
	globalRate  = 30.0
	globalBurst = 60.0
	maxSources  = 128 // rate-limit buckets kept (more: all reset, the global bucket still holds)
	maxEntries  = 256 // (unit, key, bridge) entries kept
)

type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) take(now time.Time, rate, burst float64) bool {
	if b.last.IsZero() {
		b.tokens = burst
	} else if dt := now.Sub(b.last).Seconds(); dt > 0 {
		b.tokens = min(burst, b.tokens+dt*rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type entryKey struct{ unit, keyID, bridge string }

type entry struct {
	holders []Holder
	seen    time.Time
}

type replayKey struct{ unit, keyID string }

type counter struct {
	epoch, seq uint64
	seen       time.Time
}

// Table holds the peers learnt from announcements. It is not safe for
// concurrent use (Service locks it).
type Table struct {
	own     string        // this unit's MAC: its frames are ignored
	ttl     time.Duration // a peer not re-announced for this long is dropped
	entries map[entryKey]*entry
	replay  map[replayKey]counter
	src     map[string]*bucket
	global  bucket
	stats   map[Verdict]uint64
}

// NewTable returns an empty table for unit own, whose peers expire after
// ttl.
func NewTable(own string, ttl time.Duration) *Table {
	return &Table{own: NormMAC(own), ttl: ttl, entries: map[entryKey]*entry{}, replay: map[replayKey]counter{},
		src: map[string]*bucket{}, stats: map[Verdict]uint64{}}
}

// Receive handles one Ethernet frame heard on bridge. keys are the WLAN
// keys this unit serves FT-SAE with on that bridge, by KeyID. changed
// reports that the peer set changed (a holder added, changed or
// withdrawn); unit is the frame's unit once it parsed.
func (t *Table) Receive(bridge string, frame []byte, keys map[string]string, now time.Time) (v Verdict, changed bool, unit string) {
	v, changed, unit = t.receive(bridge, frame, keys, now)
	t.stats[v]++
	return v, changed, unit
}

func (t *Table) receive(bridge string, frame []byte, keys map[string]string, now time.Time) (Verdict, bool, string) {
	src, p, ok := unframe(frame)
	if !ok || len(p) < 4 || string(p[:4]) != magic {
		return NotOurs, false, ""
	}
	if src == t.own {
		return Own, false, ""
	}
	// Rate limits before any cryptography: a flood costs a map lookup.
	if !t.global.take(now, globalRate, globalBurst) {
		return RateLimited, false, ""
	}
	b := t.src[src]
	if b == nil {
		if len(t.src) >= maxSources {
			t.src = map[string]*bucket{}
		}
		b = &bucket{}
		t.src[src] = b
	}
	if !b.take(now, srcRate, srcBurst) {
		return RateLimited, false, ""
	}
	a, err := Parse(p)
	if err != nil {
		return Malformed, false, ""
	}
	if a.Unit == t.own {
		return Own, false, ""
	}
	if a.Unit != src {
		// Bridges do not rewrite the source: a frame relayed under another
		// address is not what this protocol sends.
		return Malformed, false, ""
	}
	key, ok := keys[a.KeyID]
	if !ok {
		return UnknownKey, false, a.Unit
	}
	if !Verify(p, key) {
		return AuthFailed, false, a.Unit
	}
	rk := replayKey{a.Unit, a.KeyID}
	if c, ok := t.replay[rk]; ok && (a.Epoch < c.epoch || a.Epoch == c.epoch && a.Seq <= c.seq) {
		return Replayed, false, a.Unit
	}
	t.replay[rk] = counter{epoch: a.Epoch, seq: a.Seq, seen: now}
	ek := entryKey{a.Unit, a.KeyID, bridge}
	hs := append([]Holder(nil), a.Holders...)
	sortHolders(hs)
	old := t.entries[ek]
	if len(hs) == 0 {
		if old != nil {
			delete(t.entries, ek)
			return Accepted, true, a.Unit
		}
		return Accepted, false, a.Unit
	}
	if old == nil && len(t.entries) >= maxEntries {
		return RateLimited, false, a.Unit
	}
	changed := old == nil || !sameHolders(old.holders, hs)
	t.entries[ek] = &entry{holders: hs, seen: now}
	return Accepted, changed, a.Unit
}

func sameHolders(x, y []Holder) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// Expire drops the entries not re-announced within the TTL, and the
// replay counters of units heard from under no key for a TTL (so a unit
// that rebooted with its clock behind is accepted again once its old
// entries are gone). changed reports that peers were dropped.
func (t *Table) Expire(now time.Time) (changed bool) {
	for k, e := range t.entries {
		if now.Sub(e.seen) > t.ttl {
			delete(t.entries, k)
			changed = true
		}
	}
	for k, c := range t.replay {
		if now.Sub(c.seen) > t.ttl {
			delete(t.replay, k)
		}
	}
	for s, b := range t.src {
		if now.Sub(b.last) > t.ttl {
			delete(t.src, s)
		}
	}
	return changed
}

// Forget drops what was learnt on bridge (this unit no longer serves an
// FT-SAE BSS there). changed reports that peers were dropped.
func (t *Table) Forget(bridge string, keep func(keyID string) bool) (changed bool) {
	for k := range t.entries {
		if k.bridge == bridge && (keep == nil || !keep(k.keyID)) {
			delete(t.entries, k)
			changed = true
		}
	}
	return changed
}

// Peers returns the current peers, sorted by bridge, key id, BSSID.
func (t *Table) Peers() []Peer {
	var out []Peer
	for k, e := range t.entries {
		for _, h := range e.holders {
			out = append(out, Peer{Holder: h, KeyID: k.keyID, Unit: k.unit, Bridge: k.bridge, Seen: e.seen})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if x.Bridge != y.Bridge {
			return x.Bridge < y.Bridge
		}
		if x.KeyID != y.KeyID {
			return x.KeyID < y.KeyID
		}
		if x.BSSID != y.BSSID {
			return x.BSSID < y.BSSID
		}
		return x.Unit < y.Unit
	})
	return out
}

// Stats returns how many frames got each verdict.
func (t *Table) Stats() map[Verdict]uint64 {
	out := map[Verdict]uint64{}
	for k, v := range t.stats {
		out[k] = v
	}
	return out
}
