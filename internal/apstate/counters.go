// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

import (
	"encoding/json"
	"math"
	"strings"
)

// Counters keeps the byte and packet counters the inform reports monotonic,
// per reported key: per VAP name (vap_table rows), per station MAC
// (sta_table rows) and per if_table row (the uplink). docs/deco/agent-design.md
// §3.9 has the controller evidence; in short, the controller turns each
// counter into a delta against the last value it stored under the same key
// (a VAP's key is its name, not its interface), counts nothing when a value
// drops (it takes the lower value as the new base) and counts the whole rise
// when it climbs back. Two sources alternating under one key (two VAPs with
// one devname, an SSID moving to another vif, a TP-Link vif taking a
// position-based name, a station listed on two vifs) are therefore counted
// as the difference of their totals at every alternation: terabytes per day.
//
// Here every counter is read per source (a vif or port by name and
// interface index, a station by MAC, vif and association), only the
// source's own increase since its last reading is added to the total of the
// key it is reported under now, and the total is what the inform carries. A
// source moving to another key, a vif recreated by hostapd, a 32-bit driver
// counter wrapping and a station reassociating therefore all add only real
// traffic. Ambiguity is resolved towards counting less: a netdev first seen
// under a key that already has a total (an interface the agent did not read
// before) is a baseline and adds nothing.
//
// The state (Counters marshals to JSON) is kept in the agent's RAM run dir,
// so totals survive an agent restart; a reboot clears it, as it clears a
// real AP's counters. Its clock is the unit's uptime (Snapshot.Uptime), so a
// wall-clock step never looks like a gap.
//
// Not safe for concurrent use: the agent's loop goroutine owns it.
type Counters struct {
	Src map[string]*ctrSource `json:"src"` // source -> its last raw reading
	Acc map[string]*ctrTotal  `json:"acc"` // reported key -> totals
	// Ifindex reads a netdev's interface index (0 = unknown). nil: unknown,
	// so a recreated interface is only seen by its counters dropping.
	Ifindex func(dev string) int64 `json:"-"`

	now   int64 // uptime seconds of the reading in progress
	dirty bool
	// urgent: the reading changed the state in a way a restart from an
	// older state would not repeat (a source or key first seen, a reset,
	// a wrap, a new association): persist it now, not within counterEvery,
	// or the restarted agent's totals could fall below what it reported.
	urgent bool
}

type ctrSource struct {
	ID   int64             `json:"id,omitempty"` // netdev ifindex (a station: its vif's)
	Up   int64             `json:"up,omitempty"` // station: seconds associated at the last reading
	Raw  map[string]uint64 `json:"raw"`
	Seen int64             `json:"seen"` // uptime seconds
}

type ctrTotal struct {
	V    map[string]uint64 `json:"v"`
	Seen int64             `json:"seen"`
}

// Retention, in uptime seconds. Forgetting is always safe for a netdev (it
// comes back as a baseline); a station source must outlive the gaps in
// which it is associated but not read (its VAP briefly not user-facing).
const (
	ctrStaSourceTTL = 3600
	ctrStaTotalTTL  = 86400
	ctrOtherTTL     = 7 * 86400
	ctrStaleSlack   = 60
)

// Fields of the counters, per kind of row.
var (
	// VAPNetdevFields are the vif's /sys/class/net statistics a vap_table
	// row carries.
	VAPNetdevFields = []string{"rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"}
	// IfFields are the if_table row's counters.
	IfFields = []string{"rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped", "rx_multicast"}
)

// NewCounters returns an empty state.
func NewCounters() *Counters {
	return &Counters{Src: map[string]*ctrSource{}, Acc: map[string]*ctrTotal{}}
}

// LoadCounters reads a state written by Marshal. Anything unreadable gives
// an empty state (the next reading is a baseline), never an error.
func LoadCounters(b []byte) *Counters {
	c := NewCounters()
	if len(b) == 0 || json.Unmarshal(b, c) != nil {
		return NewCounters()
	}
	if c.Src == nil {
		c.Src = map[string]*ctrSource{}
	}
	if c.Acc == nil {
		c.Acc = map[string]*ctrTotal{}
	}
	for k, s := range c.Src {
		if s == nil || s.Raw == nil {
			delete(c.Src, k)
		}
	}
	for k, t := range c.Acc {
		if t == nil || t.V == nil {
			delete(c.Acc, k)
		}
	}
	return c
}

// Marshal is the state to persist.
func (c *Counters) Marshal() ([]byte, error) { return json.Marshal(c) }

// Dirty reports whether a reading changed the state since the last
// ClearDirty.
func (c *Counters) Dirty() bool { return c.dirty }

// Urgent reports whether the state changed since the last ClearDirty in a
// way that should be persisted at once (see Counters.urgent).
func (c *Counters) Urgent() bool { return c.dirty && c.urgent }

// ClearDirty marks the state as persisted.
func (c *Counters) ClearDirty() { c.dirty, c.urgent = false, false }

// Begin starts a reading at uptime seconds: it forgets what has not been
// seen for long, and a state from another boot (seen "later" than now)
// entirely.
func (c *Counters) Begin(uptime int64) {
	c.now = uptime
	if uptime <= 0 {
		return
	}
	for _, s := range c.Src {
		if s.Seen > uptime+ctrStaleSlack {
			c.Src, c.Acc, c.dirty = map[string]*ctrSource{}, map[string]*ctrTotal{}, true
			return
		}
	}
	for k, s := range c.Src {
		ttl := int64(ctrOtherTTL)
		if strings.HasPrefix(k, "sta:") {
			ttl = ctrStaSourceTTL
		}
		if uptime-s.Seen > ttl {
			delete(c.Src, k)
			c.dirty = true
		}
	}
	for k, t := range c.Acc {
		ttl := int64(ctrOtherTTL)
		if strings.HasPrefix(k, "sta:") {
			ttl = ctrStaTotalTTL
		}
		if uptime-t.Seen > ttl {
			delete(c.Acc, k)
			c.dirty = true
		}
	}
}

func (c *Counters) ifindex(dev string) int64 {
	if c.Ifindex == nil || dev == "" {
		return 0
	}
	return c.Ifindex(dev)
}

func u64(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// increase is one counter's rise from p to r on the same source. With wrap
// a drop is a 32-bit wrap when p fits 32 bits (the Broadcom driver keeps
// net_device_stats, unsigned long on this armv7 kernel), otherwise, and
// always without wrap, a reset to zero: r is new traffic. A reset read as a
// wrap would add up to 4 GiB of traffic that never was, so wrap is only
// allowed where a reset cannot hide behind the drop (step).
func increase(p, r uint64, wrap bool) uint64 {
	switch {
	case r >= p:
		return r - p
	case wrap && p <= math.MaxUint32:
		return r + (1 << 32) - p
	default:
		return r
	}
}

// step reads one source and returns how much each field rose since its last
// reading. fresh: the counters started from zero since that reading (all of
// raw is new traffic); have: the source was read before. netdev: a
// netdev's counters, whose drop may be a 32-bit wrap, but only while its
// identity is confirmed (the same interface index as at the last reading,
// or no index reader at all): a vif whose index was not readable (being
// recreated) may be a new instance. A station's drop is always a reset: a
// reassociation the "in network" time did not reveal (wl sta_info's byte
// counters are 64-bit and its packet counters do not wrap within one
// association in practice).
func (c *Counters) step(src string, id, up int64, raw map[string]int64, fresh, netdev bool) (d map[string]uint64, have bool) {
	prev := c.Src[src]
	have = prev != nil
	if have && id != 0 && prev.ID != 0 && id != prev.ID {
		fresh = true // another instance of the interface: its counters started at 0
	}
	wrap := netdev && (c.Ifindex == nil || have && id != 0 && id == prev.ID)
	d = make(map[string]uint64, len(raw))
	cur := make(map[string]uint64, len(raw))
	for k, v := range raw {
		r := u64(v)
		cur[k] = r
		switch {
		case fresh:
			d[k] = r
		case have:
			if p, ok := prev.Raw[k]; ok {
				d[k] = increase(p, r, wrap)
				if r < p {
					c.urgent = true // a reset or wrap: not path-independent
				}
			}
		}
	}
	if !have || fresh {
		c.urgent = true
	}
	c.Src[src] = &ctrSource{ID: id, Up: up, Raw: cur, Seen: c.now}
	c.dirty = true
	return d, have
}

// total adds d to key's totals and returns them. init: the key has no
// totals yet and this is its first source: start from raw (what a real AP
// would report) rather than from zero.
func (c *Counters) total(key string, d map[string]uint64) *ctrTotal {
	t := c.Acc[key]
	if t == nil {
		t = &ctrTotal{V: map[string]uint64{}}
		c.Acc[key] = t
		c.urgent = true
	}
	for k, v := range d {
		t.V[k] += v
	}
	t.Seen = c.now
	c.dirty = true
	return t
}

func (t *ctrTotal) get(k string) int64 {
	v := t.V[k]
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// Netdev reports the counters of the netdev dev under key: the key's totals,
// grown by dev's own increase since its last reading. A netdev not read
// before is a baseline (it adds nothing) unless the key is new too, which
// then starts from dev's values.
func (c *Counters) Netdev(key, dev string, raw map[string]int64) map[string]int64 {
	src := "dev:" + dev
	_, newKey := c.Acc[key]
	newKey = !newKey
	d, have := c.step(src, c.ifindex(dev), 0, raw, false, true)
	if !have && newKey {
		for k, v := range raw {
			d[k] = u64(v)
		}
	}
	t := c.total(key, d)
	out := make(map[string]int64, len(raw))
	for k := range raw {
		out[k] = t.get(k)
	}
	return out
}

// staFields are a station's counters (sta_table) plus the failures the VAP
// row sums.
func staRaw(st Station) map[string]int64 {
	return map[string]int64{
		"tx_bytes": st.TxBytes, "rx_bytes": st.RxBytes, "tx_packets": st.TxPackets, "rx_packets": st.RxPackets,
		"tx_retries": st.TxRetries, "tx_failed": st.TxFailed,
	}
}

// vapCounters is what a vap_table row reports: the vif's netdev counters
// and the sums over its stations, all monotonic per VAP name.
type vapCounters struct {
	Netdev   map[string]int64
	Retries  int64 // tx_retries / tx_combined_retries
	Failed   int64 // wifi_tx_dropped
	TxPkts   int64 // tx_total
	Success  int64 // tx_success
	Stations []map[string]int64
}

// vap reads one VAP (iface, reported as name) and its stations.
func (c *Counters) vap(name, iface string, stats map[string]int64, stas []Station) vapCounters {
	key := "vap:" + name
	raw := make(map[string]int64, len(VAPNetdevFields))
	for _, k := range VAPNetdevFields {
		raw[k] = stats[k]
	}
	out := vapCounters{Netdev: c.Netdev(key, iface, raw)}
	vid := c.ifindex(iface)
	var dRetries, dFailed, dTx, dSuccess uint64
	for _, st := range stas {
		mac := strings.ToLower(st.MAC)
		r := staRaw(st)
		// A station source is one association on one vif: a station not
		// read before, one whose association is younger than the last
		// reading (or its vif recreated) has counters that started at 0.
		src := "sta:" + mac + "@" + iface
		// ("in network" seconds; a station whose time never reads is judged
		// by its counters alone).
		fresh := false
		if p := c.Src[src]; p == nil {
			fresh = true
		} else if st.Connected > 0 || p.Up > 0 {
			fresh = st.Connected < p.Up || st.Connected > 0 && c.now > 0 && p.Seen > 0 && st.Connected+5 < c.now-p.Seen
		}
		d, _ := c.step(src, vid, st.Connected, r, fresh, false)
		dRetries += d["tx_retries"]
		dFailed += d["tx_failed"]
		dTx += d["tx_packets"]
		if d["tx_packets"] > d["tx_failed"] {
			dSuccess += d["tx_packets"] - d["tx_failed"]
		}
		// the station's own success count (tx_packets less failures) is
		// accumulated as its own monotonic key
		ds := map[string]uint64{"tx_success": 0}
		for k, v := range d {
			ds[k] = v
		}
		if d["tx_packets"] > d["tx_failed"] {
			ds["tx_success"] = d["tx_packets"] - d["tx_failed"]
		}
		t := c.total("sta:"+mac, ds)
		out.Stations = append(out.Stations, map[string]int64{
			"tx_bytes": t.get("tx_bytes"), "rx_bytes": t.get("rx_bytes"),
			"tx_packets": t.get("tx_packets"), "rx_packets": t.get("rx_packets"),
			"tx_retries": t.get("tx_retries"), "tx_failed": t.get("tx_failed"), "tx_success": t.get("tx_success"),
		})
	}
	t := c.total(key, map[string]uint64{"sta_retries": dRetries, "sta_failed": dFailed, "sta_tx": dTx, "sta_success": dSuccess})
	out.Retries, out.Failed, out.TxPkts, out.Success = t.get("sta_retries"), t.get("sta_failed"), t.get("sta_tx"), t.get("sta_success")
	return out
}

// rawVAPCounters is vapCounters as read (no Counters): the netdev
// statistics and the sums over the stations associated now.
func rawVAPCounters(v Radio) vapCounters {
	out := vapCounters{Netdev: map[string]int64{}}
	for _, k := range VAPNetdevFields {
		out.Netdev[k] = v.Stats[k]
	}
	for _, st := range v.Stations {
		out.Retries += st.TxRetries
		out.Failed += st.TxFailed
		out.TxPkts += st.TxPackets
		out.Stations = append(out.Stations, map[string]int64{
			"tx_bytes": st.TxBytes, "rx_bytes": st.RxBytes, "tx_packets": st.TxPackets, "rx_packets": st.RxPackets,
			"tx_retries": st.TxRetries, "tx_failed": st.TxFailed, "tx_success": max(st.TxPackets-st.TxFailed, 0),
		})
	}
	out.Success = max(out.TxPkts-out.Failed, 0)
	return out
}

// finish gives every user vap_table row, and every station row, the totals
// of its name (MAC) after the whole reading, so rows that share a name in
// one inform agree (the controller would otherwise see the later row's
// value rise within the inform).
func (c *Counters) finish(vaps []map[string]any) {
	for _, row := range vaps {
		if row["usage"] != "user" {
			continue
		}
		name, _ := row["name"].(string)
		if t := c.Acc["vap:"+name]; t != nil {
			for _, k := range VAPNetdevFields {
				row[k] = t.get(k)
			}
			if _, ok := row["wifi_tx_attempts"]; ok { // absent: no TX counters (Radio.NoTxCounters)
				r, tx := t.get("sta_retries"), t.get("sta_tx")
				row["tx_retries"], row["tx_combined_retries"] = r, r
				row["wifi_tx_attempts"], row["wifi_tx_dropped"] = tx+r, t.get("sta_failed")
				row["tx_total"], row["tx_success"] = tx, t.get("sta_success")
			}
		}
		stas, _ := row["sta_table"].([]map[string]any)
		for _, st := range stas {
			mac, _ := st["mac"].(string)
			if t := c.Acc["sta:"+strings.ToLower(mac)]; t != nil {
				for _, k := range []string{"tx_bytes", "rx_bytes", "tx_packets", "rx_packets"} {
					st[k] = t.get(k)
				}
				if _, ok := st["wifi_tx_attempts"]; ok { // absent: no TX counters
					staRetryFields(st, t.get("tx_packets"), t.get("tx_retries"), t.get("tx_failed"), t.get("tx_success"))
				}
			}
		}
	}
}

// staRetryFields sets a sta_table row's transmit attempt counters the way a
// real UniFi AP reports them (docs/reference mca-dump): the controller's
// per-client "TX retries" percentage is retries over wifi_tx_attempts, and
// without wifi_tx_attempts it read 100% for any client with a retry and 0%
// otherwise (2026-11-19).
func staRetryFields(row map[string]any, pkts, retries, failed, success int64) {
	row["tx_retries"], row["tx_combined_retries"] = retries, retries
	row["wifi_tx_attempts"], row["wifi_tx_dropped"] = pkts+retries, failed
	row["tx_total"], row["wifi_tx_success"] = pkts, success
}
