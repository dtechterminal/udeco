// SPDX-License-Identifier: GPL-2.0-or-later

package jioports

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Link is a port's link as the switch reports it.
type Link struct {
	Up         bool
	Speed      int // Mbit/s, 0 when down
	FullDuplex bool
}

var (
	gswLineRE  = regexp.MustCompile(`^Port\s*(\d+)\s*:\s*(.*)$`)
	gswSpeedRE = regexp.MustCompile(`^(\d+)M/(Full|Half)`)
)

// ReadLinks reads the link of the unit's ports 1-4 from the switch driver:
// /proc/tc3162/gsw_link_st ("Port1 : 1000M/Full Duplex", "Port2 : Down";
// the switch port numbers mapped to the labels by eth_portmap's
// lan_port_map), falling back to eth_port_status ("1 0 0 1", up only) when
// gsw_link_st is missing. A port missing from both is down.
func ReadLinks(root string) map[int]Link {
	read := func(p string) string {
		b, _ := os.ReadFile(filepath.Join(root, p))
		return string(b)
	}
	out := map[int]Link{}
	labelOf := lanPortMap(read("/proc/tc3162/eth_portmap"))
	if gsw := read("/proc/tc3162/gsw_link_st"); gsw != "" {
		for _, line := range strings.Split(gsw, "\n") {
			m := gswLineRE.FindStringSubmatch(strings.TrimSpace(line))
			if m == nil {
				continue
			}
			sw, _ := strconv.Atoi(m[1])
			label, ok := labelOf[sw]
			if !ok {
				continue
			}
			l := Link{}
			if s := gswSpeedRE.FindStringSubmatch(m[2]); s != nil {
				l.Up = true
				l.Speed, _ = strconv.Atoi(s[1])
				l.FullDuplex = s[2] == "Full"
			}
			out[label] = l
		}
		return out
	}
	for i, f := range strings.Fields(read("/proc/tc3162/eth_port_status")) {
		if i < 4 {
			out[i+1] = Link{Up: f == "1"}
		}
	}
	return out
}

// lanPortMap maps a switch port number to the unit's port label (1-4)
// from eth_portmap's lan_port_map block ("<lan index> <switch port>",
// index 0 = label 1). Without the block the switch ports 1-4 are the
// labels 1-4 (the JCOW414's map, read 2026-11-19).
func lanPortMap(s string) map[int]int {
	out := map[int]int{}
	in := false
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "lan_port_map":
			in = true
			continue
		case strings.HasSuffix(line, "_map") || strings.HasSuffix(line, ":"):
			in = false
			continue
		}
		f := strings.Fields(line)
		if !in || len(f) != 2 {
			continue
		}
		lan, err1 := strconv.Atoi(f[0])
		sw, err2 := strconv.Atoi(f[1])
		if err1 == nil && err2 == nil && sw >= 0 && lan >= 0 && lan < 4 {
			out[sw] = lan + 1
		}
	}
	if len(out) == 0 {
		for p := 1; p <= 4; p++ {
			out[p] = p
		}
	}
	return out
}

// Stats are a port's counters.
type Stats struct {
	RxBytes, TxBytes, RxPkts, TxPkts         int64
	RxErrors, TxErrors, RxDropped, TxDropped int64
	RxMulticast                              int64
}

var statFiles = []string{"rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped", "multicast"}

// Counters makes the ports' counters monotonic. A port's traffic is the
// sum over its VLAN devices (eth0.P.1 and eth0.P.N: the switch netdev
// eth0.P has 32-bit counters that wrap); a device that appears adds from
// zero, one that goes away stops adding, and a device whose counters went
// back (recreated) adds from its new value.
type Counters struct {
	last  map[string][]int64 // device -> last raw values
	total map[int][]int64    // port -> monotonic sums
}

// NewCounters returns empty counters.
func NewCounters() *Counters {
	return &Counters{last: map[string][]int64{}, total: map[int][]int64{}}
}

var devRE = regexp.MustCompile(`^eth0\.([1-4])\.([0-9]+)$`)

// Read adds what each port's devices counted since the last Read.
func (c *Counters) Read(root string) map[int]Stats {
	ents, _ := os.ReadDir(filepath.Join(root, "/sys/class/net"))
	seen := map[string]bool{}
	for _, e := range ents {
		m := devRE.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		port, _ := strconv.Atoi(m[1])
		raw := make([]int64, len(statFiles))
		for i, f := range statFiles {
			b, _ := os.ReadFile(filepath.Join(root, "/sys/class/net", e.Name(), "statistics", f))
			v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
			raw[i] = int64(v)
		}
		seen[e.Name()] = true
		t := c.total[port]
		if t == nil {
			t = make([]int64, len(statFiles))
			c.total[port] = t
		}
		prev, ok := c.last[e.Name()]
		for i, v := range raw {
			switch {
			case !ok, v < prev[i]:
				t[i] += v
			default:
				t[i] += v - prev[i]
			}
		}
		c.last[e.Name()] = raw
	}
	for d := range c.last {
		if !seen[d] {
			delete(c.last, d)
		}
	}
	out := map[int]Stats{}
	for p, t := range c.total {
		out[p] = Stats{RxBytes: t[0], TxBytes: t[1], RxPkts: t[2], TxPkts: t[3], RxErrors: t[4], TxErrors: t[5],
			RxDropped: t[6], TxDropped: t[7], RxMulticast: t[8]}
	}
	return out
}

// RowsInput is what the port_table is built from.
type RowsInput struct {
	Links map[int]Link  // by unit port
	Stats map[int]Stats // by unit port
	// MACs: the wired clients behind a unit port (its bdg2 FDB entries,
	// apstate.Snapshot.PortMACs); nil = none.
	MACs map[int][]map[string]any
	// Locked reports whether the controller may not change a unit port.
	Locked func(phys int) bool
}

// Rows is the inform's port_table for the UHDIW numbering: front ports 1-3
// (the unit's ports 1-3), port 4 (absent on the unit: down, not editable)
// and the rear uplink port 5 (the unit's port 4). The uplink and the
// locked ports carry attr_no_edit, which the controller copies into the
// device's port_table: it then refuses a port override for them
// (PORT_NOT_EDITABLE) and writes no switch.port lines for them, so the
// panel cannot promise a setting the agent will not apply.
func Rows(in RowsInput) []map[string]any {
	locked := in.Locked
	if locked == nil {
		locked = func(p int) bool { return p == UplinkPhys }
	}
	var rows []map[string]any
	for idx := 1; idx <= NumPorts; idx++ {
		phys := Phys(idx)
		name := "Port " + strconv.Itoa(idx)
		if idx == UplinkIdx {
			name = "PoE In + Data"
		}
		row := map[string]any{
			"port_idx": idx, "name": name, "media": "GE",
			"poe_caps": 0, "port_poe": false, "speed_caps": 1048623, // 10/100/1000, autoneg
			"enable": true, "autoneg": true, "op_mode": "switch",
			"up": false, "speed": 0, "full_duplex": false, "is_uplink": idx == UplinkIdx,
			"rx_bytes": int64(0), "tx_bytes": int64(0), "rx_packets": int64(0), "tx_packets": int64(0),
			"rx_errors": int64(0), "tx_errors": int64(0), "rx_dropped": int64(0), "tx_dropped": int64(0),
			"rx_multicast": int64(0),
			"attr_no_edit": phys == 0 || locked(phys),
		}
		if phys == 0 {
			rows = append(rows, row)
			continue
		}
		row["ifname"] = Parent(phys)
		if l := in.Links[phys]; l.Up {
			row["up"], row["speed"], row["full_duplex"] = true, l.Speed, l.FullDuplex
		}
		if s, ok := in.Stats[phys]; ok {
			row["rx_bytes"], row["tx_bytes"], row["rx_packets"], row["tx_packets"] = s.RxBytes, s.TxBytes, s.RxPkts, s.TxPkts
			row["rx_errors"], row["tx_errors"], row["rx_dropped"], row["tx_dropped"] = s.RxErrors, s.TxErrors, s.RxDropped, s.TxDropped
			row["rx_multicast"] = s.RxMulticast
		}
		if idx != UplinkIdx {
			macs := in.MACs[phys]
			if macs == nil {
				macs = []map[string]any{}
			}
			row["mac_table"] = macs
		}
		rows = append(rows, row)
	}
	return rows
}
