// SPDX-License-Identifier: GPL-2.0-or-later

package jioports

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/models"
)

func parse(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			m[k] = v
		}
	}
	return m
}

// vlanList is the controller's VLAN list for the home site: the LAN, then
// Cameras (2) and Olive (3).
const vlanList = `
switch.status=enabled
switch.vlan.status=enabled
switch.jumboframes=disabled
switch.vlan.1.id=1
switch.vlan.1.mode=untagged
switch.vlan.1.status=enabled
switch.vlan.2.id=2
switch.vlan.2.mode=tagged
switch.vlan.2.status=enabled
switch.vlan.3.id=3
switch.vlan.3.mode=tagged
switch.vlan.3.status=enabled
switch.port.1.name=Port 1
switch.port.1.opmode=switch
switch.port.2.name=Port 2
switch.port.2.opmode=switch
switch.port.3.name=Port 3
switch.port.3.opmode=switch
`

func TestFromCfg(t *testing.T) {
	// Enable Port VLAN off: only the port names; a disabled port is
	// still honoured
	w, notes := FromCfg(parse("switch.status=disabled\nswitch.port.1.name=Port 1\nswitch.port.1.opmode=switch\nswitch.port.3.status=disabled"))
	if w.VLAN || len(w.Ports) != 1 || !w.Port(3).Disabled || !w.Port(1).Default() || len(notes) != 0 {
		t.Errorf("VLAN off: %+v %q", w, notes)
	}

	// port 1 on "all": no per-port lines, every VLAN as its own mode;
	// port 2 "native" Cameras; port 3 "customize": native Olive, Cameras
	// tagged, LAN excluded
	w, notes = FromCfg(parse(vlanList + `
switch.port.2.pvid=2
switch.vlan.1.port.2.mode=exclude
switch.vlan.2.port.2.mode=untagged
switch.vlan.3.port.2.mode=exclude
switch.port.3.pvid=3
switch.vlan.1.port.3.mode=exclude
switch.vlan.2.port.3.mode=tagged
switch.vlan.3.port.3.mode=untagged
`))
	want := map[int]PortWant{1: {Tagged: []int{2, 3}}, 2: {Native: 2}, 3: {Native: 3, Tagged: []int{2}}}
	if !w.VLAN || !reflect.DeepEqual(w.Ports, want) || len(notes) != 0 {
		t.Errorf("ports %+v, want %+v; notes %q", w.Ports, want, notes)
	}

	// customize with no native VLAN: the LAN excluded and nothing
	// untagged; native LAN explicitly: the LAN untagged
	w, _ = FromCfg(parse(vlanList + `
switch.vlan.1.port.2.mode=exclude
switch.vlan.2.port.2.mode=tagged
switch.vlan.3.port.2.mode=exclude
switch.vlan.1.port.3.mode=untagged
switch.vlan.2.port.3.mode=exclude
switch.vlan.3.port.3.mode=tagged
`))
	if p := w.Port(2); p.Native != -1 || !reflect.DeepEqual(p.Tagged, []int{2}) || p.String() != "native none, tagged 2" {
		t.Errorf("port 2 %+v (%s)", p, p)
	}
	if p := w.Port(3); p.Native != 0 || !reflect.DeepEqual(p.Tagged, []int{3}) {
		t.Errorf("port 3 %+v", p)
	}

	// a native VLAN missing from the list comes from pvid; VLAN 1 tagged
	// cannot be done; bad ids and odd op modes are reported
	w, notes = FromCfg(parse(`
switch.status=enabled
switch.vlan.status=enabled
switch.vlan.1.id=1
switch.vlan.1.mode=tagged
switch.vlan.2.id=9999
switch.port.2.pvid=20
switch.port.2.opmode=mirror
switch.port.2.speed=100
`))
	if p := w.Port(2); p.Native != 20 || len(p.Tagged) != 0 {
		t.Errorf("port 2 %+v", p)
	}
	j := strings.Join(notes, "\n")
	for _, s := range []string{"VLAN 1 tagged is not supported", "VLAN id 9999 left out", `op mode "mirror"`, "speed is not applied"} {
		if !strings.Contains(j, s) {
			t.Errorf("note %q missing in %q", s, notes)
		}
	}
	if (PortWant{Disabled: true}).VLANs() != nil || len((PortWant{Native: 3, Tagged: []int{5}}).VLANs()) != 2 {
		t.Errorf("VLANs")
	}
}

func TestLayout(t *testing.T) {
	for phys, idx := range map[int]int{1: 1, 2: 2, 3: 3, 4: 5, 5: 0, 0: 0} {
		if Idx(phys) != idx {
			t.Errorf("Idx(%d) = %d, want %d", phys, Idx(phys), idx)
		}
		if idx != 0 && Phys(idx) != phys {
			t.Errorf("Phys(%d) = %d, want %d", idx, Phys(idx), phys)
		}
	}
	if Phys(MissingIdx) != 0 || Untagged(2) != "eth0.2.1" || Parent(4) != "eth0.4" {
		t.Errorf("layout")
	}
}

// The layout against the model table and against itself: the uplink's
// UniFi port is the UAP-IW-HD's rear uplink jack as internal/models has it
// (the profile's switch bits and the reported uplink follow that one), and
// LANPorts, which Idx, Phys and the agent's ports_unlocked check read, are
// in order without a gap (the check's message names them as a range), each
// under its own number in UniFi, the uplink and the missing port not among
// them.
func TestLayoutAndTheModel(t *testing.T) {
	m, ok := models.Lookup(models.ModelUHDIW)
	if !ok || m.RearUplinkPort() != UplinkIdx {
		t.Errorf("UplinkIdx %d, models: %s rear uplink port %d (found %v)", UplinkIdx, models.ModelUHDIW, m.RearUplinkPort(), ok)
	}
	if len(LANPorts) == 0 {
		t.Fatal("no LAN ports")
	}
	for i, p := range LANPorts {
		if p != LANPorts[0]+i {
			t.Errorf("LANPorts %v: not in order without a gap", LANPorts)
		}
		if Idx(p) != p || Phys(p) != p {
			t.Errorf("LAN port %d: Idx %d, Phys %d", p, Idx(p), Phys(p))
		}
	}
	if slices.Contains(LANPorts, UplinkPhys) || slices.Contains(LANPorts, MissingIdx) || slices.Contains(LANPorts, UplinkIdx) {
		t.Errorf("LANPorts %v has the uplink (port %d, UniFi %d) or the missing UniFi port %d", LANPorts, UplinkPhys, UplinkIdx, MissingIdx)
	}
	// nothing else maps: every other number is no port
	for n := -1; n <= NumPorts+2; n++ {
		if !slices.Contains(LANPorts, n) && n != UplinkPhys && Idx(n) != 0 {
			t.Errorf("Idx(%d) = %d", n, Idx(n))
		}
		if !slices.Contains(LANPorts, n) && n != UplinkIdx && Phys(n) != 0 {
			t.Errorf("Phys(%d) = %d", n, Phys(n))
		}
	}
}

// the Garage AP's switch, read 2026-11-19
const (
	gswLinkSt = `
Internal switch:
Port0 : invalid(10G)/Full Duplex FC: RX EEE100 EEE1G
Port1 : 1000M/Full Duplex
Port2 : Down
Port3 : Down
Port4 : 100M/Full Duplex EEE100
Port5 : invalid(10G)/Full Duplex FC: RX EEE100 EEE1G
Port6 : 1000M/Full Duplex
`
	ethPortmap = `-1
use_soc_lanport:
-1
lan_port_map
0 1
1 2
2 3
3 4
4 -1
5 -1
switch_port_map
0 -1
1 0
2 1
3 2
4 3
5 -1
`
)

func writeFile(t *testing.T, root, p, s string) {
	t.Helper()
	p = filepath.Join(root, p)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadLinks(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/proc/tc3162/gsw_link_st", gswLinkSt)
	writeFile(t, root, "/proc/tc3162/eth_portmap", ethPortmap)
	want := map[int]Link{1: {true, 1000, true}, 2: {}, 3: {}, 4: {true, 100, true}}
	if got := ReadLinks(root); !reflect.DeepEqual(got, want) {
		t.Errorf("links %+v, want %+v", got, want)
	}
	// a map that swaps labels 1 and 4
	writeFile(t, root, "/proc/tc3162/eth_portmap", "lan_port_map\n0 4\n1 2\n2 3\n3 1\nswitch_port_map\n")
	if got := ReadLinks(root); got[1].Speed != 100 || got[4].Speed != 1000 {
		t.Errorf("mapped links %+v", got)
	}
	// no gsw_link_st: eth_port_status, up/down only
	root = t.TempDir()
	writeFile(t, root, "/proc/tc3162/eth_port_status", "1 0 0 1 \n")
	if got := ReadLinks(root); !got[1].Up || got[2].Up || got[3].Up || !got[4].Up || got[1].Speed != 0 {
		t.Errorf("fallback links %+v", got)
	}
}

func setStats(t *testing.T, root, dev string, rx, tx int64) {
	for k, v := range map[string]int64{"rx_bytes": rx, "tx_bytes": tx, "rx_packets": rx / 100, "tx_packets": tx / 100} {
		writeFile(t, root, filepath.Join("/sys/class/net", dev, "statistics", k), strconv.FormatInt(v, 10)+"\n")
	}
}

// TestCounters: a port counts all its VLAN devices; the sums never go
// back when a device goes away or is recreated.
func TestCounters(t *testing.T) {
	root := t.TempDir()
	setStats(t, root, "eth0.2.1", 1000, 2000)
	setStats(t, root, "eth0.4.1", 50000, 60000)
	setStats(t, root, "eth0.4.3", 500, 600)
	c := NewCounters()
	s := c.Read(root)
	if s[2].RxBytes != 1000 || s[4].RxBytes != 50500 || s[4].TxBytes != 60600 || s[4].RxPkts != 505 {
		t.Fatalf("first %+v", s)
	}
	setStats(t, root, "eth0.2.1", 1500, 2000)
	setStats(t, root, "eth0.2.7", 100, 0) // a tagged VLAN arrives
	os.RemoveAll(filepath.Join(root, "sys/class/net/eth0.4.3"))
	setStats(t, root, "eth0.4.1", 50100, 60000)
	s = c.Read(root)
	if s[2].RxBytes != 1600 || s[4].RxBytes != 50600 || s[4].TxBytes != 60600 {
		t.Errorf("second %+v", s)
	}
	setStats(t, root, "eth0.4.3", 10, 10) // recreated: counts from its new value
	s = c.Read(root)
	if s[4].RxBytes != 50610 || s[4].TxBytes != 60610 {
		t.Errorf("third %+v", s)
	}
}

func TestRows(t *testing.T) {
	mac := []map[string]any{{"mac": "54:af:97:74:f4:39", "age": int64(3), "vlan": 1, "static": false}}
	rows := Rows(RowsInput{
		Links:  map[int]Link{1: {true, 1000, true}, 4: {true, 100, true}},
		Stats:  map[int]Stats{1: {RxBytes: 7, TxBytes: 8}, 4: {RxBytes: 9}},
		MACs:   map[int][]map[string]any{1: mac},
		Locked: func(p int) bool { return p == 4 || p == 1 },
	})
	if len(rows) != NumPorts {
		t.Fatalf("%d rows", len(rows))
	}
	type exp struct {
		name     string
		ifname   any
		up       bool
		speed    int
		uplink   bool
		noEdit   bool
		hasMACs  bool
		rxBytes  int64
		macCount int
	}
	for i, e := range []exp{
		{"Port 1", "eth0.1", true, 1000, false, true, true, 7, 1},
		{"Port 2", "eth0.2", false, 0, false, false, true, 0, 0},
		{"Port 3", "eth0.3", false, 0, false, false, true, 0, 0},
		{"Port 4", nil, false, 0, false, true, false, 0, 0},
		{"PoE In + Data", "eth0.4", true, 100, true, true, false, 9, 0},
	} {
		r := rows[i]
		if r["port_idx"] != i+1 || r["name"] != e.name || r["ifname"] != e.ifname || r["up"] != e.up || r["speed"] != e.speed ||
			r["is_uplink"] != e.uplink || r["attr_no_edit"] != e.noEdit || r["rx_bytes"] != e.rxBytes || r["media"] != "GE" {
			t.Errorf("row %d: %v", i+1, r)
		}
		m, ok := r["mac_table"].([]map[string]any)
		if ok != e.hasMACs || len(m) != e.macCount {
			t.Errorf("row %d mac_table %v", i+1, r["mac_table"])
		}
	}
	// port 1 unlocked: editable
	rows = Rows(RowsInput{Locked: func(p int) bool { return p == 4 }})
	if rows[0]["attr_no_edit"] != false || rows[4]["attr_no_edit"] != true || rows[3]["attr_no_edit"] != true {
		t.Errorf("attr_no_edit %v %v %v", rows[0]["attr_no_edit"], rows[3]["attr_no_edit"], rows[4]["attr_no_edit"])
	}
}
