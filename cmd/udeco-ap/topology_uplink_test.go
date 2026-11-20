// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"testing"

	"github.com/dtechterminal/udeco/internal/apstate"
)

// The Deco's eth0 row has the wired U6 Pro's key set (docs/reference/u6pro):
// integer byte/packet/error/drop/multicast counters of the real uplink port,
// no wireless keys (signal, rssi, is_mesh_v3), and the inform carries no
// top-level "stat", which a real U6 Pro does not send.
func TestUplinkFieldsU6ProShape(t *testing.T) {
	a := &agent{topo: newTopology()}
	a.topo.uplink = "eth1"
	s := &apstate.Snapshot{MAC: "b0:a7:b9:3e:17:00", IP: "192.168.0.205", Netmask: "255.255.255.0"}
	ports := map[string]apstate.Port{
		"eth0": {Name: "eth0", Up: true, Speed: 100, RxBytes: 1, TxBytes: 1},
		"eth1": {Name: "eth1", Up: true, Speed: 1000, FullDuplex: true,
			RxBytes: 777996335, TxBytes: 68071165, RxPkts: 815350, TxPkts: 203738,
			RxErrors: 1, TxErrors: 2, RxDropped: 3, TxDropped: 4, RxMulticast: 5},
	}
	f := map[string]any{
		"stat":       map[string]any{"user-num_sta": 3},
		"port_table": []map[string]any{{"port_idx": 1}},
		"if_table":   []map[string]any{{"name": "eth0", "signal": 0, "rssi": 0, "is_mesh_v3": false}},
	}
	a.uplinkFields(f, s, ports, "1c:6a:1b:c5:04:c1")

	if _, ok := f["stat"]; ok {
		t.Errorf("stat still sent: %v", f["stat"])
	}
	if _, ok := f["port_table"]; ok {
		t.Errorf("port_table still sent: %v", f["port_table"])
	}
	it, _ := f["if_table"].([]map[string]any)
	if len(it) != 1 {
		t.Fatalf("if_table %v", f["if_table"])
	}
	r := it[0]
	want := map[string]int64{"rx_bytes": 777996335, "tx_bytes": 68071165, "rx_packets": 815350, "tx_packets": 203738,
		"rx_errors": 1, "tx_errors": 2, "rx_dropped": 3, "tx_dropped": 4, "rx_multicast": 5}
	for k, v := range want {
		if got, ok := r[k].(int64); !ok || got != v {
			t.Errorf("if_table[0][%q] = %#v, want int64 %d", k, r[k], v)
		}
	}
	for _, k := range []string{"signal", "rssi", "is_mesh_v3"} {
		if _, ok := r[k]; ok {
			t.Errorf("if_table[0] has wireless key %q", k)
		}
	}
	if r["name"] != "eth0" || r["up"] != true || r["speed"] != 1000 || r["full_duplex"] != true || r["num_port"] != 1 ||
		r["mac"] != s.MAC || f["uplink"] != "eth0" || f["has_eth1"] != false || f["gateway_mac"] != "1c:6a:1b:c5:04:c1" {
		t.Errorf("if_table[0] %v uplink %v has_eth1 %v gateway_mac %v", r, f["uplink"], f["has_eth1"], f["gateway_mac"])
	}
}

// Without a reading of the uplink port the row from apstate stays, still
// single-port and without the wireless keys.
func TestUplinkFieldsNoPortReading(t *testing.T) {
	a := &agent{topo: newTopology()}
	f := map[string]any{"if_table": []map[string]any{{"name": "eth0", "num_port": 2, "signal": 0, "rssi": 0, "is_mesh_v3": false}}}
	a.uplinkFields(f, &apstate.Snapshot{}, nil, "")
	r := f["if_table"].([]map[string]any)[0]
	if r["num_port"] != 1 {
		t.Errorf("num_port %v", r["num_port"])
	}
	for _, k := range []string{"signal", "rssi", "is_mesh_v3"} {
		if _, ok := r[k]; ok {
			t.Errorf("if_table[0] has wireless key %q", k)
		}
	}
}

// Platform jio-mtk: the ports are the switch port devices (eth0.N.1, see
// mtkwifi TestPortsAreSwitchPortDevices) and the uplink is eth0.4.1. The
// if_table eth0 row carries eth0.4.1's 64-bit counters as they are, never
// those of another port, and they keep counting across readings (a total
// above 4 GiB is no 32-bit wrap).
func TestUplinkFieldsJioPortCounters(t *testing.T) {
	root := t.TempDir()
	writeIfindex(t, root, "eth0.4.1", "26")
	a := counterAgent(t, root)
	a.cfg = &Config{Platform: PlatformJio}
	a.topo.uplink = "eth0.4.1"
	s := &apstate.Snapshot{MAC: "b4:a7:c6:17:e3:f3", IP: "192.168.0.51", Netmask: "255.255.255.0"}
	read := func(uptime int64, rx, tx int64) map[string]any {
		t.Helper()
		ports := map[string]apstate.Port{
			"eth0.1.1": {Name: "eth0.1.1", Up: true, Speed: 1000, RxBytes: 20752742692, TxBytes: 45666909354},
			"eth0.2.1": {Name: "eth0.2.1", Up: true, Speed: 0, RxBytes: 0, TxBytes: 18976856502},
			"eth0.4.1": {Name: "eth0.4.1", Up: true, Speed: 1000, FullDuplex: true, RxBytes: rx, TxBytes: tx},
		}
		a.ctr.Begin(uptime)
		f := map[string]any{}
		a.uplinkFields(f, s, ports, "1c:6a:1b:c5:04:c1")
		a.monoIfTable(f)
		return ifRow(f)
	}
	r := read(8207676, 48216226929, 28955672443)
	if r["rx_bytes"] != int64(48216226929) || r["tx_bytes"] != int64(28955672443) || r["name"] != "eth0" {
		t.Fatalf("first reading %v", r)
	}
	r = read(8207736, 48216426627, 28955812289)
	if r["rx_bytes"] != int64(48216426627) || r["tx_bytes"] != int64(28955812289) {
		t.Errorf("second reading %v, want eth0.4.1's counters", r)
	}
}
