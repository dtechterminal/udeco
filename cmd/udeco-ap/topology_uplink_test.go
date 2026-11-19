// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
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
