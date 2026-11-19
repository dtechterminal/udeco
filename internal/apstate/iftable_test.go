// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

import "testing"

// The eth0 if_table row carries the counters a real U6 Pro's row has
// (docs/reference/u6pro/inform-field-inventory.tsv): bytes, packets,
// errors, drops and rx_multicast, all as integers.
func TestIfTableRowCounters(t *testing.T) {
	s := &Snapshot{MAC: "aa:bb:cc:00:00:01", IP: "192.168.0.205", Netmask: "255.255.255.0", Ports: []Port{{
		Name: "lan1", MAC: "aa:bb:cc:00:00:02", Up: true, Speed: 1000, FullDuplex: true,
		RxBytes: 777996335, TxBytes: 68071165, RxPkts: 815350, TxPkts: 203738,
		RxErrors: 1, TxErrors: 2, RxDropped: 3, TxDropped: 4, RxMulticast: 5,
	}}}
	it, _ := s.Fields(nil, CfgInfo{}, nil)["if_table"].([]map[string]any)
	if len(it) != 1 {
		t.Fatalf("if_table %v", it)
	}
	want := map[string]int64{"rx_bytes": 777996335, "tx_bytes": 68071165, "rx_packets": 815350, "tx_packets": 203738,
		"rx_errors": 1, "tx_errors": 2, "rx_dropped": 3, "tx_dropped": 4, "rx_multicast": 5}
	for k, v := range want {
		if got, ok := it[0][k].(int64); !ok || got != v {
			t.Errorf("if_table[0][%q] = %#v, want int64 %d", k, it[0][k], v)
		}
	}
}
