// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

import "testing"

// -uplink-port wins over the gateway's FDB entry.
func TestUplinkPortForced(t *testing.T) {
	s := &Snapshot{
		Gateway: "192.168.1.1", ARP: map[string]string{"40:11:22:33:44:01": "192.168.1.1"},
		Ports: []Port{{Name: "lan1", Up: true, BridgePort: 1}, {Name: "wan", Up: true, BridgePort: 4}},
		FDB:   []FDBEntry{{MAC: "40:11:22:33:44:01", Port: 1}},
	}
	if p := s.uplinkPort(); p == nil || p.Name != "lan1" {
		t.Fatalf("uplinkPort = %+v, want lan1 (gateway)", p)
	}
	s.UplinkName = "wan"
	if p := s.uplinkPort(); p == nil || p.Name != "wan" {
		t.Errorf("uplinkPort = %+v, want wan (forced)", p)
	}
}

// Without the gateway in the FDB the old rule stays: an up "lan" port first.
func TestUplinkPortFallback(t *testing.T) {
	s := &Snapshot{Gateway: "192.168.1.1", Ports: []Port{
		{Name: "wan", Up: true, BridgePort: 4},
		{Name: "lan1", Up: true, BridgePort: 1},
	}}
	if p := s.uplinkPort(); p == nil || p.Name != "lan1" {
		t.Errorf("uplinkPort = %+v, want lan1", p)
	}
}
