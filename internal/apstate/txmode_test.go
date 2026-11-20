// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

import "testing"

// TestTxPowerMode: radio_table reports the controller's power mode the
// radio runs (Radio.TxPowerMode), "custom" when the collector has none.
func TestTxPowerMode(t *testing.T) {
	s := &Snapshot{Radios: []Radio{{Iface: "ra0", Band: "ng", Channel: 1, TxPower: 17, TxPowerMode: "medium"},
		{Iface: "rai0", Band: "na", Channel: 149, TxPower: 23}}}
	f := s.Fields(nil, CfgInfo{}, nil)
	rows := f["radio_table"].([]map[string]any)
	if rows[0]["tx_power_mode"] != "medium" || rows[0]["tx_power"] != 17 {
		t.Errorf("ng row %v", rows[0])
	}
	if rows[1]["tx_power_mode"] != "custom" {
		t.Errorf("na row mode %v", rows[1]["tx_power_mode"])
	}
}
