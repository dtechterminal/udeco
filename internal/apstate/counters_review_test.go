// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

import "testing"

// A station that was associated only a few seconds at the last reading
// drops and reassociates right after it: its "in network" time neither went
// down nor is younger than the gap, so only its counters show the new
// association. A drop of a station counter is a reset (the byte counters
// of wl sta_info are 64-bit; a packet counter does not wrap within one
// association in practice), never a 32-bit wrap worth ~4.29 GB. The same
// for a station whose "in network" time is not read at all.
func TestCountersStationQuickReassociationIsNotAWrap(t *testing.T) {
	info := InfoFromCfg(mtkInfoCfg)
	info.RadioNames = map[string]string{"ng": "ra0", "na": "rai0"}
	for _, tc := range []struct {
		name        string
		conn0, con1 int64
	}{
		{"young association", 3, 8},
		{"no in-network time", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mc := NewCounters()
			mc.Ifindex = ifx{"wl13": 40}.get
			ctl := newCtrl()
			sta := func(conn, tx int64) []Station {
				return []Station{{MAC: "aa:bb:cc:00:00:03", Connected: conn, TxBytes: tx, RxBytes: tx, TxPackets: tx / 100, TxRetries: tx / 1000}}
			}
			read := func(up, conn, tx int64) map[string]any {
				mc.Begin(up)
				f := reading(up, vapSpec{band: "na", iface: "wl13", ssid: "IoT", tx: 1000, stas: sta(conn, tx)}).FieldsWith(nil, info, nil, mc)
				ctl.inform(f)
				return f
			}
			read(100, tc.conn0, 50_000)
			f := read(110, tc.con1, 10_000) // reassociated ~2 s after the last reading
			row := vapRow(t, f, "wl13")
			st := row["sta_table"].([]map[string]any)[0]
			if got := toI(st["tx_bytes"]); got > 60_000 {
				t.Errorf("station tx_bytes %d after a reassociation (at most 60000 are real)", got)
			}
			if got := ctl.total["sta:aa:bb:cc:00:00:03:tx_bytes"]; got > 10_000 {
				t.Errorf("controller counted %d station tx bytes, at most 10000 are real", got)
			}
			if got := ctl.total["vap:rai1:tx_retries"] + ctl.total["vap:rai1:wifi_tx_attempts"]; got > 1000 {
				t.Errorf("controller counted %d VAP retries/attempts, at most ~110 are real", got)
			}
		})
	}
}

// The vif's interface index could not be read at one reading (the netdev
// was being recreated by a hostapd restart), and at the next one the vif is
// a new instance whose counters started at 0. Without a confirmed identity
// a drop is a reset, not a 32-bit wrap.
func TestCountersUnreadableIfindexThenRecreated(t *testing.T) {
	info := InfoFromCfg(mtkInfoCfg)
	info.RadioNames = map[string]string{"ng": "ra0", "na": "rai0"}
	idx := ifx{"wl13": 40}
	mc := NewCounters()
	mc.Ifindex = idx.get
	ctl := newCtrl()
	step := func(up, tx int64) int64 {
		t.Helper()
		mc.Begin(up)
		f := reading(up, vapSpec{band: "na", iface: "wl13", ssid: "IoT", tx: tx, rx: 1000}).FieldsWith(nil, info, nil, mc)
		ctl.inform(f)
		return toI(vapRow(t, f, "wl13")["tx_bytes"])
	}
	v0 := step(100, 3_000_000)
	delete(idx, "wl13") // ifindex unreadable
	v1 := step(110, 3_100_000)
	idx["wl13"] = 41 // recreated, counters from 0
	v2 := step(120, 5_000)
	if v1 < v0 || v2 < v1 {
		t.Fatalf("tx_bytes went down: %d %d %d", v0, v1, v2)
	}
	if v2-v0 > 3_100_000-3_000_000+5_000 {
		t.Errorf("tx_bytes grew by %d, at most %d are real", v2-v0, 105_000)
	}
}
