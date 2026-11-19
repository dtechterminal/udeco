// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

import (
	"fmt"
	"testing"
)

// ctrlDeltas is the controller's counter handling (Network 10.6.109,
// com.ubnt.service.devmgr.lVGbxbqo and the stat3 counter type
// com.ubnt.service.system.q.a.a.vFiJoQiuQjMZUx): per key, delta = value -
// last stored value; counted only when positive (and a value was stored
// before); the new value is always stored, so a drop becomes the new base.
type ctrlDeltas struct {
	last  map[string]int64
	total map[string]int64
}

func newCtrl() *ctrlDeltas { return &ctrlDeltas{last: map[string]int64{}, total: map[string]int64{}} }

func (c *ctrlDeltas) see(key string, v int64) {
	if p, ok := c.last[key]; ok && p != 0 && v > p {
		c.total[key] += v - p
	}
	c.last[key] = v
}

// inform feeds one inform's vap_table (by VAP name) and sta_table (by MAC)
// counters to the controller model, in row order as the controller does.
func (c *ctrlDeltas) inform(f map[string]any) {
	for _, v := range f["vap_table"].([]map[string]any) {
		for _, k := range []string{"tx_bytes", "rx_bytes", "tx_packets", "wifi_tx_attempts", "tx_retries"} {
			c.see("vap:"+v["name"].(string)+":"+k, toI(v[k]))
		}
		for _, st := range v["sta_table"].([]map[string]any) {
			for _, k := range []string{"tx_bytes", "rx_bytes", "tx_packets"} {
				c.see("sta:"+st["mac"].(string)+":"+k, toI(st[k]))
			}
		}
	}
}

func toI(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	}
	panic(fmt.Sprintf("counter of type %T", v))
}

// vapSpec is one VAP in a test reading.
type vapSpec struct {
	band, iface, ssid string
	tx, rx            int64
	stas              []Station
}

func reading(uptime int64, vaps ...vapSpec) *Snapshot {
	s := &Snapshot{Uptime: uptime, Radios: []Radio{
		{Iface: "wl0", Phy: "wl0", Band: "ng", Channel: 6, Width: 20},
		{Iface: "wl1", Phy: "wl1", Band: "na", Channel: 36, Width: 80},
	}}
	for _, v := range vaps {
		i := 0
		if v.band == "na" {
			i = 1
		}
		s.Radios[i].VAPs = append(s.Radios[i].VAPs, Radio{Iface: v.iface, Mode: "Master", Band: v.band, SSID: v.ssid,
			BSSID:    "02:00:00:00:00:" + v.iface[2:],
			Stats:    map[string]int64{"tx_bytes": v.tx, "rx_bytes": v.rx, "tx_packets": v.tx / 1000, "rx_packets": v.rx / 1000},
			Stations: v.stas})
	}
	return s
}

// legacy (wifiN) naming as on .205 before the rename: the first two 5 GHz
// SSIDs are both devname wifi1.
const legacyCfg = "wireless.1.devname=wifi1\nwireless.1.ssid=Home\nwireless.1.parent=wifi1\nwireless.1.id=2\n" +
	"wireless.2.devname=wifi1\nwireless.2.ssid=olive#\nwireless.2.parent=wifi1\nwireless.2.id=3\n" +
	"wireless.3.devname=wifi0\nwireless.3.ssid=Home\nwireless.3.parent=wifi0\nwireless.3.id=2\n"

type ifx map[string]int64

func (m ifx) get(dev string) int64 { return m[dev] }

func vapRow(t *testing.T, f map[string]any, iface string) map[string]any {
	t.Helper()
	for _, v := range f["vap_table"].([]map[string]any) {
		if v["bssid"] == "02:00:00:00:00:"+iface[2:] {
			return v
		}
	}
	t.Fatalf("no vap row for %s", iface)
	return nil
}

// The live .205 failure: two VAPs named wifi1 with very different totals.
// Raw counters make the controller count the difference at every inform
// (terabytes); monotonic ones count exactly the traffic.
func TestCountersCollidingNames(t *testing.T) {
	info := InfoFromCfg(legacyCfg)
	run := func(mc *Counters) (*ctrlDeltas, []map[string]any) {
		ctl := newCtrl()
		var rows []map[string]any
		for i := int64(0); i < 100; i++ {
			s := reading(1000+10*i,
				vapSpec{band: "na", iface: "wl12", ssid: "Home", tx: 900_000_000 + i*1000},
				vapSpec{band: "na", iface: "wl13", ssid: "olive#", tx: 5_000_000 + i*500})
			if mc != nil {
				mc.Begin(s.Uptime)
			}
			f := s.FieldsWith(nil, info, nil, mc)
			ctl.inform(f)
			rows = append(rows, vapRow(t, f, "wl12"), vapRow(t, f, "wl13"))
		}
		return ctl, rows
	}
	raw, _ := run(nil)
	if got := raw.total["vap:wifi1:tx_bytes"]; got < 1e10 {
		t.Fatalf("model check: raw counters should blow up, counted %d", got)
	}
	ctl, rows := run(NewCounters())
	// real traffic after the first inform: 99 readings x (1000 + 500)
	if got, want := ctl.total["vap:wifi1:tx_bytes"], int64(99*1500); got != want {
		t.Errorf("controller counted %d tx bytes under wifi1, want %d", got, want)
	}
	for i := 2; i < len(rows); i += 2 {
		if rows[i]["tx_bytes"] != rows[i+1]["tx_bytes"] {
			t.Fatalf("rows named wifi1 disagree in one inform: %v %v", rows[i]["tx_bytes"], rows[i+1]["tx_bytes"])
		}
		if toI(rows[i]["tx_bytes"]) < toI(rows[i-2]["tx_bytes"]) {
			t.Fatalf("wifi1 tx_bytes went down: %v -> %v", rows[i-2]["tx_bytes"], rows[i]["tx_bytes"])
		}
	}
}

// An SSID moving from wl13 to wl14 (same devname rai1), its hostapd
// restarted (vif recreated: new ifindex, counters from 0) and a 32-bit
// counter wrap: the name's counter only grows, by the real traffic.
func TestCountersRenumberRestartWrap(t *testing.T) {
	info := InfoFromCfg(mtkInfoCfg)
	info.RadioNames = map[string]string{"ng": "ra0", "na": "rai0"}
	idx := ifx{"wl13": 40, "wl14": 41}
	mc := NewCounters()
	mc.Ifindex = idx.get
	ctl := newCtrl()
	step := func(up int64, iface string, tx int64) int64 {
		t.Helper()
		s := reading(up, vapSpec{band: "na", iface: iface, ssid: "IoT", tx: tx, rx: 1000})
		mc.Begin(up)
		f := s.FieldsWith(nil, info, nil, mc)
		ctl.inform(f)
		row := vapRow(t, f, iface)
		if row["name"] != "rai1" {
			t.Fatalf("name %v", row["name"])
		}
		return toI(row["tx_bytes"])
	}
	v0 := step(100, "wl13", 3_000_000_000)
	if v0 != 3_000_000_000 {
		t.Errorf("first reading starts from the counter: %d", v0)
	}
	v1 := step(110, "wl13", 3_000_010_000) // +10000
	// moved to wl14 by a re-plan: a new vif (ifindex 41) is a baseline
	// under a name that has a total (bytes since its creation are lost:
	// count less, never more)
	v2 := step(120, "wl14", 2_000_000)
	v3 := step(130, "wl14", 2_005_000) // +5000
	// hostapd restart: wl14 recreated with a new ifindex, counters from 0
	idx["wl14"] = 55
	v4 := step(140, "wl14", 7000) // all 7000 are new
	// 32-bit wrap on the same interface
	step(150, "wl14", 4_294_967_000)
	v6 := step(160, "wl14", 704) // +1000 through the wrap
	if v1-v0 != 10000 || v2 != v1 || v3-v2 != 5000 || v4-v3 != 7000 || v6-v4 != 4_294_967_000-7000+1000 {
		t.Errorf("tx_bytes %d %d %d %d %d %d", v0, v1, v2, v3, v4, v6)
	}
	if got, want := ctl.total["vap:rai1:tx_bytes"], v6-v0; got != want {
		t.Errorf("controller counted %d, want %d", got, want)
	}
}

// A station: its counters reset on reassociation (shorter "in network"
// time), it shows up on another vif, and it is listed on two vifs in one
// reading; per MAC the counter only grows, by the real traffic. The VAP's
// station sums (tx_retries, wifi_tx_attempts) do not drop when it leaves.
func TestCountersStationReassociation(t *testing.T) {
	info := InfoFromCfg(mtkInfoCfg)
	info.RadioNames = map[string]string{"ng": "ra0", "na": "rai0"}
	mc := NewCounters()
	ctl := newCtrl()
	sta := func(conn, tx, retries int64) Station {
		return Station{MAC: "aa:bb:cc:00:00:01", Connected: conn, TxBytes: tx, RxBytes: tx / 2, TxPackets: tx / 100, TxRetries: retries}
	}
	var lastTx int64
	var counted int64
	readOne := func(up int64, vaps ...vapSpec) map[string]any {
		mc.Begin(up)
		f := reading(up, vaps...).FieldsWith(nil, info, nil, mc)
		ctl.inform(f)
		for _, v := range f["vap_table"].([]map[string]any) {
			for _, st := range v["sta_table"].([]map[string]any) {
				tx := toI(st["tx_bytes"])
				if tx < lastTx {
					t.Fatalf("station tx_bytes went down at %d: %d -> %d", up, lastTx, tx)
				}
				lastTx = tx
			}
		}
		return f
	}
	readOne(100, vapSpec{band: "na", iface: "wl13", ssid: "IoT", stas: []Station{sta(50, 1_000_000, 10)}})
	readOne(110, vapSpec{band: "na", iface: "wl13", ssid: "IoT", stas: []Station{sta(60, 1_100_000, 12)}})
	counted += 100_000
	// reassociated: "in network" 3 s, counters from 0
	readOne(120, vapSpec{band: "na", iface: "wl13", ssid: "IoT", stas: []Station{sta(3, 40_000, 1)}})
	counted += 40_000
	// reassociated again but with more traffic than before: the association
	// is younger than the gap since the last reading, so all of it is new
	readOne(140, vapSpec{band: "na", iface: "wl13", ssid: "IoT", stas: []Station{sta(4, 900_000, 1)}})
	counted += 900_000
	// roams to 2.4 GHz (another vif): a new association
	f := readOne(150, vapSpec{band: "na", iface: "wl13", ssid: "IoT"},
		vapSpec{band: "ng", iface: "wl02", ssid: "Home", stas: []Station{sta(2, 5000, 0)}})
	counted += 5000
	// retries 10, +2, then two fresh associations with 1 each
	if r := vapRow(t, f, "wl13"); toI(r["tx_retries"]) != 14 || toI(r["wifi_tx_attempts"]) < 14 {
		t.Errorf("wl13 station sums dropped when the station left: %v", r)
	}
	// listed on both vifs in one reading (the old entry not yet aged out)
	readOne(160, vapSpec{band: "na", iface: "wl13", ssid: "IoT", stas: []Station{sta(24, 905_000, 1)}},
		vapSpec{band: "ng", iface: "wl02", ssid: "Home", stas: []Station{sta(12, 8000, 0)}})
	counted += 5000 + 3000
	readOne(170, vapSpec{band: "ng", iface: "wl02", ssid: "Home", stas: []Station{sta(22, 9000, 0)}})
	counted += 1000
	if got := ctl.total["sta:aa:bb:cc:00:00:01:tx_bytes"]; got != counted {
		t.Errorf("controller counted %d station tx bytes, want %d", got, counted)
	}
}

// The state survives an agent restart (Marshal/Load in the RAM run dir):
// totals continue, and the traffic while the agent was down is counted
// once. A state from an earlier boot (seen later than the uptime) is
// dropped.
func TestCountersPersist(t *testing.T) {
	info := InfoFromCfg(mtkInfoCfg)
	info.RadioNames = map[string]string{"ng": "ra0", "na": "rai0"}
	idx := ifx{"wl13": 40}
	mc := NewCounters()
	mc.Ifindex = idx.get
	st := func(conn, tx int64) []Station {
		return []Station{{MAC: "aa:bb:cc:00:00:02", Connected: conn, TxBytes: tx}}
	}
	mc.Begin(100)
	reading(100, vapSpec{band: "na", iface: "wl13", ssid: "IoT", tx: 5000, stas: st(30, 700)}).FieldsWith(nil, info, nil, mc)
	mc.Begin(110)
	f := reading(110, vapSpec{band: "na", iface: "wl13", ssid: "IoT", tx: 9000, stas: st(40, 900)}).FieldsWith(nil, info, nil, mc)
	before := toI(vapRow(t, f, "wl13")["tx_bytes"])
	b, err := mc.Marshal()
	if err != nil || !mc.Dirty() {
		t.Fatal(err, mc.Dirty())
	}
	// agent down for 5 minutes; the station stayed associated
	mc2 := LoadCounters(b)
	mc2.Ifindex = idx.get
	mc2.Begin(410)
	f = reading(410, vapSpec{band: "na", iface: "wl13", ssid: "IoT", tx: 20000, stas: st(340, 2900)}).FieldsWith(nil, info, nil, mc2)
	row := vapRow(t, f, "wl13")
	if got := toI(row["tx_bytes"]); got != before+11000 {
		t.Errorf("after restart tx_bytes %d, want %d", got, before+11000)
	}
	if got := toI(row["sta_table"].([]map[string]any)[0]["tx_bytes"]); got != 2900 {
		t.Errorf("station after restart %d, want 2900", got)
	}
	// an earlier boot's state: dropped, the reading starts afresh
	mc3 := LoadCounters(b)
	mc3.Begin(20)
	if len(mc3.Src) != 0 || len(mc3.Acc) != 0 {
		t.Errorf("stale state kept: %d sources %d totals", len(mc3.Src), len(mc3.Acc))
	}
	if c := LoadCounters([]byte("{not json")); len(c.Src) != 0 || c.Acc == nil {
		t.Error("garbage state not reset")
	}
}

// Observe mode: TP-Link's vifs whose SSIDs the controller does not have get
// names by position (athN), so a name can move between vifs as TP-Link's
// set changes; and a vif read for the first time under a name that already
// has a total (its counters hold traffic from before) is a baseline. No
// name's counter ever goes down or jumps.
func TestCountersObservePositionalNames(t *testing.T) {
	mc := NewCounters()
	mc.Ifindex = ifx{"wl02": 20, "wl03": 21, "wl12": 30}.get
	ctl := newCtrl()
	last := map[string]int64{}
	read := func(up int64, vaps ...vapSpec) {
		mc.Begin(up)
		f := reading(up, vaps...).FieldsWith(nil, CfgInfo{}, nil, mc)
		ctl.inform(f)
		for _, v := range f["vap_table"].([]map[string]any) {
			n, tx := v["name"].(string), toI(v["tx_bytes"])
			if tx < last[n] {
				t.Fatalf("%s tx_bytes went down at %d: %d -> %d", n, up, last[n], tx)
			}
			last[n] = tx
		}
	}
	read(100, vapSpec{band: "ng", iface: "wl02", ssid: "Deco", tx: 1_000_000},
		vapSpec{band: "na", iface: "wl12", ssid: "Deco", tx: 2_000_000})
	// TP-Link's guest network comes up on wl03 (counters from since boot):
	// wl12 is now ath2, wl03 takes ath1, which was wl12's
	read(110, vapSpec{band: "ng", iface: "wl02", ssid: "Deco", tx: 1_000_100},
		vapSpec{band: "ng", iface: "wl03", ssid: "Deco-guest", tx: 50_000_000},
		vapSpec{band: "na", iface: "wl12", ssid: "Deco", tx: 2_000_200})
	read(120, vapSpec{band: "ng", iface: "wl02", ssid: "Deco", tx: 1_000_400},
		vapSpec{band: "ng", iface: "wl03", ssid: "Deco-guest", tx: 50_000_300},
		vapSpec{band: "na", iface: "wl12", ssid: "Deco", tx: 2_000_500})
	var sum int64
	for k, v := range ctl.total {
		if len(k) > 9 && k[len(k)-9:] == ":tx_bytes" {
			sum += v
		}
	}
	// real traffic after the first inform: wl02 400, wl12 500, wl03 300
	// (its first 50 MB are from before it was read: not counted); ath2 is
	// new at 110 and starts at wl12's value, a first value the controller
	// does not count
	if sum > 1200 {
		t.Errorf("controller counted %d tx bytes, at most 1200 are real", sum)
	}
}

// TestStationRetryFields: a sta_table row carries wifi_tx_attempts (packets
// plus retries) like a real UniFi AP's, so the controller's per-client TX
// retry percentage is retries over attempts, not 0% or 100% (2026-11-19:
// every client read 100% once it had any retry).
func TestStationRetryFields(t *testing.T) {
	st := Station{MAC: "aa:bb:cc:00:00:09", Connected: 30, TxPackets: 900, TxRetries: 100, TxFailed: 5}
	check := func(name string, f map[string]any) {
		t.Helper()
		var row map[string]any
		for _, v := range f["vap_table"].([]map[string]any) {
			for _, s := range v["sta_table"].([]map[string]any) {
				row = s
			}
		}
		if row == nil {
			t.Fatalf("%s: no sta_table row", name)
		}
		want := map[string]int64{"tx_retries": 100, "tx_combined_retries": 100, "wifi_tx_attempts": 1000,
			"wifi_tx_dropped": 5, "tx_total": 900, "wifi_tx_success": 895}
		for k, v := range want {
			if got, ok := row[k]; !ok || toI(got) != v {
				t.Errorf("%s: %s = %v, want %d", name, k, got, v)
			}
		}
	}
	// without counter tracking (raw readings)
	check("raw", reading(100, vapSpec{band: "na", iface: "wl13", ssid: "IoT", stas: []Station{st}}).FieldsWith(nil, CfgInfo{}, nil, nil))
	// with counter tracking: the first reading's values are the totals
	mc := NewCounters()
	mc.Begin(100)
	check("counted", reading(100, vapSpec{band: "na", iface: "wl13", ssid: "IoT", stas: []Station{st}}).FieldsWith(nil, CfgInfo{}, nil, mc))
}

// TestNoDataRadio: a radio whose driver gives no busy time and no TX
// retries (jio-mtk) reports no cu_* and no retry keys, not 0%; the
// controller showed the Garage AP at 0% interference and 0% retries
// beside Decos at 15-36% (2026-11-19). A radio with data keeps them.
func TestNoDataRadio(t *testing.T) {
	st := Station{MAC: "aa:bb:cc:00:00:0a", Connected: 30, TxPackets: 900, TxRetries: 100}
	mk := func(up int64, active int64) *Snapshot {
		s := reading(up,
			vapSpec{band: "ng", iface: "wl02", ssid: "Home", stas: []Station{st}},
			vapSpec{band: "na", iface: "wl12", ssid: "Home", stas: []Station{st}})
		s.Radios[0].NoSurvey, s.Radios[0].NoTxCounters = true, true
		s.Radios[1].Survey = Survey{Active: active, Busy: active / 4, Rx: active / 10, Tx: active / 20}
		return s
	}
	for _, mc := range []*Counters{nil, NewCounters()} {
		prev, cur := mk(100, 10_000), mk(110, 20_000)
		if mc != nil {
			mc.Begin(prev.Uptime)
			prev.FieldsWith(nil, CfgInfo{}, nil, mc)
			mc.Begin(cur.Uptime)
		}
		f := cur.FieldsWith(prev, CfgInfo{}, nil, mc)
		radios, rstats := f["radio_table"].([]map[string]any), f["radio_table_stats"].([]map[string]any)
		cuKeys := []string{"cu_total", "cu_self_rx", "cu_self_tx", "cu_interf"}
		for _, k := range cuKeys {
			if _, ok := rstats[0][k]; ok {
				t.Errorf("no-survey radio_table_stats has %s", k)
			}
			if _, ok := radios[0]["athstats"].(map[string]any)[k]; ok {
				t.Errorf("no-survey athstats has %s", k)
			}
			if _, ok := rstats[1][k]; !ok {
				t.Errorf("surveyed radio_table_stats lacks %s", k)
			}
		}
		if _, ok := radios[0]["cu_interf"]; ok {
			t.Error("no-survey radio_table row has cu_interf")
		}
		if rstats[1]["cu_total"] != 25 || rstats[1]["cu_interf"] != 10 {
			t.Errorf("surveyed radio: cu_total %v cu_interf %v, want 25 and 10", rstats[1]["cu_total"], rstats[1]["cu_interf"])
		}
		retryKeys := []string{"tx_retries", "tx_combined_retries", "wifi_tx_attempts", "wifi_tx_dropped"}
		ng, na := vapRow(t, f, "wl02"), vapRow(t, f, "wl12")
		ngSta, naSta := ng["sta_table"].([]map[string]any)[0], na["sta_table"].([]map[string]any)[0]
		for _, k := range retryKeys {
			if _, ok := ng[k]; ok {
				t.Errorf("no-counter vap row has %s", k)
			}
			if _, ok := ngSta[k]; ok {
				t.Errorf("no-counter sta row has %s", k)
			}
			if _, ok := na[k]; !ok {
				t.Errorf("counted vap row lacks %s", k)
			}
			if _, ok := naSta[k]; !ok {
				t.Errorf("counted sta row lacks %s", k)
			}
		}
		if ngSta["tx_packets"] == nil || ngSta["rx_bytes"] == nil {
			t.Error("no-counter sta row lost its byte/packet counters")
		}
	}
}

// TestCUSelfWithinTotal: own tx and rx airtime, rounded each on its own,
// may not stack above the busy time they are part of (12.5 % + 12.5 % of a
// 25 % busy time is not 13 % + 13 %); a radio whose own counters really
// exceed its busy time keeps its rounded figures.
func TestCUSelfWithinTotal(t *testing.T) {
	for _, c := range []struct {
		name                  string
		busy, tx, rx          int64 // per 10000 ms
		total, selfTx, selfRx int
	}{
		{"two halves", 2500, 1250, 1250, 25, 13, 12},
		{"rx rounds up more", 2510, 1260, 1250, 25, 13, 12},
		{"tx rounds up more", 2510, 1250, 1260, 25, 12, 13},
		{"total rounds down", 2540, 1270, 1270, 25, 13, 12},
		{"no rounding over", 2500, 1240, 1240, 25, 12, 12},
		{"own counters over busy", 2000, 1250, 1250, 20, 13, 13},
	} {
		mk := func(active int64, k int64) *Snapshot {
			s := reading(100*k, vapSpec{band: "na", iface: "wl12", ssid: "Home"})
			s.Radios[1].Survey = Survey{Active: active, Busy: c.busy * k, Tx: c.tx * k, Rx: c.rx * k}
			return s
		}
		prev, cur := mk(10_000, 1), mk(20_000, 2)
		rs := cur.Fields(prev, CfgInfo{}, nil)["radio_table_stats"].([]map[string]any)[1]
		if rs["cu_total"] != c.total || rs["cu_self_tx"] != c.selfTx || rs["cu_self_rx"] != c.selfRx {
			t.Errorf("%s: cu_total %v cu_self_tx %v cu_self_rx %v, want %d %d %d", c.name, rs["cu_total"], rs["cu_self_tx"], rs["cu_self_rx"], c.total, c.selfTx, c.selfRx)
		}
	}
}
