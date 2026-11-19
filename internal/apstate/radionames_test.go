// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

import (
	"testing"
)

// A system_cfg the controller builds for a U6-Lite reported with radios
// ra0/rai0: two 5 GHz SSIDs get their own devnames (rai0, rai1).
const mtkInfoCfg = "radio.1.phyname=ra0\nradio.1.ieee_mode=11nght20\nradio.2.phyname=rai0\nradio.2.ieee_mode=11naht40\n" +
	"wireless.1.devname=ra0\nwireless.1.ssid=Home\nwireless.1.parent=ra0\nwireless.1.id=2\n" +
	"wireless.2.devname=rai0\nwireless.2.ssid=Home\nwireless.2.parent=rai0\nwireless.2.id=2\n" +
	"wireless.3.devname=rai1\nwireless.3.ssid=IoT\nwireless.3.parent=rai0\nwireless.3.id=3\n"

func mtkSnapshot() *Snapshot {
	return &Snapshot{Radios: []Radio{
		{Iface: "wl0", Phy: "wl0", Band: "ng", Channel: 6, Width: 20,
			VAPs: []Radio{{Iface: "wl02", Mode: "Master", Band: "ng", Channel: 6, SSID: "Home", BSSID: "02:00:00:00:00:02"}}},
		{Iface: "wl1", Phy: "wl1", Band: "na", Channel: 36, Width: 40,
			VAPs: []Radio{
				{Iface: "wl12", Mode: "Master", Band: "na", Channel: 36, SSID: "Home", BSSID: "02:00:00:00:01:02"},
				{Iface: "wl13", Mode: "Master", Band: "na", Channel: 36, SSID: "IoT", BSSID: "02:00:00:00:01:03"},
			}},
	}}
}

func vapNames(t *testing.T, f map[string]any) map[string]string {
	t.Helper()
	got := map[string]string{} // bssid -> name
	for _, v := range f["vap_table"].([]map[string]any) {
		got[v["bssid"].(string)] = v["name"].(string) + "@" + v["radio_name"].(string)
	}
	return got
}

// With RadioNames (MediaTek) the radio_table rows are ra0/rai0 and each VAP
// row carries its own devname from system_cfg.
func TestFieldsMediaTekRadioNames(t *testing.T) {
	s := mtkSnapshot()
	info := InfoFromCfg(mtkInfoCfg)
	info.RadioNames = map[string]string{"ng": "ra0", "na": "rai0"}
	f := s.Fields(nil, info, nil)
	var names []string
	for _, r := range f["radio_table"].([]map[string]any) {
		names = append(names, r["name"].(string)+"/"+r["radio"].(string))
		if a := r["athstats"].(map[string]any); a["name"] != r["name"] {
			t.Errorf("athstats name %v for radio %v", a["name"], r["name"])
		}
	}
	if len(names) != 2 || names[0] != "ra0/ng" || names[1] != "rai0/na" {
		t.Errorf("radio_table %v", names)
	}
	want := map[string]string{"02:00:00:00:00:02": "ra0@ra0", "02:00:00:00:01:02": "rai0@rai0", "02:00:00:00:01:03": "rai1@rai0"}
	if got := vapNames(t, f); len(got) != 3 || got["02:00:00:00:00:02"] != want["02:00:00:00:00:02"] ||
		got["02:00:00:00:01:02"] != want["02:00:00:00:01:02"] || got["02:00:00:00:01:03"] != want["02:00:00:00:01:03"] {
		t.Errorf("vap_table %v, want %v", got, want)
	}
	if m := s.IfnamesByDevname(info); len(m) != 3 || m["ra0"] != "wl02" || m["rai0"] != "wl12" || m["rai1"] != "wl13" {
		t.Errorf("devname -> vif %v", m)
	}
	for _, r := range f["radio_table_stats"].([]map[string]any) {
		if n := r["name"]; n != "ra0" && n != "rai0" {
			t.Errorf("radio_table_stats name %v", n)
		}
	}
}

// Without RadioNames the rows keep the Qualcomm wifiN names (uow, and a
// unit adopted with them), and a system_cfg built for other radio names is
// still matched by band.
func TestFieldsRadioNamesFallback(t *testing.T) {
	s := mtkSnapshot()
	info := InfoFromCfg(mtkInfoCfg)
	f := s.Fields(nil, info, nil)
	rows := f["radio_table"].([]map[string]any)
	if rows[0]["name"] != "wifi0" || rows[1]["name"] != "wifi1" {
		t.Errorf("radio names %v %v", rows[0]["name"], rows[1]["name"])
	}
	got := vapNames(t, f)
	if got["02:00:00:00:00:02"] != "ra0@wifi0" || got["02:00:00:00:01:02"] != "rai0@wifi1" || got["02:00:00:00:01:03"] != "rai1@wifi1" {
		t.Errorf("vap_table by band %v", got)
	}
	// two radios of one band: only the first takes the mapped name
	two := &Snapshot{Radios: []Radio{{Iface: "a", Band: "na"}, {Iface: "b", Band: "na"}}}
	n := CfgInfo{RadioNames: map[string]string{"na": "rai0"}}.radioNames(two.Radios)
	if n[0] != "rai0" || n[1] != "wifi1" {
		t.Errorf("duplicate band names %v", n)
	}
}
