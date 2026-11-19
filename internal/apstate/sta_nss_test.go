package apstate

import "testing"

func TestStaTableNSS(t *testing.T) {
	s := &Snapshot{Radios: []Radio{{Iface: "wl0", Band: "ng", Channel: 6, VAPs: []Radio{{Iface: "wl02", Mode: "Master", Band: "ng", Channel: 6, SSID: "x",
		Stations: []Station{{MAC: "02:00:00:00:00:01", NSS: 1}, {MAC: "02:00:00:00:00:02"}}}}}}}
	f := s.Fields(nil, CfgInfo{}, nil)
	var rows []map[string]any
	for _, v := range f["vap_table"].([]map[string]any) {
		rows = append(rows, v["sta_table"].([]map[string]any)...)
	}
	if len(rows) != 2 {
		t.Fatalf("%d rows", len(rows))
	}
	if rows[0]["nss"] != 1 {
		t.Errorf("nss %v, want 1", rows[0]["nss"])
	}
	if _, ok := rows[1]["nss"]; ok {
		t.Error("nss sent for a client whose streams are unknown")
	}
}
