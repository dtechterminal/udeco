// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
)

// readOnly are the `wl` subcommands Collect and Caps may run.
var readOnly = map[string]bool{
	"band": true, "cap": true, "hw_txchain": true, "nmode": true, "vhtmode": true,
	"chanspecs": true, "chanspec_txpwr_max": true, "revinfo": true, "country": true,
	"chanspec": true, "noise": true, "txpwr_target_max": true, "chanim_stats us": true,
	"bss": true, "dwds": true, "ssid": true, "wpa_auth": true, "sta_info all": true,
	"bw_cap 2g": true, "bw_cap 5g": true, // with only the band, a getter
}

func checkReadOnly(t *testing.T, calls []string) {
	t.Helper()
	for _, call := range calls {
		f := strings.Fields(call)
		if len(f) < 4 || f[0] != "wl" || f[1] != "-i" || !readOnly[strings.Join(f[3:], " ")] {
			t.Errorf("not a read-only wl getter: %q", call)
		}
	}
}

func TestCollect(t *testing.T) {
	c, fr, _ := newTestCollector(t)
	s, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	checkReadOnly(t, fr.callList())

	// system
	if s.Hostname != "X20" || s.Model != "Deco X20 v2" || s.Release != "1.3.0 Build 20250912 Rel. 56370" {
		t.Errorf("identity: %q %q %q", s.Hostname, s.Model, s.Release)
	}
	if s.MAC != "b0:a7:b9:3e:17:00" || s.IP != "192.168.0.205" || s.Netmask != "255.255.255.0" || s.Gateway != "192.168.0.1" {
		t.Errorf("net: %s %s %s %s", s.MAC, s.IP, s.Netmask, s.Gateway)
	}
	if s.Uptime != 18381 || s.Load != [3]float64{1.29, 1.27, 1.17} || s.MemTotal != 252152*1024 || s.MemCache != 71932*1024 || s.CPUTotal == 0 {
		t.Errorf("sys: up %d load %v mem %d cache %d cpu %d", s.Uptime, s.Load, s.MemTotal, s.MemCache, s.CPUTotal)
	}
	if len(s.ARP) != 5 || len(s.FDB) != 45 || s.LLDP != nil || s.UplinkName != "" {
		t.Errorf("arp %d fdb %d lldp %v uplink %q", len(s.ARP), len(s.FDB), s.LLDP, s.UplinkName)
	}

	// ports
	wantPorts := []apstate.Port{
		{Name: "eth0", MAC: "b0:a7:b9:3e:17:00", BridgePort: 2},
		{Name: "eth1", MAC: "b0:a7:b9:3e:17:00", Up: true, Speed: 1000, FullDuplex: true,
			RxBytes: 1402600980, TxBytes: 708503601, RxPkts: 1703644, TxPkts: 981766, BridgePort: 1},
	}
	if !reflect.DeepEqual(s.Ports, wantPorts) {
		t.Errorf("ports = %+v", s.Ports)
	}

	// radios
	if len(s.Radios) != 2 {
		t.Fatalf("%d radios", len(s.Radios))
	}
	r0, r1 := s.Radios[0], s.Radios[1]
	if r0.Phy != "wl0" || r0.Band != "ng" || r0.Channel != 2 || r0.Width != 40 || r0.Noise != -98 ||
		r0.TxPower != 24 || r0.TxMax != 25 || r0.TxMin != 5 || r0.NSS != 2 || r0.VHT || !r0.HE ||
		r0.Mode != "Master" || r0.HWName != "Broadcom BCM4491" || r0.SSID != "" {
		t.Errorf("wl0 = %+v", strip(r0))
	}
	if r1.Phy != "wl1" || r1.Band != "na" || r1.Channel != 44 || r1.Width != 80 || r1.Noise != -94 ||
		r1.TxPower != 24 || r1.TxMax != 25 || !r1.VHT || !r1.HE {
		t.Errorf("wl1 = %+v", strip(r1))
	}
	if r0.Survey != (apstate.Survey{}) || r1.Survey != (apstate.Survey{}) {
		t.Errorf("first survey should be zero: %+v %+v", r0.Survey, r1.Survey)
	}

	// VAPs: bridged, bss up, not dwds (wl01/wl11 are the hidden backhaul)
	if names := vapNames(r0); !reflect.DeepEqual(names, []string{"wl02"}) {
		t.Errorf("wl0 VAPs = %v", names)
	}
	if names := vapNames(r1); !reflect.DeepEqual(names, []string{"wl12", "wl13"}) {
		t.Errorf("wl1 VAPs = %v", names)
	}
	v := r1.VAPs[1]
	if v.SSID != "olive#" || v.BSSID != "be:a7:b9:3e:17:06" || v.Encryption != "psk+sae" || v.Phy != "wl1" ||
		v.Channel != 44 || v.Mode != "Master" || len(v.Stations) != 2 || v.Stats["tx_bytes"] == 0 || v.VAPs != nil {
		t.Errorf("wl13 = %+v", strip(v))
	}
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			for _, st := range v.Stations {
				if st.Noise != r.Noise {
					t.Errorf("%s %s noise %d, radio %d", v.Iface, st.MAC, st.Noise, r.Noise)
				}
				if r.Band == "ng" && st.VHT {
					t.Errorf("%s %s: 11ac on 2.4 GHz", v.Iface, st.MAC)
				}
			}
		}
	}
	if n := len(r0.VAPs[0].Stations); n != 4 {
		t.Errorf("wl02 has %d stations", n)
	}

	// exec budget: 8 radio getters + 3 sta_info on a cached collection
	before := len(fr.callList())
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(fr.callList()) - before; n != 11 {
		t.Errorf("second Collect ran %d wl calls, want 11: %v", n, fr.callList()[before:])
	}
}

func strip(r apstate.Radio) apstate.Radio { r.VAPs, r.Stations = nil, nil; return r }

func vapNames(r apstate.Radio) []string {
	var out []string
	for _, v := range r.VAPs {
		out = append(out, v.Iface)
	}
	return out
}

func TestCollectVAPSelection(t *testing.T) {
	c, fr, now := newTestCollector(t)
	root := c.opt.Root
	// bridge the backhaul wl11 (dwds=1) and the down wl03: neither is user-facing
	for _, d := range []string{"wl11", "wl03"} {
		p := filepath.Join(root, devPath(d, "brport"))
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := vapNames(s.Radios[1]); !reflect.DeepEqual(got, []string{"wl12", "wl13"}) {
		t.Errorf("wl1 VAPs = %v", got)
	}
	if got := vapNames(s.Radios[0]); !reflect.DeepEqual(got, []string{"wl02"}) {
		t.Errorf("wl0 VAPs = %v", got)
	}
	probed := map[string]bool{}
	for _, call := range fr.callList() {
		probed[call] = true
	}
	if !probed["wl -i wl11 dwds"] || probed["wl -i wl11 ssid"] || probed["wl -i wl03 dwds"] {
		t.Error("probe order: dwds only for up BSSes, ssid only for non-dwds")
	}

	// wl13 goes down: picked up at the next refresh, not before
	fr.set("wl -i wl13 bss", response{out: "down\n"})
	*now = now.Add(30 * time.Second)
	s, _ = c.Collect(context.Background())
	if got := vapNames(s.Radios[1]); len(got) != 2 {
		t.Errorf("before refresh: %v", got)
	}
	*now = now.Add(31 * time.Second)
	s, _ = c.Collect(context.Background())
	if got := vapNames(s.Radios[1]); !reflect.DeepEqual(got, []string{"wl12"}) {
		t.Errorf("after refresh: %v", got)
	}

	// leaving the bridge takes effect at once (file read every time)
	if err := os.RemoveAll(filepath.Join(root, devPath("wl12", "brport"))); err != nil {
		t.Fatal(err)
	}
	s, _ = c.Collect(context.Background())
	if got := vapNames(s.Radios[1]); len(got) != 0 {
		t.Errorf("unbridged: %v", got)
	}
}

func TestCollectErrors(t *testing.T) {
	c, fr, _ := newTestCollector(t)
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	// a failed client read fails the collection and forces a re-probe
	fr.set("wl -i wl12 sta_info all", response{err: errors.New("wl: Bad Argument")}, response{out: ""})
	if _, err := c.Collect(context.Background()); err == nil || !strings.Contains(err.Error(), "wl12 sta_info") {
		t.Errorf("err = %v", err)
	}
	before := len(fr.callList())
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !contains(fr.callList()[before:], "wl -i wl12 bss") {
		t.Error("no re-probe after a failed sta_info")
	}
	// measurement getters failing leave zeros, not an error
	fr.set("wl -i wl1 noise", response{err: errors.New("wl: Not Ready")})
	fr.set("wl -i wl1 chanim_stats us", response{err: errors.New("wl: Not Ready")})
	fr.set("wl -i wl1 txpwr_target_max", response{out: "garbage"})
	s, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := s.Radios[1]; r.Noise != 0 || r.TxPower != 0 || r.Channel != 44 {
		t.Errorf("degraded radio = %+v", strip(r))
	}
	// chanspec is essential
	fr.set("wl -i wl0 chanspec", response{out: "nonsense"})
	if _, err := c.Collect(context.Background()); err == nil {
		t.Error("bad chanspec accepted")
	}
	// missing /proc is fatal
	c2, _, _ := newTestCollector(t)
	os.Remove(filepath.Join(c2.opt.Root, "proc/meminfo"))
	if _, err := c2.Collect(context.Background()); err == nil {
		t.Error("missing /proc/meminfo accepted")
	}
	// no radios
	c3 := New(Options{Root: t.TempDir(), Run: &fakeRunner{}})
	os.MkdirAll(filepath.Join(c3.opt.Root, "sys/class/net/eth0"), 0o755)
	if _, err := c3.Collect(context.Background()); !errors.Is(err, errNoRadios) {
		t.Errorf("no radios: %v", err)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestCaps(t *testing.T) {
	c, fr, _ := newTestCollector(t)
	caps, err := c.Caps(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	checkReadOnly(t, fr.callList())
	eleven := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	unii := []int{36, 40, 44, 48, 149, 153, 157, 161}
	want := Caps{
		Country: "US", MaxBSS: 8,
		Bands: map[string]BandCaps{
			"ng": {Channels: map[int][]int{20: eleven, 40: eleven}, TxMinDBm: 5, TxMaxDBm: 25, NSS: 2, HT: true, HE: true, MaxListedWidth: 40},
			"na": {Channels: map[int][]int{20: append(append([]int{}, unii...), 165), 40: unii, 80: unii},
				TxMinDBm: 5, TxMaxDBm: 25, NSS: 2, HT: true, VHT: true, HE: true, MaxListedWidth: 80},
		},
	}
	if !reflect.DeepEqual(caps, want) {
		gj, _ := json.Marshal(caps)
		t.Errorf("caps = %s", gj)
	}
	// cached until Invalidate
	n := len(fr.callList())
	c.Caps(context.Background())
	if len(fr.callList()) != n {
		t.Error("Caps not cached")
	}
	c.Invalidate()
	c.Caps(context.Background())
	if len(fr.callList()) == n {
		t.Error("Invalidate did not drop the cache")
	}

	// DFS appears with a country that allows 52-64
	fr.set("wl -i wl1 chanspecs", response{out: string(fixture(t, "wl_-i_wl1_chanspecs.txt")) + "52 (0xd034)\n64 (0xd040)\n"})
	c.Invalidate()
	caps, _ = c.Caps(context.Background())
	if !caps.Bands["na"].DFS || caps.Bands["ng"].DFS {
		t.Errorf("DFS: %+v", caps.Bands)
	}
}

// TestFields checks that Snapshot.Fields turns two collections into sane
// radio_table, vap_table, sta_table and port_table rows.
func TestFields(t *testing.T) {
	c, fr, now := newTestCollector(t)
	series := offsetSeries(t)
	for _, r := range []string{"wl0", "wl1"} {
		var rs []response
		for _, out := range series[r] {
			rs = append(rs, response{out: out})
		}
		fr.set("wl -i "+r+" chanim_stats us", rs...)
	}
	prev, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * time.Second)
	cur, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := cur.Fields(prev, apstate.CfgInfo{IDs: map[string]string{"Example Network": "wlan1"}}, nil)

	radios := m["radio_table"].([]map[string]any)
	if len(radios) != 2 || radios[0]["name"] != "wifi0" || radios[0]["radio"] != "ng" || radios[1]["radio"] != "na" {
		t.Fatalf("radio_table = %v", radios)
	}
	if radios[1]["channel"] != 44 || radios[1]["ht"] != "80" || radios[1]["nss"] != 2 || radios[1]["is_11ac"] != true ||
		radios[0]["is_11ac"] != false || radios[0]["max_txpower"] != 25 || radios[0]["min_txpower"] != 5 {
		t.Errorf("radio rows = %v / %v", radios[0], radios[1])
	}
	// wl0: Δactive 2008 ms, Δbusy 616 ms -> 31 %, rx 132 ms -> 7 %, tx 324 ms -> 16 %
	ath := radios[0]["athstats"].(map[string]any)
	if ath["cu_total"] != 31 || ath["cu_self_rx"] != 7 || ath["cu_self_tx"] != 16 || ath["cu_interf"] != 8 {
		t.Errorf("wl0 athstats = %v", ath)
	}

	vaps := m["vap_table"].([]map[string]any)
	if len(vaps) != 3 {
		t.Fatalf("vap_table has %d rows", len(vaps))
	}
	total := 0
	for _, v := range vaps {
		stas := v["sta_table"].([]map[string]any)
		total += len(stas)
		if v["num_sta"] != len(stas) || v["essid"] == "" || len(v["bssid"].(string)) != 17 || v["usage"] != "user" {
			t.Errorf("vap row = %v", v)
		}
		if v["essid"] == "Example Network" && v["id"] != "wlan1" {
			t.Errorf("wlan id missing: %v", v)
		}
		for _, st := range stas {
			sig, rssi := st["signal"].(int), st["rssi"].(int)
			if sig >= 0 || sig < -100 || rssi <= 0 || st["tx_rate"].(int) <= 0 || st["uptime"].(int64) <= 0 {
				t.Errorf("sta row = %v", st)
			}
			if _, ok := st["chwidth"]; !ok {
				t.Errorf("sta row without chwidth: %v", st)
			}
		}
	}
	if total != 9 || m["num_sta"] != 9 {
		t.Errorf("stations: %d in tables, num_sta %v", total, m["num_sta"])
	}

	ports := m["port_table"].([]map[string]any)
	if len(ports) != 2 || ports[0]["ifname"] != "eth1" || ports[0]["is_uplink"] != true || ports[0]["speed"] != 1000 ||
		ports[1]["ifname"] != "eth0" || ports[1]["up"] != false {
		t.Errorf("port_table = %v", ports)
	}
	if _, ok := ports[1]["mac_table"]; !ok {
		t.Error("downlink port without mac_table")
	}
	ifs := m["if_table"].([]map[string]any)
	if len(ifs) != 1 || ifs[0]["up"] != true || ifs[0]["speed"] != 1000 || m["uplink"] != "eth0" {
		t.Errorf("if_table = %v, uplink %v", ifs, m["uplink"])
	}
	sys := m["sys_stats"].(map[string]any)
	if sys["mem_total"] != int64(252152*1024) || sys["loadavg_1"] != "1.29" {
		t.Errorf("sys_stats = %v", sys)
	}

	// a fixed uplink overrides gateway detection
	c.opt.Uplink = "eth0"
	pinned, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pp := pinned.Fields(cur, apstate.CfgInfo{}, nil)["port_table"].([]map[string]any)
	if pp[0]["ifname"] != "eth0" {
		t.Errorf("pinned uplink: %v", pp[0])
	}
}

// chanimUs builds `wl chanim_stats us` output with one data row.
func chanimUs(key string, tx, inbss, busy, total uint64) string {
	return fmt.Sprintf("version: 3 \nus version: 2 \nchanspec  tx  inbss  obss  nocat  nopkt  doze  txop  goodtx  badtx  total_tm  busy_tm  pri20  sec20  sec40\n"+
		"%s  %d  %d  0  0  0  0  0  0  0  %d  %d  0  0  0\n", key, tx, inbss, total, busy)
}

// TestCollectSurveyStampedAtRead: the channel-use row is timed when it is
// read, so a slow call earlier in the same collection does not make a real
// interval look impossible.
func TestCollectSurveyStampedAtRead(t *testing.T) {
	c, fr, now := newTestCollector(t)
	slow := false
	c.opt.Run = runnerFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if slow && strings.Join(args, " ") == "-i wl02 sta_info all" {
			*now = now.Add(5 * time.Second) // a getter that hit its timeout
		}
		return fr.Run(ctx, name, args...)
	})
	fr.set("wl -i wl1 chanim_stats us",
		response{out: chanimUs("0xd02c", 1_000_000, 1_000_000, 2_000_000, 100_000_000)},
		response{out: chanimUs("0xd02c", 2_500_000, 2_500_000, 5_000_000, 115_000_000)})
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(10 * time.Second)
	slow = true
	s, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 15 s of counters read 15 s apart (10 s between collections + 5 s of
	// delay before wl1 was read)
	if got := s.Radios[1].Survey; got.Active != 15_000 || got.Busy != 4_500 || got.Tx != 1_500 {
		t.Errorf("wl1 survey = %+v", got)
	}
}

// TestCollectRadioSetChange: a radio that appears after the first read is
// picked up, and one that disappears no longer fails every collection.
func TestCollectRadioSetChange(t *testing.T) {
	c, _, _ := newTestCollector(t)
	wl1 := filepath.Join(c.opt.Root, "sys/class/net/wl1")
	if err := os.Rename(wl1, wl1+".gone"); err != nil {
		t.Fatal(err)
	}
	s, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Radios) != 1 || s.Radios[0].Band != "ng" {
		t.Fatalf("radios without wl1: %d", len(s.Radios))
	}
	if err := os.Rename(wl1+".gone", wl1); err != nil {
		t.Fatal(err)
	}
	if s, err = c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.Radios) != 2 || s.Radios[1].Band != "na" || len(s.Radios[1].VAPs) != 2 {
		t.Fatalf("wl1 not picked up: %d radios", len(s.Radios))
	}
	caps, _ := c.Caps(context.Background())
	if _, ok := caps.Bands["na"]; !ok {
		t.Error("Caps still without 5 GHz")
	}
	// the radio goes away again: the 2.4 GHz radio still reports
	if err := os.Rename(wl1, wl1+".gone"); err != nil {
		t.Fatal(err)
	}
	if s, err = c.Collect(context.Background()); err != nil || len(s.Radios) != 1 {
		t.Fatalf("after wl1 vanished: %v, %d radios", err, len(s.Radios))
	}
}

// wlN1 never carries a client SSID on the Deco (TP-Link's backhaul in
// observe mode, the agent hostapd's placeholder in takeover): it is not a
// user VAP even when it is up, bridged and its dwds cannot be read, so its
// counters never appear under a user VAP's name.
func TestCollectBackhaulNeverUserVAP(t *testing.T) {
	c, fr, _ := newTestCollector(t)
	root := c.opt.Root
	for _, d := range []string{"wl01", "wl11"} {
		if err := os.MkdirAll(filepath.Join(root, devPath(d, "brport")), 0o755); err != nil {
			t.Fatal(err)
		}
		fr.set("wl -i "+d+" bss", response{out: "up\n"})
		fr.set("wl -i "+d+" dwds", response{err: errors.New("wl: Unsupported")})
		fr.set("wl -i "+d+" ssid", response{out: "Current SSID: \"olive#\"\n"})
	}
	s, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			if v.Iface == "wl01" || v.Iface == "wl11" {
				t.Errorf("%s reported as a user VAP (ssid %q)", v.Iface, v.SSID)
			}
		}
	}
	if got := vapNames(s.Radios[1]); !reflect.DeepEqual(got, []string{"wl12", "wl13"}) {
		t.Errorf("wl1 VAPs = %v", got)
	}
	for _, n := range []string{"wl1", "wl11", "wl12", "wl01", "wl02", "wl0", "eth0", "wl111"} {
		want := n == "wl11" || n == "wl01"
		if backhaulVif(n) != want {
			t.Errorf("backhaulVif(%s) = %v", n, !want)
		}
	}
}
