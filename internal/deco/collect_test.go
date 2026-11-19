// SPDX-License-Identifier: GPL-2.0-or-later

package deco

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/openwrt"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

var fixtureAt = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

var testUnits = []Unit{
	{Name: "deco-241", MAC: "b0:a7:b9:3e:16:94", IP: "192.168.0.241"},
	{Name: "deco-205", MAC: "B0-A7-B9-3E-17-00", IP: "192.168.0.205"},
	{Name: "deco-232", MAC: "b0a7b93e15fc", IP: "192.168.0.232"},
}

// loadState reads testdata/meshstate.json, a MeshState as the Mesh caches
// it (field names and value shapes from schemas.go).
func loadState(t *testing.T) *MeshState {
	t.Helper()
	b, err := os.ReadFile("testdata/meshstate.json")
	if err != nil {
		t.Fatal(err)
	}
	var s MeshState
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func newCollector(t *testing.T, u Unit) *Collector {
	t.Helper()
	c, err := NewCollector(u, CollectOptions{Netmask: "255.255.255.0", Gateway: "192.168.0.1"}, fixtureAt.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCollectGolden(t *testing.T) {
	s := loadState(t)
	for _, u := range testUnits {
		t.Run(u.Name, func(t *testing.T) {
			snap, err := newCollector(t, u).Collect(s, fixtureAt.Add(15*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(snap, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			p := filepath.Join("testdata", "collect-"+u.Name+".golden.json")
			if *update {
				if err := os.WriteFile(p, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("%v (run go test -run TestCollectGolden -update)", err)
			}
			if string(got) != string(want) {
				t.Errorf("snapshot differs from %s:\n%s", p, got)
			}
		})
	}
}

func vapsOf(r openwrt.Radio) map[string]openwrt.Radio {
	m := map[string]openwrt.Radio{}
	for _, v := range r.VAPs {
		m[v.Iface] = v
	}
	return m
}

func stationMACs(v openwrt.Radio) string {
	var out []string
	for _, st := range v.Stations {
		out = append(out, st.MAC)
	}
	return strings.Join(out, ",")
}

func TestCollectMapping(t *testing.T) {
	s := loadState(t)
	now := fixtureAt.Add(15 * time.Second)
	tests := []struct {
		unit                     Unit
		host, release            string
		uptime                   int64
		ch2, ch5, w2, w5         int
		ng, ngGuest, na, naGuest string // station MACs per VAP
		arp                      map[string]string
		ports                    string // name:up:speed, ...
		fdb                      string
		online                   bool
	}{
		{
			unit: testUnits[0], host: "Living Room", release: "1.1.3 Build 20240621 Rel. 52617", uptime: 86400,
			ch2: 8, ch5: 44, w2: 40, w5: 80,
			ng: "aa:bb:cc:dd:ee:02", ngGuest: "aa:bb:cc:dd:ee:03",
			arp: map[string]string{"aa:bb:cc:dd:ee:02": "192.168.0.51", "aa:bb:cc:dd:ee:03": "192.168.0.52",
				"aa:bb:cc:dd:ee:04": "192.168.0.53"},
			ports: "eth0:true:1000,eth1:true:100", fdb: "aa:bb:cc:dd:ee:04@2", online: true,
		},
		{
			unit: testUnits[1], host: "office", release: "1.1.3 Build 20240621 Rel. 52617",
			uptime: 0,                          // no runtime: seconds since first seen online
			ch2:    8, ch5: 44, w2: 40, w5: 80, // no TDP reply: radio.channel, else the backhaul channel
			na:    "aa:bb:cc:dd:ee:01",
			arp:   map[string]string{"aa:bb:cc:dd:ee:01": "192.168.0.50", "b0:a7:b9:3e:16:94": "192.168.0.241"},
			ports: "eth0:true:1000,eth1:false:0", online: true,
		},
		{
			unit: testUnits[2], host: "deco-232", ch2: 1, ch5: 36, w2: 40, w5: 80,
			ng:    "aa:bb:cc:dd:ee:08", // interface iot goes on the main VAP
			arp:   map[string]string{"aa:bb:cc:dd:ee:08": "192.168.0.57", "b0:a7:b9:3e:16:94": "192.168.0.241"},
			ports: "eth0:true:1000", online: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.unit.Name, func(t *testing.T) {
			snap, err := newCollector(t, tt.unit).Collect(s, now)
			if err != nil {
				t.Fatal(err)
			}
			if snap.MAC != NormMAC(tt.unit.MAC) || snap.IP != tt.unit.IP || snap.Hostname != tt.host ||
				snap.Release != tt.release || snap.Uptime != tt.uptime || snap.UplinkName != "eth0" ||
				snap.Netmask != "255.255.255.0" || snap.Gateway != "192.168.0.1" {
				t.Errorf("identity: mac=%s ip=%s host=%q rel=%q up=%d", snap.MAC, snap.IP, snap.Hostname, snap.Release, snap.Uptime)
			}
			if len(snap.Radios) != 2 || snap.Radios[0].Band != "ng" || snap.Radios[1].Band != "na" {
				t.Fatalf("radios: %+v", snap.Radios)
			}
			r2, r5 := snap.Radios[0], snap.Radios[1]
			if r2.Channel != tt.ch2 || r5.Channel != tt.ch5 || r2.Width != tt.w2 || r5.Width != tt.w5 {
				t.Errorf("channels %d/%d widths %d/%d", r2.Channel, r5.Channel, r2.Width, r5.Width)
			}
			if !r2.HE || !r5.HE || r2.VHT || !r5.VHT || r2.NSS != 2 || r2.Noise != noiseFloor || r2.TxPower == 0 {
				t.Errorf("radio caps: %+v", r2)
			}
			v2, v5 := vapsOf(r2), vapsOf(r5)
			if v2["main"].SSID != "Home" || v2["guest"].SSID != "Home-Guest" || v5["main"].SSID != "Home" || len(r2.VAPs) != 2 {
				t.Errorf("vaps: %+v / %+v", v2, v5)
			}
			for _, x := range []struct{ got, want string }{
				{stationMACs(v2["main"]), tt.ng}, {stationMACs(v2["guest"]), tt.ngGuest},
				{stationMACs(v5["main"]), tt.na}, {stationMACs(v5["guest"]), tt.naGuest},
			} {
				if x.got != x.want {
					t.Errorf("stations %q, want %q", x.got, x.want)
				}
			}
			if len(snap.ARP) != len(tt.arp) {
				t.Errorf("arp %v, want %v", snap.ARP, tt.arp)
			}
			for k, v := range tt.arp {
				if snap.ARP[k] != v {
					t.Errorf("arp[%s]=%q want %q", k, snap.ARP[k], v)
				}
			}
			var ports, fdb []string
			for _, p := range snap.Ports {
				ports = append(ports, p.Name+":"+fmtBool(&p.Up)+":"+itoa(p.Speed))
			}
			for _, e := range snap.FDB {
				fdb = append(fdb, e.MAC+"@"+itoa(e.Port))
			}
			if strings.Join(ports, ",") != tt.ports || strings.Join(fdb, ",") != tt.fdb {
				t.Errorf("ports %v fdb %v", ports, fdb)
			}
			if got := UnitOnline(FindUnit(s, tt.unit.MAC)); got != tt.online {
				t.Errorf("online %t", got)
			}
		})
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestCollectStations(t *testing.T) {
	s := loadState(t)
	now := fixtureAt.Add(15 * time.Second)
	m, _ := newCollector(t, testUnits[0]).Collect(s, now)
	sat, _ := newCollector(t, testUnits[1]).Collect(s, now)
	laptop := vapsOf(m.Radios[0])["main"].Stations[0]
	tablet := vapsOf(m.Radios[0])["guest"].Stations[0]
	phone := vapsOf(sat.Radios[1])["main"].Stations[0]
	tests := []struct {
		name                string
		st                  openwrt.Station
		signal, tx, rx, mhz int
		conn                int64
		ht, vht, he         bool
	}{
		{"phone dBm, wifi6, 80 MHz", phone, -55, 866000, 780000, 80, 3600, true, true, true},
		{"laptop bars, access_time", laptop, -60, 144000, 72000, 0, 615, true, false, false},
		{"tablet combo key", tablet, -67, 300000, 0, 0, 0, true, false, false},
	}
	for _, tt := range tests {
		st := tt.st
		if st.Signal != tt.signal || st.TxRate != tt.tx || st.RxRate != tt.rx || st.MHz != tt.mhz ||
			st.Connected != tt.conn || st.HT != tt.ht || st.VHT != tt.vht || st.HE != tt.he ||
			st.Noise != noiseFloor || !st.Authorized || st.Signal-st.Noise <= 0 {
			t.Errorf("%s: %+v", tt.name, st)
		}
	}
	if got := GuestAuthorized(m); len(got) != 2 || !got["aa:bb:cc:dd:ee:03"] {
		t.Errorf("guest authorized: %v", got)
	}
}

// The inform payload built from a collected snapshot is complete: radio
// rows for both bands, VAPs with clients, rssi above 0, wired clients on the
// LAN port, and the guest flag from the controller's config.
func TestCollectFields(t *testing.T) {
	s := loadState(t)
	snap, err := newCollector(t, testUnits[0]).Collect(s, fixtureAt.Add(15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	info := openwrt.CfgInfo{
		IDs:      map[string]string{"Home": "w1", "Home-Guest": "w2"},
		DevName:  map[string]string{"Home|wifi0": "ath0", "Home-Guest|wifi0": "ath1", "Home|wifi1": "ath2", "Home-Guest|wifi1": "ath3"},
		GuestVAP: map[string]bool{"ath1": true, "ath3": true},
	}
	info.Authorized = GuestAuthorized(snap)
	f := snap.Fields(nil, info, nil)
	if rt := f["radio_table"].([]map[string]any); len(rt) != 2 || rt[0]["radio"] != "ng" || rt[1]["radio"] != "na" || rt[1]["channel"] != 44 {
		t.Fatalf("radio_table: %v", rt)
	}
	vaps := f["vap_table"].([]map[string]any)
	if len(vaps) != 4 {
		t.Fatalf("vap_table: %d rows", len(vaps))
	}
	byName := map[string]map[string]any{}
	for _, v := range vaps {
		byName[v["name"].(string)] = v
	}
	if byName["ath0"]["id"] != "w1" || byName["ath1"]["is_guest"] != true || byName["ath0"]["is_guest"] != false {
		t.Fatalf("vap ids/guest: %v", vaps)
	}
	st := byName["ath1"]["sta_table"].([]map[string]any)
	if len(st) != 1 || st[0]["authorized"] != true || st[0]["ip"] != "192.168.0.52" || st[0]["rssi"].(int) <= 0 {
		t.Fatalf("guest sta_table: %v", st)
	}
	if f["num_sta"] != 2 {
		t.Errorf("num_sta %v", f["num_sta"])
	}
	it := f["if_table"].([]map[string]any)
	if len(it) != 1 || it[0]["up"] != true || it[0]["speed"] != 1000 || it[0]["mac"] != "b0:a7:b9:3e:16:94" {
		t.Fatalf("if_table: %v", it)
	}
	pt := f["port_table"].([]map[string]any)
	if len(pt) != 2 || pt[0]["is_uplink"] != true {
		t.Fatalf("port_table: %v", pt)
	}
	mt := pt[1]["mac_table"].([]map[string]any)
	if len(mt) != 1 || mt[0]["mac"] != "aa:bb:cc:dd:ee:04" {
		t.Fatalf("mac_table: %v", mt)
	}
}

func TestCollectByteCounters(t *testing.T) {
	s := loadState(t)
	c := newCollector(t, testUnits[1])
	phoneBytes := func(snap *openwrt.Snapshot) (int64, int64) {
		st := vapsOf(snap.Radios[1])["main"].Stations[0]
		return st.TxBytes, st.RxBytes
	}
	snap, _ := c.Collect(s, fixtureAt)
	if tx, rx := phoneBytes(snap); tx != 0 || rx != 0 {
		t.Fatalf("first sample integrated: %d/%d", tx, rx)
	}
	// 15 s at 2000 kbps down / 100 kbps up.
	s.Speeds.At = fixtureAt.Add(15 * time.Second)
	snap, _ = c.Collect(s, s.Speeds.At)
	if tx, rx := phoneBytes(snap); tx != 3_750_000 || rx != 187_500 {
		t.Fatalf("after 15 s: tx=%d rx=%d", tx, rx)
	}
	v := vapsOf(snap.Radios[1])["main"]
	if v.Stats["tx_bytes"] != 3_750_000 || snap.Ports[0].RxBytes != 3_750_000 || snap.Ports[0].TxBytes != 187_500 {
		t.Fatalf("vap %v port %+v", v.Stats, snap.Ports[0])
	}
	// The same sample again adds nothing.
	snap, _ = c.Collect(s, s.Speeds.At.Add(5*time.Second))
	if tx, _ := phoneBytes(snap); tx != 3_750_000 {
		t.Fatalf("re-integrated: %d", tx)
	}
	// A long gap is capped at MaxGap (60 s).
	s.Speeds.At = s.Speeds.At.Add(10 * time.Minute)
	s.Devices.At, s.Clients.At = s.Speeds.At, s.Speeds.At // the lists were re-read too
	snap, _ = c.Collect(s, s.Speeds.At)
	if tx, _ := phoneBytes(snap); tx != 3_750_000+15_000_000 {
		t.Fatalf("gap not capped: %d", tx)
	}
}

func TestCollectUptimeFallback(t *testing.T) {
	s := loadState(t)
	c := newCollector(t, testUnits[1])
	snap, _ := c.Collect(s, fixtureAt)
	if snap.Uptime != 0 {
		t.Fatalf("uptime %d", snap.Uptime)
	}
	snap, _ = c.Collect(s, fixtureAt.Add(90*time.Second))
	if snap.Uptime != 90 {
		t.Fatalf("uptime %d, want 90", snap.Uptime)
	}
	// Offline resets the clock.
	off := *s
	devs := *s.Devices.Value
	devs.DeviceList = append([]Deco(nil), devs.DeviceList...)
	devs.DeviceList[1].InetStatus = InetOffline
	off.Devices.Value = &devs
	c.Collect(&off, fixtureAt.Add(100*time.Second))
	snap, _ = c.Collect(s, fixtureAt.Add(130*time.Second))
	if snap.Uptime != 0 {
		t.Fatalf("uptime after offline %d", snap.Uptime)
	}
}

func TestCollectErrorsAndSkeleton(t *testing.T) {
	c := newCollector(t, testUnits[0])
	if _, err := c.Collect(&MeshState{}, fixtureAt); !errors.Is(err, ErrNoDeviceList) {
		t.Fatalf("empty state: %v", err)
	}
	other := newCollector(t, Unit{Name: "x", MAC: "02:00:00:00:00:01"})
	if _, err := other.Collect(loadState(t), fixtureAt); !errors.Is(err, ErrUnitAbsent) {
		t.Fatalf("absent unit: %v", err)
	}
	if _, err := NewCollector(Unit{MAC: "nope"}, CollectOptions{}, fixtureAt); err == nil {
		t.Fatal("bad mac accepted")
	}
	sk := c.Skeleton(fixtureAt)
	if sk.Uptime != 3600 || sk.MAC != "b0:a7:b9:3e:16:94" || len(sk.Radios) != 2 || len(sk.Ports) != 1 || sk.ARP == nil {
		t.Fatalf("skeleton: %+v", sk)
	}
	f := sk.Fields(nil, openwrt.CfgInfo{}, nil)
	if len(f["radio_table"].([]map[string]any)) != 2 || f["uptime"] != int64(3600) || f["if_table"] == nil {
		t.Fatalf("skeleton fields: %v", f)
	}
	// Only the master's wireless info is unknown: radios still carry VAP-less rows.
	s := loadState(t)
	s.Wireless = Polled[WirelessInfo]{}
	snap, err := c.Collect(s, fixtureAt)
	if err != nil || len(snap.Radios) != 2 || len(snap.Radios[0].VAPs) != 2 {
		// stations still appear, on VAPs created from the client list
		t.Fatalf("no wireless info: %v %+v", err, snap)
	}
}

func TestSyntheticBSSID(t *testing.T) {
	unit := "b0:a7:b9:3e:16:94"
	seen := map[string]bool{unit: true}
	for _, band := range []string{"ng", "na"} {
		for _, guest := range []bool{false, true} {
			b := SyntheticBSSID(unit, band, guest)
			if seen[b] || len(b) != 17 || b[3:14] != unit[3:14] || b[:2] != "b2" {
				t.Fatalf("bssid %s (band %s guest %t)", b, band, guest)
			}
			seen[b] = true
		}
	}
	if SyntheticBSSID("x", "ng", false) != "" {
		t.Fatal("bad mac")
	}
}

func TestLinkHelpers(t *testing.T) {
	for key, want := range map[string]string{"band2_4": "ng", "band2": "ng", "band5": "na", "band5_1": "na", "band5_2": "na",
		"band2+band5": "ng", "band5+band6": "na", "wired": "wired", "plc": "wired", "band6": "", "zigbee": "", "": ""} {
		if got := linkBand(key); got != want {
			t.Errorf("linkBand(%q)=%q want %q", key, got, want)
		}
	}
	for s, want := range map[string]int{"HE80": 80, "HT20": 20, "VHT160": 160, "80MHz": 80, "40": 40, "": 0, "auto": 0, "HE33": 0} {
		if got := widthOf(s); got != want {
			t.Errorf("widthOf(%q)=%d want %d", s, got, want)
		}
	}
	for _, tt := range []struct {
		ld   LinkedDevice
		want int
	}{
		{LinkedDevice{SignalStrength: ClientSignalLevel{"band5": -48}}, -48},
		{LinkedDevice{SignalStrength: ClientSignalLevel{"band5": 70}, SignalLevel: ClientSignalLevel{"band5": 1}}, -80},
		{LinkedDevice{SignalLevel: ClientSignalLevel{"BAND5": 4}}, -50},
		{LinkedDevice{SignalLevel: ClientSignalLevel{"band2_4": 2}}, -70}, // the only entry
		{LinkedDevice{}, defaultSignal},
	} {
		if got := signalOf(&tt.ld, "band5"); got != tt.want {
			t.Errorf("signalOf(%+v)=%d want %d", tt.ld, got, tt.want)
		}
	}
	if connKey([]Enum{" Band5 ", "wired"}) != "band5" || connKey(nil) != "" {
		t.Error("connKey")
	}
}

// Through the real Mesh and emulator: TDP replies land in MeshState.Units,
// RequestPoll re-reads ahead of the interval, and the cache maps to a
// snapshot with the emulated client on the satellite's 5 GHz VAP.
func TestCollectFromMesh(t *testing.T) {
	r := newRig(t, nil)
	r.step()
	s := r.m.Snapshot()
	if len(s.Units) != 3 || s.Units["b0:a7:b9:3e:17:00"] == nil || s.Units["b0:a7:b9:3e:17:00"].DeviceID != tdpID205 {
		t.Fatalf("units: %v", s.Units)
	}
	ports := r.emu.count(OpGetDeviceEthPort)
	r.clock.Add(time.Second)
	r.step()
	if r.emu.count(OpGetDeviceEthPort) != ports {
		t.Fatal("ports polled before their interval")
	}
	r.m.RequestPoll(OpGetDeviceEthPort)
	r.step()
	if r.emu.count(OpGetDeviceEthPort) != ports+1 {
		t.Fatal("RequestPoll did not re-read ports")
	}
	c, err := NewCollector(Unit{Name: "deco-205", MAC: "b0:a7:b9:3e:17:00", IP: "192.168.0.205"}, CollectOptions{}, r.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	s = r.m.Snapshot()
	snap, err := c.Collect(&s, r.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	v := vapsOf(snap.Radios[1])["main"]
	if v.SSID != "Home" || stationMACs(v) != "aa:bb:cc:dd:ee:01" || snap.ARP["aa:bb:cc:dd:ee:01"] != "192.168.0.50" {
		t.Fatalf("5 GHz main VAP: %+v arp %v", v, snap.ARP)
	}
	r.noSecrets()
}

// A client list that stopped refreshing (failed polls, or disabled for the
// session) or predates the current session is never reported as current.
func TestCollectStaleClients(t *testing.T) {
	now := fixtureAt.Add(15 * time.Second)
	for _, tc := range []struct {
		name     string
		edit     func(*MeshState)
		now      time.Time
		stations bool
	}{
		{"fresh", func(*MeshState) {}, now, true},
		{"clients past MaxAge", func(*MeshState) {}, fixtureAt.Add(46 * time.Second), false},
		{"clients disabled", func(s *MeshState) { s.Clients.Disabled = true }, now, false},
		{"device_list past MaxAge", func(s *MeshState) { s.Clients.At = fixtureAt.Add(time.Minute) }, fixtureAt.Add(time.Minute), false},
		{"read before the reconnect", func(s *MeshState) { s.ConnectedSince = fixtureAt.Add(5 * time.Second) }, now, false},
		{"session down, within MaxAge", func(s *MeshState) { s.Connected, s.DownSince = false, now }, now, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := loadState(t)
			tc.edit(s)
			snap, err := newCollector(t, testUnits[1]).Collect(s, tc.now)
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, r := range snap.Radios {
				for _, v := range vapsOf(r) {
					n += len(v.Stations)
				}
			}
			if (n > 0) != tc.stations {
				t.Fatalf("%d stations, want stations=%v", n, tc.stations)
			}
		})
	}
}

// The finding's case: 0x4012 disabled for the session keeps the old client
// list in the cache, but Collect no longer uses it: 0x4014 still shows the
// phone present, but nothing places it on a unit.
func TestCollectFromMeshClientsDisabled(t *testing.T) {
	r := newRig(t, nil)
	r.step()
	c, err := NewCollector(Unit{Name: "deco-205", MAC: "b0:a7:b9:3e:17:00", IP: "192.168.0.205"}, CollectOptions{}, r.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	s := r.m.Snapshot()
	if snap, _ := c.Collect(&s, r.clock.Now()); stationMACs(vapsOf(snap.Radios[1])["main"]) != "aa:bb:cc:dd:ee:01" {
		t.Fatal("no station while the list is fresh")
	}
	r.emu.set(OpGetClientList, `{"error_code":-40210}`)
	for range 4 {
		r.clock.Add(MinClientsEvery)
		r.step()
	}
	s = r.m.Snapshot()
	if !s.Connected || !s.Clients.Disabled || s.Clients.Value == nil {
		t.Fatalf("setup: %+v", s.Clients)
	}
	snap, err := c.Collect(&s, r.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := stationMACs(vapsOf(snap.Radios[1])["main"]); got != "" {
		t.Fatalf("frozen client list reported: %s", got)
	}
}
