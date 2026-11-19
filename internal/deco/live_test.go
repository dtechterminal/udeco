// SPDX-License-Identifier: GPL-2.0-or-later

package deco

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// liveState is meshstate.json (device_list, Wi-Fi, ports) with the client
// lists of the live fw 1.3.0 shape: 0x4012 is the settings-only reply (every
// entry online:false, keys as the live sample, a few with a last known
// linked_device_info), read 9 minutes ago; 0x4014 and 0x4040 are fresh.
func liveState(t *testing.T) *MeshState {
	t.Helper()
	s := loadState(t)
	var cl ClientListResult
	var sp ClientSpeedListResult
	var iot IoTClientListResult
	loadJSON(t, "testdata/live-clientlist-settings.json", &cl)
	loadJSON(t, "testdata/live-speeds.json", &sp)
	loadJSON(t, "testdata/live-iot.json", &iot)
	s.Clients = Polled[ClientListResult]{Value: &cl, At: fixtureAt.Add(-9 * time.Minute), OK: true}
	s.Speeds = Polled[ClientSpeedListResult]{Value: &sp, At: fixtureAt, OK: true}
	s.IoT = Polled[IoTClientListResult]{Value: &iot, At: fixtureAt, OK: true}
	return s
}

func liveByMAC(lv *LiveView) map[string]LiveClient {
	m := map[string]LiveClient{}
	for _, c := range lv.Clients {
		m[c.MAC] = c
	}
	return m
}

func TestLiveFixturesDecode(t *testing.T) {
	s := liveState(t)
	for _, c := range s.Clients.Value.ClientList {
		if c.IsOnline() {
			t.Fatalf("settings-only fixture has an online entry: %s", c.MAC)
		}
	}
	if n := len(s.Clients.Value.ClientList); n != 7 || s.Clients.Value.PriorityCountMax != 256 {
		t.Fatalf("0x4012 fixture: %d entries %+v", n, s.Clients.Value)
	}
	iot := s.IoT.Value
	if len(iot.IoTClientList) != 4 || !iot.ScanStatus.Is("idle") || iot.IoTCountPerCateMax != 64 {
		t.Fatalf("0x4040 fixture: %+v", iot)
	}
	plug, hub, door, lock := iot.IoTClientList[0], iot.IoTClientList[1], iot.IoTClientList[2], iot.IoTClientList[3]
	if !plug.IsOnline() || plug.Name != "plug" || plug.TypeName != "Smart Plug" || *plug.OnlineTime != 5400 ||
		plug.DetailMAC() != "50-C7-BF-11-22-33" || plug.DetailIP() != "192.168.0.80" || plug.LinkedDeviceInfo.DeviceID != "dev205" {
		t.Fatalf("plug: %+v", plug)
	}
	if hub.DetailMAC() != "50-C7-BF-44-55-66" || hub.Category != "5" || door.IsOnline() || door.DetailMAC() != "" || lock.DetailMAC() != "" {
		t.Fatalf("hub %+v door %+v lock %+v", hub, door, lock)
	}
	if s.Speeds.Value.ClientListSpeed[3].UpSpeed != 16 {
		t.Fatalf("quoted speed: %+v", s.Speeds.Value.ClientListSpeed[3])
	}
}

func TestLiveClientsSettingsOnlyReply(t *testing.T) {
	s := liveState(t)
	now := fixtureAt.Add(15 * time.Second)
	lv := LiveClients(s, now, defaultMaxAge)
	if lv == nil {
		t.Fatal("no live view")
	}
	if !slices.Equal(lv.Sources, []string{SrcSpeeds, SrcIoT}) {
		t.Fatalf("sources %v (0x4012 is 9 min old: enrichment only)", lv.Sources)
	}
	by := liveByMAC(lv)
	for _, deco := range []string{"b2:a7:b9:3e:17:02", "b0:a7:b9:3e:15:fc"} {
		if _, ok := by[deco]; ok {
			t.Errorf("unit MAC %s listed as a client", deco)
		}
	}
	tests := []struct {
		mac, device, link, by, name, ctype, iface, ip string
		seen                                          []string
	}{
		{"8e:56:d7:04:bb:8f", "", "", "", "phone-a", "phone", "main", "", []string{SrcSpeeds}},
		{"02:42:c0:59:ef:05", "", "", "", "Home Server", "Computer", "main", "", []string{SrcSpeeds}},
		{"44:07:0b:11:22:33", "dev205", "band5", SrcClientsLast, "tv-a", "Television", "main", "", []string{SrcSpeeds}},
		{"f4:cf:a2:11:22:33", masterRawID, "band2_4", SrcClientsLast, "guest-phone", "Mobile", "guest", "", []string{SrcSpeeds}},
		{"3a:11:22:33:44:55", "", "", "", "", "", "", "", []string{SrcSpeeds}},
		{"50:c7:bf:11:22:33", "dev205", "band2_4", SrcIoT, "plug", "", "main", "192.168.0.80", []string{SrcIoT}},
		{"50:c7:bf:44:55:66", masterRawID, "wired", SrcIoT, "hub", "", "", "192.168.0.81", []string{SrcIoT}},
	}
	if len(lv.Clients) != len(tests) || lv.Placed != 4 || lv.Unplaced != 3 {
		t.Fatalf("%d clients, placed %d, unplaced %d: %+v", len(lv.Clients), lv.Placed, lv.Unplaced, lv.Clients)
	}
	for _, tt := range tests {
		c, ok := by[tt.mac]
		if !ok {
			t.Errorf("%s missing", tt.mac)
			continue
		}
		if c.DeviceID != tt.device || c.Link != tt.link || c.PlacedBy != tt.by || c.Name != tt.name ||
			c.ClientType != tt.ctype || c.Interface != tt.iface || c.IP != tt.ip || !slices.Equal(c.Seen, tt.seen) {
			t.Errorf("%s: %+v", tt.mac, c)
		}
	}
	// Offline settings entries that no fast list shows are not present.
	for _, absent := range []string{"9c:9e:6e:11:22:33", "62:fe:8b:aa:e3:3a", "c8:5c:cc:11:22:33"} {
		if _, ok := by[absent]; ok {
			t.Errorf("%s reported present from the settings list", absent)
		}
	}
}

// Collect places what LiveClients placed: the right unit, band, VAP and
// port; unplaced clients are not invented onto a radio.
func TestCollectFromLiveLists(t *testing.T) {
	s := liveState(t)
	now := fixtureAt.Add(15 * time.Second)
	master, err := newCollector(t, testUnits[0]).Collect(s, now)
	if err != nil {
		t.Fatal(err)
	}
	sat, err := newCollector(t, testUnits[1]).Collect(s, now)
	if err != nil {
		t.Fatal(err)
	}
	off, err := newCollector(t, testUnits[2]).Collect(s, now)
	if err != nil {
		t.Fatal(err)
	}
	m2, s2, s5 := vapsOf(master.Radios[0]), vapsOf(sat.Radios[0]), vapsOf(sat.Radios[1])
	if got := stationMACs(m2["guest"]); got != "f4:cf:a2:11:22:33" {
		t.Errorf("master 2.4 GHz guest: %q", got)
	}
	if got := stationMACs(m2["main"]) + stationMACs(vapsOf(master.Radios[1])["main"]); got != "" {
		t.Errorf("master main VAPs: %q (unplaced clients must not be invented)", got)
	}
	if got := stationMACs(s5["main"]); got != "44:07:0b:11:22:33" {
		t.Errorf("deco-205 5 GHz: %q", got)
	}
	if got := stationMACs(s2["main"]); got != "50:c7:bf:11:22:33" {
		t.Errorf("deco-205 2.4 GHz: %q", got)
	}
	if plug := s2["main"].Stations[0]; plug.Signal != -61 || plug.Connected != 5400 || plug.HE {
		t.Errorf("plug station: %+v", plug)
	}
	if tv := s5["main"].Stations[0]; tv.Signal != -70 || !tv.Authorized { // signal_level 2 bars
		t.Errorf("tv station: %+v", tv)
	}
	if len(master.FDB) != 1 || master.FDB[0].MAC != "50:c7:bf:44:55:66" || master.ARP["50:c7:bf:44:55:66"] != "192.168.0.81" {
		t.Errorf("master wired: fdb %+v arp %v", master.FDB, master.ARP)
	}
	if sat.ARP["50:c7:bf:11:22:33"] != "192.168.0.80" {
		t.Errorf("deco-205 arp %v", sat.ARP)
	}
	for _, r := range off.Radios {
		for _, v := range r.VAPs {
			if len(v.Stations) != 0 {
				t.Errorf("deco-232: stations %v", stationMACs(v))
			}
		}
	}
}

// A firmware that does fill 0x4012's live state: entries it saw online stay
// placed after the reply ages past MaxAge, as long as 0x4014 still shows them.
func TestLiveClientsPlacementOutlivesSlowList(t *testing.T) {
	s := loadState(t)
	s.Clients.At = fixtureAt.Add(-9 * time.Minute) // after ConnectedSince (11:00)
	now := fixtureAt.Add(15 * time.Second)
	lv := LiveClients(s, now, defaultMaxAge)
	by := liveByMAC(lv)
	if len(lv.Clients) != 4 || lv.Placed != 4 || by["aa:bb:cc:dd:ee:01"].PlacedBy != SrcClients ||
		by["aa:bb:cc:dd:ee:01"].DeviceID != "dev205" || by["aa:bb:cc:dd:ee:01"].IP != "192.168.0.50" {
		t.Fatalf("live %+v", lv)
	}
	snap, _ := newCollector(t, testUnits[1]).Collect(s, now)
	if got := stationMACs(vapsOf(snap.Radios[1])["main"]); got != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("deco-205 5 GHz: %q", got)
	}
	// A 0x4012 reply from before the reconnect places nothing.
	s.Clients.At = s.ConnectedSince.Add(-time.Second)
	if lv := LiveClients(s, now, defaultMaxAge); lv.Placed != 0 || lv.Unplaced != 4 {
		t.Fatalf("pre-session placement used: %+v", lv)
	}
	// No fresh presence list: nothing at all, not a frozen list.
	if lv := LiveClients(s, fixtureAt.Add(time.Minute), defaultMaxAge); lv != nil {
		t.Fatalf("stale lists reported: %+v", lv)
	}
}

func TestIsDecoMAC(t *testing.T) {
	var decos []uint64
	for _, m := range []string{"B0-A7-B9-3E-16-94", "b0:a7:b9:3e:17:fe"} {
		v, _ := macValue(m)
		decos = append(decos, v)
	}
	for mac, want := range map[string]bool{
		"B0-A7-B9-3E-16-94": true,  // the unit
		"B2-A7-B9-3E-16-96": true,  // + 2, second digit varied (l0.java:622-633)
		"BE-A7-B9-3E-16-96": true,  // any second digit
		"B0-A7-B9-3E-16-96": true,  // + 2 as is
		"B0-A7-B9-3E-18-00": true,  // + 2 with a carry (E1, l0.java:234-256)
		"B0-A7-B9-3E-16-95": false, // + 1
		"A0-A7-B9-3E-16-96": false, // first digit differs
		"8E-56-D7-04-BB-8F": false,
		"nope":              false,
	} {
		if got := isDecoMAC(mac, decos); got != want {
			t.Errorf("isDecoMAC(%s)=%v want %v", mac, got, want)
		}
	}
}

// Time the Mesh spends blocked in the slow 0x4012 does not age the other
// lists, up to 0x4012's budget; any other in-flight Get does not count.
func TestFreshWhileSlowPollBlocks(t *testing.T) {
	at := fixtureAt
	for _, tt := range []struct {
		name string
		busy *BusyPoll
		now  time.Time
		want bool
	}{
		{"no busy, within", nil, at.Add(45 * time.Second), true},
		{"no busy, past", nil, at.Add(46 * time.Second), false},
		{"0x4012 since +10s, now +80s", &BusyPoll{Op: OpGetClientList, Since: at.Add(10 * time.Second)}, at.Add(80 * time.Second), true},
		{"0x4012 past its budget", &BusyPoll{Op: OpGetClientList, Since: at.Add(10 * time.Second)}, at.Add(10*time.Second + AppRequestTimeout(OpGetClientList) + 40*time.Second), false},
		{"0x4012 started before the read", &BusyPoll{Op: OpGetClientList, Since: at.Add(-time.Second)}, at.Add(80 * time.Second), false},
		{"other op in flight", &BusyPoll{Op: OpGetWireless, Since: at.Add(10 * time.Second)}, at.Add(80 * time.Second), false},
	} {
		s := &MeshState{Connected: true, ConnectedSince: at.Add(-time.Hour), Busy: tt.busy,
			Speeds: Polled[ClientSpeedListResult]{Value: &ClientSpeedListResult{}, At: at, OK: true}}
		if got := Fresh(s, &s.Speeds, tt.now, defaultMaxAge); got != tt.want {
			t.Errorf("%s: Fresh=%v want %v", tt.name, got, tt.want)
		}
	}
}

// The new Get through the real Mesh: polled on the base interval when
// iot_client is negotiated, and decoded into MeshState.IoT.
func TestMeshIoTPoll(t *testing.T) {
	r := newRig(t, nil)
	b, err := os.ReadFile("testdata/live-iot.json")
	if err != nil {
		t.Fatal(err)
	}
	r.emu.ok(OpGetIoTClientList, strings.TrimSpace(string(b)))
	r.step()
	s := r.m.Snapshot()
	if !s.IoT.OK || len(s.IoT.Value.IoTClientList) != 4 || s.IoT.Err != "" {
		t.Fatalf("iot: %+v", s.IoT)
	}
	if got := r.emu.params(t, OpGetIoTClientList, 0); got != "" {
		t.Fatalf("0x4040 must send null params, got %s", got)
	}
	r.clock.Add(15 * time.Second)
	r.step()
	if n := r.emu.count(OpGetIoTClientList); n != 2 {
		t.Fatalf("0x4040 polled %d times in 15 s, want 2", n)
	}
}

// pollOrder records the Gets the emulator answers, in order.
func pollOrder(r *rig) func() []uint16 {
	var mu sync.Mutex
	var seen []uint16
	r.emu.setHook(func(op uint16) {
		if op >= 0x4002 { // not the token or NEGOTIATE
			mu.Lock()
			seen = append(seen, op)
			mu.Unlock()
		}
	})
	return func() []uint16 { mu.Lock(); defer mu.Unlock(); return slices.Clone(seen) }
}

// The fast lists come first and the slow 0x4012 last, at most every
// MinClientsEvery; ClientsEvery < 0 drops it.
func TestMeshClientListIsSlowEnrichment(t *testing.T) {
	r := newRig(t, func(c *MeshConfig) { c.ClientsEvery = time.Minute }) // raised to the floor
	seen := pollOrder(r)
	r.step()
	want := []uint16{OpGetDeviceList, OpGetClientSpeedList, OpGetIoTClientList, OpGetWireless, OpGetDeviceEthPort, OpGetBlockList, OpGetClientList}
	if got := seen(); !slices.Equal(got, want) {
		t.Fatalf("poll order %x, want %x", got, want)
	}
	if r.m.cfg.ClientsEvery != MinClientsEvery {
		t.Fatalf("ClientsEvery %s", r.m.cfg.ClientsEvery)
	}
	for range 39 { // 9m45s
		r.clock.Add(15 * time.Second)
		r.step()
	}
	if c, sp := r.emu.count(OpGetClientList), r.emu.count(OpGetClientSpeedList); c != 1 || sp != 40 {
		t.Fatalf("0x4012 %d, 0x4014 %d polls in 9m45s", c, sp)
	}
	r.clock.Add(15 * time.Second)
	r.step()
	if c := r.emu.count(OpGetClientList); c != 2 {
		t.Fatalf("0x4012 not re-read after 10 min: %d", c)
	}
	off, err := NewMesh(MeshConfig{MasterIP: "127.0.0.1", MasterMAC: "b0:a7:b9:3e:16:94", TPLinkID: "x", Password: "y", ClientsEvery: -1})
	if err != nil || slices.Contains(off.PolledOps(), OpGetClientList) {
		t.Fatalf("ClientsEvery<0: %v %x", err, off.PolledOps())
	}
}

// Client Gets run only when NEGOTIATE lists their component; a NEGOTIATE
// without a component list gates nothing.
func TestMeshComponentGating(t *testing.T) {
	r := newRig(t, nil)
	r.emu.ok(OpNegotiation, `{"operation_mode":"AP","component_list":[{"id":"client","ver_code":2},{"id":"wireless","ver_code":2}]}`)
	r.step()
	s := r.m.Snapshot()
	if r.emu.count(OpGetClientSpeedList) != 0 || r.emu.count(OpGetIoTClientList) != 0 || r.emu.count(OpGetClientList) != 1 {
		t.Fatalf("gated Gets sent: 0x4014=%d 0x4040=%d 0x4012=%d", r.emu.count(OpGetClientSpeedList),
			r.emu.count(OpGetIoTClientList), r.emu.count(OpGetClientList))
	}
	if !s.IoT.Disabled || !strings.Contains(s.IoT.Err, `"iot_client"`) || !s.Speeds.Disabled || !s.Clients.OK {
		t.Fatalf("iot %+v speeds %+v", s.IoT, s.Speeds)
	}
	if p, ok := s.Poll(OpGetIoTClientList); !ok || !p.Ran || !p.Disabled {
		t.Fatalf("Poll(0x4040) %+v %v", p, ok)
	}
	r.clock.Add(15 * time.Second)
	r.step()
	if r.emu.count(OpGetIoTClientList) != 0 {
		t.Fatal("gated 0x4040 sent later")
	}

	r2 := newRig(t, nil)
	r2.emu.ok(OpNegotiation, `{"operation_mode":"AP"}`)
	r2.step()
	if r2.emu.count(OpGetClientSpeedList) != 1 || r2.emu.count(OpGetIoTClientList) != 1 || r2.emu.count(OpGetClientList) != 1 {
		t.Fatal("no component_list must gate nothing")
	}
}

// The live -print trace: 0x4012 took 62 s, the same step's second pass
// sent it again, -print cancelled that retry and the cancel cleared the ok
// flag. With Once a Get that answered is not sent again; without it the
// interval runs from the end of the slow request. While 0x4012 blocks the
// session, the other lists stay Fresh.
func TestMeshSlowClientListNotRepolled(t *testing.T) {
	for _, once := range []bool{true, false} {
		r := newRig(t, func(c *MeshConfig) { c.Once = once })
		var during MeshState
		r.emu.setHook(func(op uint16) {
			if op == OpGetClientList {
				r.clock.Add(62 * time.Second)
				during = r.m.Snapshot()
			}
		})
		r.step()
		r.emu.setHook(nil)
		s := r.m.Snapshot()
		ops := []uint16{OpGetClientList}
		if once { // without Once the 15 s/60 s lists are due again after 62 s, and re-read
			ops = append(ops, OpGetDeviceList, OpGetClientSpeedList, OpGetWireless)
		}
		for _, op := range ops {
			if n := r.emu.count(op); n != 1 {
				t.Errorf("once=%v: 0x%04x sent %d times in one step", once, op, n)
			}
		}
		if !s.Clients.OK || s.Clients.Err != "" || s.Busy != nil {
			t.Fatalf("once=%v: clients %+v busy %+v", once, s.Clients, s.Busy)
		}
		if during.Busy == nil || during.Busy.Op != OpGetClientList ||
			!Fresh(&during, &during.Speeds, r.clock.Now(), defaultMaxAge) {
			t.Fatalf("once=%v: during 0x4012: busy %+v, speeds not fresh", once, during.Busy)
		}
		// Later steps: Once never re-reads; otherwise the base lists are due.
		r.clock.Add(20 * time.Minute)
		r.step()
		want := 1
		if !once {
			want = 2
		}
		if n := r.emu.count(OpGetClientList); n != want {
			t.Fatalf("once=%v: 0x4012 sent %d times after 20 min, want %d", once, n, want)
		}
	}
}

// The gap after 0x4012 returns: Busy is cleared, but the lists read before
// it are not re-read yet (or not at all under Once / -only). The time spent
// blocked must still not age them, or every unit reports no clients until
// the next pass re-reads them.
func TestFreshAfterSlowPollEnds(t *testing.T) {
	r := newRig(t, func(c *MeshConfig) { c.Once = true })
	r.emu.setHook(func(op uint16) {
		if op == OpGetClientList {
			r.clock.Add(62 * time.Second)
		}
	})
	r.step()
	s := r.m.Snapshot()
	if s.Busy != nil || s.LastSlow == nil || s.LastSlow.Op != OpGetClientList {
		t.Fatalf("busy %+v last slow %+v", s.Busy, s.LastSlow)
	}
	now := r.clock.Now()
	if !Fresh(&s, &s.Speeds, now, defaultMaxAge) || !Fresh(&s, &s.Devices, now, defaultMaxAge) {
		t.Fatalf("right after 0x4012: speeds %v devices %v (read %s before)",
			Fresh(&s, &s.Speeds, now, defaultMaxAge), Fresh(&s, &s.Devices, now, defaultMaxAge), now.Sub(s.Speeds.At))
	}
	// Bounded: past maxAge plus the blocked time, the list is stale.
	if Fresh(&s, &s.Speeds, now.Add(defaultMaxAge+time.Second), defaultMaxAge) {
		t.Fatal("speeds still fresh maxAge after 0x4012 ended")
	}

	at := fixtureAt
	for _, tt := range []struct {
		name string
		last *SlowPoll
		now  time.Time
		want bool
	}{
		{"ended 62s run, now +70s", &SlowPoll{Op: OpGetClientList, Since: at.Add(time.Second), End: at.Add(63 * time.Second)}, at.Add(70 * time.Second), true},
		{"ended 62s run, now +110s", &SlowPoll{Op: OpGetClientList, Since: at.Add(time.Second), End: at.Add(63 * time.Second)}, at.Add(110 * time.Second), false},
		{"run before the read", &SlowPoll{Op: OpGetClientList, Since: at.Add(-70 * time.Second), End: at.Add(-8 * time.Second)}, at.Add(70 * time.Second), false},
		{"capped at the budget", &SlowPoll{Op: OpGetClientList, Since: at.Add(time.Second), End: at.Add(10 * time.Minute)}, at.Add(10*time.Minute + time.Second), false},
	} {
		s := &MeshState{Connected: true, ConnectedSince: at.Add(-time.Hour), LastSlow: tt.last,
			Speeds: Polled[ClientSpeedListResult]{Value: &ClientSpeedListResult{}, At: at, OK: true}}
		if got := Fresh(s, &s.Speeds, tt.now, defaultMaxAge); got != tt.want {
			t.Errorf("%s: Fresh=%v want %v", tt.name, got, tt.want)
		}
	}
}

// Once retries a Get that failed, and stops once it answers.
func TestMeshOnceRetriesFailures(t *testing.T) {
	r := newRig(t, func(c *MeshConfig) { c.Once = true; c.Only = []uint16{OpGetClientSpeedList} })
	r.emu.set(OpGetClientSpeedList, `{"error_code":-1}`)
	r.step()
	r.emu.ok(OpGetClientSpeedList, `{"client_list_speed":[]}`)
	for range 3 {
		r.clock.Add(15 * time.Second)
		r.step()
	}
	if n, s := r.emu.count(OpGetClientSpeedList), r.m.Snapshot(); n != 2 || !s.Speeds.OK {
		t.Fatalf("0x4014 sent %d times: %+v", n, s.Speeds)
	}
}
