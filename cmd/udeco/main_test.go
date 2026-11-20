// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/deco"
)

// ---- helpers ----

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) { b.mu.Lock(); defer b.mu.Unlock(); return b.b.Write(p) }
func (b *syncBuf) String() string              { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

// captureLog sends the standard logger (runners, Mesh, applier) to a buffer.
func captureLog(t *testing.T) *syncBuf {
	buf := &syncBuf{}
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	return buf
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitFor(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// testConfig builds a validated config for the emulated mesh.
func testConfig(t *testing.T, informURL, dir string) *Config {
	t.Helper()
	var units []map[string]any
	for _, u := range testUnits {
		units = append(units, map[string]any{"name": u.Name, "ip": u.IP, "mac": u.MAC, "sshd_port": freePort(t)})
	}
	raw, _ := json.Marshal(map[string]any{
		"inform_url": informURL, "daemon_ip": "192.0.2.10", "console_ip": "127.0.0.1",
		"tplink_id": testTPLinkID, "mesh": map[string]any{"master": "127.0.0.1"},
		"units": units, "wifi_caps": 131072, "state_dir": dir,
	})
	c, err := parseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testHooks(e *decoEmu) hooks {
	return hooks{discover: e.discover, heartbeat: 50 * time.Millisecond, sshListenHost: "127.0.0.1",
		minWait: 50 * time.Millisecond, immediateWait: 20 * time.Millisecond, gatedWait: 50 * time.Millisecond}
}

var secrets = []string{testPassword, testTPLinkID, strings.ToLower(testTPLinkID), testPSK, b64(testPSK), testUniFiPSK, b64(testUniFiPSK)}

func noSecrets(t *testing.T, where, s string, extra ...string) {
	t.Helper()
	for _, sec := range append(secrets, extra...) {
		if strings.Contains(s, sec) {
			t.Errorf("secret %q leaked into %s", sec, where)
		}
	}
}

const unifiSystemCfg = `radio.1.phyname=wifi0
radio.2.phyname=wifi1
aaa.1.ssid=UniFiHome
aaa.1.wpa=2
aaa.1.wpa.key.1.mgmt=WPA-PSK
aaa.1.wpa.psk=` + testUniFiPSK + `
wireless.1.ssid=UniFiHome
wireless.1.id=w1
wireless.1.parent=wifi0
wireless.1.devname=ath0
wireless.1.usage=user
aaa.2.ssid=UniFiHome
aaa.2.wpa=2
aaa.2.wpa.key.1.mgmt=WPA-PSK
aaa.2.wpa.psk=` + testUniFiPSK + `
wireless.2.ssid=UniFiHome
wireless.2.id=w1
wireless.2.parent=wifi1
wireless.2.devname=ath1
wireless.2.usage=user
`

// stations lists the sta_table MACs of the payload's VAPs on radio band.
func stations(m map[string]any, band string) []string {
	var out []string
	vaps, _ := m["vap_table"].([]any)
	for _, v := range vaps {
		vm, _ := v.(map[string]any)
		if vm["radio"] != band {
			continue
		}
		stas, _ := vm["sta_table"].([]any)
		for _, s := range stas {
			if sm, ok := s.(map[string]any); ok {
				out = append(out, fmt.Sprint(sm["mac"]))
			}
		}
	}
	return out
}

// lastAdopted is the controller's last inform from mac sent after adoption.
func lastAdopted(c *fakeCtl, mac string) map[string]any {
	d := c.dev(mac)
	if d.newKey == 0 || len(d.informs) == 0 {
		return nil
	}
	return d.informs[len(d.informs)-1]
}

// ---- end to end ----

// TestDaemonEndToEnd runs the whole daemon (Mesh, Wi-Fi applier, block
// reconciler, three runners) against the in-process Deco emulator and fake
// controller: every unit adopts with the controller's authkey and then
// informs with its own MAC, the daemon IP, the model, both radios and the
// Deco's client on the right AP. apply=false: nothing is written to the Deco.
func TestDaemonEndToEnd(t *testing.T) {
	logs := captureLog(t)
	emu := newDecoEmu(t)
	ctl := newFakeCtl(t)
	ctl.systemCfg = unifiSystemCfg
	ctl.blocked = clientMAC
	ctl.queue("b0:a7:b9:3e:15:fc", `{"_type":"cmd","cmd":"restart"}`, `{"_type":"noop","interval":1}`,
		`{"_type":"cmd","cmd":"locate"}`, `{"_type":"setdefault"}`)
	dir := t.TempDir()
	cfg := testConfig(t, ctl.url(), dir)
	d, err := newDaemon(cfg, Secrets{TPLinkID: testTPLinkID, Password: testPassword}, testHooks(emu))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- d.run(ctx) }()

	waitFor(t, "every unit adopted and reporting the mesh", 30*time.Second, func() bool {
		m241 := lastAdopted(ctl, "b0:a7:b9:3e:16:94")
		m205 := lastAdopted(ctl, "b0:a7:b9:3e:17:00")
		return m241 != nil && m241["uptime"] == float64(5000) &&
			m205 != nil && strings.Join(stations(m205, "na"), ",") == clientMAC &&
			ctl.dev("b0:a7:b9:3e:15:fc").newKey > 0 &&
			strings.Contains(logs.String(), "would send block") &&
			strings.Contains(logs.String(), "would send reboot") &&
			strings.Contains(logs.String(), "[deco-232] STOP")
	})
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not stop")
	}

	for i, u := range testUnits {
		dev := ctl.dev(u.MAC)
		if !dev.adopted || dev.newKey == 0 || dev.staleKey != 0 {
			t.Errorf("%s: adopted=%v informs on the new key=%d, on the default key after adoption=%d", u.Name, dev.adopted, dev.newKey, dev.staleKey)
		}
		if dev.gcm == 0 {
			t.Errorf("%s: never informed with AES-GCM after use_aes_gcm=true", u.Name)
		}
		m := lastAdopted(ctl, u.MAC)
		if m == nil {
			t.Fatalf("%s: no adopted inform", u.Name)
		}
		if m["mac"] != u.MAC || m["ip"] != "192.0.2.10" || m["model"] != "U7PG2" || m["sshd_port"] != float64(cfg.Units[i].SSHDPort) {
			t.Errorf("%s: identity mac=%v ip=%v model=%v sshd_port=%v", u.Name, m["mac"], m["ip"], m["model"], m["sshd_port"])
		}
		if want := "00000000000000c1"; m["cfgversion"] != want {
			t.Errorf("%s: cfgversion %v, want %s", u.Name, m["cfgversion"], want)
		}
		radios, _ := m["radio_table"].([]any)
		var bands []string
		for _, r := range radios {
			bands = append(bands, fmt.Sprint(r.(map[string]any)["radio"]))
		}
		if strings.Join(bands, ",") != "ng,na" {
			t.Errorf("%s: radios %v", u.Name, bands)
		}
		st, err := os.Stat(filepath.Join(dir, "units", strings.ReplaceAll(u.MAC, ":", ""), "state.json"))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: state.json %v %v", u.Name, err, st)
		}
	}
	m205 := lastAdopted(ctl, "b0:a7:b9:3e:17:00")
	if m205["hostname"] != "Bedroom" || len(stations(m205, "ng")) != 0 {
		t.Errorf("deco-205: hostname %v, 2.4 GHz stations %v", m205["hostname"], stations(m205, "ng"))
	}
	if s := stations(lastAdopted(ctl, "b0:a7:b9:3e:16:94"), "na"); len(s) != 0 {
		t.Errorf("deco-241 reports the satellite's client: %v", s)
	}

	// apply=false: plans are logged, nothing is written; one login only.
	for _, op := range []uint16{deco.OpSetWireless, deco.OpBlockClients, deco.OpUnblockClients, deco.OpRebootDevices} {
		if n := emu.count(op); n != 0 {
			t.Errorf("opcode 0x%04x sent %d time(s) with apply=false", op, n)
		}
	}
	if conns, tries, logins := emu.counts(); conns != 1 || tries != 1 || logins != 1 {
		t.Errorf("ssh: conns=%d password attempts=%d logins=%d, want 1/1/1", conns, tries, logins)
	}
	out := logs.String()
	for _, want := range []string{
		"[deco-241] Wi-Fi config from the controller",
		"deco wlan [deco-241]: plan from system_cfg (apply=false: log only)",
		"deco wlan [deco-205]: plan from system_cfg (not the config owner: log only)",
		"blocks: apply=false: block [" + clientMAC + "] not sent",
		"[deco-232] locate on: logged only",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q", want)
		}
	}
	if n := strings.Count(out, "would send block"); n != 1 {
		t.Errorf("block dry run logged %d times, want once", n)
	}
	var keys []string
	for _, u := range testUnits {
		keys = append(keys, ctl.dev(u.MAC).authkey)
	}
	noSecrets(t, "the logs", out, keys...)
	if t.Failed() || os.Getenv("UDECO_TEST_LOGS") != "" {
		t.Logf("logs:\n%s", out)
	}
}

// A master whose TDP owner hash is not md5(tplink_id) stops the daemon
// before any SSH connection.
func TestDaemonRefusesWrongOwner(t *testing.T) {
	captureLog(t)
	emu := newDecoEmu(t)
	emu.setOwner(md5hex("someone-else@example.com"))
	cfg := testConfig(t, "http://127.0.0.1:9/inform", t.TempDir())
	d, err := newDaemon(cfg, Secrets{TPLinkID: testTPLinkID, Password: testPassword}, testHooks(emu))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var re *deco.RefusedError
	if err := d.run(ctx); !errors.As(err, &re) {
		t.Fatalf("run: %v, want a refusal", err)
	}
	if conns, _, _ := emu.counts(); conns != 0 {
		t.Fatalf("%d SSH connection(s) despite the owner mismatch", conns)
	}
}

// ---- -print and -discover ----

func TestPrintOnce(t *testing.T) {
	logs := captureLog(t)
	emu := newDecoEmu(t)
	cfg := testConfig(t, "http://127.0.0.1:9/inform", t.TempDir())
	var out bytes.Buffer
	if err := printOnce(context.Background(), cfg, Secrets{TPLinkID: testTPLinkID, Password: testPassword}, testHooks(emu), &out); err != nil {
		t.Fatalf("print: %v\n%s", err, logs.String())
	}
	var po struct {
		Result string `json:"result"`
		Mesh   struct {
			OperationMode string         `json:"operation_mode"`
			Master        *deco.DecoInfo `json:"master"`
			Wireless      struct {
				Value *deco.WirelessInfo `json:"value"`
			} `json:"wireless"`
		} `json:"mesh"`
		Units map[string]map[string]json.RawMessage `json:"units"`
	}
	if err := json.Unmarshal(out.Bytes(), &po); err != nil {
		t.Fatal(err)
	}
	if po.Result != "ok" || po.Mesh.OperationMode != "AP" || po.Mesh.Master == nil || po.Mesh.Master.Owner != "[redacted]" {
		t.Errorf("result %q mode %q master %+v", po.Result, po.Mesh.OperationMode, po.Mesh.Master)
	}
	if w := po.Mesh.Wireless.Value; w == nil || w.Band5G1 == nil || w.Band5G1.Host == nil || string(*w.Band5G1.Host.Password) != "***" {
		t.Errorf("wireless not masked: %+v", w)
	}
	if string(po.Units["deco-205"]["online"]) != "true" || !strings.Contains(string(po.Units["deco-205"]["snapshot"]), clientMAC) {
		t.Errorf("deco-205: %s", po.Units["deco-205"])
	}
	noSecrets(t, "-print output", out.String(), md5hex(testTPLinkID))
	noSecrets(t, "-print logs", logs.String())
	if conns, tries, logins := emu.counts(); conns != 1 || tries != 1 || logins != 1 {
		t.Errorf("ssh: conns=%d password attempts=%d logins=%d, want 1/1/1", conns, tries, logins)
	}
	for _, op := range []uint16{deco.OpSetWireless, deco.OpBlockClients, deco.OpRebootDevices} {
		if emu.count(op) != 0 {
			t.Errorf("-print sent 0x%04x", op)
		}
	}
	if emu.count(deco.OpcodeTokenFree) != 1 {
		t.Errorf("token not freed at exit")
	}
}

// A rejected password: -print reports it after exactly one attempt.
func TestPrintOnceAuthFailure(t *testing.T) {
	captureLog(t)
	emu := newDecoEmu(t)
	cfg := testConfig(t, "http://127.0.0.1:9/inform", t.TempDir())
	var out bytes.Buffer
	err := printOnce(context.Background(), cfg, Secrets{TPLinkID: testTPLinkID, Password: "wrong-password"}, testHooks(emu), &out)
	if err == nil || !strings.Contains(err.Error(), "latched") {
		t.Fatalf("err %v", err)
	}
	if _, tries, _ := emu.counts(); tries != 1 {
		t.Fatalf("%d password attempts", tries)
	}
	noSecrets(t, "-print output", out.String(), "wrong-password")
}

func TestDiscoverOnly(t *testing.T) {
	for _, tt := range []struct {
		name, owner, verdict string
		matches              bool
	}{
		{"owner", md5hex(testTPLinkID), "ok", true},
		{"not the owner", md5hex("x@y.z"), "TDP owner hash does not match", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			captureLog(t)
			emu := newDecoEmu(t)
			emu.setOwner(tt.owner)
			cfg := testConfig(t, "http://127.0.0.1:9/inform", t.TempDir())
			var out bytes.Buffer
			if err := discoverOnly(context.Background(), cfg, Secrets{TPLinkID: testTPLinkID}, testHooks(emu), &out); err != nil {
				t.Fatal(err)
			}
			var got struct {
				Units []struct {
					Name         string `json:"name"`
					OwnerMatches *bool  `json:"owner_matches"`
					MACMatches   *bool  `json:"mac_matches"`
				} `json:"units"`
				Precheck string `json:"precheck"`
			}
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if len(got.Units) != 3 || !strings.Contains(got.Precheck, tt.verdict) {
				t.Fatalf("%s", out.String())
			}
			for _, u := range got.Units {
				if u.OwnerMatches == nil || *u.OwnerMatches != tt.matches || u.MACMatches == nil || !*u.MACMatches {
					t.Errorf("%s: %s", u.Name, out.String())
				}
			}
			noSecrets(t, "-discover output", out.String(), tt.owner)
			if conns, _, _ := emu.counts(); conns != 0 {
				t.Fatalf("-discover connected over SSH")
			}
		})
	}
}

// ---- offline policy ----

func TestGate(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	devs := func(list ...deco.Deco) deco.Polled[deco.DeviceListResult] {
		return deco.Polled[deco.DeviceListResult]{Value: &deco.DeviceListResult{DeviceList: list}, OK: true}
	}
	devsAt := func(at time.Time, list ...deco.Deco) deco.Polled[deco.DeviceListResult] {
		p := devs(list...)
		p.At = at
		return p
	}
	stale := func(d deco.Deco, now time.Time) deco.Polled[deco.DeviceListResult] {
		p := devsAt(now.Add(-2*time.Minute), d)
		p.OK = false
		return p
	}
	disabled := func(d deco.Deco, now time.Time) deco.Polled[deco.DeviceListResult] {
		p := devsAt(now, d)
		p.Disabled = true
		return p
	}
	online := deco.Deco{DecoBase: deco.DecoBase{MAC: "B0-A7-B9-3E-17-00"}}
	offline := deco.Deco{DecoBase: deco.DecoBase{MAC: "B0-A7-B9-3E-17-00", InetStatus: "offline"}}
	up := deco.MeshState{Connected: true}
	for _, tt := range []struct {
		name     string
		steps    []deco.MeshState // evaluated at now, now+30s, now+60s, ...
		everSeen bool
		want     bool
		why      string
	}{
		{"not read yet: skeleton", []deco.MeshState{up}, false, true, ""},
		{"online", []deco.MeshState{{Connected: true, Devices: devs(online)}}, false, true, ""},
		{"never in device_list", []deco.MeshState{{Connected: true, Devices: devs()}}, false, false, "not in the mesh device_list"},
		{"gone after being seen: grace", []deco.MeshState{{Connected: true, Devices: devs()}}, true, true, ""},
		{"offline within grace", []deco.MeshState{{Connected: true, Devices: devs(offline)}, {Connected: true, Devices: devs(offline)}}, true, true, ""},
		{"offline past grace", []deco.MeshState{{Connected: true, Devices: devs(offline)}, {Connected: true, Devices: devs(offline)}, {Connected: true, Devices: devs(offline)}}, true, false, "unit offline for 1m0s"},
		{"back online resets grace", []deco.MeshState{{Connected: true, Devices: devs(offline)}, {Connected: true, Devices: devs(online)}, {Connected: true, Devices: devs(offline)}}, true, true, ""},
		{"master down 100s", []deco.MeshState{{DownSince: now.Add(-100 * time.Second), Devices: devs(online)}}, true, true, ""},
		{"master down 3m", []deco.MeshState{{DownSince: now.Add(-3 * time.Minute), Devices: devs(online)}}, true, false, "master session down for 3m0s"},
		{"latched", []deco.MeshState{{DownSince: now.Add(-3 * time.Minute), Latched: "SSH login rejected"}}, false, false, "latched off: SSH login rejected"},
		// device_list kept from failed or disabled polls is not "online".
		{"stale device_list within grace", []deco.MeshState{{Connected: true, Devices: stale(online, now)}}, true, true, ""},
		{"stale device_list past grace", []deco.MeshState{
			{Connected: true, Devices: stale(online, now)}, {Connected: true, Devices: stale(online, now)},
			{Connected: true, Devices: stale(online, now)}}, true, false, "device_list not refreshed for 1m0s"},
		{"disabled device_list past grace", []deco.MeshState{
			{Connected: true, Devices: disabled(online, now)}, {Connected: true, Devices: disabled(online, now.Add(30*time.Second))},
			{Connected: true, Devices: disabled(online, now.Add(time.Minute))}}, true, false, "device_list not refreshed"},
		{"device_list from before the reconnect", []deco.MeshState{
			{Connected: true, ConnectedSince: now, Devices: devsAt(now.Add(-time.Second), online)},
			{Connected: true, ConnectedSince: now, Devices: devsAt(now.Add(30*time.Second), online)}}, true, true, ""},
		{"stale while down: masterDownMax governs", []deco.MeshState{{DownSince: now.Add(-100 * time.Second), Devices: stale(online, now)}}, true, true, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := hooks{}
			h.fill()
			r := &runner{d: &daemon{h: h}, u: UnitConfig{Name: "deco-205", MAC: "b0:a7:b9:3e:17:00"}, everSeen: tt.everSeen}
			var ok bool
			var why string
			for i := range tt.steps {
				at := now.Add(time.Duration(i) * 30 * time.Second)
				if tt.steps[i].Devices.Value != nil && tt.steps[i].Devices.At.IsZero() {
					tt.steps[i].Devices.At = at // no At given: read by this step's poll
				}
				ok, why = r.gate(&tt.steps[i], at)
			}
			if ok != tt.want || (tt.why == "" && why != "") || !strings.Contains(why, tt.why) {
				t.Fatalf("gate = %v %q, want %v %q", ok, why, tt.want, tt.why)
			}
		})
	}
}

// ---- block reconcile ----

type fakeMesh struct {
	mu    sync.Mutex
	state deco.MeshState
	apply bool
	cmds  []deco.Command
	polls int
	fail  error
}

func (f *fakeMesh) Snapshot() deco.MeshState { f.mu.Lock(); defer f.mu.Unlock(); return f.state }
func (f *fakeMesh) RequestPoll(uint16)       { f.mu.Lock(); f.polls++; f.mu.Unlock() }
func (f *fakeMesh) Submit(c deco.Command) <-chan deco.CommandResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, c)
	ch := make(chan deco.CommandResult, 1)
	ch <- deco.CommandResult{Kind: c.Kind, DryRun: !f.apply, Err: f.fail}
	return ch
}

func (f *fakeMesh) setBlocked(at time.Time, macs ...string) {
	var l []deco.ClientBlockEntry
	for _, m := range macs {
		l = append(l, deco.ClientBlockEntry{MAC: m})
	}
	f.mu.Lock()
	f.state.Connected = true
	f.state.Blocks = deco.Polled[deco.ClientBlockListResult]{Value: &deco.ClientBlockListResult{ClientList: l}, At: at, OK: true}
	f.mu.Unlock()
}

func (f *fakeMesh) sent() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var s []string
	for _, c := range f.cmds {
		s = append(s, fmt.Sprintf("%s%v", c.Kind, c.MACs))
	}
	f.cmds = nil
	return strings.Join(s, " ")
}

func TestBlockSync(t *testing.T) {
	ctx := context.Background()
	t.Run("apply off: plan once per change, nothing recorded", func(t *testing.T) {
		f := &fakeMesh{}
		f.setBlocked(time.Now(), "AA-BB-CC-DD-EE-09")
		path := filepath.Join(t.TempDir(), "blocks.json")
		b := newBlockSync(f, false, path, func(string, ...any) {})
		b.reconcile(ctx)
		if f.sent() != "" {
			t.Fatal("acted without any blocked_sta")
		}
		b.Set("deco-241", []string{"aa:bb:cc:dd:ee:01"})
		b.Set("deco-205", []string{"aa:bb:cc:dd:ee:01"})
		b.reconcile(ctx)
		b.reconcile(ctx)
		if got := f.sent(); got != "block[aa:bb:cc:dd:ee:01]" {
			t.Fatalf("sent %q", got)
		}
		if _, err := os.Stat(path); err == nil {
			t.Fatal("blocks.json written for a dry run")
		}
	})
	t.Run("apply on: add, then remove only our own", func(t *testing.T) {
		f := &fakeMesh{apply: true}
		t0 := time.Now().Add(-time.Minute)
		f.setBlocked(t0, "AA-BB-CC-DD-EE-09") // blocked in the Deco app, not by us
		path := filepath.Join(t.TempDir(), "blocks.json")
		b := newBlockSync(f, true, path, func(string, ...any) {})
		b.Seed("deco-241", []string{"aa:bb:cc:dd:ee:07"})
		b.Set("deco-205", []string{"AA:BB:CC:DD:EE:01", "aa:bb:cc:dd:ee:02"}) // newer than the seed
		b.reconcile(ctx)
		if got := f.sent(); got != "block[aa:bb:cc:dd:ee:01 aa:bb:cc:dd:ee:02]" {
			t.Fatalf("sent %q", got)
		}
		b.reconcile(ctx) // the cache still predates the write: wait
		if got := f.sent(); got != "" {
			t.Fatalf("re-sent before the re-read: %q", got)
		}
		f.setBlocked(time.Now().Add(time.Second), "AA-BB-CC-DD-EE-09", "AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-02")
		b.Set("deco-241", nil) // the controller unblocked everything
		b.reconcile(ctx)
		if got := f.sent(); got != "unblock[aa:bb:cc:dd:ee:01 aa:bb:cc:dd:ee:02]" {
			t.Fatalf("sent %q (must never unblock ee:09)", got)
		}
		raw, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(raw), `"added": []`) {
			t.Fatalf("blocks.json %s %v", raw, err)
		}
		if f.polls == 0 {
			t.Fatal("no block-list re-read requested")
		}
	})
	t.Run("added list survives a restart", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "blocks.json")
		os.WriteFile(path, []byte(`{"added":["aa:bb:cc:dd:ee:01"]}`), 0o600)
		f := &fakeMesh{apply: true}
		f.setBlocked(time.Now(), "AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-09")
		b := newBlockSync(f, true, path, func(string, ...any) {})
		b.Set("deco-241", nil)
		b.reconcile(ctx)
		if got := f.sent(); got != "unblock[aa:bb:cc:dd:ee:01]" {
			t.Fatalf("sent %q", got)
		}
	})
	// After a restart the runners' saved lists can disagree (one unit was
	// gated when the list changed). The pick must not depend on map order.
	settle := func(t *testing.T, f *fakeMesh, b *blockSync, cur ...string) string {
		t.Helper()
		var all []string
		for i := 0; i < 40; i++ {
			f.setBlocked(time.Now().Add(time.Duration(i+1)*time.Second), cur...)
			b.sentAt = time.Time{}
			b.reconcile(ctx)
			if got := f.sent(); got != "" {
				all = append(all, got)
				for _, c := range strings.Fields(got) { // apply the write to the cache
					mac := strings.Trim(c[strings.Index(c, "["):], "[]")
					if strings.HasPrefix(c, "unblock") {
						cur = slices.DeleteFunc(cur, func(m string) bool { return deco.NormMAC(m) == mac })
					} else {
						cur = append(cur, mac)
					}
				}
			}
		}
		return strings.Join(all, " ")
	}
	t.Run("disagreeing seeds do not flap", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "blocks.json")
		os.WriteFile(path, []byte(`{"added":["aa:bb:cc:dd:ee:02"]}`), 0o600)
		f := &fakeMesh{apply: true}
		b := newBlockSync(f, true, path, func(string, ...any) {})
		b.Seed("deco-241", []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})
		b.Seed("deco-205", []string{"aa:bb:cc:dd:ee:01"})
		if got := settle(t, f, b, "AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-02"); got != "" {
			t.Fatalf("writes %q", got)
		}
	})
	t.Run("the last received list is saved and beats stale seeds", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "blocks.json")
		f := &fakeMesh{apply: true}
		f.setBlocked(time.Now())
		b := newBlockSync(f, true, path, func(string, ...any) {})
		b.Set("deco-241", []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})
		b.reconcile(ctx)
		f.sent()
		b.Set("deco-241", []string{"aa:bb:cc:dd:ee:01"}) // ee:02 unblocked while deco-205 was gated
		b.reconcile(ctx)
		raw, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(raw), `"desired": [`) || strings.Count(string(raw), "aa:bb:cc:dd:ee:02") != 1 {
			t.Fatalf("blocks.json %s %v", raw, err)
		}
		// Restart: deco-205 still holds the old list in its state.json.
		f = &fakeMesh{apply: true}
		b = newBlockSync(f, true, path, func(string, ...any) {})
		b.Seed("deco-241", []string{"aa:bb:cc:dd:ee:01"})
		b.Seed("deco-205", []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})
		if got := settle(t, f, b, "AA-BB-CC-DD-EE-01", "AA-BB-CC-DD-EE-02"); got != "unblock[aa:bb:cc:dd:ee:02]" {
			t.Fatalf("writes %q", got)
		}
	})
	t.Run("no session, failure and drop", func(t *testing.T) {
		f := &fakeMesh{apply: true, fail: deco.ErrNotConnected}
		b := newBlockSync(f, true, filepath.Join(t.TempDir(), "blocks.json"), func(string, ...any) {})
		b.Set("deco-241", []string{"aa:bb:cc:dd:ee:01"})
		b.reconcile(ctx)
		if f.sent() != "" {
			t.Fatal("acted before the block list was read")
		}
		f.setBlocked(time.Now())
		b.reconcile(ctx)
		b.reconcile(ctx) // a failed write is retried
		if got := f.sent(); got != "block[aa:bb:cc:dd:ee:01] block[aa:bb:cc:dd:ee:01]" {
			t.Fatalf("sent %q", got)
		}
		b.Drop("deco-241")
		b.reconcile(ctx)
		if f.sent() != "" {
			t.Fatal("acted with no runner list")
		}
	})
}

// ---- config and secrets ----

func TestExampleConfig(t *testing.T) {
	c, err := loadConfig(filepath.Join("..", "..", "deploy", "udeco.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Apply || c.master().IP != "192.168.0.241" || c.master().MAC != "b0:a7:b9:3e:16:94" || len(c.Units) != 3 {
		t.Fatalf("%+v", c)
	}
	for i, want := range []int{22201, 22202, 22203} {
		if c.Units[i].SSHDPort != want {
			t.Errorf("unit %d sshd_port %d", i, c.Units[i].SSHDPort)
		}
	}
	if c.Model != "U7PG2" || time.Duration(c.Poll) != 15*time.Second || c.ReportIP != "daemon" || c.OnRemove != "stop" {
		t.Errorf("defaults: %+v", c)
	}
}

func TestParseConfig(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"inform_url": "http://192.168.0.1:8080/inform",
			"tplink_id":  "a@b.c",
			"mesh":       map[string]any{"master": "b0:a7:b9:3e:16:94"},
			"units": []any{
				map[string]any{"ip": "192.168.0.241", "mac": "B0-A7-B9-3E-16-94"},
				map[string]any{"ip": "192.168.0.205", "mac": "b0:a7:b9:3e:17:00"},
			},
		}
	}
	for _, tt := range []struct {
		name string
		mut  func(map[string]any)
		err  string
	}{
		{"ok", func(map[string]any) {}, ""},
		{"master by ip", func(m map[string]any) { m["mesh"] = map[string]any{"master": "192.168.0.205"} }, ""},
		{"password in config", func(m map[string]any) { m["password"] = "x" }, "not read from the config"},
		{"unknown field", func(m map[string]any) { m["aply"] = true }, "unknown field"},
		{"hostname inform", func(m map[string]any) { m["inform_url"] = "http://unifi:8080/inform" }, "IP-literal"},
		{"bad model", func(m map[string]any) { m["model"] = "NOPE" }, "unknown UniFi model"},
		{"master not a unit", func(m map[string]any) { m["mesh"] = map[string]any{"master": "192.168.0.9"} }, "not one of the units"},
		{"duplicate mac", func(m map[string]any) {
			m["units"] = []any{map[string]any{"ip": "192.168.0.241", "mac": "b0:a7:b9:3e:16:94"}, map[string]any{"ip": "192.168.0.5", "mac": "B0:A7:B9:3E:16:94"}}
		}, "duplicate mac"},
		{"multicast mac", func(m map[string]any) {
			m["units"] = []any{map[string]any{"ip": "192.168.0.241", "mac": "01:00:5e:00:00:01"}}
		}, "bad mac"},
		{"bad poll", func(m map[string]any) { m["poll"] = "1s" }, "below 5s"},
		{"clients_every 10m", func(m map[string]any) { m["clients_every"] = "10m" }, ""},
		{"clients_every too often", func(m map[string]any) { m["clients_every"] = "15s" }, "below the 10m0s minimum"},
		{"no_client_list", func(m map[string]any) { m["no_client_list"] = true }, ""},
		{"bad report_ip", func(m map[string]any) { m["report_ip"] = "x" }, "report_ip"},
		{"bad host key", func(m map[string]any) {
			m["mesh"] = map[string]any{"master": "192.168.0.241", "host_key_sha256": "abc"}
		}, "SHA256:"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := base()
			tt.mut(m)
			raw, _ := json.Marshal(m)
			c, err := parseConfig(raw)
			if tt.err == "" {
				if err != nil {
					t.Fatal(err)
				}
				if c.Units[0].MAC != "b0:a7:b9:3e:16:94" || c.Units[0].Name != "deco-241" || c.Units[1].SSHDPort != 22202 || c.ConsoleIP != "192.168.0.1" {
					t.Fatalf("normalised: %+v", c.Units)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Fatalf("err %v, want %q", err, tt.err)
			}
		})
	}
}

func TestLoadSecrets(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	os.WriteFile(pwFile, []byte("from-file pw\n"), 0o600)
	envFile := filepath.Join(dir, "credentials.env")
	os.WriteFile(envFile, []byte("# TP-Link\nexport TPLINK_EMAIL=\"Env@Example.com\"\nTPLINK_PASSWORD='from env file'\n"), 0o600)
	for _, tt := range []struct {
		name       string
		cfg        Config
		env        map[string]string
		id, pw     string
		err, nolog string
	}{
		{"env file only", Config{StateDir: dir}, nil, "Env@Example.com", "from env file", "", ""},
		{"config id wins", Config{StateDir: dir, TPLinkID: "Cfg@Example.com"}, nil, "Cfg@Example.com", "from env file", "", ""},
		{"env password wins", Config{StateDir: dir}, map[string]string{"TPLINK_PASSWORD": "env pw"}, "Env@Example.com", "env pw", "", ""},
		{"password file", Config{StateDir: dir}, map[string]string{"TPLINK_PASSWORD_FILE": pwFile}, "Env@Example.com", "from-file pw", "", ""},
		{"config password_file", Config{StateDir: dir, PasswordFile: pwFile}, nil, "Env@Example.com", "from-file pw", "", ""},
		{"missing password file", Config{StateDir: dir}, map[string]string{"TPLINK_PASSWORD_FILE": filepath.Join(dir, "nope")}, "", "", "password file", ""},
		{"no env file, no id", Config{StateDir: t.TempDir()}, nil, "", "", "no TP-Link ID", ""},
		{"no env file, env vars", Config{StateDir: t.TempDir()}, map[string]string{"TPLINK_EMAIL": "env-id@x.example", "TPLINK_PASSWORD": "env-only-pw"}, "env-id@x.example", "env-only-pw", "", ""},
		{"explicit env file missing", Config{StateDir: dir, CredentialsFile: filepath.Join(dir, "missing.env")}, nil, "", "", "not found", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var warns []string
			s, err := loadSecrets(&tt.cfg, func(k string) string { return tt.env[k] }, func(f string, a ...any) { warns = append(warns, fmt.Sprintf(f, a...)) })
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("err %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.TPLinkID != tt.id || string(s.Password) != tt.pw {
				t.Fatalf("got id %q pw %q", s.TPLinkID, string(s.Password))
			}
			if p := fmt.Sprintf("%v %+v %#v %s", s, s, s, s); strings.Contains(p, tt.pw) || strings.Contains(p, tt.id) {
				t.Fatalf("secrets printed: %s", p)
			}
			if b, _ := json.Marshal(s.Password); strings.Contains(string(b), tt.pw) {
				t.Fatal("password marshals")
			}
		})
	}
	t.Run("loose file mode warns, never shows the value", func(t *testing.T) {
		loose := filepath.Join(dir, "loose")
		os.WriteFile(loose, []byte("loose-pw"), 0o644)
		var warns []string
		_, err := loadSecrets(&Config{StateDir: dir, PasswordFile: loose}, func(string) string { return "" },
			func(f string, a ...any) { warns = append(warns, fmt.Sprintf(f, a...)) })
		if err != nil || len(warns) != 1 || !strings.Contains(warns[0], "chmod 600") || strings.Contains(warns[0], "loose-pw") {
			t.Fatalf("err %v warns %q", err, warns)
		}
	})
}
