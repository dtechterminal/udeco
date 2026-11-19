// SPDX-License-Identifier: GPL-2.0-or-later

package deco

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testTPLinkID = "Owner@Example.com"
	testPassword = "hunter2-tplink-pw"
	testPSK      = "s3cret-Wifi-PSK"
	// masterRawID is the master's TMP device_list device_id. TDP carries the
	// MD5 digest of it (masterDevID), like the live 8e6a0e5a... value.
	masterRawID = "8022B0A7B93E16940A1B2C3D4E5F60718293A4B5"
)

// TDP device_id / master_device_id values: md5hex of the device_list ids.
var (
	masterDevID = md5hex(masterRawID)
	tdpID205    = md5hex("dev205")
	tdpID232    = md5hex("dev232")
)

func hexsum(b []byte) string  { return hex.EncodeToString(b) }
func md5hex(s string) string  { h := md5.Sum([]byte(s)); return hexsum(h[:]) }
func sha1hex(s string) string { h := sha1.Sum([]byte(s)); return hexsum(h[:]) }
func b64(s string) string     { return base64.StdEncoding.EncodeToString([]byte(s)) }

// meshEmu is the business-level state of an emulated three-unit X20 mesh.
// Replies per opcode can be swapped by tests; every request is recorded.
type meshEmu struct {
	mu      sync.Mutex
	replies map[uint16]string
	calls   map[uint16]int
	reqs    map[uint16][]string
	hook    func(op uint16) // called before each request is answered
}

func (e *meshEmu) setHook(f func(op uint16)) {
	e.mu.Lock()
	e.hook = f
	e.mu.Unlock()
}

func newMeshEmu() *meshEmu {
	e := &meshEmu{replies: map[uint16]string{}, calls: map[uint16]int{}, reqs: map[uint16][]string{}}
	e.ok(OpNegotiation, `{"operation_mode":"AP","component_list":[{"id":"block_list","ver_code":1},{"id":"wireless","ver_code":2},`+
		`{"id":"client","ver_code":2},{"id":"client_mesh","ver_code":2},{"id":"client_link","ver_code":1},{"id":"client_speed","ver_code":1},`+
		`{"id":"iot_client","ver_code":1},{"id":"client_device","ver_code":1},{"id":"device","ver_code":5}]}`)
	e.ok(OpGetDeviceList, devicesJSON(
		`{"device_id":"`+masterRawID+`","mac":"B0-A7-B9-3E-16-94","ip":"192.168.0.241","role":"master","master_device_id":"`+masterRawID+`","runtime":5000}`,
		`{"device_id":"dev205","mac":"B0-A7-B9-3E-17-00","ip":"192.168.0.205","role":"slave","inet_status":"online"}`,
		`{"device_id":"dev232","mac":"B0-A7-B9-3E-15-FC","ip":"192.168.0.232","role":"slave"}`))
	e.ok(OpGetClientList, `{"client_list":[{"mac":"AA-BB-CC-DD-EE-01","ip":"192.168.0.50","name":"`+b64("phone")+
		`","client_type":"phone","online":true,"interface":"main","linked_device_info":{"device_id":"dev205","connection_type":["band5"]}}]}`)
	e.ok(OpGetClientSpeedList, `{"client_list_speed":[{"mac":"AA-BB-CC-DD-EE-01","up_speed":12,"down_speed":340}]}`)
	e.ok(OpGetIoTClientList, `{"iot_client_list":[],"iot_count_per_cate_max":64,"scan_status":"idle","scan_wait_time":0}`)
	host := `{"enable":true,"ssid":"` + b64("Home") + `","password":"` + b64(testPSK) + `","encryption_mode":"wpa2","enable_wpa3":false}`
	e.ok(OpGetWireless, `{"band2_4":{"host":`+host+`,"radio":{"channel":"8","enable":true}},"band5_1":{"host":`+host+`}}`)
	e.ok(OpGetDeviceEthPort, `{"device_list":[{"device_id":"`+masterRawID+`","port_info":[{"port":1,"port_speed":1000,"ports_status_info":[{"status":"well","type":"lan"}]}]}]}`)
	e.ok(OpGetBlockList, `{"client_list":[{"mac":"AA-BB-CC-DD-EE-09","name":"`+b64("old")+`","client_type":"other"}],"max_count":64}`)
	e.ok(OpRebootDevices, `{"reboot_time":80}`)
	e.ok(OpBlockClients, `null`)
	e.ok(OpUnblockClients, `null`)
	e.ok(OpSetWireless, `true`)
	return e
}

func devicesJSON(devs ...string) string {
	return `{"device_list":[` + strings.Join(devs, ",") + `]}`
}

func (e *meshEmu) ok(op uint16, result string) {
	e.set(op, `{"error_code":0,"result":`+result+`}`)
}

func (e *meshEmu) set(op uint16, reply string) {
	e.mu.Lock()
	e.replies[op] = reply
	e.mu.Unlock()
}

func (e *meshEmu) count(op uint16) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls[op]
}

// params returns the params of the i-th request with op (-1: last).
func (e *meshEmu) params(t *testing.T, op uint16, i int) string {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.reqs[op]
	if i < 0 {
		i = len(r) + i
	}
	if i < 0 || i >= len(r) {
		t.Fatalf("no request %d for 0x%04x (have %d)", i, op, len(r))
	}
	var p struct {
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal([]byte(r[i]), &p); err != nil {
		t.Fatalf("bad request body for 0x%04x: %v", op, err)
	}
	return string(p.Params)
}

func (e *meshEmu) handle(op uint16, req []byte) []byte {
	e.mu.Lock()
	hook := e.hook
	e.mu.Unlock()
	if hook != nil {
		hook(op)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls[op]++
	switch op {
	case OpcodeTokenAlloc:
		return []byte("tok")
	case OpcodeTokenVerify, OpcodeTokenFree:
		return nil
	}
	e.reqs[op] = append(e.reqs[op], string(req))
	if r, ok := e.replies[op]; ok {
		return []byte(r)
	}
	return []byte(`{"error_code":-40210,"msg":"unsupported"}`)
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuf) logf(f string, a ...any) {
	b.mu.Lock()
	fmt.Fprintf(&b.b, f+"\n", a...)
	b.mu.Unlock()
}
func (b *syncBuf) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

type rig struct {
	t     *testing.T
	m     *Mesh
	emu   *meshEmu
	srv   *sshDeco
	clock *fakeClock
	logs  *syncBuf
	dir   string

	tdpMu sync.Mutex
	tdp   map[string]*DecoInfo // ip -> TDP reply; nil entry: no reply
}

func tdpUnits(port int) map[string]*DecoInfo {
	owner := md5hex(testTPLinkID)
	unit := func(ip, mac, id, role string) *DecoInfo {
		return &DecoInfo{IP: ip, MAC: mac, DeviceID: id, MasterDeviceID: masterDevID, Role: role,
			Owner: owner, NeedAccountDigest: true, TMPPorts: []int{port}, DeviceModel: "X20"}
	}
	return map[string]*DecoInfo{
		"127.0.0.1": unit("127.0.0.1", "B0-A7-B9-3E-16-94", masterDevID, "master"),
		"127.0.0.2": unit("127.0.0.2", "B0-A7-B9-3E-17-00", tdpID205, "slave"),
		"127.0.0.3": unit("127.0.0.3", "B0-A7-B9-3E-15-FC", tdpID232, "slave"),
	}
}

func newRig(t *testing.T, mut func(*MeshConfig)) *rig {
	t.Helper()
	r := &rig{t: t, emu: newMeshEmu(), clock: &fakeClock{t: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)},
		logs: &syncBuf{}, dir: t.TempDir()}
	r.srv = newSSHDeco(t, sha1hex(testTPLinkID), testPassword, r.emu.handle)
	r.tdp = tdpUnits(r.srv.port())
	cfg := MeshConfig{
		MasterIP:  "127.0.0.1",
		MasterMAC: "b0:a7:b9:3e:16:94",
		UnitIPs:   []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"},
		TPLinkID:  testTPLinkID,
		Password:  testPassword,
		StateDir:  r.dir,
		Heartbeat: 20 * time.Millisecond,
		Logf:      r.logs.logf,
		Discover: func(_ context.Context, ip string) (*DecoInfo, error) {
			r.tdpMu.Lock()
			defer r.tdpMu.Unlock()
			d := r.tdp[ip]
			if d == nil {
				return nil, errors.New("tdp timeout")
			}
			c := *d
			return &c, nil
		},
	}
	if mut != nil {
		mut(&cfg)
	}
	m, err := NewMesh(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.now = r.clock.Now
	m.state.DownSince = r.clock.Now()
	r.m = m
	t.Cleanup(m.shutdown)
	return r
}

func (r *rig) tdpEdit(ip string, f func(*DecoInfo)) {
	r.tdpMu.Lock()
	defer r.tdpMu.Unlock()
	f(r.tdp[ip])
}

func (r *rig) step() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r.m.step(ctx)
}

// waitDead waits (real time) until the client sees its transport die.
func (r *rig) waitDead() {
	r.t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if r.m.client == nil || !r.m.client.Alive() {
			return
		}
	}
	r.t.Fatal("transport did not die")
}

// noSecrets fails if the password, the TP-Link ID or the PSK leaked into
// the logs or the JSON of the snapshot (with Wi-Fi masked as -print will).
func (r *rig) noSecrets() {
	r.t.Helper()
	s := r.m.Snapshot()
	s.Wireless.Value = MaskWireless(s.Wireless.Value)
	js, err := json.Marshal(s)
	if err != nil {
		r.t.Fatal(err)
	}
	for _, where := range []string{r.logs.String(), string(js)} {
		for _, secret := range []string{testPassword, testTPLinkID, testPSK, b64(testPSK), b64(testPassword)} {
			if strings.Contains(where, secret) {
				r.t.Fatalf("secret %q leaked into %.300s", secret, where)
			}
		}
	}
	if cfg := fmt.Sprintf("%v %+v %#v", r.m.cfg, r.m.cfg, r.m.cfg); strings.Contains(cfg, testPassword) {
		r.t.Fatalf("password printed with the config: %s", cfg)
	}
}

func TestMeshBringUpAndPolling(t *testing.T) {
	r := newRig(t, nil)
	r.step()
	s := r.m.Snapshot()
	if !s.Connected || s.Latched != "" || s.Logins != 1 {
		t.Fatalf("not up: %+v", s)
	}
	if s.OperationMode != "AP" || s.Negotiation == nil || !s.Negotiation.HasComponent("block_list") {
		t.Fatalf("negotiation: mode=%q %+v", s.OperationMode, s.Negotiation)
	}
	want := fmt.Sprintf(`{"role":"owner","username":"%s"}`, AccountDigest(testTPLinkID))
	if got := r.emu.params(t, OpNegotiation, 0); got != want {
		t.Fatalf("negotiate params %s, want %s", got, want)
	}
	if conns, tries, logins := r.srv.counts(); conns != 1 || tries != 1 || logins != 1 {
		t.Fatalf("conns=%d tries=%d logins=%d", conns, tries, logins)
	}
	if !s.Devices.OK || len(s.Devices.Value.DeviceList) != 3 || !s.Clients.OK || len(s.Clients.Value.ClientList) != 1 ||
		!s.Speeds.OK || s.Speeds.Value.ClientListSpeed[0].DownSpeed != 340 || !s.Wireless.OK ||
		string(*s.Wireless.Value.Band5G1.Host.SSID) != "Home" || !s.Ports.OK || !s.Blocks.OK {
		t.Fatalf("cache incomplete: %+v", s)
	}
	if got := r.emu.params(t, OpGetDeviceEthPort, 0); !strings.Contains(got, `"dev205"`) || !strings.Contains(got, masterRawID) {
		t.Fatalf("0x4327 must ask for every device_id: %s", got)
	}
	if got := r.emu.params(t, OpGetDeviceList, 0); got != "" {
		t.Fatalf("0x400f must send null params, got %s", got)
	}

	// TOFU: the master's fingerprint is remembered, mode 0600.
	p := filepath.Join(r.dir, hostKeyFile)
	b, err := os.ReadFile(p)
	if err != nil || strings.TrimSpace(string(b)) != r.srv.fingerprint() {
		t.Fatalf("host key file: %q %v", b, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("host key file mode %v", fi.Mode())
	}

	// Intervals: lists every 15 s, wireless every 60 s, ports every 5 min.
	for i := 1; i <= 4; i++ {
		r.clock.Add(15 * time.Second)
		r.step()
	}
	if n := r.emu.count(OpGetDeviceList); n != 5 {
		t.Fatalf("device list polls %d, want 5", n)
	}
	if n := r.emu.count(OpGetWireless); n != 2 {
		t.Fatalf("wireless polls %d, want 2", n)
	}
	if n := r.emu.count(OpGetDeviceEthPort); n != 1 {
		t.Fatalf("port polls %d, want 1", n)
	}
	r.step() // nothing due
	if n := r.emu.count(OpGetDeviceList); n != 5 {
		t.Fatalf("device list polled early: %d", n)
	}

	// Fresh data replaces the cache.
	r.emu.ok(OpGetDeviceList, devicesJSON(`{"device_id":"`+masterRawID+`","mac":"B0-A7-B9-3E-16-94","role":"master"}`))
	r.clock.Add(15 * time.Second)
	r.step()
	if s := r.m.Snapshot(); len(s.Devices.Value.DeviceList) != 1 || !s.Devices.At.Equal(r.clock.Now()) {
		t.Fatalf("device list not refreshed: %+v", s.Devices)
	}

	// 1010 is "no data"; another error_code three times disables the opcode.
	r.emu.set(OpGetBlockList, `{"error_code":1010}`)
	r.emu.set(OpGetDeviceEthPort, `{"error_code":-40210}`)
	for i := 0; i < 4; i++ {
		r.clock.Add(5 * time.Minute)
		r.step()
	}
	s = r.m.Snapshot()
	if !s.Blocks.OK || len(s.Blocks.Value.ClientList) != 0 {
		t.Fatalf("1010 must cache an empty block list: %+v", s.Blocks)
	}
	if !s.Ports.Disabled || r.emu.count(OpGetDeviceEthPort) != 1+disableAfter {
		t.Fatalf("0x4327 not disabled after %d errors: %+v calls=%d", disableAfter, s.Ports, r.emu.count(OpGetDeviceEthPort))
	}
	if !s.Connected || s.Logins != 1 {
		t.Fatalf("polling must reuse the session: %+v", s)
	}

	// Heartbeats are echoed and recorded.
	for end := time.Now().Add(2 * time.Second); r.m.client.LastHeartbeatEcho().IsZero() && time.Now().Before(end); {
		time.Sleep(5 * time.Millisecond)
	}
	r.step()
	if r.m.Snapshot().LastHeartbeat.IsZero() {
		t.Fatal("no heartbeat echo recorded")
	}
	r.noSecrets()
}

func TestMeshWarnsInRouterMode(t *testing.T) {
	r := newRig(t, nil)
	r.emu.ok(OpNegotiation, `{"operation_mode":"Router"}`)
	r.step()
	if s := r.m.Snapshot(); !s.Connected || s.OperationMode != "Router" {
		t.Fatalf("%+v", s)
	}
	if !strings.Contains(r.logs.String(), "not AP") {
		t.Fatalf("no Router-mode warning: %s", r.logs.String())
	}
}

func TestMeshReconnectBackoff(t *testing.T) {
	r := newRig(t, nil)
	r.srv.setRefuse(true)
	start := r.clock.Now()
	var attempts []time.Duration // offsets of SSH connection attempts
	seen := 0
	for off := time.Duration(0); off <= 45*time.Minute; off += time.Second {
		r.clock.Set(start.Add(off))
		r.step()
		if c, _, _ := r.srv.counts(); c != seen {
			seen = c
			attempts = append(attempts, off)
		}
	}
	var gaps []time.Duration
	for i := 1; i < len(attempts); i++ {
		gaps = append(gaps, attempts[i]-attempts[i-1])
	}
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	if len(gaps) < len(want) {
		t.Fatalf("attempts at %v", attempts)
	}
	for i, w := range want {
		if gaps[i] != w {
			t.Fatalf("gap %d = %v, want %v (attempts %v)", i, gaps[i], w, attempts)
		}
	}
	if s := r.m.Snapshot(); s.Connected || s.Latched != "" || s.LastError == "" || s.NextLoginAt.IsZero() {
		t.Fatalf("state after failures: %+v", s)
	}
	if _, tries, _ := r.srv.counts(); tries != 0 {
		t.Fatalf("refused connections must not reach auth: %d", tries)
	}

	// The device comes back: the next scheduled login succeeds.
	r.srv.setRefuse(false)
	next := r.m.Snapshot().NextLoginAt
	r.clock.Set(next.Add(-time.Second))
	r.step()
	if r.m.Snapshot().Connected {
		t.Fatal("logged in before the backoff expired")
	}
	r.clock.Set(next)
	r.step()
	if !r.m.Snapshot().Connected {
		t.Fatalf("not reconnected: %+v", r.m.Snapshot())
	}

	// A session lost soon after login keeps the long backoff ...
	upAt := r.clock.Now()
	r.srv.bye(2)
	r.waitDead()
	r.clock.Add(time.Second)
	r.step()
	if s := r.m.Snapshot(); s.Connected || !s.NextLoginAt.Equal(upAt.Add(15*time.Minute)) {
		t.Fatalf("short session: next login %v, want %v", s.NextLoginAt, upAt.Add(15*time.Minute))
	}
	// ... a session that was stable resets it to the floor.
	r.clock.Set(r.m.Snapshot().NextLoginAt)
	r.step()
	upAt = r.clock.Now()
	r.clock.Add(stableAfter)
	r.step()
	r.srv.bye(2)
	r.waitDead()
	r.step()
	if s := r.m.Snapshot(); !s.Connected || s.Logins != len(attempts)+3 || !r.m.lastLogin.Equal(upAt.Add(stableAfter)) {
		t.Fatalf("stable session should relogin at once (>= %v after the last): %+v", RedialFloor, s)
	}
}

func TestMeshPrecheckNoReplyIsNotARefusal(t *testing.T) {
	r := newRig(t, nil)
	r.tdpMu.Lock()
	r.tdp["127.0.0.1"] = nil
	r.tdpMu.Unlock()
	r.step()
	r.clock.Add(30 * time.Second)
	r.step()
	s := r.m.Snapshot()
	if s.Latched != "" || s.Logins != 0 || !s.NextLoginAt.Equal(r.clock.Now().Add(30*time.Second)) {
		t.Fatalf("%+v", s)
	}
	if c, _, _ := r.srv.counts(); c != 0 {
		t.Fatal("dialled without a TDP reply")
	}
	// A satellite that does not answer does not block login.
	r.tdpMu.Lock()
	r.tdp = tdpUnits(r.srv.port())
	r.tdp["127.0.0.3"] = nil
	r.tdpMu.Unlock()
	r.clock.Add(30 * time.Second)
	r.step()
	if !r.m.Snapshot().Connected {
		t.Fatalf("%+v", r.m.Snapshot())
	}
}

func TestMeshPrecheckRefusals(t *testing.T) {
	one := 1
	for _, tc := range []struct {
		name string
		edit func(map[string]*DecoInfo)
		want string
	}{
		{"owner hash mismatch", func(u map[string]*DecoInfo) { u["127.0.0.1"].Owner = md5hex("owner@example.com") }, "owner hash"},
		{"empty owner", func(u map[string]*DecoInfo) { u["127.0.0.1"].Owner = "" }, "owner hash"},
		{"sha256 owner mismatch", func(u map[string]*DecoInfo) { u["127.0.0.1"].HashVersion = "1" }, "owner hash"},
		{"two masters", func(u map[string]*DecoInfo) { u["127.0.0.2"].Role = "master" }, "exactly one"},
		{"no master", func(u map[string]*DecoInfo) { u["127.0.0.1"].Role = "slave" }, "exactly one"},
		{"other unit is master", func(u map[string]*DecoInfo) {
			u["127.0.0.1"].Role, u["127.0.0.3"].Role = "slave", "master"
		}, "not the configured"},
		{"master mac", func(u map[string]*DecoInfo) { u["127.0.0.1"].MAC = "B0-A7-B9-3E-15-FC" }, "mac"},
		{"device id", func(u map[string]*DecoInfo) { u["127.0.0.1"].DeviceID = "dev999" }, "master_device_id"},
		{"factory default", func(u map[string]*DecoInfo) { u["127.0.0.1"].FactoryDefault = true }, "factory_default"},
		{"tls", func(u map[string]*DecoInfo) { u["127.0.0.1"].TPAP = &TPAP{Port: 4433, Pake: []int{2}} }, "TLS"},
		{"tps banner", func(u map[string]*DecoInfo) { u["127.0.0.1"].BannerType = &one }, "TPS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil)
			r.tdpMu.Lock()
			tc.edit(r.tdp)
			r.tdpMu.Unlock()
			_, err := r.m.Precheck(context.Background())
			var re *RefusedError
			if !errors.As(err, &re) || !strings.Contains(re.Reason, tc.want) {
				t.Fatalf("Precheck = %v, want refusal about %q", err, tc.want)
			}
			r.step()
			r.clock.Add(time.Hour)
			r.step()
			if c, _, _ := r.srv.counts(); c != 0 {
				t.Fatalf("connected %d times despite the refusal", c)
			}
			if s := r.m.Snapshot(); s.Latched == "" || s.Logins != 0 {
				t.Fatalf("%+v", s)
			}
			r.noSecrets()
		})
	}
}

func TestMeshAuthFailureLatches(t *testing.T) {
	r := newRig(t, nil)
	r.srv.setPassword("the-real-one")
	r.step()
	s := r.m.Snapshot()
	if s.Connected || !strings.Contains(s.Latched, "rejected") {
		t.Fatalf("not latched: %+v", s)
	}
	for i := 0; i < 48; i++ {
		r.clock.Add(30 * time.Minute)
		r.step()
	}
	if conns, tries, _ := r.srv.counts(); conns != 1 || tries != 1 {
		t.Fatalf("second login after an auth failure: conns=%d password attempts=%d", conns, tries)
	}
	res := <-r.m.Submit(Command{Kind: CmdReboot, DeviceID: "dev205"})
	if !errors.Is(res.Err, ErrLatched) {
		t.Fatalf("command while latched: %v", res.Err)
	}
	r.noSecrets()
}

func TestMeshHostKey(t *testing.T) {
	t.Run("pinned ok", func(t *testing.T) {
		var r *rig
		r = newRig(t, func(c *MeshConfig) { c.StateDir = "" })
		r.m.cfg.HostKeySHA256 = r.srv.fingerprint()
		r.step()
		if !r.m.Snapshot().Connected {
			t.Fatalf("%+v", r.m.Snapshot())
		}
	})
	t.Run("pinned mismatch", func(t *testing.T) {
		r := newRig(t, func(c *MeshConfig) { c.HostKeySHA256 = "SHA256:wcQkT6FKAB+PxFEAkHQhV3++pQsPCk9bNpU+4EfN4b4" })
		r.step()
		r.clock.Add(time.Hour)
		r.step()
		if s := r.m.Snapshot(); !strings.Contains(s.Latched, "host key") {
			t.Fatalf("%+v", s)
		}
		if conns, tries, _ := r.srv.counts(); conns != 1 || tries != 0 {
			t.Fatalf("password must not be sent to an unpinned host: conns=%d tries=%d", conns, tries)
		}
	})
	t.Run("tofu mismatch", func(t *testing.T) {
		r := newRig(t, nil)
		if err := os.WriteFile(filepath.Join(r.dir, hostKeyFile), []byte("SHA256:somethingelse\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		r.step()
		if s := r.m.Snapshot(); !strings.Contains(s.Latched, "host key") {
			t.Fatalf("%+v", s)
		}
		if _, tries, _ := r.srv.counts(); tries != 0 {
			t.Fatal("password sent to a changed host key")
		}
	})
}

func TestMeshBye(t *testing.T) {
	for _, tc := range []struct {
		reason byte
		delay  time.Duration // from the BYE; 0: the normal backoff from the login
		latch  bool
	}{
		{reason: 2},
		{reason: 3, delay: 10 * time.Minute},
		{reason: 7, delay: 10 * time.Minute},
		{reason: 4, delay: 3 * time.Minute},
		{reason: 6, delay: 3 * time.Minute},
		{reason: 16},
		{reason: 8, latch: true},
	} {
		t.Run(fmt.Sprint(tc.reason), func(t *testing.T) {
			r := newRig(t, nil)
			r.step()
			login := r.clock.Now()
			r.clock.Add(5 * time.Second)
			r.srv.bye(tc.reason)
			r.waitDead()
			byeAt := r.clock.Now()
			r.step()
			s := r.m.Snapshot()
			if s.Connected || s.LastBye == nil || s.LastBye.Reason != tc.reason {
				t.Fatalf("%+v", s)
			}
			if tc.latch {
				if !strings.Contains(s.Latched, "AUTH_CHANGED") {
					t.Fatalf("reason 8 must latch: %+v", s)
				}
				r.clock.Add(24 * time.Hour)
				r.step()
				if c, _, _ := r.srv.counts(); c != 1 {
					t.Fatal("logged in after AUTH_CHANGED")
				}
				return
			}
			next := login.Add(RedialFloor)
			if tc.delay > 0 {
				next = byeAt.Add(tc.delay)
			}
			if !s.NextLoginAt.Equal(next) {
				t.Fatalf("next login at +%v, want +%v", s.NextLoginAt.Sub(login), next.Sub(login))
			}
			r.clock.Set(next.Add(-time.Second))
			r.step()
			if c, _, _ := r.srv.counts(); c != 1 {
				t.Fatal("relogin before the BYE back-off")
			}
			r.clock.Set(next)
			r.step()
			if s := r.m.Snapshot(); !s.Connected || s.Logins != 2 {
				t.Fatalf("no relogin after the back-off: %+v", s)
			}
		})
	}
}

func recv(t *testing.T, ch <-chan CommandResult) CommandResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	default:
		t.Fatal("no command result")
	}
	return CommandResult{}
}

func wifiBody(t *testing.T, r *rig, ssid string) *WirelessInfo {
	t.Helper()
	cur := r.m.Snapshot().Wireless.Value
	h := *cur.Band2G4.Host
	s := B64(ssid)
	h.SSID = &s
	return BuildHostSet(cur, h)
}

func TestMeshCommandsDryRun(t *testing.T) {
	r := newRig(t, nil) // apply defaults to false
	r.step()
	ch := r.m.Submit(Command{Kind: CmdReboot, MAC: "b0:a7:b9:3e:17:00"})
	wch := r.m.Submit(Command{Kind: CmdSetWireless, Wireless: wifiBody(t, r, "NewHome")})
	r.step()
	res := recv(t, ch)
	if res.Err != nil || !res.DryRun || res.Opcode != OpRebootDevices || res.Plan != `{"device_list":[{"device_id":"dev205"}]}` {
		t.Fatalf("%+v", res)
	}
	w := recv(t, wch)
	if w.Err != nil || !w.DryRun || !strings.Contains(w.Plan, `"password":"***"`) || !strings.Contains(w.Plan, b64("NewHome")) {
		t.Fatalf("%+v", w)
	}
	for _, op := range []uint16{OpRebootDevices, OpSetWireless, OpBlockClients, OpUnblockClients} {
		if r.emu.count(op) != 0 {
			t.Fatalf("apply=false sent 0x%04x", op)
		}
	}
	if !strings.Contains(r.logs.String(), "apply=false, would send wifi-set") {
		t.Fatal("dry run not logged")
	}
	r.noSecrets()
}

// A command submitted after step() drained the dry-run queue (here: while
// the speed list is being polled) must not be sent with apply=false.
func TestMeshApplyOffGatesCommandsSubmittedMidStep(t *testing.T) {
	r := newRig(t, nil) // apply defaults to false
	r.step()
	got := make(chan (<-chan CommandResult), 4)
	var once sync.Once
	r.emu.setHook(func(op uint16) {
		if op == OpGetClientSpeedList {
			once.Do(func() {
				got <- r.m.Submit(Command{Kind: CmdReboot, MAC: "b0:a7:b9:3e:17:00"})
				got <- r.m.Submit(Command{Kind: CmdBlock, MACs: []string{"aa:bb:cc:dd:ee:01"}})
				got <- r.m.Submit(Command{Kind: CmdUnblock, MACs: []string{"aa:bb:cc:dd:ee:09"}})
			})
		}
	})
	r.clock.Add(15 * time.Second)
	r.step()
	r.emu.setHook(nil)
	if len(got) != 3 {
		t.Fatalf("hook submitted %d commands", len(got))
	}
	for range 3 {
		if res := recv(t, <-got); res.Err != nil || !res.DryRun {
			t.Fatalf("mid-step command with apply=false: %+v", res)
		}
	}
	for _, op := range []uint16{OpRebootDevices, OpSetWireless, OpBlockClients, OpUnblockClients} {
		if n := r.emu.count(op); n != 0 {
			t.Fatalf("apply=false sent 0x%04x %d times", op, n)
		}
	}
}

// masterConsistent (design §3.3) works on device_list data; the TDP ids are
// md5hex of the device_list ids, as in the app (TmpGenericDevice.a()).
func TestMasterConsistent(t *testing.T) {
	master := func(f func(*Deco)) Deco {
		d := Deco{DecoBase: DecoBase{DeviceID: masterRawID, MAC: "B0-A7-B9-3E-16-94"}, MasterDeviceID: masterRawID, Role: "master"}
		if f != nil {
			f(&d)
		}
		return d
	}
	sat := Deco{DecoBase: DecoBase{DeviceID: "dev205", MAC: "B0-A7-B9-3E-17-00"}, Role: "slave"}
	tdp := &DecoInfo{DeviceID: masterDevID, MasterDeviceID: masterDevID, Role: "master"}
	for _, tc := range []struct {
		name string
		devs []Deco
		tdp  *DecoInfo
		ok   bool
	}{
		{"tdp md5 of device_list id", []Deco{master(nil), sat}, tdp, true},
		{"uppercase tdp digest", []Deco{master(nil), sat}, &DecoInfo{MasterDeviceID: strings.ToUpper(masterDevID)}, true},
		{"tdp master_device_id empty: device_id used", []Deco{master(nil), sat}, &DecoInfo{DeviceID: masterDevID}, true},
		{"no master_device_id in device_list", []Deco{master(func(d *Deco) { d.MasterDeviceID = "" }), sat}, tdp, true},
		{"absent role means master", []Deco{master(func(d *Deco) { d.Role = "" }), sat}, tdp, true},
		{"tdp names another device", []Deco{master(nil), sat}, &DecoInfo{MasterDeviceID: md5hex("other")}, false},
		{"device_list master_device_id differs", []Deco{master(func(d *Deco) { d.MasterDeviceID = "dev205" }), sat}, tdp, false},
		{"master mac differs", []Deco{master(func(d *Deco) { d.MAC = "B0-A7-B9-3E-15-FC" }), sat}, tdp, false},
		{"two masters", []Deco{master(nil), {DecoBase: sat.DecoBase, Role: "master"}}, tdp, false},
		{"no device_id", []Deco{master(func(d *Deco) { d.DeviceID, d.MasterDeviceID = "", "" }), sat}, tdp, false},
		{"tdp not read", []Deco{master(nil), sat}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &Mesh{cfg: MeshConfig{MasterMAC: "b0:a7:b9:3e:16:94"}}
			s := &MeshState{Master: tc.tdp, Devices: Polled[DeviceListResult]{Value: &DeviceListResult{DeviceList: tc.devs}}}
			if err := m.masterConsistent(s); (err == nil) != tc.ok {
				t.Fatalf("masterConsistent = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestMeshCommandsApply(t *testing.T) {
	r := newRig(t, func(c *MeshConfig) { c.Apply = true })
	ch := r.m.Submit(Command{Kind: CmdReboot, MAC: "B0:A7:B9:3E:17:00"})
	select {
	case <-ch:
		t.Fatal("Submit must not run the command inline")
	default:
	}
	r.step() // login, poll, then the queue
	if res := recv(t, ch); res.Err != nil || string(res.Raw) != `{"reboot_time":80}` {
		t.Fatalf("reboot: %+v", res)
	}
	if got := r.emu.params(t, OpRebootDevices, 0); got != `{"device_list":[{"device_id":"dev205"}]}` {
		t.Fatalf("0x4016 params %s", got)
	}
	if n := r.emu.count(OpGetDeviceList); n != 2 {
		t.Fatalf("device list not re-read after reboot: %d", n)
	}

	blk := r.m.Submit(Command{Kind: CmdBlock, MACs: []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:77"}})
	unb := r.m.Submit(Command{Kind: CmdUnblock, MACs: []string{"aa:bb:cc:dd:ee:09"}})
	r.step()
	if res := recv(t, blk); res.Err != nil {
		t.Fatal(res.Err)
	}
	if res := recv(t, unb); res.Err != nil {
		t.Fatal(res.Err)
	}
	wantBlock := `{"client_list":[{"client_type":"phone","mac":"AA-BB-CC-DD-EE-01","name":"` + b64("phone") +
		`"},{"client_type":"other","mac":"AA-BB-CC-DD-EE-77"}]}`
	if got := r.emu.params(t, OpBlockClients, 0); got != wantBlock {
		t.Fatalf("0x4017 params\n got %s\nwant %s", got, wantBlock)
	}
	if got := r.emu.params(t, OpUnblockClients, 0); got != `{"client_list":["AA-BB-CC-DD-EE-09"]}` {
		t.Fatalf("0x4019 params %s", got)
	}

	before := r.emu.count(OpGetWireless)
	res := <-func() <-chan CommandResult {
		c := r.m.Submit(Command{Kind: CmdSetWireless, Wireless: wifiBody(t, r, "NewHome")})
		r.step()
		return c
	}()
	if res.Err != nil || string(res.Raw) != "true" || strings.Contains(res.Plan, b64(testPSK)) {
		t.Fatalf("wifi set: %+v", res)
	}
	sent := r.emu.params(t, OpSetWireless, 0)
	if !strings.Contains(sent, b64(testPSK)) || !strings.Contains(sent, b64("NewHome")) ||
		strings.Contains(sent, "radio") || strings.Contains(sent, "config_spec") {
		t.Fatalf("0x4008 body must be partial and carry the real host: %s", sent)
	}
	if r.emu.count(OpGetWireless) != before+1 {
		t.Fatal("wireless not re-read after the Set")
	}
	again := r.m.Submit(Command{Kind: CmdSetWireless, Wireless: wifiBody(t, r, "Other")})
	r.step()
	if res := recv(t, again); !errors.Is(res.Err, ErrRateLimited) {
		t.Fatalf("second Set within 5 min: %v", res.Err)
	}
	r.noSecrets()

	// device_list disagreeing with the configured master refuses writes.
	r.emu.ok(OpGetDeviceList, devicesJSON(
		`{"device_id":"`+masterRawID+`","mac":"B0-A7-B9-3E-16-94","role":"master"}`,
		`{"device_id":"dev205","mac":"B0-A7-B9-3E-17-00","role":"master"}`))
	r.clock.Add(15 * time.Second)
	bad := r.m.Submit(Command{Kind: CmdReboot, DeviceID: "dev205"})
	r.step()
	if res := recv(t, bad); !errors.Is(res.Err, ErrOwnerMismatch) {
		t.Fatalf("want ErrOwnerMismatch, got %v", res.Err)
	}
	if n := r.emu.count(OpRebootDevices); n != 1 {
		t.Fatal("refused reboot was sent")
	}
}

func TestMeshCommandWaitsForSessionThenExpires(t *testing.T) {
	r := newRig(t, func(c *MeshConfig) { c.Apply = true; c.CommandTimeout = 2 * time.Minute })
	r.srv.setRefuse(true)
	ch := r.m.Submit(Command{Kind: CmdReboot, DeviceID: "dev205"})
	r.step()
	select {
	case res := <-ch:
		t.Fatalf("answered without a session: %+v", res)
	default:
	}
	// The device returns within the command's lifetime: it runs.
	r.srv.setRefuse(false)
	r.clock.Add(time.Minute)
	r.step()
	if res := recv(t, ch); res.Err != nil {
		t.Fatal(res.Err)
	}
	// Now it never comes back.
	r.srv.bye(2)
	r.waitDead()
	r.srv.setRefuse(true)
	ch = r.m.Submit(Command{Kind: CmdReboot, DeviceID: "dev205"})
	r.step()
	r.clock.Add(2 * time.Minute)
	r.step()
	if res := recv(t, ch); !errors.Is(res.Err, ErrNotConnected) {
		t.Fatalf("want ErrNotConnected, got %v", res.Err)
	}
}

func TestMeshRunAndShutdown(t *testing.T) {
	r := newRig(t, nil)
	r.m.now = time.Now
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.m.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for !r.m.Snapshot().Wireless.OK { // concurrent reads race the poller under -race
		if time.Now().After(deadline) {
			t.Fatalf("no poll: %+v", r.m.Snapshot())
		}
		time.Sleep(5 * time.Millisecond)
	}
	ch := r.m.Submit(Command{Kind: CmdReboot, DeviceID: "dev205"})
	select {
	case res := <-ch:
		if !res.DryRun {
			t.Fatalf("%+v", res)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Submit did not wake the loop")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if r.emu.count(OpcodeTokenFree) != 1 {
		t.Fatal("token not freed on shutdown")
	}
	if r.m.Snapshot().Connected {
		t.Fatal("still connected after Run")
	}
	if res := <-r.m.Submit(Command{Kind: CmdReboot, DeviceID: "dev205"}); !errors.Is(res.Err, ErrStopped) {
		t.Fatalf("Submit after Run: %v", res.Err)
	}
}

func TestBackoffSchedule(t *testing.T) {
	m, err := NewMesh(MeshConfig{MasterIP: "x", MasterMAC: "b0:a7:b9:3e:16:94", TPLinkID: "a", Password: "b",
		RedialMin: time.Second}) // below the floor: raised to 60 s
	if err != nil {
		t.Fatal(err)
	}
	for n, want := range map[int]time.Duration{1: time.Minute, 2: 2 * time.Minute, 4: 8 * time.Minute, 5: 15 * time.Minute, 50: 15 * time.Minute} {
		if got := m.backoff(n); got != want {
			t.Errorf("backoff(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestMACHelpers(t *testing.T) {
	for _, tc := range []struct{ in, norm, likeDash, likeLower string }{
		{"B0-A7-B9-3E-16-94", "b0:a7:b9:3e:16:94", "B0-A7-B9-3E-16-94", "b0:a7:b9:3e:16:94"},
		{"b0a7b93e1694", "b0:a7:b9:3e:16:94", "B0-A7-B9-3E-16-94", "b0:a7:b9:3e:16:94"},
		{"zz:a7:b9:59:27:94", "", "zz:a7:b9:59:27:94", "zz:a7:b9:59:27:94"},
		{"b0:a7", "", "b0:a7", "b0:a7"},
	} {
		if got := NormMAC(tc.in); got != tc.norm {
			t.Errorf("NormMAC(%q) = %q", tc.in, got)
		}
		if got := MACLike("AA-BB-CC-DD-EE-FF", tc.in); got != tc.likeDash {
			t.Errorf("MACLike(dash, %q) = %q", tc.in, got)
		}
		if got := MACLike("aa:bb:cc:dd:ee:ff", tc.in); got != tc.likeLower {
			t.Errorf("MACLike(colon, %q) = %q", tc.in, got)
		}
	}
}

func TestRedaction(t *testing.T) {
	got := string(RedactJSON([]byte(`{"a":{"password":"c2VjcmV0","x":[{"default_password":"p"}]},"ssid":"s"}`)))
	if got != `{"a":{"password":"***","x":[{"default_password":"***"}]},"ssid":"s"}` {
		t.Fatal(got)
	}
	if got := string(RedactJSON([]byte(`{"password":`))); strings.Contains(got, "password") {
		t.Fatal(got)
	}
	pw := B64(testPSK)
	w := &WirelessInfo{Band2G4: &WirelessBand{Host: &WirelessHost{Password: &pw}, Guest: &WirelessGuest{Password: &pw}}}
	mw := MaskWireless(w)
	b, _ := json.Marshal(mw)
	if strings.Contains(string(b), b64(testPSK)) || string(*w.Band2G4.Host.Password) != testPSK {
		t.Fatalf("mask leaked or mutated the original: %s", b)
	}
	s := Secret(testPassword)
	out := fmt.Sprintf("%v %s %q %+v %#v %x", s, s, s, Config{CloudPassword: s}, Config{CloudPassword: s}, s)
	j, err := json.Marshal(struct{ P Secret }{s})
	if err != nil || strings.Contains(out+string(j), testPassword) {
		t.Fatalf("secret printed: %s %s", out, j)
	}
}

// NEGOTIATE values Gson reads leniently (numbers for String fields, "true"
// for Boolean ones) must not fail Connect; a type no lenient field takes is
// kept as NegotiationErr with the rest of the result, like the app does.
func TestMeshNegotiateLenient(t *testing.T) {
	for _, tc := range []struct {
		name, result string
		wantErr      bool
	}{
		{"gson lenient values", `{"operation_mode":"AP","device_color":1,"front_modem":0,"eco_mode_advanced_status":0,` +
			`"topology_limit":"true","alert_operation_mode_switch":"false","working_status":1}`, false},
		{"unexpected type kept as an error", `{"operation_mode":"AP","component_list":{"id":"wireless"}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil)
			r.emu.ok(OpNegotiation, tc.result)
			r.step()
			s := r.m.Snapshot()
			if !s.Connected || s.OperationMode != "AP" || s.Logins != 1 || (s.NegotiationErr != "") != tc.wantErr {
				t.Fatalf("connected=%v mode=%q logins=%d negotiation_err=%q", s.Connected, s.OperationMode, s.Logins, s.NegotiationErr)
			}
			if !tc.wantErr && (s.Negotiation.TopologyLimit == nil || !bool(*s.Negotiation.TopologyLimit) || s.Negotiation.EcoModeAdvanced != "0") {
				t.Fatalf("negotiation %+v", s.Negotiation)
			}
		})
	}
}

// Java String fields may arrive as numbers; a field of another unexpected
// type keeps the rest of a list (never Wi-Fi) and does not drop the session.
func TestMeshPollLenientDecode(t *testing.T) {
	r := newRig(t, nil)
	host := `{"enable":true,"ssid":"` + b64("Home") + `","password":"` + b64(testPSK) + `","encryption_mode":"wpa2"}`
	r.emu.ok(OpGetWireless, `{"band2_4":{"host":`+host+`,"radio":{"channel":8,"enable":true}},"band5_1":{"host":`+host+`,"radio":{"channel":44,"enable":true}}}`)
	r.emu.ok(OpGetClientList, `{"client_list":[{"mac":"AA-BB-CC-DD-EE-01","online":true,"owner_id":3,"space_id":7,`+
		`"linked_device_info":{"device_id":"dev205","connection_type":["band5"],"bandwidth":80}}]}`)
	r.step()
	s := r.m.Snapshot()
	if !s.Wireless.OK || s.Wireless.Value.Band5G1.Radio.Channel != "44" || !s.Clients.OK || s.Clients.Err != "" ||
		s.Clients.Value.ClientList[0].OwnerID != "3" || s.Clients.Value.ClientList[0].LinkedDeviceInfo.Bandwidth != "80" {
		t.Fatalf("wireless %+v clients %+v", s.Wireless, s.Clients)
	}

	r.emu.ok(OpGetClientList, `{"client_list":[{"mac":"AA-BB-CC-DD-EE-02","online":true,"ip":17}]}`)
	r.emu.ok(OpGetWireless, `{"band2_4":{"host":`+host+`,"guest":{"access_duration":"forever"}}}`)
	for range 2 {
		r.clock.Add(MinClientsEvery) // 0x4012 is re-read every 10 min
		r.step()
	}
	s = r.m.Snapshot()
	if !s.Connected || s.Logins != 1 {
		t.Fatalf("a schema mismatch dropped the session: %+v", s)
	}
	if !s.Clients.OK || s.Clients.Err == "" || len(s.Clients.Value.ClientList) != 1 ||
		s.Clients.Value.ClientList[0].MAC != "AA-BB-CC-DD-EE-02" || !s.Clients.At.Equal(r.clock.Now()) {
		t.Fatalf("partial client list not kept: %+v", s.Clients)
	}
	if s.Wireless.OK || s.Wireless.Err == "" || s.Wireless.Value.Band5G1 == nil {
		t.Fatalf("partial Wi-Fi must not replace the cache: %+v", s.Wireless)
	}
	if n := strings.Count(r.logs.String(), "partial decode kept"); n != 1 {
		t.Fatalf("partial decode logged %d times", n)
	}
}
