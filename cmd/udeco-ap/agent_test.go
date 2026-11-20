// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
	"github.com/antoniocosta/unifi-openwrt/internal/inform"
	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

// Fakes only: nothing here touches a device or a real controller.

const (
	unitMAC   = "b0:a7:b9:00:00:05"
	gwMAC     = "60:22:32:00:00:01"
	staMAC    = "aa:bb:cc:00:00:01"
	testKey   = "0123456789abcdef0123456789abcdef"
	fakePSK   = "Fake-Test-PSK-77"   // a made-up test passphrase
	fakeRadSc = "fake-radius-secret" // a made-up test RADIUS secret
)

// testCfg is a system_cfg with one WPA2 WLAN on 5 GHz.
var testCfg = "radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght20\nradio.2.phyname=wifi1\nradio.2.ieee_mode=11acvht80\n" +
	"wireless.1.ssid=net\nwireless.1.id=w1\nwireless.1.parent=wifi1\nwireless.1.devname=wifi1ap1\n" +
	"aaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\naaa.1.wpa.psk=" + fakePSK + "\n"

// recorder is the shared, ordered call log of the fakes.
type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) add(c string) {
	r.mu.Lock()
	r.calls = append(r.calls, c)
	r.mu.Unlock()
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.calls...)
}

func (r *recorder) index(c string) int { return slices.Index(r.list(), c) }

func (r *recorder) count(c string) int {
	n := 0
	for _, x := range r.list() {
		if x == c {
			n++
		}
	}
	return n
}

type fakeCol struct {
	rec      *recorder
	mu       sync.Mutex
	fail     error
	scanBusy bool                     // WithoutScan waits until its ctx ends
	snap     func() *apstate.Snapshot // nil = testSnapshot
}

func (c *fakeCol) Collect(ctx context.Context) (*apstate.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return nil, c.fail
	}
	if c.snap != nil {
		return c.snap(), nil
	}
	return testSnapshot(), nil
}

func (c *fakeCol) Caps(ctx context.Context) (wl.Caps, error) {
	return wl.Caps{Country: "IN", Bands: map[string]wl.BandCaps{"ng": {NSS: 2, HE: true}, "na": {NSS: 2, VHT: true, HE: true}}}, nil
}

func (c *fakeCol) HomeScan(ctx context.Context, band string) (*apstate.ScanResult, error) {
	c.rec.add("homescan:" + band)
	return &apstate.ScanResult{Band: band, Time: time.Now(), BSS: []apstate.BSS{
		{BSSID: "11:22:33:44:55:77", SSID: "same-channel", Freq: 5200, Channel: 40, Width: 40, CenterFreq: 5190, Signal: -60, Security: "WPA2-Personal (AES/CCMP)"},
	}}, nil
}

func (c *fakeCol) Scan(ctx context.Context, band string) (*apstate.ScanResult, error) {
	c.rec.add("scan:" + band)
	return &apstate.ScanResult{Band: band, Time: time.Now().Add(-3 * time.Second),
		BSS: []apstate.BSS{
			{BSSID: "11:22:33:44:55:66", SSID: "neighbour", Freq: 5180, Channel: 36, Width: 80, CenterFreq: 5210, Signal: -70, Security: "wpapsk"},
			// a VAP of a LAN device (middle bytes of gwMAC): a UniFi neighbour
			{BSSID: "62:22:32:00:00:09", SSID: "other", Freq: 5200, Channel: 40, Width: 20, CenterFreq: 5200, Signal: -50, Security: "wpapsk"},
		},
		Spectrum: []apstate.SpectrumEntry{{Channel: 36, Width: 20, CenterFreq: 5180, Utilization: 12, Interference: -95}},
	}, nil
}

func (c *fakeCol) Invalidate() { c.rec.add("invalidate") }

// Spectrum: the unit tests have no spectrum runner (the e2e tests run the
// real one, spectrum_e2e_test.go).
func (c *fakeCol) Spectrum(ctx context.Context, band string) (*wl.SpectrumRunner, error) {
	c.rec.add("spectrum:" + band)
	return nil, errors.New("fake: no spectrum runner")
}

// WithoutScan runs fn unless scanBusy is set: then it waits for ctx, as
// the real one does while a scan holds the lock.
func (c *fakeCol) WithoutScan(ctx context.Context, fn func(context.Context) error) error {
	c.mu.Lock()
	busy := c.scanBusy
	c.mu.Unlock()
	if busy {
		c.rec.add("withoutscan:busy")
		<-ctx.Done()
		return ctx.Err()
	}
	return fn(ctx)
}

func testSnapshot() *apstate.Snapshot {
	sta := apstate.Station{MAC: staMAC, Signal: -55, Noise: -92, TxRate: 866000, RxRate: 650000, Connected: 30, Authorized: true, VHT: true, HE: true, MHz: 80}
	return &apstate.Snapshot{
		Time: time.Now(), Hostname: "deco-205", Uptime: 5000, Load: [3]float64{0.5, 0.4, 0.3},
		CPUTotal: 1000, CPUIdle: 800, MemTotal: 264241152, MemFree: 100000000,
		MAC: unitMAC, IP: "192.168.0.205", Netmask: "255.255.255.0", Gateway: "192.168.0.1",
		ARP: map[string]string{gwMAC: "192.168.0.1", staMAC: "192.168.0.50"},
		FDB: []apstate.FDBEntry{{MAC: gwMAC, Port: 2}, {MAC: unitMAC, Port: 1, Local: true}},
		Ports: []apstate.Port{
			{Name: "eth0", MAC: unitMAC, Up: false, BridgePort: 1},
			{Name: "eth1", MAC: unitMAC, Up: true, Speed: 1000, FullDuplex: true, BridgePort: 2},
		},
		Radios: []apstate.Radio{
			{Iface: "wl0", Phy: "wl0", Mode: "Master", Band: "ng", Channel: 6, Width: 20, TxPower: 20, TxMin: 5, TxMax: 24, NSS: 2, HE: true},
			{Iface: "wl1", Phy: "wl1", Mode: "Master", Band: "na", Channel: 36, Width: 80, TxPower: 23, TxMin: 5, TxMax: 23, NSS: 2, VHT: true, HE: true,
				VAPs: []apstate.Radio{{Iface: "wl12", Mode: "Master", Band: "na", SSID: "net", BSSID: "b2:a7:b9:00:00:07",
					Stats: map[string]int64{"rx_bytes": 10}, Stations: []apstate.Station{sta}}}},
		},
	}
}

type fakeSys struct {
	rec        *recorder
	mu         sync.Mutex
	enforceErr error
	report     decosys.Report // what Enforce returns
	lan        decosys.LAN
	counts     map[string]int
}

func (s *fakeSys) Enforce(ctx context.Context) (decosys.Report, error) {
	s.rec.add("enforce")
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.report, s.enforceErr
}

func (s *fakeSys) Egress(ctx context.Context, on bool) error {
	s.rec.add(fmt.Sprintf("egress:%v", on))
	return nil
}

func (s *fakeSys) Restore(ctx context.Context) error {
	s.rec.add("restore")
	return nil
}

func (s *fakeSys) RestoreLoopGuard(ctx context.Context) error {
	s.rec.add("restore-loopguard")
	return nil
}

func (s *fakeSys) Ingress(ctx context.Context, on bool) error {
	s.rec.add(fmt.Sprintf("ingress:%v", on))
	return nil
}

func (s *fakeSys) SetLAN(l decosys.LAN) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lan == l {
		return false
	}
	s.lan = l
	s.rec.add("setlan:" + l.GatewayIP + "," + l.LANCIDR + "," + l.UnitIP)
	return true
}

func (s *fakeSys) Counts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.counts)
}

func (s *fakeSys) FlushFlows(ctx context.Context, f decosys.FlowScope) error {
	s.rec.add("flush:" + f.Dev + f.MAC)
	return nil
}

// fakeWifi stands in for bcmwifi. Apply "owns" Wi-Fi by creating the
// hostapd confs under the test root, a hand-back removes them.
type fakeWifi struct {
	rec      *recorder
	runDir   string // host path of the run dir
	mu       sync.Mutex
	applyErr error // returned by Apply
	handBack bool  // Apply / Rollback leave Wi-Fi with TP-Link
	verify   error
	rollback error
	desired  []bcmwifi.Desired
	failed   *bcmwifi.Desired // like bcmwifi: the last Desired whose Apply failed
	tick     bcmwifi.TickReport
	during   func(op string) // nil, or run inside Apply and Rollback ("apply", "rollback")
}

func (w *fakeWifi) Plan(ctx context.Context, d bcmwifi.Desired) (bcmwifi.Plan, error) {
	w.rec.add("plan")
	w.mu.Lock()
	w.desired = append(w.desired, d)
	w.mu.Unlock()
	return bcmwifi.Plan{Desired: d, Steps: []bcmwifi.Step{{Kind: bcmwifi.StepCmd, Desc: "x", Argv: []string{"wl", "-i", "wl1", "chanspec", "36/80"}}}}, nil
}

func (w *fakeWifi) own(on bool) {
	for _, p := range []string{"wl0", "wl1"} {
		f := filepath.Join(w.runDir, "hapd-"+p+".conf")
		if on {
			os.MkdirAll(w.runDir, 0o700)
			os.WriteFile(f, []byte("interface="+p+"\n"), 0o600)
		} else {
			os.Remove(f)
		}
	}
}

// Apply refuses a Desired that failed before with bcmwifi.ErrDesiredFailed
// and changes nothing, as bcmwifi does.
func (w *fakeWifi) Apply(ctx context.Context, p bcmwifi.Plan) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil && reflect.DeepEqual(*w.failed, p.Desired) {
		w.rec.add("apply-refused")
		return fmt.Errorf("%w (test)", bcmwifi.ErrDesiredFailed)
	}
	w.rec.add("apply")
	if w.during != nil {
		w.during("apply")
	}
	w.own(!w.handBack)
	if w.applyErr != nil {
		d := p.Desired
		w.failed = &d
	}
	return w.applyErr
}

func (w *fakeWifi) Verify(ctx context.Context, d bcmwifi.Desired) error {
	w.rec.add("verify")
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.verify
}

func (w *fakeWifi) Rollback(ctx context.Context) error {
	w.rec.add("rollback")
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.during != nil {
		w.during("rollback")
	}
	if w.handBack {
		w.own(false)
	}
	return w.rollback
}

func (w *fakeWifi) Kick(ctx context.Context, mac string) error {
	w.rec.add("kick:" + mac)
	return nil
}

func (w *fakeWifi) SetBlocked(ctx context.Context, macs []string) error {
	w.rec.add("blocked:" + strings.Join(macs, ","))
	return nil
}

func (w *fakeWifi) LED(ctx context.Context, mode string) error {
	w.rec.add("led:" + mode)
	return nil
}

func (w *fakeWifi) Tick(ctx context.Context) (bcmwifi.TickReport, error) {
	w.rec.add("tick")
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tick, nil
}

func (w *fakeWifi) AuthorizeGuest(ctx context.Context, mac string) error {
	w.rec.add("guest-auth:" + mac)
	return nil
}

func (w *fakeWifi) UnauthorizeGuest(ctx context.Context, mac string) error {
	w.rec.add("guest-unauth:" + mac)
	return nil
}

func (w *fakeWifi) SetUplink(port string) { w.rec.add("uplink:" + port) }

// ForgetFailed drops the failed-Desired memory, as bcmwifi's does.
func (w *fakeWifi) ForgetFailed() {
	w.rec.add("forget-failed")
	w.mu.Lock()
	w.failed = nil
	w.mu.Unlock()
}

// fakeRunner records commands (reboot) instead of running them. out
// answers a command line with canned output.
type fakeRunner struct {
	rec *recorder
	out map[string]string
}

func (r fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	r.rec.add("run:" + line)
	return []byte(r.out[line]), nil
}

// ctl is a UniFi controller's /inform endpoint for one device.
type ctl struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	key     string
	informs []map[string]any
	replies []string
	// stamp, when not zero, is the next server_time_in_utc (ms) a reply
	// carries, as a real controller's do; it grows by a second per reply
	stamp int64
	raw   [][]byte // frames sent as they are, ahead of replies
	onRaw func()   // called as each raw frame is sent
	sent  [][]byte // every frame sent
}

func newCtl(t *testing.T) *ctl {
	c := &ctl{t: t, key: inform.DefaultKeyHex}
	c.srv = httptest.NewServer(http.HandlerFunc(c.inform))
	t.Cleanup(c.srv.Close)
	return c
}

var authkeyRe = regexp.MustCompile(`authkey=([0-9a-f]{32})`)

func (c *ctl) inform(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	hdr, plain, err := inform.Decode(body, c.key)
	if err != nil {
		http.Error(w, "undecodable", http.StatusBadRequest)
		return
	}
	var m map[string]any
	if err := json.Unmarshal(plain, &m); err != nil {
		http.Error(w, "not json", http.StatusBadRequest)
		return
	}
	c.informs = append(c.informs, m)
	if len(c.raw) > 0 {
		var pkt []byte
		pkt, c.raw = c.raw[0], c.raw[1:]
		c.sent = append(c.sent, pkt)
		if c.onRaw != nil {
			c.onRaw()
		}
		w.Write(pkt)
		return
	}
	reply := `{"_type":"noop"}`
	if len(c.replies) > 0 {
		reply, c.replies = c.replies[0], c.replies[1:]
	}
	if c.stamp != 0 {
		reply = `{"server_time_in_utc":"` + strconv.FormatInt(c.stamp, 10) + `",` + strings.TrimPrefix(reply, "{")
		c.stamp += 1000
	}
	pkt, err := inform.Encode(hdr.MAC, c.key, inform.CBC, []byte(reply), nil)
	if err != nil {
		c.t.Errorf("controller encode: %v", err)
		return
	}
	if k := authkeyRe.FindStringSubmatch(reply); k != nil {
		c.key = k[1]
	}
	c.sent = append(c.sent, pkt)
	w.Write(pkt)
}

// sendRaw queues frames sent as they are.
func (c *ctl) sendRaw(frames ...[]byte) {
	c.mu.Lock()
	c.raw = append(c.raw, frames...)
	c.mu.Unlock()
}

// sentFrames is every frame sent so far.
func (c *ctl) sentFrames() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.sent)
}

func (c *ctl) queue(replies ...string) {
	c.mu.Lock()
	c.replies = append(c.replies, replies...)
	c.mu.Unlock()
}

func (c *ctl) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.replies)
}

func (c *ctl) last() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.informs) == 0 {
		return nil
	}
	return c.informs[len(c.informs)-1]
}

func (c *ctl) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.informs)
}

const (
	adoptReply     = `{"_type":"setparam","mgmt_cfg":"cfgversion=0000000000000001\nauthkey=` + testKey + `\nled_enabled=true\n"}`
	blockedReplyFm = `{"_type":"setparam","cfgversion":"00000000000000c1","mgmt_cfg":"cfgversion=00000000000000c1\n","system_cfg":%q,"blocked_sta":"aa:bb:cc:00:00:99"}`
)

func provisionReply(cfg string) string { return fmt.Sprintf(blockedReplyFm, cfg) }

// logBuf collects the agent's log lines.
type logBuf struct {
	mu    sync.Mutex
	lines []string
}

func (l *logBuf) logf(f string, a ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(f, a...))
	l.mu.Unlock()
}

func (l *logBuf) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

type harness struct {
	t      *testing.T
	root   string
	cfg    *Config
	ctl    *ctl
	rec    *recorder
	col    *fakeCol
	sys    *fakeSys
	wifi   *fakeWifi
	logs   *logBuf
	a      *agent
	built  int // decosys/bcmwifi handles built
	wopts  bcmwifi.Options
	sopts  decosys.Options
	cancel context.CancelFunc
	done   chan error
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func newHarness(t *testing.T, mod func(*Config, *options)) *harness {
	h := &harness{t: t, root: t.TempDir(), ctl: newCtl(t), rec: &recorder{}, logs: &logBuf{}}
	h.col = &fakeCol{rec: h.rec}
	h.sys = &fakeSys{rec: h.rec}
	h.wifi = &fakeWifi{rec: h.rec, runDir: filepath.Join(h.root, "tmp/udeco")}
	h.cfg = &Config{InformURL: h.ctl.srv.URL + "/inform", ConsoleIP: "127.0.0.1", Model: "UAL6", SSHDPort: freePort(t), Log: "stderr"}
	openGate(t, h.root, "5000.00 9000.00")
	o := options{root: h.root, base: "/tp_data/udeco", runDir: "/tmp/udeco", run: fakeRunner{rec: h.rec}, col: h.col,
		sshListen: "127.0.0.1", logf: h.logs.logf, noLLDP: true,
		newSys:  func(so decosys.Options) sysManager { h.built++; h.sopts = so; return h.sys },
		newWifi: func(bo bcmwifi.Options) wifiApplier { h.built++; h.wopts = bo; return h.wifi },
		t: timing{interval: 10 * time.Millisecond, minWait: time.Millisecond, immediateWait: time.Millisecond,
			retryWait: 5 * time.Millisecond, enforceEvery: time.Hour, fastEnforce: time.Hour, gateEvery: 5 * time.Millisecond}}
	if mod != nil {
		mod(h.cfg, &o)
	}
	if err := h.cfg.validate(); err != nil {
		t.Fatal(err)
	}
	a, err := newAgent(h.cfg, o)
	if err != nil {
		t.Fatal(err)
	}
	h.a = a
	return h
}

func (h *harness) start() {
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.done = cancel, make(chan error, 1)
	go func() { h.done <- h.a.run(ctx) }()
	h.t.Cleanup(h.stop)
}

func (h *harness) stop() {
	if h.cancel == nil {
		return
	}
	h.cancel()
	select {
	case err := <-h.done:
		if err != nil && !errors.Is(err, context.Canceled) {
			h.t.Errorf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		h.t.Error("agent did not stop")
	}
	h.cancel = nil
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func num(v any) float64 { f, _ := v.(float64); return f }

func radioRow(t *testing.T, m map[string]any, band string) map[string]any {
	t.Helper()
	rows, _ := m["radio_table"].([]any)
	for _, r := range rows {
		if rr := r.(map[string]any); rr["radio"] == band {
			return rr
		}
	}
	t.Fatalf("no %s radio in %v", band, m["radio_table"])
	return nil
}

// Observe mode: the unit is read and reported as a U6-Lite with the chosen
// capability words; adoption, provisioning and actions change nothing on
// the unit (no decosys/bcmwifi handle is even built), and the passphrase
// never reaches the log.
func TestObserveMode(t *testing.T) {
	h := newHarness(t, nil)
	h.ctl.queue(adoptReply, provisionReply(testCfg),
		`{"_type":"cmd","cmd":"set-locate"}`,
		`{"_type":"cmd","cmd":"kick-sta","mac":"`+staMAC+`"}`,
		`{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":80}`,
		`{"_type":"cmd","cmd":"reboot"}`,
		`{"_type":"noop"}`)
	h.start()
	eventually(t, "replies consumed", func() bool { return h.ctl.pending() == 0 && h.ctl.count() > 9 })
	h.stop()

	if h.built != 0 {
		t.Errorf("observe mode built %d decosys/bcmwifi handles", h.built)
	}
	for _, c := range h.rec.list() {
		t.Errorf("observe mode touched the unit: %s", c)
	}
	if !h.a.x.S.Adopted || h.a.x.S.Key != testKey {
		t.Fatalf("not adopted: %+v", h.a.x.S.Adopted)
	}
	m := h.ctl.last()
	if m["model"] != "UAL6" || m["model_display"] != "U6-Lite" || m["version"] != "6.7.54.15663" || m["mac"] != unitMAC {
		t.Errorf("identity: %v %v %v %v", m["model"], m["model_display"], m["version"], m["mac"])
	}
	// WPA3 only: observe mode runs no scans and owns no Wi-Fi, so no
	// RF_SCAN and no takeover feature bit (minimum rates, PPSK, Lock to
	// AP, Roaming Assistant, RADIUS filter, multicast inspect, RadSec, mDNS
	// bridge, Hotspot 2.0). Encrypted syslog (fw_caps 0x1000000), SNMPv3
	// (fw_caps 0x4000) and path monitoring (fw3_caps 0x40) only read the
	// unit or send ICMP echoes, so they are claimed in both modes.
	if num(m["wifi_caps"]) != 131072 || num(m["fw_caps"]) != 0x1405403 || num(m["fw3_caps"]) != 0x40 ||
		m["wifi_caps2"] != nil || m["fw2_caps"] != nil || m["hw_caps"] != nil {
		t.Errorf("caps: wifi %v fw %v fw3 %v wifi2 %v fw2 %v hw %v", m["wifi_caps"], m["fw_caps"], m["fw3_caps"], m["wifi_caps2"], m["fw2_caps"], m["hw_caps"])
	}
	ng, na := radioRow(t, m, "ng"), radioRow(t, m, "na")
	if num(ng["ieee_modes"]) != 90 || num(na["ieee_modes"]) != 85 || num(na["radio_caps"]) != 16 || num(ng["radio_caps"]) != 16 || na["has_dfs"] != false || num(na["nss"]) != 2 {
		t.Errorf("radio rows: ng %v na %v", ng, na)
	}
	// the session.go defect: real stats survive adoption
	if ss := m["sys_stats"].(map[string]any); num(ss["mem_total"]) != 264241152 {
		t.Errorf("sys_stats not the unit's: %v", ss)
	}
	rs := m["radio_table_stats"].([]any)
	if len(rs) != 2 || num(rs[1].(map[string]any)["num_sta"]) != 1 || num(rs[1].(map[string]any)["channel"]) != 36 {
		t.Errorf("radio_table_stats not the unit's: %v", rs)
	}
	if num(m["sshd_port"]) != float64(h.cfg.SSHDPort) || m["ip"] != "192.168.0.205" {
		t.Errorf("sshd_port %v ip %v", m["sshd_port"], m["ip"])
	}
	// the WLAN plan is logged (masked), actions only logged
	logs := h.logs.all()
	if strings.Contains(logs, fakePSK) {
		t.Error("passphrase in the log")
	}
	for _, want := range []string{"observe mode: the controller's Wi-Fi plan above is logged only", "observe mode: locate:on logged only",
		"observe mode: kick:" + staMAC + " logged only", "observe mode: quick-scan:na:80 logged only", "observe mode: reboot logged only"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %q", want)
		}
	}
	// the VAP gets the controller's devname from system_cfg
	vaps, _ := m["vap_table"].([]any)
	if len(vaps) != 1 || vaps[0].(map[string]any)["name"] != "wifi1ap1" || vaps[0].(map[string]any)["id"] != "w1" {
		t.Errorf("vap_table %v", vaps)
	}
}

// Takeover: Enforce runs before any bcmwifi Plan/Apply, egress is turned
// on with each Enforce, the collector is invalidated after Apply, the
// blocked list goes to bcmwifi around the provision, and the uplink found
// from the gateway's FDB entry reaches bcmwifi.
func TestTakeoverOrdering(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply, c.Egress = true, true, true
		o.t.enforceEvery = 20 * time.Millisecond
	})
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	eventually(t, "apply", func() bool { return h.rec.index("apply") >= 0 })
	eventually(t, "a second enforce tick with egress", func() bool { return h.rec.count("enforce") >= 3 })
	// the health check runs on the tick after the one that applied, which
	// may be the third (the provision can land on any tick)
	eventually(t, "a health check of the applied Wi-Fi", func() bool { return h.rec.index("verify") >= 0 })
	h.stop()

	calls := h.rec.list()
	enf, plan, apply := h.rec.index("enforce"), h.rec.index("plan"), h.rec.index("apply")
	if enf < 0 || plan < enf || apply < plan {
		t.Fatalf("order: %v", calls)
	}
	if !(h.rec.index("egress:true") > enf) || h.rec.count("egress:true") < h.rec.count("enforce")-1 {
		t.Errorf("egress not on with every enforce: %v", calls)
	}
	if i := slices.Index(calls[apply:], "invalidate"); i != 1 {
		t.Errorf("Invalidate not right after Apply: %v", calls[apply:])
	}
	bl := "blocked:aa:bb:cc:00:00:99"
	first := h.rec.index(bl)
	if first < 0 || first > plan || slices.Index(calls[apply:], bl) < 0 {
		t.Errorf("blocked list not set before the plan and after the apply: %v", calls)
	}
	if h.rec.index("verify") < 0 {
		t.Errorf("no health check of the applied Wi-Fi: %v", calls)
	}
	if h.wopts.Uplink != "eth1" || h.wopts.DryRun || h.wopts.RunDir != "/tmp/udeco" || h.wopts.StateDir != "/tp_data/udeco/state" {
		t.Errorf("bcmwifi options %+v", h.wopts)
	}
	if h.wopts.Caps == nil {
		t.Error("bcmwifi has no hardware caps for channel validation")
	} else if c, err := h.wopts.Caps(context.Background()); err != nil || c.Country != "IN" {
		t.Errorf("bcmwifi caps are not the collector's: %+v %v", c, err)
	}
	if h.sopts.ControllerIP != "127.0.0.1" || h.sopts.ConsoleIP != "127.0.0.1" {
		t.Errorf("decosys options %+v", h.sopts)
	}
	// built in phase 1 (fence first), the LAN handed over from the first
	// reading, before the first Enforce
	if f, l := h.rec.index("ingress:true"), h.rec.index("setlan:192.168.0.1,192.168.0.0/24,192.168.0.205"); f < 0 || l < f || l > enf {
		t.Errorf("fence %d, LAN %d, enforce %d: %v", f, l, enf, calls)
	}
	d := h.wifi.desired[0]
	if len(d.SSIDs) != 1 || d.SSIDs[0].SSID != "net" || d.SSIDs[0].Passphrase != fakePSK || !slices.Equal(d.SSIDs[0].Bands, []string{"na"}) {
		t.Errorf("desired %v", d.SSIDs)
	}
	if strings.Contains(h.logs.all(), fakePSK) {
		t.Error("passphrase in the log")
	}
	if h.rec.index("restore") >= 0 || h.rec.index("rollback") >= 0 {
		t.Errorf("SIGTERM handed Wi-Fi back: %v", calls)
	}
}

// No chanspec is pinned while decosys.Enforce fails; the provision waits
// and runs on the first successful Enforce.
func TestApplyWaitsForEnforce(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		o.t.enforceEvery = 20 * time.Millisecond
	})
	h.sys.enforceErr = errors.New("stop awn: exit 1")
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	// The provision is taken off the controller before the worker gets to
	// it: wait for the worker's own log of it waiting, or an enforce that
	// succeeds first would apply it at once (a race seen in CI).
	eventually(t, "a few failed enforces, the provision waiting", func() bool {
		return h.rec.count("enforce") >= 3 && h.ctl.pending() == 0 && strings.Contains(h.logs.all(), "waits for decosys.Enforce")
	})
	if h.rec.index("plan") >= 0 || h.rec.index("apply") >= 0 {
		t.Fatalf("Wi-Fi planned before Enforce succeeded: %v", h.rec.list())
	}
	h.sys.mu.Lock()
	h.sys.enforceErr = nil
	h.sys.mu.Unlock()
	eventually(t, "apply after enforce", func() bool { return h.rec.index("apply") >= 0 })
	h.stop()
	if !strings.Contains(h.logs.all(), "waits for decosys.Enforce") {
		t.Error("no log of the waiting provision")
	}
}

// An Apply error that left Wi-Fi with TP-Link restores TP-Link's services
// and drops to observe mode until the persistent marker is removed.
func TestApplyHandBackDropsToObserve(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	h.wifi.applyErr = errors.New("bcmwifi: apply: verify: wl12 bss is \"down\" (rolled back)")
	h.wifi.handBack = true
	h.ctl.queue(adoptReply, provisionReply(testCfg), `{"_type":"cmd","cmd":"set-locate"}`, `{"_type":"noop"}`)
	h.start()
	eventually(t, "restore", func() bool { return h.rec.index("restore") >= 0 })
	eventually(t, "observe", func() bool { return !h.a.takeover.Load() })
	eventually(t, "replies consumed", func() bool { return h.ctl.pending() == 0 })
	h.stop()
	calls := h.rec.list()
	if h.rec.index("restore") < h.rec.index("apply") || h.rec.index("led:"+bcmwifi.LEDLocate) >= 0 {
		t.Errorf("calls %v", calls)
	}
	b, err := os.ReadFile(filepath.Join(h.root, "tp_data/udeco", observeMarker))
	if err != nil || !strings.Contains(string(b), "apply") {
		t.Errorf("observe marker: %q %v", b, err)
	}
	if !strings.Contains(h.logs.all(), "dropping to OBSERVE mode") {
		t.Error("no loud log")
	}
}

// An Apply error after which the agent still owns Wi-Fi (rolled back to
// last-good) keeps takeover mode. The same Wi-Fi asked for again (here by a
// system_cfg that differs only outside Wi-Fi) is refused by bcmwifi with
// ErrDesiredFailed: no hand-back, no Restore, no retry loop, and the health
// check of the live Wi-Fi is left as it was.
func TestApplyErrorStillOwned(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	h.wifi.applyErr = errors.New("bcmwifi: apply: x (rolled back)")
	h.wifi.own(true)
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	eventually(t, "apply", func() bool { return h.rec.index("apply") >= 0 })
	sameWifi := testCfg + "system.timezone=IST-5:30\n"
	h.ctl.queue(provisionReply(sameWifi), `{"_type":"noop"}`)
	eventually(t, "refused", func() bool { return h.rec.index("apply-refused") >= 0 })
	eventually(t, "replies consumed", func() bool { return h.ctl.pending() == 0 })
	h.stop()
	if h.rec.index("restore") >= 0 || !h.a.takeover.Load() || h.rec.count("apply") != 1 || h.rec.count("apply-refused") != 1 {
		t.Errorf("calls %v takeover %v", h.rec.list(), h.a.takeover.Load())
	}
	if i := h.rec.index("apply-refused"); i+1 < len(h.rec.list()) && h.rec.list()[i+1] == "invalidate" {
		t.Errorf("a refused apply (nothing changed) invalidated the collector: %v", h.rec.list())
	}
	if !strings.Contains(h.logs.all(), "not retried until the controller sends a different one") {
		t.Error("no log of the refused repeat")
	}
}

// Two failed health checks roll back; a Rollback with no TP-Link baseline
// restores TP-Link's services and drops to observe mode.
func TestRollbackNoBaseline(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		o.t.enforceEvery = 10 * time.Millisecond
	})
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	eventually(t, "apply", func() bool { return h.rec.index("apply") >= 0 })
	h.wifi.mu.Lock()
	h.wifi.verify = &bcmwifi.VerifyError{Problems: []string{"hostapd for wl1 not running"}}
	h.wifi.rollback = bcmwifi.ErrNoBaseline
	h.wifi.mu.Unlock()
	eventually(t, "restore", func() bool { return h.rec.index("restore") >= 0 })
	h.stop()
	calls := h.rec.list()
	rb := h.rec.index("rollback")
	if rb < 0 || calls[rb+1] != "invalidate" || h.rec.index("restore") < rb || h.a.takeover.Load() {
		t.Errorf("calls %v takeover %v", calls, h.a.takeover.Load())
	}
}

// Takeover actions go to bcmwifi (locate via LED, kick, block) and to the
// scanner (`cmd scan`: both bands); the scan is reported in the next
// inform: scan_table with is_unifi/serialno, rssi = signal - noise (noise
// unknown here: -95), an age and the U6 Pro's keys. The neighbour scan
// never reports a spectrum_table (the legacy ScanResult.Spectrum the fake
// returns is dropped): spectrum rows come only from the spectrum runner.
func TestTakeoverActionsAndScan(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	h.ctl.queue(adoptReply,
		`{"_type":"cmd","cmd":"set-locate"}`,
		`{"_type":"cmd","cmd":"unset-locate"}`,
		`{"_type":"cmd","cmd":"kick-sta","mac":"`+strings.ToUpper(staMAC)+`"}`,
		`{"_type":"cmd","cmd":"block-sta","mac":"aa:bb:cc:00:00:42"}`,
		`{"_type":"cmd","cmd":"scan"}`)
	h.start()
	eventually(t, "scan reported", func() bool {
		m := h.ctl.last()
		if m == nil || m["radio_table"] == nil {
			return false
		}
		rr := radioRow(t, m, "na")
		return rr["scan_table"] != nil && m["spectrum_scanning"] == false
	})
	eventually(t, "actions", func() bool { return h.rec.index("blocked:aa:bb:cc:00:00:42") >= 0 })
	h.stop()
	for _, want := range []string{"led:" + bcmwifi.LEDLocate, "led:" + bcmwifi.LEDLocateOff, "kick:" + staMAC, "scan:na", "scan:ng"} {
		if h.rec.index(want) < 0 {
			t.Errorf("no %s in %v", want, h.rec.list())
		}
	}
	rr := radioRow(t, h.ctl.last(), "na")
	rows := rr["scan_table"].([]any)
	if len(rows) != 2 {
		t.Fatalf("scan_table %v", rows)
	}
	for _, r := range rows {
		row := r.(map[string]any)
		switch row["bssid"] {
		case "11:22:33:44:55:66":
			if num(row["rssi"]) != 25 || row["is_unifi"] != false || num(row["age"]) < 3 || row["is_ubnt"] != false ||
				num(row["noise"]) != -95 || num(row["rssi_age"]) != 10*num(row["age"]) || row["ap_name"] != "" {
				t.Errorf("neighbour row %v", row)
			}
		case "62:22:32:00:00:09":
			if row["is_unifi"] != true || row["is_ubnt"] != true || row["serialno"] != gwMAC || num(row["rssi"]) != 45 {
				t.Errorf("unifi row %v", row)
			}
		}
	}
	if rr["spectrum_table"] != nil || rr["spectrum_table_time"] != nil || rr["spectrum_scanning_abnormal"] != false {
		t.Errorf("spectrum %v time %v abnormal %v", rr["spectrum_table"], rr["spectrum_table_time"], rr["spectrum_scanning_abnormal"])
	}
	if _, ok := h.ctl.last()["quickscan_scanning"]; ok {
		t.Error("quickscan_scanning sent at rest")
	}
}

// A controller restart reboots the unit in takeover mode (after the state
// is saved); in observe mode it is faked.
func TestRebootTakeover(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover = true })
	h.ctl.queue(adoptReply, `{"_type":"cmd","cmd":"reboot"}`)
	h.start()
	eventually(t, "reboot", func() bool { return h.rec.index("run:reboot") >= 0 })
	h.stop()
	if h.wopts.DryRun != true {
		t.Error("apply=false must make bcmwifi a dry run")
	}
}

// The agent informs nothing until the unit can be read.
func TestNoInformBeforeFirstReading(t *testing.T) {
	h := newHarness(t, nil)
	h.col.fail = errors.New("wl: no Broadcom radios")
	h.start()
	time.Sleep(50 * time.Millisecond)
	if n := h.ctl.count(); n != 0 {
		t.Fatalf("%d informs without a reading", n)
	}
	h.col.mu.Lock()
	h.col.fail = nil
	h.col.mu.Unlock()
	eventually(t, "inform", func() bool { return h.ctl.count() > 0 })
	h.stop()
}

// A forced observe (crash loop, earlier hand-back) never builds the
// takeover handles even with takeover configured.
func TestForcedObserve(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply, c.Egress = true, true, true
		o.forceObserve = "crash loop"
	})
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	eventually(t, "replies consumed", func() bool { return h.ctl.pending() == 0 && h.ctl.count() > 3 })
	h.stop()
	if h.built != 0 || len(h.rec.list()) != 0 {
		t.Errorf("built %d, calls %v", h.built, h.rec.list())
	}
	if !strings.Contains(h.logs.all(), "OBSERVE MODE FORCED (crash loop)") {
		t.Error("no loud log")
	}
}

// SSH adoption on sshd_port is refused from anywhere but console_ip.
func TestSSHAdoptOnlyFromConsole(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.ConsoleIP = "192.0.2.10" })
	h.start()
	eventually(t, "inform", func() bool { return h.ctl.count() > 0 })
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", h.cfg.SSHDPort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 64)
	n, _ := c.Read(b)
	c.Close()
	h.stop()
	if n != 0 {
		t.Errorf("a non-console peer got an SSH banner: %q", b[:n])
	}
}

// openGate writes what the boot gate waits for (R1) under root, with
// /proc/uptime = uptime.
func openGate(t *testing.T, root, uptime string) {
	t.Helper()
	for _, f := range append([]string{"/proc/uptime"}, gateFiles...) {
		p := filepath.Join(root, f)
		os.MkdirAll(filepath.Dir(p), 0o755)
		v := ""
		if f == "/proc/uptime" {
			v = uptime + "\n"
		}
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
