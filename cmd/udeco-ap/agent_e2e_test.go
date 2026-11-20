// SPDX-License-Identifier: GPL-2.0-or-later

package main

// End-to-end: the agent as built (real internal/wl collector, real
// internal/device session and SSH-adopt responder, real internal/decosys and
// internal/bcmwifi) against an in-process UniFi controller that speaks the
// internal/inform codec, with every device command served from the .205
// captures (internal/wl/testdata, internal/decosys/testdata) by a fake
// Runner and every device file in a temp root. Nothing here touches a device
// or a real controller, and the takeover run forces decosys and bcmwifi into
// DryRun, so even a bug cannot reach beyond the temp root.
//
// The flow is a real adoption: pending informs on the factory key (HTTP
// 404) -> SSH set-adopt from the console -> informs on the per-device key ->
// mgmt_cfg turns on AES-GCM -> GCM informs -> the controller provisions the
// system_cfg a real U6 Pro got (docs/reference/u6pro, redacted there; the
// test synthesises fake secrets in place of the redactions).

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
	"github.com/antoniocosta/unifi-openwrt/internal/inform"
	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

const (
	wlFixtures  = "../../internal/wl/testdata"
	sysFixtures = "../../internal/decosys/testdata"
	u6proCfg    = "../../docs/reference/u6pro/config-apply/tmp_system.cfg.redacted"
	e2eAuthkey  = "00112233445566778899aabbccddeeff" // made up
	e2eUnitIP   = "192.168.0.205"
	e2eCfgVer   = "00000000000000c1" // the cfgversion the controller provisions
)

// ---------------------------------------------------------------- device

// e2eUnit is the .205 Deco as captured: a filesystem root plus a Runner.
type e2eUnit struct {
	t    *testing.T
	root string

	mu    sync.Mutex
	calls [][]string
	// getters the captures lack, with the values the research read on .205
	// (the same table bcmwifi's own fake uses)
	extra map[string]string
	// spec, when set, answers the spectrum runner's scan calls
	// (spectrum_e2e_test.go)
	spec *specFake
}

func readFixture(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newE2EUnit(t *testing.T) *e2eUnit {
	u := &e2eUnit{t: t, root: t.TempDir(), extra: map[string]string{}}
	put := func(p, s string) { u.write(p, s) }
	wlf := func(name string) string { return string(readFixture(t, wlFixtures, name)) }

	// /proc and /tmp as the collector reads them (no getfirm-product-info:
	// that capture holds device keys)
	for p, f := range map[string]string{
		"/proc/uptime": "proc_uptime.txt", "/proc/loadavg": "proc_loadavg.txt", "/proc/stat": "proc_stat.txt",
		"/proc/meminfo": "proc_meminfo.txt", "/proc/net/route": "proc_net_route.txt", "/proc/net/arp": "proc_net_arp.txt",
		"/proc/sys/kernel/hostname": "proc_sys_kernel_hostname.txt", "/tmp/getfirm-soft-version": "tmp_getfirm-soft-version.txt",
	} {
		put(p, wlf(f))
	}
	// every netdev the unit had, up (IFF_UP in flags, which bcmwifi reads)
	for _, n := range strings.Fields(wlf("ls_sys_class_net.txt")) {
		put("/sys/class/net/"+n+"/flags", "0x1003\n")
	}
	put("/sys/class/net/br-lan/address", wlf("sys_class_net_br-lan_address.txt"))
	put("/sys/class/net/br-lan/brforward", wlf("sys_class_net_br-lan_brforward.bin"))
	for line := range strings.Lines(wlf("sys_class_net_br-lan_brif_port_no.txt")) {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		put("/sys/class/net/br-lan/brif/"+f[0], "")
		put("/sys/class/net/"+f[0]+"/brport/port_no", f[1]+"\n")
		if err := os.Symlink("../../../devices/virtual/net/br-lan", u.path("/sys/class/net/"+f[0]+"/brport/bridge")); err != nil {
			t.Fatal(err)
		}
	}
	sysDump := func(dev, name string) {
		sc := bufio.NewScanner(strings.NewReader(wlf(name)))
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			switch {
			case !ok || k == "brport":
			case slices.Contains([]string{"address", "operstate", "carrier", "speed", "duplex", "ifindex", "mtu", "carrier_changes"}, k):
				put("/sys/class/net/"+dev+"/"+k, v+"\n")
			default:
				put("/sys/class/net/"+dev+"/statistics/"+k, v+"\n")
			}
		}
	}
	sysDump("eth0", "sys_class_net_eth0.txt")
	sysDump("eth1", "sys_class_net_eth1.txt")
	for _, v := range []string{"wl01", "wl02", "wl11", "wl12", "wl13"} {
		sysDump(v, "sys_class_net_"+v+"_statistics.txt")
	}
	for _, v := range []string{"wl01", "wl02", "wl03", "wl04", "wl05", "wl06", "wl11", "wl12", "wl13", "wl14", "wl15", "wl16"} {
		put("/sys/class/net/"+v+"/address", strings.ToLower(wlf("wl_-i_"+v+"_bssid.txt")))
	}

	// processes, init scripts, crontab and binaries as decosys sees them
	for line := range strings.Lines(string(readFixture(t, sysFixtures, "procs-205.txt"))) {
		f := strings.SplitN(strings.TrimRight(line, "\n"), "|", 5)
		if len(f) != 5 {
			continue
		}
		if _, err := strconv.Atoi(f[0]); err != nil {
			t.Fatalf("procs fixture line %q", line)
		}
		argv := strings.Fields(f[4])
		cl := ""
		if len(argv) > 0 {
			cl = strings.Join(argv, "\x00") + "\x00"
		}
		put("/proc/"+f[0]+"/cmdline", cl)
	}
	for _, n := range strings.Fields(string(readFixture(t, sysFixtures, "initd-205.txt"))) {
		put("/etc/init.d/"+n, "#!/bin/sh /etc/rc.common\n")
	}
	put("/etc/crontabs/root", string(readFixture(t, sysFixtures, "crontab-205")))
	for _, b := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables", "/usr/sbin/ntpd", "/sbin/start-stop-daemon", "/bin/kill", "/bin/ubus"} {
		put(b, "")
	}
	// TP-Link's hostapd per radio (pids from procs-205.txt), as on a
	// satellite; the confs carry no real passphrase
	for i, p := range []string{"wl0", "wl1"} {
		put("/tmp/"+p+".1_hapd.pid", strconv.Itoa(10510+402*i)+"\n")
		put("/tmp/"+p+".1_hapd.conf", "interface="+p+"1\nssid=tplink\nwpa_passphrase=***\n")
	}
	for _, v := range []string{"wl02", "wl12", "wl13"} {
		u.extra[v+" rrm"] = "0x33  Link_Measurement Neighbor_Report Beacon_Passive Beacon_Active"
		u.extra[v+" wmf_bss_enable"] = "1"
		u.extra[v+" bss_maxassoc"] = "128 (0x80)"
		u.extra[v+" macmode"] = "1"
	}
	for _, v := range []string{"wl01", "wl11"} {
		u.extra[v+" rrm"] = "0x0"
		u.extra[v+" bss_maxassoc"] = "16 (0x10)"
	}
	u.extra["wl0 txpwr_degrade"] = "0"
	u.extra["wl1 txpwr_degrade"] = "0"
	return u
}

func (u *e2eUnit) path(p string) string { return filepath.Join(u.root, filepath.FromSlash(p)) }

func (u *e2eUnit) write(p, s string) {
	u.t.Helper()
	if err := os.MkdirAll(filepath.Dir(u.path(p)), 0o755); err != nil {
		u.t.Fatal(err)
	}
	if err := os.WriteFile(u.path(p), []byte(s), 0o644); err != nil {
		u.t.Fatal(err)
	}
}

// Run serves every command from the captures. It runs nothing.
func (u *e2eUnit) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if u.spec != nil && filepath.Base(name) == "wl" {
		if out, err, ok := u.spec.serve(args); ok {
			u.mu.Lock()
			u.calls = append(u.calls, append([]string{name}, args...))
			u.mu.Unlock()
			return out, err
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.calls = append(u.calls, append([]string{name}, args...))
	switch filepath.Base(name) {
	case "wl":
		if out, ok := u.wlGetter(args); ok {
			return out.b, out.err
		}
		return []byte("wl: Unsupported\n"), errors.New("exit status 1")
	case "ubus":
		if strings.Join(args, " ") == "call service list" {
			return readFixture(u.t, sysFixtures, "ubus-service-list-205.json"), nil
		}
	case "iptables", "ip6tables":
		if slices.Contains(args, "-S") || slices.Contains(args, "-C") {
			return nil, errors.New("iptables: No chain/target/match by that name")
		}
	}
	return nil, nil
}

type wlOut struct {
	b   []byte
	err error
}

// wlGetter answers a read-only `wl -i <if> <getter...>` from the captures
// (or the research table in extra); ok is false for anything else.
func (u *e2eUnit) wlGetter(args []string) (wlOut, bool) {
	if len(args) < 3 || args[0] != "-i" {
		return wlOut{}, false
	}
	iface, rest := args[1], args[2:]
	if v, ok := u.extra[iface+" "+strings.Join(rest, " ")]; ok {
		return wlOut{b: []byte(v + "\n")}, true
	}
	if len(rest) == 1 && rest[0] == "fbt" {
		return wlOut{b: []byte("0\n")}, true
	}
	if len(rest) == 2 && rest[0] == "twt" && rest[1] == "enab" && len(iface) == 3 {
		// not captured; read under TP-Link on the Bedroom Deco (2026-11-20)
		return wlOut{b: []byte("0\n")}, true
	}
	if len(rest) == 1 && rest[0] == "closednet" {
		rest = []string{"closed"}
	}
	file := filepath.Join(wlFixtures, "wl_-i_"+iface+"_"+strings.Join(rest, "_")+".txt")
	b, err := os.ReadFile(file)
	if err != nil {
		return wlOut{}, false
	}
	if se, err := os.ReadFile(file + ".stderr"); err == nil && len(b) == 0 {
		return wlOut{err: errors.New(strings.TrimSpace(string(se)))}, true
	}
	return wlOut{b: b}, true
}

// mutating lists the calls that would change the unit: anything but a
// `wl` getter the captures (or the research table) answer, `ubus call
// service list`, and iptables -S/-C.
func (u *e2eUnit) mutating() []string {
	u.mu.Lock()
	calls := slices.Clone(u.calls)
	u.mu.Unlock()
	var out []string
	for _, c := range calls {
		switch filepath.Base(c[0]) {
		case "wl":
			if _, ok := u.wlGetter(c[1:]); ok {
				continue
			}
			// getters the captures lack: `wl -i <vif> macmode|mac|dwds` with
			// no value read the driver's ACL and WDS state; the radio-wide
			// driver settings bcmwifi holds at a U6 Pro's value (parity.go)
			if len(c) == 4 && c[1] == "-i" && slices.Contains([]string{"macmode", "mac", "dwds",
				"bssload", "txbf_imp", "vht_features", "rxchain_pwrsave_enable", "radio_pwrsave_enable",
				"interference", "interference_override", "dhcp_unicast", "wnm", "spect", "dfs_status", "chan_info"}, c[3]) {
				continue
			}
		case "ebtables":
			if len(c) == 3 && c[1] == "-L" {
				continue
			}
		case "ip":
			if strings.Join(c[1:], " ") == "-4 -o addr show dev br-lan" {
				continue
			}
		case "ubus":
			if strings.Join(c[1:], " ") == "call service list" {
				continue
			}
		case "iptables", "ip6tables":
			if slices.Contains(c, "-S") || slices.Contains(c, "-C") {
				continue
			}
		}
		out = append(out, strings.Join(c, " "))
	}
	return out
}

// e2eCollector is the real collector. The one value the captures cannot
// give is br-lan's address: the collector reads it from the host's netlink
// (net.InterfaceByName), and the test host has no br-lan. It is filled in
// with .205's address (ip_-4_addr_show_br-lan.txt).
type e2eCollector struct{ *wl.Collector }

func (c e2eCollector) Collect(ctx context.Context) (*apstate.Snapshot, error) {
	s, err := c.Collector.Collect(ctx)
	if err == nil && s.IP == "" {
		s.IP, s.Netmask = e2eUnitIP, "255.255.255.0"
	}
	return s, err
}

// ------------------------------------------------------------ controller

type e2eInform struct {
	key     string // "factory" or "device"
	gcm     bool
	payload map[string]any
	raw     string
}

// e2eCtl is a UniFi controller's /inform for one device: 404 while the
// device is pending (factory key), then on the device key a setparam that
// turns on AES-GCM, then the provisioning, then noops.
type e2eCtl struct {
	t         *testing.T
	srv       *httptest.Server
	systemCfg string

	mu      sync.Mutex
	informs []e2eInform
	stage   int
	hook    func(e2eInform) // called for each inform (under mu)
	// reply, after the provisioning, may answer an inform with a command
	// instead of the noop ("" = noop; under mu)
	reply func(e2eInform) string
}

func newE2ECtl(t *testing.T, systemCfg string) *e2eCtl {
	c := &e2eCtl{t: t, systemCfg: systemCfg}
	c.srv = httptest.NewServer(http.HandlerFunc(c.inform))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *e2eCtl) url() string { return c.srv.URL + "/inform" }

func (c *e2eCtl) inform(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	key, which := e2eAuthkey, "device"
	hdr, plain, err := inform.Decode(body, key)
	if err != nil {
		key, which = inform.DefaultKeyHex, "factory"
		if hdr, plain, err = inform.Decode(body, key); err != nil {
			http.Error(w, "undecodable", http.StatusBadRequest)
			return
		}
	}
	var m map[string]any
	if err := json.Unmarshal(plain, &m); err != nil {
		http.Error(w, "not json", http.StatusBadRequest)
		return
	}
	in := e2eInform{key: which, gcm: hdr.Flags&inform.FlagGCM != 0, payload: m, raw: string(plain)}
	c.informs = append(c.informs, in)
	if c.hook != nil {
		c.hook(in)
	}
	if which == "factory" {
		http.NotFound(w, req) // pending adoption
		return
	}
	var reply string
	switch c.stage {
	case 0:
		reply = `{"_type":"setparam","mgmt_cfg":"cfgversion=0000000000000001\nauthkey=` + e2eAuthkey + `\nuse_aes_gcm=true\nled_enabled=true\n"}`
	case 1:
		b, _ := json.Marshal(map[string]string{"_type": "setparam", "cfgversion": e2eCfgVer,
			"mgmt_cfg": "cfgversion=" + e2eCfgVer + "\nauthkey=" + e2eAuthkey + "\nuse_aes_gcm=true\nled_enabled=true\n", "system_cfg": c.systemCfg})
		reply = string(b)
	default:
		reply = `{"_type":"noop","interval":1}`
		if c.reply != nil {
			if r := c.reply(in); r != "" {
				reply = r
			}
		}
	}
	c.stage++
	cph := inform.CBC
	if in.gcm {
		cph = inform.GCM
	}
	pkt, err := inform.Encode(hdr.MAC, key, cph, []byte(reply), nil)
	if err != nil {
		c.t.Errorf("controller encode: %v", err)
		return
	}
	w.Write(pkt)
}

// live reports whether the inform shows the provisioned cfgversion. The
// agent reports it only once the system_cfg is live, after the Wi-Fi apply
// finished (cfgack.go), and Network sends a device commands only once it is
// out of provisioning. A script that sends a scan before that races the
// apply, which aborts the band (scanBlock: "a Wi-Fi apply or rollback is
// running").
func (in e2eInform) live() bool {
	return in.key == "device" && in.payload["cfgversion"] == e2eCfgVer
}

func (c *e2eCtl) snapshot() []e2eInform {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.informs)
}

func (c *e2eCtl) countWhere(f func(e2eInform) bool) int {
	n := 0
	for _, i := range c.snapshot() {
		if f(i) {
			n++
		}
	}
	return n
}

// sshSetAdopt is the console adopting a pending device over SSH (Network
// 10.6: ubnt@device, syswrapper.sh set-adopt <url> <key>).
func sshSetAdopt(t *testing.T, port int, informURL string) {
	t.Helper()
	cl, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &ssh.ClientConfig{
		User: "ubnt", Auth: []ssh.AuthMethod{ssh.Password("ubnt")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh: %v", err)
	}
	defer cl.Close()
	s, err := cl.NewSession()
	if err != nil {
		t.Fatalf("ssh session: %v", err)
	}
	defer s.Close()
	if err := s.Run("/usr/bin/syswrapper.sh set-adopt " + informURL + " " + e2eAuthkey); err != nil {
		var miss *ssh.ExitMissingError
		if !errors.As(err, &miss) {
			t.Fatalf("set-adopt: %v", err)
		}
	}
}

// ----------------------------------------------------------- system_cfg

var redactedRe = regexp.MustCompile(`(?m)^([^=\n]+)=\*\*\*REDACTED\*\*\*$`)

// u6proSystemCfg is the U6 Pro's real system_cfg with each redaction
// replaced by a made-up value. secrets lists those values (group_rekey is
// a number, not a secret).
func u6proSystemCfg(t *testing.T) (cfg string, secrets []string) {
	t.Helper()
	b := readFixture(t, ".", u6proCfg)
	seen := map[string]bool{}
	cfg = redactedRe.ReplaceAllStringFunc(string(b), func(line string) string {
		k := redactedRe.FindStringSubmatch(line)[1]
		var v string
		switch {
		case strings.HasSuffix(k, ".group_rekey"):
			return k + "=3600"
		case strings.HasSuffix(k, ".password"):
			v = "$6$e2esalt$E2eFakeHash" + strings.ReplaceAll(k, ".", "")
		case strings.HasSuffix(k, ".wpa.psk"):
			v = "E2e-Fake-Psk-" + strings.ReplaceAll(k, ".", "")
		default:
			v = "e2e-fake-secret-" + strings.ReplaceAll(k, ".", "-")
		}
		if !seen[v] {
			seen[v] = true
			secrets = append(secrets, v)
		}
		return k + "=" + v
	})
	if strings.Contains(cfg, "REDACTED") || len(secrets) < 5 {
		t.Fatalf("redactions not all replaced (%d secrets)", len(secrets))
	}
	return cfg, secrets
}

// ---------------------------------------------------------------- harness

type e2e struct {
	t    *testing.T
	unit *e2eUnit
	ctl  *e2eCtl
	cfg  *Config
	logs *logBuf
	a    *agent
	opts options // what the agent was built with (rebuild)

	mu      sync.Mutex
	sysOpts []decosys.Options
	sysLAN  []decosys.LAN
	wifi    *planRecorder
	cancel  context.CancelFunc
	done    chan error

	failApply bool // bcmwifi's Apply fails (set before start)
	ctlStep   int  // the controller script's step (spectrum_e2e_test.go; under ctl.mu)
}

// sysRecorder is the real decosys Manager; it keeps what the agent told it
// about the LAN.
type sysRecorder struct {
	*decosys.Manager
	e *e2e
}

func (s sysRecorder) SetLAN(l decosys.LAN) bool {
	s.e.mu.Lock()
	s.e.sysLAN = append(s.e.sysLAN, l)
	s.e.mu.Unlock()
	return s.Manager.SetLAN(l)
}

// planRecorder is the real bcmwifi Applier; it keeps every Plan it made.
// With failApply its Apply fails without running the plan.
type planRecorder struct {
	*bcmwifi.Applier
	mu        sync.Mutex
	plans     []bcmwifi.Plan
	opts      bcmwifi.Options
	failApply atomic.Bool
}

func (p *planRecorder) Apply(ctx context.Context, pl bcmwifi.Plan) error {
	if p.failApply.Load() {
		return errors.New("e2e: hostapd did not come up")
	}
	return p.Applier.Apply(ctx, pl)
}

func (p *planRecorder) Plan(ctx context.Context, d bcmwifi.Desired) (bcmwifi.Plan, error) {
	pl, err := p.Applier.Plan(ctx, d)
	if err == nil {
		p.mu.Lock()
		p.plans = append(p.plans, pl)
		p.mu.Unlock()
	}
	return pl, err
}

func (p *planRecorder) lastPlan() (bcmwifi.Plan, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.plans) == 0 {
		return bcmwifi.Plan{}, false
	}
	return p.plans[len(p.plans)-1], true
}

// newE2E builds the agent on the captured unit; mods change the config
// and options before the agent is built (o.root is the unit's root).
func newE2E(t *testing.T, systemCfg string, takeover bool, mods ...func(*Config, *options)) *e2e {
	e := &e2e{t: t, unit: newE2EUnit(t), ctl: newE2ECtl(t, systemCfg), logs: &logBuf{}}
	e.cfg = &Config{InformURL: e.ctl.url(), ConsoleIP: "127.0.0.1", Model: "UAL6", SSHDPort: freePort(t), Log: "stderr",
		Takeover: takeover, Apply: takeover, Egress: takeover}
	col := e2eCollector{wl.New(wl.Options{Root: e.unit.root, Run: e.unit})}
	for _, f := range gateFiles { // TP-Link's boot has finished (R1); uptime from the capture
		e.unit.write(f, "")
	}
	o := options{root: e.unit.root, base: "/tp_data/udeco", runDir: "/tmp/udeco", run: e.unit, col: col,
		sshListen: "127.0.0.1", logf: e.logs.logf, noLLDP: true,
		// the real packages, forced into DryRun whatever the config says
		newSys: func(so decosys.Options) sysManager {
			so.DryRun = true
			e.mu.Lock()
			e.sysOpts = append(e.sysOpts, so)
			e.mu.Unlock()
			return sysRecorder{decosys.New(so), e}
		},
		newWifi: func(bo bcmwifi.Options) wifiApplier {
			bo.DryRun = true
			e.mu.Lock()
			defer e.mu.Unlock()
			e.wifi = &planRecorder{Applier: bcmwifi.New(bo), opts: bo}
			e.wifi.failApply.Store(e.failApply)
			return e.wifi
		},
		t: timing{interval: 20 * time.Millisecond, minWait: 5 * time.Millisecond, immediateWait: time.Millisecond,
			retryWait: 5 * time.Millisecond, enforceEvery: time.Hour, fastEnforce: time.Hour, gateEvery: 5 * time.Millisecond}}
	for _, m := range mods {
		m(e.cfg, &o)
	}
	if err := e.cfg.validate(); err != nil {
		t.Fatal(err)
	}
	a, err := newAgent(e.cfg, o)
	if err != nil {
		t.Fatal(err)
	}
	e.a, e.opts = a, o
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("agent log:\n%s", e.logs.all())
		}
	})
	return e
}

// rebuild replaces the (stopped) agent with a new one on the same unit,
// controller and config: an agent restart, so a new process with a new wl
// collector (nothing of the old one's memory, spectrum runners included).
func (e *e2e) rebuild() {
	e.opts.col = e2eCollector{wl.New(wl.Options{Root: e.unit.root, Run: e.unit})}
	a, err := newAgent(e.cfg, e.opts)
	if err != nil {
		e.t.Fatal(err)
	}
	e.a = a
}

func (e *e2e) start() {
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel, e.done = cancel, make(chan error, 1)
	go func() { e.done <- e.a.run(ctx) }()
	e.t.Cleanup(e.stop)
}

func (e *e2e) stop() {
	if e.cancel == nil {
		return
	}
	e.cancel()
	select {
	case err := <-e.done:
		if err != nil && !errors.Is(err, context.Canceled) {
			e.t.Errorf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		e.t.Error("agent did not stop")
	}
	e.cancel = nil
}

// adopt runs the adoption up to provisioned GCM informs.
func (e *e2e) adopt() {
	t := e.t
	e.start()
	eventually(t, "a pending inform on the factory key", func() bool {
		return e.ctl.countWhere(func(i e2eInform) bool { return i.key == "factory" }) >= 2
	})
	sshSetAdopt(t, e.cfg.SSHDPort, e.ctl.url())
	eventually(t, "GCM informs after the provisioning", func() bool {
		e.ctl.mu.Lock()
		stage := e.ctl.stage
		e.ctl.mu.Unlock()
		return stage >= 4
	})
}

// checkFlow: factory-key CBC informs, then device-key CBC, then GCM only;
// the unit's identity and real radio values in the adopted payload.
func (e *e2e) checkFlow() map[string]any {
	t := e.t
	in := e.ctl.snapshot()
	phase := 0 // 0 factory/CBC, 1 device/CBC, 2 device/GCM
	for i, x := range in {
		p := map[bool]int{false: 1, true: 2}[x.gcm]
		if x.key == "factory" {
			p = 0
			if x.gcm {
				t.Errorf("inform %d: GCM on the factory key", i)
			}
		}
		if p < phase {
			t.Errorf("inform %d went back from phase %d to %d", i, phase, p)
		}
		phase = p
	}
	if phase != 2 {
		t.Fatalf("never reached GCM informs (phase %d)", phase)
	}
	if !e.a.x.S.Adopted || !e.a.x.S.GCM {
		t.Errorf("session: adopted=%v gcm=%v", e.a.x.S.Adopted, e.a.x.S.GCM)
	}
	m := in[len(in)-1].payload
	if m["model"] != "UAL6" || m["mac"] != "b0:a7:b9:3e:17:00" || m["ip"] != e2eUnitIP || m["cfgversion"] != "00000000000000c1" {
		t.Errorf("identity: model %v mac %v ip %v cfgversion %v", m["model"], m["mac"], m["ip"], m["cfgversion"])
	}
	// WPA3, plus in takeover, where the agent owns Wi-Fi: RF_SCAN and
	// BANDSTEER (it scans, bcmwifi steers), WPA_PSK_FILE and LOCK_AP
	// (MINRATE_CTRL only with min_rates), Roaming Assistant (wifi_caps2),
	// RADIUS filter (fw_caps), RadSec (fw2_caps) and multicast inspect
	// (fw3_caps); the mDNS bridge and Hotspot 2.0 only with their config
	// keys. Encrypted syslog, SNMPv3 and path monitoring in both modes.
	want := map[string]float64{"wifi_caps": 131072, "fw_caps": 0x1405403, "fw3_caps": 0x40}
	if e.cfg.Takeover {
		want = map[string]float64{"wifi_caps": 131092 | 1<<20 | 1<<24, "wifi_caps2": 0x20,
			"fw_caps": 0x21405403, "fw2_caps": 0x80000, "fw3_caps": 0xc0}
	}
	for _, k := range []string{"wifi_caps", "wifi_caps2", "fw_caps", "fw2_caps", "fw3_caps"} {
		if num(m[k]) != want[k] {
			t.Errorf("%s %v, want %v", k, m[k], want[k])
		}
	}
	docsCapabilityWords(t, e.cfg.Takeover, m) // and the design document quotes the same words
	// The session.go fix: once adopted, sys_stats and radio_table_stats are
	// the unit's (proc_meminfo.txt MemTotal 252152 kB; chanspecs 2l and
	// 44/80; clients from sta_info all), not the canned U7PG2 constants
	// (mem_total 129130496, channel 6/36).
	ss, _ := m["sys_stats"].(map[string]any)
	if num(ss["mem_total"]) != 252152*1024 {
		t.Errorf("sys_stats not the unit's: %v", ss)
	}
	rs, _ := m["radio_table_stats"].([]any)
	got := map[string]map[string]any{}
	for _, r := range rs {
		rr := r.(map[string]any)
		got[fmt.Sprint(rr["radio"])] = rr
	}
	if len(got) != 2 || num(got["ng"]["channel"]) != 2 || num(got["na"]["channel"]) != 44 {
		t.Fatalf("radio_table_stats not the unit's: %v", rs)
	}
	if num(got["ng"]["num_sta"])+num(got["na"]["num_sta"]) == 0 {
		t.Errorf("radio_table_stats without the captured clients: %v", rs)
	}
	if vaps, _ := m["vap_table"].([]any); len(vaps) == 0 {
		t.Error("no vap_table")
	}
	return m
}

// checkNoSecrets: no synthesised secret in the log, an inform or any file
// the agent wrote, except the saved system_cfg itself (0600, as on a UAP).
func (e *e2e) checkNoSecrets(secrets []string) {
	t := e.t
	logs := e.logs.all()
	var informs strings.Builder
	for _, i := range e.ctl.snapshot() {
		informs.WriteString(i.raw)
	}
	for _, s := range secrets {
		if strings.Contains(logs, s) {
			t.Errorf("secret %.10q... in the log", s)
		}
		if strings.Contains(informs.String(), s) {
			t.Errorf("secret %.10q... in an inform", s)
		}
	}
	sess := e.unit.path("/tp_data/udeco/session")
	filepath.WalkDir(e.unit.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasPrefix(p, sess) && strings.Contains(p, "system_cfg") {
			if fi, err := os.Stat(p); err == nil && fi.Mode().Perm() != 0o600 {
				t.Errorf("%s: mode %o, want 0600", p, fi.Mode().Perm())
			}
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, s := range secrets {
			if strings.Contains(string(b), s) {
				rel, _ := filepath.Rel(e.unit.root, p)
				t.Errorf("secret %.10q... written to %s", s, rel)
			}
		}
		return nil
	})
}

// ------------------------------------------------------------------ tests

// Observe mode: the whole adoption and provisioning runs while the unit is
// only read: every command the agent ran is a getter, and no decosys or
// bcmwifi handle exists.
func TestE2EObserve(t *testing.T) {
	cfg, secrets := u6proSystemCfg(t)
	e := newE2E(t, cfg, false)
	e.unit.spec = newSpecFake() // would answer a scan, were one run
	e.ctl.reply = func(in e2eInform) string {
		if e.ctlStep == 0 {
			e.ctlStep = 1
			return `{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":80}`
		}
		return ""
	}
	e.adopt()
	eventually(t, "the quick-scan logged", func() bool {
		return strings.Contains(e.logs.all(), "observe mode: quick-scan:na:80 logged only")
	})
	e.stop()

	e.checkFlow()
	if sc := e.unit.spec.scanList(); len(sc) != 0 {
		t.Errorf("observe mode scanned: %v", sc)
	}
	if m := e.unit.mutating(); len(m) > 0 {
		t.Errorf("observe mode issued %d mutating command(s): %q", len(m), m)
	}
	if n := len(e.unit.calls); n == 0 {
		t.Error("the collector ran no command at all")
	}
	if e.wifi != nil || len(e.sysOpts) != 0 {
		t.Error("observe mode built decosys/bcmwifi")
	}
	logs := e.logs.all()
	for _, want := range []string{"ADOPTED via SSH set-adopt", "observe mode: the controller's Wi-Fi plan above is logged only",
		"wifi: controller plan from system_cfg"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %q", want)
		}
	}
	e.checkNoSecrets(secrets)
}

// Takeover with apply (decosys and bcmwifi forced into DryRun): decosys
// plans the TP-Link stop set from the .205 process table and crontab;
// bcmwifi plans the controller's two WLANs (VLAN 2 on the uplink found from
// the gateway's FDB entry, eth1) with the hardware caps the collector read;
// nothing is changed on the unit.
func TestE2ETakeoverDryRun(t *testing.T) {
	cfg, secrets := u6proSystemCfg(t)
	e := newE2E(t, cfg, true)
	e.adopt()
	eventually(t, "the bcmwifi dry-run apply", func() bool { return strings.Contains(e.logs.all(), "is live") })
	e.stop()

	e.checkFlow()
	if m := e.unit.mutating(); len(m) > 0 {
		t.Errorf("DryRun takeover issued %d mutating command(s): %q", len(m), m)
	}
	logs := e.logs.all()

	// decosys
	if len(e.sysOpts) != 1 {
		t.Fatalf("decosys built %d times", len(e.sysOpts))
	}
	so := e.sysOpts[0]
	if so.LANCIDR != "" || so.ControllerIP != "127.0.0.1" || so.ConsoleIP != "127.0.0.1" || so.SSHDPort != e.cfg.SSHDPort {
		t.Errorf("phase-1 decosys options %+v", so)
	}
	if want := (decosys.LAN{GatewayIP: "192.168.0.1", LANCIDR: "192.168.0.0/24", UnitIP: e2eUnitIP}); len(e.sysLAN) == 0 || e.sysLAN[0] != want {
		t.Errorf("LAN handed to decosys: %+v", e.sysLAN)
	}
	for _, want := range []string{
		"decosys: dry-run: stop awn",                           // the mesh daemons
		"decosys: dry-run: cron",                               // dwds_tpbr_check, tmpsvr_check
		"decosys: dry-run: ntp udeco-ntpd",                     // NTP from the gateway only
		"decosys: dry-run: /usr/sbin/iptables -w -N UDECO-OUT", // egress chain (egress=true)
		"decosys: TP-Link services stopped",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %q", want)
		}
	}
	if b, err := os.ReadFile(e.unit.path("/etc/crontabs/root")); err != nil || !strings.Contains(string(b), "dwds_tpbr_check") {
		t.Error("DryRun rewrote the crontab")
	}

	// bcmwifi
	w := e.wifi
	if w == nil {
		t.Fatal("bcmwifi not built")
	}
	if w.opts.Uplink != "eth1" || w.opts.Caps == nil || w.opts.RunDir != "/tmp/udeco" || w.opts.StateDir != "/tp_data/udeco/state" {
		t.Errorf("bcmwifi options: uplink %q caps %v run %q state %q", w.opts.Uplink, w.opts.Caps != nil, w.opts.RunDir, w.opts.StateDir)
	}
	p, ok := w.lastPlan()
	if !ok {
		t.Fatal("no bcmwifi plan")
	}
	d := p.Desired
	if d.Country != "IN" || len(d.SSIDs) != 2 {
		t.Fatalf("desired: country %q, %d SSIDs", d.Country, len(d.SSIDs))
	}
	ssids := map[string]bcmwifi.SSID{}
	for _, s := range d.SSIDs {
		ssids[s.SSID] = s
	}
	iot, home := ssids["EXN IOT"], ssids["Example Network"]
	if iot.VLAN != 2 || !iot.Isolation || !slices.Equal(iot.Bands, []string{"ng"}) || iot.Security != "wpa2" {
		t.Errorf("IOT SSID %v", iot)
	}
	if home.VLAN != 0 || !slices.Equal(home.Bands, []string{"na"}) || home.Security != "wpa2wpa3" || home.Passphrase != "E2e-Fake-Psk-aaa2wpapsk" {
		t.Errorf("home SSID %v", home)
	}
	steps := p.String()
	for _, want := range []string{
		"ip link add link eth1 name eth1.2 type vlan id 2", // VLAN 2 on the detected uplink
		"brctl addbr br-v2",
		"write /tmp/udeco/hapd-wl0.conf (0600",
		"write /tmp/udeco/hapd-wl1.conf (0600",
		"chanspec 40/80", // 11naht160 on channel 40: no 160 MHz on the unit
	} {
		if !strings.Contains(steps, want) {
			t.Errorf("plan lacks %q:\n%s", want, steps)
		}
	}
	// the caps the collector read reach bcmwifi: .205 was captured with
	// country US, the controller asks for IN, so bcmwifi says it cannot use
	// them for this country
	if !strings.Contains(strings.Join(p.Notes, "\n"), `hardware caps are for country "US", not "IN"`) {
		t.Errorf("caps not consulted: notes %q", p.Notes)
	}
	var conf []byte
	for _, s := range p.Steps {
		if s.Kind == bcmwifi.StepWrite && s.Path == "/tmp/udeco/hapd-wl1.conf" {
			conf = s.Data
		}
	}
	if !strings.Contains(string(conf), "ssid=Example Network\n") || !strings.Contains(string(conf), "E2e-Fake-Psk-aaa2wpapsk") {
		t.Errorf("wl1 hostapd conf lacks the home SSID or its passphrase")
	}
	if !strings.Contains(logs, "bcmwifi dry-run: ") {
		t.Error("the dry-run apply logged no plan")
	}
	if _, err := os.Stat(e.unit.path("/tmp/udeco/hapd-wl1.conf")); err == nil {
		t.Error("DryRun wrote a hostapd conf")
	}
	if !e.a.takeover.Load() || strings.Contains(logs, "OBSERVE") {
		t.Error("dropped out of takeover")
	}
	e.checkNoSecrets(secrets)
}

// With the controller's country equal to the one the driver was read in
// (US), bcmwifi checks the channels against the driver's own list: channel
// 13 is not in the US list, so 2.4 GHz stays on the live channel (auto)
// instead of an apply that fails and rolls back.
func TestE2ECapsClampChannel(t *testing.T) {
	cfg, _ := u6proSystemCfg(t)
	cfg = regexp.MustCompile(`(?m)^(radio(\.[12])?\.countrycode)=356$`).ReplaceAllString(cfg, "${1}=840")
	e := newE2E(t, cfg, true)
	e.adopt()
	eventually(t, "a bcmwifi plan", func() bool { _, ok := e.wifi.lastPlan(); return ok })
	e.stop()
	p, _ := e.wifi.lastPlan()
	notes := strings.Join(p.Notes, "\n")
	if p.Desired.Country != "US" || !strings.Contains(notes, "channel 13 is not allowed") {
		t.Errorf("country %q, notes:\n%s", p.Desired.Country, notes)
	}
	if strings.Contains(p.String(), "chanspec 13") {
		t.Errorf("planned a channel the driver does not list:\n%s", p)
	}
	if m := e.unit.mutating(); len(m) > 0 {
		t.Errorf("DryRun takeover issued mutating commands: %q", m)
	}
}
