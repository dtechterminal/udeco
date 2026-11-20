package decosys

// Fixtures in testdata were captured read-only from the satellite
// 192.168.0.205 and the master 192.168.0.241 (services research, 2026-11-18):
//   procs-*.txt              pid|ppid|rss|name|cmdline (cmdline space-joined)
//   crontab-*                /etc/crontabs/root
//   ubus-service-list-*.json 'ubus call service list'
//   initd-*.txt              'ls /etc/init.d'

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRun records commands and answers from a script of responses.
type fakeRun struct {
	mu    sync.Mutex
	calls []string
	// resp maps a full command line to its answers; the last answer repeats.
	resp map[string][]fakeResp
}

type fakeResp struct {
	out []byte
	err error
}

func newFakeRun() *fakeRun { return &fakeRun{resp: map[string][]fakeResp{}} }

func (f *fakeRun) on(cmd string, out string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resp[cmd] = append(f.resp[cmd], fakeResp{[]byte(out), err})
}

// set replaces the answers for cmd.
func (f *fakeRun) set(cmd string, out string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resp[cmd] = []fakeResp{{[]byte(out), err}}
}

func (f *fakeRun) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	rs := f.resp[line]
	if len(rs) == 0 {
		return nil, nil
	}
	r := rs[0]
	if len(rs) > 1 {
		f.resp[line] = rs[1:]
	}
	return r.out, r.err
}

func (f *fakeRun) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls
	f.calls = nil
	return c
}

var errExit1 = errors.New("exit status 1")

// fakeUnit is a fake device root.
type fakeUnit struct {
	t    *testing.T
	root string
}

// newUnit builds a fake root from the fixtures of one device ("205"/"241").
func newUnit(t *testing.T, dev string) *fakeUnit {
	t.Helper()
	u := &fakeUnit{t: t, root: t.TempDir()}
	u.setProcs(readProcsFixture(t, dev))
	for _, n := range readLinesFixture(t, "initd-"+dev+".txt") {
		u.write("etc/init.d/"+n, "#!/bin/sh /etc/rc.common\n")
	}
	u.write("etc/crontabs/root", string(readFixture(t, "crontab-"+dev)))
	for _, b := range []string{"usr/sbin/iptables", "usr/sbin/ip6tables", "usr/sbin/ntpd",
		"sbin/start-stop-daemon", "bin/kill", "bin/ubus"} {
		u.write(b, "")
	}
	u.write("var/run/udeco-ntpd.pid", "4242\n") // stale
	return u
}

func (u *fakeUnit) write(p, s string) {
	u.t.Helper()
	full := filepath.Join(u.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		u.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(s), 0o600); err != nil {
		u.t.Fatal(err)
	}
}

func (u *fakeUnit) read(p string) string {
	u.t.Helper()
	b, err := os.ReadFile(filepath.Join(u.root, p))
	if err != nil {
		u.t.Fatal(err)
	}
	return string(b)
}

// setProcs replaces the fake /proc with the given pid -> argv table. Kernel
// threads get an empty cmdline, as on the device.
func (u *fakeUnit) setProcs(ps map[int][]string) {
	u.t.Helper()
	if err := os.RemoveAll(filepath.Join(u.root, "proc")); err != nil {
		u.t.Fatal(err)
	}
	for pid, argv := range ps {
		s := ""
		if len(argv) > 0 {
			s = strings.Join(argv, "\x00") + "\x00"
		}
		u.write(fmt.Sprintf("proc/%d/cmdline", pid), s)
	}
	u.write("proc/self/cmdline", "udeco-ap\x00") // non-numeric entries are skipped
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readLinesFixture(t *testing.T, name string) []string {
	return strings.Fields(string(readFixture(t, name)))
}

func readProcsFixture(t *testing.T, dev string) map[int][]string {
	t.Helper()
	ps := map[int][]string{}
	sc := bufio.NewScanner(strings.NewReader(string(readFixture(t, "procs-"+dev+".txt"))))
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), "|", 5)
		if len(f) != 5 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			t.Fatalf("bad fixture line %q", sc.Text())
		}
		ps[pid] = strings.Fields(f[4])
	}
	return ps
}

// keepProcs filters a process table down to what the takeover leaves
// running, and adds the agent's ntpd.
func keepProcs(ps map[int][]string, gw string) map[int][]string {
	keep := []string{"procd", "ubusd", "logd", "leds", "netifd", "login", "dropbear", "powermanager",
		"smartipd", "udhcpc", "hostapd", "wpa_supplicant", "eapd", "apsd", "imsnoop", "crond", "ash", "ps"}
	out := map[int][]string{}
	for pid, argv := range ps {
		if len(argv) == 0 {
			out[pid] = nil
			continue
		}
		if argv[0] == "/usr/sbin/dropbear" {
			continue
		}
		if slices.Contains(keep, filepath.Base(argv[0])) {
			out[pid] = argv
		}
	}
	out[30000] = []string{"/usr/sbin/ntpd", "-n", "-p", gw}
	return out
}

func newManager(u *fakeUnit, r Runner, dry bool) *Manager {
	return New(Options{Root: u.root, Run: r, ControllerIP: "192.168.0.1", GatewayIP: "192.168.0.1",
		LANCIDR: "192.168.0.0/24", DryRun: dry})
}

func diff(t *testing.T, got, want []string) {
	t.Helper()
	if slices.Equal(got, want) {
		return
	}
	t.Errorf("commands differ\n got (%d):\n  %s\nwant (%d):\n  %s", len(got), strings.Join(got, "\n  "),
		len(want), strings.Join(want, "\n  "))
}

var want205 = []string{
	"/bin/ubus call service list",
	"/etc/init.d/tmpsvr stop",
	"/etc/init.d/dropbear stop",
	"/bin/kill 6244",
	"/etc/init.d/awn stop",
	"/etc/init.d/sync-server stop",
	"/etc/init.d/tipc-server stop",
	"/etc/init.d/cloud_client stop",
	"/etc/init.d/cloud_https stop",
	"/etc/init.d/cloud_proxy stop",
	"/bin/kill 8793", // cloud-proxy outside procd: the init stop leaves it running
	"/etc/init.d/cloud_pfclient stop",
	"/etc/init.d/msgcenter stop",
	`/bin/ubus call service delete {"name":"wifi"}`,
	`/bin/ubus call service delete {"name":"sysmode"}`,
	`/bin/ubus call service delete {"name":"guest_eth"}`,
	`/bin/ubus call service delete {"name":"guest-schedule"}`,
	`/bin/ubus call service delete {"name":"guest-bandwidth"}`,
	`/bin/ubus call service delete {"name":"leds_night_mode"}`,
	`/bin/ubus call service delete {"name":"time_settings"}`,
	"/etc/init.d/nrd stop",
	"/etc/init.d/wpsd stop",
	"/etc/init.d/conn-indicator stop",
	"/etc/init.d/server-probe stop",
	"/etc/init.d/wan stop",
	"/etc/init.d/client_mgmt stop",
	"/etc/init.d/dhcp_hook_d stop",
	"/etc/init.d/msg_server stop",
	"/etc/init.d/tfstats stop",
	"/etc/init.d/tsched stop",
	"/etc/init.d/uhttpd stop",
	"/etc/init.d/uhttpd-fw stop",
	"/bin/kill 13709",
	"/etc/init.d/sysntpd stop",
	"/sbin/start-stop-daemon -S -b -m -p /var/run/udeco-ntpd.pid -x /usr/sbin/ntpd -- -n -p 192.168.0.1",
}

func TestEnforceSatellite(t *testing.T) {
	ctx := context.Background()
	u := newUnit(t, "205")
	r := newFakeRun()
	r.on("/bin/ubus call service list", string(readFixture(t, "ubus-service-list-205.json")), nil)
	m := newManager(u, r, false)
	clock := time.Date(2026, 11, 18, 22, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return clock }

	rep, err := m.Enforce(ctx)
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	diff(t, r.take(), want205)
	if !rep.Changed() || rep.Steps[0].Kind != KindCron {
		t.Fatalf("first step = %v, want the crontab rewrite", rep.Steps[0])
	}

	if got, want := u.read("etc/crontabs/root"), "* * * * * /data/persist_shell.sh\n"; got != want {
		t.Errorf("crontab = %q, want %q", got, want)
	}
	if fi, _ := os.Stat(filepath.Join(u.root, "etc/crontabs/root")); fi.Mode().Perm() != 0o600 {
		t.Errorf("crontab mode = %v, want 0600", fi.Mode())
	}
	if got := strings.Count(u.read("etc/udeco/crontab.root.tplink"), "\n"); got != 5 {
		t.Errorf("cron backup holds %d lines, want 5", got)
	}
	if _, err := os.Stat(filepath.Join(u.root, "var/run/udeco-ntpd.pid")); !os.IsNotExist(err) {
		t.Errorf("stale ntpd pidfile not removed: %v", err)
	}
	stopped := strings.Fields(u.read("etc/udeco/decosys.stopped"))
	for _, s := range []string{"awn", "tmpsvr", "dropbear", "sysntpd", "uhttpd-fw"} {
		if !slices.Contains(stopped, s) {
			t.Errorf("stop record %v lacks %s", stopped, s)
		}
	}

	// Already clean: no commands at all, and nothing written.
	u.setProcs(keepProcs(readProcsFixture(t, "205"), "192.168.0.1"))
	rep, err = m.Enforce(ctx)
	if err != nil {
		t.Fatalf("second Enforce: %v", err)
	}
	if c := r.take(); len(c) != 0 || rep.Changed() {
		t.Fatalf("second Enforce ran %q, steps %v; want nothing", c, rep.Steps)
	}

	// Later, procd's trigger list is re-read once; nothing to delete.
	r.set("/bin/ubus call service list", `{"cron":{},"network":{}}`, nil)
	clock = clock.Add(triggerRecheck)
	if _, err := m.Enforce(ctx); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{"/bin/ubus call service list"})
	if _, err := m.Enforce(ctx); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), nil)
}

func TestEnforceMaster(t *testing.T) {
	u := newUnit(t, "241")
	r := newFakeRun()
	r.on("/bin/ubus call service list", string(readFixture(t, "ubus-service-list-241.json")), nil)
	m := newManager(u, r, false)
	if _, err := m.Enforce(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := r.take()
	for _, want := range []string{
		"/etc/init.d/cloud_brd stop",
		"/etc/init.d/iot-wifi-center mgmt false",
		"/etc/init.d/dropbear stop",
		"/bin/kill 2341 9205", // the :20001 listener and its session
	} {
		if !slices.Contains(calls, want) {
			t.Errorf("missing %q in\n  %s", want, strings.Join(calls, "\n  "))
		}
	}
	// One group stop covers every IoT daemon.
	for _, c := range calls {
		for _, iot := range []string{"iot-netdev", "iot-tapo", "iot-tpra", "philips-hue"} {
			if strings.Contains(c, iot) {
				t.Errorf("IoT daemon %s stopped individually: %q", iot, c)
			}
		}
	}
	got := u.read("etc/crontabs/root")
	if got != "* * * * * /data/persist_shell.sh\n" {
		t.Errorf("crontab = %q", got)
	}
}

// keepPIDs returns the PIDs of processes the takeover must never signal.
func keepPIDs(ps map[int][]string) map[string]bool {
	keep := []string{"procd", "ubusd", "logd", "leds", "netifd", "login", "powermanager", "smartipd",
		"udhcpc", "hostapd", "wpa_supplicant", "eapd", "apsd", "imsnoop", "crond"}
	out := map[string]bool{}
	for pid, argv := range ps {
		if len(argv) > 0 && (slices.Contains(keep, filepath.Base(argv[0])) || argv[0] == "/data/dropbear") {
			out[strconv.Itoa(pid)] = true
		}
	}
	return out
}

func TestNeverTouchesKeep(t *testing.T) {
	forbidden := []string{"repacd", "/sbin/wifi", "/etc/init.d/wifi", "/etc/init.d/network", "tpbr",
		"/etc/init.d/sysmode", "uci", "nvram", "reboot", "/etc/init.d/cron", "/etc/init.d/log",
		"/etc/init.d/leds", "/etc/init.d/imsnoop", "/etc/init.d/apsd", "/etc/init.d/powermanager",
		"/etc/init.d/smartipd", "eapd", "wpa_supplicant", "hostapd", "/data/dropbear", "killall"}
	for _, dev := range []string{"205", "241"} {
		u := newUnit(t, dev)
		r := newFakeRun()
		r.on("/bin/ubus call service list", string(readFixture(t, "ubus-service-list-"+dev+".json")), nil)
		if _, err := newManager(u, r, false).Enforce(context.Background()); err != nil {
			t.Fatal(err)
		}
		keep := keepPIDs(readProcsFixture(t, dev))
		for _, c := range r.take() {
			for _, f := range forbidden {
				if strings.Contains(c, f) {
					t.Errorf("%s: command %q contains forbidden %q", dev, c, f)
				}
			}
			if strings.HasPrefix(c, "/bin/kill ") {
				for _, pid := range strings.Fields(c)[1:] {
					if keep[pid] {
						t.Errorf("%s: %q signals KEEP pid %s", dev, c, pid)
					}
				}
			}
		}
	}
}

func TestDryRun(t *testing.T) {
	u := newUnit(t, "205")
	before := u.read("etc/crontabs/root")
	r := newFakeRun()
	r.on("/bin/ubus call service list", string(readFixture(t, "ubus-service-list-205.json")), nil)
	m := newManager(u, r, true)

	plan, err := m.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rep, err := m.Enforce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{"/bin/ubus call service list", "/bin/ubus call service list"})
	if !rep.DryRun || len(rep.Steps) != len(plan) {
		t.Fatalf("dry-run report has %d steps, plan %d", len(rep.Steps), len(plan))
	}
	var cmds []string
	for _, s := range rep.Steps {
		if s.Cmd != nil {
			cmds = append(cmds, strings.Join(s.Cmd, " "))
		}
	}
	diff(t, cmds, want205[1:])
	if u.read("etc/crontabs/root") != before {
		t.Error("dry run changed the crontab")
	}
	if _, err := os.Stat(filepath.Join(u.root, "etc/udeco")); !os.IsNotExist(err) {
		t.Error("dry run wrote state")
	}
	// Still dirty: triggers are checked again next time.
	if m.triggersClean {
		t.Error("dry run marked triggers clean")
	}
}

func TestTriggerListFailureIsRetried(t *testing.T) {
	u := newUnit(t, "205")
	u.setProcs(keepProcs(readProcsFixture(t, "205"), "192.168.0.1"))
	r := newFakeRun()
	r.on("/bin/ubus call service list", "", errExit1)
	r.on("/bin/ubus call service list", `{"wifi":{}}`, nil)
	m := newManager(u, r, false)
	if _, err := m.Enforce(context.Background()); err == nil {
		t.Fatal("want error when procd cannot be asked")
	}
	r.take()
	if _, err := m.Enforce(context.Background()); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{"/bin/ubus call service list", `/bin/ubus call service delete {"name":"wifi"}`})
	if _, err := m.Enforce(context.Background()); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), nil)
}

func TestKillToleratesExitedProcess(t *testing.T) {
	u := newUnit(t, "205")
	u.setProcs(map[int][]string{1: {"/sbin/procd"}, 13709: {"acsd2"}})
	r := newFakeRun()
	r.on("/bin/kill 13709", "", errExit1)
	m := newManager(u, r, false)
	m.triggersClean, m.triggersAt = true, time.Now()
	// The fake kill fails while the process still exists: a real error.
	if _, err := m.Enforce(context.Background()); err == nil {
		t.Fatal("want error when kill fails and the process lives")
	}
	// Same failure, but the process is gone by then (procd reaped it).
	s := m.killStep("acsd2", "test", []int{13709}, phaseKills[0].matches)
	u.setProcs(map[int][]string{1: {"/sbin/procd"}})
	r.take()
	if err := m.exec(context.Background(), s); err != nil {
		t.Fatalf("kill of an exited process: %v", err)
	}
	diff(t, r.take(), nil) // nothing left to signal
}

// A PID from the plan that now belongs to another program (reused, or a
// zombie with an empty cmdline) is never signalled.
func TestKillRevalidatesPIDs(t *testing.T) {
	u := newUnit(t, "205")
	u.setProcs(map[int][]string{1: {"/sbin/procd"}, 100: {"acsd2"}, 101: {"/usr/sbin/radar"}})
	r := newFakeRun()
	m := newManager(u, r, false)
	s := m.killStep("acsd2", "test", []int{100, 101}, func(argv []string) bool {
		return phaseKills[0].matches(argv) || phaseKills[1].matches(argv)
	})
	u.setProcs(map[int][]string{1: {"/sbin/procd"}, 100: {"hostapd", "-B", "/tmp/wl0.1_hapd.conf"}, 101: {"/usr/sbin/radar"}})
	if err := m.exec(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{"/bin/kill 101"})
}

// Shell scripts run as "/bin/sh <script>" are matched by the script name;
// init-script shells and inline shells are not.
func TestScriptTargets(t *testing.T) {
	u := newUnit(t, "205")
	u.setProcs(map[int][]string{
		1:   {"/sbin/procd"},
		200: {"/bin/sh", "/usr/sbin/sync-check", "role"},
		201: {"/bin/sh", "/usr/sbin/start_nrd"},
		202: {"/bin/sh", "/usr/sbin/bcm_nrd_check_acs"},
		203: {"/bin/sh", "/etc/rc.common", "/etc/init.d/repacd", "restart"},
		204: {"ash", "-c", "sync-check role"},
		205: {"/bin/sh", "/data/persist_shell.sh"},
		206: {"/usr/sbin/ntpd", "-n", "-p", "192.168.0.1"},
	})
	u.write("etc/crontabs/root", "* * * * * /data/persist_shell.sh\n")
	r := newFakeRun()
	m := newManager(u, r, false)
	m.triggersClean, m.triggersAt = true, time.Now()
	rep, err := m.Enforce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{"/bin/kill 201 202", "/bin/kill 200"})
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "pid 203") {
		t.Errorf("warnings = %q, want the in-flight repacd only", rep.Warnings)
	}
}

// A pass cut short before the trigger deletes leaves procd's triggers to be
// checked again on the next pass.
func TestCancelledPassKeepsTriggersDirty(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	r.on("/bin/ubus call service list", string(readFixture(t, "ubus-service-list-205.json")), nil)
	m := newManager(u, r, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Enforce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Enforce = %v, want context.Canceled", err)
	}
	if m.triggersClean {
		t.Error("cancelled pass marked the procd triggers clean")
	}
}

// Without an init script, dropbear's procd service is deleted and its
// session processes are still killed, so the pass converges.
func TestDropbearWithoutInit(t *testing.T) {
	u := newUnit(t, "241")
	if err := os.Remove(filepath.Join(u.root, "etc/init.d/dropbear")); err != nil {
		t.Fatal(err)
	}
	u.setProcs(map[int][]string{1: {"/sbin/procd"}, 22386: {"/data/dropbear", "-p", "22"},
		9205: {"/usr/sbin/dropbear", "-F", "-p", "20001"}})
	u.write("etc/crontabs/root", "* * * * * /data/persist_shell.sh\n")
	r := newFakeRun()
	r.on("/bin/ubus call service list", `{"dropbear":{}}`, nil)
	m := New(Options{Root: u.root, Run: r})
	if _, err := m.Enforce(context.Background()); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{"/bin/ubus call service list",
		`/bin/ubus call service delete {"name":"dropbear"}`, "/bin/kill 9205"})
}

func TestNTP(t *testing.T) {
	gw := "192.168.0.1"
	cases := []struct {
		name  string
		gw    string
		procs map[int][]string
		want  []string
	}{
		{"ours running", gw, map[int][]string{5: {"/usr/sbin/ntpd", "-n", "-p", gw}}, nil},
		{"none running", gw, nil,
			[]string{"/sbin/start-stop-daemon -S -b -m -p /var/run/udeco-ntpd.pid -x /usr/sbin/ntpd -- -n -p 192.168.0.1"}},
		{"stale gateway and duplicate", gw, map[int][]string{
			5: {"/usr/sbin/ntpd", "-n", "-p", "10.0.0.1"},
			6: {"/usr/sbin/ntpd", "-n", "-p", gw},
			7: {"/usr/sbin/ntpd", "-n", "-p", gw}},
			[]string{"/bin/kill 5 7"}},
		{"tp-link and ours", gw, map[int][]string{
			5: {"/usr/sbin/ntpd", "-n", "-C", "-p", "us.pool.ntp.org"},
			6: {"/usr/sbin/ntpd", "-n", "-p", gw}},
			[]string{"/etc/init.d/sysntpd stop"}},
		{"no gateway: hands off", "", map[int][]string{
			5: {"/usr/sbin/ntpd", "-n", "-C", "-p", "us.pool.ntp.org"}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := newUnit(t, "205")
			u.setProcs(c.procs)
			u.write("etc/crontabs/root", "* * * * * /data/persist_shell.sh\n")
			r := newFakeRun()
			m := New(Options{Root: u.root, Run: r, GatewayIP: c.gw})
			m.triggersClean, m.triggersAt = true, time.Now()
			if _, err := m.Enforce(context.Background()); err != nil {
				t.Fatal(err)
			}
			diff(t, r.take(), c.want)
		})
	}
}

func TestCronClassification(t *testing.T) {
	for line, tp := range map[string]bool{
		"*/10 * * * * /usr/bin/dwds_tpbr_check":                       true,
		"24 10 19 11 * /lib/deleteToken.sh /tmp/cloud/x nbu.homecare": true,
		"0-59/1 * * * * /usr/sbin/smart_home_schedule":                true,
		"@reboot /sbin/something":                                     true,
		"* * * * * /data/persist_shell.sh":                            false,
		"*/5 * * * * /tp_data/udeco/check.sh":                         false,
		"* * * * * sh /data/x.sh":                                     false,
		"# */5 * * * * /usr/sbin/tmpsvr_check":                        false,
		"PATH=/usr/sbin:/usr/bin":                                     false,
		"":                                                            false,
	} {
		if got := isTPLinkCron(line); got != tp {
			t.Errorf("isTPLinkCron(%q) = %v, want %v", line, got, tp)
		}
	}
}

func TestRestore(t *testing.T) {
	ctx := context.Background()
	u := newUnit(t, "205")
	orig := u.read("etc/crontabs/root")
	r := newFakeRun()
	r.on("/bin/ubus call service list", string(readFixture(t, "ubus-service-list-205.json")), nil)
	m := newManager(u, r, false)
	if _, err := m.Enforce(ctx); err != nil {
		t.Fatal(err)
	}
	r.take()
	u.setProcs(keepProcs(readProcsFixture(t, "205"), "192.168.0.1"))
	u.write("var/run/udeco-ntpd.pid", "30000\n")
	// The user's own line added while TP-Link was stopped survives.
	u.write("etc/crontabs/root", "* * * * * /data/persist_shell.sh\n*/5 * * * * /tp_data/x.sh\n")
	for _, b := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"} {
		r.on(b+" -w -C OUTPUT -j UDECO-OUT", "", errExit1)
		r.on(b+" -w -S UDECO-OUT", "", errExit1)
		r.on(b+" -w -C INPUT -j UDECO-IN", "", errExit1)
		r.on(b+" -w -S UDECO-IN", "", errExit1)
		r.on(b+" -w -S UDECO-LOCK", "", errExit1)
	}

	if err := m.Restore(ctx); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	diff(t, r.take(), []string{
		"/usr/sbin/iptables -w -S INPUT", // the login lock first (loginlock.go)
		"/usr/sbin/iptables -w -S UDECO-LOCK",
		"/usr/sbin/ip6tables -w -S INPUT",
		"/usr/sbin/ip6tables -w -S UDECO-LOCK",
		"/usr/sbin/iptables -w -C OUTPUT -j UDECO-OUT",
		"/usr/sbin/iptables -w -S UDECO-OUT",
		"/usr/sbin/ip6tables -w -C OUTPUT -j UDECO-OUT",
		"/usr/sbin/ip6tables -w -S UDECO-OUT",
		"/usr/sbin/iptables -w -C INPUT -j UDECO-IN",
		"/usr/sbin/iptables -w -S UDECO-IN",
		"/usr/sbin/ip6tables -w -C INPUT -j UDECO-IN",
		"/usr/sbin/ip6tables -w -S UDECO-IN",
		"/bin/kill 30000",
		"/etc/init.d/sysntpd start",
		"/etc/init.d/uhttpd-fw start",
		"/etc/init.d/uhttpd start",
		"/etc/init.d/tsched start",
		"/etc/init.d/tfstats start",
		"/etc/init.d/msg_server start",
		"/etc/init.d/dhcp_hook_d start",
		"/etc/init.d/client_mgmt start",
		"/etc/init.d/wan start",
		"/etc/init.d/server-probe start",
		"/etc/init.d/conn-indicator start",
		"/etc/init.d/wpsd start",
		"/etc/init.d/nrd start",
		"/etc/init.d/msgcenter start",
		"/etc/init.d/cloud_pfclient start",
		"/etc/init.d/cloud_proxy start",
		"/etc/init.d/cloud_https start",
		"/etc/init.d/cloud_client start",
		"/etc/init.d/tipc-server start",
		"/etc/init.d/sync-server start",
		"/etc/init.d/awn start",
		"/etc/init.d/dropbear start",
		"/etc/init.d/tmpsvr start",
	})
	cron := u.read("etc/crontabs/root")
	for _, l := range strings.Split(strings.TrimSpace(orig), "\n") {
		if !strings.Contains(cron, l+"\n") {
			t.Errorf("restored crontab lacks %q:\n%s", l, cron)
		}
	}
	if !strings.Contains(cron, "/tp_data/x.sh") {
		t.Error("restore dropped the user's line")
	}
	for _, p := range []string{"etc/udeco/decosys.stopped", "etc/udeco/crontab.root.tplink", "var/run/udeco-ntpd.pid"} {
		if _, err := os.Stat(filepath.Join(u.root, p)); !os.IsNotExist(err) {
			t.Errorf("%s left behind", p)
		}
	}
}

// Restore puts the ports the agent's loop guard took out of br-lan back
// (brctl addif, then a flow flush for the port) and removes the record; a
// port that is already a bridge member is left alone. Dry-run changes
// nothing and keeps the record.
func TestRestoreLoopGuardPorts(t *testing.T) {
	for _, dry := range []bool{false, true} {
		u := newUnit(t, "205")
		u.write("usr/sbin/brctl", "")
		u.write("usr/bin/fc", "")
		u.write("sys/class/net/eth1/brport/port_no", "2\n")
		u.write("tmp/udeco/loopguard", "eth0 lldp\neth1 fdb\n")
		r := newFakeRun()
		m := New(Options{Root: u.root, Run: r, LoopGuardFile: "/tmp/udeco/loopguard", DryRun: dry})
		if err := m.Restore(context.Background()); err != nil {
			t.Fatalf("dry %v: %v", dry, err)
		}
		calls := r.take()
		var bridge []string
		for _, c := range calls {
			if strings.Contains(c, "brctl") || strings.Contains(c, "fc flush") {
				bridge = append(bridge, c)
			}
		}
		_, err := os.Stat(filepath.Join(u.root, "tmp/udeco/loopguard"))
		if dry {
			if len(bridge) != 0 || err != nil {
				t.Errorf("dry run: %q, record %v", bridge, err)
			}
			continue
		}
		diff(t, bridge, []string{"/usr/sbin/brctl addif br-lan eth0", "/usr/bin/fc flush --if eth0"})
		if !os.IsNotExist(err) {
			t.Errorf("record left behind: %v", err)
		}
	}
}

// A port the loop guard took out goes back only when that cannot close the
// loop again (br-lan has no STP): with carrier on it and on another
// Ethernet port of br-lan it stays out, logged, and stays in the record; a
// port without carrier, or one whose bridged partner has none, goes back.
func TestRestoreLoopGuardKeepsLoopOut(t *testing.T) {
	for _, tc := range []struct {
		name        string
		eth0, eth1  string // carrier
		back        bool
		recordAfter string
	}{
		{"both cabled: loop", "1", "1", false, "eth0 lldp\n"},
		{"port without carrier", "0", "1", true, ""},
		{"uplink without carrier", "1", "0", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newUnit(t, "205")
			u.write("usr/sbin/brctl", "")
			u.write("usr/bin/fc", "")
			u.write("sys/class/net/eth1/brport/port_no", "2\n")
			u.write("sys/class/net/br-lan/brif/eth1/port_no", "2\n")
			u.write("sys/class/net/eth0/carrier", tc.eth0+"\n")
			u.write("sys/class/net/eth1/carrier", tc.eth1+"\n")
			u.write("tmp/udeco/loopguard", "eth0 lldp\n")
			r := newFakeRun()
			var logs strings.Builder
			m := New(Options{Root: u.root, Run: r, LoopGuardFile: "/tmp/udeco/loopguard",
				Logf: func(f string, a ...any) { fmt.Fprintf(&logs, f+"\n", a...) }})
			if err := m.RestoreLoopGuard(context.Background()); err != nil {
				t.Fatal(err)
			}
			calls := r.take()
			b, err := os.ReadFile(filepath.Join(u.root, "tmp/udeco/loopguard"))
			if tc.back {
				diff(t, calls, []string{"/usr/sbin/brctl addif br-lan eth0", "/usr/bin/fc flush --if eth0"})
				if !os.IsNotExist(err) {
					t.Errorf("record left behind: %q %v", b, err)
				}
				return
			}
			if len(calls) != 0 {
				t.Errorf("re-added into a loop: %q", calls)
			}
			if string(b) != tc.recordAfter {
				t.Errorf("record %q %v, want %q", b, err, tc.recordAfter)
			}
			if !strings.Contains(logs.String(), "eth0 stays out of br-lan") {
				t.Errorf("not logged: %s", logs.String())
			}
		})
	}
}

// RestoreLoopGuard (an observe-mode start) is the loop-guard part of Restore
// alone: the listed port goes back with its flow flush, the record goes, and
// nothing else (no firewall, NTP, cron or service command) is run.
func TestRestoreLoopGuardOnly(t *testing.T) {
	u := newUnit(t, "205")
	u.write("usr/sbin/brctl", "")
	u.write("usr/bin/fc", "")
	u.write("tmp/udeco/loopguard", "eth0 fdb\n")
	r := newFakeRun()
	m := New(Options{Root: u.root, Run: r, LoopGuardFile: "/tmp/udeco/loopguard"})
	if err := m.RestoreLoopGuard(context.Background()); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{"/usr/sbin/brctl addif br-lan eth0", "/usr/bin/fc flush --if eth0"})
	if _, err := os.Stat(filepath.Join(u.root, "tmp/udeco/loopguard")); !os.IsNotExist(err) {
		t.Errorf("record left behind: %v", err)
	}
}
