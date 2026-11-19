// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Tests for the start-up, self-protection, cfgversion, SSH, topology,
// user, schedule, steering and scan behaviour. Fakes only.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
	"github.com/antoniocosta/unifi-openwrt/internal/lldp"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// ------------------------------------------------------------ R6, R3, R7

func TestInstanceLockConcurrent(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var got []*instanceLock
	var refused int
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := acquireLock(dir)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.Is(err, errRunning):
				refused++
			case err != nil:
				t.Error(err)
			default:
				got = append(got, l)
			}
		}()
	}
	wg.Wait()
	if len(got) != 1 || refused != 3 {
		t.Fatalf("%d agents got the lock, %d refused", len(got), refused)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "udeco-ap.pid")); strings.TrimSpace(string(b)) != fmt.Sprint(os.Getpid()) {
		t.Errorf("pid file %q", b)
	}
	got[0].release()
	l, err := acquireLock(dir)
	if err != nil {
		t.Fatalf("lock not free after release: %v", err)
	}
	l.release()
}

func TestApplyLimits(t *testing.T) {
	defer debug.SetMemoryLimit(debug.SetMemoryLimit(-1))
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(0))
	proc := t.TempDir()
	os.MkdirAll(filepath.Join(proc, "self"), 0o755)
	adj := filepath.Join(proc, "self", "oom_score_adj")
	os.WriteFile(adj, []byte("0\n"), 0o644)
	msg := applyLimits(proc)
	if b, _ := os.ReadFile(adj); strings.TrimSpace(string(b)) != "300" {
		t.Errorf("oom_score_adj %q", b)
	}
	if debug.SetMemoryLimit(-1) != 48<<20 || runtime.GOMAXPROCS(0) > 3 {
		t.Errorf("limits: %s", msg)
	}
	if old := debug.SetGCPercent(50); old != 50 {
		t.Errorf("GOGC %d", old)
	}
	// a higher score is kept (never lowered)
	os.WriteFile(adj, []byte("800\n"), 0o644)
	applyLimits(proc)
	if b, _ := os.ReadFile(adj); strings.TrimSpace(string(b)) != "800" {
		t.Errorf("oom_score_adj lowered to %q", b)
	}
}

// A crash loop with takeover configured writes the persistent marker; the
// marker alone (after a reboot cleared the start log) still forces observe.
func TestStartGuardMarker(t *testing.T) {
	root := t.TempDir()
	openGate(t, root, "200.00 1.00")
	cfg := &Config{Takeover: true}
	var why string
	for i := range crashStarts {
		os.WriteFile(filepath.Join(root, "proc/uptime"), []byte(fmt.Sprintf("%d.00 1.00\n", 200+i)), 0o644)
		why = startGuard(cfg, root, "/tp_data/udeco", "/tmp/udeco", time.Now(), t.Logf)
	}
	if !strings.Contains(why, "crash loop") {
		t.Fatalf("no crash loop: %q", why)
	}
	marker := filepath.Join(root, "tp_data/udeco", observeMarker)
	if readMarker(marker) == "" {
		t.Fatal("no persistent marker")
	}
	os.RemoveAll(filepath.Join(root, "tmp/udeco")) // reboot: the run dir is RAM
	os.WriteFile(filepath.Join(root, "proc/uptime"), []byte("40.00 1.00\n"), 0o644)
	if why := startGuard(cfg, root, "/tp_data/udeco", "/tmp/udeco", time.Now(), t.Logf); !strings.Contains(why, "crash loop") {
		t.Fatalf("marker ignored after reboot: %q", why)
	}
	os.Remove(marker)
	if why := startGuard(cfg, root, "/tp_data/udeco", "/tmp/udeco", time.Now(), t.Logf); why != "" {
		t.Fatalf("still forced after the marker was removed: %q", why)
	}
}

// ------------------------------------------------------------ R1 gate

func TestGateStatus(t *testing.T) {
	for _, c := range []struct {
		name   string
		uptime string
		files  []string
		procs  map[string]string
		open   bool
	}{
		{"early", "60.0", gateFiles, nil, false},
		{"booted", "130.0", gateFiles, nil, true},
		{"wifi not done", "130.0", gateFiles[:1], nil, false},
		{"gave up waiting", "700.0", nil, nil, true},
		{"upgrade flag", "700.0", append(slices.Clone(gateFiles), "/tmp/firmware_upgrade_flag"), nil, false},
		{"upgrade dir", "700.0", append(slices.Clone(gateFiles), "/tmp/upgrade/fw.bin"), nil, false},
		{"flashing", "700.0", gateFiles, map[string]string{"77": "nvrammanager\x00-u\x00/tmp/fw\x00"}, false},
		{"fetching", "700.0", gateFiles, map[string]string{"78": "sshhttpget\x00x\x00"}, false},
		{"other process", "700.0", gateFiles, map[string]string{"79": "/usr/sbin/nvrammanager\x00-r\x00"}, true},
	} {
		root := t.TempDir()
		write := func(p, v string) {
			os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
			os.WriteFile(filepath.Join(root, p), []byte(v), 0o644)
		}
		write("/proc/uptime", c.uptime+" 1.0\n")
		for _, f := range c.files {
			write(f, "")
		}
		for pid, cl := range c.procs {
			write("/proc/"+pid+"/cmdline", cl)
		}
		if open, why := gateStatus(root); open != c.open {
			t.Errorf("%s: open=%v (%s)", c.name, open, why)
		}
	}
}

// R1/R2: nothing is informed and nothing is enforced before the gate opens;
// in takeover mode only the fence runs in phase 1 (and is re-asserted while
// the gate is closed).
func TestBootGateHoldsEverything(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	os.Remove(filepath.Join(h.root, "tmp/wifi_set_done"))
	os.WriteFile(filepath.Join(h.root, "proc/uptime"), []byte("90.00 1.00\n"), 0o644)
	h.start()
	time.Sleep(100 * time.Millisecond)
	calls := h.rec.list()
	if h.ctl.count() != 0 || h.built != 1 || len(calls) < 2 {
		t.Fatalf("before the gate: %d informs, calls %v, built %d", h.ctl.count(), calls, h.built)
	}
	for _, c := range calls {
		if c != "ingress:true" {
			t.Fatalf("before the gate: %q (only the fence may run)", c)
		}
	}
	os.WriteFile(filepath.Join(h.root, "proc/uptime"), []byte("130.00 1.00\n"), 0o644)
	os.WriteFile(filepath.Join(h.root, "tmp/wifi_set_done"), nil, 0o644)
	eventually(t, "inform after the gate", func() bool { return h.ctl.count() > 0 })
	eventually(t, "enforce after the gate", func() bool { return h.rec.index("enforce") >= 0 })
	h.stop()
	if !strings.Contains(h.logs.all(), "boot gate open") {
		t.Error("gate opening not logged")
	}
	b, _ := os.ReadFile(filepath.Join(h.root, "tp_data/udeco", eventsFile))
	if !strings.Contains(string(b), "boot gate open") {
		t.Errorf("event ring: %q", b)
	}
}

// R1: right after the gate Enforce runs every fastEnforce until two clean
// passes and fastMin, then every enforceEvery.
func TestFastEnforceAfterGate(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover = true
		o.t.fastEnforce, o.t.fastMin, o.t.enforceEvery = 5*time.Millisecond, 50*time.Millisecond, time.Hour
	})
	h.start()
	eventually(t, "steady", func() bool { return strings.Contains(h.logs.all(), "Enforce every 1h0m0s") })
	n := h.rec.count("enforce")
	time.Sleep(60 * time.Millisecond)
	h.stop()
	if n < 3 {
		t.Errorf("only %d fast Enforce passes", n)
	}
	if m := h.rec.count("enforce"); m > n+1 {
		t.Errorf("still fast after the steady state: %d -> %d", n, m)
	}
}

// ------------------------------------------------------------ R4, R13

func TestResources(t *testing.T) {
	root := t.TempDir()
	put := func(p, v string) {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(v), 0o644)
	}
	put("proc/self/status", "Name:\tudeco-ap\nVmRSS:\t   20480 kB\n")
	put("proc/meminfo", "MemTotal: 252000 kB\nMemAvailable:   93520 kB\n")
	put("tmp/a", strings.Repeat("x", 3<<10))
	put("etc/b", strings.Repeat("x", 2<<10))
	r, err := readResources(root)
	if err != nil || r.RSSKB != 20480 || r.AvailKB != 93520 || r.RAMfsKB != 5 {
		t.Fatalf("%+v %v", r, err)
	}
	for _, c := range []struct {
		r                resources
		base             int64
		shed, exit, alrm bool
	}{
		{resources{20000, 90000, 7000}, 7000, false, false, false},
		{resources{20000, 30000, 7000}, 7000, true, false, false},
		{resources{20000, 15000, 7000}, 7000, true, true, true},
		{resources{70000, 90000, 7000}, 7000, false, true, true},
		{resources{20000, 90000, 7000 + 9<<10}, 7000, false, false, true},
	} {
		shed, exit, alarm := resourceVerdict(c.r, c.base)
		if shed != c.shed || exit != c.exit || (alarm != "") != c.alrm {
			t.Errorf("%+v: shed %v exit %v alarm %q", c.r, shed, exit, alarm)
		}
	}
}

// R4: our RSS over the limit ends the agent (persist_shell restarts it).
func TestResourceExit(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { o.t.resourceEvery = 5 * time.Millisecond })
	os.MkdirAll(filepath.Join(h.root, "proc/self"), 0o755)
	os.WriteFile(filepath.Join(h.root, "proc/self/status"), []byte("VmRSS:\t 70000 kB\n"), 0o644)
	os.WriteFile(filepath.Join(h.root, "proc/meminfo"), []byte("MemAvailable: 90000 kB\n"), 0o644)
	done := make(chan error, 1)
	go func() { done <- h.a.run(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, errResources) {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent kept running over the RSS limit")
	}
}

// R4: low MemAvailable sheds scans; they run again once memory is back.
func TestResourceShedScans(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover = true; o.t.resourceEvery = 5 * time.Millisecond })
	os.MkdirAll(filepath.Join(h.root, "proc/self"), 0o755)
	os.WriteFile(filepath.Join(h.root, "proc/self/status"), []byte("VmRSS:\t 20000 kB\n"), 0o644)
	mem := filepath.Join(h.root, "proc/meminfo")
	os.WriteFile(mem, []byte("MemAvailable: 30000 kB\n"), 0o644)
	scan := `{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":80}`
	h.ctl.queue(adoptReply)
	h.start()
	eventually(t, "shedding", func() bool { return h.a.shed.Load() })
	h.ctl.queue(scan)
	eventually(t, "scan refused", func() bool { return strings.Contains(h.logs.all(), "skipped, memory is low") })
	if h.rec.index("spectrum:na") >= 0 {
		t.Fatal("scanned while shedding")
	}
	os.WriteFile(mem, []byte("MemAvailable: 90000 kB\n"), 0o644)
	eventually(t, "not shedding", func() bool { return !h.a.shed.Load() })
	h.ctl.queue(scan)
	eventually(t, "scan after recovery", func() bool { return h.rec.index("spectrum:na") >= 0 })
	h.stop()
}

func TestEventRingBounded(t *testing.T) {
	dir := t.TempDir()
	e := &eventLog{path: filepath.Join(dir, "events.log"), root: dir, clock: time.Now, logf: func(string, ...any) {}}
	for i := range 3000 {
		e.add(fmt.Sprintf("event %d %s", i, strings.Repeat("y", 40)))
	}
	b, _ := os.ReadFile(e.path)
	if len(b) > eventMax || !strings.Contains(string(b), "event 2999 ") || strings.Contains(string(b), "event 0 ") {
		t.Errorf("ring %d bytes", len(b))
	}
	// an unset clock is not written as a date
	e2 := &eventLog{path: filepath.Join(dir, "e2.log"), root: dir, logf: func(string, ...any) {},
		clock: func() time.Time { return time.Date(2025, 9, 12, 0, 0, 0, 0, time.UTC) }}
	e2.add("early")
	if b, _ := os.ReadFile(e2.path); !strings.HasPrefix(string(b), "unsynced ") {
		t.Errorf("unsynced clock: %q", b)
	}
}

// ------------------------------------------------------------ cfgversion

func cfgversionOf(m map[string]any) string { v, _ := m["cfgversion"].(string); return v }

// The cfgversion of a system_cfg is reported only after it is live; a
// failed apply keeps the previous one, and a resend is retried once with
// bcmwifi's failure memory cleared.
func TestCfgVersionAckAfterApply(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	eventually(t, "cfgversion c1 reported", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c1" })
	if h.rec.index("apply") < 0 {
		t.Fatal("acknowledged without an apply")
	}

	// a different system_cfg whose apply fails (still owned): c2 is never
	// reported
	h.wifi.mu.Lock()
	h.wifi.applyErr = errors.New("verify failed (rolled back)")
	h.wifi.mu.Unlock()
	cfg2 := testCfg + "wireless.1.hide_ssid=true\n"
	reply2 := strings.ReplaceAll(provisionReply(cfg2), "c1", "c2")
	h.ctl.queue(reply2)
	eventually(t, "failed apply", func() bool { return h.rec.count("apply") >= 2 })
	eventually(t, "a few more informs", func() bool { return h.ctl.pending() == 0 })
	time.Sleep(50 * time.Millisecond)
	if v := cfgversionOf(h.ctl.last()); v != "00000000000000c1" {
		t.Fatalf("failed apply acknowledged: %s", v)
	}
	// the controller sends it again: retried once (bcmwifi forgets the
	// failure first), and it works this time
	h.wifi.mu.Lock()
	h.wifi.applyErr = nil
	h.wifi.mu.Unlock()
	h.ctl.queue(reply2)
	eventually(t, "c2 reported after the retry", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c2" })
	h.stop()
	if i, j := h.rec.index("forget-failed"), slices.Index(h.rec.list()[h.rec.index("forget-failed")+1:], "apply"); i < 0 || j < 0 {
		t.Errorf("no ForgetFailed before the retry: %v", h.rec.list())
	}
}

// Observe mode acknowledges after logging the plan.
func TestCfgVersionAckObserve(t *testing.T) {
	h := newHarness(t, nil)
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	eventually(t, "c1 reported", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c1" })
	h.stop()
	if !strings.Contains(h.logs.all(), "logged only") {
		t.Error("plan not logged")
	}
}

// ------------------------------------------------------------ SSH (R12)

// testUserHash is the SHA-crypt specification's example hash of the
// made-up password "Hello world!" (not a real credential).
const testUserHash = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"

var usersCfg = testCfg + "users.status=enabled\nusers.1.status=enabled\nusers.1.name=siteadmin\nusers.1.password=" + testUserHash + "\n"

func sshRun(t *testing.T, port int, user, pw, cmd string) error {
	t.Helper()
	c, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &ssh.ClientConfig{User: user,
		Auth: []ssh.AuthMethod{ssh.Password(pw)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Run(cmd)
}

func TestSSHAdoptNeedsSiteCredentialOnceAdopted(t *testing.T) {
	h := newHarness(t, nil)
	h.ctl.queue(adoptReply)
	h.start()
	eventually(t, "adopted", func() bool { return h.ctl.pending() == 0 && h.ctl.count() > 2 })
	// adopted, no system_cfg (no site user) yet: refused
	setInform := "/usr/bin/syswrapper.sh set-inform http://192.0.2.99:8080/inform"
	if err := sshRun(t, h.cfg.SSHDPort, "ubnt", "ubnt", setInform); err == nil {
		t.Fatal("factory login accepted once adopted")
	}
	h.ctl.queue(provisionReply(usersCfg))
	eventually(t, "provisioned", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c1" })
	if err := sshRun(t, h.cfg.SSHDPort, "siteadmin", "wrong", setInform); err == nil {
		t.Fatal("wrong password accepted")
	}
	if err := sshRun(t, h.cfg.SSHDPort, "siteadmin", "Hello world!", setInform); err != nil {
		t.Fatalf("site credential refused: %v", err)
	}
	eventually(t, "set-inform applied", func() bool { return strings.Contains(h.logs.all(), "set-inform: inform_url=http://192.0.2.99") })
	h.stop()
	if strings.Contains(h.logs.all(), "Hello world!") || strings.Contains(h.logs.all(), testUserHash) {
		t.Error("a password or hash was logged")
	}
}

// ------------------------------------------------------------ users

func TestSyncUserFiles(t *testing.T) {
	dir := t.TempDir()
	pw, sh := filepath.Join(dir, "passwd"), filepath.Join(dir, "shadow")
	os.WriteFile(pw, []byte("root:x:0:0:root:/root:/bin/ash\ndaemon:*:1:1:daemon:/var:/bin/false\nold:x:0:0:"+userGECOS+":/root:/bin/ash\n"), 0o777)
	os.WriteFile(sh, []byte("root:$1$x$y:17603:0:99999:7:::\ndaemon:*:0:0:99999:7:::\nold:$6$a$b:1:0:99999:7:::\n"), 0o777)
	os.Chmod(pw, 0o777) // as on the unit (WriteFile's mode is masked by umask)
	os.Chmod(sh, 0o777)
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	want := []translate.User{{Name: "siteadmin", Hash: "$6$s$h"}, {Name: "root", Hash: "$6$s$evil"}, {Name: "daemon", Hash: "$6$s$x"}}
	changes, skipped, err := syncUserFiles(pw, sh, want, now)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := os.ReadFile(pw)
	s, _ := os.ReadFile(sh)
	if !strings.Contains(string(p), "root:x:0:0:root:/root:/bin/ash\n") || !strings.Contains(string(s), "root:$1$x$y:17603") ||
		!strings.Contains(string(p), "daemon:*:1:1") || strings.Contains(string(p), "old:") || strings.Contains(string(s), "old:") ||
		!strings.Contains(string(p), "siteadmin:x:0:0:"+userGECOS+":/root:/bin/ash") || !strings.Contains(string(s), "siteadmin:$6$s$h:20775:0:99999:7:::") {
		t.Fatalf("passwd:\n%s\nshadow:\n%s", p, s)
	}
	if len(changes) != 2 || len(skipped) != 2 {
		t.Errorf("changes %v skipped %v", changes, skipped)
	}
	if fi, _ := os.Stat(sh); fi.Mode().Perm() != 0o777 {
		t.Errorf("mode changed to %v", fi.Mode().Perm())
	}
	// unchanged: nothing written; a new hash: updated in place
	before, _ := os.Stat(sh)
	if c, _, _ := syncUserFiles(pw, sh, want, now); c != nil {
		t.Errorf("second run changed %v", c)
	}
	if after, _ := os.Stat(sh); !after.ModTime().Equal(before.ModTime()) {
		t.Error("rewritten without a change")
	}
	syncUserFiles(pw, sh, []translate.User{{Name: "siteadmin", Hash: "$6$s$new"}}, now)
	if s, _ := os.ReadFile(sh); !strings.Contains(string(s), "siteadmin:$6$s$new:") || strings.Count(string(s), "siteadmin") != 1 {
		t.Errorf("shadow after change:\n%s", s)
	}
	syncUserFiles(pw, sh, nil, now)
	if p, _ := os.ReadFile(pw); strings.Contains(string(p), "siteadmin") || !strings.Contains(string(p), "root:") {
		t.Errorf("passwd after removal:\n%s", p)
	}
}

func TestProvisionInstallsSiteUsers(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	os.MkdirAll(filepath.Join(h.root, "etc"), 0o755)
	os.WriteFile(filepath.Join(h.root, "etc/passwd"), []byte("root:x:0:0:root:/root:/bin/ash\n"), 0o644)
	os.WriteFile(filepath.Join(h.root, "etc/shadow"), []byte("root:$1$x$y:17603:0:99999:7:::\n"), 0o600)
	h.ctl.queue(adoptReply, provisionReply(usersCfg))
	h.start()
	eventually(t, "site user", func() bool {
		b, _ := os.ReadFile(filepath.Join(h.root, "etc/shadow"))
		return strings.Contains(string(b), "siteadmin:"+testUserHash)
	})
	h.stop()
}

// ------------------------------------------------------------ topology

// fakeLLDP is an lldp.Conn per port: queued frames in, frames out recorded.
type fakeLLDP struct {
	mu  sync.Mutex
	in  map[string][][]byte
	out map[string][][]byte
}

type fakeLLDPConn struct {
	f    *fakeLLDP
	port string
}

func (c fakeLLDPConn) Recv(b []byte) (int, error) {
	c.f.mu.Lock()
	q := c.f.in[c.port]
	if len(q) == 0 {
		c.f.mu.Unlock()
		time.Sleep(time.Millisecond)
		return 0, lldp.ErrTimeout
	}
	c.f.in[c.port] = q[1:]
	c.f.mu.Unlock()
	return copy(b, q[0]), nil
}

func (c fakeLLDPConn) Send(f []byte) error {
	c.f.mu.Lock()
	c.f.out[c.port] = append(c.f.out[c.port], f)
	c.f.mu.Unlock()
	return nil
}

func (c fakeLLDPConn) Close() error { return nil }

func (f *fakeLLDP) push(port string, frame []byte) {
	f.mu.Lock()
	f.in[port] = append(f.in[port], frame)
	f.mu.Unlock()
}

func (f *fakeLLDP) sent(port string) [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.out[port])
}

// gatewayLLDP is the gateway's LLDPDU (chassis subtype local, as the UCG
// sends it; management address 192.168.0.1).
func gatewayLLDP(t *testing.T) []byte {
	t.Helper()
	gw, _ := net.ParseMAC(gwMAC)
	f, err := lldp.Encode(gw, lldp.Info{ChassisMAC: gw, PortID: "eth3", TTL: 120, SysName: "UCG",
		MgmtIPv4: net.ParseIP("192.168.0.1"), Caps: lldp.CapRouter | lldp.CapBridge})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func withLLDP(f *fakeLLDP) func(*Config, *options) {
	return func(c *Config, o *options) {
		o.noLLDP = false
		o.lldpOpen = func(p string) (lldp.Conn, error) { return fakeLLDPConn{f, p}, nil }
		o.t.lldpEvery = 5 * time.Millisecond
	}
}

func TestTopologyInformFields(t *testing.T) {
	f := &fakeLLDP{in: map[string][][]byte{}, out: map[string][][]byte{}}
	h := newHarness(t, withLLDP(f))
	f.push("eth1", gatewayLLDP(t))
	os.MkdirAll(filepath.Join(h.root, "sys/class/net/eth1"), 0o755)
	os.WriteFile(filepath.Join(h.root, "sys/class/net/eth1/ifindex"), []byte("9\n"), 0o644)
	h.start()
	eventually(t, "lldp_table", func() bool { l, _ := h.ctl.last()["lldp_table"].([]any); return len(l) == 1 })
	eventually(t, "announced", func() bool { return len(f.sent("eth1")) > 1 })
	h.stop()
	m := h.ctl.last()
	row := m["lldp_table"].([]any)[0].(map[string]any)
	if row["chassis_id"] != gwMAC || row["chassis_id_subtype"] != "mac" || row["is_wired"] != true || num(row["local_port_idx"]) != 1 ||
		row["local_port_name"] != "eth0" || row["port_id"] != "eth3" || fmt.Sprint(row["mgmt_ips"]) != "[192.168.0.1]" {
		t.Errorf("lldp row %v", row)
	}
	it, _ := m["if_table"].([]any)
	if len(it) != 1 {
		t.Fatalf("if_table %v", m["if_table"])
	}
	e := it[0].(map[string]any)
	if e["name"] != "eth0" || e["up"] != true || num(e["speed"]) != 1000 || num(e["num_port"]) != 1 {
		t.Errorf("if_table row %v", e)
	}
	if m["uplink"] != "eth0" || m["gateway_mac"] != gwMAC || m["port_table"] != nil || m["has_eth1"] != false {
		t.Errorf("uplink %v gateway_mac %v port_table %v has_eth1 %v", m["uplink"], m["gateway_mac"], m["port_table"], m["has_eth1"])
	}
	if len(f.sent("eth0")) != 0 {
		t.Error("announced on the non-uplink port")
	}
	n, err := lldp.Decode(f.sent("eth1")[0])
	if err != nil || n.ChassisID != unitMAC || n.ChassisIDSubtype != lldp.ChassisMAC || n.PortID != "eth0" || n.TTL != 120 ||
		n.SysName != "deco-205" || n.CapsOn != lldp.CapBridge|lldp.CapWLANAP || fmt.Sprint(n.MgmtIPs) != "[192.168.0.205]" ||
		!strings.Contains(n.SysDescr, "U6-Lite") {
		t.Errorf("announced %+v %v", n, err)
	}
}

// twoPorts is testSnapshot with both Ethernet ports up and in br-lan.
func twoPorts(eth0Up bool, eth0Bridged bool) *apstate.Snapshot {
	s := testSnapshot()
	bp := 0
	if eth0Bridged {
		bp = 1
	}
	s.Ports[0] = apstate.Port{Name: "eth0", MAC: unitMAC, Up: eth0Up, Speed: 1000, FullDuplex: true, BridgePort: bp}
	return s
}

// R9: the gateway heard on both ports takes the non-uplink port out of
// br-lan; it comes back when it loses carrier.
func TestLoopGuard(t *testing.T) {
	f := &fakeLLDP{in: map[string][][]byte{}, out: map[string][][]byte{}}
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover = true
		withLLDP(f)(c, o)
	})
	var mu sync.Mutex
	up, bridged := true, true
	h.col.snap = func() *apstate.Snapshot { mu.Lock(); defer mu.Unlock(); return twoPorts(up, bridged) }
	f.push("eth1", gatewayLLDP(t))
	f.push("eth0", gatewayLLDP(t))
	h.start()
	eventually(t, "delif", func() bool { return h.rec.index("run:brctl delif br-lan eth0") >= 0 })
	eventually(t, "fc flush", func() bool { return h.rec.index("flush:eth0") >= 0 })
	if d, f := h.rec.index("run:brctl delif br-lan eth0"), h.rec.index("flush:eth0"); f < d {
		t.Errorf("flows flushed (%d) before the delif (%d)", f, d)
	}
	mu.Lock()
	bridged = false // out of br-lan now
	mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	if n := h.rec.count("run:brctl delif br-lan eth0"); n != 1 {
		t.Errorf("delif %d times", n)
	}
	mu.Lock()
	up = false // cable pulled
	mu.Unlock()
	eventually(t, "addif", func() bool { return h.rec.index("run:brctl addif br-lan eth0") >= 0 })
	eventually(t, "flush after addif", func() bool { return h.rec.count("flush:eth0") >= 2 })
	h.stop()
	if !strings.Contains(h.logs.all(), "LOOP GUARD") {
		t.Error("no loud log")
	}
	b, _ := os.ReadFile(filepath.Join(h.root, "tp_data/udeco", eventsFile))
	if !strings.Contains(string(b), "LOOP GUARD") || !strings.Contains(string(b), "back into br-lan") {
		t.Errorf("events: %s", b)
	}
}

// Observe mode only logs a loop (here seen through the gateway's MAC
// learned on both ports).
func TestLoopGuardObserve(t *testing.T) {
	h := newHarness(t, nil)
	var mu sync.Mutex
	port := 2
	h.col.snap = func() *apstate.Snapshot {
		mu.Lock()
		defer mu.Unlock()
		s := twoPorts(true, true)
		s.FDB[0].Port = port
		port = 3 - port // the gateway's MAC flaps between eth0 (1) and eth1 (2)
		return s
	}
	h.start()
	eventually(t, "loop logged", func() bool { return strings.Contains(h.logs.all(), "LOOP: the gateway's MAC was learned on both") })
	h.stop()
	for _, c := range h.rec.list() {
		t.Errorf("observe mode changed the unit: %s", c)
	}
}

// ------------------------------------------------------------ R8a, R10, R11

// R8a and R11 are decosys's (its address watch and reset-button wrapper run
// inside Enforce): the agent hands it the lease and gateway from every
// reading, follows a lease change, and leaves the hand-back of the reset
// handler to decosys.Restore.
func TestDecosysGetsLAN(t *testing.T) {
	var mu sync.Mutex
	ip := "192.168.0.205"
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover = true
		c.MgmtSources = []string{"192.168.1.0/24"}
	})
	h.col.snap = func() *apstate.Snapshot {
		mu.Lock()
		defer mu.Unlock()
		s := testSnapshot()
		s.IP = ip
		return s
	}
	h.start()
	eventually(t, "LAN handed to decosys", func() bool { return h.rec.index("setlan:192.168.0.1,192.168.0.0/24,192.168.0.205") >= 0 })
	if i, e := h.rec.index("setlan:192.168.0.1,192.168.0.0/24,192.168.0.205"), h.rec.index("enforce"); e >= 0 && e < i {
		t.Errorf("Enforce (%d) before decosys knew the lease (%d)", e, i)
	}
	mu.Lock()
	ip = "192.168.0.77" // a new lease
	mu.Unlock()
	eventually(t, "new lease handed over", func() bool { return h.rec.index("setlan:192.168.0.1,192.168.0.0/24,192.168.0.77") >= 0 })
	h.stop()
	if !slices.Equal(h.sopts.MgmtSources, []string{"192.168.1.0/24"}) || h.sopts.ConsoleIP != "127.0.0.1" || h.sopts.SSHDPort != h.cfg.SSHDPort ||
		h.sopts.LANCIDR != "" || h.sopts.UnitIP != "" {
		t.Errorf("phase-1 decosys options %+v", h.sopts)
	}
	b, _ := os.ReadFile(filepath.Join(h.root, "tp_data/udeco", eventsFile))
	if !strings.Contains(string(b), "address changed from 192.168.0.205 to 192.168.0.77") {
		t.Errorf("lease change not in the event ring: %q", b)
	}
	for _, c := range h.rec.list() {
		if strings.Contains(c, "ip addr del") || strings.Contains(c, "rc.button") {
			t.Errorf("the agent did decosys's R8a/R11 work itself: %s", c)
		}
	}
}

// R10: decosys's findings are logged as they come, the loud ones reach
// the event ring at most once an hour, bcmwifi.Tick runs on owned Wi-Fi,
// and the self-check summary carries both packages' counts.
func TestSelfCheck(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		o.t.enforceEvery, o.t.fastEnforce, o.t.selfCheck = 5*time.Millisecond, 5*time.Millisecond, time.Millisecond
	})
	h.sys.report = decosys.Report{Foreign: []decosys.Finding{
		{Kind: decosys.KindAddr, Detail: "br-lan 192.168.0.1/22: the gateway's own address", Fixed: true},
		{Kind: decosys.KindStop, Detail: "tmpsvr: TP-Link management", Fixed: true},
	}}
	h.sys.counts = map[string]int{"addr": 3, "stop": 1, "ingress": 2}
	h.wifi.tick = bcmwifi.TickReport{Foreign: []string{"wl02 macmode 1 (TP-Link)"}, Steps: 1}
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	eventually(t, "bcmwifi tick on owned Wi-Fi", func() bool { return h.rec.index("tick") >= 0 })
	eventually(t, "summary", func() bool {
		return strings.Contains(h.logs.all(), "self-check: foreign state since start: addr=3 ingress=2 stop=1 wifi-foreign=")
	})
	h.stop()
	logs := h.logs.all()
	if !strings.Contains(logs, "decosys: foreign: addr: br-lan 192.168.0.1/22") || !strings.Contains(logs, "decosys: foreign: stop: tmpsvr") {
		t.Error("findings not logged")
	}
	if i, a := h.rec.index("tick"), h.rec.index("apply"); i < a {
		t.Errorf("bcmwifi Tick (%d) before the Wi-Fi was applied (%d)", i, a)
	}
	b, _ := os.ReadFile(filepath.Join(h.root, "tp_data/udeco", eventsFile))
	if n := strings.Count(string(b), "FOREIGN STATE: addr"); n != 1 {
		t.Errorf("the address finding reached the event ring %d times (want once an hour)", n)
	}
	if strings.Contains(string(b), "FOREIGN STATE: stop") {
		t.Error("a re-stopped service is not an event-ring event")
	}
	if h.rec.count("invalidate") == 0 {
		t.Error("a bcmwifi repair did not invalidate the collector")
	}
}

// R17: an upgrade in flight (decosys Report.Guard) holds every Wi-Fi
// change: no apply, no bcmwifi Tick, no health check.
func TestUpgradeHoldsWifi(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		o.t.enforceEvery, o.t.fastEnforce = 5*time.Millisecond, 5*time.Millisecond
	})
	h.sys.report = decosys.Report{Guard: decosys.Guard{Upgrade: []string{"/tmp/firmware_upgrade_flag"}}}
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	eventually(t, "the provision waits", func() bool { return strings.Contains(h.logs.all(), "waits for decosys.Enforce") })
	time.Sleep(30 * time.Millisecond)
	for _, c := range []string{"plan", "apply", "tick", "verify"} {
		if h.rec.index(c) >= 0 {
			t.Fatalf("%s during an upgrade", c)
		}
	}
	h.sys.mu.Lock()
	h.sys.report = decosys.Report{}
	h.sys.mu.Unlock()
	eventually(t, "apply after the upgrade", func() bool { return h.rec.index("apply") >= 0 })
	h.stop()
	if !strings.Contains(h.logs.all(), "firmware upgrade is in flight") {
		t.Error("hold not logged")
	}
}

// holdReason: a rebuild or an upgrade holds Wi-Fi changes; the boot chain
// only while the unit is plausibly still booting.
func TestHoldReason(t *testing.T) {
	for _, c := range []struct {
		rep  decosys.Report
		up   float64
		hold bool
	}{
		{decosys.Report{}, 900, false},
		{decosys.Report{Guard: decosys.Guard{Rebuild: []string{"pid 9: repacd"}}}, 900, true},
		{decosys.Report{Guard: decosys.Guard{Upgrade: []string{"x"}}}, 9000, true},
		{decosys.Report{Guard: decosys.Guard{Boot: []string{"pid 9: S99zzz"}}}, 300, true},
		{decosys.Report{Guard: decosys.Guard{Boot: []string{"pid 9: S99zzz"}}}, 900, false}, // a boot script that never ends
		{decosys.Report{Warnings: []string{decosys.WarnRebuild + " (x)"}}, 900, true},
	} {
		if got := holdReason(c.rep, c.up) != ""; got != c.hold {
			t.Errorf("%+v at %.0f s: hold %v", c.rep, c.up, got)
		}
	}
}

// ------------------------------------------------------------ scans

func TestU6ScanRows(t *testing.T) {
	rows := u6ScanRows([]map[string]any{{"signal": -70, "age": 15, "is_unifi": false}, {"signal": -50, "age": 2, "is_unifi": true, "serialno": "x"}}, -96)
	if rows[0]["rssi"] != 26 || rows[0]["noise"] != -96 || rows[0]["rssi_age"] != 150 || rows[0]["is_ubnt"] != false || rows[0]["ap_name"] != "" {
		t.Errorf("row 0 %v", rows[0])
	}
	if rows[1]["is_ubnt"] != true || rows[1]["is_unifi"] != true || rows[1]["serialno"] != "x" {
		t.Errorf("row 1 %v", rows[1])
	}
	// unknown noise floor: -95, the old signal + 95
	if r := u6ScanRows([]map[string]any{{"signal": -100, "age": 0}}, 0); r[0]["rssi"] != 0 || r[0]["noise"] != -95 {
		t.Errorf("clamp %v", r[0])
	}
}

// ------------------------------------------------------------ schedules

func TestScheduleOn(t *testing.T) {
	mon := time.Date(2026, 11, 16, 0, 0, 0, 0, time.Local) // a Monday
	w := []string{"mon 0800-1730", "tue 0000-2400"}
	for _, c := range []struct {
		at time.Time
		on bool
	}{
		{mon.Add(7*time.Hour + 59*time.Minute), false},
		{mon.Add(8 * time.Hour), true},
		{mon.Add(17*time.Hour + 29*time.Minute), true},
		{mon.Add(17*time.Hour + 30*time.Minute), false},
		{mon.Add(24*time.Hour + 23*time.Hour + 59*time.Minute), true},
		{mon.Add(48 * time.Hour), false},
	} {
		if got := scheduleOn(w, c.at); got != c.on {
			t.Errorf("%s: %v", c.at.Format("Mon 15:04"), got)
		}
	}
}

// A scheduled WLAN that is off now is applied disabled; when its window
// opens the worker applies it enabled.
func TestScheduleSwitchesSSID(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 11, 16, 7, 58, 0, 0, time.Local) // Monday 07:58
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		o.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
		o.t.scheduleEvery = 5 * time.Millisecond
	})
	sched := testCfg + "wireless.1.schedule_enabled=enabled\nwireless.1.schedule_mon.1=0800-1700\n"
	h.ctl.queue(adoptReply, provisionReply(sched))
	h.start()
	enabled := func(i int) (bool, bool) {
		h.wifi.mu.Lock()
		defer h.wifi.mu.Unlock()
		if len(h.wifi.desired) <= i || len(h.wifi.desired[i].SSIDs) == 0 {
			return false, false
		}
		return h.wifi.desired[i].SSIDs[0].Enabled, true
	}
	eventually(t, "first plan", func() bool { _, ok := enabled(0); return ok })
	if on, _ := enabled(0); on {
		t.Fatal("applied enabled outside its window")
	}
	mu.Lock()
	now = now.Add(3 * time.Minute)
	mu.Unlock()
	eventually(t, "re-plan in the window", func() bool { on, ok := enabled(1); return ok && on })
	h.stop()
}

// ------------------------------------------------------------ steering

// steerWifi is fakeWifi with bcmwifi's steering primitive.
type steerWifi struct{ *fakeWifi }

func (w steerWifi) SteerToBand(ctx context.Context, vif, mac, bssid string) error {
	w.rec.add(fmt.Sprintf("steer:%s@%s->%s", mac, vif, bssid))
	return nil
}

var steerCfg = "radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght20\nradio.2.phyname=wifi1\nradio.2.ieee_mode=11acvht80\n" +
	"wireless.1.ssid=net\nwireless.1.id=w1\nwireless.1.parent=wifi1\nwireless.1.devname=wifi1ap1\n" +
	"wireless.2.ssid=net\nwireless.2.id=w1\nwireless.2.parent=wifi0\nwireless.2.devname=wifi0ap1\n" +
	"aaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\naaa.1.wpa.psk=" + fakePSK + "\n" +
	"aaa.2.wpa=2\naaa.2.wpa.key.1.mgmt=WPA-PSK\naaa.2.wpa.psk=" + fakePSK + "\n" +
	"bandsteering.status=enabled\nbandsteering.mode=prefer_5g\nbandsteering.1.status=enabled\n" +
	"bandsteering.1.vap.1.devname=wifi0ap1\nbandsteering.1.vap.2.devname=wifi1ap1\n"

func TestBandSteering(t *testing.T) {
	var mu sync.Mutex
	on5 := true
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	sw := steerWifi{h.wifi}
	h.a.o.newWifi = func(bcmwifi.Options) wifiApplier { h.built++; return sw }
	sta := apstate.Station{MAC: staMAC, Signal: -50}
	h.col.snap = func() *apstate.Snapshot {
		mu.Lock()
		defer mu.Unlock()
		s := testSnapshot()
		s.Radios[1].VAPs[0].Stations = nil
		ng := apstate.Radio{Iface: "wl02", Band: "ng", SSID: "net", BSSID: "b2:a7:b9:00:00:02"}
		if on5 {
			s.Radios[1].VAPs[0].Stations = []apstate.Station{sta} // first seen on 5 GHz: dual-band
		} else {
			ng.Stations = []apstate.Station{sta}
		}
		s.Radios[0].VAPs = []apstate.Radio{ng}
		return s
	}
	h.ctl.queue(adoptReply, provisionReply(steerCfg))
	h.start()
	eventually(t, "provisioned", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c1" })
	if int(num(h.ctl.last()["wifi_caps"]))&4 == 0 {
		t.Error("BANDSTEER not claimed with a steering backend")
	}
	mu.Lock()
	on5 = false // now on 2.4 GHz with a strong signal
	mu.Unlock()
	want := "steer:" + staMAC + "@wl02->b2:a7:b9:00:00:07"
	eventually(t, "steering request", func() bool { return h.rec.index(want) >= 0 })
	time.Sleep(50 * time.Millisecond) // more readings: rate-limited
	h.stop()
	if n := h.rec.count(want); n != 1 {
		t.Errorf("%d steering requests (want 1 per %s)", n, steerEvery)
	}
}

// Without band steering from the controller nothing is steered, and the
// bit is not claimed without a steering backend.
func TestNoSteeringWithoutController(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	eventually(t, "provisioned", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c1" })
	h.stop()
	if int(num(h.ctl.last()["wifi_caps"]))&4 != 0 {
		t.Error("BANDSTEER claimed without a steering backend")
	}
	for _, c := range h.rec.list() {
		if strings.HasPrefix(c, "steer:") {
			t.Errorf("steered: %s", c)
		}
	}
}
