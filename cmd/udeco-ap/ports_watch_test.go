// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is the agent's clock (options.now) under the test's control.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// portsRig is an agent with the port manager on a fake unit and a fake
// clock; the test plays the controller (informed) and the worker (jobs).
type portsRig struct {
	t    *testing.T
	a    *agent
	pw   *portsWifi
	clk  *fakeClock
	logs *logBuf
	ctx  context.Context
}

func newPortsRig(t *testing.T, mod func(*Config)) *portsRig {
	r := &portsRig{t: t, clk: newFakeClock(), logs: &logBuf{}, ctx: context.Background()}
	r.pw = newPortsWifi(&fakeWifi{rec: &recorder{}})
	r.pw.br["eth0.1.1"] = "br-v9" // the tenant's router: locked, wherever it is
	r.pw.br["eth0.4.3"] = "br-v3" // a VLAN SSID's device on the uplink
	cfg := &Config{InformURL: "http://192.168.0.1:8080/inform", ConsoleIP: "192.168.0.1", SSHDPort: 2222, Log: "stderr",
		Platform: PlatformJio, Model: "UHDIW", Takeover: true, Apply: true}
	if mod != nil {
		mod(cfg)
	}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	o := options{root: root, base: "/flash2/udeco", logf: r.logs.logf, now: r.clk.now}
	o.t.fill()
	a := &agent{cfg: cfg, o: o, t: o.t, jobs: make(chan job, 32), topo: newTopology(), wifi: r.pw}
	a.events = &eventLog{path: filepath.Join(root, "flash2/udeco", eventsFile), root: root, clock: r.clk.now, logf: r.logs.logf}
	a.takeover.Store(true)
	a.topo.uplinkName.Store("eth0.4.1")
	if !a.portsSetup() {
		t.Fatal("ports not set up")
	}
	r.a = a
	return r
}

// provision hands a system_cfg's switch section to the ports, as a
// provision job does after the Wi-Fi.
func (r *portsRig) provision(cfg string) {
	r.a.portsPrepare(provision{systemCfg: cfg})
	r.a.portsApply(r.ctx, "system_cfg")
}

// inform is an inform that started at start and got a valid reply; the
// jobs it submits run.
func (r *portsRig) inform(start time.Time) {
	r.a.portsInformed(start)
	r.jobs()
}

func (r *portsRig) jobs() {
	for {
		select {
		case j := <-r.a.jobs:
			j.fn(r.ctx)
		default:
			return
		}
	}
}

// after moves the clock on by d and runs a pass of the port monitor.
func (r *portsRig) after(d time.Duration) {
	r.clk.add(d)
	r.a.portsWatch(r.ctx)
}

func (r *portsRig) events() string {
	b, _ := os.ReadFile(filepath.Join(r.a.o.root, "flash2/udeco", eventsFile))
	return string(b)
}

// live is ports 2 and 3 as switchCfg makes them: port 2 native VLAN 2,
// port 3 tagged 2 and 3.
func (r *portsRig) live() bool {
	return r.pw.BridgeOf("eth0.2.1") == "br-v2" && r.pw.BridgeOf("eth0.3.2") == "br-v2" && r.pw.BridgeOf("eth0.3.3") == "br-v3"
}

// onLAN: ports 2 and 3 on the plain LAN, no tagged VLANs.
func (r *portsRig) onLAN() bool {
	return r.pw.BridgeOf("eth0.2.1") == "bdg2" && r.pw.BridgeOf("eth0.3.1") == "bdg2" &&
		!r.pw.Exists("eth0.2.2") && !r.pw.Exists("eth0.3.2") && !r.pw.Exists("eth0.3.3")
}

// untouched: the locked port 1 and the uplink are as the rig made them.
func (r *portsRig) untouched() {
	r.t.Helper()
	if r.pw.BridgeOf("eth0.1.1") != "br-v9" || r.pw.BridgeOf("eth0.4.1") != "bdg2" || r.pw.BridgeOf("eth0.4.3") != "br-v3" {
		r.t.Errorf("port 1 or the uplink changed: %v", r.pw.br)
	}
	for _, op := range r.pw.opsList() {
		if strings.Contains(op, "eth0.1.") || strings.Contains(op, "eth0.4.") {
			r.t.Errorf("touched: %s", op)
		}
	}
}

// switchCfg3: port 2 native VLAN 3 instead of 2 (another setting).
var switchCfg3 = strings.NewReplacer("switch.port.2.pvid=2", "switch.port.2.pvid=3",
	"switch.vlan.2.port.2.mode=untagged\nswitch.vlan.3.port.2.mode=exclude",
	"switch.vlan.2.port.2.mode=exclude\nswitch.vlan.3.port.2.mode=untagged").Replace(switchCfg)

// TestPortsConfirmed: a change is confirmed by an inform that started
// after it; one that started before (or as it finished) confirms nothing.
func TestPortsConfirmed(t *testing.T) {
	r := newPortsRig(t, nil)
	t0 := r.clk.now()
	r.inform(t0)
	r.provision(switchCfg)
	if !r.live() {
		t.Fatalf("not applied: %v", r.pw.br)
	}
	r.after(10 * time.Second)
	r.inform(t0) // started before the change finished: no confirmation
	r.after(80 * time.Second)
	if !r.onLAN() {
		t.Fatalf("not reverted at 90 s after an inform that started before the change: %v", r.pw.br)
	}

	r = newPortsRig(t, nil)
	r.inform(r.clk.now())
	r.provision(switchCfg)
	r.clk.add(time.Second)
	r.inform(r.clk.now())
	r.after(4 * time.Minute) // past the confirm window, short of the loss window
	if !r.live() || strings.Contains(r.logs.all(), "PORTS REVERTED") {
		t.Errorf("a confirmed change reverted: %v\n%s", r.pw.br, r.logs.all())
	}
	if !strings.Contains(r.logs.all(), "ports: port 2: native VLAN 2 confirmed") {
		t.Errorf("no confirmation logged:\n%s", r.logs.all())
	}
	r.untouched()
}

// TestPortsRevertedUnconfirmed: no inform within 90 s: the ports of the
// change go back to what they were, an EVENT goes to the ring on flash,
// and the reverted settings are not applied again until the controller
// sends another one.
func TestPortsRevertedUnconfirmed(t *testing.T) {
	r := newPortsRig(t, nil)
	r.inform(r.clk.now())
	r.provision(switchCfg)
	r.after(89 * time.Second)
	if !r.live() {
		t.Fatalf("reverted before 90 s: %v", r.pw.br)
	}
	r.after(time.Second)
	if !r.onLAN() {
		t.Fatalf("not reverted at 90 s: %v", r.pw.br)
	}
	logs := r.logs.all()
	if !strings.Contains(logs, "EVENT: PORTS REVERTED (no inform reached the controller within 1m30s of the change): port 2 native VLAN 2 -> native LAN, port 3 native LAN, tagged 2,3 -> native LAN") {
		t.Errorf("event line:\n%s", logs)
	}
	if !strings.Contains(r.events(), "PORTS REVERTED") {
		t.Errorf("events.log: %q", r.events())
	}
	// the controller answers again and sends the same settings: not applied
	r.clk.add(time.Second)
	r.inform(r.clk.now())
	ops := len(r.pw.opsList())
	r.provision(switchCfg)
	r.a.portsApply(r.ctx, "tick")
	if !r.onLAN() || len(r.pw.opsList()) != ops {
		t.Fatalf("reverted settings re-applied: %q", r.pw.opsList()[ops:])
	}
	if !strings.Contains(r.logs.all(), "port 2: native VLAN 2 failed to apply before (or was reverted)") {
		t.Errorf("no not-retried note:\n%s", r.logs.all())
	}
	// another setting for port 2: applied (port 3's is still the reverted one)
	r.provision(switchCfg3)
	if r.pw.BridgeOf("eth0.2.1") != "br-v3" || r.pw.Exists("eth0.3.2") {
		t.Errorf("new setting: %v", r.pw.br)
	}
	r.untouched()
}

// TestPortsRevertToPrevious: a port changed from one VLAN to another goes
// back to the first, not to the LAN.
func TestPortsRevertToPrevious(t *testing.T) {
	r := newPortsRig(t, nil)
	r.inform(r.clk.now())
	r.provision(switchCfg)
	r.clk.add(time.Second)
	r.inform(r.clk.now())
	r.provision(switchCfg3)
	if r.pw.BridgeOf("eth0.2.1") != "br-v3" {
		t.Fatalf("port 2 %q", r.pw.BridgeOf("eth0.2.1"))
	}
	r.after(90 * time.Second)
	if !r.live() || !strings.Contains(r.logs.all(), "port 2 native VLAN 3 -> native VLAN 2") {
		t.Fatalf("not back on VLAN 2: %v\n%s", r.pw.br, r.logs.all())
	}
	// then the controller is lost: every port on the LAN, and the
	// monitor's later passes do not put port 2 back on VLAN 2
	r.after(210 * time.Second)
	r.after(5 * time.Second)
	if !r.onLAN() {
		t.Errorf("not held on the LAN: %v", r.pw.br)
	}
	r.untouched()
}

// TestPortsStartupHold: nothing is applied before the first answered
// inform; the inform submits the apply, which then waits for its own
// confirmation.
func TestPortsStartupHold(t *testing.T) {
	r := newPortsRig(t, nil)
	r.provision(switchCfg)
	r.a.portsApply(r.ctx, "tick")
	if !r.onLAN() || len(r.pw.opsList()) != 0 {
		t.Fatalf("applied before an inform: %q", r.pw.opsList())
	}
	r.clk.add(time.Second)
	r.inform(r.clk.now())
	if !r.live() {
		t.Fatalf("not applied after the first inform: %v", r.pw.br)
	}
	r.after(90 * time.Second)
	if !r.onLAN() {
		t.Errorf("the startup change was not waiting for its confirmation: %v", r.pw.br)
	}
}

// TestPortsLossWatchdog: with no answered inform for 300 s every port the
// agent may change goes on the LAN and stays there; answered informs bring
// the settings back (through the confirm window); a second loss revert of
// the same settings marks them failed.
func TestPortsLossWatchdog(t *testing.T) {
	r := newPortsRig(t, nil)
	r.inform(r.clk.now())
	r.provision(switchCfg)
	r.clk.add(time.Second)
	r.inform(r.clk.now()) // confirmed; the last answered inform
	r.after(298 * time.Second)
	if !r.live() {
		t.Fatalf("reverted before 300 s: %v", r.pw.br)
	}
	r.after(2 * time.Second)
	if !r.onLAN() {
		t.Fatalf("not on the LAN after 300 s: %v", r.pw.br)
	}
	if !strings.Contains(r.logs.all(), "EVENT: PORTS REVERTED (controller unreachable for 5m0s): port 2, port 3 back on the untagged LAN") ||
		!strings.Contains(r.events(), "controller unreachable") {
		t.Fatalf("loss event:\n%s\nevents.log: %q", r.logs.all(), r.events())
	}
	// held: neither the tick nor more passes apply anything or log again
	ops := len(r.pw.opsList())
	r.a.portsApply(r.ctx, "tick")
	r.after(10 * time.Minute)
	if len(r.pw.opsList()) != ops || strings.Count(r.logs.all(), "controller unreachable for") != 1 {
		t.Fatalf("held ports changed: %q\n%s", r.pw.opsList()[ops:], r.logs.all())
	}
	// informs again: re-applied, then confirmed
	r.inform(r.clk.now())
	if !r.live() {
		t.Fatalf("not re-applied after informs returned: %v", r.pw.br)
	}
	r.clk.add(time.Second)
	r.inform(r.clk.now())
	// the second loss of the same settings: marked failed
	r.after(300 * time.Second)
	if !r.onLAN() || !strings.Contains(r.logs.all(), "taken off twice in a row") {
		t.Fatalf("second loss: %v\n%s", r.pw.br, r.logs.all())
	}
	r.inform(r.clk.now())
	if !r.onLAN() {
		t.Errorf("settings taken off twice re-applied: %v", r.pw.br)
	}
	r.untouched()
}

// TestPortsLossRetried: a port the loss revert could not put on the LAN
// (its move failed and left it in no bridge) is retried at every pass
// until it is there, with one note, not an event per pass.
func TestPortsLossRetried(t *testing.T) {
	r := newPortsRig(t, nil)
	r.inform(r.clk.now())
	r.provision(switchCfg)
	r.clk.add(time.Second)
	r.inform(r.clk.now())
	r.pw.mu.Lock()
	r.pw.fail["eth0.2.1 0"] = true
	r.pw.mu.Unlock()
	r.after(300 * time.Second)
	if r.pw.BridgeOf("eth0.2.1") != "" || !strings.Contains(r.logs.all(), "PORTS REVERTED") {
		t.Fatalf("port 2 in %q:\n%s", r.pw.BridgeOf("eth0.2.1"), r.logs.all())
	}
	for i := 0; i < 3; i++ {
		r.after(5 * time.Second)
	}
	if n := strings.Count(r.logs.all(), "port 2 is not on the LAN"); n != 1 {
		t.Errorf("%d not-on-the-LAN notes:\n%s", n, r.logs.all())
	}
	r.pw.mu.Lock()
	delete(r.pw.fail, "eth0.2.1 0")
	r.pw.mu.Unlock()
	r.after(5 * time.Second)
	if !r.onLAN() {
		t.Errorf("not retried: %v", r.pw.br)
	}
	r.untouched()
}

// TestPortsRevertRetried: an unconfirmed change whose revert fails (the
// port left in no bridge) is retried by the next passes until the port is
// back on the LAN; the failed setting is not applied meanwhile.
func TestPortsRevertRetried(t *testing.T) {
	r := newPortsRig(t, nil)
	r.inform(r.clk.now())
	r.provision(switchCfg)
	r.pw.mu.Lock()
	r.pw.fail["eth0.2.1 0"] = true
	r.pw.mu.Unlock()
	r.after(90 * time.Second)
	if r.pw.BridgeOf("eth0.2.1") != "" || !strings.Contains(r.logs.all(), "EVENT: ports: port 2: putting it back failed") {
		t.Fatalf("port 2 in %q:\n%s", r.pw.BridgeOf("eth0.2.1"), r.logs.all())
	}
	r.a.portsApply(r.ctx, "tick")
	r.after(5 * time.Second)
	if r.pw.BridgeOf("eth0.2.1") != "" {
		t.Fatalf("port 2 in %q", r.pw.BridgeOf("eth0.2.1"))
	}
	r.pw.mu.Lock()
	delete(r.pw.fail, "eth0.2.1 0")
	r.pw.mu.Unlock()
	r.after(5 * time.Second)
	if r.pw.BridgeOf("eth0.2.1") != "bdg2" {
		t.Errorf("not back on the LAN: %v", r.pw.br)
	}
	ops := len(r.pw.opsList())
	r.a.portsApply(r.ctx, "tick")
	if len(r.pw.opsList()) != ops {
		t.Errorf("failed setting applied: %q", r.pw.opsList()[ops:])
	}
}

// TestPortsConfigKeys: ports_confirm_s 30-900 and ports_loss_s 60-3600,
// on jio-mtk as UHDIW only; 0 (absent) is the default.
func TestPortsConfigKeys(t *testing.T) {
	base := `{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1","platform":"jio-mtk"`
	for _, good := range []string{`,"model":"UHDIW"}`, `,"model":"UHDIW","ports_confirm_s":30,"ports_loss_s":60}`,
		`,"model":"UHDIW","ports_confirm_s":900,"ports_loss_s":3600}`} {
		c, err := parseConfig([]byte(base + good))
		if err != nil {
			t.Errorf("%s: %v", good, err)
			continue
		}
		if good == `,"model":"UHDIW"}` && (c.portsConfirm() != 90*time.Second || c.portsLoss() != 300*time.Second) {
			t.Errorf("defaults %s %s", c.portsConfirm(), c.portsLoss())
		}
	}
	for _, bad := range []string{`,"model":"UHDIW","ports_confirm_s":29}`, `,"model":"UHDIW","ports_confirm_s":901}`,
		`,"model":"UHDIW","ports_loss_s":59}`, `,"model":"UHDIW","ports_loss_s":3601}`, `,"model":"UHDIW","ports_confirm_s":-1}`,
		`,"model":"U7LT","ports_confirm_s":90}`} {
		if _, err := parseConfig([]byte(base + bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, err := parseConfig([]byte(`{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1","ports_loss_s":300}`)); err == nil {
		t.Errorf("ports_loss_s accepted on the Deco")
	}
	c, _ := parseConfig([]byte(base + `,"model":"UHDIW","ports_confirm_s":45,"ports_loss_s":120}`))
	if c.portsConfirm() != 45*time.Second || c.portsLoss() != 120*time.Second {
		t.Errorf("%s %s", c.portsConfirm(), c.portsLoss())
	}
}

// TestJioPortsRevertWhileBlocked: the whole agent with the fake controller
// and clock: the controller stops answering (each inform hangs on a dead
// connection) while the Wi-Fi worker is stuck in a long job; the monitor
// still reverts the unconfirmed ports at 90 s.
func TestJioPortsRevertWhileBlocked(t *testing.T) {
	clk := newFakeClock()
	var down atomic.Bool
	posts := make(chan struct{}, 100)
	h, pw := jioPortsHarness(t)
	real := httpPoster(time.Second)
	h.a.o.now = clk.now
	h.a.events.clock = clk.now
	h.a.o.post = func(ctx context.Context, u string, b []byte) (int, []byte, error) {
		if down.Load() {
			select {
			case posts <- struct{}{}:
			default:
			}
			<-ctx.Done() // a dead TCP connection
			return 0, nil, errors.New("controller down")
		}
		return real(ctx, u, b)
	}
	h.a.t.portsWatch = 5 * time.Millisecond
	h.ctl.queue(adoptReply, provisionReply(testCfg+switchCfg))
	h.start()
	eventually(t, "ports applied", func() bool { return pw.BridgeOf("eth0.2.1") == "br-v2" })
	down.Store(true)
	<-posts // an inform hangs now
	release := make(chan struct{})
	defer close(release)
	busy := make(chan struct{})
	h.a.submit("long wifi job", func(context.Context) { close(busy); <-release })
	<-busy
	clk.add(91 * time.Second)
	eventually(t, "ports reverted", func() bool { return pw.BridgeOf("eth0.2.1") == "bdg2" && !pw.Exists("eth0.3.2") })
	if !strings.Contains(h.logs.all(), "EVENT: PORTS REVERTED") {
		t.Errorf("no event:\n%s", h.logs.all())
	}
	if pw.BridgeOf("eth0.1.1") != "bdg2" || pw.BridgeOf("eth0.4.1") != "bdg2" {
		t.Errorf("port 1 or the uplink changed: %v", pw.br)
	}
}
