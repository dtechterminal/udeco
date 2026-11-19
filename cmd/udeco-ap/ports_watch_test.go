// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"encoding/json"
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

// tick is now, moved on by a millisecond at every reading (each reading
// is later than the one before, as on the unit).
func (c *fakeClock) tick() time.Time {
	c.add(time.Millisecond)
	return c.now()
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

// TestPortsConfigKeys: ports_confirm_s 60-900 and ports_loss_s 60-3600,
// on jio-mtk as UHDIW only; 0 (absent) is the default.
func TestPortsConfigKeys(t *testing.T) {
	base := `{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1","platform":"jio-mtk"`
	for _, good := range []string{`,"model":"UHDIW"}`, `,"model":"UHDIW","ports_confirm_s":60,"ports_loss_s":60}`,
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
	for _, bad := range []string{`,"model":"UHDIW","ports_confirm_s":59}`, `,"model":"UHDIW","ports_confirm_s":30}`, `,"model":"UHDIW","ports_confirm_s":901}`,
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

// aliveJob is the job in the rig's alive record ("-" = no record).
func (r *portsRig) aliveJob() string {
	b, err := os.ReadFile(r.a.alivePath())
	if err != nil {
		return "-"
	}
	var rec aliveRec
	if err := json.Unmarshal(b, &rec); err != nil {
		r.t.Fatalf("alive %q: %v", b, err)
	}
	return rec.Job
}

// TestAliveMarksTickChanges: a routine tick (the "enforce" job) that puts
// a moved port back is in the alive record while it changes the unit, as
// a provision job is, and the mark is cleared after; an idle tick writes
// nothing to flash; changes made outside the worker (a provision called
// directly, the port monitor's revert) mark no tick.
func TestAliveMarksTickChanges(t *testing.T) {
	r := newPortsRig(t, nil)
	r.a.watchChanges()
	var during []string
	hook := r.pw.change
	if hook == nil {
		t.Fatal("the Wi-Fi backend got no change hook")
	}
	r.pw.OnChange(func(ctx context.Context) {
		hook(ctx)
		during = append(during, r.aliveJob())
	})
	tick := func() {
		r.a.runJob(r.ctx, job{"enforce", func(ctx context.Context) { r.a.portsApply(ctx, "tick") }})
	}
	r.inform(r.clk.now())
	r.provision(switchCfg)
	r.clk.add(time.Second)
	r.inform(r.clk.now()) // confirmed
	if !r.live() {
		t.Fatalf("not applied: %v", r.pw.br)
	}

	// idle tick: no flash write
	os.Remove(r.a.alivePath())
	during = nil
	tick()
	if job := r.aliveJob(); job != "-" || len(during) != 0 {
		t.Errorf("idle tick wrote the alive record (%q) or changed %v", job, during)
	}

	// someone put port 2 back on the LAN: the tick moves it, marked
	r.pw.mu.Lock()
	r.pw.br["eth0.2.1"] = "bdg2"
	r.pw.mu.Unlock()
	tick()
	if !r.live() {
		t.Fatalf("port 2 not put back: %v", r.pw.br)
	}
	if len(during) == 0 || during[0] != "enforce" {
		t.Errorf("alive job while the tick changed the unit: %q, want enforce", during)
	}
	if job := r.aliveJob(); job != "" {
		t.Errorf("alive job after the tick: %q, want none", job)
	}

	// outside the worker: no mark
	os.Remove(r.a.alivePath())
	during = nil
	r.provision(switchCfg3)
	r.after(90 * time.Second) // unconfirmed: the port monitor reverts it
	if len(during) == 0 {
		t.Fatal("no change made outside the worker")
	}
	if job := r.aliveJob(); job != "-" {
		t.Errorf("a change outside the worker marked the alive record: %q", job)
	}
}

// switchCfgLAN2: port 2 back on the plain LAN (native LAN only).
var switchCfgLAN2 = strings.Replace(switchCfg,
	"switch.port.2.pvid=2\nswitch.vlan.1.port.2.mode=exclude\nswitch.vlan.2.port.2.mode=untagged\nswitch.vlan.3.port.2.mode=exclude\n",
	"switch.vlan.1.port.2.mode=untagged\nswitch.vlan.2.port.2.mode=exclude\nswitch.vlan.3.port.2.mode=exclude\n", 1)

// confirmed brings switchCfg live and has the controller confirm it.
func (r *portsRig) confirmed() {
	r.t.Helper()
	r.inform(r.clk.now())
	r.provision(switchCfg)
	r.clk.add(time.Second)
	r.inform(r.clk.now())
	if !r.live() || r.a.portsRetry() != 0 {
		r.t.Fatalf("switchCfg not live and confirmed: %v", r.pw.br)
	}
}

// TestPortsMoveToLANWatched: a move back to the plain LAN is a change too
// (the LAN can cut the unit off: a loop through a downstream switch). With
// no inform it goes back to the VLAN it was on, and the LAN is not applied
// again until the controller sends another setting; with an inform it
// stays.
func TestPortsMoveToLANWatched(t *testing.T) {
	r := newPortsRig(t, nil)
	r.confirmed()
	r.provision(switchCfgLAN2)
	if r.pw.BridgeOf("eth0.2.1") != "bdg2" {
		t.Fatalf("port 2 not moved to the LAN: %v", r.pw.br)
	}
	if r.a.portsRetry() == 0 {
		t.Fatalf("the move to the LAN is not waiting for the controller:\n%s", r.logs.all())
	}
	r.after(90 * time.Second)
	if r.pw.BridgeOf("eth0.2.1") != "br-v2" || !strings.Contains(r.logs.all(), "EVENT: PORTS REVERTED (no inform reached the controller within 1m30s of the change): port 2 native LAN -> native VLAN 2") {
		t.Fatalf("not reverted to VLAN 2: %v\n%s", r.pw.br, r.logs.all())
	}
	r.inform(r.clk.now())
	ops := len(r.pw.opsList())
	r.provision(switchCfgLAN2)
	if r.pw.BridgeOf("eth0.2.1") != "br-v2" || len(r.pw.opsList()) != ops {
		t.Errorf("the reverted LAN setting re-applied: %q", r.pw.opsList()[ops:])
	}
	r.untouched()

	r = newPortsRig(t, nil)
	r.confirmed()
	r.provision(switchCfgLAN2)
	r.clk.add(time.Second)
	r.inform(r.clk.now())
	r.after(4 * time.Minute)
	if r.pw.BridgeOf("eth0.2.1") != "bdg2" || !strings.Contains(r.logs.all(), "port 2: native LAN confirmed") {
		t.Errorf("a confirmed move to the LAN: %v\n%s", r.pw.br, r.logs.all())
	}
	r.untouched()
}

// TestPortsRevertNeverToNoBridge: a port found in no bridge (a move cut
// short by an earlier run) that a change then moves is reverted to the
// plain LAN, never back into no bridge, and stays there while informs are
// answered.
func TestPortsRevertNeverToNoBridge(t *testing.T) {
	r := newPortsRig(t, nil)
	r.pw.br["eth0.2.1"] = ""
	r.inform(r.clk.now())
	r.provision(switchCfg)
	if r.pw.BridgeOf("eth0.2.1") != "br-v2" {
		t.Fatalf("port 2 %q", r.pw.BridgeOf("eth0.2.1"))
	}
	r.after(90 * time.Second)
	if r.pw.BridgeOf("eth0.2.1") != "bdg2" || !strings.Contains(r.logs.all(), "port 2 native VLAN 2 -> native LAN") {
		t.Fatalf("port 2 in %q:\n%s", r.pw.BridgeOf("eth0.2.1"), r.logs.all())
	}
	for i := 0; i < 20; i++ {
		r.clk.add(5 * time.Second)
		r.inform(r.clk.now())
		r.a.portsWatch(r.ctx)
		r.a.portsApply(r.ctx, "tick")
	}
	if r.pw.BridgeOf("eth0.2.1") != "bdg2" {
		t.Errorf("port 2 left in %q", r.pw.BridgeOf("eth0.2.1"))
	}
	r.untouched()
}

// TestPortsChangedTwiceUnconfirmed: LAN -> VLAN 2 -> VLAN 3 with no
// confirmation in between goes back to the LAN, not to the unconfirmed
// VLAN 2; the window runs from the second change.
func TestPortsChangedTwiceUnconfirmed(t *testing.T) {
	r := newPortsRig(t, nil)
	r.inform(r.clk.now())
	r.provision(switchCfg)
	r.after(60 * time.Second)
	r.provision(switchCfg3)
	r.after(60 * time.Second)
	if r.pw.BridgeOf("eth0.2.1") != "br-v3" {
		t.Fatalf("reverted 60 s after the second change: %v", r.pw.br)
	}
	r.after(30 * time.Second)
	if r.pw.BridgeOf("eth0.2.1") != "bdg2" || !strings.Contains(r.logs.all(), "port 2 native VLAN 3 -> native LAN") {
		t.Fatalf("not back on the LAN: %v\n%s", r.pw.br, r.logs.all())
	}
	r.untouched()
}

// TestPortsFailedApplyPending: a change that failed and was rolled back
// onto the LAN the port was on has nothing to confirm (no "waiting", no
// "confirmed"); one rolled back onto the LAN from a VLAN waits, and goes
// back to the VLAN without an inform, the failed setting still not retried.
func TestPortsFailedApplyPending(t *testing.T) {
	r := newPortsRig(t, nil)
	r.pw.fail["eth0.2.1 2"] = true
	r.inform(r.clk.now())
	r.provision(switchCfg)
	if r.pw.BridgeOf("eth0.2.1") != "bdg2" {
		t.Fatalf("port 2 %q", r.pw.BridgeOf("eth0.2.1"))
	}
	r.clk.add(time.Second)
	r.inform(r.clk.now())
	if logs := r.logs.all(); strings.Contains(logs, "port 2: native VLAN 2 is waiting") || strings.Contains(logs, "port 2: native VLAN 2 confirmed") ||
		!strings.Contains(logs, "port 3: native LAN, tagged 2,3 confirmed") {
		t.Errorf("a failed change waits or is confirmed:\n%s", logs)
	}

	r = newPortsRig(t, nil)
	r.confirmed()
	r.pw.mu.Lock()
	r.pw.fail["eth0.2.1 3"] = true
	r.pw.mu.Unlock()
	r.provision(switchCfg3)
	if r.pw.BridgeOf("eth0.2.1") != "bdg2" || !strings.Contains(r.logs.all(), "port 2: native VLAN 3 failed and the rollback put the port on the LAN (it was native VLAN 2)") {
		t.Fatalf("port 2 %q:\n%s", r.pw.BridgeOf("eth0.2.1"), r.logs.all())
	}
	r.after(90 * time.Second)
	if r.pw.BridgeOf("eth0.2.1") != "br-v2" || !strings.Contains(r.logs.all(), "port 2 native LAN -> native VLAN 2") {
		t.Fatalf("not back on VLAN 2: %v\n%s", r.pw.br, r.logs.all())
	}
	r.pw.mu.Lock()
	delete(r.pw.fail, "eth0.2.1 3")
	r.pw.mu.Unlock()
	r.inform(r.clk.now())
	ops := len(r.pw.opsList())
	r.a.portsApply(r.ctx, "tick")
	if r.pw.BridgeOf("eth0.2.1") != "br-v2" || len(r.pw.opsList()) != ops {
		t.Errorf("the failed setting retried: %q", r.pw.opsList()[ops:])
	}
	r.untouched()
}

// TestPortsDoubleLossApart: two outages a day apart, the setting re-applied
// and confirmed in between, are not "twice in a row": the setting comes
// back after the second one too.
func TestPortsDoubleLossApart(t *testing.T) {
	r := newPortsRig(t, nil)
	r.confirmed()
	r.after(300 * time.Second)
	if !r.onLAN() {
		t.Fatalf("first loss: %v", r.pw.br)
	}
	r.inform(r.clk.now())
	r.clk.add(time.Second)
	r.inform(r.clk.now())
	if !r.live() {
		t.Fatalf("not re-applied: %v", r.pw.br)
	}
	for i := 0; i < 24*60; i++ { // a day of answered informs
		r.after(time.Minute)
		r.inform(r.clk.now())
	}
	r.after(300 * time.Second)
	if !r.onLAN() || strings.Contains(r.logs.all(), "taken off twice in a row") {
		t.Fatalf("second loss: %v\n%s", r.pw.br, r.logs.all())
	}
	r.inform(r.clk.now())
	if !r.live() {
		t.Errorf("not re-applied after the second outage: %v", r.pw.br)
	}
	r.untouched()
}

// TestPortsChangeWakesInform: a port change asks the inform loop for an
// inform at once, and while it waits the loop's backoff is capped.
func TestPortsChangeWakesInform(t *testing.T) {
	r := newPortsRig(t, nil)
	r.a.wake = make(chan struct{}, 1)
	r.inform(r.clk.now())
	if r.a.portsRetry() != 0 {
		t.Fatalf("retry cap with nothing pending")
	}
	r.provision(switchCfg)
	select {
	case <-r.a.wake:
	default:
		t.Fatal("the change did not wake the inform loop")
	}
	if r.a.portsRetry() != r.a.t.portsRetry {
		t.Errorf("retry cap %s while a change waits", r.a.portsRetry())
	}
	r.clk.add(time.Second)
	r.inform(r.clk.now())
	if r.a.portsRetry() != 0 {
		t.Errorf("retry cap after the confirmation")
	}
}

// TestJioPortsInformInFlight: the whole agent: a port change that finishes
// while an inform is on the wire is not confirmed by that inform's reply
// (the inform started before it), and with the controller gone after that
// it is reverted at 90 s.
func TestJioPortsInformInFlight(t *testing.T) {
	clk := newFakeClock()
	var phase atomic.Int32
	dead := make(chan struct{}, 1)
	h, pw := jioPortsHarness(t)
	real := httpPoster(time.Second)
	h.a.o.now = clk.tick
	h.a.events.clock = clk.now
	h.a.t.portsWatch = 5 * time.Millisecond
	h.a.o.post = func(ctx context.Context, u string, b []byte) (int, []byte, error) {
		switch phase.Load() {
		case 1: // the change finishes while this inform is on the wire
			clk.add(time.Second)
			h.a.portsPrepare(provision{systemCfg: testCfg + switchCfg3})
			h.a.portsApply(ctx, "test")
			clk.add(time.Second)
			phase.Store(2)
		case 2:
			select {
			case dead <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return 0, nil, errors.New("controller down")
		}
		return real(ctx, u, b)
	}
	h.ctl.queue(adoptReply, provisionReply(testCfg+switchCfg))
	h.start()
	eventually(t, "the first change confirmed", func() bool { return strings.Contains(h.logs.all(), "port 2: native VLAN 2 confirmed") })
	phase.Store(1)
	<-dead // the inform the change overlapped is handled, the next hangs
	if pw.BridgeOf("eth0.2.1") != "br-v3" {
		t.Fatalf("port 2 %q", pw.BridgeOf("eth0.2.1"))
	}
	if logs := h.logs.all(); strings.Contains(logs, "port 2: native VLAN 3 confirmed") {
		t.Fatalf("confirmed by an inform that started before the change:\n%s", logs)
	}
	clk.add(91 * time.Second)
	eventually(t, "port 2 back on VLAN 2", func() bool {
		return pw.BridgeOf("eth0.2.1") == "br-v2" && strings.Contains(h.logs.all(), "port 2 native VLAN 3 -> native VLAN 2")
	})
}

// TestJioPortsRetryWhilePending: the whole agent: informs that fail right
// after a port change are retried every portsRetry, not backed off 5, 10,
// 20 s, so the controller can still confirm the change in its window.
func TestJioPortsRetryWhilePending(t *testing.T) {
	clk := newFakeClock() // a millisecond a reading: the confirm window does not run out
	var fails atomic.Int32
	h, _ := jioPortsHarness(t)
	real := httpPoster(time.Second)
	h.a.o.now = clk.tick
	h.a.events.clock = clk.now
	h.a.t.portsRetry = 5 * time.Millisecond
	h.a.o.post = func(ctx context.Context, u string, b []byte) (int, []byte, error) {
		if h.a.portsRetry() > 0 && fails.Load() < 4 {
			fails.Add(1)
			return 0, nil, errors.New("connection refused")
		}
		return real(ctx, u, b)
	}
	h.ctl.queue(adoptReply, provisionReply(testCfg+switchCfg))
	h.start()
	eventually(t, "the change confirmed after four failed informs", func() bool {
		return fails.Load() == 4 && strings.Contains(h.logs.all(), "port 2: native VLAN 2 confirmed")
	})
}

// TestJioPortsRevertWaitsForWifiApply: a Wi-Fi apply holds the applier's
// lock, which every bridge change takes: the monitor's revert waits for it
// (at most one Wi-Fi apply, jobTimeout) and runs as soon as it ends.
func TestJioPortsRevertWaitsForWifiApply(t *testing.T) {
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
			<-ctx.Done()
			return 0, nil, errors.New("controller down")
		}
		return real(ctx, u, b)
	}
	h.a.t.portsWatch = 5 * time.Millisecond
	h.ctl.queue(adoptReply, provisionReply(testCfg+switchCfg))
	h.start()
	eventually(t, "ports applied", func() bool { return pw.BridgeOf("eth0.2.1") == "br-v2" })
	down.Store(true)
	<-posts
	busy, release := make(chan struct{}), make(chan struct{})
	h.a.submit("wifi apply", func(context.Context) {
		pw.mu.Lock() // the applier's lock, as mtkwifi.Applier.Apply holds it
		close(busy)
		<-release
		pw.mu.Unlock()
	})
	<-busy
	clk.add(91 * time.Second)
	time.Sleep(100 * time.Millisecond)
	if strings.Contains(h.logs.all(), "PORTS REVERTED") {
		t.Fatalf("reverted while the Wi-Fi apply held the applier")
	}
	close(release)
	eventually(t, "reverted once the Wi-Fi apply ended", func() bool {
		return strings.Contains(h.logs.all(), "EVENT: PORTS REVERTED") && pw.BridgeOf("eth0.2.1") == "bdg2"
	})
}
