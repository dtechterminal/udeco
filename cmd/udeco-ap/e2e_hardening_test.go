// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Fake-controller end-to-end tests of the build-2 behaviour: the captured
// .205 unit (agent_e2e_test.go), the real decosys and bcmwifi in DryRun,
// and a controller that adopts over SSH.

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// liveRe matches the worker's "this system_cfg is live" line.
var liveRe = regexp.MustCompile(`wifi: system_cfg [0-9a-f]+ (\([^)]*\) )?is (already )?live`)

// lastPayload is the newest device-key inform's payload.
func (c *e2eCtl) lastPayload() map[string]any {
	in := c.snapshot()
	for i := len(in) - 1; i >= 0; i-- {
		if in[i].key == "device" {
			return in[i].payload
		}
	}
	return nil
}

// adoptFrom runs the adoption on an agent that is already started.
func (e *e2e) adoptFrom() {
	t := e.t
	eventually(t, "a pending inform on the factory key", func() bool {
		return e.ctl.countWhere(func(i e2eInform) bool { return i.key == "factory" }) >= 2
	})
	sshSetAdopt(t, e.cfg.SSHDPort, e.ctl.url())
	eventually(t, "GCM informs after the provisioning", func() bool {
		e.ctl.mu.Lock()
		defer e.ctl.mu.Unlock()
		return e.ctl.stage >= 4
	})
}

// R1/R2/R5: while TP-Link is still booting the agent informs nothing,
// stops nothing and builds no Wi-Fi; in takeover mode it installs only the
// inbound fence, and keeps it in place. When the gate opens the fence is
// already there before the first inform and before the first Enforce.
func TestE2EBootGateAndFence(t *testing.T) {
	cfg, _ := u6proSystemCfg(t)
	e := newE2E(t, cfg, true)
	e.unit.write("/proc/uptime", "90.00 100.00\n")
	os.Remove(e.unit.path("/tmp/wifi_set_done"))
	var firstLogs string
	e.ctl.hook = func(in e2eInform) {
		if firstLogs == "" {
			firstLogs = e.logs.all()
		}
	}
	e.start()
	eventually(t, "the gate closed", func() bool { return strings.Contains(e.logs.all(), "boot gate closed") })
	time.Sleep(100 * time.Millisecond)
	logs := e.logs.all()
	if n := len(e.ctl.snapshot()); n != 0 {
		t.Fatalf("%d inform(s) before the gate opened", n)
	}
	if !strings.Contains(logs, "decosys: dry-run: /usr/sbin/iptables -w -N UDECO-IN") {
		t.Errorf("no inbound fence before the gate:\n%s", logs)
	}
	for _, not := range []string{"stop awn", "UDECO-OUT", "bcmwifi"} {
		if strings.Contains(logs, not) {
			t.Errorf("before the gate: %q in the log", not)
		}
	}
	e.mu.Lock()
	built := e.wifi != nil
	e.mu.Unlock()
	if built {
		t.Error("bcmwifi built before the gate")
	}

	// TP-Link has finished booting
	e.unit.write("/proc/uptime", "200.00 300.00\n")
	e.unit.write("/tmp/wifi_set_done", "")
	e.adoptFrom()
	eventually(t, "the bcmwifi dry-run apply", func() bool { return liveRe.MatchString(e.logs.all()) })
	e.stop()
	e.checkFlow()
	logs = e.logs.all()
	fence := strings.Index(logs, "UDECO-IN")
	enforce := strings.Index(logs, "decosys: dry-run: stop awn")
	if fence < 0 || enforce < 0 || fence > enforce {
		t.Errorf("fence at %d, first Enforce at %d", fence, enforce)
	}
	if !strings.Contains(firstLogs, "UDECO-IN") {
		t.Error("the first inform went out before the inbound fence")
	}
	if b, _ := os.ReadFile(e.unit.path("/tp_data/udeco/" + eventsFile)); !strings.Contains(string(b), "boot gate open") {
		t.Errorf("gate opening not in the event ring: %q", b)
	}
	if m := e.unit.mutating(); len(m) > 0 {
		t.Errorf("DryRun issued mutating commands: %q", m)
	}
}

// sysValue reads one key of a captured /sys/class/net dump.
func sysValue(t *testing.T, name, key string) string {
	t.Helper()
	sc := bufio.NewScanner(strings.NewReader(string(readFixture(t, wlFixtures, name))))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok && k == key {
			return v
		}
	}
	t.Fatalf("%s has no %s", name, key)
	return ""
}

// LLDP and the port shape in the inform: the gateway heard on the uplink
// (eth1 on .205) is the lldp_table row, reported on the U6-Lite's only
// port eth0; if_table is that one eth0 row with the uplink's counters; the
// unit announces itself on the uplink only.
func TestE2ELLDPAndIfTable(t *testing.T) {
	cfg, _ := u6proSystemCfg(t)
	f := &fakeLLDP{in: map[string][][]byte{}, out: map[string][][]byte{}}
	e := newE2E(t, cfg, false, withLLDP(f))
	f.push("eth1", gatewayLLDP(t))
	e.adopt()
	eventually(t, "lldp_table", func() bool { l, _ := e.ctl.lastPayload()["lldp_table"].([]any); return len(l) == 1 })
	eventually(t, "announced on the uplink", func() bool { return len(f.sent("eth1")) > 0 })
	e.stop()
	e.checkFlow()
	m := e.ctl.lastPayload()
	row := m["lldp_table"].([]any)[0].(map[string]any)
	if row["chassis_id"] != gwMAC || row["local_port_name"] != "eth0" || num(row["local_port_idx"]) != 1 || row["port_id"] != "eth3" ||
		row["is_wired"] != true || fmt.Sprint(row["mgmt_ips"]) != "[192.168.0.1]" {
		t.Errorf("lldp_table row %v", row)
	}
	it, _ := m["if_table"].([]any)
	if len(it) != 1 {
		t.Fatalf("if_table has %d rows: %v", len(it), m["if_table"])
	}
	r := it[0].(map[string]any)
	if r["name"] != "eth0" || num(r["num_port"]) != 1 || r["ip"] != e2eUnitIP || r["mac"] != "b0:a7:b9:3e:17:00" ||
		strconv.FormatFloat(num(r["rx_bytes"]), 'f', -1, 64) != sysValue(t, "sys_class_net_eth1.txt", "rx_bytes") {
		t.Errorf("if_table row %v (eth1 rx_bytes %s)", r, sysValue(t, "sys_class_net_eth1.txt", "rx_bytes"))
	}
	if m["uplink"] != "eth0" || m["has_eth1"] != false || m["port_table"] != nil {
		t.Errorf("uplink %v has_eth1 %v port_table %v", m["uplink"], m["has_eth1"], m["port_table"])
	}
	if len(f.sent("eth0")) != 0 {
		t.Error("LLDP announced on the non-uplink port")
	}
}

// A guest WLAN: bcmwifi gets the isolation policy with the gateway the
// unit reads from ARP, plans the UDECO-GIN/GOUT chains, and the plan's
// last datapath change is followed by the flow-cache flush (R21). DryRun:
// nothing reaches the unit.
func TestE2EGuestRulesAndFlush(t *testing.T) {
	cfg, _ := u6proSystemCfg(t)
	cfg = strings.NewReplacer("aaa.1.is_guest=false", "aaa.1.is_guest=true", "wireless.1.is_guest=false", "wireless.1.is_guest=true").Replace(cfg)
	e := newE2E(t, cfg, true)
	e.adopt()
	eventually(t, "the bcmwifi dry-run apply", func() bool { return liveRe.MatchString(e.logs.all()) })
	e.stop()
	p, ok := e.wifi.lastPlan()
	if !ok {
		t.Fatal("no plan")
	}
	g := p.Desired.Guest
	if g == nil || g.GatewayMAC != "1e:6a:1b:c5:04:c2" || g.GatewayIP != "192.168.0.1" {
		t.Fatalf("guest policy %+v", g)
	}
	guest := 0
	for _, s := range p.Desired.SSIDs {
		if s.Guest {
			guest++
		}
	}
	if guest != 1 {
		t.Errorf("%d guest SSIDs", guest)
	}
	lastDatapath, flush, gin := -1, -1, -1
	for i, s := range p.Steps {
		cmd := strings.Join(s.Argv, " ")
		switch {
		case s.Kind == bcmwifi.StepCmd && strings.HasPrefix(cmd, "fc flush"):
			flush = i
		case s.Kind == bcmwifi.StepCmd && strings.HasPrefix(cmd, "ebtables") && strings.Contains(cmd, "UDECO-GIN"):
			gin = i
			lastDatapath = i
		case s.Kind == bcmwifi.StepBridgeAdd || s.Kind == bcmwifi.StepBridgeDel ||
			s.Kind == bcmwifi.StepCmd && (strings.HasPrefix(cmd, "brctl") || strings.HasPrefix(cmd, "ip link add") || strings.HasPrefix(cmd, "ebtables")):
			lastDatapath = i
		}
	}
	if gin < 0 {
		t.Fatalf("no UDECO-GIN rules in the plan:\n%s", p)
	}
	if flush < 0 || flush < lastDatapath {
		t.Errorf("flow-cache flush at step %d, last datapath change at %d:\n%s", flush, lastDatapath, p)
	}
	if !strings.Contains(p.String(), "1e:6a:1b:c5:04:c2") {
		t.Error("the guest chains do not name the gateway's MAC")
	}
	if m := e.unit.mutating(); len(m) > 0 {
		t.Errorf("DryRun issued mutating commands: %q", m)
	}
}

// A failed apply holds the cfgversion back: the inform keeps reporting the
// one from before the provisioning, so the controller provisions again. (A
// failed first apply also hands Wi-Fi back to TP-Link: observe mode.)
func TestE2ECfgversionHeldOnFailedApply(t *testing.T) {
	cfg, _ := u6proSystemCfg(t)
	e := newE2E(t, cfg, true)
	e.failApply = true
	var before any // the cfgversion the unit reported when it was provisioned
	e.ctl.hook = func(in e2eInform) {
		if in.key == "device" && e.ctl.stage == 1 {
			before = in.payload["cfgversion"]
		}
	}
	e.adopt()
	eventually(t, "the failed apply", func() bool { return strings.Contains(e.logs.all(), "hostapd did not come up") })
	n := len(e.ctl.snapshot())
	eventually(t, "informs after the failure", func() bool { return len(e.ctl.snapshot()) >= n+3 })
	e.stop()
	in := e.ctl.snapshot()
	for _, x := range in[n:] {
		if cv := x.payload["cfgversion"]; cv == "00000000000000c1" {
			t.Fatalf("cfgversion of the failed system_cfg reported: %v", cv)
		}
	}
	if cv := e.ctl.lastPayload()["cfgversion"]; before == nil || cv != before {
		t.Errorf("cfgversion %v, want the one reported before the provisioning (%v)", cv, before)
	}
	logs := e.logs.all()
	if !strings.Contains(logs, "cfgversion 00000000000000c1 not acknowledged") || liveRe.MatchString(logs) {
		t.Errorf("the failed system_cfg was acknowledged or logged as live:\n%s", logs)
	}
	// a failed first apply hands Wi-Fi back to TP-Link and observes until
	// the persistent marker is removed
	if e.a.takeover.Load() {
		t.Error("still in takeover after the failed apply")
	}
	if _, err := os.Stat(e.unit.path("/tp_data/udeco/" + observeMarker)); err != nil {
		t.Error("no forced-observe marker after the hand-back")
	}
}

// The forced-observe marker is persistent: a crash loop writes it on
// /tp_data, the agent then observes although the config says takeover, and
// after a reboot (ramfs start log gone) it still observes.
func TestE2EForceObserveMarker(t *testing.T) {
	cfg, _ := u6proSystemCfg(t)
	var why string
	loop := func(c *Config, o *options) {
		for range crashStarts {
			why = startGuard(c, o.root, o.base, o.runDir, time.Now(), o.logf)
		}
	}
	e := newE2E(t, cfg, true, loop, func(c *Config, o *options) { o.forceObserve = why })
	marker := e.unit.path("/tp_data/udeco/" + observeMarker)
	if !strings.Contains(why, "crash loop") {
		t.Fatalf("no crash loop seen: %q", why)
	}
	if b, err := os.ReadFile(marker); err != nil || !strings.Contains(string(b), "crash loop") {
		t.Fatalf("marker: %q %v", b, err)
	}
	e.adopt()
	e.stop()
	e2Observes := func(e *e2e) {
		t.Helper()
		if e.a.takeover.Load() || len(e.sysOpts) != 0 || e.wifi != nil {
			t.Error("took over with the marker in place")
		}
		if m := e.unit.mutating(); len(m) > 0 {
			t.Errorf("forced observe issued mutating commands: %q", m)
		}
		if !strings.Contains(e.logs.all(), observeMarker) {
			t.Error("the log does not say why the agent observes")
		}
	}
	e2Observes(e)
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the marker did not survive the run")
	}

	// a reboot: ramfs (/tmp) is gone, /tp_data stays
	root := e.unit.root
	if err := os.RemoveAll(filepath.Join(root, "tmp/udeco")); err != nil {
		t.Fatal(err)
	}
	why2 := startGuard(e.cfg, root, "/tp_data/udeco", "/tmp/udeco", time.Now(), e.logs.logf)
	if why2 == "" || !strings.Contains(why2, "crash loop") {
		t.Fatalf("after the reboot: %q", why2)
	}
	e2 := newE2E(t, cfg, true, func(c *Config, o *options) {
		os.MkdirAll(filepath.Join(o.root, "tp_data/udeco"), 0o700)
		b, _ := os.ReadFile(marker)
		os.WriteFile(filepath.Join(o.root, "tp_data/udeco", observeMarker), b, 0o600)
		o.forceObserve = startGuard(c, o.root, o.base, o.runDir, time.Now(), o.logf)
	})
	e2.adopt()
	e2.stop()
	e2Observes(e2)
}

// R12: once adopted, the SSH adopt listener refuses the factory login, so
// a second set-adopt (another controller, a stray console) cannot take
// the unit; the session and its informs stay as they are.
func TestE2EAdoptionRefusedAfterAdoption(t *testing.T) {
	cfg, _ := u6proSystemCfg(t)
	e := newE2E(t, cfg, false)
	e.adopt()
	_, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", e.cfg.SSHDPort), &ssh.ClientConfig{
		User: "ubnt", Auth: []ssh.AuthMethod{ssh.Password("ubnt")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err == nil || !regexp.MustCompile(`unable to authenticate`).MatchString(err.Error()) {
		t.Fatalf("factory login after adoption: %v", err)
	}
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("the listener is gone rather than refusing: %v", err)
	}
	n := len(e.ctl.snapshot())
	eventually(t, "informs go on", func() bool { return len(e.ctl.snapshot()) >= n+2 })
	e.stop()
	if !e.a.x.S.Adopted {
		t.Error("no longer adopted")
	}
	in := e.ctl.snapshot()
	if slices.ContainsFunc(in[n:], func(x e2eInform) bool { return x.key == "factory" }) {
		t.Error("back on the factory key after a refused adoption")
	}
}
