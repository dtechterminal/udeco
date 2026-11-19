// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/jioports"
	"github.com/antoniocosta/unifi-openwrt/internal/models"
)

// portsWifi is the fake Wi-Fi backend with mtkwifi's port bridging: an
// in-memory bridge table of the JCOW414's port devices.
type portsWifi struct {
	*fakeWifi
	mu  sync.Mutex
	br  map[string]string // dev -> bridge ("" = none)
	ops []string
	// fail: PortToBridge("dev vid") fails, leaving dev in no bridge
	// (brctl delif done, addif failed)
	fail map[string]bool
	// change: mtkwifi's OnChange hook, called before each change
	change func(context.Context)
}

func (p *portsWifi) OnChange(f func(context.Context)) {
	p.mu.Lock()
	p.change = f
	p.mu.Unlock()
}

func (p *portsWifi) changing(ctx context.Context) {
	p.mu.Lock()
	f := p.change
	p.mu.Unlock()
	if f != nil {
		f(ctx)
	}
}

func newPortsWifi(w *fakeWifi) *portsWifi {
	p := &portsWifi{fakeWifi: w, br: map[string]string{}, fail: map[string]bool{}}
	for i := 1; i <= 4; i++ {
		p.br[jioports.Untagged(i)] = "bdg2"
	}
	return p
}

func (p *portsWifi) op(f string, a ...any) { p.ops = append(p.ops, fmt.Sprintf(f, a...)) }

func (p *portsWifi) LANBridge() string { return "bdg2" }
func (p *portsWifi) BridgeOf(dev string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.br[dev]
}
func (p *portsWifi) Exists(dev string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.br[dev]
	return ok
}
func (p *portsWifi) PortToBridge(ctx context.Context, dev string, vid int) error {
	p.changing(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if strings.HasPrefix(dev, "eth0.4") {
		return fmt.Errorf("uplink")
	}
	if p.fail[dev+" "+strconv.Itoa(vid)] {
		p.br[dev] = ""
		return fmt.Errorf("brctl addif %s: failed", dev)
	}
	switch {
	case vid < 0:
		p.br[dev] = ""
	case vid == 0:
		p.br[dev] = "bdg2"
	default:
		p.br[dev] = "br-v" + strconv.Itoa(vid)
	}
	p.op("bridge %s %d", dev, vid)
	return nil
}
func (p *portsWifi) EnsurePortVLAN(ctx context.Context, parent string, vid int) (string, error) {
	p.changing(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	d := parent + "." + strconv.Itoa(vid)
	p.br[d] = "br-v" + strconv.Itoa(vid)
	p.op("vlan %s", d)
	return d, nil
}
func (p *portsWifi) DelPortVLAN(ctx context.Context, dev string) error {
	p.changing(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.br, dev)
	p.op("del %s", dev)
	return nil
}
func (p *portsWifi) PortVLANDevs(parent string) map[int]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[int]string{}
	for d := range p.br {
		if v, err := strconv.Atoi(strings.TrimPrefix(d, parent+".")); err == nil && strings.HasPrefix(d, parent+".") && v > 1 {
			out[v] = d
		}
	}
	return out
}
func (p *portsWifi) SetPortVLANs(map[int]bool)        {}
func (p *portsWifi) PruneVLANs(context.Context) error { return nil }

func (p *portsWifi) opsList() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string{}, p.ops...)
}

// switchCfg: port 2 native Cameras (VLAN 2), port 3 on "all" (Olive
// tagged), port 1's lines as the controller would write them were it
// editable (it is locked: none of it is applied).
const switchCfg = "switch.status=enabled\nswitch.vlan.status=enabled\n" +
	"switch.vlan.1.id=1\nswitch.vlan.1.mode=untagged\nswitch.vlan.1.status=enabled\n" +
	"switch.vlan.2.id=2\nswitch.vlan.2.mode=tagged\nswitch.vlan.2.status=enabled\n" +
	"switch.vlan.3.id=3\nswitch.vlan.3.mode=tagged\nswitch.vlan.3.status=enabled\n" +
	"switch.port.1.name=Port 1\nswitch.port.1.pvid=3\nswitch.vlan.1.port.1.mode=exclude\nswitch.vlan.3.port.1.mode=untagged\n" +
	"switch.port.2.name=Port 2\nswitch.port.2.pvid=2\n" +
	"switch.vlan.1.port.2.mode=exclude\nswitch.vlan.2.port.2.mode=untagged\nswitch.vlan.3.port.2.mode=exclude\n" +
	"switch.port.3.name=Port 3\n"

func jioPortsHarness(t *testing.T, unlocked ...int) (*harness, *portsWifi) {
	var pw *portsWifi
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply, c.Platform, c.Model, c.PortsUnlocked = true, true, PlatformJio, "UHDIW", unlocked
	})
	pw = newPortsWifi(h.wifi)
	h.a.o.newWifi = func(bo bcmwifi.Options) wifiApplier { h.built++; h.wopts = bo; return pw }
	for p, l := range map[string]string{"gsw_link_st": "Port1 : 1000M/Full Duplex\nPort2 : Down\nPort3 : Down\nPort4 : 100M/Full Duplex EEE100\n"} {
		f := filepath.Join(h.root, "proc/tc3162", p)
		os.MkdirAll(filepath.Dir(f), 0o755)
		os.WriteFile(f, []byte(l), 0o644)
	}
	return h, pw
}

// TestJioPortsEndToEnd: as UHDIW in takeover mode the agent claims the
// switch bits, reports five ports (the uplink as port 5, port 4 absent,
// the uplink and port 1 not editable) and applies the switch section to
// ports 2 and 3 only.
func TestJioPortsEndToEnd(t *testing.T) {
	h, pw := jioPortsHarness(t)
	h.ctl.queue(adoptReply, provisionReply(testCfg+switchCfg))
	h.start()
	eventually(t, "ports applied", func() bool { return len(pw.opsList()) >= 3 })
	eventually(t, "an inform with the switch bits", func() bool {
		m := h.ctl.last()
		return m != nil && int(num(m["fw_caps"]))&(models.FWCapQCASwitch|models.FWCapOWRTSwitch) == models.FWCapQCASwitch|models.FWCapOWRTSwitch
	})
	m := h.ctl.last()
	h.stop()
	if m["model"] != "UHDIW" {
		t.Errorf("model %v", m["model"])
	}
	rows, _ := m["port_table"].([]any)
	if len(rows) != jioports.NumPorts {
		t.Fatalf("port_table %v", m["port_table"])
	}
	for i, want := range []struct {
		up, uplink, noEdit bool
		speed              float64
	}{{true, false, true, 1000}, {false, false, false, 0}, {false, false, false, 0}, {false, false, true, 0}, {true, true, true, 100}} {
		r := rows[i].(map[string]any)
		if int(num(r["port_idx"])) != i+1 || r["up"] != want.up || r["is_uplink"] != want.uplink || r["attr_no_edit"] != want.noEdit || num(r["speed"]) != want.speed {
			t.Errorf("port %d: %v", i+1, r)
		}
	}
	if it, _ := m["if_table"].([]any); len(it) != 1 || num(it[0].(map[string]any)["num_port"]) != jioports.NumPorts || num(it[0].(map[string]any)["speed"]) != 100 {
		t.Errorf("if_table %v", m["if_table"])
	}
	ops := pw.opsList()
	sort.Strings(ops)
	want := []string{"bridge eth0.2.1 2", "vlan eth0.3.2", "vlan eth0.3.3"}
	if strings.Join(ops, "|") != strings.Join(want, "|") {
		t.Errorf("port ops %q, want %q", ops, want)
	}
	if pw.BridgeOf("eth0.1.1") != "bdg2" || pw.BridgeOf("eth0.4.1") != "bdg2" {
		t.Errorf("port 1 or the uplink changed")
	}
	logs := h.logs.all()
	if !strings.Contains(logs, "port 1 is locked") || strings.Contains(logs, "switch: not supported") {
		t.Errorf("logs:\n%s", logs)
	}
	if !strings.Contains(logs, "ports: port 2 (UniFi port 2) is native VLAN 2") {
		t.Errorf("port change not logged:\n%s", logs)
	}
}

// TestJioPortsUnlocked: ports_unlocked [1] lets the controller move port 1.
func TestJioPortsUnlocked(t *testing.T) {
	h, pw := jioPortsHarness(t, 1)
	h.ctl.queue(adoptReply, provisionReply(testCfg+switchCfg))
	h.start()
	eventually(t, "port 1 moved", func() bool { return pw.BridgeOf("eth0.1.1") == "br-v3" })
	eventually(t, "port 1 editable", func() bool {
		m := h.ctl.last()
		rows, _ := m["port_table"].([]any)
		return len(rows) == jioports.NumPorts && rows[0].(map[string]any)["attr_no_edit"] == false
	})
	h.stop()
}

// TestJioPortsObserveAndU7LT: observe mode reports the ports but claims no
// switch and changes none; U7LT keeps its single port.
func TestJioPortsObserveAndU7LT(t *testing.T) {
	h, pw := jioPortsHarness(t)
	h.cfg.Takeover, h.cfg.Apply = false, false
	h.a.takeover.Store(false)
	h.ctl.queue(adoptReply, provisionReply(testCfg+switchCfg))
	h.start()
	eventually(t, "an inform with ports", func() bool {
		m := h.ctl.last()
		rows, _ := m["port_table"].([]any)
		return len(rows) == jioports.NumPorts
	})
	m := h.ctl.last()
	h.stop()
	if int(num(m["fw_caps"]))&(models.FWCapQCASwitch|models.FWCapOWRTSwitch) != 0 || len(pw.opsList()) != 0 {
		t.Errorf("observe: fw_caps %v ops %v", m["fw_caps"], pw.opsList())
	}

	h2 := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply, c.Platform, c.Model = true, true, PlatformJio, "U7LT"
	})
	h2.start()
	eventually(t, "an inform", func() bool { return h2.ctl.last() != nil })
	m = h2.ctl.last()
	h2.stop()
	if m["port_table"] != nil || int(num(m["fw_caps"]))&models.FWCapQCASwitch != 0 {
		t.Errorf("U7LT: port_table %v fw_caps %v", m["port_table"], m["fw_caps"])
	}
}

// TestPortFieldsMACs: the tenant's router behind port 1 is listed as a
// wired client of UniFi port 1, and the LLDP neighbour sits on port 5.
func TestPortFieldsMACs(t *testing.T) {
	a := &agent{cfg: &Config{Platform: PlatformJio, Model: "UHDIW"}, o: options{root: t.TempDir()}}
	s := &apstate.Snapshot{MAC: "b4:a7:c6:17:e3:f3",
		Ports: []apstate.Port{{Name: "eth0.1.1", MAC: "b6:a0:c6:17:e3:f2", Up: true, BridgePort: 1},
			{Name: "eth0.4.1", MAC: "b6:a3:c6:17:e3:f2", Up: true, BridgePort: 4}},
		FDB: []apstate.FDBEntry{{MAC: "54:af:97:74:f4:39", Port: 1, Age: 2}, {MAC: "aa:bb:cc:dd:ee:01", Port: 4}}}
	f := map[string]any{"if_table": []map[string]any{{"name": "eth0", "num_port": 1}},
		"lldp_table": []map[string]any{{"local_port_idx": 1, "chassis_id": "x"}}}
	a.portFields(f, s)
	rows := f["port_table"].([]map[string]any)
	macs := rows[0]["mac_table"].([]map[string]any)
	if len(macs) != 1 || macs[0]["mac"] != "54:af:97:74:f4:39" || rows[4]["mac_table"] != nil {
		t.Errorf("mac tables %v / %v", rows[0]["mac_table"], rows[4]["mac_table"])
	}
	if f["if_table"].([]map[string]any)[0]["num_port"] != jioports.NumPorts || f["lldp_table"].([]map[string]any)[0]["local_port_idx"] != jioports.UplinkIdx {
		t.Errorf("if_table %v lldp %v", f["if_table"], f["lldp_table"])
	}
}
