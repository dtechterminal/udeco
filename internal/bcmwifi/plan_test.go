// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// twoSSIDs: a transition-mode main SSID on both bands and a hidden,
// isolated IoT SSID on VLAN 20, 2.4 GHz only.
func twoSSIDs() Desired {
	return Desired{
		Country: "US",
		Radios: map[string]Radio{
			"ng": {Enabled: true, Channel: 6, Width: 20},
			"na": {Enabled: true, Channel: 44, Width: 80},
		},
		SSIDs: []SSID{
			{ID: "b-iot", SSID: "EXN IOT", Bands: []string{"ng"}, Enabled: true, Hidden: true, Isolation: true, Security: SecWPA2, Passphrase: "iot-passphrase-1", VLAN: 20},
			{ID: "a-main", SSID: "Example Network", Bands: []string{"ng", "na"}, Enabled: true, Security: SecWPA2WPA3, Passphrase: testPSK, FT: true},
		},
	}
}

func stepIndex(t *testing.T, p Plan, sub string) int {
	t.Helper()
	for i, s := range p.Steps {
		if strings.Contains(s.String(), sub) {
			return i
		}
	}
	t.Fatalf("no step contains %q in plan:\n%s", sub, p)
	return -1
}

func TestPlanTakeover(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	p, err := a.Plan(context.Background(), twoSSIDs())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.mutating()) != 0 {
		t.Fatalf("Plan ran mutating commands: %v", f.mutating())
	}
	out := p.String()
	for _, secret := range []string{testPSK, "iot-passphrase-1"} {
		if strings.Contains(out, secret) {
			t.Fatalf("plan text leaks a passphrase:\n%s", out)
		}
	}
	if !p.takeover {
		t.Error("takeover not detected with TP-Link hostapd running")
	}
	// VLAN first, then per radio: lower the vifs while TP-Link's hostapd
	// still runs (its exit deletes them, F2), stop it, PHY, start ours, wait
	// for its BSS setup, then driver iovars, bridge, netdev up, BSS up.
	vlan := stepIndex(t, p, "ip link add link eth1 name eth1.20 type vlan id 20")
	lower := stepIndex(t, p, "wl -i wl02 bss down")
	stop0 := stepIndex(t, p, "stop hostapd from /tmp/wl0.1_hapd.pid")
	cs0 := stepIndex(t, p, "wl -i wl0 chanspec 6")
	start0 := stepIndex(t, p, "hostapd -B -P /tmp/udeco/hapd-wl0.pid /tmp/udeco/hapd-wl0.conf")
	wait0 := stepIndex(t, p, "wait for hostapd on wl0")
	ph := stepIndex(t, p, "wl -i wl01 bss down [optional]")
	cn := stepIndex(t, p, "wl -i wl03 closednet 1")
	br := stepIndex(t, p, "brctl addif br-v20 wl03")
	up := stepIndex(t, p, "ifconfig wl03 up")
	raise := stepIndex(t, p, "wl -i wl03 bss up")
	if !(vlan < lower && lower < stop0 && stop0 < cs0 && cs0 < start0 && start0 < wait0 && wait0 < ph && ph < cn && cn < br && br < up && up < raise) {
		t.Errorf("bad order vlan=%d lower=%d stop=%d chanspec=%d start=%d wait=%d placeholder=%d closednet=%d bridge=%d up=%d raise=%d\n%s",
			vlan, lower, stop0, cs0, start0, wait0, ph, cn, br, up, raise, out)
	}
	// After the stop, nothing touches a vif TP-Link's hostapd created
	// until ours has recreated it (the F7 failure: "lower wl02" after it
	// was gone).
	for i := stop0 + 1; i < wait0; i++ {
		for _, v := range []string{"wl02", "wl03", "wl04", "wl05", "wl06"} {
			if strings.Contains(p.Steps[i].String(), " "+v+" ") || strings.HasSuffix(p.Steps[i].String(), " "+v) {
				t.Errorf("step %d touches %s between the stop and the start: %s", i+1, v, p.Steps[i])
			}
		}
	}
	stepIndex(t, p, "wl -i wl0 bw_cap 2g 1")
	stepIndex(t, p, "stop hostapd from /tmp/wl1.1_hapd.pid")
	stepIndex(t, p, "brctl addif br-lan wl12")
	stepIndex(t, p, "wl -i wl02 fbt_mdid")
	stepIndex(t, p, "wl -i wl03 closednet 1")
	stepIndex(t, p, "wl -i wl03 ap_isolate 1")
	// wl1 already runs 44/80 with bw_cap 7: no PHY change on 5 GHz.
	for _, s := range p.Steps {
		str := s.String()
		if strings.Contains(str, "wl -i wl1 chanspec") || strings.Contains(str, "wl -i wl1 down") && !strings.Contains(str, "for dwds/rrm") {
			t.Errorf("unexpected 5 GHz PHY step %q", str)
		}
		if strings.Contains(str, "wl01 bss up") || strings.Contains(str, "wl11 bss up") {
			t.Errorf("backhaul vif raised: %q", str)
		}
	}
	// Placement is by WLAN id: a-main -> wl02/wl12, b-iot -> wl03.
	var conf0 string
	for _, s := range p.Steps {
		if s.Kind == StepWrite && s.Path == "/tmp/udeco/hapd-wl0.conf" {
			conf0 = string(s.Data)
			if s.Mode != 0o600 {
				t.Errorf("conf mode %o", s.Mode)
			}
		}
	}
	if !strings.Contains(conf0, "interface=wl01\n") || !strings.Contains(conf0, "bss=wl02\nbssid=ba:a7:b9:3e:17:04\n") ||
		!strings.Contains(conf0, "bss=wl03\nbssid=ba:a7:b9:3e:17:05\n") ||
		!strings.Contains(conf0, "bridge=br-v20\n") || !strings.Contains(conf0, "wpa_passphrase="+testPSK+"\n") {
		t.Errorf("wl0 conf:\n%s", conf0)
	}
}

func TestApplyThenPlanIsEmpty(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	// Live result.
	for vif, br := range map[string]string{"wl02": "br-lan", "wl03": "br-v20", "wl12": "br-lan", "wl13": "", "wl01": "", "wl11": ""} {
		if got := f.bridgeOf(vif); got != br {
			t.Errorf("%s bridge %q, want %q", vif, got, br)
		}
	}
	if f.bridgeOf("eth1.20") != "br-v20" {
		t.Error("eth1.20 not in br-v20")
	}
	// Files: conf 0600, baseline captured, last-good split.
	st, err := os.Stat(f.path("/tmp/udeco/hapd-wl1.conf"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("conf: %v %v", st, err)
	}
	if _, err := os.Stat(f.path("/tmp/udeco/tplink-baseline.json")); err != nil {
		t.Fatal("no baseline:", err)
	}
	pub, _ := os.ReadFile(f.path("/tp_data/udeco/state/last-good.json"))
	sec, _ := os.ReadFile(f.path("/tp_data/udeco/state/last-good.secrets.json"))
	if strings.Contains(string(pub), testPSK) || !strings.Contains(string(pub), "Example Network") {
		t.Errorf("public last-good:\n%s", pub)
	}
	if !strings.Contains(string(sec), testPSK) {
		t.Error("secrets file lacks the passphrase")
	}
	if st, _ := os.Stat(f.path("/tp_data/udeco/state/last-good.secrets.json")); st.Mode().Perm() != 0o600 {
		t.Errorf("secrets mode %o", st.Mode().Perm())
	}
	// Second plan: nothing to do.
	f.reset()
	p2, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if !p2.Empty() {
		t.Fatalf("second plan not empty:\n%s", p2)
	}
	// A new SSID on 5 GHz reconciles wl1 only.
	d.SSIDs = append(d.SSIDs, SSID{ID: "c-guest", SSID: "Guest", Bands: []string{"na"}, Enabled: true, Security: SecOpen, Isolation: true})
	p3, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range p3.Steps {
		if strings.Contains(s.String(), "wl0.") || strings.Contains(s.String(), "hapd-wl0") {
			t.Errorf("2.4 GHz touched: %s", s)
		}
	}
	stepIndex(t, p3, "stop hostapd from /tmp/udeco/hapd-wl1.pid")
	stepIndex(t, p3, "brctl addif br-lan wl13")
	if err := a.Apply(ctx, p3); err != nil {
		t.Fatal(err)
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, true)
	p, err := a.Plan(ctx, twoSSIDs())
	if err != nil || p.Empty() {
		t.Fatal(err, p.Empty())
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := a.SetBlocked(ctx, []string{"aa:bb:cc:dd:ee:ff"}); err != nil {
		t.Fatal(err)
	}
	if err := a.LED(ctx, LEDLocate); err != nil {
		t.Fatal(err)
	}
	if err := a.Rollback(ctx); err != nil && !errors.Is(err, ErrNoBaseline) {
		t.Fatal(err)
	}
	if m := f.mutating(); len(m) != 0 {
		t.Fatalf("dry run mutated: %v", m)
	}
	if _, err := os.Stat(f.path("/tmp/udeco")); err == nil {
		t.Error("dry run wrote RunDir")
	}
}

func TestApplyFailureHandsBackToTPLink(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	f.failOn = func(argv []string) bool {
		return argv[0] == "hostapd" && strings.Contains(argv[len(argv)-1], "hapd-wl1")
	}
	p, err := a.Plan(ctx, twoSSIDs())
	if err != nil {
		t.Fatal(err)
	}
	err = a.Apply(ctx, p)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("Apply = %v, want rolled back", err)
	}
	// TP-Link's hostapd is back with its own argv and conf, and the state is
	// the captured baseline.
	if !f.called("hostapd -B -P /tmp/wl0.1_hapd.pid /tmp/wl0.1_hapd.conf") || !f.called("hostapd -B -P /tmp/wl1.1_hapd.pid /tmp/wl1.1_hapd.conf") {
		t.Error("TP-Link hostapd not restarted")
	}
	for vif, br := range map[string]string{"wl02": "br-lan", "wl12": "br-lan", "wl13": "br-lan", "wl03": "", "wl01": ""} {
		if got := f.bridgeOf(vif); got != br {
			t.Errorf("%s bridge %q, want %q", vif, got, br)
		}
	}
	for vif, want := range map[string]string{"wl01": "up", "wl11": "up", "wl02": "up", "wl03": "down", "wl05": "down"} {
		if got := f.state[vif+" bss"]; got != want {
			t.Errorf("%s bss %q, want %q", vif, got, want)
		}
	}
	if a.netdevExists("br-v20") || a.netdevExists("eth1.20") {
		t.Error("VLAN bridge left behind")
	}
	if _, err := os.Stat(f.path("/tmp/udeco/hapd-wl0.conf")); err == nil {
		t.Error("agent conf left behind")
	}
	if _, err := os.Stat(f.path("/tp_data/udeco/state/last-good.json")); err == nil {
		t.Error("failed apply saved last-good")
	}
	if !f.called("wl -i wl02 closednet 0") || !f.called("wl -i wl02 rrm 0x33") {
		t.Error("baseline iovars not restored")
	}
}

func TestApplyFailureRestoresLastGood(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	good := twoSSIDs()
	p, _ := a.Plan(ctx, good)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	bad := twoSSIDs()
	bad.SSIDs[1].SSID = "Renamed"
	f.failOn = func(argv []string) bool {
		return argv[0] == "hostapd_cli" && argv[len(argv)-1] == "ping" && f.state["wl12 ssid"] == "Renamed"
	}
	p2, err := a.Plan(ctx, bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, p2); err == nil {
		t.Fatal("Apply succeeded with failing verify")
	}
	f.failOn = nil
	if err := a.Verify(ctx, good); err != nil {
		t.Fatalf("not back on last-good: %v", err)
	}
	if f.state["wl12 ssid"] != "Example Network" {
		t.Errorf("wl12 ssid %q", f.state["wl12 ssid"])
	}
	if p, _ := a.Plan(ctx, good); !p.Empty() {
		t.Errorf("plan after rollback not empty:\n%s", p)
	}
}

// Without a baseline TP-Link's hostapd is restarted from its conf where it
// is not running, and only there: a restart that is not needed is no error.
func TestRollbackWithoutBaseline(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	f.killProc(10912, true) // wl1's
	err := a.Rollback(context.Background())
	if !errors.Is(err, ErrNoBaseline) {
		t.Fatalf("Rollback = %v", err)
	}
	if !f.called("hostapd -B -P /tmp/wl1.1_hapd.pid /tmp/wl1.1_hapd.conf") {
		t.Error("TP-Link hostapd not restarted")
	}
	if f.called("hostapd -B -P /tmp/wl0.1_hapd.pid /tmp/wl0.1_hapd.conf") {
		t.Error("running TP-Link hostapd on wl0 restarted")
	}
	if !f.netdevExists("wl12") || f.procs[10510] == nil {
		t.Error("TP-Link Wi-Fi not running after the hand-back")
	}
}

func TestRadioChanges(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	d.Country = "CA"
	d.Radios["na"] = Radio{Enabled: true, Channel: 149, Width: 40, TxPowerMode: "custom", TxPower: 20}
	p, err := a.Plan(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	down := stepIndex(t, p, "wl -i wl1 down")
	co := stepIndex(t, p, "wl -i wl1 country CA/2")
	bw := stepIndex(t, p, "wl -i wl1 bw_cap 5g 3")
	cs := stepIndex(t, p, "wl -i wl1 chanspec 149l")
	// the new chanspec and country's limit is read after the move (no
	// degrade until then: the next plan sets custom 20 dBm live)
	tx := stepIndex(t, p, "wl -i wl1 txpwr_degrade 0")
	up := stepIndex(t, p, "wl -i wl1 up")
	if !(down < co && co < bw && bw < cs && cs < tx && tx < up) {
		t.Errorf("PHY order %d %d %d %d %d %d", down, co, bw, cs, tx, up)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "boardflags4") {
		t.Errorf("no kernel-nvram note for non-US country: %v", p.Notes)
	}
}

func TestSetBlockedAndKick(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	if err := a.Kick(ctx, "aa:bb:cc:dd:ee:ff"); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("Kick before takeover = %v", err)
	}
	d := twoSSIDs()
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	f.reset()
	if err := a.SetBlocked(ctx, []string{"AA-BB-CC-DD-EE-FF", "junk"}); err != nil {
		t.Fatal(err)
	}
	deny, err := os.ReadFile(f.path("/tmp/udeco/wl12.deny"))
	if err != nil || strings.TrimSpace(string(deny)) != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("deny file %q %v", deny, err)
	}
	for _, want := range []string{
		"hostapd_cli -p /var/run/udeco-hostapd -i wl12 DENY_ACL ADD_MAC aa:bb:cc:dd:ee:ff",
		"wl -i wl03 macmode 1",
		"wl -i wl03 mac aa:bb:cc:dd:ee:ff",
		"hostapd_cli -p /var/run/udeco-hostapd -i wl02 deauthenticate aa:bb:cc:dd:ee:ff",
	} {
		if !f.called(want) {
			t.Errorf("missing call %q", want)
		}
	}
	if p, _ := a.Plan(ctx, d); !p.Empty() {
		t.Errorf("plan after SetBlocked not empty:\n%s", p)
	}
	// A fresh Applier (agent restart) keeps the list from RunDir.
	b := newTestApplier(f, false)
	if got := b.loadBlocked(); len(got) != 1 || got[0] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("reloaded block list %v", got)
	}
	if p, _ := b.Plan(ctx, d); !p.Empty() {
		t.Errorf("plan from fresh applier not empty:\n%s", p)
	}
	if err := a.Kick(ctx, "not-a-mac"); err == nil {
		t.Error("Kick accepted a bad MAC")
	}
}

func TestLED(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	ctx := context.Background()
	for _, m := range []string{LEDOn, LEDOff, LEDLocate, LEDLocateOff} {
		if err := a.LED(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	got := f.mutating()
	want := []string{
		`ubus call leds conn {"state":"online"}`, // conn-indicator is stopped: clear its last state
		`ubus call leds off {"state":"done"}`,
		`ubus call leds off {"state":"off"}`,
		`ubus call leds off {"state":"done"}`,
		`ubus call leds zigbee {"state":"identifying"}`,
		`ubus call leds zigbee {"state":"done"}`,
		`ubus call leds off {"state":"off"}`,
	}
	if len(got) != len(want) {
		t.Fatalf("calls %v", got)
	}
	for i := range want {
		if strings.Join(got[i], " ") != want[i] {
			t.Errorf("call %d = %q, want %q", i, strings.Join(got[i], " "), want[i])
		}
	}
	if err := a.LED(ctx, "disco"); err == nil {
		t.Error("bad mode accepted")
	}
}

// upAfterLastDown reports whether "wl -i radio up" was called after the
// last "wl -i radio down".
func upAfterLastDown(f *fakeDev, radio string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	up := true
	for _, c := range f.calls {
		switch strings.Join(c, " ") {
		case "wl -i " + radio + " down":
			up = false
		case "wl -i " + radio + " up":
			up = true
		}
	}
	return up
}

// A PHY step that fails between "wl down" and "wl up" must not leave the
// radio down: neither the last-good re-apply nor the hand-back sees a PHY
// difference (the failed setter changed nothing), so both must raise it.
func TestPHYFailureLeavesRadioUp(t *testing.T) {
	ctx := context.Background()
	for _, withLastGood := range []bool{false, true} {
		t.Run(fmt.Sprintf("lastgood=%t", withLastGood), func(t *testing.T) {
			f := newFakeDev(t)
			a := newTestApplier(f, false)
			if withLastGood {
				p, _ := a.Plan(ctx, twoSSIDs())
				if err := a.Apply(ctx, p); err != nil {
					t.Fatal(err)
				}
			}
			d := twoSSIDs()
			d.Country = "CA"
			f.failOn = func(argv []string) bool {
				return strings.Join(argv, " ") == "wl -i wl1 country CA/2"
			}
			p, err := a.Plan(ctx, d)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.Apply(ctx, p); err == nil {
				t.Fatal("Apply succeeded with a failing country step")
			}
			if !f.called("wl -i wl1 down") {
				t.Fatal("test did not take wl1 down")
			}
			if !upAfterLastDown(f, "wl1") {
				t.Error("wl1 left down after rollback")
			}
			if !upAfterLastDown(f, "wl0") {
				t.Error("wl0 left down after rollback")
			}
		})
	}
}

// A context cancelled during Apply (agent shutdown, request deadline) must
// not cancel the rollback: TP-Link's hostapd was already stopped.
func TestApplyRollbackSurvivesCancelledContext(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := a.Plan(ctx, twoSSIDs())
	if err != nil {
		t.Fatal(err)
	}
	f.failOn = func(argv []string) bool {
		if argv[0] == "hostapd" && strings.Contains(argv[len(argv)-1], "hapd-wl0") {
			cancel()
		}
		return false
	}
	if err := a.Apply(ctx, p); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("Apply = %v, want rolled back", err)
	}
	// The apply stopped on wl0, before wl1's TP-Link hostapd was stopped:
	// wl0's is restarted and raised, wl1's is left running (F7).
	if !f.called("hostapd -B -P /tmp/wl0.1_hapd.pid /tmp/wl0.1_hapd.conf") {
		t.Error("TP-Link hostapd on wl0 not restarted after a cancelled apply")
	}
	if f.called("hostapd -B -P /tmp/wl1.1_hapd.pid /tmp/wl1.1_hapd.conf") {
		t.Error("TP-Link hostapd on wl1 restarted though it never stopped")
	}
	for _, v := range []string{"wl02", "wl12"} {
		if got := f.state[v+" bss"]; got != "up" {
			t.Errorf("%s bss %q after hand-back, want up", v, got)
		}
	}
}

// The hand-back is best effort: a failed restore step must not stop
// TP-Link's hostapd from being restarted.
func TestHandbackContinuesPastFailures(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	f.failOn = func(argv []string) bool {
		j := strings.Join(argv, " ")
		return j == "wl -i wl0 chanspec 2l" || argv[0] == "hostapd" && strings.Contains(argv[len(argv)-1], "hapd-wl1")
	}
	p, _ := a.Plan(ctx, twoSSIDs())
	err := a.Apply(ctx, p)
	if err == nil || !strings.Contains(err.Error(), "chanspec") {
		t.Fatalf("Apply = %v, want the failed chanspec restore reported", err)
	}
	for _, want := range []string{
		"hostapd -B -P /tmp/wl0.1_hapd.pid /tmp/wl0.1_hapd.conf",
		"hostapd -B -P /tmp/wl1.1_hapd.pid /tmp/wl1.1_hapd.conf",
	} {
		if !f.called(want) {
			t.Errorf("hand-back stopped early: no %q", want)
		}
	}
	if !upAfterLastDown(f, "wl0") {
		t.Error("wl0 left down")
	}
}

// Block-list changes on an allow-list SSID must not CLEAR hostapd's accept
// list (that disassociates every station), only add and remove the
// difference.
func TestSetBlockedAllowListByDifference(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	d.SSIDs[1].MACFilter = &MACFilter{Policy: "allow", MACs: []string{"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"}}
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	f.reset()
	if err := a.SetBlocked(ctx, []string{"aa:bb:cc:00:00:02"}); err != nil {
		t.Fatal(err)
	}
	if f.called("CLEAR") {
		t.Error("SetBlocked cleared a hostapd ACL")
	}
	for _, want := range []string{
		"-i wl12 ACCEPT_ACL DEL_MAC aa:bb:cc:00:00:02",
		"-i wl12 DENY_ACL ADD_MAC aa:bb:cc:00:00:02",
		"-i wl03 DENY_ACL ADD_MAC aa:bb:cc:00:00:02",
	} {
		if !f.called(want) {
			t.Errorf("missing %q", want)
		}
	}
	if f.called("ACCEPT_ACL ADD_MAC aa:bb:cc:00:00:01") {
		t.Error("unchanged accept entry re-added")
	}
	f.reset()
	if err := a.SetBlocked(ctx, nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"-i wl12 ACCEPT_ACL ADD_MAC aa:bb:cc:00:00:02",
		"-i wl12 DENY_ACL DEL_MAC aa:bb:cc:00:00:02",
	} {
		if !f.called(want) {
			t.Errorf("missing %q", want)
		}
	}
	if p, _ := a.Plan(ctx, d); !p.Empty() {
		t.Errorf("plan after unblock not empty:\n%s", p)
	}
}

// Duplicate WLAN ids: the served (first) SSID keeps its own passphrase
// through last-good storage.
func TestSecretsDuplicateIDs(t *testing.T) {
	d := Desired{SSIDs: []SSID{
		{ID: "x", SSID: "A", Passphrase: "first-passphrase"},
		{ID: "x", SSID: "B", Passphrase: "second-passphrase"},
	}}
	pub, sec := splitSecrets(d)
	joinSecrets(&pub, sec)
	if pub.SSIDs[0].Passphrase != "first-passphrase" {
		t.Errorf("first SSID got %q", pub.SSIDs[0].Passphrase)
	}
}

// With RADIUS MAC authentication (macaddr_acl=2) hostapd loads no accept
// list and checks its accept list before RADIUS: an ACCEPT_ACL entry would
// admit the station without asking RADIUS. Unblocking a station on such an
// allow-list SSID must therefore update only the driver's allow list.
func TestSetBlockedMACAuthAllowListSkipsHostapdAccept(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	d.SSIDs[1].Radius = &Radius{MACAuth: true, Auth: []RadiusServer{{IP: "192.0.2.10", Port: 1812, Secret: testSecret}}}
	d.SSIDs[1].MACFilter = &MACFilter{Policy: "allow", MACs: []string{"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"}}
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := a.SetBlocked(ctx, []string{"aa:bb:cc:00:00:02"}); err != nil {
		t.Fatal(err)
	}
	f.reset()
	if err := a.SetBlocked(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if f.called("-i wl12 ACCEPT_ACL") {
		t.Error("ACCEPT_ACL sent to a RADIUS MAC-auth BSS: the station would skip RADIUS")
	}
	if !f.called("-i wl12 DENY_ACL DEL_MAC aa:bb:cc:00:00:02") {
		t.Error("unblock did not lift the deny entry")
	}
	if !f.called("wl -i wl12 mac") {
		t.Error("driver allow list not updated")
	}
}

// A per-band country override sets that radio's driver country alone: the
// X20 runs 2.4 GHz as US (24 dBm) beside 5 GHz in IN/288 (DFS, 23.5-25 dBm
// on 100-144), verified on .232 2026-11-20.
func TestBandCountry(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	d.Country = "CA"
	d.BandCountry = map[string]string{"ng": "US"} // the fake's radios read US
	d.Radios["na"] = Radio{Enabled: true, Channel: 149, Width: 40}
	p, err := a.Plan(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	stepIndex(t, p, "wl -i wl1 country CA/2")
	for _, s := range p.Steps {
		if strings.HasPrefix(strings.Join(s.Argv, " "), "wl -i wl0 country") {
			t.Errorf("2.4 GHz country changed under its US override: %v", s.Argv)
		}
	}
	d.Country = "US"
	d.BandCountry = map[string]string{"ng": "CA"}
	if p, err = a.Plan(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	stepIndex(t, p, "wl -i wl0 country CA/2")
	for _, s := range p.Steps {
		if strings.HasPrefix(strings.Join(s.Argv, " "), "wl -i wl1 country") {
			t.Errorf("5 GHz country changed with only a 2.4 GHz override: %v", s.Argv)
		}
	}
}
