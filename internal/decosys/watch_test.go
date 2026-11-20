package decosys

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	ipBin      = "/usr/sbin/ip"
	tcBin      = "/usr/sbin/tc"
	logreadBin = "/sbin/logread"
	addrShow   = ipBin + " -o -4 addr show dev br-lan"
	qdiscShow  = tcBin + " qdisc show dev br-lan"
	logreadCmd = logreadBin + " -l 200"
)

// ipLine renders one 'ip -o -4 addr show' line as on .205.
func ipLine(cidr string) string {
	return "15: br-lan    inet " + cidr + " brd 192.168.0.255 scope global br-lan\\       valid_lft forever preferred_lft forever\n"
}

// watchUnit is a quiet, taken-over 205 with the watch tools present.
func watchUnit(t *testing.T) (*fakeUnit, *fakeRun, *Manager) {
	t.Helper()
	u := newUnit(t, "205")
	u.setProcs(keepProcs(readProcsFixture(t, "205"), "192.168.0.1"))
	u.write("etc/crontabs/root", "* * * * * sh /data/persist_shell.sh\n")
	u.write("etc/config/firewall", "config include\n    option type 'script'\n    option path '/data/persist_shell.sh'\n")
	u.write("tmp/work_mode", `{"work_mode":"RE"}`)
	for _, b := range []string{ipBin, tcBin, logreadBin} {
		u.write(b[1:], "")
	}
	r := newFakeRun()
	m := New(Options{Root: u.root, Run: r, ControllerIP: "192.168.0.1", GatewayIP: "192.168.0.1",
		LANCIDR: "192.168.0.0/24", UnitIP: "192.168.0.205"})
	m.triggersClean, m.triggersAt = true, time.Now()
	return u, r, m
}

func kinds(fs []Finding) []string {
	var k []string
	for _, f := range fs {
		k = append(k, f.Kind)
	}
	return k
}

// R8a: the lan default 192.168.0.1/22 (the gateway's own address) is
// deleted; the lease stays.
func TestAddrWatchDeletesAlias(t *testing.T) {
	_, r, m := watchUnit(t)
	r.on(addrShow, ipLine("192.168.0.205/24")+ipLine("192.168.0.1/22"), nil)
	r.on(addrShow, ipLine("192.168.0.205/24"), nil)
	rep, err := m.Enforce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{addrShow, qdiscShow, logreadCmd,
		ipBin + " addr del 192.168.0.1/22 dev br-lan", addrShow})
	if !slices.Contains(kinds(rep.Foreign), KindAddr) || m.Counts()[KindAddr] != 1 {
		t.Errorf("foreign %v counts %v", rep.Foreign, m.Counts())
	}
}

// If deleting the alias took the lease with it, the lease is re-added.
func TestAddrWatchReaddsLease(t *testing.T) {
	_, r, m := watchUnit(t)
	r.on(addrShow, ipLine("192.168.0.1/22")+ipLine("192.168.0.205/24"), nil)
	r.on(addrShow, "", nil)
	if _, err := m.Enforce(context.Background()); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{addrShow, qdiscShow, logreadCmd,
		ipBin + " addr del 192.168.0.1/22 dev br-lan", addrShow,
		ipBin + " addr add 192.168.0.205/24 brd + dev br-lan"})
}

// Without the lease on br-lan (or with no UnitIP) only the gateway's own
// address goes: deleting anything else could cut the unit off.
func TestAddrWatchLockoutSafe(t *testing.T) {
	for _, unitIP := range []string{"", "192.168.0.99"} {
		_, r, m := watchUnit(t)
		m.o.UnitIP = unitIP
		r.on(addrShow, ipLine("192.168.0.205/24")+ipLine("10.0.0.5/8")+ipLine("192.168.0.1/22"), nil)
		rep, err := m.Enforce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var dels []string
		for _, c := range r.take() {
			if strings.Contains(c, " addr del ") || strings.Contains(c, " addr add ") {
				dels = append(dels, c)
			}
		}
		diff(t, dels, []string{ipBin + " addr del 192.168.0.1/22 dev br-lan"})
		if hasUnit := slices.Contains(kinds(rep.Foreign), WatchUnitIP); hasUnit != (unitIP != "") {
			t.Errorf("UnitIP %q: foreign %v", unitIP, rep.Foreign)
		}
	}
}

// Lease-change race and a lease that is really the gateway's alias: an
// address inside LANCIDR other than the gateway's/controller's is never
// deleted, one outside it is (while the lease is on br-lan), and a UnitIP
// equal to the gateway's or controller's address is never taken as the
// lease (it would keep TP-Link's 192.168.0.1/22 and delete the real lease).
func TestAddrWatchLeaseRace(t *testing.T) {
	cases := []struct {
		name, unitIP, addrs string
		want                []string
	}{
		{"new lease not told yet", "192.168.0.205", ipLine("192.168.0.205/24") + ipLine("192.168.0.77/24"), nil},
		{"outside the LAN", "192.168.0.205", ipLine("192.168.0.205/24") + ipLine("10.0.0.5/8"),
			[]string{ipBin + " addr del 10.0.0.5/8 dev br-lan"}},
		{"UnitIP is the gateway's", "192.168.0.1", ipLine("192.168.0.1/22") + ipLine("192.168.0.205/24") + ipLine("10.0.0.5/8"),
			[]string{ipBin + " addr del 192.168.0.1/22 dev br-lan"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, r, m := watchUnit(t)
			m.o.UnitIP = tc.unitIP
			r.on(addrShow, tc.addrs, nil)
			if _, err := m.Enforce(context.Background()); err != nil {
				t.Fatal(err)
			}
			var dels []string
			for _, c := range r.take() {
				if strings.Contains(c, " addr del ") || strings.Contains(c, " addr add ") {
					dels = append(dels, c)
				}
			}
			diff(t, dels, tc.want)
		})
	}
	// a controller on another address is protected the same way
	_, r, m := watchUnit(t)
	m.o.ControllerIP, m.o.UnitIP = "192.168.0.9", "192.168.0.9"
	r.on(addrShow, ipLine("192.168.0.9/24")+ipLine("192.168.0.205/24"), nil)
	if _, err := m.Enforce(context.Background()); err != nil {
		t.Fatal(err)
	}
	var dels []string
	for _, c := range r.take() {
		if strings.Contains(c, " addr del ") {
			dels = append(dels, c)
		}
	}
	diff(t, dels, []string{ipBin + " addr del 192.168.0.9/24 dev br-lan"})
}

// R8: a udhcpd on br-lan is killed (smartipd's FAP fallback, B6); one on
// another bridge is only reported.
func TestDHCPDWatch(t *testing.T) {
	u, r, m := watchUnit(t)
	ps := keepProcs(readProcsFixture(t, "205"), "192.168.0.1")
	ps[700] = []string{"udhcpd", "-f", "/tmp/udhcpd_lan.conf"}
	ps[701] = []string{"/usr/sbin/udhcpd", "/tmp/udhcpd_guest.conf"}
	u.setProcs(ps)
	u.write("tmp/udhcpd_lan.conf", "start 192.168.0.100\nend 192.168.0.250\ninterface br-lan\nopt router 192.168.0.1\n")
	u.write("tmp/udhcpd_guest.conf", "interface br-guest\n")
	rep, err := m.Enforce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	calls := r.take()
	if !slices.Contains(calls, "/bin/kill 700") || slices.ContainsFunc(calls, func(c string) bool { return strings.Contains(c, "701") }) {
		t.Errorf("calls %q: want pid 700 killed, 701 left", calls)
	}
	k := kinds(rep.Foreign)
	if !slices.Contains(k, KindDHCPD) || !slices.Contains(k, WatchDHCPD) {
		t.Errorf("foreign kinds %v", k)
	}
	// The other bridge's server is reported once, not every pass.
	u.setProcs(map[int][]string{1: {"/sbin/procd"}, 701: ps[701], 2: {"/usr/sbin/crond"}, 3: {"/usr/bin/apsd"}, 4: {"/usr/sbin/imsnoop"}})
	rep, _ = m.Enforce(context.Background())
	if slices.Contains(kinds(rep.Foreign), WatchDHCPD) {
		t.Errorf("reported again: %v", rep.Foreign)
	}
}

// R8b: smartipd's alarm lines are reported once each; its routine lines
// (the boot alias removal) are not.
func TestSmartipLogWatch(t *testing.T) {
	_, r, m := watchUnit(t)
	l1 := "Wed Nov 18 22:23:30 2026 daemon.notice smartip: !!ip addr del!! 192.168.0.1"
	l2 := "Wed Nov 18 23:40:01 2026 daemon.notice smartip: lan ip change to another subnet, disconnect all sta"
	l3 := "Wed Nov 18 23:41:01 2026 daemon.notice smartip: ethctl eth1 phy-power down"
	r.on(logreadCmd, l1+"\n"+l2+"\n", nil)
	r.on(logreadCmd, l1+"\n"+l2+"\n"+l3+"\n", nil)
	var got []string
	for range 3 {
		rep, err := m.Enforce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range rep.Foreign {
			if f.Kind == WatchSmartIP {
				got = append(got, f.Detail)
			}
		}
	}
	diff(t, got, []string{l2, l3})
}

// R10/R19: lasting conditions are reported when they appear and when they
// clear; apsd is never restarted; an imsnoop restart and a work_mode change
// are reported; a 'wifi disconnsta' child is reported, not killed.
func TestWatchConditions(t *testing.T) {
	u, r, m := watchUnit(t)
	r.on(addrShow, ipLine("192.168.0.205/24"), nil)
	ctx := context.Background()
	if rep, _ := m.Enforce(ctx); len(rep.Foreign) != 0 {
		t.Fatalf("quiet unit reports %v", rep.Foreign)
	}
	base := keepProcs(readProcsFixture(t, "205"), "192.168.0.1")
	ps := map[int][]string{}
	for pid, argv := range base {
		if len(argv) > 0 && (filepath.Base(argv[0]) == "apsd" || filepath.Base(argv[0]) == "imsnoop") {
			continue
		}
		ps[pid] = argv
	}
	ps[900] = []string{"/usr/sbin/imsnoop", "-d", "-C", "/tmp/ims.conf"}
	ps[901] = []string{"/bin/sh", "/sbin/wifi", "disconnsta", "lan"}
	u.setProcs(ps)
	u.write("etc/config/firewall", "config include\n    option path '/etc/firewall.user'\n")
	u.write("tmp/work_mode", `{"work_mode":"HAP"}`)
	rep, err := m.Enforce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	k := kinds(rep.Foreign)
	slices.Sort(k)
	diff(t, k, []string{WatchApsd, WatchHook, WatchImsnoop, WatchProcess, WatchWorkMode})
	for _, c := range r.take() {
		if strings.Contains(c, "apsd") || strings.Contains(c, " 901") {
			t.Errorf("acted on a report-only condition: %q", c)
		}
	}
	// Unchanged: nothing new.
	if rep, _ := m.Enforce(ctx); len(rep.Foreign) != 0 {
		t.Errorf("repeated: %v", rep.Foreign)
	}
	// Cleared.
	u.setProcs(base)
	u.write("etc/config/firewall", "config include\n    option path '/data/persist_shell.sh'\n")
	rep, _ = m.Enforce(ctx)
	var cleared []string
	for _, f := range rep.Foreign {
		if f.Detail == "cleared" {
			cleared = append(cleared, f.Kind)
		}
	}
	slices.Sort(cleared)
	diff(t, cleared, []string{WatchApsd, WatchHook})
	if c := m.Counts(); c[WatchHook] != 2 || c[WatchApsd] != 2 {
		t.Errorf("counts %v", c)
	}
}

// R10: once taken over, a TP-Link daemon that comes back is stopped again
// and reported as foreign.
func TestForeignAfterTakeover(t *testing.T) {
	u, r, m := watchUnit(t)
	ctx := context.Background()
	if _, err := m.Enforce(ctx); err != nil {
		t.Fatal(err)
	}
	ps := keepProcs(readProcsFixture(t, "205"), "192.168.0.1")
	ps[4000] = []string{"/usr/sbin/nrd"}
	u.setProcs(ps)
	r.on("/bin/ubus call service list", `{"nrd":{}}`, nil)
	rep, err := m.Enforce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(rep.Foreign, func(f Finding) bool { return f.Kind == KindStop && f.Fixed && strings.Contains(f.Detail, "nrd") }) {
		t.Errorf("foreign %v", rep.Foreign)
	}
	if m.Counts()[KindStop] != 1 {
		t.Errorf("counts %v", m.Counts())
	}
}

// D13/R24: TP-Link's htb on br-lan is saved and deleted at takeover and
// replayed by Restore.
func TestQdiscTakeoverAndRestore(t *testing.T) {
	u, r, m := watchUnit(t)
	ctx := context.Background()
	// 'tc ... show dev br-lan' as read on .205.
	r.on(qdiscShow, "qdisc htb 2: root refcnt 2 r2q 10 default 202 direct_packets_stat 0\n"+
		"qdisc sfq 202: parent 2:202 limit 127p quantum 1514b depth 127 divisor 1024 perturb 10sec \n", nil)
	r.on(tcBin+" class show dev br-lan", "class htb 2:202 parent 2:2 leaf 202: prio 3 rate 1024Mbit ceil 1024Mbit burst 129408b cburst 129408b \n"+
		"class htb 2:2 root rate 317440Kbit ceil 317440Kbit burst 41267b cburst 41267b \n", nil)
	rep, err := m.Enforce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.take(), tcBin+" qdisc del dev br-lan root") || len(rep.Steps) != 1 || rep.Steps[0].Kind != KindQdisc {
		t.Fatalf("steps %v", rep.Steps)
	}
	if !strings.Contains(u.read("etc/udeco/qos.br-lan.tplink"), "class htb 2:2 root rate 317440Kbit") {
		t.Error("qdisc tree not saved")
	}

	r.set(qdiscShow, "qdisc noqueue 0: root refcnt 2 \n", nil)
	for _, b := range []string{ipt, ip6t} {
		r.on(b+" -w -C OUTPUT -j UDECO-OUT", "", errExit1)
		r.on(b+" -w -S UDECO-OUT", "", errExit1)
		r.on(b+" -w -C INPUT -j UDECO-IN", "", errExit1)
		r.on(b+" -w -S UDECO-IN", "", errExit1)
	}
	if err := m.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	var tc []string
	for _, c := range r.take() {
		if strings.HasPrefix(c, tcBin+" ") && !strings.Contains(c, " show ") {
			tc = append(tc, c)
		}
	}
	diff(t, tc, []string{
		tcBin + " qdisc add dev br-lan root handle 2: htb r2q 10 default 202",
		tcBin + " class add dev br-lan parent 2: classid 2:2 htb rate 317440Kbit ceil 317440Kbit burst 41267b cburst 41267b",
		tcBin + " class add dev br-lan parent 2:2 classid 2:202 htb prio 3 rate 1024Mbit ceil 1024Mbit burst 129408b cburst 129408b",
		tcBin + " qdisc add dev br-lan parent 2:202 handle 202: sfq limit 127 quantum 1514b depth 127 divisor 1024 perturb 10",
	})
	if _, err := os.Stat(filepath.Join(u.root, "etc/udeco/qos.br-lan.tplink")); !os.IsNotExist(err) {
		t.Error("qos record left behind")
	}
}

// A root qdisc that is not TP-Link's is reported once and left alone.
func TestQdiscOtherLeftAlone(t *testing.T) {
	_, r, m := watchUnit(t)
	r.on(qdiscShow, "qdisc prio 1: root refcnt 2 bands 3\n", nil)
	rep, err := m.Enforce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Steps) != 0 || !slices.Contains(kinds(rep.Foreign), WatchQdisc) {
		t.Errorf("steps %v foreign %v", rep.Steps, rep.Foreign)
	}
}

// R11: the wrapper replaces TP-Link's reset script at takeover, stays put,
// is re-installed when the stock script comes back, and Restore undoes it.
func TestResetButtonInstallAndRestore(t *testing.T) {
	u, r, m := watchUnit(t)
	ctx := context.Background()
	stock := "#!/bin/sh\n[ \"$ACTION\" = pressed ] && lua -e factory\n"
	u.write("etc/rc.button/reset", stock)
	if _, err := m.Enforce(ctx); err != nil {
		t.Fatal(err)
	}
	w := u.read("etc/rc.button/reset")
	if w != resetWrapper(resetBackup) || u.read("etc/udeco/reset.tplink") != stock {
		t.Fatalf("wrapper not installed / stock not saved:\n%s", w)
	}
	if fi, _ := os.Stat(filepath.Join(u.root, "etc/rc.button/reset")); fi.Mode().Perm() != 0o755 {
		t.Errorf("mode %v", fi.Mode())
	}
	if rep, _ := m.Enforce(ctx); len(rep.Steps) != 0 {
		t.Errorf("re-installed an installed wrapper: %v", rep.Steps)
	}
	u.write("etc/rc.button/reset", stock) // something restored the stock file
	rep, _ := m.Enforce(ctx)
	if len(rep.Steps) != 1 || rep.Steps[0].Kind != KindButton || m.Counts()[KindButton] != 1 {
		t.Errorf("steps %v counts %v", rep.Steps, m.Counts())
	}
	for _, b := range []string{ipt, ip6t} {
		r.on(b+" -w -C OUTPUT -j UDECO-OUT", "", errExit1)
		r.on(b+" -w -S UDECO-OUT", "", errExit1)
		r.on(b+" -w -C INPUT -j UDECO-IN", "", errExit1)
		r.on(b+" -w -S UDECO-IN", "", errExit1)
	}
	if err := m.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if u.read("etc/rc.button/reset") != stock {
		t.Error("stock script not restored")
	}
}

// The wrapper itself, run by a real shell: only a release after a hold of
// 5 s or more reaches TP-Link's script, and then as ACTION=pressed.
func TestResetWrapperScript(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "reset-ran")
	orig := filepath.Join(dir, "reset.tplink")
	if err := os.WriteFile(orig, []byte("#!/bin/sh\necho \"$ACTION\" > "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0o755)
	if err := os.WriteFile(filepath.Join(bin, "logger"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(dir, "reset")
	if err := os.WriteFile(wrapper, []byte(resetWrapper(orig)), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		env  []string
		want string
	}{
		{[]string{"ACTION=pressed", "SEEN=0"}, ""},
		{[]string{"ACTION=released", "SEEN=1"}, ""},
		{[]string{"ACTION=released", "SEEN=4"}, ""},
		{[]string{"ACTION=released"}, ""},
		{[]string{"ACTION=released", "SEEN=abc"}, ""},
		{[]string{"ACTION=released", "SEEN=5"}, "pressed"},
		{[]string{"ACTION=released", "SEEN=12"}, "pressed"},
	} {
		os.Remove(marker)
		cmd := exec.Command(sh, wrapper)
		cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin"}, c.env...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", c.env, err, out)
		}
		got, _ := os.ReadFile(marker)
		if strings.TrimSpace(string(got)) != c.want {
			t.Errorf("%v: TP-Link script got ACTION %q, want %q", c.env, strings.TrimSpace(string(got)), c.want)
		}
	}
}

// R21: flushes are scoped, and a MAC still in the bridge flow list is an
// error.
func TestFlushFlows(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	m := newManager(u, r, false)
	ctx := context.Background()
	if err := m.FlushFlows(ctx, FlowScope{Dev: "eth0"}); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), nil) // no fc: nothing to flush
	u.write("sbin/fc", "")
	u.write("proc/fcache/brlist", "Broadcom Packet Flow Cache v4.0\n00012 ... AA:BB:CC:00:11:22 wl02\n")
	if err := m.FlushFlows(ctx, FlowScope{Dev: "eth0"}); err != nil {
		t.Fatal(err)
	}
	if err := m.FlushFlows(ctx, FlowScope{MAC: "aa:bb:cc:00:11:22"}); err == nil {
		t.Error("want an error while the MAC is still in brlist")
	}
	u.write("proc/fcache/brlist", "Broadcom Packet Flow Cache v4.0\n")
	if err := m.FlushFlows(ctx, FlowScope{MAC: "AA:BB:CC:00:11:22"}); err != nil {
		t.Fatal(err)
	}
	if err := m.FlushFlows(ctx, FlowScope{}); err != nil {
		t.Fatal(err)
	}
	if err := m.FlushFlows(ctx, FlowScope{Dev: "eth0", MAC: "aa:bb:cc:00:11:22"}); err == nil {
		t.Error("want an error for two scopes")
	}
	diff(t, r.take(), []string{"/sbin/fc flush --if eth0", "/sbin/fc flush --mac aa:bb:cc:00:11:22",
		"/sbin/fc flush --mac aa:bb:cc:00:11:22", "/sbin/fc flush"})
}

// Plan does not consume edge-triggered watch state: the following Enforce
// still reports what Plan saw.
func TestPlanKeepsWatchState(t *testing.T) {
	u, r, m := watchUnit(t)
	r.on(addrShow, ipLine("192.168.0.205/24"), nil)
	u.write("etc/config/firewall", "")
	if _, err := m.Plan(context.Background()); err != nil {
		t.Fatal(err)
	}
	rep, err := m.Enforce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(kinds(rep.Foreign), WatchHook) {
		t.Errorf("foreign %v lacks the missing hook", rep.Foreign)
	}
}

// A watch that cannot read, or a watch step that fails, never fails
// Enforce: the agent owns Wi-Fi only after a clean Enforce.
func TestWatchFailuresDoNotFailEnforce(t *testing.T) {
	_, r, m := watchUnit(t)
	r.on(addrShow, ipLine("192.168.0.205/24")+ipLine("192.168.0.1/22"), nil)
	r.on(ipBin+" addr del 192.168.0.1/22 dev br-lan", "", errExit1)
	r.on(qdiscShow, "", errExit1)
	rep, err := m.Enforce(context.Background())
	if err != nil {
		t.Fatalf("Enforce = %v, want nil", err)
	}
	k := kinds(rep.Foreign)
	if !slices.Contains(k, WatchError) || !slices.ContainsFunc(rep.Foreign, func(f Finding) bool { return f.Kind == KindAddr && !f.Fixed }) {
		t.Errorf("foreign %v", rep.Foreign)
	}
	if !m.tookOver {
		t.Error("a watch failure blocked the takeover")
	}
}
