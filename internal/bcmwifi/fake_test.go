// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixtures are getter outputs captured from the Deco X20 at .205 (see
// internal/wl/testdata and docs/deco collector.md).
const fixtures = "../wl/testdata"

// fakeDev simulates the bits of a Deco the Applier touches: wl getters (from
// the fixtures) and setters (as state), a sysfs tree for netdevs and
// bridges, /proc for hostapd processes, hostapd/hostapd_cli, brctl, ip and
// kill. It never runs anything.
type fakeDev struct {
	t    *testing.T
	root string

	mu      sync.Mutex
	calls   [][]string
	state   map[string]string   // "iface iovar [arg]" -> value
	maclist map[string][]string // iface -> driver MAC filter list (upper case, as wl prints it)
	procs   map[int]*fakeHapd   // live hostapd processes
	failOn  func([]string) bool // inject a failure
	failOut string              // output of an injected failure ("" = "injected failure")
	stall   bool                // hostapd never finishes its BSS setup
	nextPid int
	eb      *fakeEbtables
	tc      map[string][]string // dev -> qdisc show lines
	tcCalls [][]string
	fcOff   bool // the flow cache is not learning (fc disable)
	noFC    bool // the unit has no fc binary
}

// TP-Link's driver deny lists as found on .205 (topology-and-tplink-scrub.md;
// placeholder MACs).
var tplinkDeny = []string{"02:00:00:00:0D:01", "02:00:00:00:0D:02", "02:00:00:00:0D:03"}

func newFakeDev(t *testing.T) *fakeDev { t.Helper(); return newFakeDevLayout(t, false) }

// newFakeDevLayout is newFakeDev with TP-Link's mesh-master hostapd layout
// when master is set (read on .241, 2026-11-19): /tmp/wlN_hapd.{conf,pid},
// interface=wlN (the primary) and bss=wlN1..wlN6, so wlN1 is created by
// that hostapd like the others.
func newFakeDevLayout(t *testing.T, master bool) *fakeDev {
	t.Helper()
	f := &fakeDev{t: t, root: t.TempDir(), state: map[string]string{}, maclist: map[string][]string{}, procs: map[int]*fakeHapd{}, nextPid: 20000,
		eb: newFakeEbtables(), tc: map[string][]string{}}
	names, err := os.ReadFile(filepath.Join(fixtures, "ls_sys_class_net.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range strings.Fields(string(names)) {
		f.mkNetdev(n)
	}
	f.write("/sys/class/net/eth1/carrier", "1\n")
	f.write("/sys/class/net/ifb0/flags", "0x82\n") // down, as on .205
	f.write("/sys/class/net/ifb1/flags", "0x82\n")
	f.write("/sys/class/net/eth0/carrier", "0\n")
	for _, p := range []string{"eth0", "eth1", "wl02", "wl12", "wl13"} {
		f.addif("br-lan", p)
	}
	// TP-Link's hostapd per radio, as on the satellite (live fact F1):
	// interface= is the radio's first vif wlN1 (hidden backhaul), then
	// bss=wlN2..wlN6, each with bssid=. The bss= vifs exist only while it
	// runs.
	for i, p := range []string{"wl0", "wl1"} {
		pid := 10510 + 402*i
		var conf strings.Builder
		base, first := "/tmp/"+p+".1_hapd", 1
		if master {
			base, first = "/tmp/"+p+"_hapd", 0
		}
		h := &fakeHapd{argv: []string{"hostapd", "-B", "-P", base + ".pid", base + ".conf"},
			pidFile: base + ".pid", ctrl: "/var/run/hostapd", ready: true}
		for j := first; j <= 6; j++ {
			v := fmt.Sprintf("%s%d", p, j)
			if j == 0 {
				v = p
			}
			if j == first {
				h.iface = v
				fmt.Fprintf(&conf, "interface=%s\ndriver=nl80211\nctrl_interface=/var/run/hostapd\n", v)
			} else {
				h.bss = append(h.bss, v)
				out, _ := f.fixture(v, []string{"cur_etheraddr"})
				fl := strings.Fields(out)
				fmt.Fprintf(&conf, "bss=%s\nbssid=%s\nctrl_interface=/var/run/hostapd\n", v, strings.ToLower(fl[len(fl)-1]))
			}
			fmt.Fprintf(&conf, "bridge=br-lan\nssid=tplink-%s\nwpa_passphrase=***\n", v)
		}
		f.write(base+".conf", conf.String())
		f.startProc(pid, h)
	}
	// Getters the collector did not capture, with the values the research
	// read on .205 (wl_bss_features.txt, wl_per_if.txt).
	for _, v := range []string{"wl02", "wl12", "wl13"} {
		f.state[v+" rrm"] = "0x33  Link_Measurement Neighbor_Report Beacon_Passive Beacon_Active"
		f.state[v+" wmf_bss_enable"] = "1"
		f.state[v+" bss_maxassoc"] = "128 (0x80)"
	}
	for _, v := range []string{"wl01", "wl11"} {
		f.state[v+" rrm"] = "0x0"
		f.state[v+" bss_maxassoc"] = "16 (0x10)"
	}
	// Driver MAC filters and dwds as read on .205 (2026-11-18): TP-Link's
	// deny lists on the client vifs, macmode 1 with an empty list on some
	// unused ones, dwds 1 on the backhaul vifs, wl04/wl14 and the primaries.
	for _, p := range []string{"wl0", "wl1"} {
		f.state[p+" macmode"] = "0"
		f.state[p+" dwds"] = "1"
		for j := 1; j <= 6; j++ {
			v := fmt.Sprintf("%s%d", p, j)
			f.state[v+" macmode"] = map[bool]string{true: "1", false: "0"}[j == 2 || j == 3 || j == 6]
			f.state[v+" dwds"] = map[bool]string{true: "1", false: "0"}[j == 1 || j == 4]
		}
	}
	f.state["wl13 macmode"] = "1"
	f.maclist["wl02"] = append([]string{}, tplinkDeny...)
	f.maclist["wl12"] = append([]string{}, tplinkDeny...)
	f.state["wl0 txpwr_degrade"] = "0"
	f.state["wl1 txpwr_degrade"] = "0"
	for _, d := range []string{"wl0", "wl1", "wl01", "wl02", "wl03", "wl04", "wl05", "wl06", "wl11", "wl12", "wl13", "wl14", "wl15", "wl16"} {
		f.tc[d] = []string{"qdisc pfifo_fast 0: root refcnt 2 bands 3"}
	}
	f.tc["br-lan"] = []string{"qdisc htb 2: root refcnt 2 r2q 10 default 202", "qdisc sfq 202: parent 2:202 limit 127p"}
	f.write("/proc/fcache/brlist", "Broadcom Packet Flow Cache v4.0\nFlowObject idle ... tx_dev\n\n")
	return f
}

// rateset is what wl prints for a rateset getter.
func fakeRateset(legacy string) string {
	return "[ " + legacy + " ]\nMCS SET : [ 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 ]\n"
}

func (f *fakeDev) path(p string) string { return filepath.Join(f.root, filepath.FromSlash(p)) }

func (f *fakeDev) write(p, s string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(f.path(p)), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(f.path(p), []byte(s), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeDev) mkNetdev(n string) {
	_ = os.MkdirAll(f.path("/sys/class/net/"+n), 0o755)
	f.write("/sys/class/net/"+n+"/flags", "0x1003\n")
	f.write("/proc/sys/net/ipv6/conf/"+n+"/disable_ipv6", "0\n")
	if strings.HasPrefix(n, "br-") {
		_ = os.MkdirAll(f.path("/sys/class/net/"+n+"/brif"), 0o755)
	}
}

func (f *fakeDev) addif(br, port string) {
	f.write("/sys/class/net/"+br+"/brif/"+port, "")
	_ = os.MkdirAll(f.path("/sys/class/net/"+port+"/brport"), 0o755)
	_ = os.Symlink("../../../devices/virtual/net/"+br, f.path("/sys/class/net/"+port+"/brport/bridge"))
	f.write("/sys/class/net/"+port+"/brport/proxyarp_wifi", "0\n")
}

func (f *fakeDev) delif(br, port string) {
	_ = os.Remove(f.path("/sys/class/net/" + br + "/brif/" + port))
	_ = os.RemoveAll(f.path("/sys/class/net/" + port + "/brport"))
}

func (f *fakeDev) bridgeOf(port string) string {
	t, err := os.Readlink(f.path("/sys/class/net/" + port + "/brport/bridge"))
	if err != nil {
		return ""
	}
	return filepath.Base(t)
}

// fakeHapd is one hostapd process.
type fakeHapd struct {
	argv    []string
	pidFile string   // -P
	iface   string   // interface=: must exist before start, survives exit
	bss     []string // bss=: created by this process, deleted when it exits
	bssids  map[string]string
	ssids   map[string]string
	ours    bool   // runs a conf from /tmp/udeco
	ctrl    string // ctrl_interface= directory
	ready   bool   // BSS setup finished (bss= vifs exist, control sockets up)
}

func (h *fakeHapd) vifs() []string { return append([]string{h.iface}, h.bss...) }

// startProc registers a running hostapd and writes its pid file. A ready
// process's bss= vifs must already exist (the boot-time TP-Link one).
func (f *fakeDev) startProc(pid int, h *fakeHapd) {
	f.write(fmt.Sprintf("/proc/%d/cmdline", pid), strings.Join(h.argv, "\x00")+"\x00")
	f.procs[pid] = h
	if h.pidFile != "" {
		f.write(h.pidFile, strconv.Itoa(pid)+"\n")
	}
	if h.ready && h.ctrl != "" {
		for _, v := range h.vifs() {
			if v != "" {
				f.write(h.ctrl+"/"+v, "")
			}
		}
	}
}

// tick lets time pass: every hostapd that started finishes its BSS setup
// now, as the real one does after `hostapd -B` has returned (the hand-back
// on .205 found wl02 missing right after the restart). Setup creates the
// bss= vifs with BSS down, netdev down and not bridged (bridge= is not
// honoured), and sets the interface= BSS down too (live fact F3).
func (f *fakeDev) tick() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, h := range f.procs {
		if h.ready || f.stall {
			continue
		}
		h.ready = true
		for _, v := range h.bss {
			f.createVif(v)
		}
		for _, v := range h.vifs() {
			f.state[v+" bss"] = "down"
			if s, ok := h.ssids[v]; ok {
				f.state[v+" ssid"] = s
			}
			if h.ctrl != "" {
				f.write(h.ctrl+"/"+v, "")
			}
		}
	}
}

// createVif makes a fresh vif as hostapd's NEW_INTERFACE does: netdev
// down, BSS down, driver defaults.
func (f *fakeDev) createVif(v string) {
	f.mkNetdev(v)
	f.write("/sys/class/net/"+v+"/flags", "0x1002\n")
	f.maclist[v] = nil
	f.tc[v] = []string{"qdisc pfifo_fast 0: root refcnt 2 bands 3"}
	for k, val := range map[string]string{"assoclist": "", "bss": "down", "dwds": "0", "macmode": "0", "closednet": "0", "ap_isolate": "0", "dhcp_unicast": "0", "wnm": "0x1",
		"bss_maxassoc": "128", "wmf_bss_enable": "0", "rrm": "0x0", "rrm_nbr_scan": "0", "fbt": "0", "fbt_mdid": "0", "fbt_ap": "0"} {
		f.state[v+" "+k] = val
	}
}

// deleteVif removes a vif hostapd created (on its exit, live fact F2).
func (f *fakeDev) deleteVif(v string) {
	if br := f.bridgeOf(v); br != "" {
		f.delif(br, v)
	}
	_ = os.RemoveAll(f.path("/sys/class/net/" + v))
	_ = os.RemoveAll(f.path("/proc/sys/net/ipv6/conf/" + v))
	for k := range f.state {
		if strings.HasPrefix(k, v+" ") {
			delete(f.state, k)
		}
	}
	delete(f.maclist, v)
	delete(f.tc, v) // qdiscs go with the netdev
}

// killProc ends a hostapd: SIGTERM removes its pid file; the bss= vifs it
// created are deleted at once, the interface= BSS goes down.
func (f *fakeDev) killProc(pid int, term bool) {
	h := f.procs[pid]
	if h == nil {
		return
	}
	_ = os.RemoveAll(f.path(fmt.Sprintf("/proc/%d", pid)))
	if term && h.pidFile != "" {
		_ = os.Remove(f.path(h.pidFile))
	}
	for _, v := range h.vifs() {
		if h.ctrl != "" {
			_ = os.Remove(f.path(h.ctrl + "/" + v))
		}
	}
	for _, v := range h.bss {
		f.deleteVif(v)
	}
	if h.iface != "" {
		f.state[h.iface+" bss"] = "down"
	}
	delete(f.procs, pid)
}

// servedBy returns the live hostapd serving vif.
func (f *fakeDev) servedBy(vif string) (int, *fakeHapd) {
	for pid, h := range f.procs {
		for _, v := range h.vifs() {
			if v == vif {
				return pid, h
			}
		}
	}
	return 0, nil
}

// fixture returns a wl getter's captured output.
func (f *fakeDev) fixture(iface string, rest []string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(fixtures, "wl_-i_"+iface+"_"+strings.Join(rest, "_")+".txt"))
	return string(b), err == nil
}

func (f *fakeDev) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	argv := append([]string{name}, args...)
	// Like exec.CommandContext: a done context runs nothing.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.calls = append(f.calls, argv)
	if f.failOn != nil && f.failOn(argv) {
		out := f.failOut
		if out == "" {
			out = "injected failure"
		}
		return []byte(out), errors.New("exit status 1")
	}
	switch name {
	case "wl":
		return f.wl(args)
	case "hostapd":
		return f.hostapd(args)
	case "hostapd_cli":
		return f.hostapdCLI(args)
	case "kill":
		pid, _ := strconv.Atoi(args[len(args)-1])
		f.killProc(pid, args[0] != "-9")
		return nil, nil
	case "brctl":
		switch args[0] {
		case "addif":
			if !f.netdevExists(args[2]) {
				return []byte("interface " + args[2] + " does not exist!\n"), errors.New("exit status 1")
			}
			if f.bridgeOf(args[2]) != "" {
				return nil, fmt.Errorf("%s already a member of a bridge", args[2])
			}
			f.addif(args[1], args[2])
		case "delif":
			if !f.netdevExists(args[2]) {
				return []byte("interface " + args[2] + " does not exist!\n"), errors.New("exit status 1")
			}
			f.delif(args[1], args[2])
		case "addbr":
			f.mkNetdev(args[1])
			f.write("/sys/class/net/"+args[1]+"/flags", "0x1002\n")
			// Linux 4.1's defaults for a new bridge
			for k, v := range map[string]string{"multicast_snooping": "1", "multicast_querier": "0", "hash_max": "512"} {
				f.write("/sys/class/net/"+args[1]+"/bridge/"+k, v+"\n")
			}
		case "delbr":
			ents, _ := os.ReadDir(f.path("/sys/class/net/" + args[1] + "/brif"))
			for _, e := range ents {
				f.delif(args[1], e.Name())
			}
			_ = os.RemoveAll(f.path("/sys/class/net/" + args[1]))
		}
		return nil, nil
	case "ip":
		// ip link add link X name D type vlan id N | ip link set D up|down | ip link del D
		switch args[1] {
		case "add":
			f.mkNetdev(args[5])
			f.write("/sys/class/net/"+args[5]+"/flags", "0x1002\n")
		case "set":
			flags := "0x1002\n"
			if args[3] == "up" {
				flags = "0x1003\n"
			}
			f.write("/sys/class/net/"+args[2]+"/flags", flags)
		case "del":
			_ = os.RemoveAll(f.path("/sys/class/net/" + args[2]))
		}
		return nil, nil
	case "ifconfig":
		if !f.netdevExists(args[0]) {
			return []byte("ifconfig: SIOCGIFFLAGS: No such device\n"), errors.New("exit status 1")
		}
		if len(args) > 1 {
			f.write("/sys/class/net/"+args[0]+"/flags", map[bool]string{true: "0x1003\n", false: "0x1002\n"}[args[1] == "up"])
		}
		return nil, nil
	case "ubus":
		return nil, nil
	case "fc":
		return f.fc(args)
	case "ebtables":
		return f.eb.run(args)
	case "tc":
		return f.tcRun(args)
	}
	return nil, fmt.Errorf("fake: unknown command %q", name)
}

// fcStatusOut is `fc status` stdout as captured on .205 (2026-11-19), with
// the learning state filled in; "OVS Flow Learning" and "MCast Learning"
// are other switches the parser must not read.
func fcStatusOut(learning string) string {
	return "\tFlow Timer Interval = 10000 millisecs\n" +
		"\tAcceleration Mode: <L3>\n" +
		"\tMCast Learning <Disabled>\n" +
		"\tHW Acceleration <Enabled> \n" +
		"\tOVS Flow Learning <Disabled> \n" +
		"\tFlow Learning " + learning + " : Max<16383>, Active<93>, Cummulative [ 172798 - 172705 ]\n"
}

// fc is the Broadcom flow cache tool as seen on .205 (2026-11-19): status
// prints the table above, enable/disable flip it and print the BLOG line.
func (f *fakeDev) fc(args []string) ([]byte, error) {
	if f.noFC {
		return nil, errors.New(`exec: "fc": executable file not found in $PATH`)
	}
	switch args[0] {
	case "status":
		return []byte(fcStatusOut(map[bool]string{false: "Enabled", true: "Disabled"}[f.fcOff])), nil
	case "enable":
		f.fcOff = false
		return []byte("Broadcom Packet Flow Cache learning via BLOG enabled.\n"), nil
	case "disable":
		f.fcOff = true
		return []byte("Broadcom Packet Flow Cache learning via BLOG disabled.\n"), nil
	}
	return nil, nil
}

func (f *fakeDev) wl(args []string) ([]byte, error) {
	if len(args) < 3 || args[0] != "-i" {
		return nil, fmt.Errorf("fake wl: bad args %v", args)
	}
	iface, rest := args[1], args[2:]
	getter := len(rest) == 1 || rest[0] == "bw_cap" && len(rest) == 2
	if !f.netdevExists(iface) {
		return []byte("wl: wl driver adapter not found\n"), errors.New("exit status 1")
	}
	switch {
	case rest[0] == "mac" && len(rest) == 1:
		var b strings.Builder
		for _, m := range f.maclist[iface] {
			fmt.Fprintf(&b, "mac %s 2\n", m)
		}
		return []byte(b.String()), nil
	case rest[0] == "mac" && rest[1] == "none":
		f.maclist[iface] = nil
		return nil, nil
	case rest[0] == "mac":
		f.maclist[iface] = append(f.maclist[iface], strings.ToUpper(rest[1]))
		return nil, nil
	case (rest[0] == "dwds" || rest[0] == "rrm") && len(rest) == 2 && f.state[fakeRadioOf(iface)+" radio"] != "down":
		// Seen on .205: the driver refuses dwds and rrm writes unless the
		// radio is down (wl down), whatever the BSS state, even when the
		// value does not change.
		return []byte("wl: Not down\n"), errors.New("exit status 211")
	case rest[0] == "twt" && (len(rest) == 1 || len(rest) == 2 && rest[1] == "enab"):
		// Seen on the Bedroom Deco 2026-11-20: `wl twt` and `wl twt enab`
		// print the radio's TWT enable state, 0 under TP-Link.
		v, ok := f.state[fakeRadioOf(iface)+" twt"]
		if !ok {
			v = "0"
		}
		return []byte(v + "\n"), nil
	case rest[0] == "twt" && len(rest) == 3 && rest[1] == "enab" && f.state[fakeRadioOf(iface)+" radio"] != "down":
		// Same day: `wl twt enab 1` is refused while the radio is up and
		// taken after `wl down`.
		return []byte("wl: Not down\n"), errors.New("exit status 211")
	case rest[0] == "twt" && len(rest) == 3 && rest[1] == "enab":
		f.state[fakeRadioOf(iface)+" twt"] = rest[2]
		return nil, nil
	case rest[0] == "twt":
		// TP-Link's `wl twt 0` form is not modelled: no test may rely on it.
		return []byte("wl: unsupported twt form\n"), errors.New("exit status 1")
	case rest[0] == "rateset" && len(rest) == 1:
		if v, ok := f.state[iface+" rateset"]; ok {
			return []byte(fakeRateset(v)), nil
		}
		if strings.HasPrefix(iface, "wl1") {
			return []byte(fakeRateset("6(b) 9 12(b) 18 24(b) 36 48 54")), nil
		}
		return []byte(fakeRateset("1(b) 2(b) 5.5(b) 6 9 11(b) 12 18 24 36 48 54")), nil
	case rest[0] == "rateset" && f.state[fakeRadioOf(iface)+" radio"] != "down":
		// Seen on the X20 2026-11-19 (r10's provision): rateset writes
		// are refused like dwds and rrm unless the radio is down.
		return []byte("wl: Not down\n"), errors.New("exit status 211")
	case rest[0] == "rateset":
		var toks []string
		for _, r := range rest[1:] {
			if strings.HasSuffix(r, "b") {
				r = strings.TrimSuffix(r, "b") + "(b)"
			}
			toks = append(toks, r)
		}
		f.state[iface+" rateset"] = strings.Join(toks, " ")
		return nil, nil
	case len(rest) == 1 && (rest[0] == "up" || rest[0] == "down"):
		// Radio up/down: every BSS keeps its own up/down state across it
		// (seen on .205).
		f.state[fakeRadioOf(iface)+" radio"] = rest[0]
		return nil, nil
	case rest[0] == "deauthenticate":
		return nil, nil
	case rest[0] == "scan":
		f.state[iface+" scans"] += "x"
		return nil, nil
	case rest[0] == "rrm_nbr_list":
		return []byte("RRM Neighbor Report List:\n" + f.state[iface+" nbr"]), nil
	case rest[0] == "rrm_nbr_del_nbr" && len(rest) == 2:
		var keep []string
		for _, l := range strings.SplitAfter(f.state[iface+" nbr"], "\n") {
			if l != "" && !strings.Contains(l, "bssid "+strings.ToUpper(rest[1])+" ") {
				keep = append(keep, l)
			}
		}
		f.state[iface+" nbr"] = strings.Join(keep, "")
		return nil, nil
	case rest[0] == "rrm_nbr_add_nbr" && len(rest) >= 6:
		// As .205 prints it (2026-11-19).
		n := func(s string) uint64 { v, _ := strconv.ParseUint(s, 0, 32); return v }
		f.state[iface+" nbr"] += fmt.Sprintf("AP %2d: bssid %s bssid_info 0x%08x reg 0x%02x channel 0x%02x phytype 0x%02x ssid  chanspec 0x0000 preference 0x00\n",
			strings.Count(f.state[iface+" nbr"], "\n")+1, strings.ToUpper(rest[1]), n(rest[2]), n(rest[3]), n(rest[4]), n(rest[5]))
		return nil, nil
	}
	if rest[0] == "country" && len(rest) == 2 {
		cc, _, _ := strings.Cut(rest[1], "/")
		f.state[iface+" country"] = fmt.Sprintf("%s (%s) SET", cc, rest[1])
		return nil, nil
	}
	if !getter {
		if len(rest) >= 2 {
			key := iface + " " + strings.Join(rest[:len(rest)-1], " ")
			f.state[key] = rest[len(rest)-1]
		}
		return nil, nil
	}
	key := iface + " " + strings.Join(rest, " ")
	if v, ok := f.state[key]; ok {
		if rest[0] == "ssid" {
			return []byte(fmt.Sprintf("Current SSID: %q\n", v)), nil
		}
		return []byte(v + "\n"), nil
	}
	if rest[0] == "closednet" {
		rest = []string{"closed"}
	}
	if out, ok := f.fixture(iface, rest); ok {
		return []byte(out), nil
	}
	if rest[0] == "fbt" {
		return []byte("0\n"), nil
	}
	return []byte("wl: Unsupported\n"), errors.New("exit status 1")
}

// hostapd -B -P pidfile conf, as the X20's hostapd behaves (live facts
// F2-F5): interface= must be an existing netdev, every bss= section needs a
// bssid=, proxy_arp=1 fails on a vif that is not a bridge port at BSS setup
// (a vif hostapd creates never is), and a vif another hostapd serves fails
// the start. A failed start removes the -P pid file (hostapd's exit path
// unlinks it even when another process wrote it). Success writes the pid
// file and returns; the BSS setup finishes later (tick).
func (f *fakeDev) hostapd(args []string) ([]byte, error) {
	if len(args) != 4 || args[0] != "-B" || args[1] != "-P" {
		return nil, fmt.Errorf("fake hostapd: bad args %v", args)
	}
	pidFile, conf := args[2], args[3]
	fail := func(msg string) ([]byte, error) {
		_ = os.Remove(f.path(pidFile))
		return []byte("Configuration file: " + conf + "\n" + msg + "\n"), errors.New("exit status 1")
	}
	cf, err := os.Open(f.path(conf))
	if err != nil {
		return fail("Could not open configuration file '" + conf + "' for reading.")
	}
	defer cf.Close()
	h := &fakeHapd{argv: append([]string{"hostapd"}, args...), pidFile: pidFile, ours: strings.HasPrefix(conf, "/tmp/udeco/"),
		bssids: map[string]string{}, ssids: map[string]string{}}
	cur := ""
	proxyARP := map[string]bool{}
	sc := bufio.NewScanner(cf)
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "interface":
			h.iface, cur = v, v
		case "bss":
			h.bss = append(h.bss, v)
			cur = v
		case "bssid":
			h.bssids[cur] = v
		case "ssid":
			h.ssids[cur] = v
		case "proxy_arp":
			proxyARP[cur] = v == "1"
		case "ctrl_interface":
			h.ctrl = v
		}
	}
	if h.iface == "" || !f.netdevExists(h.iface) {
		return fail(fmt.Sprintf("Could not read interface %s flags: No such device\nnl80211 driver initialization failed.", h.iface))
	}
	for _, v := range h.vifs() {
		if pid, _ := f.servedBy(v); pid != 0 {
			return fail(fmt.Sprintf("nl80211: Failed to create interface %s: -16 (Device or resource busy)\nInterface initialization failed", v))
		}
	}
	for _, v := range h.bss {
		if h.bssids[v] == "" {
			return fail("Invalid BSSID mask 00:00:00:00:00:00 for start address 00:00:00:00:00:00.\nStart address must be the first address in the block (i.e., addr AND mask == addr).\nUnable to setup interface.")
		}
	}
	for _, v := range h.vifs() {
		if proxyARP[v] && (v != h.iface || f.bridgeOf(v) == "") {
			return fail(v + ": Generic snooping infrastructure initialization failed\nInterface initialization failed")
		}
	}
	f.nextPid++
	f.startProc(f.nextPid, h)
	f.state[h.iface+" bss"] = "down"
	return nil, nil
}

// hostapdCLI answers ping and status on a BSS whose control socket exists.
func (f *fakeDev) hostapdCLI(args []string) ([]byte, error) {
	if len(args) < 5 || args[0] != "-p" || args[2] != "-i" {
		return nil, fmt.Errorf("fake hostapd_cli: bad args %v", args)
	}
	if _, err := os.Stat(f.path(args[1] + "/" + args[3])); err != nil {
		return []byte("Failed to connect to hostapd - wpa_ctrl_open: No such file or directory\n"), errors.New("exit status 255")
	}
	switch args[4] {
	case "ping":
		return []byte("PONG\n"), nil
	case "status":
		return []byte("state=ENABLED\nphy=" + args[3] + "\n"), nil
	}
	return []byte("OK\n"), nil
}

func (f *fakeDev) netdevExists(n string) bool {
	_, err := os.Stat(f.path("/sys/class/net/" + n))
	return err == nil
}

// tcRun models tc qdisc add/del/show on root and ingress; classes and
// filters are only recorded.
func (f *fakeDev) tcRun(args []string) ([]byte, error) {
	f.tcCalls = append(f.tcCalls, args)
	if len(args) >= 4 && args[0] == "qdisc" && args[1] == "show" {
		return []byte(strings.Join(f.tc[args[3]], "\n") + "\n"), nil
	}
	if len(args) < 4 || args[0] != "qdisc" {
		return nil, nil
	}
	dev := args[3]
	switch args[1] {
	case "add":
		if args[4] == "root" {
			f.tc[dev] = append([]string{"qdisc htb 1: root refcnt 2 r2q 10 default 1"}, withoutPrefix(f.tc[dev], "qdisc pfifo_fast")...)
		} else if args[len(args)-1] == "ingress" {
			f.tc[dev] = append(f.tc[dev], "qdisc ingress ffff: parent ffff:fff1 ----------------")
		}
	case "del":
		switch args[4] {
		case "root":
			if len(withPrefix(f.tc[dev], "qdisc htb 1: root")) == 0 {
				return []byte("RTNETLINK answers: No such file or directory"), errors.New("exit status 2")
			}
			f.tc[dev] = append([]string{"qdisc pfifo_fast 0: root refcnt 2 bands 3"}, withoutPrefix(withoutPrefix(f.tc[dev], "qdisc htb 1: root"), "qdisc pfifo_fast")...)
		case "ingress":
			f.tc[dev] = withoutPrefix(f.tc[dev], "qdisc ingress")
		}
	}
	return nil, nil
}

func withPrefix(ls []string, p string) []string {
	var out []string
	for _, l := range ls {
		if strings.HasPrefix(l, p) {
			out = append(out, l)
		}
	}
	return out
}

func withoutPrefix(ls []string, p string) []string {
	var out []string
	for _, l := range ls {
		if !strings.HasPrefix(l, p) {
			out = append(out, l)
		}
	}
	return out
}

// fakeEbtables models the filter table: chains with a policy and rules.
type fakeEbtables struct {
	chains map[string]*fakeChain
}

type fakeChain struct {
	policy string
	rules  []string // rule arguments joined by spaces, as -L prints them
}

func newFakeEbtables() *fakeEbtables {
	e := &fakeEbtables{chains: map[string]*fakeChain{}}
	for _, c := range []string{"INPUT", "FORWARD", "OUTPUT"} {
		e.chains[c] = &fakeChain{policy: "ACCEPT"}
	}
	e.chains["blacklist"] = &fakeChain{policy: "ACCEPT"} // TP-Link's, empty
	return e
}

func (e *fakeEbtables) run(args []string) ([]byte, error) {
	fail := func(msg string) ([]byte, error) { return []byte(msg), errors.New("exit status 255") }
	if len(args) < 2 {
		return fail("bad args")
	}
	c := e.chains[args[1]]
	switch args[0] {
	case "-N":
		if c != nil {
			return fail("Chain " + args[1] + " already exists.")
		}
		e.chains[args[1]] = &fakeChain{policy: "RETURN"}
	case "-X":
		if c == nil {
			return fail("Chain '" + args[1] + "' doesn't exist.")
		}
		for _, o := range e.chains {
			for _, r := range o.rules {
				if strings.HasSuffix(r, "-j "+args[1]) {
					return fail("Chain " + args[1] + " is referenced")
				}
			}
		}
		delete(e.chains, args[1])
	case "-P":
		if c == nil {
			return fail("Chain '" + args[1] + "' doesn't exist.")
		}
		c.policy = args[2]
	case "-F":
		if c == nil {
			return fail("Chain '" + args[1] + "' doesn't exist.")
		}
		c.rules = nil
	case "-A", "-I", "-D":
		if c == nil {
			return fail("Chain '" + args[1] + "' doesn't exist.")
		}
		rest := args[2:]
		if args[0] == "-I" {
			rest = args[3:]
		}
		for i, a := range rest {
			if a == "-j" && i+1 < len(rest) {
				t := rest[i+1]
				if t != "ACCEPT" && t != "DROP" && t != "RETURN" && e.chains[t] == nil {
					return fail("Chain '" + t + "' doesn't exist.")
				}
			}
		}
		r := strings.Join(rest, " ")
		switch args[0] {
		case "-A":
			c.rules = append(c.rules, r)
		case "-I":
			c.rules = append([]string{r}, c.rules...)
		case "-D":
			for i, x := range c.rules {
				if x == r {
					c.rules = append(c.rules[:i], c.rules[i+1:]...)
					return nil, nil
				}
			}
			return fail("Sorry, rule does not exist.")
		}
	case "-L":
		if c == nil {
			return fail("Chain '" + args[1] + "' doesn't exist.")
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Bridge table: filter\n\nBridge chain: %s, entries: %d, policy: %s\n", args[1], len(c.rules), c.policy)
		for _, r := range c.rules {
			// ebtables prints MACs without leading zeros.
			b.WriteString(strings.ReplaceAll(r, ":0", ":") + " \n")
		}
		return []byte(b.String()), nil
	default:
		return fail("unknown option " + args[0])
	}
	return nil, nil
}

// mutating reports the calls that change the device (not getters).
func (f *fakeDev) mutating() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]string
	for _, c := range f.calls {
		switch c[0] {
		case "wl":
			rest := c[3:]
			if len(rest) == 1 && rest[0] != "up" && rest[0] != "down" || rest[0] == "bw_cap" && len(rest) == 2 ||
				rest[0] == "twt" && len(rest) == 2 && rest[1] == "enab" {
				continue
			}
		case "hostapd_cli":
			if c[len(c)-1] == "ping" {
				continue
			}
		case "ebtables":
			if c[1] == "-L" {
				continue
			}
		case "tc":
			if len(c) > 2 && c[2] == "show" {
				continue
			}
		case "fc":
			if c[1] == "status" {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func (f *fakeDev) called(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), sub) {
			return true
		}
	}
	return false
}

func (f *fakeDev) reset() {
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
}

func newTestApplier(f *fakeDev, dry bool) *Applier {
	a := New(Options{Root: f.root, Run: f, DryRun: dry, Logf: f.t.Logf, VerifyTimeout: 4 * time.Second})
	a.sleep = func(time.Duration) { f.tick() }
	return a
}

// fakeRadioOf is the radio netdev of a vif ("wl02" -> "wl0").
func fakeRadioOf(iface string) string {
	if len(iface) > 3 {
		return iface[:3]
	}
	return iface
}
