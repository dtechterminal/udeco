// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/dtechterminal/udeco/internal/unit"
)

// liveRadio is the PHY state read with wl getters.
type liveRadio struct {
	Primary   string
	Chanspec  chanspec
	Country   country
	Degrade   int
	BWCap     int
	TargetMax float64
	MAC       liveMAC // the primary's driver MAC filter
	TWT       int     // wl twt enab: 0 or 1, -1 when unreadable (twt.go)
	// Drv: the radio-wide driver settings the agent holds at a U6 Pro's
	// value, by iovar (unread when a getter failed; parity.go).
	Drv map[string]int
}

// liveMAC is a driver MAC filter as read back (wl macmode, wl mac).
type liveMAC struct {
	Known bool // both getters answered
	Mode  int
	List  []string // sorted
}

// matches reports whether the live filter is exactly mode with list.
func (m liveMAC) matches(mode int, list []string) bool {
	if !m.Known || m.Mode != mode || len(m.List) != len(list) {
		return false
	}
	want := append([]string(nil), list...)
	sort.Strings(want)
	for i := range want {
		if want[i] != m.List[i] {
			return false
		}
	}
	return true
}

// liveVif is one vif's BSS, bridge and driver state.
type liveVif struct {
	Exists bool // the netdev exists (a bss= vif exists only while its hostapd runs)
	Up     bool
	Bridge string // "" when not a bridge port
	MAC    liveMAC
	DWDS   int    // -1 when unreadable
	Rates  string // canonical legacy rateset (Options.MinRates only)
	// DHCPUnicast: wl dhcp_unicast, -1 when unreadable (hostapd.go
	// dhcpUnicastStep)
	DHCPUnicast int
}

// liveState is what Plan diffs against.
type liveState struct {
	Radios   map[string]*liveRadio // by primary
	Vifs     map[string]liveVif
	Ours     map[string]bool     // primary -> our hostapd alive
	OursBSS  map[string][]string // primary -> the bss= vifs our running hostapd created
	TPLink   map[string]hapdProc // primary -> live TP-Link hostapd
	VBridges []int               // existing br-v<vid> bridges
	Uplink   string
}

// tplinkPidFiles are the pid files hapdsupport uses: wlN.1 on a satellite
// (the primary is a STA), wlN on the master.
func tplinkPidFiles(primary string) []string {
	return []string{"/tmp/" + primary + ".1_hapd.pid", "/tmp/" + primary + "_hapd.pid"}
}

// tplinkBases are TP-Link's hostapd file stems per radio, in the order
// tplinkPidFiles uses: /tmp/wlN.1_hapd.{conf,pid} on a satellite,
// /tmp/wlN_hapd.* on the master.
func tplinkBases(primary string) []string {
	return []string{"/tmp/" + primary + ".1_hapd", "/tmp/" + primary + "_hapd"}
}

// hapdProc is a running hostapd.
type hapdProc struct {
	Pid      int
	PidFile  string   // its -P file (may be missing: PidLost)
	PidLost  bool     // the pid file is missing or names another process
	Conf     string   // its conf
	Argv     []string // its command line
	BSS      []string // the bss= vifs it created (deleted when it exits)
	Iface    string   // its interface= vif (survives its exit)
	CtrlDir  string   // ctrl_interface= of its last BSS ("" = none)
	LastBSS  string   // the last vif its conf lists
	confRead bool
}

// tplinkHostapd finds TP-Link's hostapd for a radio: by its pid file, else
// (F7: a failed second hostapd with the same -P deleted it) by a process
// whose command line names TP-Link's conf for the radio.
func (a *Applier) tplinkHostapd(primary string) (hapdProc, bool) {
	for _, base := range tplinkBases(primary) {
		if pid, ok := a.pidAlive(base+".pid", "hostapd"); ok {
			return a.hapdInfo(pid, base+".pid", base+".conf", false), true
		}
	}
	for _, base := range tplinkBases(primary) {
		if pid, ok := a.findProc("hostapd", base+".conf"); ok {
			pf := base + ".pid"
			argv := a.procArgv(pid)
			for i := 0; i+1 < len(argv); i++ {
				if argv[i] == "-P" {
					pf = argv[i+1]
				}
			}
			return a.hapdInfo(pid, pf, base+".conf", true), true
		}
	}
	return hapdProc{}, false
}

// hapdInfo describes a running hostapd, reading its conf.
func (a *Applier) hapdInfo(pid int, pidFile, conf string, lost bool) hapdProc {
	h := hapdProc{Pid: pid, PidFile: pidFile, PidLost: lost, Conf: conf, Argv: a.procArgv(pid)}
	if len(h.Argv) > 1 {
		h.Conf = h.Argv[len(h.Argv)-1]
	}
	h.hapdConf(a, h.Conf)
	return h
}

// hapdConf fills Iface, BSS, CtrlDir and LastBSS from a hostapd conf.
func (h *hapdProc) hapdConf(a *Applier, conf string) {
	b, err := a.readFile(conf)
	if err != nil {
		return
	}
	h.confRead = true
	for _, line := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "interface":
			h.Iface, h.LastBSS = v, v
		case "bss":
			h.BSS = append(h.BSS, v)
			h.LastBSS = v
		case "ctrl_interface":
			h.CtrlDir = v
		}
	}
}

// confBSSIDs reads the bss=/bssid= pairs of a hostapd conf.
func (a *Applier) confBSSIDs(conf string, into map[string]string) {
	b, err := a.readFile(conf)
	if err != nil {
		return
	}
	cur := ""
	for _, line := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "interface", "bss":
			cur = v
		case "bssid":
			if m := normMAC(v); m != "" && cur != "" {
				into[cur] = m
			}
		}
	}
}

// findProc finds a live process named name with an argument equal to arg.
func (a *Applier) findProc(name, arg string) (int, bool) {
	ents, err := os.ReadDir(a.fsPath("/proc"))
	if err != nil {
		return 0, false
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}
		argv := a.procArgv(pid)
		if len(argv) == 0 || !strings.Contains(path.Base(argv[0]), name) {
			continue
		}
		for _, x := range argv[1:] {
			if x == arg {
				return pid, true
			}
		}
	}
	return 0, false
}

// fs helpers: device paths resolved under Root.

func (a *Applier) fsPath(p string) string { return filepath.Join(a.o.Root, filepath.FromSlash(p)) }

func (a *Applier) readFile(p string) ([]byte, error) { return os.ReadFile(a.fsPath(p)) }

func (a *Applier) exists(p string) bool {
	_, err := os.Stat(a.fsPath(p))
	return err == nil
}

func (a *Applier) netdevExists(name string) bool { return a.exists("/sys/class/net/" + name) }

// bridgeOf returns the bridge port's bridge, or "".
func (a *Applier) bridgeOf(port string) string { return BridgeOf(a.o.Root, port) }

// BridgeOf returns the bridge that port is a member of on the unit whose
// filesystem is at root (the name /sys/class/net/<port>/brport/bridge
// points to), or "" when it is in none. It is the one reader of that
// link: this package's applier, internal/mtkwifi's and cmd/udeco-ap's
// gratuitous ARP use it.
func BridgeOf(root, port string) string {
	t, err := os.Readlink(filepath.Join(root, filepath.FromSlash("/sys/class/net/"+port+"/brport/bridge")))
	if err != nil {
		return ""
	}
	return path.Base(filepath.ToSlash(t))
}

// bridgePorts lists a bridge's ports.
func (a *Applier) bridgePorts(br string) []string {
	ents, err := os.ReadDir(a.fsPath("/sys/class/net/" + br + "/brif"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// pidAlive reads a pid file and reports the pid if that process is alive and
// its command line contains name.
func (a *Applier) pidAlive(pidFile, name string) (int, bool) {
	b, err := a.readFile(pidFile)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return 0, false
	}
	return pid, a.procAlive(pid, name)
}

func (a *Applier) procAlive(pid int, name string) bool {
	cl, err := a.readFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return err == nil && bytes.Contains(cl, []byte(name))
}

// procArgv returns a process's argv.
func (a *Applier) procArgv(pid int) []string {
	cl, err := a.readFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(cl), "\x00"), "\x00")
}

// wlGet runs a wl getter and returns its trimmed output.
func (a *Applier) wlGet(ctx context.Context, iface string, args ...string) (string, error) {
	out, err := a.o.Run.Run(ctx, "wl", append([]string{"-i", iface}, args...)...)
	if err != nil {
		return "", fmt.Errorf("wl -i %s %s: %w", iface, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// bssid returns a vif's MAC (cur_etheraddr), cached: the MACs are fixed.
// A bss= vif exists only while a hostapd serves it, so an absent vif's MAC
// comes from the confs and the baseline (knownBSSID).
func (a *Applier) bssid(ctx context.Context, vif string) (string, error) {
	if m, ok := a.macs[vif]; ok {
		return m, nil
	}
	if !a.netdevExists(vif) {
		if m := a.knownBSSID(vif); m != "" {
			return m, nil
		}
		return "", fmt.Errorf("%s: absent and its BSSID is not known", vif)
	}
	out, err := a.wlGet(ctx, vif, "cur_etheraddr")
	if err != nil {
		return "", err
	}
	f := strings.Fields(out)
	if len(f) == 0 || normMAC(f[len(f)-1]) == "" {
		return "", fmt.Errorf("%s: cannot parse cur_etheraddr %q", vif, out)
	}
	m := normMAC(f[len(f)-1])
	a.macs[vif] = m
	return m, nil
}

// knownBSSID returns an absent vif's BSSID from what this boot recorded:
// TP-Link's confs (bssid= per bss=, F1), the agent's conf, the baseline.
// "" when none has it. Found MACs are cached.
func (a *Applier) knownBSSID(vif string) string {
	if m, ok := a.macs[vif]; ok {
		return m
	}
	prim := vif
	if len(vif) == 4 {
		prim = vif[:3]
	}
	found := map[string]string{}
	for _, base := range tplinkBases(prim) {
		a.confBSSIDs(base+".conf", found)
	}
	a.confBSSIDs(ConfPath(a.o.RunDir, prim), found)
	if b, err := a.loadBaseline(); err == nil && b != nil {
		for _, v := range b.Vifs {
			if m := normMAC(v.BSSID); m != "" {
				found[v.Vif] = m
			}
		}
	}
	for v, m := range found {
		a.macs[v] = m
	}
	return found[vif]
}

// vifKnown reports whether a vif can be placed: it exists, or hostapd can
// create it (its BSSID is known). Primaries must exist.
func (a *Applier) vifKnown(name string) bool {
	if a.netdevExists(name) {
		return true
	}
	return vifIndex(name) > 0 && a.knownBSSID(name) != ""
}

// vBridgeRe: a VLAN bridge's name (vlanBridge), with up to four digits.
var vBridgeRe = regexp.MustCompile(`^` + regexp.QuoteMeta(unit.VLANBridgePrefix) + `([0-9]{1,4})$`)

// readLive reads the state Plan needs. Radio getters must succeed; a vif
// whose bss state cannot be read counts as up (so it is taken down).
func (a *Applier) readLive(ctx context.Context, l *layout) (*liveState, error) {
	ls := &liveState{
		Radios: map[string]*liveRadio{}, Vifs: map[string]liveVif{},
		Ours: map[string]bool{}, OursBSS: map[string][]string{}, TPLink: map[string]hapdProc{},
	}
	for _, rl := range l.Radios {
		p := rl.Primary
		if !a.netdevExists(p) {
			continue
		}
		lr := &liveRadio{Primary: p}
		out, err := a.wlGet(ctx, p, "chanspec")
		if err != nil {
			return nil, err
		}
		if lr.Chanspec, err = parseChanspec(out); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if out, err = a.wlGet(ctx, p, "country"); err != nil {
			return nil, err
		}
		lr.Country = parseCountry(out)
		if out, err = a.wlGet(ctx, p, "txpwr_degrade"); err != nil {
			return nil, err
		}
		if lr.Degrade, err = parseIntOut(out); err != nil {
			return nil, fmt.Errorf("%s txpwr_degrade %q: %w", p, out, err)
		}
		if out, err = a.wlGet(ctx, p, "bw_cap", bandArg(rl.Band)); err != nil {
			return nil, err
		}
		if lr.BWCap, err = parseIntOut(out); err != nil {
			return nil, fmt.Errorf("%s bw_cap %q: %w", p, out, err)
		}
		if out, err = a.wlGet(ctx, p, "txpwr_target_max"); err == nil {
			lr.TargetMax = parseTargetMax(out)
		}
		lr.MAC = a.readMAC(ctx, p)
		lr.TWT = a.readTWT(ctx, p)
		lr.Drv = a.readDriver(ctx, p, rl.Band)
		ls.Radios[p] = lr
		for _, v := range rl.Vifs {
			if !a.netdevExists(v) {
				ls.Vifs[v] = liveVif{DWDS: -1}
				continue
			}
			out, err := a.wlGet(ctx, v, "bss")
			lv := liveVif{Exists: true, Up: err != nil || out != "down", Bridge: a.bridgeOf(v), MAC: a.readMAC(ctx, v), DWDS: -1, DHCPUnicast: -1}
			if out, err := a.wlGet(ctx, v, "dwds"); err == nil {
				if n, err := parseIntOut(out); err == nil {
					lv.DWDS = n
				}
			}
			if out, err := a.wlGet(ctx, v, "dhcp_unicast"); err == nil {
				if n, err := parseIntOut(out); err == nil {
					lv.DHCPUnicast = n
				}
			}
			if a.o.MinRates {
				if out, err := a.wlGet(ctx, v, "rateset"); err == nil {
					lv.Rates = parseRateset(out)
				}
			}
			ls.Vifs[v] = lv
		}
		if _, ours := a.ourHostapd(p); ours {
			ls.Ours[p] = true
			var h hapdProc
			h.hapdConf(a, ConfPath(a.o.RunDir, p))
			ls.OursBSS[p] = h.BSS
			a.learnAnchor(p, h.Iface)
		}
		if tp, ok := a.tplinkHostapd(p); ok {
			ls.TPLink[p] = tp
			a.learnAnchor(p, tp.Iface)
		}
	}
	ls.VBridges = a.vlanBridges()
	return ls, nil
}

// ourHostapd finds the agent's hostapd for a radio, by its pid file or its
// conf.
func (a *Applier) ourHostapd(primary string) (int, bool) {
	if pid, ok := a.pidAlive(pidPath(a.o.RunDir, primary), "hostapd"); ok {
		return pid, true
	}
	return a.findProc("hostapd", ConfPath(a.o.RunDir, primary))
}

// readMAC reads a vif's driver MAC filter. Unknown (Known=false) when a
// getter fails: the plan then rewrites the filter.
func (a *Applier) readMAC(ctx context.Context, vif string) liveMAC {
	mode, err1 := a.wlGet(ctx, vif, "macmode")
	list, err2 := a.wlGet(ctx, vif, "mac")
	if err1 != nil || err2 != nil {
		return liveMAC{}
	}
	n, err := parseIntOut(mode)
	if err != nil {
		return liveMAC{}
	}
	l := parseMaclist(list)
	sort.Strings(l)
	return liveMAC{Known: true, Mode: n, List: l}
}

// wdsPorts lists the WDS peer netdevs (wds<radio>.<bss>.<n>) that are bridge
// ports, as TP-Link's hotplug 01-wds bridges them (audit D8).
func (a *Applier) wdsPorts() map[string]string {
	ents, err := os.ReadDir(a.fsPath("/sys/class/net"))
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "wds") {
			if br := a.bridgeOf(e.Name()); br != "" {
				out[e.Name()] = br
			}
		}
	}
	return out
}

// vlanBridges lists the br-v<vid> bridges that exist.
func (a *Applier) vlanBridges() []int {
	ents, err := os.ReadDir(a.fsPath("/sys/class/net"))
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range ents {
		if m := vBridgeRe.FindStringSubmatch(e.Name()); m != nil {
			v, _ := strconv.Atoi(m[1])
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

// SetUplink changes the wired port VLAN devices hang off; "" picks the only
// br-lan eth port with carrier again. The agent calls it when its uplink
// tracking (audit R9/D7) sees the uplink move. Nothing changes on the unit
// until the next Plan, Apply or Tick: br-v<vid> then gets <port>.<vid> and
// the old port's VLAN device is detached and deleted. A name that is not an
// interface name is ignored.
func (a *Applier) SetUplink(port string) {
	if port != "" && !ifnameOK(port) {
		a.o.Logf("bcmwifi: uplink %q is not an interface name: ignored", port)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.o.Uplink != port {
		a.o.Logf("bcmwifi: uplink %q -> %q: VLAN devices follow at the next plan", a.o.Uplink, port)
		a.o.Uplink = port
	}
}

// uplink returns Options.Uplink or the only br-lan eth port with carrier.
func (a *Applier) uplink() (string, error) {
	if a.o.Uplink != "" {
		return a.o.Uplink, nil
	}
	var up []string
	for _, p := range a.bridgePorts(unit.LANBridge) {
		if !strings.HasPrefix(p, "eth") {
			continue
		}
		if c, err := a.readFile("/sys/class/net/" + p + "/carrier"); err == nil && strings.TrimSpace(string(c)) == "1" {
			up = append(up, p)
		}
	}
	if len(up) != 1 {
		return "", fmt.Errorf("cannot pick the uplink port: br-lan eth ports with carrier: %v (set Options.Uplink)", up)
	}
	return up[0], nil
}
