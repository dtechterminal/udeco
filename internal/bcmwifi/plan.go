// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	wlcaps "github.com/dtechterminal/udeco/internal/wl" // planRadio has a local wl
)

// StepKind says what a Step does.
type StepKind int

// Step kinds.
const (
	StepCmd       StepKind = iota // run Argv
	StepWrite                     // write Data to Path with Mode (atomic)
	StepRemove                    // remove Path if present
	StepStop                      // stop the Proc whose pid is in Path, if alive
	StepBridgeAdd                 // make Port a member of Bridge (leaving any other bridge)
	StepBridgeDel                 // take Port out of whatever bridge it is in
	StepPut                       // write Data into the existing file Path in place (/proc/sys)
	StepWait                      // wait for a hostapd that just started to finish its BSS setup
)

// Step is one action of a Plan. Argv never holds a secret; Data (a hostapd
// conf) may, and is never printed or marshalled.
type Step struct {
	Kind     StepKind
	Desc     string
	Argv     []string    `json:",omitempty"`
	Path     string      `json:",omitempty"`
	Mode     os.FileMode `json:",omitempty"`
	Data     []byte      `json:"-"`
	Bridge   string      `json:",omitempty"`
	Port     string      `json:",omitempty"`
	Proc     string      `json:",omitempty"`
	Optional bool        `json:",omitempty"` // a failure is logged and Apply goes on
	// Alts (StepCmd) are run in turn when Argv fails; the first that
	// works stands in for it, and Argv is remembered as refused
	// (Applier.refused) so later plans use the alternative.
	Alts [][]string `json:",omitempty"`
	// IfPresent names the vif a lower or unbridge step acts on: when that
	// netdev does not exist (a hostapd that exited deleted it, live fact
	// F2), there is nothing to do and the step succeeds.
	IfPresent string `json:",omitempty"`
	// Match (StepStop) finds the process by an argument of its command line
	// (its conf) when the pid file is missing or stale.
	Match string `json:",omitempty"`
	// Ifaces (StepWait) must all exist as netdevs; with Path (a control
	// directory) and Port (a BSS), hostapd_cli status must also report
	// state=ENABLED.
	Ifaces []string `json:",omitempty"`
}

// String renders the step for logs; it never includes file contents.
func (s Step) String() string {
	var what string
	switch s.Kind {
	case StepCmd:
		what = strings.Join(s.Argv, " ")
	case StepWrite:
		what = fmt.Sprintf("write %s (%04o, %d bytes)", s.Path, s.Mode.Perm(), len(s.Data))
	case StepRemove:
		what = "rm -f " + s.Path
	case StepStop:
		what = fmt.Sprintf("stop %s from %s", s.Proc, s.Path)
	case StepBridgeAdd:
		what = fmt.Sprintf("brctl addif %s %s (if not a member)", s.Bridge, s.Port)
	case StepBridgeDel:
		what = fmt.Sprintf("brctl delif <bridge> %s (if bridged)", s.Port)
	case StepPut:
		what = fmt.Sprintf("echo %s > %s", strings.TrimSpace(string(s.Data)), s.Path)
	case StepWait:
		what = "until " + strings.Join(s.Ifaces, " ") + " exist"
		if s.Path != "" {
			what += fmt.Sprintf(" and hostapd_cli -p %s -i %s status reports state=ENABLED", s.Path, s.Port)
		}
	}
	if s.Match != "" {
		what += " (or the process running " + s.Match + ")"
	}
	if s.IfPresent != "" {
		what += " [if " + s.IfPresent + " exists]"
	}
	if s.Optional {
		what += " [optional]"
	}
	return s.Desc + ": " + what
}

func cmdStep(desc string, argv ...string) Step { return Step{Kind: StepCmd, Desc: desc, Argv: argv} }

func optStep(desc string, argv ...string) Step {
	s := cmdStep(desc, argv...)
	s.Optional = true
	return s
}

// onVif marks s as a step that has nothing to do when vif is absent.
func onVif(vif string, s Step) Step {
	s.IfPresent = vif
	return s
}

func writeStep(desc, path string, mode os.FileMode, data []byte) Step {
	return Step{Kind: StepWrite, Desc: desc, Path: path, Mode: mode, Data: data}
}

// Plan is the ordered list of steps that takes the unit from its live state
// to Desired. An empty Steps means nothing to do.
type Plan struct {
	Desired Desired `json:"-"` // holds passphrases and RADIUS secrets
	Steps   []Step
	Notes   []string // unsupported, clamped or skipped settings
	// Foreign lists state the agent did not set that the steps remove or
	// repair: driver MAC filter entries (TP-Link's per-client binding), WDS
	// peer ports, vifs out of their bridge, a client vif with dwds on, an
	// unused vif up, missing guest chains. One line each; MACs, no secrets.
	Foreign []string

	takeover   bool // a TP-Link hostapd was running: Apply captures a baseline first
	disruptive bool // a radio is reconciled in full (hostapd restarted)
	// cac: the radios in a DFS channel availability check (Tick leaves
	// them alone, dfs.go)
	cac []string
	// restart: the bands whose radio the plan takes down (RadioRestartBand)
	restart map[string]bool
	// twt: band -> the radio's TWT line, band+" driver" -> its driver-parity
	// line (parity.go), also in Notes (Tick logs changes)
	twt map[string]string
}

// Empty reports whether the plan changes nothing.
func (p Plan) Empty() bool { return len(p.Steps) == 0 }

// RadioRestart: the plan takes a radio down (a full reconcile, a PHY
// change, a dwds repair), so a channel change in it costs no extra outage.
func (p Plan) RadioRestart() bool {
	if p.disruptive {
		return true
	}
	for _, s := range p.Steps {
		if s.Kind == StepCmd && len(s.Argv) == 4 && s.Argv[0] == "wl" && s.Argv[3] == "down" {
			return true
		}
	}
	return false
}

// RadioRestartBand: the plan takes band's radio down (a full reconcile, a
// PHY change, a dwds repair). The auto channel pick rides only such a
// restart of the same radio (cmd/udeco-ap autochan.go).
func (p Plan) RadioRestartBand(band string) bool { return p.restart[band] }

// String lists the notes and steps, one per line, without secrets.
func (p Plan) String() string {
	var b strings.Builder
	for _, n := range p.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	for i, s := range p.Steps {
		fmt.Fprintf(&b, "%3d %s\n", i+1, s)
	}
	return b.String()
}

// Plan computes the steps that bring the unit to d. It only runs read-only
// getters and reads files; it is the same with and without DryRun.
func (a *Applier) Plan(ctx context.Context, d Desired) (Plan, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.plan(ctx, d)
}

func (a *Applier) plan(ctx context.Context, d Desired) (Plan, error) {
	l := a.layout(d)
	ls, err := a.readLive(ctx, l)
	if err != nil {
		return Plan{}, err
	}
	p := Plan{Desired: d.clone(), Notes: l.Notes, takeover: len(ls.TPLink) > 0}
	blocked := a.loadBlocked()

	// WDS peers bridged by TP-Link's hotplug (audit D8): out first.
	wds := a.wdsPorts()
	for _, port := range sortedKeys(wds) {
		p.Steps = append(p.Steps, Step{Kind: StepBridgeDel, Desc: "unbridge WDS peer " + port, Port: port})
		p.Foreign = append(p.Foreign, fmt.Sprintf("WDS peer %s in %s, unbridged", port, wds[port]))
	}

	if len(l.VLANs) > 0 {
		up, err := a.uplink()
		if err != nil {
			return Plan{}, err
		}
		ls.Uplink = up
		for _, vid := range l.VLANs {
			p.Steps = append(p.Steps, a.vlanUpSteps(up, vid)...)
		}
	}
	var caps *wlcaps.Caps
	if a.o.Caps != nil {
		if c, err := a.o.Caps(ctx); err != nil {
			p.Notes = append(p.Notes, fmt.Sprintf("hardware caps unavailable (%v): channels checked against the static table only", err))
		} else {
			caps = &c
		}
	}
	// Guest isolation before any BSS comes up (fail closed).
	gst, gforeign := a.guestSteps(l.Guest, l.guestVifs(), a.readGuest(ctx))
	p.Steps = append(p.Steps, gst...)
	p.Foreign = append(p.Foreign, gforeign...)
	// The bridge group address filter on every served vif (bga.go).
	bst, bforeign := a.bgaSteps(l.bgaVifs(), a.readBGA(ctx))
	p.Steps = append(p.Steps, bst...)
	p.Foreign = append(p.Foreign, bforeign...)
	for _, rl := range l.Radios {
		want := d.Country
		if c := d.BandCountry[rl.Band]; c != "" {
			want = c
		}
		rp, err := a.planRadio(ctx, rl, ls, blocked, want, caps)
		if err != nil {
			return Plan{}, err
		}
		p.Steps = append(p.Steps, rp.Steps...)
		p.Notes = append(p.Notes, rp.Notes...)
		if lr := ls.Radios[rl.Primary]; lr != nil {
			line := "radio " + rl.Band + ": " + twtStatus(rl.Primary, lr.TWT, !a.o.NoTWT, rp.TWTSet)
			dline := "radio " + rl.Band + ": " + rp.Driver
			p.Notes = append(p.Notes, line, dline)
			if p.twt == nil {
				p.twt = map[string]string{}
			}
			p.twt[rl.Band] = line
			p.twt[rl.Band+" driver"] = dline
		}
		p.Foreign = append(p.Foreign, rp.Foreign...)
		p.disruptive = p.disruptive || rp.Reconcile
		down := rp.Reconcile
		for _, s := range rp.Steps {
			if s.Kind == StepCmd && len(s.Argv) == 4 && s.Argv[0] == "wl" && s.Argv[2] == rl.Primary && s.Argv[3] == "down" {
				down = true
			}
		}
		if down {
			if p.restart == nil {
				p.restart = map[string]bool{}
			}
			p.restart[rl.Band] = true
		}
		if rl.Band == "na" && a.inCAC(ctx, rl.Primary) {
			p.cac = append(p.cac, rl.Primary)
			p.Notes = append(p.Notes, "radio na: DFS channel availability check in progress (no beacons until it ends)")
		}
	}
	for _, vid := range ls.VBridges {
		if !containsInt(l.VLANs, vid) {
			p.Steps = append(p.Steps, a.vlanDownSteps(vid)...)
		}
	}
	p.Steps = withFlush(p.Steps)
	return p, nil
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ifUp reports IFF_UP from sysfs flags.
func (a *Applier) ifUp(name string) bool {
	b, err := a.readFile("/sys/class/net/" + name + "/flags")
	if err != nil {
		return false
	}
	var f int
	_, err = fmt.Sscanf(strings.TrimSpace(string(b)), "0x%x", &f)
	return err == nil && f&1 == 1
}

// noIPv6 disables IPv6 on a VLAN netdev (audit X7, R25): the AP takes no
// fe80:: address and sends no DAD or MLD into the VLAN. Done when the device
// is created, before link up, or when it reads 0 later. Optional: a kernel
// without IPv6 on that device has no such file.
func (a *Applier) noIPv6(dev string, created bool) []Step {
	p := "/proc/sys/net/ipv6/conf/" + dev + "/disable_ipv6"
	if !created {
		if b, err := a.readFile(p); err != nil || strings.TrimSpace(string(b)) != "0" {
			return nil
		}
	}
	return []Step{{Kind: StepPut, Desc: "disable IPv6 on " + dev, Path: p, Data: []byte("1\n"), Optional: true}}
}

// vlanUpSteps creates <uplink>.<vid> and br-v<vid> as needed.
func (a *Applier) vlanUpSteps(uplink string, vid int) []Step {
	dev, br := fmt.Sprintf("%s.%d", uplink, vid), vlanBridge(vid)
	var st []Step
	if !a.netdevExists(dev) {
		st = append(st, cmdStep("create VLAN "+itoa(vid)+" on "+uplink,
			"ip", "link", "add", "link", uplink, "name", dev, "type", "vlan", "id", itoa(vid)))
	}
	st = append(st, a.noIPv6(dev, !a.netdevExists(dev))...)
	if !a.netdevExists(dev) || !a.ifUp(dev) {
		st = append(st, cmdStep("bring "+dev+" up", "ip", "link", "set", dev, "up"))
	}
	if !a.netdevExists(br) {
		st = append(st,
			cmdStep("create bridge "+br, "brctl", "addbr", br),
			cmdStep("disable STP on "+br, "brctl", "stp", br, "off"),
			cmdStep("zero forward delay on "+br, "brctl", "setfd", br, "0"))
	}
	st = append(st, a.noIPv6(br, !a.netdevExists(br))...)
	if a.bridgeOf(dev) != br {
		st = append(st, Step{Kind: StepBridgeAdd, Desc: "attach " + dev, Bridge: br, Port: dev})
	}
	// The uplink moved (SetUplink): the old port's VLAN device leaves the
	// bridge, or br-v<vid> would bridge the two wired ports on this VLAN.
	for _, p := range a.bridgePorts(br) {
		if p != dev && strings.HasPrefix(p, "eth") && strings.HasSuffix(p, "."+itoa(vid)) {
			st = append(st, Step{Kind: StepBridgeDel, Desc: "detach " + p + " (no longer the uplink)", Port: p},
				cmdStep("delete VLAN device "+p, "ip", "link", "del", p))
		}
	}
	st = append(st, a.snoopSteps(br, !a.netdevExists(br))...)
	if !a.netdevExists(br) || !a.ifUp(br) {
		st = append(st, cmdStep("bring "+br+" up", "ip", "link", "set", br, "up"))
	}
	return st
}

// BridgeSnoop are the IGMP/MLD snooping knobs of the agent's VLAN bridges,
// as a U6 Pro's mcsd sets them on every bridge (mcsd.conf snooping 1,
// policy flood; plugin_stop's multicast_querier 0; bridge.conf hash_max
// 2048): the bridge learns which ports want a group and floods unknown
// groups (Linux floods while no querier is seen), without querying itself.
// br-lan is TP-Link's imsnoop's and left alone; Multicast Enhancement stays
// the driver's wmf_bss_enable. The Garage's VLAN bridges take the same
// (mtkwifi snoop.go).
var BridgeSnoop = [][2]string{{"hash_max", "2048"}, {"multicast_snooping", "1"}, {"multicast_querier", "0"}}

// snoopSteps sets br's snooping knobs where they read otherwise (all of
// them for a bridge created by the plan). Optional: a kernel without
// multicast snooping has no such files, and the bridge forwards anyway.
func (a *Applier) snoopSteps(br string, created bool) []Step {
	var st []Step
	for _, k := range BridgeSnoop {
		p := "/sys/class/net/" + br + "/bridge/" + k[0]
		if !created {
			b, err := a.readFile(p)
			if err != nil || strings.TrimSpace(string(b)) == k[1] {
				continue
			}
		}
		st = append(st, Step{Kind: StepPut, Desc: "IGMP/MLD snooping on " + br, Path: p, Data: []byte(k[1] + "\n"), Optional: true})
	}
	return st
}

// vlanDownSteps removes a br-v<vid> bridge the agent no longer needs, with
// its <port>.<vid> VLAN device.
func (a *Applier) vlanDownSteps(vid int) []Step {
	br := vlanBridge(vid)
	st := []Step{
		cmdStep("bring "+br+" down", "ip", "link", "set", br, "down"),
		cmdStep("delete bridge "+br, "brctl", "delbr", br),
	}
	for _, p := range a.bridgePorts(br) {
		if strings.HasSuffix(p, "."+itoa(vid)) {
			st = append(st, cmdStep("delete VLAN device "+p, "ip", "link", "del", p))
		}
	}
	return st
}

// radioProfile re-asserts TP-Link's post-wlconf radio tweaks
// (tplink_brcm.sh wifi_features_set) while the radio is down. They persist
// in the driver, so this only matters if something reset them; failures are
// tolerated. TWT and the settings a U6 Pro holds differently are the
// exceptions: TWT on (twt enab 1, as a U6 Pro) unless the config turns it
// off, which is TP-Link's `twt 0` (twt.go), and drv, the U6 Pro's driver
// settings (parity.go planDriver: BSS Load on instead of TP-Link's
// `bssload 0`, no implicit beamforming, no 2.4 GHz vendor VHT instead of
// TP-Link's `vht_features 0x7`, power save off). Both X20 radios are HE
// (`he 1` here), so both get it.
func radioProfile(primary, band string, twt bool, drv []Step) []Step {
	wl := func(args ...string) Step {
		return optStep("radio profile "+args[0], append([]string{"wl", "-i", primary}, args...)...)
	}
	st := []Step{wl("he", "1"), twtStep(primary, twt), wl("tpc_report_ie", "0"), wl("pwr_const_ie", "0"),
		wl("sgi_tx", "-1")}
	return append(st, drv...)
}

// radioPlan is planRadio's result.
type radioPlan struct {
	Steps     []Step
	Notes     []string
	Foreign   []string
	Reconcile bool // hostapd restarted, BSSes cycled
	// TWTSet: TWT and the other radio-down driver settings are written
	// inside one of the plan's radio down/ups (twt.go, parity.go)
	TWTSet bool
	Driver string // the radio's driver-parity line (parity.go driverStatus)
}

// macDrift returns the steps that put a vif's driver MAC filter to mode/list
// when the live one differs, and a foreign line naming the entries the agent
// did not set (TP-Link's nrd/client_mgmt lists outlive the daemons, see
// topology-and-tplink-scrub.md). force rewrites it even when it matches.
func macDrift(vif string, live liveMAC, mode int, list []string, force bool) ([]Step, string) {
	if !force && live.matches(mode, list) {
		return nil, ""
	}
	var foreign string
	if live.Known {
		if extra := minus(live.List, list); len(extra) > 0 || live.Mode != mode {
			foreign = fmt.Sprintf("%s: driver MAC filter macmode %d with %d entries not set by the agent %v, reset to macmode %d", vif, live.Mode, len(extra), extra, mode)
		}
	}
	return macSteps(vif, mode, list), foreign
}

// planRadio plans one radio. A radio is either reconciled in full or, when
// hostapd and its files already match and every vif it serves exists, only
// its BSS, bridge and driver MAC filter state is fixed up live.
//
// The full reconcile follows what the X20's hostapd does (live facts
// F2-F6): every existing vif goes BSS down while its hostapd still runs;
// the hostapd stops, which deletes its bss= vifs, so nothing is done to
// them afterwards; the survivor wlN1 is unbridged, MAC-flushed and gets
// dwds 0 (best effort); PHY, files; our hostapd starts and the plan waits
// for its BSS setup; the placeholder is kept down; then per SSID vif:
// driver iovars (BSS down), brctl addif, proxyarp_wifi, ifconfig up, wl bss
// up.
//
// The driver MAC filter of every existing vif and of the primary is
// compared with the live driver, not only with drv-wlN.json (scrub
// requirement 3); at takeover TP-Link's filters go with the deleted vifs and
// are flushed on the primary and wlN1 (requirement 2).
func (a *Applier) planRadio(ctx context.Context, rl *radioLayout, ls *liveState, blocked []string, wantCountry string, caps *wlcaps.Caps) (radioPlan, error) {
	var rp radioPlan
	p := rl.Primary
	lr := ls.Radios[p]
	if lr == nil {
		return rp, nil
	}
	note := func(s string) { rp.Notes = append(rp.Notes, "radio "+rl.Band+": "+s) }
	foreign := func(s string) {
		if s != "" {
			rp.Foreign = append(rp.Foreign, s)
		}
	}

	// PHY.
	var phy []Step
	wl := func(desc string, args ...string) Step {
		return cmdStep(desc, append([]string{"wl", "-i", p}, args...)...)
	}
	cs := lr.Chanspec
	a.setLiveChannel(rl.Band, cs.Ctrl)
	// hapdCh is the channel hostapd's conf names. While a radar move is
	// followed it stays the wanted DFS channel (written as 36, hostapd.go),
	// whatever channel the driver chose: a conf that followed the driver
	// (149/80 under IN/288) would differ from the running one and turn
	// every Tick into a NeedsApply and every provision into a hostapd
	// restart until the dfs-reset.
	hapdCh := 0
	cc := lr.Country.Code
	if wantCountry != "" {
		arg, same := countryArg(wantCountry, lr.Country)
		cc = NormCountry(wantCountry)
		fb := countryFallback[cc]
		if fb != "" && a.refused["wl -i "+p+" country "+arg] {
			note(fmt.Sprintf("country %s refused by the driver: running %s (the driver's own rev)", arg, fb))
			arg, same = fb, lr.Country.Code == cc
			fb = ""
		}
		if !same {
			cst := wl("set country "+arg, "country", arg)
			if fb != "" {
				cst.Alts = [][]string{{"wl", "-i", p, "country", fb}}
			}
			phy = append(phy, cst)
			if cc != "US" {
				note("country " + cc + ": TP-Link also writes boardflags4/ED thresholds to kernel nvram for non-US; the agent never does")
			}
		}
	}
	degrade := lr.Degrade
	if rl.Radio.Enabled && rl.HasCfg {
		// The driver's channel list holds for the country it was read in.
		var bc *wlcaps.BandCaps
		if caps != nil {
			if b, ok := caps.Bands[rl.Band]; !ok {
				note("no hardware caps for this band: static channel table only")
			} else if cc == "" || !strings.EqualFold(caps.Country, cc) {
				note(fmt.Sprintf("hardware caps are for country %q, not %q: static channel table only", caps.Country, cc))
			} else {
				bc = &b
			}
		}
		want, change, n := desiredChanspec(rl.Band, rl.Radio, lr.Chanspec, bc)
		rp.Notes = append(rp.Notes, n...)
		if rl.Band == "na" && change && NoRadarCountry(cc) && weatherRadar(want) {
			note(fmt.Sprintf("%s covers the weather-radar band (5600-5650 MHz) and country %s runs no radar detection: keeping %s", want, cc, lr.Chanspec))
			want, change = lr.Chanspec, false
		}
		if rl.Band == "na" && want != lr.Chanspec && want.dfs() {
			// radar: follow the driver's move (dfs.go)
			if moved, n := a.followRadar(ctx, p, want, lr.Chanspec); moved {
				note(n)
				hapdCh = want.Ctrl
				change, want = false, lr.Chanspec
			}
		}
		if change && want.dfs() && lr.Drv["spect"] != 1 {
			// 802.11h before the DFS chanspec (dfs.go)
			phy = append(phy, wl("802.11h on for DFS", "spect", "1"))
		}
		if change {
			if bw := bwCap(want.Width); bw != lr.BWCap {
				phy = append(phy, wl("set bw_cap", "bw_cap", bandArg(rl.Band), itoa(bw)))
			}
			phy = append(phy, wl("set chanspec "+want.String(), "chanspec", want.String()))
			cs = want
		}
		ceil, n1, measure := a.txCeiling(p, lr.Country.Code, lr.Chanspec, cc, cs, lr.Degrade, lr.TargetMax)
		if n1 != "" {
			note(n1)
		}
		q, n2 := txpwrDegrade(rl.Radio, ceil)
		if measure {
			q = 0 // the next plan reads the new limit and sets the preset live
		} else if n2 != "" {
			note(n2)
		}
		degrade = q
		mode, dbm := txReportFor(rl.Radio, ceil, q)
		a.setTxReport(rl.Band, txReport{Mode: mode, DBm: dbm})
	}
	txStep := wl("set tx power", "txpwr_degrade", itoa(degrade))
	txChange := degrade != lr.Degrade
	// TWT: written only inside a radio down/up made for something else
	// (twt.go); an unreadable state is left alone there.
	twtWant := !a.o.NoTWT
	twtPending := lr.TWT >= 0 && lr.TWT != b2i(twtWant)
	// The U6 Pro's radio-wide driver settings (parity.go): the radio-down
	// ones ride along with TWT, the live ones run with the radio up.
	bssload, bn := radioBSSLoad(rl)
	if bn != "" {
		note(bn)
	}
	baseMode := unread
	if a.o.KeepDesense {
		baseMode = a.baseDriver(p, interferenceIov)
	}
	dp := planDriver(p, rl.Band, lr.Drv, bssload, a.o.KeepDesense, baseMode)
	// rideAlong: what a radio down/up made for something else also writes
	// (once per plan).
	// heldPending: per-vif radio-down iovars (rrm, wnm) whose stored value
	// differs from the wanted one (heldDriver); they ride the same way.
	var heldPending []Step
	heldSet := false
	rideAlong := func() []Step {
		if rp.TWTSet {
			return nil
		}
		var st []Step
		if twtPending {
			st = append(st, twtStep(p, twtWant))
		}
		st = append(st, dp.down...)
		if len(heldPending) > 0 {
			st = append(st, heldPending...)
			heldSet = true
		}
		rp.TWTSet = len(st) > 0
		return st
	}
	liveDrv := func(profiled bool) []Step {
		var st []Step
		for _, s := range dp.live {
			if profiled && s.Argv[3] != interferenceIov && s.Argv[3] != interfOverIov {
				continue // radioProfile wrote it (bssload, txbf_imp)
			}
			st = append(st, s)
		}
		return st
	}

	// hostapd conf, ACL files and driver state for the used vifs.
	maxSta := rl.Radio.MaxClients
	if maxSta <= 0 || maxSta > defaultMaxSta {
		maxSta = defaultMaxSta
	}
	minRSSI := 0
	if rl.Radio.MinRSSI < 0 {
		minRSSI = rl.Radio.MinRSSI
	}
	if hapdCh == 0 {
		hapdCh = cs.Ctrl
	}
	hr := hapdRadio{Band: rl.Band, Channel: hapdCh, Country: cc, MinRSSI: minRSSI, MaxSta: maxSta, RunDir: a.o.RunDir}
	var drv []vifDriver
	drvOf := map[string]vifDriver{}
	var files []Step
	for _, u := range rl.Used {
		mac, err := a.bssid(ctx, u.Vif)
		if err != nil {
			return rp, err
		}
		d := driverFor(u, mac, maxSta, blocked, a.o.MinRates)
		drv = append(drv, d)
		drvOf[u.Vif] = a.withTempDeny(d) // the live filter carries the bans (tempdeny.go); the stored state does not
		hr.BSS = append(hr.BSS, hapdBSS{Vif: u.Vif, BSSID: mac, Bridge: u.Bridge, SSID: u.SSID, Accept: d.Allow,
			FTPeers: a.peersFor(u.SSID, rl.Band, u.Bridge)}) // ftpeers.go
		files = append(files, aclSteps(a.o.RunDir, d)...)
		files = append(files, pskSteps(a.o.RunDir, u.Vif, u.SSID, a.exists)...)
	}
	stale := a.staleVifSteps(p, rl) // slots.go
	var conf, drvJSON []byte
	var drvACL []vifDriver
	drvStep := -1
	if len(hr.BSS) > 0 {
		ph, err := a.placeholder(rl.Anchor)
		if err != nil {
			return rp, err
		}
		hr.Placeholder = ph
		c, err := renderHostapd(hr)
		if err != nil {
			return rp, err
		}
		conf = []byte(c)
		drvJSON, _ = json.MarshalIndent(drv, "", " ")
		// The stored driver state keeps what the driver holds: rrm/wnm
		// values that changed only in the agent (an upgrade) wait for the
		// next radio down/up instead of reconciling the radio (heldDriver).
		var held []vifDriver
		var hn []string
		held, heldPending, hn = a.heldDriver(p, drv)
		for _, n := range hn {
			note(n)
		}
		heldJSON := drvJSON
		if len(heldPending) > 0 {
			heldJSON, _ = json.MarshalIndent(held, "", " ")
		}
		drvACL = held
		drvStep = len(files)
		files = append(files,
			writeStep("write driver state", drvPath(a.o.RunDir, p), 0o644, heldJSON),
			writeStep("write hostapd conf", ConfPath(a.o.RunDir, p), 0o600, conf))
	}

	_, takeover := ls.TPLink[p]
	reconcile := takeover || len(phy) > 0
	var acl *aclLive // only station ACLs or live settings changed: updated in place (acllive.go)
	if len(hr.BSS) > 0 {
		acl = a.planACLLive(p, conf, drvACL, files)
		// sameConf: the FT-SAE peer lines are added live (SyncFTPeers), not
		// by a restart.
		reconcile = reconcile || !ls.Ours[p] || !acl.covers(ConfPath(a.o.RunDir, p)) && !a.sameConf(ConfPath(a.o.RunDir, p), conf) ||
			!acl.covers(drvPath(a.o.RunDir, p)) && !a.sameFile(drvPath(a.o.RunDir, p), files[drvStep].Data)
		for _, f := range files {
			if f.Kind == StepWrite && !acl.covers(f.Path) && f.Path != ConfPath(a.o.RunDir, p) && !a.sameFile(f.Path, f.Data) {
				reconcile = true
			}
		}
		// Our hostapd runs but a vif it should serve is gone (or the
		// placeholder): only a restart recreates it.
		for _, u := range rl.Used {
			if !ls.Vifs[u.Vif].Exists {
				reconcile = true
			}
		}
		if !a.netdevExists(hr.Placeholder.Vif) {
			reconcile = true
		}
	} else if ls.Ours[p] {
		reconcile = true
	}
	rp.Reconcile = reconcile

	// The primary carries no SSID: no MAC filter either.
	primMAC, primForeign := macDrift(p, lr.MAC, 0, nil, false)
	foreign(primForeign)

	var st []Step
	if !reconcile {
		if txChange {
			st = append(st, txStep)
		}
		st = append(st, primMAC...)
		for _, v := range rl.Vifs {
			lv := ls.Vifs[v]
			if !lv.Exists {
				continue // not served: nothing to lower, unbridge or filter
			}
			u, used := findUsed(rl, v)
			switch {
			case used:
				d := drvOf[v]
				if lv.DWDS != d.DWDS {
					// Refused by the driver unless the radio is down. A TWT
					// state that differs rides along (twt.go).
					st = append(st, radioDownSteps(p, []vifDriver{d}, rideAlong()...)...)
					foreign(fmt.Sprintf("%s: dwds %d on a client vif, set to %d", v, lv.DWDS, d.DWDS))
				}
				ms, f := macDrift(v, lv.MAC, d.Macmode, d.Maclist, false)
				st = append(st, ms...)
				foreign(acl.driverNote(v, lv.MAC, f))
				if lv.Bridge != u.Bridge {
					st = append(st, Step{Kind: StepBridgeAdd, Desc: "bridge " + v, Bridge: u.Bridge, Port: v})
					if lv.Bridge == "" {
						foreign(fmt.Sprintf("%s: out of %s (netifd?), re-added", v, u.Bridge))
					}
				}
				if want := proxyARPWanted(u.SSID); lv.Bridge != u.Bridge && want || a.proxyARPDiffers(v, want) {
					st = append(st, proxyARPStep(v, want))
				}
				switch {
				case !lv.Up && !a.ssidsDown:
					st = append(st, cmdStep("raise "+v, "wl", "-i", v, "bss", "up"))
				case lv.Up && a.ssidsDown:
					// the uplink-loss hold (ssidhold.go): not foreign
					st = append(st, onVif(v, cmdStep("uplink lost: lower "+v, "wl", "-i", v, "bss", "down")))
				}
				if lv.DHCPUnicast == 0 { // live-settable: re-asserted in place
					st = append(st, dhcpUnicastStep(v))
				}
			default:
				// The placeholder wlN1 (or a vif no hostapd serves) stays
				// BSS down, out of every bridge and without a MAC filter.
				// Its dwds is left alone: a BSS that is down takes no WDS
				// peer, and the driver may refuse dwds on it ("Not down").
				if lv.Up {
					st = append(st, onVif(v, cmdStep("lower unused "+v, "wl", "-i", v, "bss", "down")))
					foreign(fmt.Sprintf("%s: unused vif was up, lowered", v))
				}
				ms, f := macDrift(v, lv.MAC, 0, nil, false)
				st = append(st, ms...)
				foreign(f)
				if lv.Bridge != "" {
					st = append(st, Step{Kind: StepBridgeDel, Desc: "unbridge unused " + v, Port: v, IfPresent: v})
				}
			}
		}
		st = append(st, stale...)
		st = append(st, acl.Steps()...)
		if heldSet {
			// the pending rrm/wnm went in with the radio down above
			st = append(st, writeStep("write driver state", drvPath(a.o.RunDir, p), 0o644, drvJSON))
		}
		st = append(st, liveDrv(false)...)
		rp.Steps = st
		rp.Driver = driverStatus(dp, rp.TWTSet)
		return rp, nil
	}

	// Full reconcile: radioDownSteps below writes every vif's rrm and wnm,
	// so the stored state is the wanted one.
	if drvStep >= 0 {
		files[drvStep].Data = drvJSON
	}
	heldPending = nil
	// Every vif goes BSS down while its hostapd still runs:
	// once it stops, the bss= vifs it created are gone (F2) and the
	// survivors (its interface= vif) are the only ones left to scrub.
	for _, v := range rl.Vifs {
		if ls.Vifs[v].Exists {
			st = append(st, onVif(v, cmdStep("lower "+v, "wl", "-i", v, "bss", "down")))
		}
	}
	gone := map[string]bool{}
	if tp, ok := ls.TPLink[p]; ok {
		st = append(st, Step{Kind: StepStop, Desc: "stop TP-Link hostapd on " + p, Path: tp.PidFile, Proc: "hostapd", Match: tp.Conf})
		if tp.confRead {
			for _, v := range tp.BSS {
				gone[v] = true
			}
		} else {
			for _, v := range rl.Vifs {
				gone[v] = !isBackhaul(v) // unknown conf: assume TP-Link's layout (F1)
			}
		}
	}
	if ls.Ours[p] {
		st = append(st, Step{Kind: StepStop, Desc: "stop agent hostapd on " + p, Path: pidPath(a.o.RunDir, p), Proc: "hostapd", Match: ConfPath(a.o.RunDir, p)})
		for _, v := range ls.OursBSS[p] {
			gone[v] = true
		}
		if len(ls.OursBSS[p]) == 0 {
			for _, v := range rl.Vifs {
				gone[v] = gone[v] || !isBackhaul(v) // conf unreadable: every bss= is wlN2..
			}
		}
	}
	if len(phy) > 0 {
		st = append(st, wl("radio down", "down"))
		st = append(st, phy...)
		st = append(st, txStep)
		st = append(st, radioProfile(p, rl.Band, twtWant, dp.profile)...)
		st = append(st, wl("radio up", "up"))
		rp.TWTSet = true
	} else {
		if txChange {
			st = append(st, txStep)
		}
		// A PHY step that failed between "wl down" and "wl up" (in this or
		// an earlier apply) leaves the radio down while chanspec and
		// country still read as wanted, so nothing above would raise it.
		// wl up on a radio that is up does nothing.
		st = append(st, optStep("ensure radio up", "wl", "-i", p, "up"))
	}
	st = append(st, primMAC...)
	for _, v := range rl.Vifs {
		lv := ls.Vifs[v]
		if _, used := findUsed(rl, v); used {
			if d := drvOf[v]; lv.MAC.Known && !lv.MAC.matches(d.Macmode, d.Maclist) {
				_, f := macDrift(v, lv.MAC, d.Macmode, d.Maclist, false)
				foreign(f)
			}
			continue // recreated by our hostapd; driverSteps after its start
		}
		if !lv.Exists || gone[v] {
			if lv.Exists && lv.MAC.Known && (lv.MAC.Mode != 0 || len(lv.MAC.List) > 0) {
				_, f := macDrift(v, lv.MAC, 0, nil, true)
				foreign(f + " (vif deleted with its hostapd)")
			}
			continue
		}
		// A survivor (the placeholder wlN1): out of every bridge, no MAC
		// filter. Its dwds goes off after hostapd starts, inside the radio
		// down/up that dwds needs (radioDownSteps).
		if lv.Bridge != "" {
			st = append(st, Step{Kind: StepBridgeDel, Desc: "unbridge unused " + v, Port: v, IfPresent: v})
		}
		ms, f := macDrift(v, lv.MAC, 0, nil, takeover)
		for _, m := range ms {
			st = append(st, onVif(v, m))
		}
		foreign(f)
	}
	st = append(st, files...)
	st = append(st, stale...)
	if len(hr.BSS) == 0 {
		rp.Steps = append(st,
			Step{Kind: StepRemove, Desc: "remove hostapd conf", Path: ConfPath(a.o.RunDir, p)},
			Step{Kind: StepRemove, Desc: "remove driver state", Path: drvPath(a.o.RunDir, p)})
		rp.Steps = append(rp.Steps, liveDrv(len(phy) > 0)...)
		rp.Driver = driverStatus(dp, rp.TWTSet)
		return rp, nil
	}
	// Start hostapd and wait for its BSS setup: it creates the bss= vifs
	// (BSS down, netdev down, not bridged: bridge= is not honoured) and sets
	// every BSS down, the placeholder too, after `-B` has returned (F3).
	var vifs []string
	for _, u := range rl.Used {
		vifs = append(vifs, u.Vif)
	}
	ph := hr.Placeholder.Vif
	if ph == p {
		st = append(st, apResetSteps(p, false)...) // anchor.go: the master
	}
	st = append(st,
		cmdStep("start hostapd on "+p, "hostapd", "-B", "-P", pidPath(a.o.RunDir, p), ConfPath(a.o.RunDir, p)),
		Step{Kind: StepWait, Desc: "wait for hostapd on " + p, Ifaces: vifs, Path: CtrlDir, Port: vifs[len(vifs)-1]},
		optStep("keep placeholder "+ph+" down", "wl", "-i", ph, "bss", "down"))
	// dwds and rrm need the radio down: one wl down / wl up for all the
	// radio's SSIDs while their fresh BSSs are down anyway.
	var ds []vifDriver
	for _, u := range rl.Used {
		ds = append(ds, drvOf[u.Vif])
	}
	// The placeholder's dwds off too (audit D8; best effort: its BSS stays
	// down, so no WDS peer can join anyway).
	var extra []Step
	if lv, ok := ls.Vifs[ph]; ok && isBackhaul(ph) && lv.DWDS != 0 {
		extra = append(extra, onVif(ph, optStep("backhaul "+ph+" dwds off (audit D8)", "wl", "-i", ph, "dwds", "0")))
	}
	extra = append(extra, rideAlong()...)
	if rl.Band == "na" && rl.Radio.Enabled && hapdChannel(rl.Band, hr.Channel) != cs.Ctrl {
		// hostapd's conf names another channel than the chanspec (a DFS
		// channel, a radar move followed): set the chanspec again after
		// hostapd is up, inside the radio down/up made here anyway, so
		// its START_AP cannot leave the radio on the conf's channel
		// (deco-crosscheck dfs step 4; whether wl_cfg80211's start_ap
		// applies the conf channel is unverified on an X20).
		extra = append(extra, optStep("chanspec "+cs.String()+" after hostapd (DFS)", "wl", "-i", p, "chanspec", cs.String()))
	}
	st = append(st, radioDownSteps(p, ds, extra...)...)
	// Then what TP-Link's wifi script does per enabled vap (F3), with the
	// other driver iovars first while the fresh BSS is down (F6).
	for _, u := range rl.Used {
		st = append(st, driverSteps(drvOf[u.Vif])...)
		st = append(st, Step{Kind: StepBridgeAdd, Desc: "bridge " + u.Vif, Bridge: u.Bridge, Port: u.Vif})
		if proxyARPWanted(u.SSID) {
			st = append(st, proxyARPStep(u.Vif, true))
		}
		st = append(st, cmdStep("netdev up "+u.Vif, "ifconfig", u.Vif, "up"))
		if !a.ssidsDown { // else the uplink-loss hold keeps it down (ssidhold.go)
			st = append(st, cmdStep("raise "+u.Vif, "wl", "-i", u.Vif, "bss", "up"))
		}
	}
	rp.Steps = append(st, liveDrv(len(phy) > 0)...)
	rp.Driver = driverStatus(dp, rp.TWTSet)
	return rp, nil
}

// proxyARPWanted: hostapd's proxy_arp cannot be used here (F5), so an
// SSID asking for it gets the bridge port's proxyarp_wifi: the bridge
// answers ARP for stations from its neighbour table, and an ARP request it
// answered is not flooded onto the air. There is no hostapd DHCP/ND
// snooping table behind it, so only addresses the AP has already seen are
// answered; others are flooded as usual. A U6 Pro runs proxyarp 1 on a
// non-isolated SSID too (aaa.conf with l2_isolation disabled), and the
// bridge port attribute has no isolation precondition.
func proxyARPWanted(s SSID) bool { return s.ProxyARP }

func proxyARPPath(vif string) string { return "/sys/class/net/" + vif + "/brport/proxyarp_wifi" }

// proxyARPStep sets the bridge port attribute. Optional: a kernel without it
// has no such file, and isolation does not depend on it.
func proxyARPStep(vif string, on bool) Step {
	return Step{Kind: StepPut, Desc: "proxy ARP on " + vif, Path: proxyARPPath(vif), Data: []byte(itoa(b2i(on)) + "\n"), Optional: true, IfPresent: vif}
}

// proxyARPDiffers reports whether a bridge port's proxyarp_wifi reads
// other than want (false when it cannot be read).
func (a *Applier) proxyARPDiffers(vif string, want bool) bool {
	b, err := a.readFile(proxyARPPath(vif))
	return err == nil && strings.TrimSpace(string(b)) != itoa(b2i(want))
}

// placeholder returns the radio's interface= placeholder: the one in the
// agent's conf when it has one (so an unchanged radio keeps its hostapd),
// else a fresh random one, kept for this process.
func (a *Applier) placeholder(vif string) (hapdPlaceholder, error) {
	if ph, ok := a.ph[vif]; ok {
		return ph, nil
	}
	if b, err := a.readFile(ConfPath(a.o.RunDir, vif[:3])); err == nil {
		if ph, ok := parsePlaceholder(b, vif); ok {
			a.ph[vif] = ph
			return ph, nil
		}
	}
	ph, err := newPlaceholder(vif)
	if err != nil {
		return ph, err
	}
	a.ph[vif] = ph
	return ph, nil
}

func findUsed(rl *radioLayout, vif string) (vifAssign, bool) {
	for _, u := range rl.Used {
		if u.Vif == vif {
			return u, true
		}
	}
	return vifAssign{}, false
}

// aclSteps writes a vif's hostapd deny list (always, possibly empty) and its
// accept list (allow-list SSIDs only; removed otherwise).
func aclSteps(runDir string, d vifDriver) []Step {
	st := []Step{writeStep("write deny list "+d.Vif, DenyPath(runDir, d.Vif), 0o600, aclFile(d.DenyACL))}
	if d.Allow {
		st = append(st, writeStep("write accept list "+d.Vif, acceptPath(runDir, d.Vif), 0o600, aclFile(d.AcceptACL)))
	} else {
		st = append(st, Step{Kind: StepRemove, Desc: "remove accept list " + d.Vif, Path: acceptPath(runDir, d.Vif)})
	}
	return st
}

// sameFile reports whether the file at device path p holds exactly data.
func (a *Applier) sameFile(p string, data []byte) bool {
	b, err := a.readFile(p)
	return err == nil && bytes.Equal(b, data)
}

// heldDriver compares the wanted driver state drv of the primary's vifs
// with the stored one (drv-wlN.json, what the driver was given). rrm and
// wnm are taken by the driver only with the radio down (radioDownSteps), so
// a value that changed only in the agent (an upgrade: the previous build
// stored rrm 0x0 for an SSID with 11k off and no wnm) must not reconcile
// the radio: held is drv with the stored rrm/wnm, pending writes the wanted
// ones inside the next radio down/up made for something else (as TWT,
// twt.go), and notes say so. A stored state that cannot be read, or that
// names other vifs, holds nothing back.
func (a *Applier) heldDriver(primary string, drv []vifDriver) (held []vifDriver, pending []Step, notes []string) {
	b, err := a.readFile(drvPath(a.o.RunDir, primary))
	if err != nil {
		return drv, nil, nil
	}
	var prev []vifDriver
	if json.Unmarshal(b, &prev) != nil || len(prev) != len(drv) {
		return drv, nil, nil
	}
	held = make([]vifDriver, len(drv))
	for i, d := range drv {
		if prev[i].Vif != d.Vif {
			return drv, nil, nil
		}
		h := d
		if prev[i].RRM != d.RRM && prev[i].RRM != "" {
			h.RRM = prev[i].RRM
			pending = append(pending, optStep("set "+d.Vif+" rrm (U6 parity)", "wl", "-i", d.Vif, "rrm", d.RRM))
			notes = append(notes, fmt.Sprintf("%s: rrm %s -> %s at the next radio down/up (never a restart of its own)", d.Vif, prev[i].RRM, d.RRM))
		}
		if d.WNM != "" && prev[i].WNM != d.WNM {
			h.WNM = prev[i].WNM
			pending = append(pending, optStep("set "+d.Vif+" wnm (no BSS transition)", "wl", "-i", d.Vif, "wnm", d.WNM))
			notes = append(notes, fmt.Sprintf("%s: wnm -> %s at the next radio down/up (never a restart of its own)", d.Vif, d.WNM))
		}
		held[i] = h
	}
	return held, pending, notes
}
