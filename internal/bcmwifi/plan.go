// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	wlcaps "github.com/antoniocosta/unifi-openwrt/internal/wl" // planRadio has a local wl
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
	// twt: band -> the radio's TWT line, also in Notes (Tick logs changes)
	twt map[string]string
}

// Empty reports whether the plan changes nothing.
func (p Plan) Empty() bool { return len(p.Steps) == 0 }

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
	for _, rl := range l.Radios {
		rp, err := a.planRadio(ctx, rl, ls, blocked, d.Country, caps)
		if err != nil {
			return Plan{}, err
		}
		p.Steps = append(p.Steps, rp.Steps...)
		p.Notes = append(p.Notes, rp.Notes...)
		if lr := ls.Radios[rl.Primary]; lr != nil {
			line := "radio " + rl.Band + ": " + twtStatus(rl.Primary, lr.TWT, !a.o.NoTWT, rp.TWTSet)
			p.Notes = append(p.Notes, line)
			if p.twt == nil {
				p.twt = map[string]string{}
			}
			p.twt[rl.Band] = line
		}
		p.Foreign = append(p.Foreign, rp.Foreign...)
		p.disruptive = p.disruptive || rp.Reconcile
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
	if !a.netdevExists(br) || !a.ifUp(br) {
		st = append(st, cmdStep("bring "+br+" up", "ip", "link", "set", br, "up"))
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
// tolerated. TWT is the exception: on (twt enab 1, as a U6 Pro) unless the
// config turns it off, which is TP-Link's `twt 0` (twt.go). Both X20
// radios are HE (`he 1` here), so both get it.
func radioProfile(primary, band string, twt bool) []Step {
	wl := func(args ...string) Step {
		return optStep("radio profile "+args[0], append([]string{"wl", "-i", primary}, args...)...)
	}
	st := []Step{wl("he", "1")}
	if band == "ng" {
		st = append(st, wl("vht_features", "0x7"))
	}
	return append(st, twtStep(primary, twt), wl("tpc_report_ie", "0"), wl("pwr_const_ie", "0"),
		wl("bssload", "0"), wl("sgi_tx", "-1"))
}

// radioPlan is planRadio's result.
type radioPlan struct {
	Steps     []Step
	Notes     []string
	Foreign   []string
	Reconcile bool // hostapd restarted, BSSes cycled
	TWTSet    bool // TWT written inside one of the plan's radio down/ups (twt.go)
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
	cc := lr.Country.Code
	if wantCountry != "" {
		arg, same := countryArg(wantCountry, lr.Country)
		cc = strings.ToUpper(wantCountry)
		if !same {
			phy = append(phy, wl("set country "+arg, "country", arg))
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
		if change {
			if bw := bwCap(want.Width); bw != lr.BWCap {
				phy = append(phy, wl("set bw_cap", "bw_cap", bandArg(rl.Band), itoa(bw)))
			}
			phy = append(phy, wl("set chanspec "+want.String(), "chanspec", want.String()))
			cs = want
		}
		q, n2 := txpwrDegrade(rl.Radio, lr.TargetMax)
		if n2 != "" {
			note(n2)
		}
		degrade = q
	}
	txStep := wl("set tx power", "txpwr_degrade", itoa(degrade))
	txChange := degrade != lr.Degrade
	// TWT: written only inside a radio down/up made for something else
	// (twt.go); an unreadable state is left alone there.
	twtWant := !a.o.NoTWT
	twtPending := lr.TWT >= 0 && lr.TWT != b2i(twtWant)

	// hostapd conf, ACL files and driver state for the used vifs.
	maxSta := rl.Radio.MaxClients
	if maxSta <= 0 || maxSta > defaultMaxSta {
		maxSta = defaultMaxSta
	}
	minRSSI := 0
	if rl.Radio.MinRSSI < 0 {
		minRSSI = rl.Radio.MinRSSI
	}
	hr := hapdRadio{Band: rl.Band, Channel: cs.Ctrl, Country: cc, MinRSSI: minRSSI, MaxSta: maxSta, RunDir: a.o.RunDir}
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
		files = append(files,
			writeStep("write driver state", drvPath(a.o.RunDir, p), 0o644, drvJSON),
			writeStep("write hostapd conf", confPath(a.o.RunDir, p), 0o600, conf))
	}

	_, takeover := ls.TPLink[p]
	reconcile := takeover || len(phy) > 0
	var acl *aclLive // only station ACLs or live settings changed: updated in place (acllive.go)
	if len(hr.BSS) > 0 {
		acl = a.planACLLive(p, conf, drv, files)
		// sameConf: the FT-SAE peer lines are added live (SyncFTPeers), not
		// by a restart.
		reconcile = reconcile || !ls.Ours[p] || !acl.covers(confPath(a.o.RunDir, p)) && !a.sameConf(confPath(a.o.RunDir, p), conf) ||
			!acl.covers(drvPath(a.o.RunDir, p)) && !a.sameFile(drvPath(a.o.RunDir, p), drvJSON)
		for _, f := range files {
			if f.Kind == StepWrite && !acl.covers(f.Path) && f.Path != confPath(a.o.RunDir, p) && !a.sameFile(f.Path, f.Data) {
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
					var extra []Step
					if twtPending && !rp.TWTSet {
						extra, rp.TWTSet = []Step{twtStep(p, twtWant)}, true
					}
					st = append(st, radioDownSteps(p, []vifDriver{d}, extra...)...)
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
		rp.Steps = st
		return rp, nil
	}

	// Full reconcile. Every vif goes BSS down while its hostapd still runs:
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
		st = append(st, Step{Kind: StepStop, Desc: "stop agent hostapd on " + p, Path: pidPath(a.o.RunDir, p), Proc: "hostapd", Match: confPath(a.o.RunDir, p)})
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
		st = append(st, radioProfile(p, rl.Band, twtWant)...)
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
			Step{Kind: StepRemove, Desc: "remove hostapd conf", Path: confPath(a.o.RunDir, p)},
			Step{Kind: StepRemove, Desc: "remove driver state", Path: drvPath(a.o.RunDir, p)})
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
		cmdStep("start hostapd on "+p, "hostapd", "-B", "-P", pidPath(a.o.RunDir, p), confPath(a.o.RunDir, p)),
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
	if twtPending && !rp.TWTSet {
		extra, rp.TWTSet = append(extra, twtStep(p, twtWant)), true
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
	rp.Steps = st
	return rp, nil
}

// proxyARPWanted: hostapd's proxy_arp cannot be used here (F5), so an
// isolated SSID asking for proxy ARP gets the bridge port's proxyarp_wifi:
// the bridge answers ARP for stations from its neighbour table. There is no
// hostapd DHCP/ND snooping table behind it, so only addresses the AP has
// already seen are answered; others are flooded as usual.
func proxyARPWanted(s SSID) bool { return s.ProxyARP && s.Isolation }

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
	if b, err := a.readFile(confPath(a.o.RunDir, vif[:3])); err == nil {
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
	st := []Step{writeStep("write deny list "+d.Vif, denyPath(runDir, d.Vif), 0o600, aclFile(d.DenyACL))}
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
