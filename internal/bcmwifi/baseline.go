// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
)

// baseline is TP-Link's Wi-Fi state, captured once per boot (RunDir is
// tmpfs) before the agent's first change. It holds no secrets: TP-Link's
// own hostapd confs, which do, stay where TP-Link wrote them.
type baseline struct {
	Radios []baseRadio `json:"radios"`
	Vifs   []baseVif   `json:"vifs"`
}

type baseRadio struct {
	Primary  string   `json:"primary"`
	Band     string   `json:"band"`
	Chanspec string   `json:"chanspec"` // as wl prints it, e.g. "44/80"
	Country  string   `json:"country"`  // wl country argument, e.g. "US/0"
	BWCap    int      `json:"bw_cap"`
	Degrade  int      `json:"txpwr_degrade"`
	Hostapd  []string `json:"hostapd,omitempty"` // TP-Link hostapd argv
	Macmode  string   `json:"macmode,omitempty"` // the primary's driver MAC filter
	Maclist  []string `json:"maclist,omitempty"`
}

type baseVif struct {
	Vif     string      `json:"vif"`
	BSSID   string      `json:"bssid,omitempty"` // cur_etheraddr: hostapd recreates the vif with it
	Up      bool        `json:"up"`
	Bridge  string      `json:"bridge,omitempty"`
	Iovars  [][2]string `json:"iovars,omitempty"`
	Macmode string      `json:"macmode,omitempty"`
	Maclist []string    `json:"maclist,omitempty"`
	Rateset string      `json:"rateset,omitempty"` // canonical legacy rateset ("1b 2b 5.5b 6 ...")
}

// baseIovars are the per-vif iovars the agent changes, in restore order.
// dwds first: the driver takes it only while the BSS is down.
var baseIovars = []string{"dwds", "closednet", "ap_isolate", "bss_maxassoc", "wmf_bss_enable", "rrm", "rrm_nbr_scan", "fbt", "fbt_mdid", "fbt_ap"}

// backhaulDefaults are TP-Link's settings of its backhaul vif wlN1 (read on
// .205: dwds 1, closednet 1, bss_maxassoc 16). The hand-back restores them
// when the baseline lacks them (captured by an older agent, or no baseline).
var backhaulDefaults = [][2]string{{"dwds", "1"}, {"closednet", "1"}, {"bss_maxassoc", "16"}}

func hasIovar(io [][2]string, name string) bool {
	for _, x := range io {
		if x[0] == name {
			return true
		}
	}
	return false
}

func (a *Applier) baselinePath() string { return path.Join(a.o.RunDir, "tplink-baseline.json") }

// captureBaseline reads TP-Link's state and writes the baseline file.
func (a *Applier) captureBaseline(ctx context.Context) error {
	var b baseline
	for _, band := range radioOrder {
		p := bandPrimary[band]
		if !a.netdevExists(p) {
			continue
		}
		r := baseRadio{Primary: p, Band: band}
		out, err := a.wlGet(ctx, p, "chanspec")
		if err != nil {
			return err
		}
		if f := strings.Fields(out); len(f) > 0 {
			r.Chanspec = f[0]
		}
		if out, err = a.wlGet(ctx, p, "country"); err != nil {
			return err
		}
		c := parseCountry(out)
		r.Country = c.Code
		if c.Rev >= 0 {
			r.Country = fmt.Sprintf("%s/%d", c.Code, c.Rev)
		}
		if out, err = a.wlGet(ctx, p, "bw_cap", bandArg(band)); err != nil {
			return err
		}
		if r.BWCap, err = parseIntOut(out); err != nil {
			return fmt.Errorf("%s bw_cap: %w", p, err)
		}
		if out, err = a.wlGet(ctx, p, "txpwr_degrade"); err != nil {
			return err
		}
		if r.Degrade, err = parseIntOut(out); err != nil {
			return fmt.Errorf("%s txpwr_degrade: %w", p, err)
		}
		if tp, ok := a.tplinkHostapd(p); ok && len(tp.Argv) > 1 && path.Base(tp.Argv[0]) == "hostapd" {
			r.Hostapd = tp.Argv
		}
		if m := a.readMAC(ctx, p); m.Known {
			r.Macmode, r.Maclist = itoa(m.Mode), m.List
		}
		b.Radios = append(b.Radios, r)
		for i := 1; i <= maxVifIndex; i++ {
			v := fmt.Sprintf("%s%d", p, i)
			if !a.netdevExists(v) {
				continue
			}
			bv := baseVif{Vif: v, Bridge: a.bridgeOf(v)}
			if m, err := a.bssid(ctx, v); err == nil {
				bv.BSSID = m
			}
			out, err := a.wlGet(ctx, v, "bss")
			if err != nil {
				return err
			}
			bv.Up = out == "up"
			for _, io := range baseIovars {
				if out, err := a.wlGet(ctx, v, io); err == nil {
					if f := strings.Fields(out); len(f) > 0 {
						bv.Iovars = append(bv.Iovars, [2]string{io, f[0]})
					}
				}
			}
			if out, err := a.wlGet(ctx, v, "macmode"); err == nil {
				if f := strings.Fields(out); len(f) > 0 {
					bv.Macmode = f[0]
				}
			}
			if out, err := a.wlGet(ctx, v, "mac"); err == nil {
				bv.Maclist = parseMaclist(out)
			}
			if out, err := a.wlGet(ctx, v, "rateset"); err == nil {
				bv.Rateset = parseRateset(out)
			}
			b.Vifs = append(b.Vifs, bv)
		}
	}
	data, err := json.MarshalIndent(b, "", " ")
	if err != nil {
		return err
	}
	return writeFileAtomic(a.fsPath(a.baselinePath()), data, 0o600)
}

// parseMaclist reads `wl mac` output: lines "mac AA:BB:CC:DD:EE:FF ...".
func parseMaclist(out string) []string {
	var macs []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "mac" {
			if m := normMAC(f[1]); m != "" {
				macs = append(macs, m)
			}
		}
	}
	return macs
}

func (a *Applier) loadBaseline() (*baseline, error) {
	data, err := a.readFile(a.baselinePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var b baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", a.baselinePath(), err)
	}
	return &b, nil
}

// handback returns Wi-Fi to TP-Link (see Rollback for the exact sequence).
func (a *Applier) handback(ctx context.Context) error {
	st, b, err := a.handbackSteps(ctx)
	if err != nil {
		return err
	}
	st = withFlush(st)
	a.o.Logf("bcmwifi: handing Wi-Fi back to TP-Link (%d steps)", len(st))
	err = a.executeAll(ctx, st)
	a.applied = nil
	// TP-Link learns flows: the cache goes back on whoever turned it off
	// (the tc trees went with the steps above)
	a.flowCacheOn(ctx, "hand-back to TP-Link")
	if err != nil {
		return err
	}
	if b == nil {
		return ErrNoBaseline
	}
	return nil
}

// hbRadio is one radio in a hand-back.
type hbRadio struct {
	p       string
	vifs    []string // existing vifs at plan time
	tp      hapdProc // TP-Link's hostapd when running
	running bool     // TP-Link's hostapd still runs: leave the radio alone
}

func (a *Applier) handbackSteps(ctx context.Context) ([]Step, *baseline, error) {
	b, err := a.loadBaseline()
	if err != nil {
		return nil, nil, err
	}
	var st []Step
	var radios []*hbRadio
	var vifs []string
	for _, band := range radioOrder {
		p := bandPrimary[band]
		if !a.netdevExists(p) {
			continue
		}
		r := &hbRadio{p: p}
		r.tp, r.running = a.tplinkHostapd(p)
		for i := 1; i <= maxVifIndex; i++ {
			if v := fmt.Sprintf("%s%d", p, i); a.netdevExists(v) {
				r.vifs = append(r.vifs, v)
				vifs = append(vifs, v)
			}
		}
		radios = append(radios, r)
	}
	// 1-2: the agent lets go. A radio whose TP-Link hostapd still runs (an
	// apply that failed before reaching it, F7) is left alone: its vifs are
	// TP-Link's and must stay up.
	for _, r := range radios {
		if r.running {
			if r.tp.PidLost {
				st = append(st, writeStep("restore TP-Link pid file of "+r.p, r.tp.PidFile, 0o644, []byte(itoa(r.tp.Pid)+"\n")))
			}
			continue
		}
		for _, v := range r.vifs {
			st = append(st, onVif(v, optStep("lower "+v, "wl", "-i", v, "bss", "down")))
		}
		st = append(st, Step{Kind: StepStop, Desc: "stop agent hostapd on " + r.p, Path: pidPath(a.o.RunDir, r.p), Proc: "hostapd", Match: confPath(a.o.RunDir, r.p)})
		for _, v := range r.vifs {
			if br := a.bridgeOf(v); br != "" && (b != nil || vBridgeRe.MatchString(br)) {
				st = append(st, Step{Kind: StepBridgeDel, Desc: "unbridge " + v, Port: v, IfPresent: v})
			}
		}
	}
	for _, vid := range a.vlanBridges() {
		for _, s := range a.vlanDownSteps(vid) {
			s.Optional = true
			st = append(st, s)
		}
	}
	for _, r := range radios {
		for _, f := range []string{confPath(a.o.RunDir, r.p), drvPath(a.o.RunDir, r.p), pidPath(a.o.RunDir, r.p)} {
			st = append(st, Step{Kind: StepRemove, Desc: "remove agent file", Path: f, Optional: true})
		}
	}
	for _, v := range vifs {
		for _, f := range []string{denyPath(a.o.RunDir, v), acceptPath(a.o.RunDir, v), pskPath(a.o.RunDir, v)} {
			st = append(st, Step{Kind: StepRemove, Desc: "remove agent file", Path: f, Optional: true})
		}
	}
	// The agent's guest chains and rate limits go too (TP-Link has neither).
	gst, _ := a.guestSteps(nil, nil, a.readGuest(ctx))
	for _, s := range gst {
		s.Optional = true
		st = append(st, s)
	}
	st = append(st, a.shapingTeardownSteps()...)
	backhaul := func(v string, have [][2]string) {
		for _, d := range backhaulDefaults {
			if !hasIovar(have, d[0]) {
				st = append(st, onVif(v, optStep("restore TP-Link backhaul "+v+" "+d[0], "wl", "-i", v, d[0], d[1])))
			}
		}
	}
	// A failed apply may have stopped between "wl down" and "wl up"; the
	// radio must be up for any BSS to beacon. A no-op when it already is.
	ensureUp := func(p string) Step { return optStep("ensure radio up", "wl", "-i", p, "up") }
	baseRadioOf := func(p string) *baseRadio {
		if b == nil {
			return nil
		}
		for i := range b.Radios {
			if b.Radios[i].Primary == p {
				return &b.Radios[i]
			}
		}
		return nil
	}

	// 3: PHY and the primary's MAC filter, on the radios the agent had.
	for _, r := range radios {
		if r.running {
			continue
		}
		br := baseRadioOf(r.p)
		if br == nil || a.radioMatches(ctx, *br) {
			st = append(st, ensureUp(r.p))
		} else {
			wl := func(desc string, args ...string) Step {
				return cmdStep(desc, append([]string{"wl", "-i", r.p}, args...)...)
			}
			st = append(st, wl("radio down", "down"))
			if br.Country != "" {
				st = append(st, wl("restore country", "country", br.Country))
			}
			st = append(st, wl("restore bw_cap", "bw_cap", bandArg(br.Band), itoa(br.BWCap)))
			if br.Chanspec != "" {
				st = append(st, wl("restore chanspec", "chanspec", br.Chanspec))
			}
			st = append(st, wl("restore tx power", "txpwr_degrade", itoa(br.Degrade)), wl("radio up", "up"))
		}
		if br != nil && br.Macmode != "" && (br.Macmode != "0" || len(br.Maclist) > 0) {
			for _, s := range macSteps(r.p, 0, br.Maclist) {
				if s.Argv[3] == "macmode" {
					s.Argv[4] = br.Macmode
				}
				s.Optional = true
				st = append(st, s)
			}
		}
	}

	// 4: TP-Link's hostapd, only where it is not running: a second one with
	// the same -P fails and deletes the running one's pid file (F7). Then
	// wait for its BSS setup: the bss= vifs appear after -B returns.
	restarted := map[string]bool{}
	for _, r := range radios {
		if r.running {
			continue
		}
		argv := []string(nil)
		if br := baseRadioOf(r.p); br != nil {
			argv = br.Hostapd
		}
		if len(argv) == 0 {
			for _, base := range tplinkBases(r.p) {
				if a.exists(base + ".conf") {
					argv = []string{"hostapd", "-B", "-P", base + ".pid", base + ".conf"}
					break
				}
			}
		}
		if len(argv) == 0 {
			a.o.Logf("bcmwifi: no TP-Link hostapd conf for %s; not restarting it", r.p)
			continue
		}
		conf := argv[len(argv)-1]
		if !a.exists(conf) {
			a.o.Logf("bcmwifi: TP-Link conf %s missing; not restarting its hostapd on %s", conf, r.p)
			continue
		}
		restarted[r.p] = true
		var h hapdProc
		h.hapdConf(a, conf)
		if h.Iface == r.p {
			st = append(st, apResetSteps(r.p, true)...) // anchor.go: the master
		}
		st = append(st, cmdStep("restart TP-Link hostapd on "+r.p, argv...))
		if len(h.BSS) > 0 {
			w := Step{Kind: StepWait, Desc: "wait for TP-Link hostapd on " + r.p, Ifaces: h.BSS, Optional: true}
			if h.CtrlDir != "" {
				w.Path, w.Port = h.CtrlDir, h.LastBSS
			}
			st = append(st, w)
		}
	}

	// 5: the restarted radios' vifs get TP-Link's driver state back (the
	// recreated ones have driver defaults; their BSS is down, which dwds
	// needs, F6), then the BSS and bridge state the baseline recorded, as
	// TP-Link's wifi script does after starting hostapd: ifconfig up,
	// wl bss up, brctl addif (F3). On a radio whose TP-Link hostapd kept
	// running this only re-asserts what should already be so.
	radioOf := func(v string) string { return v[:3] }
	if b == nil {
		for _, r := range radios {
			if restarted[r.p] {
				backhaul(r.p+"1", nil)
			}
		}
		return st, nil, nil
	}
	// dwds and rrm are accepted only while the radio is down (seen on
	// .205): they are restored per radio inside one wl down / wl up, all
	// optional so the hand-back goes on, and the up runs whatever happens.
	downOnly := map[string][]Step{}
	var downOrder []string
	for _, v := range b.Vifs {
		if !restarted[radioOf(v.Vif)] {
			continue
		}
		for _, io := range v.Iovars {
			s := onVif(v.Vif, optStep("restore "+v.Vif+" "+io[0], "wl", "-i", v.Vif, io[0], io[1]))
			if io[0] == "dwds" || io[0] == "rrm" {
				r := radioOf(v.Vif)
				if _, seen := downOnly[r]; !seen {
					downOrder = append(downOrder, r)
				}
				downOnly[r] = append(downOnly[r], s)
				continue
			}
			st = append(st, s)
		}
		if isBackhaul(v.Vif) {
			backhaul(v.Vif, v.Iovars)
		}
		if v.Rateset != "" {
			if out, err := a.wlGet(ctx, v.Vif, "rateset"); err != nil || parseRateset(out) != v.Rateset {
				// refused while the radio is up, like dwds and rrm
				r := radioOf(v.Vif)
				if _, seen := downOnly[r]; !seen {
					downOrder = append(downOrder, r)
				}
				downOnly[r] = append(downOnly[r], onVif(v.Vif, optStep("restore "+v.Vif+" rateset", append([]string{"wl", "-i", v.Vif, "rateset"}, strings.Fields(v.Rateset)...)...)))
			}
		}
		if v.Macmode != "" {
			for _, s := range macSteps(v.Vif, 0, v.Maclist) {
				if s.Argv[3] == "macmode" {
					s.Argv[4] = v.Macmode
				}
				s.Optional = true
				st = append(st, onVif(v.Vif, s))
			}
		}
	}
	for _, r := range downOrder {
		st = append(st, optStep("radio "+r+" down to restore dwds/rrm/rateset", "wl", "-i", r, "down"))
		st = append(st, downOnly[r]...)
		st = append(st, optStep("radio "+r+" up", "wl", "-i", r, "up"))
	}
	for _, v := range b.Vifs {
		if v.Up {
			st = append(st, optStep("netdev up "+v.Vif, "ifconfig", v.Vif, "up"),
				cmdStep("raise "+v.Vif, "wl", "-i", v.Vif, "bss", "up"))
		} else {
			st = append(st, onVif(v.Vif, optStep("lower "+v.Vif, "wl", "-i", v.Vif, "bss", "down")))
		}
		if v.Bridge != "" {
			st = append(st, Step{Kind: StepBridgeAdd, Desc: "re-bridge " + v.Vif, Bridge: v.Bridge, Port: v.Vif})
		}
	}
	return st, b, nil
}

// radioMatches reports whether the radio's live PHY equals r.
func (a *Applier) radioMatches(ctx context.Context, r baseRadio) bool {
	cs, err1 := a.wlGet(ctx, r.Primary, "chanspec")
	co, err2 := a.wlGet(ctx, r.Primary, "country")
	bw, err3 := a.wlGet(ctx, r.Primary, "bw_cap", bandArg(r.Band))
	dg, err4 := a.wlGet(ctx, r.Primary, "txpwr_degrade")
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return false
	}
	f := strings.Fields(cs)
	c := parseCountry(co)
	ca := c.Code
	if c.Rev >= 0 {
		ca = fmt.Sprintf("%s/%d", c.Code, c.Rev)
	}
	bwv, _ := parseIntOut(bw)
	dgv, _ := parseIntOut(dg)
	return len(f) > 0 && f[0] == r.Chanspec && ca == r.Country && bwv == r.BWCap && dgv == r.Degrade
}
