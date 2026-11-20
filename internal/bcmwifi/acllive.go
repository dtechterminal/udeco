// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"bytes"
	"encoding/json"
	"slices"
	"sort"
	"strings"
)

// Live station-ACL updates (Lock to AP, docs/deco/features/lock-to-ap.md).
//
// The controller enforces "Lock to Access Point" (a client's
// fixed_ap_enabled/fixed_ap_mac) by provisioning every OTHER AP of the site:
// each of their WLANs gets the locked client in its MAC filter (system_cfg
// macacl.N.acl.M.mac with type=lock2ap; a deny entry, or the client left out
// of an allow list). The locked AP itself gets nothing. Each lock, unlock or
// move re-provisions all APs, and so does the locked AP going offline or
// coming back (the controller then drops or restores the entries: failover).
//
// Without this file such a change rewrote the deny/accept files and the
// driver state, which made planRadio reconcile the radio in full: hostapd
// restarted and every client of every SSID on the radio was dropped, on
// every AP of the site, for each lock change. When the station ACLs are the
// only thing that changed, the radio is now updated in place instead, the
// way SetBlocked updates the block list (refreshACLs): hostapd's lists by
// difference over its control socket (DENY_ACL / ACCEPT_ACL ADD_MAC /
// DEL_MAC; hostapd 2.9 disassociates a station it newly denies, and one it
// takes off an accept list), the ACL files hostapd reads at its next start,
// the driver MAC filter (planRadio's macDrift) and drv-wlN.json. The lists
// themselves still come from computeACL, so the block list and the per-SSID
// filter (with its lock2ap entries) are one union and neither clobbers the
// other.
//
// The same in-place update carries the per-SSID settings the X20 takes
// while the BSS runs (verified on .205, 2026-11-19: hostapd 2.9 answers OK
// to SET and stays ENABLED, the driver accepts the iovar with the radio up
// and its other BSSes keep their stations): hide SSID (closednet,
// ignore_broadcast_ssid), client isolation (ap_isolate), max clients
// (bss_maxassoc, max_num_sta) and multicast enhancement (wmf_bss_enable,
// multicast_to_unicast). The driver iovar does the work; hostapd's SET keeps
// its in-memory conf in line for any beacon it pushes later, and the conf
// file holds the value for its next start. Everything else (SSID, security,
// keys, FT, DTIM, U-APSD, 802.11k: wl rrm is refused unless the whole radio
// is down, and a radio down/up drops every station) still reconciles the
// radio in full.

// aclLive is the in-place update of one radio's station ACLs. A nil
// *aclLive means the radio's change is not ACL-only (or there is none); its
// methods are nil-safe.
type aclLive struct {
	prev  map[string]vifDriver // by vif: what drv-wlN.json (and so hostapd) holds now
	paths map[string]bool      // files the update rewrites: ACL files, driver state
	steps []Step
}

// planACLLive returns the in-place update for the radio whose primary is
// primary, when the hostapd conf differs from the running one only in
// liveConfKeys of its SSID sections (or not at all) and drv differs from the
// stored driver state only in the station ACLs (deny/accept lists and the
// driver MAC filter derived from them) and the live settings (liveDriver).
// files are planRadio's file steps for the radio (ACL files, driver state,
// hostapd conf). It returns nil when anything else changed, or nothing did.
func (a *Applier) planACLLive(primary string, conf []byte, drv []vifDriver, files []Step) *aclLive {
	run := a.o.RunDir
	if len(drv) == 0 {
		return nil
	}
	var sets []confSet
	if !a.sameConf(ConfPath(run, primary), conf) {
		old, err := a.readFile(ConfPath(run, primary))
		if err != nil {
			return nil
		}
		var ok bool
		if sets, ok = confLiveDiff(old, conf); !ok {
			return nil
		}
	}
	b, err := a.readFile(drvPath(run, primary))
	if err != nil {
		return nil
	}
	var prev []vifDriver
	if json.Unmarshal(b, &prev) != nil || len(prev) != len(drv) {
		return nil
	}
	l := &aclLive{prev: map[string]vifDriver{}, paths: map[string]bool{drvPath(run, primary): true}}
	if len(sets) > 0 {
		l.paths[ConfPath(run, primary)] = true
	}
	changed := len(sets) > 0
	var settings []Step
	for i, d := range drv {
		p := prev[i]
		if p.Vif != d.Vif || p.Allow != d.Allow || !sameStatic(p, d) {
			return nil
		}
		if st := liveDriverSteps(p, d); len(st) > 0 {
			settings = append(settings, st...)
			changed = true
		}
		l.prev[d.Vif] = p
		l.paths[denyPath(run, d.Vif)] = true
		l.paths[acceptPath(run, d.Vif)] = true
		l.paths[pskPath(run, d.Vif)] = true
		if !sameSet(p.DenyACL, d.DenyACL) || !sameSet(p.AcceptACL, d.AcceptACL) {
			changed = true
		}
	}
	if !changed {
		return nil
	}
	for _, f := range files {
		switch {
		case f.Kind == StepWrite && f.Path == ConfPath(run, primary) && len(sets) == 0:
			// unchanged (checked above)
		case !l.paths[f.Path]:
			return nil // a file this update does not own: full reconcile
		case f.Kind == StepWrite && a.sameFile(f.Path, f.Data):
		case f.Kind == StepRemove && !a.exists(f.Path):
		case isPSKPath(f.Path):
			return nil // hostapd reads its key file only at start (ppsk.go)
		default:
			l.steps = append(l.steps, f)
		}
	}
	// The settings: driver iovars (they do the work), then hostapd's
	// in-memory conf (optional: the conf file above holds it for the next
	// start; hostapd_cli matches "set" exactly).
	l.steps = append(l.steps, settings...)
	for _, c := range sets {
		l.steps = append(l.steps, onVif(c.Vif, optStep("hostapd "+c.Key+" "+c.Value+" on "+c.Vif,
			"hostapd_cli", "-p", CtrlDir, "-i", c.Vif, "set", c.Key, c.Value)))
	}
	// hostapd's in-memory lists, by difference (never CLEAR: with
	// macaddr_acl=1 an emptied accept list disassociates every station of
	// the BSS). Accept-list additions first, so a station is never missing
	// from both lists; the removals then disassociate exactly the stations
	// newly denied or taken off an accept list. Optional: the files above
	// hold the lists for hostapd's next start, and the driver MAC filter
	// (set by planRadio) refuses the station meanwhile.
	moved := map[string]bool{}
	var flush []string
	note := func(macs []string) {
		for _, m := range macs {
			if !moved[m] {
				moved[m] = true
				flush = append(flush, m)
			}
		}
	}
	for _, d := range drv {
		p := l.prev[d.Vif]
		cli := func(list, op, m string) Step {
			return onVif(d.Vif, optStep(list+" "+op+" "+m+" on "+d.Vif,
				"hostapd_cli", "-p", CtrlDir, "-i", d.Vif, list, op, m))
		}
		addAcc, delAcc := minus(d.AcceptACL, p.AcceptACL), minus(p.AcceptACL, d.AcceptACL)
		addDeny, delDeny := minus(d.DenyACL, p.DenyACL), minus(p.DenyACL, d.DenyACL)
		// hostapd keeps an accept list only where the conf loads one: with
		// RADIUS MAC authentication (macaddr_acl=2) the allow list is the
		// driver's alone, and an ACCEPT_ACL entry would admit the station
		// without asking RADIUS.
		accept := d.Allow && bytes.Contains(conf, []byte("\naccept_mac_file="+acceptPath(run, d.Vif)+"\n"))
		if accept {
			for _, m := range addAcc {
				l.steps = append(l.steps, cli("ACCEPT_ACL", "ADD_MAC", m))
			}
		}
		for _, m := range addDeny {
			l.steps = append(l.steps, cli("DENY_ACL", "ADD_MAC", m))
		}
		if accept {
			for _, m := range delAcc {
				l.steps = append(l.steps, cli("ACCEPT_ACL", "DEL_MAC", m))
			}
		}
		for _, m := range delDeny {
			l.steps = append(l.steps, cli("DENY_ACL", "DEL_MAC", m))
		}
		if d.Allow {
			note(addAcc)
			note(delAcc)
		}
		note(addDeny)
		note(delDeny)
	}
	// The stations' established flows (audit R21, as SetBlocked does): a
	// station sent to its locked AP must not keep a cached path here.
	for _, m := range flush {
		s := cmdStep("flush flows of "+m+" (audit R21)", FlowScope{MAC: m}.argv()...)
		s.Optional = true
		l.steps = append(l.steps, s)
	}
	return l
}

// covers reports whether the in-place update rewrites the file at p.
func (l *aclLive) covers(p string) bool { return l != nil && l.paths[p] }

// driverNote drops planRadio's "not set by the agent" line for vif when the
// live driver MAC filter is the one the agent stored (the update changes
// it, it is not foreign).
func (l *aclLive) driverNote(vif string, live liveMAC, note string) string {
	if l == nil || note == "" {
		return note
	}
	if p, ok := l.prev[vif]; ok && live.matches(p.Macmode, p.Maclist) {
		return ""
	}
	return note
}

// Steps returns the update's steps (nil for a nil update).
func (l *aclLive) Steps() []Step {
	if l == nil {
		return nil
	}
	return l.steps
}

// sameStatic compares two vif driver states with their station ACLs (and
// the driver MAC filter derived from them) and the live settings
// (liveDriverSteps) left out.
func sameStatic(x, y vifDriver) bool {
	strip := func(d vifDriver) []byte {
		d.Macmode, d.Maclist, d.DenyACL, d.AcceptACL = 0, nil, nil, nil
		d.Closed, d.Isolate, d.MaxAssoc, d.WMF = 0, 0, 0, 0
		b, _ := json.Marshal(d)
		return b
	}
	return bytes.Equal(strip(x), strip(y))
}

// liveDriverSteps sets the iovars the driver takes on a running BSS
// (closednet, ap_isolate, bss_maxassoc, wmf_bss_enable: verified live on
// .205) where want differs from the stored state cur.
func liveDriverSteps(cur, want vifDriver) []Step {
	var st []Step
	set := func(c, w int, iovar string) {
		if c != w {
			st = append(st, onVif(want.Vif, cmdStep("set "+want.Vif+" "+iovar, "wl", "-i", want.Vif, iovar, itoa(w))))
		}
	}
	set(cur.Closed, want.Closed, "closednet")
	set(cur.Isolate, want.Isolate, "ap_isolate")
	set(cur.MaxAssoc, want.MaxAssoc, "bss_maxassoc")
	set(cur.WMF, want.WMF, "wmf_bss_enable")
	return st
}

// liveConfKeys are the hostapd BSS keys taken live (SET), each with the
// value hostapd assumes when its line is absent.
var liveConfKeys = map[string]string{
	"ignore_broadcast_ssid": "0",
	"ap_isolate":            "0",
	"max_num_sta":           "2007",
	"multicast_to_unicast":  "0",
}

// confSet is one hostapd SET for a BSS.
type confSet struct{ Vif, Key, Value string }

// liveSection is one BSS section of a hostapd conf: the interface= section
// (vif "") or a bss= one, its lines other than liveConfKeys in order, and
// its liveConfKeys values.
type liveSection struct {
	vif    string
	static []string
	live   map[string]string
}

func liveSections(conf []byte) ([]liveSection, bool) {
	secs := []liveSection{{live: map[string]string{}}}
	for _, line := range strings.Split(string(conf), "\n") {
		if line == "" {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		if k == "bss" {
			secs = append(secs, liveSection{vif: v, live: map[string]string{}})
		}
		cur := &secs[len(secs)-1]
		if _, isLive := liveConfKeys[k]; isLive && cur.vif != "" {
			if _, dup := cur.live[k]; dup {
				return nil, false
			}
			cur.live[k] = v
			continue
		}
		cur.static = append(cur.static, line)
	}
	return secs, true
}

// confLiveDiff returns the SETs that turn the running conf old into new, and
// false when they differ in anything else (FT-SAE peer lines aside: those
// are synced live by SyncFTPeers). The interface= section (the hidden
// placeholder) must match as a whole.
func confLiveDiff(old, new []byte) ([]confSet, bool) {
	ol, ok1 := liveSections(stripFTPeers(old))
	nl, ok2 := liveSections(stripFTPeers(new))
	if !ok1 || !ok2 || len(ol) != len(nl) {
		return nil, false
	}
	var sets []confSet
	for i := range ol {
		o, n := ol[i], nl[i]
		if o.vif != n.vif || !slices.Equal(o.static, n.static) {
			return nil, false
		}
		var keys []string
		for k := range liveConfKeys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ov, ook := o.live[k]
			nv, nok := n.live[k]
			if !ook {
				ov = liveConfKeys[k]
			}
			if !nok {
				nv = liveConfKeys[k]
			}
			if ov != nv {
				sets = append(sets, confSet{Vif: n.vif, Key: k, Value: nv})
			}
		}
	}
	return sets, true
}

// sameSet reports whether xs and ys hold the same MACs.
func sameSet(xs, ys []string) bool {
	return len(minus(xs, ys)) == 0 && len(minus(ys, xs)) == 0
}
