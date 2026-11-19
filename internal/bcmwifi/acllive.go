// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"bytes"
	"encoding/json"
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

// aclLive is the in-place update of one radio's station ACLs. A nil
// *aclLive means the radio's change is not ACL-only (or there is none); its
// methods are nil-safe.
type aclLive struct {
	prev  map[string]vifDriver // by vif: what drv-wlN.json (and so hostapd) holds now
	paths map[string]bool      // files the update rewrites: ACL files, driver state
	steps []Step
}

// planACLLive returns the in-place ACL update for the radio whose primary
// is primary, when the hostapd conf is unchanged and drv differs from the
// stored driver state only in the station ACLs (deny/accept lists and the
// driver MAC filter derived from them). files are planRadio's file steps for
// the radio (ACL files, driver state, hostapd conf). It returns nil when
// anything else changed, or nothing did.
func (a *Applier) planACLLive(primary string, conf []byte, drv []vifDriver, files []Step) *aclLive {
	run := a.o.RunDir
	if len(drv) == 0 || !a.sameConf(confPath(run, primary), conf) {
		return nil
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
	changed := false
	for i, d := range drv {
		p := prev[i]
		if p.Vif != d.Vif || p.Allow != d.Allow || !sameNonACL(p, d) {
			return nil
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
		case f.Kind == StepWrite && f.Path == confPath(run, primary):
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

// sameNonACL compares two vif driver states with their station ACLs (and
// the driver MAC filter derived from them) left out.
func sameNonACL(x, y vifDriver) bool {
	strip := func(d vifDriver) []byte {
		d.Macmode, d.Maclist, d.DenyACL, d.AcceptACL = 0, nil, nil, nil
		b, _ := json.Marshal(d)
		return b
	}
	return bytes.Equal(strip(x), strip(y))
}

// sameSet reports whether xs and ys hold the same MACs.
func sameSet(xs, ys []string) bool {
	return len(minus(xs, ys)) == 0 && len(minus(ys, xs)) == 0
}
