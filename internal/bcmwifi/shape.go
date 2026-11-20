// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/dtechterminal/udeco/internal/wl"
)

// Per-client rate limits with tc (docs/deco/device-capabilities.md; audit
// D2, D3, R24).
//
// The X20 has tc iproute2-ss3.3.0 with htb, sfq, u32 (IP and Ethernet
// matches), ingress, mirred and police, and two IFB devices (ifb0, ifb1;
// fq_codel, codel, fq and flower are missing). A SSID with a RateLimit (its
// user group) limits every associated station on its own:
//
//   - download: htb root 1: on the vif, default class 1:1 (1000mbit) for
//     everyone else, one class 1:<id> per limited station at DownKbps with an
//     sfq leaf, chosen by `u32 match ether dst <mac>`;
//   - upload: an ingress qdisc on the vif with one `u32 match ether src <mac>
//     action mirred egress redirect dev ifb<radio>` per limited station (never
//     a match-all), and on ifb0 (2.4 GHz) / ifb1 (5 GHz) the same htb tree
//     keyed on `ether src` at UpKbps.
//
// Filters carry explicit handles (800::<id>) so a station is removed on its
// own. Every tc command is checked; a failure marks the device dirty and the
// next sync rebuilds it from scratch. The flows of each station whose limit
// changed are flushed from the flow cache (R21/R24). TP-Link's htb on br-lan
// is never touched (decosys owns it).
//
// Cost: tc only sees what the Broadcom flow cache does not accelerate.
// Measured on .205 (2026-11-19), accelerated flows bypass the trees
// entirely (512 kbit/s limit, 4.9 Mbit/s measured), so the flow cache is
// turned off on the unit while any tree is wanted and back on when none is
// (fcache.go): no hardware acceleration on that unit while limits are set.
// Only vifs with a limited station carry a tree; it is removed when the
// last limited station leaves.
//
// A station the controller gave its own limit (cmd rate-update,
// clientrate.go) is shaped the same way on any SSID vif it is associated on,
// at its own limit in each direction it has one and the SSID's in the other.
//
// Stations are the driver's association list (`wl -i <vif> assoclist`), read
// at each sync: a station that joins between syncs is unlimited until the
// next one (Tick runs it; the agent also syncs when a client with its own
// limit joins).

// tcState is what the agent built on one device (RunDir/tc-state.json).
type tcState struct {
	Root    bool              `json:"root,omitempty"`
	Dir     string            `json:"dir,omitempty"`   // ether dst (vif) or src (ifb)
	Class   map[string]int    `json:"class,omitempty"` // mac -> class/leaf/filter id
	Rate    map[string]int    `json:"rate,omitempty"`  // mac -> kbit/s
	Ingress bool              `json:"ingress,omitempty"`
	Redir   map[string]int    `json:"redir,omitempty"` // mac -> ingress filter id
	To      map[string]string `json:"to,omitempty"`    // mac -> ifb
	Dirty   bool              `json:"dirty,omitempty"` // a command failed: rebuild
}

// tcWant is the wanted tree on one device.
type tcWant struct {
	Root  map[string]int    // mac -> kbit/s
	Dir   string            // dst or src
	Redir map[string]string // mac -> ifb (vif ingress)
}

func (a *Applier) tcStatePath() string { return path.Join(a.o.RunDir, "tc-state.json") }

func (a *Applier) loadTC() map[string]*tcState {
	st := map[string]*tcState{}
	if b, err := a.readFile(a.tcStatePath()); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func (a *Applier) saveTC(st map[string]*tcState) error {
	for k, v := range st {
		if !v.Root && !v.Ingress && !v.Dirty {
			delete(st, k)
		}
	}
	b, _ := json.MarshalIndent(st, "", " ")
	return writeFileAtomic(a.fsPath(a.tcStatePath()), b, 0o644)
}

// ifbFor is the IFB device for a radio's uploads.
func ifbFor(primary string) string { return "ifb" + primary[2:] }

// parseAssoclist reads `wl assoclist` (wl.ParseAssoclist), sorted.
func parseAssoclist(out string) []string {
	macs := wl.ParseAssoclist(out)
	sort.Strings(macs)
	return macs
}

// wantShaping computes the wanted trees for l, reading the association
// list of each vif that has a limited SSID or, while there are per-client
// limits (clientrate.go), of every SSID vif. A station's limit in each
// direction is its own entry's when the entry limits that way, else its
// SSID's.
func (a *Applier) wantShaping(ctx context.Context, l *layout) (map[string]*tcWant, shapeNeed, error) {
	want := map[string]*tcWant{}
	need := shapeNeed{perClient: map[string]bool{}, ssid: map[string]bool{}}
	get := func(dev, dir string) *tcWant {
		w := want[dev]
		if w == nil {
			w = &tcWant{Root: map[string]int{}, Dir: dir, Redir: map[string]string{}}
			want[dev] = w
		}
		return w
	}
	per := a.loadClientRates()
	var tc map[string]*tcState // loaded only when a read fails
	for _, rl := range l.Radios {
		for _, u := range rl.Used {
			var ssid RateLimit
			if r := u.SSID.RateLimit; r != nil {
				ssid = *r
			}
			ssidLimited := ssid.DownKbps > 0 || ssid.UpKbps > 0
			// never the backhaul (TP-Link's mesh uplink between units)
			if !ssidLimited && (len(per) == 0 || isBackhaul(u.Vif)) {
				continue
			}
			out, err := a.wlGet(ctx, u.Vif, "assoclist")
			if err != nil {
				if !ssidLimited {
					// per-client only: this vif keeps what it has until
					// the next sync; the SSID-wide limits elsewhere are
					// still synced
					a.o.Logf("bcmwifi: per-client limits on %s: %v (kept as built)", u.Vif, err)
					if tc == nil {
						tc = a.loadTC()
					}
					for _, m := range keepShaping(tc, u.Vif, a.netdevExists(u.Vif), get) {
						need.perClient[m] = true
					}
					continue
				}
				return nil, need, err
			}
			for _, m := range parseAssoclist(out) {
				pc := per[m] // zero: no entry
				down, up := ssid.DownKbps, ssid.UpKbps
				if pc.DownKbps > 0 {
					down = pc.DownKbps
					need.perClient[m] = true
				}
				if pc.UpKbps > 0 {
					up = pc.UpKbps
					need.perClient[m] = true
				}
				if pc.DownKbps <= 0 && ssid.DownKbps > 0 || pc.UpKbps <= 0 && ssid.UpKbps > 0 {
					need.ssid[u.SSID.ID] = true
				}
				if down > 0 {
					get(u.Vif, "dst").Root[m] = down
				}
				if up > 0 {
					ifb := ifbFor(rl.Primary)
					get(u.Vif, "dst").Redir[m] = ifb
					get(ifb, "src").Root[m] = up
				}
			}
		}
	}
	return want, need, nil
}

// keepShaping wants again what was built for the stations of vif (its
// download classes, upload redirects and their IFB classes), so a vif whose
// association list could not be read is left as it is. A vif that is gone
// keeps nothing. It returns the stations kept.
func keepShaping(tc map[string]*tcState, vif string, exists bool, get func(dev, dir string) *tcWant) []string {
	st := tc[vif]
	if st == nil || !exists || st.Dirty {
		return nil
	}
	var kept []string
	if st.Root && st.Dir == "dst" {
		for m, kbps := range st.Rate {
			get(vif, "dst").Root[m] = kbps
			kept = append(kept, m)
		}
	}
	if st.Ingress {
		for m, ifb := range st.To {
			if ist := tc[ifb]; ist != nil && ist.Root && ist.Rate[m] > 0 {
				get(vif, "dst").Redir[m] = ifb
				get(ifb, "src").Root[m] = ist.Rate[m]
				kept = append(kept, m)
			}
		}
	}
	return kept
}

// SyncRateLimits brings the tc trees in line with the applied Desired and
// the stations associated now. It returns the number of stations whose
// limit was added, changed or removed. Tick runs it; the agent may run it
// more often (it reads one assoclist per limited vif and `tc qdisc show` per
// shaped device, and changes nothing when nothing moved).
func (a *Applier) SyncRateLimits(ctx context.Context) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	d := a.current()
	if d == nil {
		return a.syncShaping(ctx, nil)
	}
	return a.syncShaping(ctx, a.layout(*d))
}

// syncShaping applies wantShaping(l) (l nil: remove every tree).
// The flow cache follows: off while anything is shaped, else back on
// (syncFlowCache).
func (a *Applier) syncShaping(ctx context.Context, l *layout) (int, error) {
	want := map[string]*tcWant{}
	var need shapeNeed
	if l != nil {
		w, n, err := a.wantShaping(ctx, l)
		if err != nil {
			return 0, err
		}
		want, need = w, n
	}
	state := a.loadTC()
	var devs []string
	for d := range want {
		devs = append(devs, d)
	}
	for d := range state {
		if want[d] == nil {
			devs = append(devs, d)
		}
	}
	// IFBs first: a redirect must land on a shaped device.
	sort.Slice(devs, func(i, j int) bool {
		fi, fj := strings.HasPrefix(devs[i], "ifb"), strings.HasPrefix(devs[j], "ifb")
		if fi != fj {
			return fi
		}
		return devs[i] < devs[j]
	})
	changed := map[string]bool{}
	var firstErr error
	for _, dev := range devs {
		st := state[dev]
		if st == nil {
			st = &tcState{}
			state[dev] = st
		}
		w := want[dev]
		if w == nil {
			w = &tcWant{}
		}
		if err := a.syncDev(ctx, dev, w, st, changed); err != nil {
			a.o.Logf("bcmwifi: rate limits on %s: %v (rebuilt at the next sync)", dev, err)
			state[dev] = &tcState{Dirty: true, Root: st.Root, Ingress: st.Ingress}
			if firstErr == nil {
				firstErr = fmt.Errorf("bcmwifi: rate limits on %s: %w", dev, err)
			}
		}
	}
	if !a.o.DryRun {
		if err := a.saveTC(state); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	macs := sortedKeys(changed)
	a.syncFlowCache(ctx, need)
	for _, m := range macs {
		if err := a.flushFlows(ctx, FlowScope{MAC: m}); err != nil {
			a.o.Logf("%v", err)
		}
	}
	return len(macs), firstErr
}

// syncDev reconciles one device. It runs every command checked (R24).
func (a *Applier) syncDev(ctx context.Context, dev string, w *tcWant, st *tcState, changed map[string]bool) error {
	tc := func(args ...string) error {
		argv := append([]string{"tc"}, args...)
		if a.o.DryRun {
			a.o.Logf("bcmwifi dry-run: %s", strings.Join(argv, " "))
			return nil
		}
		a.o.Logf("bcmwifi: %s", strings.Join(argv, " "))
		return a.run(ctx, argv...)
	}
	if !a.netdevExists(dev) {
		if len(w.Root) > 0 || len(w.Redir) > 0 {
			return fmt.Errorf("device %s missing", dev)
		}
		*st = tcState{}
		return nil
	}
	out, err := a.o.Run.Run(ctx, "tc", "qdisc", "show", "dev", dev)
	if err != nil {
		return fmt.Errorf("tc qdisc show: %w", err)
	}
	q := string(out)
	hasRoot := strings.Contains(q, "qdisc htb 1: root")
	hasIngress := strings.Contains(q, "qdisc ingress ffff:")
	if st.Dirty || st.Root && !hasRoot {
		if st.Root && !hasRoot && !st.Dirty {
			a.o.Logf("bcmwifi: rate limit tree on %s was removed by something else; rebuilding", dev)
		}
		for m := range st.Class {
			changed[m] = true
		}
		st.Root, st.Class, st.Rate = false, nil, nil
	}
	if st.Dirty || st.Ingress && !hasIngress {
		for m := range st.Redir {
			changed[m] = true
		}
		st.Ingress, st.Redir, st.To = false, nil, nil
	}
	dirty := st.Dirty
	st.Dirty = false

	// Root (egress) tree.
	if len(w.Root) == 0 {
		if st.Root || dirty && hasRoot {
			if err := tc("qdisc", "del", "dev", dev, "root"); err != nil {
				return err
			}
		}
		for m := range st.Class {
			changed[m] = true
		}
		st.Root, st.Class, st.Rate, st.Dir = false, nil, nil, ""
	} else {
		if !st.Root || st.Dir != w.Dir {
			if hasRoot {
				if err := tc("qdisc", "del", "dev", dev, "root"); err != nil {
					return err
				}
			}
			for m := range st.Class {
				changed[m] = true
			}
			if strings.HasPrefix(dev, "ifb") && !a.ifUp(dev) {
				if a.o.DryRun {
					a.o.Logf("bcmwifi dry-run: ip link set %s up", dev)
				} else if err := a.run(ctx, "ip", "link", "set", dev, "up"); err != nil {
					return err
				}
			}
			for _, c := range [][]string{
				{"qdisc", "add", "dev", dev, "root", "handle", "1:", "htb", "default", "1"},
				{"class", "add", "dev", dev, "parent", "1:", "classid", "1:1", "htb", "rate", "1000mbit"},
				{"qdisc", "add", "dev", dev, "parent", "1:1", "handle", "1001:", "sfq", "perturb", "10"},
			} {
				if err := tc(c...); err != nil {
					return err
				}
			}
			st.Root, st.Dir, st.Class, st.Rate = true, w.Dir, map[string]int{}, map[string]int{}
		}
		for _, m := range sortedKeys(st.Class) {
			if _, keep := w.Root[m]; keep {
				continue
			}
			id := st.Class[m]
			if err := tc("filter", "del", "dev", dev, "parent", "1:", "protocol", "all", "prio", "1", "handle", fmt.Sprintf("800::%x", id), "u32"); err != nil {
				return err
			}
			if err := tc("class", "del", "dev", dev, "classid", fmt.Sprintf("1:%x", id)); err != nil {
				return err
			}
			delete(st.Class, m)
			delete(st.Rate, m)
			changed[m] = true
		}
		for _, m := range sortedKeys(w.Root) {
			kbps := w.Root[m]
			rate := []string{"htb", "rate", fmt.Sprintf("%dkbit", kbps), "ceil", fmt.Sprintf("%dkbit", kbps)}
			if id, ok := st.Class[m]; ok {
				if st.Rate[m] != kbps {
					if err := tc(append([]string{"class", "change", "dev", dev, "parent", "1:", "classid", fmt.Sprintf("1:%x", id)}, rate...)...); err != nil {
						return err
					}
					st.Rate[m] = kbps
					changed[m] = true
				}
				continue
			}
			id, err := allocID(st.Class)
			if err != nil {
				return err
			}
			for _, c := range [][]string{
				append([]string{"class", "add", "dev", dev, "parent", "1:", "classid", fmt.Sprintf("1:%x", id)}, rate...),
				{"qdisc", "add", "dev", dev, "parent", fmt.Sprintf("1:%x", id), "handle", fmt.Sprintf("%x:", id), "sfq", "perturb", "10"},
				{"filter", "add", "dev", dev, "parent", "1:", "protocol", "all", "prio", "1", "handle", fmt.Sprintf("800::%x", id), "u32", "match", "ether", w.Dir, m, "classid", fmt.Sprintf("1:%x", id)},
			} {
				if err := tc(c...); err != nil {
					return err
				}
			}
			st.Class[m], st.Rate[m] = id, kbps
			changed[m] = true
		}
	}

	// Ingress (upload redirect to the radio's IFB).
	if len(w.Redir) == 0 {
		if st.Ingress || dirty && hasIngress {
			if err := tc("qdisc", "del", "dev", dev, "ingress"); err != nil {
				return err
			}
		}
		for m := range st.Redir {
			changed[m] = true
		}
		st.Ingress, st.Redir, st.To = false, nil, nil
		return nil
	}
	if !st.Ingress {
		if hasIngress {
			if err := tc("qdisc", "del", "dev", dev, "ingress"); err != nil {
				return err
			}
		}
		if err := tc("qdisc", "add", "dev", dev, "handle", "ffff:", "ingress"); err != nil {
			return err
		}
		st.Ingress, st.Redir, st.To = true, map[string]int{}, map[string]string{}
	}
	for _, m := range sortedKeys(st.Redir) {
		if to, keep := w.Redir[m]; keep && to == st.To[m] {
			continue
		}
		if err := tc("filter", "del", "dev", dev, "parent", "ffff:", "protocol", "all", "prio", "1", "handle", fmt.Sprintf("800::%x", st.Redir[m]), "u32"); err != nil {
			return err
		}
		delete(st.Redir, m)
		delete(st.To, m)
		changed[m] = true
	}
	for _, m := range sortedKeys(w.Redir) {
		if _, ok := st.Redir[m]; ok {
			continue
		}
		id, err := allocID(st.Redir)
		if err != nil {
			return err
		}
		if err := tc("filter", "add", "dev", dev, "parent", "ffff:", "protocol", "all", "prio", "1", "handle", fmt.Sprintf("800::%x", id),
			"u32", "match", "ether", "src", m, "action", "mirred", "egress", "redirect", "dev", w.Redir[m]); err != nil {
			return err
		}
		st.Redir[m], st.To[m] = id, w.Redir[m]
		changed[m] = true
	}
	return nil
}

// allocID returns the lowest free id in 0x10..0xfff (u32 node ids are 12
// bits; 1:1 and 1001: are the default class and leaf).
func allocID(used map[string]int) (int, error) {
	taken := map[int]bool{}
	for _, id := range used {
		taken[id] = true
	}
	for id := 0x10; id <= 0xfff; id++ {
		if !taken[id] {
			return id, nil
		}
	}
	return 0, fmt.Errorf("no free tc id")
}

// shapingTeardownSteps removes every tree the agent built (hand-back).
func (a *Applier) shapingTeardownSteps() []Step {
	state := a.loadTC()
	var st []Step
	for _, dev := range sortedKeys(state) {
		s := state[dev]
		if s.Root || s.Dirty {
			st = append(st, optStep("remove rate limits on "+dev, "tc", "qdisc", "del", "dev", dev, "root"))
		}
		if s.Ingress || s.Dirty {
			st = append(st, optStep("remove upload redirect on "+dev, "tc", "qdisc", "del", "dev", dev, "ingress"))
		}
	}
	if len(state) > 0 || a.exists(a.tcStatePath()) {
		st = append(st, Step{Kind: StepRemove, Desc: "remove tc state", Path: a.tcStatePath(), Optional: true})
	}
	return st
}
