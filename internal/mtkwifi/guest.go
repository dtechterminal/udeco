// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

// Guest WLANs. The JCOW414 has ebtables with the filter table and the ip,
// ip6, arp and mark matches (checked on the unit 2026-11-20), so a guest
// SSID gets the Deco's fail-closed isolation (bcmwifi guest.go, rendered
// by bcmwifi.GuestEbtables): its vifs jump to UDECO-GIN (FORWARD and INPUT
// in) and UDECO-GOUT (FORWARD out), chains with policy DROP that let a
// guest reach DHCP, DNS, the gateway and the internet, never a LAN host,
// and, with the portal on, only the allow-list and the portal until the
// controller authorises it (UDECO-GAUTH). A guest SSID is served only with
// a usable policy (the gateway's MAC and IP known).
//
// The chains are built, policy DROP first, and the jumps added before a
// guest SSID's netdev comes up; jumps of vifs that no longer carry a guest
// SSID go only after the radios were applied, so a vif is never
// unrestricted while it carries one. The hand-back removes everything.

const (
	guestFile     = "mtk-guest.txt"      // RunDir: the vifs and rules last built
	guestAuthFile = "mtk-guest-auth.txt" // RunDir: authorised guest MACs
)

// guestVifs are the netdevs of want's guest BSSes, sorted.
func guestVifs(layout []RadioDef, want map[string]RadioPlan) []string {
	var out []string
	for _, rd := range layout {
		rp := want[rd.Band]
		for i, b := range rp.BSS {
			if b.Guest && rp.slot(i) < len(rd.Ifaces) {
				out = append(out, rd.Ifaces[rp.slot(i)])
			}
		}
	}
	sort.Strings(out)
	return out
}

type guestBuilt struct {
	vifs  []string
	rules string
}

func renderGuest(r *bcmwifi.GuestRules) string {
	var b strings.Builder
	fmt.Fprintf(&b, "portal %t\n", r.Portal)
	for _, x := range r.In {
		fmt.Fprintf(&b, "in %s\n", strings.Join(x, " "))
	}
	for _, x := range r.Out {
		fmt.Fprintf(&b, "out %s\n", strings.Join(x, " "))
	}
	return b.String()
}

func (a *Applier) loadGuestBuilt() guestBuilt {
	b, err := os.ReadFile(a.dev(filepath.Join(a.o.RunDir, guestFile)))
	if err != nil {
		return guestBuilt{}
	}
	first, rest, _ := strings.Cut(string(b), "\n")
	return guestBuilt{vifs: strings.Fields(strings.TrimPrefix(first, "vifs")), rules: rest}
}

func guestJumps(vif string) [][]string {
	return [][]string{
		{"FORWARD", "-i", vif, "-j", chainGIn},
		{"FORWARD", "-o", vif, "-j", chainGOut},
		{"INPUT", "-i", vif, "-j", chainGIn},
	}
}

const (
	chainGIn   = "UDECO-GIN"
	chainGOut  = "UDECO-GOUT"
	chainGAuth = "UDECO-GAUTH"
)

func (a *Applier) eb(ctx context.Context, args ...string) error {
	return a.run(ctx, "ebtables", args...)
}

// chainExists: `ebtables -L <chain>` works (a read: not through a.run).
func (a *Applier) chainExists(ctx context.Context, c string) bool {
	if a.o.DryRun {
		return true
	}
	_, err := a.o.Run.Run(ctx, "ebtables", "-L", c)
	return err == nil
}

// syncGuest brings the guest chains to d's policy on want's guest vifs.
// prune false (before the radios change) only adds: the vifs built
// before keep their jumps; prune true (after) also removes what want no
// longer has. d nil or no guest vif (with prune) removes everything.
func (a *Applier) syncGuest(ctx context.Context, d *bcmwifi.Desired, want map[string]RadioPlan, prune bool) error {
	cur := a.loadGuestBuilt()
	var rules *bcmwifi.GuestRules
	if d != nil {
		rules = bcmwifi.GuestEbtables(d.Guest)
	}
	vifs := guestVifs(a.o.Layout, want)
	if rules == nil || len(vifs) == 0 {
		if !prune || len(cur.vifs) == 0 && cur.rules == "" {
			return nil
		}
		return a.removeGuest(ctx, cur)
	}
	if a.o.DryRun {
		a.o.Logf("mtkwifi: dry run: guest chains on %v", vifs)
		return nil
	}
	state := renderGuest(rules)
	keep := vifs
	if !prune {
		for _, v := range cur.vifs {
			if !slices.Contains(keep, v) {
				keep = append(keep, v)
			}
		}
		sort.Strings(keep)
	}
	chains := []string{chainGIn, chainGOut}
	if rules.Portal {
		chains = append(chains, chainGAuth)
	}
	ok := true
	for _, c := range chains {
		ok = ok && a.chainExists(ctx, c)
	}
	if ok && cur.rules == state && slices.Equal(cur.vifs, keep) {
		return nil
	}
	// chains first, policy DROP: a jump to an empty chain drops all
	for _, c := range chains {
		if !a.chainExists(ctx, c) {
			if err := a.eb(ctx, "-N", c); err != nil {
				return err
			}
		}
		if err := a.eb(ctx, "-P", c, "DROP"); err != nil {
			return err
		}
	}
	for _, v := range keep {
		if ok && slices.Contains(cur.vifs, v) {
			continue
		}
		for _, j := range guestJumps(v) {
			_ = a.eb(ctx, append([]string{"-D"}, j...)...) // never twice
			if err := a.eb(ctx, append([]string{"-I", j[0], "1"}, j[1:]...)...); err != nil {
				return err
			}
		}
	}
	if !ok || cur.rules != state {
		for _, c := range chains {
			if err := a.eb(ctx, "-F", c); err != nil {
				return err
			}
		}
		if rules.Portal {
			for _, m := range a.loadGuestAuth() {
				if err := a.eb(ctx, "-A", chainGAuth, "-s", m, "-j", "RETURN"); err != nil {
					return err
				}
			}
		}
		for _, x := range rules.In {
			if err := a.eb(ctx, append([]string{"-A", chainGIn}, x...)...); err != nil {
				return err
			}
		}
		for _, x := range rules.Out {
			if err := a.eb(ctx, append([]string{"-A", chainGOut}, x...)...); err != nil {
				return err
			}
		}
		if !rules.Portal && strings.HasPrefix(cur.rules, "portal true") {
			_ = a.eb(ctx, "-F", chainGAuth)
			_ = a.eb(ctx, "-X", chainGAuth)
		}
	}
	for _, v := range cur.vifs {
		if !slices.Contains(keep, v) {
			for _, j := range guestJumps(v) {
				_ = a.eb(ctx, append([]string{"-D"}, j...)...)
			}
		}
	}
	return writeFile(a.dev(filepath.Join(a.o.RunDir, guestFile)), []byte("vifs "+strings.Join(keep, " ")+"\n"+state), 0o600)
}

// removeGuest takes the guest jumps and chains away.
func (a *Applier) removeGuest(ctx context.Context, cur guestBuilt) error {
	for _, v := range cur.vifs {
		for _, j := range guestJumps(v) {
			_ = a.eb(ctx, append([]string{"-D"}, j...)...)
		}
	}
	for _, c := range []string{chainGIn, chainGOut, chainGAuth} {
		_ = a.eb(ctx, "-F", c)
	}
	for _, c := range []string{chainGIn, chainGOut, chainGAuth} {
		_ = a.eb(ctx, "-X", c)
	}
	err := os.Remove(a.dev(filepath.Join(a.o.RunDir, guestFile)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (a *Applier) loadGuestAuth() []string {
	b, err := os.ReadFile(a.dev(filepath.Join(a.o.RunDir, guestAuthFile)))
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

// AuthorizeGuest lets a guest past the portal restriction (the controller's
// authorize-guest): kept in the run dir for every rebuild, and added to the
// live auth chain.
func (a *Applier) AuthorizeGuest(ctx context.Context, mac string) error {
	return a.setGuestAuth(ctx, mac, true)
}

// UnauthorizeGuest takes the authorisation back and disconnects the guest.
func (a *Applier) UnauthorizeGuest(ctx context.Context, mac string) error {
	return a.setGuestAuth(ctx, mac, false)
}

func (a *Applier) setGuestAuth(ctx context.Context, mac string, on bool) error {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) != 6 {
		return fmt.Errorf("mtkwifi: guest authorisation: bad MAC %q", mac)
	}
	m := hw.String()
	a.mu.Lock()
	defer a.mu.Unlock()
	list := a.loadGuestAuth()
	had := slices.Contains(list, m)
	switch {
	case on && !had:
		list = append(list, m)
	case !on && had:
		list = slices.DeleteFunc(list, func(x string) bool { return x == m })
	}
	sort.Strings(list)
	if err := writeFile(a.dev(filepath.Join(a.o.RunDir, guestAuthFile)), []byte(strings.Join(list, "\n")), 0o600); err != nil {
		return err
	}
	if strings.HasPrefix(a.loadGuestBuilt().rules, "portal true") && a.chainExists(ctx, chainGAuth) {
		op := "-A"
		if !on {
			op = "-D"
		}
		if on != had {
			if err := a.eb(ctx, op, chainGAuth, "-s", m, "-j", "RETURN"); err != nil {
				return fmt.Errorf("mtkwifi: guest authorisation: %w", err)
			}
		}
	}
	a.kickDue = slices.DeleteFunc(a.kickDue, func(x string) bool { return x == m })
	if !on {
		if a.settling() {
			// live iwpriv waits for the settle time (flushLive); the
			// guest's RETURN rule is gone already
			a.kickDue = append(a.kickDue, m)
		} else {
			a.disconnect(ctx, m)
		}
	}
	return nil
}

// disconnect sends a station off every up BSS (live iwpriv: outside a
// settle time only).
func (a *Applier) disconnect(ctx context.Context, mac string) {
	for _, ifc := range a.upIfaces() {
		_ = a.run(ctx, "iwpriv", ifc, "set", "DisConnectSta="+strings.ToUpper(mac))
	}
}
