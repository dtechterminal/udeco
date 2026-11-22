// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Bridge group address filter (the controller's bga_filter, on unless a
// WLAN has it disabled), as the Deco applies it (bcmwifi bga.go): no STP
// BPDU (01:80:c2:00:00:00 exactly; EAPOL :03 and LLDP :0e pass) goes from
// the LAN onto a served BSS or from a bridging client into the LAN.
//
//	FORWARD -j UDECO-BGA            (inserted first; policy RETURN)
//	UDECO-BGA -i <vif> -d 01:80:c2:00:00:00 -j DROP
//	UDECO-BGA -o <vif> -d 01:80:c2:00:00:00 -j DROP
//
// The address is written out rather than as ebtables' BGA alias, which an
// older ebtables may not know. RETURN: a frame the filter does not drop
// goes on through FORWARD (the proxy ARP and guest chains). Built after
// the radios were applied and re-checked each Tick after the settle time
// (a chain deleted by something else is rebuilt with its jump; as for
// the guest chains, a FORWARD jump deleted on its own is not seen); a
// filter that cannot be built never holds Wi-Fi back (logged). The hand-back removes the chain and its jump. The
// vifs built are kept in RunDir/mtk-bga.txt.

const (
	chainBGA = "UDECO-BGA"
	bgaFile  = "mtk-bga.txt"
	bgaMAC   = "01:80:c2:00:00:00"
)

// bgaVifs are the netdevs of want's BSSes that keep the filter, sorted.
func bgaVifs(layout []RadioDef, want map[string]RadioPlan) []string {
	var out []string
	for _, rd := range layout {
		rp := want[rd.Band]
		if !rp.On {
			continue
		}
		for i, b := range rp.BSS {
			if !b.NoBGA && rp.slot(i) < len(rd.Ifaces) {
				out = append(out, rd.Ifaces[rp.slot(i)])
			}
		}
	}
	slices.Sort(out)
	return out
}

func (a *Applier) bgaPath() string { return a.dev(filepath.Join(a.o.RunDir, bgaFile)) }

// syncBGA brings the filter to want's vifs (none: removes it).
func (a *Applier) syncBGA(ctx context.Context, want map[string]RadioPlan) {
	vifs := bgaVifs(a.o.Layout, want)
	if a.o.DryRun {
		if len(vifs) > 0 {
			a.o.Logf("mtkwifi: dry run: BGA filter on %v", vifs)
		}
		return
	}
	b, _ := os.ReadFile(a.bgaPath())
	built := string(b)
	if len(vifs) == 0 {
		if built != "" || a.chainExists(ctx, chainBGA) {
			a.removeBGA(ctx)
		}
		return
	}
	state := "vifs " + strings.Join(vifs, " ") + "\n"
	chain := a.chainExists(ctx, chainBGA)
	if chain && built == state {
		return
	}
	if built != "" && !chain {
		a.o.Logf("mtkwifi: ebtables %s missing (removed by something else): rebuilt", chainBGA)
	}
	fail := func(err error) { a.o.Logf("mtkwifi: BGA filter: %v", err) }
	if !chain {
		if err := a.eb(ctx, "-N", chainBGA); err != nil {
			fail(err)
			return
		}
	}
	// RETURN before the jump goes in: a frame not dropped carries on
	if err := a.eb(ctx, "-P", chainBGA, "RETURN"); err != nil {
		fail(err)
		return
	}
	if err := a.eb(ctx, "-F", chainBGA); err != nil {
		fail(err)
		return
	}
	for _, v := range vifs {
		for _, dir := range []string{"-i", "-o"} {
			if err := a.eb(ctx, "-A", chainBGA, dir, v, "-d", bgaMAC, "-j", "DROP"); err != nil {
				fail(err)
				return
			}
		}
	}
	if !chain || built == "" {
		_ = a.eb(ctx, "-D", "FORWARD", "-j", chainBGA) // never twice
		if err := a.eb(ctx, "-I", "FORWARD", "1", "-j", chainBGA); err != nil {
			fail(err)
			return
		}
	}
	if err := writeFile(a.bgaPath(), []byte(state), 0o600); err != nil {
		fail(err)
	}
}

// removeBGA takes the jump and the chain away (hand-back, or no BSS keeps
// the filter).
func (a *Applier) removeBGA(ctx context.Context) {
	if !a.o.DryRun {
		_ = a.eb(ctx, "-D", "FORWARD", "-j", chainBGA)
		_ = a.eb(ctx, "-F", chainBGA)
		_ = a.eb(ctx, "-X", chainBGA)
	}
	_ = os.Remove(a.bgaPath())
}
