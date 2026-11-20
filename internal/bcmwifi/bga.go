// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"path"
	"strings"
)

// Bridge group address filter. The controller sends bga_filter=enabled on
// every WLAN (a U6 Pro has it too, tmp_system.cfg) together with ebtables
// lines for its own radios (`-t nat -A PREROUTING --in-interface ra0 -d
// BGA -j DROP`, system_cfg ebtables.N.cmd), which name the UAP's
// interfaces and are not run here. The agent applies the same filter to
// the vifs it serves:
//
//	FORWARD -j UDECO-BGA            (inserted first; policy RETURN)
//	UDECO-BGA -i <vif> -d BGA -j DROP
//	UDECO-BGA -o <vif> -d BGA -j DROP
//
// BGA is ebtables' name for 01:80:c2:00:00:00 exactly (802.1D bridge
// group address: STP BPDUs), so EAPOL (01:80:c2:00:00:03) and LLDP (:0e)
// are not affected. Without it, br-lan (STP off) forwards switch BPDUs
// onto the air, and a bridging client can inject BPDUs into the LAN.
// UDECO-BGA's policy is RETURN, so a frame it does not drop goes on
// through FORWARD (the guest chains among them) as before. The chain and
// its jump go with the hand-back. The agent's vifs are kept in
// RunDir/bga-ebtables.txt: a change rebuilds the chain.

const chainBGA = "UDECO-BGA"

func (a *Applier) bgaStatePath() string { return path.Join(a.o.RunDir, "bga-ebtables.txt") }

// bgaLive is the live state of the filter.
type bgaLive struct {
	Chain bool   // UDECO-BGA exists
	Jumps int    // FORWARD rules jumping to it
	State string // what was last built
}

func (a *Applier) readBGA(ctx context.Context) bgaLive {
	var g bgaLive
	if _, err := a.o.Run.Run(ctx, "ebtables", "-L", chainBGA); err == nil {
		g.Chain = true
	}
	if out, err := a.o.Run.Run(ctx, "ebtables", "-L", "FORWARD"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[len(f)-2] == "-j" && f[len(f)-1] == chainBGA {
				g.Jumps++
			}
		}
	}
	if b, err := a.readFile(a.bgaStatePath()); err == nil {
		g.State = string(b)
	}
	return g
}

// bgaVifs are the vifs l serves whose SSID keeps the filter (the
// controller's bga_filter, on unless disabled), by radio then vif.
func (l *layout) bgaVifs() []string {
	var out []string
	for _, r := range l.Radios {
		for _, u := range r.Used {
			if !u.SSID.NoBGAFilter {
				out = append(out, u.Vif)
			}
		}
	}
	return out
}

// bgaSteps brings the filter to vifs (removing it when there are none).
func (a *Applier) bgaSteps(vifs []string, g bgaLive) (st []Step, foreign []string) {
	eb := func(desc string, args ...string) Step { return cmdStep(desc, append([]string{"ebtables"}, args...)...) }
	jump := []string{"-j", chainBGA}
	if len(vifs) == 0 {
		for i := 0; i < g.Jumps; i++ {
			st = append(st, optStep("remove BGA filter jump", append([]string{"ebtables", "-D", "FORWARD"}, jump...)...))
		}
		if g.Chain {
			st = append(st, optStep("flush "+chainBGA, "ebtables", "-F", chainBGA), optStep("delete "+chainBGA, "ebtables", "-X", chainBGA))
		}
		if g.State != "" {
			st = append(st, Step{Kind: StepRemove, Desc: "remove BGA filter state", Path: a.bgaStatePath(), Optional: true})
		}
		return st, nil
	}
	state := "vifs " + strings.Join(vifs, " ") + "\n"
	if g.Chain && g.Jumps == 1 && g.State == state {
		return nil, nil
	}
	if g.State != "" && (!g.Chain || g.Jumps == 0) {
		foreign = append(foreign, "ebtables "+chainBGA+" or its FORWARD jump missing (removed by something else), rebuilt")
	}
	if !g.Chain {
		st = append(st, eb("create "+chainBGA, "-N", chainBGA))
	}
	// RETURN before the jump goes in: a frame the filter does not drop
	// carries on through FORWARD.
	st = append(st, eb(chainBGA+" policy RETURN", "-P", chainBGA, "RETURN"))
	for i := 1; i < g.Jumps; i++ {
		st = append(st, optStep("remove duplicate BGA filter jump", append([]string{"ebtables", "-D", "FORWARD"}, jump...)...))
	}
	if g.Jumps == 0 {
		st = append(st, eb("BGA filter jump", append([]string{"-I", "FORWARD", "1"}, jump...)...))
	}
	st = append(st, eb("flush "+chainBGA, "-F", chainBGA))
	for _, v := range vifs {
		st = append(st,
			eb("drop BPDUs from "+v, "-A", chainBGA, "-i", v, "-d", "BGA", "-j", "DROP"),
			eb("drop BPDUs to "+v, "-A", chainBGA, "-o", v, "-d", "BGA", "-j", "DROP"))
	}
	for i := range st {
		st[i].Optional = true // a filter that cannot be built never holds Wi-Fi back
	}
	return append(st, writeStep("write BGA filter state", a.bgaStatePath(), 0o600, []byte(state))), foreign
}
