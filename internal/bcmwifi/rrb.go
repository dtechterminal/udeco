// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"path"
	"strings"
)

// The RRB receive path for FT-SAE (docs/deco/features/ft-sae.md,
// "Receiving key holder frames"). The X20's bridge (TP-Link's tpbr) drops
// every unicast frame of EtherType 0x88b7 before it reaches br-lan, so the
// stock hostapd, whose RRB-OUI socket is bound to br-lan, never hears the
// other APs' PMK-R1 pulls, responses, pushes and sequence messages
// (verified on .232 2026-11-23: received on eth1, absent on br-lan,
// broadcast passes). The agent works around it in two parts:
//
//	broute  UDECO-RRB -p 0x88b7 -d <FT-SAE BSSID> -j DROP
//	        (BROUTING -j UDECO-RRB first; policy RETURN): the frame is
//	        handed to the stack on the port it came in on, not bridged;
//	shim    hostapd is started with LD_PRELOAD=RunDir/udeco_rrb.so
//	        (tools/deco-rrbshim), which binds its 0x88b7 sockets to all
//	        interfaces and still sends them out br-lan.
//
// hostapd then gets the frame on eth0/eth1 and processes it as usual (it
// drops what is not addressed to one of its BSSes, and every message is
// authenticated with the r0kh/r1kh key). The chain holds only the FT-SAE
// BSSIDs, so TP-Link's own 0x88b7 traffic between the Decos is untouched.
// The BSSIDs are kept in RunDir/rrb-ebtables.txt: a change rebuilds the
// chain; the chain and its jump go with the hand-back.

//go:embed rrbshim/udeco_rrb.so
var rrbShim []byte

const chainRRB = "UDECO-RRB"

// rrbShimPath is where the agent writes the shim.
func rrbShimPath(runDir string) string { return path.Join(runDir, "udeco_rrb.so") }

// rrbShimID names the shim's build in the hostapd conf, so a new shim (or
// the first one) restarts hostapd with it.
func rrbShimID() string {
	h := sha256.Sum256(rrbShim)
	return hex.EncodeToString(h[:8])
}

// usesRRB reports that a BSS exchanges PMK-R1s with other APs: FT-SAE
// (writeFT lists r0kh/r1kh peers and pmk_r1_push). FT-PSK derives its keys
// locally and needs no RRB.
func (x hapdBSS) usesRRB() bool {
	s := x.SSID
	return s.FT && s.FTSAE && (s.Security == SecWPA3 || s.Security == SecWPA2WPA3)
}

// usesRRB reports that some BSS of the radio does.
func (r hapdRadio) usesRRB() bool {
	for _, x := range r.BSS {
		if x.usesRRB() {
			return true
		}
	}
	return false
}

// hostapdArgv is the agent's hostapd command for radio primary, with the
// RRB shim preloaded when the radio serves FT-SAE (BusyBox env).
func hostapdArgv(runDir, primary string, shim bool) []string {
	argv := []string{"hostapd", "-B", "-P", pidPath(runDir, primary), ConfPath(runDir, primary)}
	if !shim {
		return argv
	}
	return append([]string{"env", "LD_PRELOAD=" + rrbShimPath(runDir)}, argv...)
}

func (a *Applier) rrbStatePath() string { return path.Join(a.o.RunDir, "rrb-ebtables.txt") }

// rrbLive is the live state of the broute chain.
type rrbLive struct {
	Chain bool   // UDECO-RRB exists in the broute table
	Jumps int    // BROUTING rules jumping to it
	State string // what was last built
}

func (a *Applier) readRRB(ctx context.Context) rrbLive {
	var g rrbLive
	if _, err := a.o.Run.Run(ctx, "ebtables", "-t", "broute", "-L", chainRRB); err == nil {
		g.Chain = true
	}
	if out, err := a.o.Run.Run(ctx, "ebtables", "-t", "broute", "-L", "BROUTING"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[len(f)-2] == "-j" && f[len(f)-1] == chainRRB {
				g.Jumps++
			}
		}
	}
	if b, err := a.readFile(a.rrbStatePath()); err == nil {
		g.State = string(b)
	}
	return g
}

// rrbSteps brings the broute chain to bssids (removing it when there are
// none). Every step is optional: without the chain FT-SAE roams fall back
// to a full SAE join, Wi-Fi itself is not held back.
func (a *Applier) rrbSteps(bssids []string, g rrbLive) (st []Step, foreign []string) {
	eb := func(desc string, args ...string) Step {
		return optStep(desc, append([]string{"ebtables", "-t", "broute"}, args...)...)
	}
	jump := []string{"-j", chainRRB}
	if len(bssids) == 0 {
		for i := 0; i < g.Jumps; i++ {
			st = append(st, eb("remove RRB broute jump", append([]string{"-D", "BROUTING"}, jump...)...))
		}
		if g.Chain {
			st = append(st, eb("flush "+chainRRB, "-F", chainRRB), eb("delete "+chainRRB, "-X", chainRRB))
		}
		if g.State != "" {
			st = append(st, Step{Kind: StepRemove, Desc: "remove RRB broute state", Path: a.rrbStatePath(), Optional: true})
		}
		return st, nil
	}
	state := "bssids " + strings.Join(bssids, " ") + "\n"
	if g.Chain && g.Jumps == 1 && g.State == state {
		return nil, nil
	}
	if g.State != "" && (!g.Chain || g.Jumps == 0) {
		foreign = append(foreign, "ebtables broute "+chainRRB+" or its BROUTING jump missing (removed by something else), rebuilt")
	}
	if !g.Chain {
		st = append(st, eb("create "+chainRRB, "-N", chainRRB))
	}
	// RETURN before the jump goes in: every other frame is bridged as before.
	st = append(st, eb(chainRRB+" policy RETURN", "-P", chainRRB, "RETURN"))
	for i := 1; i < g.Jumps; i++ {
		st = append(st, eb("remove duplicate RRB broute jump", append([]string{"-D", "BROUTING"}, jump...)...))
	}
	if g.Jumps == 0 {
		st = append(st, eb("RRB broute jump", append([]string{"-I", "BROUTING", "1"}, jump...)...))
	}
	st = append(st, eb("flush "+chainRRB, "-F", chainRRB))
	for _, b := range bssids {
		st = append(st, eb("hand RRB frames for "+b+" to hostapd", "-A", chainRRB, "-p", "0x88b7", "-d", b, "-j", "DROP"))
	}
	w := writeStep("write RRB broute state", a.rrbStatePath(), 0o600, []byte(state))
	w.Optional = true
	return append(st, w), foreign
}
