// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"fmt"
	"strings"
)

// Broadcom flow cache (interference audit D1, requirement R21).
//
// The X20's flow cache (and Archer HW forwarding) carries established flows
// past the bridge, ebtables and qdiscs. A flow learnt before a datapath change
// keeps its old path until it idles out, so every change the agent makes to
// bridges, VLAN devices, ebtables, tc or the block list is followed by a
// flush. `fc` usage on .205 (read 2026-11-18):
//
//	fc flush [ --hw ]
//	   [ --if <interface> ] | [ --flow <flowid> ] | [ <--mac|--dstmac|--srcmac> <macaddr> ]
//
// and /proc/fcache/brlist lists the bridged flows, MACs as <aa:bb:..>,
// tx_dev last.

// FlowScope selects the flows FlushFlows removes. The zero value flushes the
// whole cache.
type FlowScope struct {
	If  string // flows through this interface (fc flush --if)
	MAC string // flows from or to this station (fc flush --mac)
}

func (s FlowScope) argv() []string {
	switch {
	case s.MAC != "":
		return []string{"fc", "flush", "--mac", s.MAC}
	case s.If != "":
		return []string{"fc", "flush", "--if", s.If}
	}
	return []string{"fc", "flush"}
}

// flushStep is the plan step that flushes the whole cache after the plan's
// datapath changes. It is optional: a missing fc must not fail an apply.
func flushStep() Step {
	s := cmdStep("flush flow cache (audit R21)", "fc", "flush")
	s.Optional = true
	return s
}

// datapathStep reports a step after which established flows must be flushed:
// a bridge port change, a bridge or VLAN device created or deleted, or an
// ebtables change.
func datapathStep(s Step) bool {
	switch s.Kind {
	case StepBridgeAdd, StepBridgeDel:
		return true
	case StepCmd:
		switch s.Argv[0] {
		case "ebtables":
			return true
		case "brctl":
			return len(s.Argv) > 1 && (s.Argv[1] == "addbr" || s.Argv[1] == "delbr" || s.Argv[1] == "addif" || s.Argv[1] == "delif")
		case "ip":
			return len(s.Argv) > 2 && s.Argv[1] == "link" && (s.Argv[2] == "add" || s.Argv[2] == "del")
		}
	}
	return false
}

// withFlush appends one whole-cache flush when steps change the datapath.
func withFlush(steps []Step) []Step {
	for _, s := range steps {
		if datapathStep(s) {
			return append(steps, flushStep())
		}
	}
	return steps
}

// FlushFlows flushes the flow cache for s and then counts the flows left in
// /proc/fcache/brlist for s's MAC or tx interface. Flows still listed are
// logged, not an error: an active stream is re-learnt at once, on its new
// path. Use it after a datapath change made outside this package (decosys,
// the agent's loop guard).
func (a *Applier) FlushFlows(ctx context.Context, s FlowScope) error {
	if s.MAC != "" {
		m := normMAC(s.MAC)
		if m == "" {
			return fmt.Errorf("bcmwifi: flush flows: bad MAC %q", s.MAC)
		}
		s.MAC = m
	}
	if s.If != "" && !ifnameOK(s.If) {
		return fmt.Errorf("bcmwifi: flush flows: bad interface %q", s.If)
	}
	return a.flushFlows(ctx, s)
}

func (a *Applier) flushFlows(ctx context.Context, s FlowScope) error {
	argv := s.argv()
	if a.o.DryRun {
		a.o.Logf("bcmwifi dry-run: %s", strings.Join(argv, " "))
		return nil
	}
	if err := a.run(ctx, argv...); err != nil {
		return fmt.Errorf("bcmwifi: %s: %w", strings.Join(argv, " "), err)
	}
	if n := a.cachedFlows(s); n > 0 {
		a.o.Logf("bcmwifi: %d flows for %s still in the flow cache after the flush (re-learnt on the new path)", n, strings.Join(argv[2:], " "))
	}
	return nil
}

// cachedFlows counts /proc/fcache/brlist rows for s (MAC anywhere in the
// row, or tx_dev equal to s.If); -1 when unreadable or s is whole-cache.
func (a *Applier) cachedFlows(s FlowScope) int {
	if s.MAC == "" && s.If == "" {
		return -1
	}
	b, err := a.readFile("/proc/fcache/brlist")
	if err != nil {
		return -1
	}
	n := 0
	for _, line := range strings.Split(strings.ToLower(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || !strings.HasPrefix(f[0], "0x") {
			continue
		}
		if s.MAC != "" && strings.Contains(line, "<"+s.MAC+">") || s.If != "" && f[len(f)-1] == s.If {
			n++
		}
	}
	return n
}

// ifnameOK accepts a Linux interface name (also used for tc and ebtables
// arguments, which go to argv, never a shell).
func ifnameOK(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
