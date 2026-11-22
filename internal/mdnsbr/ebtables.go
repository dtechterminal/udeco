// SPDX-License-Identifier: GPL-2.0-or-later

package mdnsbr

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Interception of a vif's native mDNS (ebtables, filter table).
//
// A vif whose own-VLAN filter restricts something must not get the bridge's
// mDNS unfiltered, so the bridge's copy is dropped on the way to it and the
// engine sends it the filtered copy on the vif itself (which bypasses
// ebtables):
//
//	FORWARD -o <vif> -j UDECO-MDNS          (inserted first)
//	UDECO-MDNS: -p IPv4 --ip-dst 224.0.0.251 --ip-proto udp --ip-dport 5353 -j DROP
//	            -p IPv6 --ip6-dst ff02::fb --ip6-proto udp --ip6-dport 5353 -j DROP
//	            (policy RETURN)
//
// Only multicast mDNS is dropped (unicast replies to port 5353 pass), and
// only towards the vif: what its clients send is bridged as before. The
// X20's ebtables 2.0.10-4 has the ip and ip6 matches with --ip(6)-dport
// (checked on .205, 2026-11-19). A jump is only installed for a vif the
// engine is serving (service.go): if the agent stops, Close removes the
// chain; a crashed agent leaves it until Cleanup (the next start) or a
// reboot, during which the vif gets no mDNS at all (closed, not open).

// ChainName is the agent's ebtables chain for mDNS interception.
const ChainName = "UDECO-MDNS"

// Runner runs a command (the agent's runner).
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

var chainRules = [][]string{
	{"-p", "IPv4", "--ip-dst", "224.0.0.251", "--ip-proto", "udp", "--ip-dport", "5353", "-j", "DROP"},
	{"-p", "IPv6", "--ip6-dst", "ff02::fb", "--ip6-proto", "udp", "--ip6-dport", "5353", "-j", "DROP"},
}

// Interceptor keeps the ebtables state for a set of vifs.
type Interceptor struct {
	Run    Runner
	DryRun bool
	Logf   func(string, ...any)
	// NoFlowCache: the unit has no Broadcom flow cache (the JCOW414): no
	// `fc flush` after a jump changes
	NoFlowCache bool
}

func (x *Interceptor) logf(f string, a ...any) {
	if x.Logf != nil {
		x.Logf(f, a...)
	}
}

func (x *Interceptor) do(ctx context.Context, args ...string) error {
	if x.DryRun {
		x.logf("mdns bridge: would run: ebtables %s", strings.Join(args, " "))
		return nil
	}
	if out, err := x.Run.Run(ctx, "ebtables", args...); err != nil {
		return fmt.Errorf("ebtables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// jumps lists the vifs FORWARD sends to the chain.
func (x *Interceptor) jumps(ctx context.Context) ([]string, error) {
	out, err := x.Run.Run(ctx, "ebtables", "-L", "FORWARD")
	if err != nil {
		return nil, fmt.Errorf("ebtables -L FORWARD: %v", err)
	}
	var vifs []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		var vif, target string
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "-o", "--out-if", "--out-interface":
				vif = f[i+1]
			case "-j":
				target = f[i+1]
			}
		}
		if target == ChainName && vif != "" {
			vifs = append(vifs, vif)
		}
	}
	return vifs, nil
}

// chainOK reports whether the chain exists with exactly our rules (as
// ebtables -L prints them: the arguments in order, maybe with other
// spellings; checked loosely by the DROP count and the addresses).
func (x *Interceptor) chainOK(ctx context.Context) (exists, ok bool) {
	out, err := x.Run.Run(ctx, "ebtables", "-L", ChainName)
	if err != nil {
		return false, false
	}
	s := string(out)
	return true, strings.Contains(s, "policy: RETURN") && strings.Count(s, "-j DROP") == 2 && strings.Contains(s, "224.0.0.251") &&
		strings.Contains(s, "ff02::fb") && strings.Count(s, "5353") == 2
}

// Set makes the vifs (and only them) intercepted. On an error the state is
// partial; the caller retries, and a vif whose jump is missing just gets
// its bridge's mDNS unfiltered.
func (x *Interceptor) Set(ctx context.Context, vifs []string) error {
	want := map[string]bool{}
	for _, v := range vifs {
		if !devRE.MatchString(v) {
			return fmt.Errorf("mdns bridge: %q is not an interface name", v)
		}
		want[v] = true
	}
	have, err := x.jumps(ctx)
	if err != nil {
		return err
	}
	if len(want) == 0 {
		return x.clear(ctx, have)
	}
	exists, ok := x.chainOK(ctx)
	if !ok {
		if exists {
			// rebuild in place: jumps keep pointing at it
			if err := x.do(ctx, "-F", ChainName); err != nil {
				return err
			}
			if err := x.do(ctx, "-P", ChainName, "RETURN"); err != nil {
				return err
			}
		} else if err := x.do(ctx, "-N", ChainName, "-P", "RETURN"); err != nil {
			return err
		}
		for _, r := range chainRules {
			if err := x.do(ctx, append([]string{"-A", ChainName}, r...)...); err != nil {
				return err
			}
		}
	}
	got := map[string]int{}
	for _, v := range have {
		got[v]++
	}
	var errs []string
	changed := map[string]bool{}
	for _, v := range sortedSet(want) {
		if got[v] == 0 {
			if err := x.do(ctx, "-I", "FORWARD", "1", "-o", v, "-j", ChainName); err != nil {
				errs = append(errs, err.Error())
			}
			changed[v] = true
		}
	}
	for _, v := range sortedKeys(got) {
		for i := 0; i < got[v]; i++ {
			if !want[v] || i > 0 { // not wanted, or a duplicate
				if err := x.do(ctx, "-D", "FORWARD", "-o", v, "-j", ChainName); err != nil {
					errs = append(errs, err.Error())
				}
				changed[v] = true
			}
		}
	}
	x.flush(ctx, changed)
	if len(errs) > 0 {
		return fmt.Errorf("mdns bridge: %s", strings.Join(errs, "; "))
	}
	return nil
}

// flush drops the Broadcom flow cache's flows through the vifs whose path
// changed (audit R21); best effort, as bcmwifi's: a missing fc is no error.
func (x *Interceptor) flush(ctx context.Context, vifs map[string]bool) {
	if x.DryRun || x.NoFlowCache {
		return
	}
	for _, v := range sortedSet(vifs) {
		x.Run.Run(ctx, "fc", "flush", "--if", v)
	}
}

func (x *Interceptor) clear(ctx context.Context, have []string) error {
	var errs []string
	changed := map[string]bool{}
	for _, v := range have {
		if err := x.do(ctx, "-D", "FORWARD", "-o", v, "-j", ChainName); err != nil {
			errs = append(errs, err.Error())
		}
		changed[v] = true
	}
	x.flush(ctx, changed)
	if exists, _ := x.chainOK(ctx); exists {
		if err := x.do(ctx, "-X", ChainName); err != nil {
			// a chain still referenced cannot go: flush it so it drops nothing
			if err2 := x.do(ctx, "-F", ChainName); err2 != nil {
				errs = append(errs, err.Error(), err2.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("mdns bridge: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Clear removes every jump to the chain and the chain itself.
func (x *Interceptor) Clear(ctx context.Context) error {
	have, err := x.jumps(ctx)
	if err != nil {
		return err
	}
	return x.clear(ctx, have)
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
