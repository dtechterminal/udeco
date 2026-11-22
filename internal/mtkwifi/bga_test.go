// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// ebDev is fakeDev with ebtables chains and FORWARD jumps kept, and
// bridges made with brctl having the kernel's snooping files.
type ebDev struct {
	*fakeDev
	chains  map[string][]string
	forward []string
}

func newEbDev(t *testing.T) *ebDev {
	return &ebDev{fakeDev: newFakeDev(t), chains: map[string][]string{}}
}

func (e *ebDev) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := e.fakeDev.Run(ctx, name, args...)
	if err != nil {
		return out, err
	}
	if name == "brctl" && args[0] == "addbr" {
		d := filepath.Join(e.root, "sys/class/net", args[1], "bridge")
		os.MkdirAll(d, 0o755)
		for k, v := range map[string]string{"hash_max": "512", "multicast_snooping": "1", "multicast_querier": "0"} {
			os.WriteFile(filepath.Join(d, k), []byte(v+"\n"), 0o644)
		}
	}
	if name != "ebtables" {
		return out, nil
	}
	switch args[0] {
	case "-L":
		if args[1] == "FORWARD" {
			return []byte("Bridge chain: FORWARD, entries: 1, policy: ACCEPT\n" + strings.Join(e.forward, "\n") + "\n"), nil
		}
		if _, ok := e.chains[args[1]]; !ok {
			return nil, os.ErrNotExist
		}
	case "-N":
		e.chains[args[1]] = nil
	case "-X":
		delete(e.chains, args[1])
	case "-F":
		if _, ok := e.chains[args[1]]; ok {
			e.chains[args[1]] = nil
		}
	case "-A":
		e.chains[args[1]] = append(e.chains[args[1]], strings.Join(args[2:], " "))
	case "-I":
		if args[1] == "FORWARD" {
			e.forward = append([]string{strings.Join(args[3:], " ")}, e.forward...)
		}
	case "-D":
		if args[1] == "FORWARD" {
			if i := slices.Index(e.forward, strings.Join(args[2:], " ")); i >= 0 {
				e.forward = slices.Delete(e.forward, i, i+1)
			}
		}
	}
	return out, nil
}

// ebApplier's clock moves past the settle time at each Tick.
func ebApplier(e *ebDev) (*Applier, *time.Duration) {
	now := new(time.Duration)
	*now = time.Hour
	return New(Options{Root: e.root, Run: e, RunDir: "/tmp/udeco", StateDir: "/state", Uplink: "eth0.4.1",
		VerifyTimeout: time.Millisecond, sleep: func(context.Context, time.Duration) error { return nil },
		mono: func() time.Duration { return *now }}), now
}

func countJumps(fw []string, chain string) int {
	n := 0
	for _, r := range fw {
		if r == "-j "+chain {
			n++
		}
	}
	return n
}

// TestBGAFilter: each served BSS drops the bridge group address both
// ways, one FORWARD jump, policy RETURN; a WLAN with bga_filter disabled
// is left out (no radio restart for that); an ebtables flush by something
// else is rebuilt by Tick; the hand-back removes the chain and the jump.
func TestBGAFilter(t *testing.T) {
	e := newEbDev(t)
	a, now := ebApplier(e)
	ctx := context.Background()
	p, _ := a.Plan(ctx, home())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	*now += defaultSettle + time.Second
	want := bgaVifs(a.o.Layout, a.live)
	if !slices.Contains(want, "rai1") || !slices.Contains(want, "ra0") || len(want) < 4 {
		t.Fatalf("vifs %v", want)
	}
	rules := e.chains[chainBGA]
	if len(rules) != 2*len(want) || countJumps(e.forward, chainBGA) != 1 {
		t.Fatalf("rules %v, FORWARD %v", rules, e.forward)
	}
	for _, v := range want {
		for _, r := range []string{"-i " + v + " -d 01:80:c2:00:00:00 -j DROP", "-o " + v + " -d 01:80:c2:00:00:00 -j DROP"} {
			if !slices.Contains(rules, r) {
				t.Errorf("missing %q in %v", r, rules)
			}
		}
	}
	if !slices.Contains(e.log, "ebtables -P UDECO-BGA RETURN") {
		t.Error("no RETURN policy")
	}
	// unchanged: nothing rebuilt
	n := len(e.log)
	a.Tick(ctx)
	if c := cmdsFrom(e.fakeDev, n, "ebtables -A"); len(c) > 0 {
		t.Errorf("rebuilt an unchanged filter: %v", c)
	}
	// bga_filter disabled on ORCHID (2.4 GHz only): its BSS leaves the
	// filter, live
	d := home()
	for i := range d.SSIDs {
		if d.SSIDs[i].SSID == "ORCHID" {
			d.SSIDs[i].NoBGAFilter = true
		}
	}
	n = len(e.log)
	p, _ = a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if c := cmdsFrom(e.fakeDev, n, "ifconfig ra"); len(c) > 0 {
		t.Errorf("bga_filter restarted the radio: %v", c)
	}
	if got := bgaVifs(a.o.Layout, a.live); len(got) != len(want)-1 || len(e.chains[chainBGA]) != 2*len(got) {
		t.Errorf("vifs %v, rules %v", got, e.chains[chainBGA])
	}
	// deleted by something else
	e.forward, e.chains = nil, map[string][]string{}
	*now += defaultSettle + time.Second
	a.Tick(ctx)
	if countJumps(e.forward, chainBGA) != 1 || len(e.chains[chainBGA]) == 0 {
		t.Errorf("not rebuilt: FORWARD %v, chain %v", e.forward, e.chains[chainBGA])
	}
	// hand-back
	a.mu.Lock()
	a.restoreBaseline(ctx)
	a.mu.Unlock()
	if _, ok := e.chains[chainBGA]; ok || countJumps(e.forward, chainBGA) != 0 {
		t.Errorf("hand-back left FORWARD %v, chain %v", e.forward, e.chains[chainBGA])
	}
	if _, err := os.Stat(a.bgaPath()); err == nil {
		t.Error("hand-back left the state file")
	}
}

// TestVLANBridgeSnoop: a VLAN bridge the agent makes gets the Deco's
// snooping values; a value that drifts is put back by Tick; bdg2 is not
// touched.
func TestVLANBridgeSnoop(t *testing.T) {
	e := newEbDev(t)
	lan := filepath.Join(e.root, "sys/class/net/bdg2/bridge")
	os.MkdirAll(lan, 0o755)
	os.WriteFile(filepath.Join(lan, "hash_max"), []byte("512\n"), 0o644)
	a, _ := ebApplier(e)
	ctx := context.Background()
	p, _ := a.Plan(ctx, home())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(e.root, "sys/class/net/br-v3/bridge")
	read := func(k string) string {
		b, _ := os.ReadFile(filepath.Join(dir, k))
		return strings.TrimSpace(string(b))
	}
	if read("hash_max") != "2048" || read("multicast_snooping") != "1" || read("multicast_querier") != "0" {
		t.Errorf("br-v3: %s %s %s", read("hash_max"), read("multicast_snooping"), read("multicast_querier"))
	}
	os.WriteFile(filepath.Join(dir, "multicast_snooping"), []byte("0\n"), 0o644)
	a.Tick(ctx)
	if read("multicast_snooping") != "1" {
		t.Error("drift not put back")
	}
	if b, _ := os.ReadFile(filepath.Join(lan, "hash_max")); strings.TrimSpace(string(b)) != "512" {
		t.Error("bdg2 changed")
	}
}
