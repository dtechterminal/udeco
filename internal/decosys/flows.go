package decosys

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The Broadcom flow cache (and the Archer hardware path) forwards
// established flows past the bridge, VLAN devices, ebtables and qdiscs
// (audit D1). A flow learned before a bridge, VLAN, loop-guard or tc change
// keeps its old path until it idles out, which a long stream never does;
// 'brctl delif/addif' evicts nothing. R21: flush after every such change, as
// narrowly as possible.

// FlowScope selects the flows FlushFlows removes. At most one field may be
// set; neither flushes the whole cache.
type FlowScope struct {
	Dev string // flows through this interface ('fc flush --if')
	MAC string // flows to or from this station ('fc flush --mac')
}

const fcBrlist = "/proc/fcache/brlist"

// FlushFlows flushes flow-cache entries (R21). A unit without the flow
// cache ('fc' missing) has nothing to flush. With a MAC, it then checks that
// /proc/fcache/brlist no longer lists the MAC and returns an error when it
// still does. It is safe to call from any goroutine; bcmwifi and the agent's
// loop guard share it.
func (m *Manager) FlushFlows(ctx context.Context, s FlowScope) error {
	if s.Dev != "" && s.MAC != "" {
		return fmt.Errorf("flush flows: set Dev or MAC, not both")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushFlows(ctx, s)
}

// flushFlows is FlushFlows with m.mu held.
func (m *Manager) flushFlows(ctx context.Context, s FlowScope) error {
	fc := m.bin("fc")
	if !strings.HasPrefix(fc, "/") {
		m.note("no-fc", "fc not found: no flow cache to flush")
		return nil
	}
	args := []string{"flush"}
	switch {
	case s.Dev != "":
		args = append(args, "--if", s.Dev)
	case s.MAC != "":
		args = append(args, "--mac", strings.ToLower(s.MAC))
	}
	if err := m.mutate(ctx, fc, args...); err != nil {
		return err
	}
	if s.MAC == "" || m.o.DryRun {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(m.o.Root, fcBrlist))
	if err != nil {
		return nil // no bridge flow list to check
	}
	if n := strings.Count(strings.ToLower(string(b)), strings.ToLower(s.MAC)); n > 0 {
		return fmt.Errorf("flush flows: %s still in %s (%d row(s))", s.MAC, fcBrlist, n)
	}
	return nil
}
