// SPDX-License-Identifier: GPL-2.0-or-later

package main

// blockSync turns the controller's blocked_sta into the Deco block list
// (docs/deco/design.md §7). The controller sends the site-wide list to every
// AP; the most recently received list wins. Writes go through the Mesh
// (0x4017 add, 0x4019 remove) and only MACs udeco itself added are ever
// removed; those are kept in blocks.json. With apply=false the Mesh logs
// the plan instead, once per change of plan.
//
// After a restart, before any list is received, the desired list is the
// last received one saved in blocks.json; without one (apply=false, or an
// older blocks.json) it is the union of the runners' saved lists. Either way
// the choice is deterministic, so a runner whose saved list is out of date
// (its unit was gated when the list changed) cannot make blocks flap.

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dtechterminal/udeco/internal/atomicfile"
	"github.com/dtechterminal/udeco/internal/deco"
)

const blockEvery = 60 * time.Second

type blockList struct {
	macs []string
	// seq orders the lists: received ones count up from 1, the list saved
	// in blocks.json is 0 and runner seeds are -1. Lists tied at the top
	// seq are merged (only seeds can tie).
	seq int
}

const (
	seqSaved = 0
	seqSeed  = -1
	// savedKey holds the blocks.json list in lists; no runner has this name.
	savedKey = "\x00blocks.json"
)

type blockSync struct {
	mesh  meshAPI
	apply bool
	path  string
	logf  func(string, ...any)
	every time.Duration

	mu     sync.Mutex
	lists  map[string]blockList // runner -> its latest list
	seq    int
	latest []string // the last received list (seq), to persist
	wake   chan struct{}

	// owned by Run
	added    map[string]bool // MACs udeco blocked (blocks.json)
	saved    *[]string       // the last received list as in blocks.json; nil: none
	savedSeq int             // seq of the list in saved, 0 if loaded at start
	lastPlan string
	sentAt   time.Time
	disabled bool
}

func newBlockSync(m meshAPI, apply bool, path string, logf func(string, ...any)) *blockSync {
	b := &blockSync{mesh: m, apply: apply, path: path, logf: logf, every: blockEvery,
		lists: map[string]blockList{}, wake: make(chan struct{}, 1), added: map[string]bool{}}
	var saved blocksFile
	if raw, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(raw, &saved); err != nil {
			logf("blocks: %s unreadable (%v): starting with no udeco-added blocks", path, err)
			saved = blocksFile{}
		}
	}
	for _, m := range saved.Added {
		if n := deco.NormMAC(m); n != "" {
			b.added[n] = true
		}
	}
	if saved.Desired != nil {
		norm := normMACs(*saved.Desired)
		b.saved = &norm
		b.lists[savedKey] = blockList{macs: norm, seq: seqSaved}
	}
	return b
}

// blocksFile is blocks.json.
type blocksFile struct {
	Added []string `json:"added"`
	// Desired is the last blocked_sta received from the controller, the
	// starting point after a restart. Absent: none received yet.
	Desired *[]string `json:"desired,omitempty"`
}

func normMACs(macs []string) []string {
	norm := []string{}
	for _, m := range macs {
		if n := deco.NormMAC(m); n != "" {
			norm = append(norm, n)
		}
	}
	sort.Strings(norm)
	return norm
}

// Set records the blocked list a runner just received.
func (b *blockSync) Set(runner string, macs []string) { b.put(runner, macs, false) }

// Seed records a runner's list from saved state; any received list, and the
// list saved in blocks.json, wins over it.
func (b *blockSync) Seed(runner string, macs []string) { b.put(runner, macs, true) }

func (b *blockSync) put(runner string, macs []string, seed bool) {
	norm := normMACs(macs)
	b.mu.Lock()
	seq := seqSeed
	if !seed {
		b.seq++
		seq = b.seq
		b.latest = norm
	}
	b.lists[runner] = blockList{macs: norm, seq: seq}
	b.mu.Unlock()
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// Drop forgets a runner's list (it stopped: removed from the controller).
func (b *blockSync) Drop(runner string) {
	b.mu.Lock()
	delete(b.lists, runner)
	b.mu.Unlock()
}

// desired is the most recently received list, else the one saved in
// blocks.json, else the union of the runners' seeds; ok=false when there is
// none (nothing is changed then). The result never depends on map order.
func (b *blockSync) desired() (map[string]bool, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	top, ok := seqSeed-1, false
	for _, l := range b.lists {
		if l.seq > top {
			top, ok = l.seq, true
		}
	}
	want := map[string]bool{}
	for _, l := range b.lists {
		if l.seq == top {
			for _, m := range l.macs {
				want[m] = true
			}
		}
	}
	return want, ok
}

// persistLatest saves a newly received list to blocks.json (apply=true
// only: a dry run writes no state).
func (b *blockSync) persistLatest() {
	if !b.apply {
		return
	}
	b.mu.Lock()
	seq, latest := b.seq, b.latest
	b.mu.Unlock()
	if seq == 0 || seq == b.savedSeq {
		return
	}
	l := append([]string{}, latest...)
	b.saved, b.savedSeq = &l, seq
	b.save()
}

// Run reconciles on every change and every minute.
func (b *blockSync) Run(ctx context.Context) {
	t := time.NewTicker(b.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.wake:
		case <-t.C: // with apply=false a repeated plan is not logged again
		}
		b.reconcile(ctx)
	}
}

// reconcile adds missing blocks and removes udeco's own stale ones.
func (b *blockSync) reconcile(ctx context.Context) {
	want, ok := b.desired()
	if !ok {
		return
	}
	b.persistLatest()
	s := b.mesh.Snapshot()
	switch {
	case s.Blocks.Disabled:
		if !b.disabled {
			b.logf("blocks: the Deco does not answer the block list (0x4018): blocking unsupported this session")
			b.disabled = true
		}
		return
	case !s.Connected || s.Blocks.Value == nil:
		return // retried on the next change or tick
	case !b.sentAt.IsZero() && !s.Blocks.At.After(b.sentAt):
		return // our last write is not in the cache yet
	}
	b.disabled = false
	cur := map[string]bool{}
	for _, e := range s.Blocks.Value.ClientList {
		if n := deco.NormMAC(e.MAC); n != "" {
			cur[n] = true
		}
	}
	var add, del []string
	for m := range want {
		if !cur[m] {
			add = append(add, m)
		}
	}
	changed := false
	for m := range b.added {
		switch {
		case want[m]:
		case cur[m]:
			del = append(del, m)
		default: // unblocked by someone else: no longer ours
			delete(b.added, m)
			changed = true
		}
	}
	sort.Strings(add)
	sort.Strings(del)
	plan := "+" + strings.Join(add, ",") + " -" + strings.Join(del, ",")
	if len(add) == 0 && len(del) == 0 {
		b.lastPlan = ""
		if changed {
			b.save()
		}
		return
	}
	if !b.apply && plan == b.lastPlan {
		return // the dry run was logged already
	}
	b.lastPlan = plan
	sent := false
	for _, c := range []struct {
		kind deco.CommandKind
		macs []string
	}{{deco.CmdBlock, add}, {deco.CmdUnblock, del}} {
		if len(c.macs) == 0 {
			continue
		}
		var res deco.CommandResult
		select {
		case <-ctx.Done():
			return
		case res = <-b.mesh.Submit(deco.Command{Kind: c.kind, MACs: c.macs}):
		}
		switch {
		case res.Err != nil:
			b.logf("blocks: %s %v: not done: %v", c.kind, c.macs, res.Err)
		case res.DryRun:
			b.logf("blocks: apply=false: %s %v not sent", c.kind, c.macs)
		default:
			b.logf("blocks: %s %v done", c.kind, c.macs)
			for _, m := range c.macs {
				if c.kind == deco.CmdBlock {
					b.added[m] = true
				} else {
					delete(b.added, m)
				}
			}
			sent, changed = true, true
		}
	}
	if changed {
		b.save()
	}
	if sent {
		b.sentAt = time.Now()
		b.mesh.RequestPoll(deco.OpGetBlockList)
	}
}

func (b *blockSync) save() {
	out := blocksFile{Added: []string{}, Desired: b.saved}
	for m := range b.added {
		out.Added = append(out.Added, m)
	}
	sort.Strings(out.Added)
	raw, _ := json.MarshalIndent(out, "", "  ")
	if err := atomicfile.Write(b.path, b.path+".tmp", raw, 0o600); err != nil {
		b.logf("blocks: saving: %v", err)
	}
}
