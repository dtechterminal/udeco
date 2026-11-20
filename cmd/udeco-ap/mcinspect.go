// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Multicast inspection (the controller's fw3_caps 0x80,
// supportsMulticastInspect; docs/deco/features/multicast-inspect.md).
//
// With the bit claimed, the controller writes wireless.N.multicast.inspect=
// true on every non-service WLAN and asks for the "multicast" block in its
// inform replies (include_blocks); a real AP then reports, per client,
// sta_table[].multicast (types, groups, memberships, services, mdns_rr),
// which feeds the controller's per-client multicast statistics.
//
// Takeover only: the VAPs the controller's WLANs map to exist only when the
// agent owns Wi-Fi. A drop to observe mode, or R4 memory shedding, stops
// every reader and the block is no longer sent.

import (
	"context"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/mcinspect"
	"github.com/dtechterminal/udeco/internal/translate"
)

// mcastRetry is how long a VAP whose socket failed to open waits before
// the next try.
const mcastRetry = time.Minute

type mcastInspect struct {
	open  mcinspect.Opener // nil = mcinspect.Open (AF_PACKET)
	table *mcinspect.Table

	// loop goroutine only
	key     string          // the system_cfg the wanted set was read from
	want    map[string]bool // devnames with multicast.inspect on
	readers map[string]context.CancelFunc
	failed  map[string]time.Time // vif -> when its socket last failed to open
	done    chan string          // vif whose reader stopped on its own
}

func newMcastInspect(open mcinspect.Opener) *mcastInspect {
	return &mcastInspect{open: open, table: mcinspect.NewTable(), readers: map[string]context.CancelFunc{},
		failed: map[string]time.Time{}, done: make(chan string, 16)}
}

// mcastMerge runs the readers the controller's configuration asks for and
// adds each inspected client's multicast block to the inform fields. Loop
// goroutine only.
func (a *agent) mcastMerge(ctx context.Context, f map[string]any, s *apstate.Snapshot, info apstate.CfgInfo, now time.Time) {
	if a.mcast == nil {
		a.mcast = newMcastInspect(nil)
	}
	m := a.mcast
	if m.key != a.infoKey {
		b, _ := os.ReadFile(a.sysCfgPath)
		m.want, m.key = translate.MulticastInspect(translate.ParseCfg(string(b))), a.infoKey
	}
	// devname -> vif and vif -> its stations, for the VAPs to inspect
	vifs := map[string]string{}
	stations := map[string][]string{}
	if a.takeover.Load() && !a.shed.Load() {
		byDev := s.IfnamesByDevname(info)
		for d, vif := range byDev {
			if m.want[d] {
				vifs[d] = vif
			}
		}
		for _, r := range s.Radios {
			for _, v := range r.VAPs {
				for _, st := range v.Stations {
					stations[v.Iface] = append(stations[v.Iface], st.MAC)
				}
			}
		}
	}
	m.reconcile(ctx, a, vifs, now)
	for _, vif := range vifs {
		m.table.Retain(vif, stations[vif])
	}
	rows, _ := f["vap_table"].([]map[string]any)
	for _, row := range rows {
		d, _ := row["name"].(string)
		vif, ok := vifs[d]
		if !ok || m.readers[vif] == nil {
			continue
		}
		stas, _ := row["sta_table"].([]map[string]any)
		for _, st := range stas {
			mac, _ := st["mac"].(string)
			if b, ok := m.table.Block(vif, mac, now); ok {
				st["multicast"] = b
			}
		}
	}
}

// reconcile starts a reader on every wanted VAP that has none and stops
// the readers of VAPs no longer wanted.
func (m *mcastInspect) reconcile(ctx context.Context, a *agent, vifs map[string]string, now time.Time) {
drain:
	for {
		select {
		case vif := <-m.done: // its socket failed: retried after mcastRetry
			if c := m.readers[vif]; c != nil {
				c()
				delete(m.readers, vif)
				m.table.Drop(vif)
				m.failed[vif] = now
			}
		default:
			break drain
		}
	}
	wanted := map[string]bool{}
	for _, vif := range vifs {
		wanted[vif] = true
	}
	for vif, cancel := range m.readers {
		if !wanted[vif] {
			cancel()
			delete(m.readers, vif)
			m.table.Drop(vif)
			a.logf("multicast inspection: %s stopped", vif)
		}
	}
	var start []string
	for vif := range wanted {
		if m.readers[vif] == nil && (m.failed[vif].IsZero() || now.Sub(m.failed[vif]) >= mcastRetry) {
			start = append(start, vif)
		}
	}
	sort.Strings(start)
	open := m.open
	if open == nil {
		open = mcinspect.Open
	}
	for _, vif := range start {
		src, err := open(vif)
		if err != nil {
			if m.failed[vif].IsZero() {
				a.logf("multicast inspection: %s: %v (retrying every %s)", vif, err, mcastRetry)
			}
			m.failed[vif] = now
			continue
		}
		delete(m.failed, vif)
		rctx, cancel := context.WithCancel(ctx)
		m.readers[vif] = cancel
		a.logf("multicast inspection: %s started", vif)
		a.bg.Add(1)
		go func(vif string) {
			defer a.bg.Done()
			if err := mcinspect.Run(rctx, m.table, vif, src, time.Now); err != nil && rctx.Err() == nil {
				a.logf("multicast inspection: %s: %v", vif, strings.TrimPrefix(err.Error(), "mcinspect: "))
				select {
				case m.done <- vif:
				default:
				}
			}
		}(vif)
	}
}
