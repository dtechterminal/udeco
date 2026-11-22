// SPDX-License-Identifier: GPL-2.0-or-later

package mdnsbr

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Service runs the engine on the plan's ports: one socket and reader per
// port, sends on the ports' sockets, and the ebtables interception of the
// vifs the engine serves.

// Options configure a Service.
type Options struct {
	Open   Opener // nil = Open (AF_PACKET, Linux)
	Run    Runner // ebtables; required unless DryRun
	DryRun bool   // log what would run; no sockets, no ebtables
	Logf   func(string, ...any)
	Rates  Rates            // zero = DefaultRates
	Now    func() time.Time // nil = time.Now
	Retry  time.Duration    // a port that failed to open waits this long (0 = 15 s)
	// NoFlowCache: no Broadcom flow cache to flush (the JCOW414;
	// Interceptor.NoFlowCache)
	NoFlowCache bool
}

// Service is the running bridge.
type Service struct {
	o   Options
	eng *Engine
	x   *Interceptor
	ctx context.Context
	end context.CancelFunc
	wg  sync.WaitGroup

	mu       sync.Mutex
	conns    map[string]Conn
	stop     map[string]context.CancelFunc
	failed   map[string]time.Time
	done     chan string
	sig      string   // the last plan applied
	icept    []string // vifs intercepted now
	sendErrs uint64
}

// NewService returns a stopped service; Update starts it. Readers live
// until Close or ctx ends.
func NewService(ctx context.Context, o Options) *Service {
	if o.Open == nil {
		o.Open = Open
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Rates == (Rates{}) {
		o.Rates = DefaultRates
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Retry <= 0 {
		o.Retry = 15 * time.Second
	}
	c, end := context.WithCancel(ctx)
	return &Service{o: o, eng: NewEngine(o.Rates), x: &Interceptor{Run: o.Run, DryRun: o.DryRun, Logf: o.Logf, NoFlowCache: o.NoFlowCache},
		ctx: c, end: end, conns: map[string]Conn{}, stop: map[string]context.CancelFunc{},
		failed: map[string]time.Time{}, done: make(chan string, 64)}
}

// Counters returns the engine's totals.
func (s *Service) Counters() Counters { return s.eng.Counters() }

// Intercepted lists the vifs whose native mDNS the engine replaces.
func (s *Service) Intercepted() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.icept...)
}

// Update makes the service run plan p: sockets opened and closed, the
// engine's plan narrowed to the ports that are open, interception set for
// the vifs the engine fully serves. Call it again (each inform tick) to
// retry ports that failed.
func (s *Service) Update(ctx context.Context, p Plan) error {
	if s.o.DryRun {
		if sig := p.Sig(); sig != s.sig {
			s.sig = sig
			s.o.Logf("mdns bridge (dry run): %d ports, %d intercepted vifs, %d routes", len(p.Ports), len(p.Own), len(p.Routes))
		}
		return nil
	}
	now := s.o.Now()
	s.mu.Lock()
	s.drain()
	want := map[string]Port{}
	for _, x := range p.Ports {
		want[x.Key()] = x
	}
	for k := range s.conns {
		if _, ok := want[k]; !ok {
			s.closeLocked(k)
			s.o.Logf("mdns bridge: %s stopped", k)
		}
	}
	for k := range s.failed {
		if _, ok := want[k]; !ok {
			delete(s.failed, k)
		}
	}
	for _, k := range sortedKeys(want) {
		if s.conns[k] != nil {
			continue
		}
		if t, ok := s.failed[k]; ok && now.Sub(t) < s.o.Retry {
			continue
		}
		c, err := s.o.Open(want[k])
		if err != nil {
			if _, ok := s.failed[k]; !ok {
				s.o.Logf("mdns bridge: %s: %v (retrying every %s)", k, err, s.o.Retry)
			}
			s.failed[k] = now
			continue
		}
		delete(s.failed, k)
		s.conns[k] = c
		rctx, cancel := context.WithCancel(s.ctx)
		s.stop[k] = cancel
		s.wg.Add(1)
		go s.read(rctx, k, c)
	}
	// the engine works on the open ports only
	eff := Plan{Own: map[string]*Policy{}, APMode: p.APMode, OwnMAC: p.OwnMAC}
	open := map[string]bool{}
	vlanOpen := map[int]bool{}
	for _, x := range p.Ports {
		vlanOpen[x.VLAN] = true
	}
	for _, x := range p.Ports {
		if s.conns[x.Key()] != nil {
			open[x.Key()] = true
			eff.Ports = append(eff.Ports, x)
		} else {
			vlanOpen[x.VLAN] = false
		}
	}
	var icept []string
	for v, pol := range p.Own {
		x, ok := want[v]
		// a vif is intercepted only when every port of its VLAN is read:
		// otherwise it would miss the mDNS of the port that failed
		if ok && open[v] && x.Vif && x.VID == 0 && vlanOpen[x.VLAN] {
			eff.Own[v] = pol
			icept = append(icept, x.Name)
		}
	}
	for _, r := range p.Routes {
		if open[r.Vif] {
			eff.Routes = append(eff.Routes, r)
		}
	}
	sort.Strings(icept)
	s.mu.Unlock()

	// The engine serves a vif before its native mDNS is cut. A vif no longer
	// intercepted is unserved for the moment until its cut is undone: it
	// gets no mDNS in between (closed), never unfiltered mDNS.
	s.eng.SetPlan(eff)
	err := s.x.Set(ctx, icept)
	s.mu.Lock()
	if err != nil {
		// the cut is in an unknown state: report every vif that may be cut
		s.icept = union(s.icept, icept)
	} else {
		s.icept = icept
	}
	sig := eff.Sig()
	changed := sig != s.sig
	s.sig = sig
	s.mu.Unlock()
	if changed {
		s.o.Logf("mdns bridge: %d ports open, intercepting %v, %d routes, AP mode %t", len(eff.Ports), icept, len(eff.Routes), eff.APMode)
	}
	return err
}

func union(a, b []string) []string {
	m := map[string]bool{}
	for _, x := range append(append([]string(nil), a...), b...) {
		m[x] = true
	}
	return sortedSet(m)
}

// drain closes the sockets whose reader stopped on its own (a socket
// error: typically the vif was deleted by a Wi-Fi apply); Update opens them
// again at once. s.mu held.
func (s *Service) drain() {
	for {
		select {
		case k := <-s.done:
			if s.conns[k] != nil {
				s.closeLocked(k)
			}
		default:
			return
		}
	}
}

func (s *Service) closeLocked(k string) {
	if c := s.stop[k]; c != nil {
		c()
	}
	if c := s.conns[k]; c != nil {
		c.Close()
	}
	delete(s.stop, k)
	delete(s.conns, k)
}

func (s *Service) read(ctx context.Context, key string, c Conn) {
	defer s.wg.Done()
	b := make([]byte, snapLen)
	for ctx.Err() == nil {
		n, out, err := c.Recv(b)
		if errors.Is(err, ErrTimeout) {
			continue
		}
		if err != nil {
			if ctx.Err() == nil {
				s.o.Logf("mdns bridge: %s: %v", key, err)
				select {
				case s.done <- key:
				default:
				}
			}
			return
		}
		if out || n > len(b) {
			continue // our own (or another sender's) transmission; or cut short
		}
		for _, o := range s.eng.Handle(key, b[:n], s.o.Now()) {
			s.mu.Lock()
			dst := s.conns[o.Port]
			s.mu.Unlock()
			if dst == nil {
				continue
			}
			if err := dst.Send(o.Frame); err != nil {
				s.mu.Lock()
				s.sendErrs++
				first := s.sendErrs == 1
				s.mu.Unlock()
				if first {
					s.o.Logf("mdns bridge: send on %s: %v (further send errors are counted only)", o.Port, err)
				}
			}
		}
	}
}

// Close stops every reader and undoes the interception. It returns the
// ebtables error, if any (the chain then stays until Cleanup or a reboot).
func (s *Service) Close(ctx context.Context) error {
	var err error
	if !s.o.DryRun {
		// native mDNS back first, then stop serving
		err = s.x.Clear(ctx)
	}
	s.end()
	s.mu.Lock()
	for k := range s.conns {
		s.closeLocked(k)
	}
	s.icept = nil
	s.mu.Unlock()
	s.wg.Wait()
	s.eng.SetPlan(Plan{})
	return err
}

// Cleanup removes an interception a previous run left (the agent calls it
// at start in takeover mode, and when it drops to observe mode).
func Cleanup(ctx context.Context, run Runner) error {
	return (&Interceptor{Run: run}).Clear(ctx)
}
