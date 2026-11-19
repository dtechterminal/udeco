// SPDX-License-Identifier: GPL-2.0-or-later

package lldp

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"time"
)

// Conn is one port's LLDP socket.
type Conn interface {
	// Recv reads one frame into b. It returns ErrTimeout when nothing came
	// within the socket's poll interval (about a second), so the reader can
	// see its context end.
	Recv(b []byte) (int, error)
	// Send transmits one complete Ethernet frame.
	Send(frame []byte) error
	Close() error
}

// ErrTimeout is Conn.Recv's "nothing yet".
var ErrTimeout = errors.New("lldp: receive timeout")

// Opener opens the LLDP socket of an interface.
type Opener func(ifname string) (Conn, error)

// Options configure a Service.
type Options struct {
	// Ports are the Ethernet ports to listen on (eth0, eth1). Frames are
	// heard on a port whether or not it is in a bridge.
	Ports []string
	// Open opens a port's socket; nil = OpenRaw (AF_PACKET, Linux only).
	Open Opener
	// Self returns what to announce and on which port; ok=false sends
	// nothing this time (no uplink known yet). It is called from the
	// sender goroutine.
	Self func() (port string, src net.HardwareAddr, info Info, ok bool)
	// Every is the transmit interval (30 s, as a UAP and the UCG).
	Every time.Duration
	// Logf gets open errors (once per port and error) and nothing per frame.
	Logf func(string, ...any)
	// Now is the clock (tests); nil = time.Now.
	Now func() time.Time
}

// Service listens on Ports, keeps the neighbour table and announces Self.
type Service struct {
	o Options

	mu    sync.Mutex
	table map[key]entry
	sent  int
}

type key struct{ port, chassis, portID string }

type entry struct {
	n       Neighbor
	expires time.Time
}

// New returns a Service; Run starts it.
func New(o Options) *Service {
	if o.Open == nil {
		o.Open = OpenRaw
	}
	if o.Every <= 0 {
		o.Every = 30 * time.Second
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{o: o, table: map[key]entry{}}
}

// Run listens and announces until ctx ends. A port whose socket cannot be
// opened is retried every Every.
func (s *Service) Run(ctx context.Context) {
	var wg sync.WaitGroup
	conns := map[string]Conn{}
	var cmu sync.Mutex
	for _, p := range s.o.Ports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.listen(ctx, p, func(c Conn) {
				cmu.Lock()
				conns[p] = c
				cmu.Unlock()
			})
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(s.o.Every)
		defer t.Stop()
		last := ""
		for {
			cmu.Lock()
			last = s.announce(conns, last)
			cmu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	wg.Wait()
}

// announce sends Self on its port; it returns the port used.
func (s *Service) announce(conns map[string]Conn, last string) string {
	if s.o.Self == nil {
		return last
	}
	port, src, info, ok := s.o.Self()
	if !ok {
		return last
	}
	c := conns[port]
	if c == nil {
		return last
	}
	f, err := Encode(src, info)
	if err == nil {
		err = c.Send(f)
	}
	if err != nil {
		s.o.Logf("lldp: send on %s: %v", port, err)
		return last
	}
	if port != last {
		s.o.Logf("lldp: announcing on %s every %s", port, s.o.Every)
	}
	s.mu.Lock()
	s.sent++
	s.mu.Unlock()
	return port
}

// listen reads frames from port into the table until ctx ends.
func (s *Service) listen(ctx context.Context, port string, opened func(Conn)) {
	lastErr := ""
	for ctx.Err() == nil {
		c, err := s.o.Open(port)
		if err != nil {
			if err.Error() != lastErr {
				s.o.Logf("lldp: %s: %v (retrying every %s)", port, err, s.o.Every)
				lastErr = err.Error()
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.o.Every):
			}
			continue
		}
		opened(c)
		buf := make([]byte, 1600)
		for ctx.Err() == nil {
			n, err := c.Recv(buf)
			if errors.Is(err, ErrTimeout) {
				continue
			}
			if err != nil {
				if ctx.Err() == nil {
					s.o.Logf("lldp: %s: receive: %v", port, err)
				}
				break
			}
			if nb, err := Decode(buf[:n]); err == nil {
				s.heard(port, nb)
			}
		}
		c.Close()
		if ctx.Err() == nil {
			select {
			case <-ctx.Done():
			case <-time.After(s.o.Every):
			}
		}
	}
}

// Heard records a decoded LLDPDU received on port (Run calls it; tests and
// callers with their own receive path may too).
func (s *Service) Heard(port string, n Neighbor) { s.heard(port, n) }

// maxPerPort bounds the neighbours kept per port. A real port hears one or
// two; anything wired to the unit's free port can send LLDPDUs with a new
// chassis ID each (TTL up to 18 h), and an unbounded table would grow until
// the agent hits its memory floor. When a port is full, expired entries are
// dropped first; a new neighbour beyond the bound is ignored (the ones
// already known, such as the gateway on the uplink, are kept and refreshed).
const maxPerPort = 16

func (s *Service) heard(port string, n Neighbor) {
	k := key{port, n.ChassisID, n.PortID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n.TTL == 0 {
		delete(s.table, k)
		return
	}
	now := s.o.Now()
	if _, known := s.table[k]; !known && s.onPort(port, now) >= maxPerPort {
		return
	}
	s.table[k] = entry{n: n, expires: now.Add(time.Duration(n.TTL) * time.Second)}
}

// onPort counts port's live entries, dropping its expired ones; callers
// hold s.mu.
func (s *Service) onPort(port string, now time.Time) int {
	c := 0
	for k, e := range s.table {
		if k.port != port {
			continue
		}
		if !now.Before(e.expires) {
			delete(s.table, k)
			continue
		}
		c++
	}
	return c
}

// Neighbors lists the live neighbours heard on port ("" = every port),
// sorted by chassis ID.
func (s *Service) Neighbors(port string) []Neighbor {
	now := s.o.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Neighbor
	for k, e := range s.table {
		if !now.Before(e.expires) {
			delete(s.table, k)
			continue
		}
		if port == "" || k.port == port {
			out = append(out, e.n)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ChassisID != out[j].ChassisID {
			return out[i].ChassisID < out[j].ChassisID
		}
		return out[i].PortID < out[j].PortID
	})
	return out
}

// PortsHearing lists the ports on which a live neighbour matches: its
// chassis ID, frame source or any management address equals one of ids
// (case-insensitive for MACs). Sorted.
func (s *Service) PortsHearing(ids ...string) []string {
	want := map[string]bool{}
	for _, id := range ids {
		if id != "" {
			want[normID(id)] = true
		}
	}
	now := s.o.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	ports := map[string]bool{}
	for k, e := range s.table {
		if !now.Before(e.expires) {
			continue
		}
		hit := want[normID(e.n.ChassisID)] || want[normID(e.n.SrcMAC)]
		for _, ip := range e.n.MgmtIPs {
			hit = hit || want[ip]
		}
		if hit {
			ports[k.port] = true
		}
	}
	out := make([]string, 0, len(ports))
	for p := range ports {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Sent is the number of LLDPDUs sent.
func (s *Service) Sent() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

func normID(s string) string {
	if m, err := net.ParseMAC(s); err == nil {
		return m.String()
	}
	return s
}
