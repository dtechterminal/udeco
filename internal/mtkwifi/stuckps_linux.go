// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// The downlink watchdog's learner (stuckps.go): an AF_PACKET listener with
// learnFilter on each BSS netdev, feeding its own arpTable (the stations'
// addresses and when each was last heard). It never answers anything (the
// proxy ARP responder, proxyarp_linux.go, does that where it is on).
type learner struct {
	logf  func(string, ...any)
	tbl   arpTable
	mu    sync.Mutex
	socks map[string]*parpSock // by netdev
}

func newDownProber(logf func(string, ...any)) downProber {
	return &learner{logf: logf, socks: map[string]*parpSock{}}
}

func (l *learner) SetVifs(vifs []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	need := map[string]bool{}
	for _, v := range vifs {
		need[v] = true
	}
	for name, s := range l.socks {
		s.mu.Lock()
		dead := s.dead
		s.mu.Unlock()
		if !need[name] || dead {
			s.mu.Lock()
			s.closed = true
			s.mu.Unlock()
			s.f.Close()
			delete(l.socks, name)
		}
	}
	for name := range need {
		if l.socks[name] != nil {
			continue
		}
		f, err := openPacket(name)
		if err != nil {
			l.logf("downlink watchdog: %s: %v (retried at the next reading)", name, err)
			continue
		}
		s := &parpSock{f: f}
		l.socks[name] = s
		go l.read(s, name)
	}
}

func (l *learner) read(s *parpSock, name string) {
	buf := make([]byte, 2048)
	for {
		n, err := s.f.Read(buf)
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.dead = true
			s.mu.Unlock()
			if !closed && !errors.Is(err, os.ErrClosed) {
				l.logf("downlink watchdog: %s: %v (reopened at the next reading)", name, err)
			}
			return
		}
		l.tbl.learnFrame(name, buf[:n])
	}
}

func (l *learner) Stations(m map[string][]string)     { l.tbl.setStations(m) }
func (l *learner) Neighbor(mac string) (net.IP, bool) { return l.tbl.neighbor(mac) }
func (l *learner) Replied(mac string, self net.HardwareAddr, ip net.IP) time.Time {
	return l.tbl.lastReply(mac, self, ip)
}

func (l *learner) Self(bridge string) (net.HardwareAddr, net.IP, bool) {
	ifi, err := net.InterfaceByName(bridge)
	if err != nil || len(ifi.HardwareAddr) != 6 {
		return nil, nil, false
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil, false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if v4 := n.IP.To4(); v4 != nil && !v4.IsLoopback() {
				return ifi.HardwareAddr, v4, true
			}
		}
	}
	return nil, nil, false
}
