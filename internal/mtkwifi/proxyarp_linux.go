// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
)

// The proxy ARP responder's sockets (proxyarp.go): an AF_PACKET listener
// with learnFilter on each learning BSS netdev (the stations' own ARP and
// their DHCP ACKs, both directions) and on each of their bridges (the
// broadcast requests the bridge delivers), and one sending socket. Each
// listener is non-blocking in an *os.File, so closing it wakes its reader.

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func packetFilter() []syscall.SockFilter {
	out := make([]syscall.SockFilter, len(learnFilter))
	for i, in := range learnFilter {
		out[i] = syscall.SockFilter{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	return out
}

func openPacket(ifname string) (*os.File, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	// the filter before the bind: nothing else is ever queued
	if err := syscall.AttachLsf(fd, packetFilter()); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "packet:"+ifname), nil
}

// sendOn sends frame on ifname through fd (an AF_PACKET socket).
func sendOn(fd int, ifname string, frame []byte) error {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	var addr [8]byte
	copy(addr[:], frame[0:6])
	return syscall.Sendto(fd, frame, 0, &syscall.SockaddrLinklayer{Ifindex: ifi.Index, Halen: 6, Addr: addr})
}

// sendFrame sends one frame on dev (Options.sendFrame).
func sendFrame(dev string, frame []byte) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return sendOn(fd, dev, frame)
}

type parpSock struct {
	f      *os.File
	mu     sync.Mutex
	dead   bool
	closed bool
}

type responder struct {
	logf   func(string, ...any)
	onDown func()
	tbl    arpTable
	mu     sync.Mutex
	vifs   map[string]parpVif
	socks  map[string]*parpSock // "vif:<name>", "br:<name>"
	send   int                  // -1: closed
}

func newResponder(logf func(string, ...any), onDown func()) parpResponder {
	return &responder{logf: logf, onDown: onDown, socks: map[string]*parpSock{}, send: -1}
}

func (r *responder) SetVifs(v map[string]parpVif) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vifs = v
	need := map[string]bool{}
	for name, x := range v {
		if x.Learn {
			need["vif:"+name], need["br:"+x.Bridge] = true, true
		}
	}
	for k, s := range r.socks {
		s.mu.Lock()
		dead := s.dead
		s.mu.Unlock()
		if !need[k] || dead {
			s.mu.Lock()
			s.closed = true
			s.mu.Unlock()
			s.f.Close()
			delete(r.socks, k)
		}
	}
	for k := range need {
		if r.socks[k] != nil {
			continue
		}
		kind, name, _ := strings.Cut(k, ":")
		f, err := openPacket(name)
		if err != nil {
			r.logf("proxy ARP: %s: %v (retried at the next tick)", name, err)
			continue
		}
		s := &parpSock{f: f}
		r.socks[k] = s
		go r.read(s, kind, name)
	}
	if len(v) > 0 && r.send < 0 {
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			r.logf("proxy ARP: sending socket: %v", err)
		} else {
			r.send = fd
		}
	} else if len(v) == 0 && r.send >= 0 {
		syscall.Close(r.send)
		r.send = -1
	}
}

func (r *responder) read(s *parpSock, kind, name string) {
	buf := make([]byte, 2048)
	for {
		n, err := s.f.Read(buf)
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.dead = true
			s.mu.Unlock()
			if !closed && !errors.Is(err, os.ErrClosed) {
				r.logf("proxy ARP: %s: %v: answering stops", name, err)
				if r.onDown != nil {
					r.onDown()
				}
			}
			return
		}
		f := buf[:n]
		if kind == "vif" {
			r.tbl.learnFrame(name, f)
			continue
		}
		reply := r.tbl.answerFor(f, func(vif string) bool {
			r.mu.Lock()
			defer r.mu.Unlock()
			x, ok := r.vifs[vif]
			return ok && x.Learn && x.Bridge == name
		})
		if reply != nil {
			r.mu.Lock()
			fd := r.send
			r.mu.Unlock()
			if fd >= 0 {
				if err := sendOn(fd, name, reply); err != nil {
					r.logf("proxy ARP: %s: reply: %v", name, err)
				}
			}
		}
	}
}

func (r *responder) Healthy(vif string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	x, ok := r.vifs[vif]
	if !ok || r.send < 0 {
		return false
	}
	if !x.Learn {
		return true
	}
	for _, k := range []string{"vif:" + vif, "br:" + x.Bridge} {
		s := r.socks[k]
		if s == nil {
			return false
		}
		s.mu.Lock()
		dead := s.dead
		s.mu.Unlock()
		if dead {
			return false
		}
	}
	return true
}

// Request answers an MT7663 0x93b event on its BSS's bridge.
func (r *responder) Request(q *ProxyARPRequest) {
	if q == nil || q.IPv6 || q.StaIP.To4() == nil || len(q.ReqMAC) != 6 || len(q.StaMAC) != 6 {
		return
	}
	ifi, err := net.InterfaceByIndex(q.Ifindex)
	if err != nil {
		return
	}
	r.mu.Lock()
	x, ok := r.vifs[ifi.Name]
	fd := r.send
	r.mu.Unlock()
	if !ok || x.Learn || fd < 0 {
		return
	}
	if err := sendOn(fd, x.Bridge, arpReply(q.StaMAC, q.StaIP.To4(), q.ReqMAC, q.ReqIP.To4())); err != nil {
		r.logf("proxy ARP: %s: reply: %v", x.Bridge, err)
	}
}

func (r *responder) Stations(m map[string][]string)     { r.tbl.setStations(m) }
func (r *responder) Neighbor(mac string) (net.IP, bool) { return r.tbl.neighbor(mac) }
func (r *responder) Known(vif string) []string          { return r.tbl.known(vif) }
