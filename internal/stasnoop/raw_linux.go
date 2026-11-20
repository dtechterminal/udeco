// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux

package stasnoop

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// htons(ETH_P_ALL): ETH_P_ALL taps run before the bridge's rx_handler, so
// a VAP enslaved to a bridge still shows its clients' frames, and they
// also see the frames the VAP transmits (PACKET_OUTGOING).
const ethPAll = 0x0003>>8 | (0x0003&0xff)<<8

const packetOutgoing = 4 // PACKET_OUTGOING

type rawSource struct {
	mu sync.Mutex
	fd int
}

// Open opens an AF_PACKET socket on the VAP ifname with the filter (ARP,
// DHCP, DNS) and a 1 s receive timeout. The socket is created with
// protocol 0 (it receives nothing), gets the filter and only then is
// bound, so no unfiltered frame is queued. It does not change the
// interface (no promiscuous mode) and never sends.
func Open(ifname string) (Source, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("stasnoop: socket: %w", err)
	}
	fail := func(what string, err error) (Source, error) {
		unix.Close(fd)
		return nil, fmt.Errorf("stasnoop: %s %s: %w", what, ifname, err)
	}
	prog := make([]unix.SockFilter, len(filter))
	for i, in := range filter {
		prog[i] = unix.SockFilter{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
		return fail("filter", err)
	}
	// a small receive buffer: a burst beyond it is dropped by the kernel
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 64<<10)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: ethPAll, Ifindex: ifi.Index}); err != nil {
		return fail("bind", err)
	}
	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fail("timeout", err)
	}
	return &rawSource{fd: fd}, nil
}

func (s *rawSource) Recv(b []byte) (int, bool, error) {
	s.mu.Lock()
	fd := s.fd
	s.mu.Unlock()
	if fd < 0 {
		return 0, false, net.ErrClosed
	}
	n, from, err := unix.Recvfrom(fd, b, unix.MSG_TRUNC)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
		return 0, false, ErrTimeout
	}
	if err != nil {
		return 0, false, err
	}
	out := false
	if ll, ok := from.(*unix.SockaddrLinklayer); ok {
		out = ll.Pkttype == packetOutgoing
	}
	return n, out, nil
}

func (s *rawSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return nil
	}
	err := unix.Close(s.fd)
	s.fd = -1
	return err
}
