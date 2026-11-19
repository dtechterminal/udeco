// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux

package mcinspect

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// htons(ETH_P_ALL): the receive bind. ETH_P_ALL taps run before the
// bridge's rx_handler, so a VAP enslaved to br-lan still shows its clients'
// frames, and they also see the frames the VAP transmits (PACKET_OUTGOING).
const ethPAll = 0x0003>>8 | (0x0003&0xff)<<8

const packetOutgoing = 4 // PACKET_OUTGOING

// groupFilter is classic BPF that keeps group-addressed frames only (the
// I/G bit of the destination MAC): unicast traffic never reaches the agent.
var groupFilter = []unix.SockFilter{
	{Code: 0x30, K: 0},               // ldb [0]
	{Code: 0x45, Jt: 0, Jf: 1, K: 1}, // jset #1
	{Code: 0x06, K: 0x40000},         // ret: whole frame
	{Code: 0x06, K: 0},               // ret: drop
}

type rawSource struct {
	mu sync.Mutex
	fd int
}

// Open opens an AF_PACKET socket on the VAP ifname that receives its
// group-addressed frames in both directions, with a 1 s receive timeout.
// The socket is created with protocol 0 (it receives nothing), gets the
// filter and only then is bound, so no unfiltered frame is queued. It does
// not change the interface (no promiscuous mode, no membership).
func Open(ifname string) (Source, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("mcinspect: socket: %w", err)
	}
	fail := func(what string, err error) (Source, error) {
		unix.Close(fd)
		return nil, fmt.Errorf("mcinspect: %s %s: %w", what, ifname, err)
	}
	fprog := unix.SockFprog{Len: uint16(len(groupFilter)), Filter: &groupFilter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
		return fail("filter", err)
	}
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
	// MSG_TRUNC: n is the frame's real length even when b is shorter
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
