// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux

package ftpeer

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

type rawConn struct {
	mu      sync.Mutex
	fd      int
	ifindex int
}

// OpenRaw opens an AF_PACKET socket on the bridge that receives the
// announcements (BPF on EtherType 0x88b5, bound with ETH_P_ALL), joins
// GroupMAC and polls with a 1 s timeout.
func OpenRaw(bridge string) (Conn, error) {
	ifi, err := net.InterfaceByName(bridge)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("ftpeer: socket: %w", err)
	}
	fail := func(what string, err error) (Conn, error) {
		unix.Close(fd)
		return nil, fmt.Errorf("ftpeer: %s %s: %w", what, bridge, err)
	}
	prog := make([]unix.SockFilter, len(announceFilter))
	for i, in := range announceFilter {
		prog[i] = unix.SockFilter{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: (*unix.SockFilter)(unsafe.Pointer(&prog[0]))}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
		return fail("filter", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: ethPAll, Ifindex: ifi.Index}); err != nil {
		return fail("bind", err)
	}
	mr := unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_MULTICAST, Alen: 6}
	copy(mr.Address[:], GroupMAC)
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mr); err != nil {
		return fail("join", err)
	}
	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fail("timeout", err)
	}
	return &rawConn{fd: fd, ifindex: ifi.Index}, nil
}

func (c *rawConn) Recv(b []byte) (int, error) {
	c.mu.Lock()
	fd := c.fd
	c.mu.Unlock()
	if fd < 0 {
		return 0, net.ErrClosed
	}
	n, from, err := unix.Recvfrom(fd, b, 0)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
		return 0, ErrTimeout
	}
	if err != nil {
		return n, err
	}
	if ll, ok := from.(*unix.SockaddrLinklayer); ok && !keepPkttype(ll.Pkttype) {
		return 0, ErrTimeout // our own frame
	}
	return n, nil
}

func (c *rawConn) Send(frame []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return net.ErrClosed
	}
	sa := &unix.SockaddrLinklayer{Protocol: ethPAnnounce, Ifindex: c.ifindex, Halen: 6}
	copy(sa.Addr[:], GroupMAC)
	return unix.Sendto(c.fd, frame, 0, sa)
}

func (c *rawConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return nil
	}
	err := unix.Close(c.fd)
	c.fd = -1
	return err
}
