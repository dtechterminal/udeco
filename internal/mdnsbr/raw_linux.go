// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux

package mdnsbr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// htons(ETH_P_ALL): taps run before the bridge's rx_handler, so a port
// enslaved to a bridge still shows what arrives on it.
const ethPAll = 0x0003>>8 | (0x0003&0xff)<<8

const packetOutgoing = 4 // PACKET_OUTGOING

type rawConn struct {
	mu      sync.Mutex
	fd      int
	ifindex int
	vid     int
}

// Open opens an AF_PACKET socket on the port that receives its mDNS frames
// (the port's BPF filter) with a 1 s receive timeout, and sends on it. The
// socket is created with protocol 0 (it receives nothing), gets the filter
// and only then is bound, so no unfiltered frame is ever queued. It changes
// nothing on the interface (no promiscuous mode, no membership: bridge ports
// are promiscuous already).
func Open(p Port) (Conn, error) {
	ifi, err := net.InterfaceByName(p.Name)
	if err != nil {
		return nil, err
	}
	prog, err := assemble(filterProgram(p.VID))
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("mdnsbr: socket: %w", err)
	}
	fail := func(what string, err error) (Conn, error) {
		unix.Close(fd)
		return nil, fmt.Errorf("mdnsbr: %s %s: %w", what, p.Key(), err)
	}
	f := make([]unix.SockFilter, len(prog))
	for i, x := range prog {
		f[i] = unix.SockFilter{Code: uint16(x[0]), Jt: uint8(x[1]), Jf: uint8(x[2]), K: x[3]}
	}
	fprog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}
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
	return &rawConn{fd: fd, ifindex: ifi.Index, vid: p.VID}, nil
}

func (c *rawConn) Recv(b []byte) (int, bool, error) {
	c.mu.Lock()
	fd := c.fd
	c.mu.Unlock()
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

func (c *rawConn) Send(frame []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return net.ErrClosed
	}
	if len(frame) < 14 {
		return errors.New("mdnsbr: short frame")
	}
	if c.vid > 0 {
		frame = tag(frame, c.vid)
	}
	et := binary.BigEndian.Uint16(frame[12:]) // the frame's ethertype, as skb->protocol
	sa := &unix.SockaddrLinklayer{Protocol: et>>8 | et<<8, Ifindex: c.ifindex, Halen: 6}
	copy(sa.Addr[:], frame[:6])
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
