// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux

package mtkwifi

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// roamSys is the runtime's real IO: the private ioctls on a datagram
// socket (priv_linux.go's) and AF_PACKET taps.
type roamSys struct{ p sockPriv }

func openRoamIO() (roamIO, error) {
	p, err := openPriv()
	if err != nil {
		return nil, err
	}
	return roamSys{p: p.(sockPriv)}, nil
}

func (s roamSys) OID(ifname string, flags uint16, buf []byte) (int, error) {
	r, err := newIwreq(ifname, buf, flags)
	if err != nil {
		return 0, err
	}
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s.p.fd), ioctlOID, uintptr(unsafe.Pointer(r)))
	runtime.KeepAlive(buf)
	n := int(r.point().length)
	runtime.KeepAlive(r)
	if e != 0 {
		return 0, e
	}
	return n, nil
}

func (s roamSys) Set(ifname, arg string) error { return s.p.Set(ifname, cstr(arg)) }

func (s roamSys) Open(dev string, etherType uint16) (frameConn, error) {
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	fail := func(what string, err error) (frameConn, error) {
		unix.Close(fd)
		return nil, fmt.Errorf("%s %s: %w", what, dev, err)
	}
	// ldh [12]; jeq #type, accept; drop
	prog := []unix.SockFilter{{Code: 0x28, K: 12}, {Code: 0x15, Jt: 0, Jf: 1, K: uint32(etherType)},
		{Code: 0x06, K: 0xffff}, {Code: 0x06, K: 0}}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
		return fail("filter", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
		return fail("bind", err)
	}
	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fail("timeout", err)
	}
	return &packetConn{fd: fd, ifindex: ifi.Index, typ: etherType}, nil
}

type packetConn struct {
	mu      sync.Mutex
	fd      int
	ifindex int
	typ     uint16
}

func (c *packetConn) Recv(b []byte) (int, error) {
	c.mu.Lock()
	fd := c.fd
	c.mu.Unlock()
	if fd < 0 {
		return 0, net.ErrClosed
	}
	n, from, err := unix.Recvfrom(fd, b, 0)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		return 0, errRoamTimeout
	}
	if err != nil {
		return 0, err
	}
	if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
		return 0, errRoamTimeout // our own frame
	}
	return n, nil
}

func (c *packetConn) Send(frame []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return net.ErrClosed
	}
	if len(frame) < 14 {
		return errors.New("short frame")
	}
	sa := &unix.SockaddrLinklayer{Protocol: htons(c.typ), Ifindex: c.ifindex, Halen: 6}
	copy(sa.Addr[:], frame[:6])
	return unix.Sendto(c.fd, frame, 0, sa)
}

func (c *packetConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return nil
	}
	err := unix.Close(c.fd)
	c.fd = -1
	return err
}
