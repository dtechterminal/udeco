// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"runtime"
	"syscall"
	"unsafe"
)

// sockPriv sends the private ioctls on a datagram socket.
type sockPriv struct{ fd int }

// openPriv opens the socket the private ioctls go through.
func openPriv() (privIO, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return sockPriv{fd: fd}, nil
}

func (p sockPriv) ioctl(ifname string, req uintptr, buf []byte, flags uint16) error {
	r, err := newIwreq(ifname, buf, flags)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(p.fd), req, uintptr(unsafe.Pointer(r)))
	runtime.KeepAlive(buf) // the driver read and wrote it through r's pointer
	runtime.KeepAlive(r)
	if e != 0 {
		return e
	}
	return nil
}

func (p sockPriv) Show(ifname, what string) error { return p.ioctl(ifname, ioctlShow, cstr(what), 0) }

func (p sockPriv) Set(ifname, arg string) error { return p.ioctl(ifname, ioctlSet, cstr(arg), 0) }

func (p sockPriv) OID(ifname string, flags uint16, buf []byte) error {
	return p.ioctl(ifname, ioctlOID, buf, flags)
}

func (p sockPriv) Close() error { return syscall.Close(p.fd) }
