// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"io"
	"os"
	"syscall"
)

// The driver events' sources (drvevents.go): receive-only netlink
// multicast listeners and the kernel log's own reader. Each is a
// non-blocking descriptor in an *os.File, so Close (the monitor's context
// ending) wakes a pending Read.

const netlinkECNT = 17 // the Econet SDK's event socket (event_notify_init)

func openNetlink(proto int) (packetSource, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, proto)
	if err != nil {
		return nil, err
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 256<<10)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "netlink"), nil
}

// openRTNLSocket listens to RTMGRP_LINK (the drivers' wireless events).
func openRTNLSocket() (packetSource, error) { return openNetlink(syscall.NETLINK_ROUTE) }

// openECNTSocket listens to the ECNT driver events (group 1).
func openECNTSocket() (packetSource, error) { return openNetlink(netlinkECNT) }

// kmsgFile reads /dev/kmsg from its end: one record per Read; a record
// overwritten before it was read (EPIPE) is skipped.
type kmsgFile struct{ f *os.File }

// kmsgPrivate is the agent's own /dev/kmsg node, made where the firmware
// has none: the JioFiber JCOW414 (kernel 3.18) has no /dev/kmsg node, only
// /proc/kmsg, which syslogd holds. The kernel's kmsg device (char 1:11)
// is there; a node made for it reads the log in the same format
// (verified on the Garage unit 2026-11-20).
const kmsgPrivate = "/tmp/udeco-kmsg"

func openKmsgFile() (packetSource, error) {
	path := "/dev/kmsg"
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err == syscall.ENOENT {
		path = kmsgPrivate
		_ = os.Remove(path)
		if err = syscall.Mknod(path, syscall.S_IFCHR|0o400, 1<<8|11); err == nil {
			fd, err = syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		}
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}
	return kmsgFile{f}, nil
}

func (k kmsgFile) Read(b []byte) (int, error) {
	for {
		n, err := k.f.Read(b)
		if pe, ok := err.(*os.PathError); ok && pe.Err == syscall.EPIPE {
			continue
		}
		return n, err
	}
}

func (k kmsgFile) Close() error { return k.f.Close() }
