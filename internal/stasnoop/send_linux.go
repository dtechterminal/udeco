// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux

package stasnoop

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// SendFrame sends one complete Ethernet frame on ifname (an AF_PACKET
// socket opened for the send and closed after; nothing is received).
func SendFrame(ifname string, frame []byte) error {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	if len(frame) < 14 {
		return fmt.Errorf("stasnoop: send: runt frame")
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("stasnoop: send socket: %w", err)
	}
	defer unix.Close(fd)
	to := &unix.SockaddrLinklayer{Ifindex: ifi.Index, Halen: 6}
	copy(to.Addr[:], frame[0:6])
	if err := unix.Sendto(fd, frame, unix.MSG_DONTWAIT, to); err != nil {
		return fmt.Errorf("stasnoop: send on %s: %w", ifname, err)
	}
	return nil
}
