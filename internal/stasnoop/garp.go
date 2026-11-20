// SPDX-License-Identifier: GPL-2.0-or-later

package stasnoop

import (
	"errors"
	"net"
)

// GARP is a gratuitous ARP announcing that ip is at mac: a broadcast ARP
// request from mac with ip as both sender and target address, padded to
// the Ethernet minimum. The agent sends it on a station's behalf on the
// wired ports of the station's bridge (cmd/udeco-ap garp.go; SendFrame).
func GARP(mac, ip string) ([]byte, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 || hw[0]&1 != 0 {
		return nil, errors.New("stasnoop: GARP: not a unicast MAC")
	}
	a := net.ParseIP(ip).To4()
	if a == nil || a.IsUnspecified() {
		return nil, errors.New("stasnoop: GARP: not an IPv4 address")
	}
	f := make([]byte, 60)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], hw)
	f[12], f[13] = 0x08, 0x06
	copy(f[14:22], []byte{0, 1, 8, 0, 6, 4, 0, 1})
	copy(f[22:28], hw)
	copy(f[28:32], a)
	// target hardware address zero
	copy(f[38:42], a)
	return f, nil
}
