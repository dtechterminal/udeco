// SPDX-License-Identifier: GPL-2.0-or-later

package stasnoop

import (
	"encoding/binary"
	"errors"
	"net"
)

// The ARP frames the agents send. ARPFrame is the one writer of the frame
// and GARPFrame the one shape of a gratuitous ARP: GARP (the Deco agent,
// cmd/udeco-ap garp.go) and internal/mtkwifi (its proxy ARP replies and
// AnnounceStation) are built on them.

var broadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// ARPFrame is an untagged Ethernet IPv4 ARP frame from sha to dst, padded
// to the Ethernet minimum of 60 bytes: op 1 is a request, 2 a reply; sha
// and spa are the sender's addresses, tha and tpa the target's. Nothing is
// checked: an address that is not IPv4 is left zero.
func ARPFrame(dst, sha net.HardwareAddr, op uint16, spa net.IP, tha net.HardwareAddr, tpa net.IP) []byte {
	b := make([]byte, 60) // the Ethernet minimum, padded
	copy(b[0:], dst)
	copy(b[6:], sha)
	binary.BigEndian.PutUint16(b[12:], 0x0806)
	binary.BigEndian.PutUint16(b[14:], 1)
	binary.BigEndian.PutUint16(b[16:], 0x0800)
	b[18], b[19] = 6, 4
	binary.BigEndian.PutUint16(b[20:], op)
	copy(b[22:], sha)
	copy(b[28:], spa.To4())
	copy(b[32:], tha)
	copy(b[38:], tpa.To4())
	return b
}

// GARPFrame is a gratuitous ARP announcing that ip is at mac: a broadcast
// ARP request from mac with ip as both sender and target address and a
// zero target hardware address. The caller has checked mac and ip (GARP
// does; internal/mtkwifi's AnnounceStation has its own, looser check).
func GARPFrame(mac net.HardwareAddr, ip net.IP) []byte {
	return ARPFrame(broadcast, mac, 1, ip, make(net.HardwareAddr, 6), ip)
}

// GARP is GARPFrame for a unicast MAC and an IPv4 address given as text.
// The agent sends it on a station's behalf on the wired ports of the
// station's bridge (cmd/udeco-ap garp.go; SendFrame).
func GARP(mac, ip string) ([]byte, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 || hw[0]&1 != 0 {
		return nil, errors.New("stasnoop: GARP: not a unicast MAC")
	}
	a := net.ParseIP(ip).To4()
	if a == nil || a.IsUnspecified() {
		return nil, errors.New("stasnoop: GARP: not an IPv4 address")
	}
	return GARPFrame(hw, a), nil
}
