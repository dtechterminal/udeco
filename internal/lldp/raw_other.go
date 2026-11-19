// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package lldp

import "errors"

// OpenRaw needs Linux AF_PACKET sockets.
func OpenRaw(ifname string) (Conn, error) {
	return nil, errors.New("lldp: raw sockets need Linux")
}
