// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package ftpeer

import "errors"

// OpenRaw needs Linux AF_PACKET sockets.
func OpenRaw(bridge string) (Conn, error) {
	return nil, errors.New("ftpeer: raw sockets need Linux")
}
