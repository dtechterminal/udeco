// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package mdnsbr

import "errors"

// Open needs Linux AF_PACKET sockets.
func Open(p Port) (Conn, error) {
	return nil, errors.New("mdnsbr: raw sockets need Linux")
}
