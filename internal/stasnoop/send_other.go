// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package stasnoop

import "errors"

// SendFrame needs Linux AF_PACKET sockets.
func SendFrame(ifname string, frame []byte) error {
	return errors.New("stasnoop: raw sockets need Linux")
}
