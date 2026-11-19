// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package mcinspect

import "errors"

// Open needs Linux AF_PACKET sockets.
func Open(ifname string) (Source, error) {
	return nil, errors.New("mcinspect: raw sockets need Linux")
}
