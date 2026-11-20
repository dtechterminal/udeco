// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package mtkwifi

import (
	"net"
	"time"
)

// Off Linux there are no AF_PACKET sockets: the watchdog learns nothing
// and so never probes or kicks.
type noProber struct{}

func newDownProber(func(string, ...any)) downProber { return noProber{} }

func (noProber) SetVifs([]string)                                   {}
func (noProber) Stations(map[string][]string)                       {}
func (noProber) Neighbor(string) (net.IP, bool)                     { return nil, false }
func (noProber) Replied(string, net.HardwareAddr, net.IP) time.Time { return time.Time{} }
func (noProber) Self(string) (net.HardwareAddr, net.IP, bool)       { return nil, nil, false }
