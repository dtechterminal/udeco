// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package mtkwifi

import (
	"errors"
	"net"
)

// Off Linux there are no AF_PACKET sockets: the responder is never
// healthy, so nothing is proxied (proxyarp.go).

type noResponder struct{}

func newResponder(func(string, ...any), func()) parpResponder { return noResponder{} }

func (noResponder) SetVifs(map[string]parpVif)     {}
func (noResponder) Healthy(string) bool            { return false }
func (noResponder) Request(*ProxyARPRequest)       {}
func (noResponder) Stations(map[string][]string)   {}
func (noResponder) Neighbor(string) (net.IP, bool) { return nil, false }
func (noResponder) Known(string) []string          { return nil }
func sendFrame(string, []byte) error               { return errors.New("no AF_PACKET off Linux") }
