// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package mtkwifi

import "errors"

var errNoEvents = errors.New("mtkwifi: driver events need Linux")

func openRTNLSocket() (packetSource, error) { return nil, errNoEvents }
func openECNTSocket() (packetSource, error) { return nil, errNoEvents }
func openKmsgFile() (packetSource, error)   { return nil, errNoEvents }
