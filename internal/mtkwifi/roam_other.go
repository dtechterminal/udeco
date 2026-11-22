// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package mtkwifi

import "errors"

func openRoamIO() (roamIO, error) { return nil, errors.New("mtkwifi: no roaming sockets on this OS") }
