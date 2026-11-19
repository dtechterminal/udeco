// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package mtkwifi

import "errors"

func openPriv() (privIO, error) { return nil, errors.New("mtkwifi: no driver ioctls on this OS") }
