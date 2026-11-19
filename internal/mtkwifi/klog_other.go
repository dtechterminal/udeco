// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package mtkwifi

import "errors"

func readKlog() ([]byte, error) { return nil, errors.New("mtkwifi: no kernel log on this OS") }
