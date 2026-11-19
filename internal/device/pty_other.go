// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux && !darwin

package device

import (
	"errors"
	"os"
)

func openPTY() (master, slave *os.File, err error) {
	return nil, nil, errors.New("pty: not supported on this platform")
}

func setWinsize(*os.File, uint32, uint32) error {
	return errors.New("pty: not supported on this platform")
}
