// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package main

import (
	"errors"
	"time"
)

// setSystemClock is Linux only (the agent runs on Linux units).
func setSystemClock(time.Time) error {
	return errors.New("setting the clock is not supported on this OS")
}
