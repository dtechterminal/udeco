// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"syscall"
	"time"
)

// setSystemClock steps the system clock to t (settimeofday; needs root).
func setSystemClock(t time.Time) error {
	tv := syscall.NsecToTimeval(t.UnixNano())
	return syscall.Settimeofday(&tv)
}
