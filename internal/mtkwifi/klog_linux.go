// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import "syscall"

// readKlog is `dmesg` without clearing: klogctl(SYSLOG_ACTION_READ_ALL).
func readKlog() ([]byte, error) {
	n, err := syscall.Klogctl(10, nil) // SYSLOG_ACTION_SIZE_BUFFER
	if err != nil || n <= 0 {
		n = 1 << 17
	}
	buf := make([]byte, n)
	m, err := syscall.Klogctl(3, buf) // SYSLOG_ACTION_READ_ALL
	if err != nil {
		return nil, err
	}
	return buf[:m], nil
}
