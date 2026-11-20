// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

import (
	"errors"
	"strconv"
	"strings"
)

// The readers of /proc text that more than one collector needs. Each is
// the one copy: internal/wl (and through it internal/mtkwifi),
// internal/openwrt and cmd/udeco-ap call them.
//
// Not here, each for a reason: /proc/net/arp has two readers that take
// different rows (wl's parseARP skips an incomplete entry, flags 0x0;
// openwrt's Parse does not), and internal/snmpagent has its own readers
// of /proc/meminfo and /proc/loadavg for the host MIB (kB, where
// internal/wl reads bytes) and does not link the collectors.

// ParseCPULine sums a "cpu" line of /proc/stat ("cpu user nice system
// idle iowait irq ..."): the total jiffies, and idle plus iowait. s is
// split at any white space, so the caller hands it the one line; anything
// but "cpu" and at least four numbers gives 0, 0, and a field that is not
// a number counts 0.
func ParseCPULine(s string) (total, idle int64) {
	f := strings.Fields(s)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0
	}
	for i, v := range f[1:] {
		n, _ := strconv.ParseInt(v, 10, 64)
		total += n
		if i == 3 || i == 4 { // idle, iowait
			idle += n
		}
	}
	return total, idle
}

// ErrNoUptime is ParseUptime's error for a text with no field in it.
var ErrNoUptime = errors.New("empty /proc/uptime")

// ParseUptime is the first field of /proc/uptime: the seconds since boot.
// A text with nothing in it gives ErrNoUptime; a first field that is no
// number gives strconv.ParseFloat's value and error.
func ParseUptime(s string) (float64, error) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0, ErrNoUptime
	}
	return strconv.ParseFloat(f[0], 64)
}
