// SPDX-License-Identifier: GPL-2.0-or-later

// Package pathmon is UniFi path monitoring (the U6 Pro's upathmond) for
// the Deco agent: ICMP echo probes to the gateway, the uplink device and
// controller-named hosts, reported in the inform's "pathmon" object.
//
// What the controller sends (Network 11.1.50, com.ubnt.service.config.
// ubntconf.PCBG; only to a device whose fw3_caps has 0x40,
// supportsPathMonitoring), as system_cfg:
//
//	pathmon.status=enabled
//	pathmon.interval=5        seconds between probes of one target
//	pathmon.timeout=1000      milliseconds a probe waits for its reply
//	pathmon.ema_samples=60    averaging window
//	pathmon.size=56           ICMP payload bytes
//	pathmon.target.1.type=gateway
//	pathmon.target.2.type=uplink
//
// plus, per the U6 Pro's ubntbox strings, target.N.type=host with
// target.N.addr. What the device reports is in Monitor.Report.
package pathmon

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Target types (the controller's enum com.ubnt.i.k.g.sITFkDkyKy).
const (
	TypeGateway = "gateway" // the unit's default gateway
	TypeUplink  = "uplink"  // the device at the other end of the uplink cable (its LLDP management address)
	TypeHost    = "host"    // target.N.addr
)

// Defaults: the values the controller sends today.
const (
	DefaultInterval   = 5 * time.Second
	DefaultTimeout    = time.Second
	DefaultEMASamples = 60
	DefaultSize       = 56
)

// Limits the agent holds the controller's values to: a probe at least every
// minute and at most every second, a payload an Ethernet frame carries.
const (
	minInterval = time.Second
	maxInterval = time.Minute
	minTimeout  = 100 * time.Millisecond
	maxSize     = 1472 // 1500 - IPv4 20 - ICMP 8
	maxTargets  = 8
)

// Config is system_cfg's pathmon section.
type Config struct {
	Interval   time.Duration
	Timeout    time.Duration
	EMASamples int
	Size       int
	Targets    []Target
}

// Target is one pathmon.target.N.
type Target struct {
	Type string
	Addr string // TypeHost only: an IPv4 address
}

// FromCfg reads the pathmon section of a parsed system_cfg (key -> value).
// It returns nil when path monitoring is off or names no usable target.
// The notes say what was skipped or clamped; they never hold secrets (the
// section has none).
func FromCfg(cfg map[string]string) (*Config, []string) {
	if cfg["pathmon.status"] != "enabled" {
		return nil, nil
	}
	var notes []string
	c := &Config{Interval: DefaultInterval, Timeout: DefaultTimeout, EMASamples: DefaultEMASamples, Size: DefaultSize}
	num := func(key string, min, max int) (int, bool) {
		v, ok := cfg[key]
		if !ok {
			return 0, false
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < min || n > max {
			notes = append(notes, fmt.Sprintf("%s=%q: not a number in %d..%d, default used", key, v, min, max))
			return 0, false
		}
		return n, true
	}
	if n, ok := num("pathmon.interval", 1, 3600); ok {
		c.Interval = time.Duration(n) * time.Second
	}
	if n, ok := num("pathmon.timeout", 1, 3600000); ok {
		c.Timeout = time.Duration(n) * time.Millisecond
	}
	if n, ok := num("pathmon.ema_samples", 1, 100000); ok {
		c.EMASamples = n
	}
	if n, ok := num("pathmon.size", 0, 65507); ok {
		c.Size = n
	}
	if c.Interval < minInterval || c.Interval > maxInterval {
		clamped := min(max(c.Interval, minInterval), maxInterval)
		notes = append(notes, fmt.Sprintf("pathmon.interval %s held to %s", c.Interval, clamped))
		c.Interval = clamped
	}
	if c.Timeout < minTimeout {
		notes = append(notes, fmt.Sprintf("pathmon.timeout %s raised to %s", c.Timeout, minTimeout))
		c.Timeout = minTimeout
	}
	if c.Timeout > c.Interval {
		// a probe must finish before the next one of the same target
		notes = append(notes, fmt.Sprintf("pathmon.timeout %s held to the interval %s", c.Timeout, c.Interval))
		c.Timeout = c.Interval
	}
	if c.Size > maxSize {
		notes = append(notes, fmt.Sprintf("pathmon.size %d held to %d (one unfragmented frame)", c.Size, maxSize))
		c.Size = maxSize
	}
	// targets, in index order
	var idx []int
	for k := range cfg {
		rest, ok := strings.CutPrefix(k, "pathmon.target.")
		if !ok {
			continue
		}
		n, field, ok := strings.Cut(rest, ".")
		i, err := strconv.Atoi(n)
		if !ok || err != nil || i < 0 || field != "type" {
			continue
		}
		idx = append(idx, i)
	}
	sort.Ints(idx)
	seen := map[Target]bool{}
	for _, i := range idx {
		p := fmt.Sprintf("pathmon.target.%d.", i)
		t := Target{Type: cfg[p+"type"]}
		switch t.Type {
		case TypeGateway, TypeUplink:
		case TypeHost:
			ip := net.ParseIP(strings.TrimSpace(cfg[p+"addr"])).To4()
			if ip == nil {
				// upathmond: "target %d: invalid or missing addr (%s); skipping"
				notes = append(notes, fmt.Sprintf("pathmon target %d: host address %q is not an IPv4 address: skipped (IPv6 and names are not probed)", i, cfg[p+"addr"]))
				continue
			}
			t.Addr = ip.String()
		default:
			notes = append(notes, fmt.Sprintf("pathmon target %d: unknown type %q: skipped", i, t.Type))
			continue
		}
		if seen[t] {
			continue
		}
		if len(c.Targets) == maxTargets {
			notes = append(notes, fmt.Sprintf("pathmon: more than %d targets: the rest skipped", maxTargets))
			break
		}
		seen[t] = true
		c.Targets = append(c.Targets, t)
	}
	if len(c.Targets) == 0 {
		return nil, append(notes, "pathmon: no target to probe: off")
	}
	return c, notes
}
