// SPDX-License-Identifier: GPL-2.0-or-later

// Package wl reads a Broadcom-based TP-Link Deco (X20) on the device itself
// and turns it into an openwrt.Snapshot, so the existing inform code
// (openwrt.Snapshot.Fields) can describe it as a UniFi AP.
//
// Sources (docs/deco/agent-design.md §3.1, research report collector.md):
//   - system, ports, FDB, ARP, gateway: files under /proc and /sys, read
//     directly (no exec);
//   - radios, VAPs, clients, channel use: the Broadcom `wl` tool, read-only
//     getters only (about 11 calls per collection).
//
// The package never runs iwinfo, ubus or any mutating `wl` command. The
// exceptions are `wl scan`, which Collector.Scan and the spectrum runner
// (spectrum.go) run, and `wl scanabort`, which only the spectrum runner sends
// to end its own scan early.
package wl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/unit"
)

// Runner executes a command and returns its stdout. Implementations must
// honour ctx (cancel or deadline ends the command) and should put the
// command's stderr into the error.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs commands with os/exec. The Collector bounds every call with
// its own timeout through ctx.
type ExecRunner struct{}

// Run runs name with args and returns stdout. On failure the error carries
// the first line of stderr (for example "wl: Not Found").
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if msg := firstLine(errb.String()); msg != "" {
			return out.Bytes(), fmt.Errorf("%w: %s", err, msg)
		}
		return out.Bytes(), err
	}
	return out.Bytes(), nil
}

// Options configures a Collector.
type Options struct {
	Root   string // filesystem root ("/" on the device; a testdata tree in tests)
	Run    Runner // nil = ExecRunner
	Uplink string // optional fixed uplink port name; "" = gateway FDB detection
	// CallTimeout bounds each `wl` call (0 = 5 s). Scan's polling is bounded
	// separately (ScanTimeout).
	CallTimeout time.Duration
	// ScanTimeout bounds how long Scan waits for results (0 = 15 s).
	ScanTimeout time.Duration
	// Bridge is the LAN bridge the AP's identity, address and FDB are read
	// from ("" = br-lan, the Deco's). Ports matches the wired port netdevs
	// (nil = eth0, eth1, ...).
	Bridge string
	Ports  *regexp.Regexp
}

const (
	defaultCallTimeout = 5 * time.Second
	defaultScanTimeout = 15 * time.Second
	// vapRefresh is how long the per-VAP identity (bss state, dwds, SSID,
	// security) is reused before it is read again. A change in bridge
	// membership or a failed client read refreshes it at once.
	vapRefresh = 60 * time.Second
)

// Collector reads the device. It is safe for concurrent use; Collect calls
// are serialised because they share the channel-use accumulators.
type Collector struct {
	opt Options

	// test hooks
	now     func() time.Time
	ifAddrs func(name string) ([]net.Addr, error)
	sleep   func(ctx context.Context, d time.Duration) error

	capsMu sync.Mutex
	caps   *capsState // nil until read

	mu     sync.Mutex // Collect state below
	survey map[string]*surveyState
	vaps   map[string]*vapCache // per radio

	scanMu ctxMutex // one scan at a time: Scan or a spectrum band

	specMu sync.Mutex
	spec   map[string]*SpectrumRunner // spectrum runners by radio

	bandMu sync.Mutex
	bands  map[string]*bandSnap // radios with a spectrum band running (Collect reports these)
}

// New returns a Collector. Nothing is read until the first call.
func New(o Options) *Collector {
	if o.Root == "" {
		o.Root = "/"
	}
	if o.Run == nil {
		o.Run = ExecRunner{}
	}
	if o.CallTimeout <= 0 {
		o.CallTimeout = defaultCallTimeout
	}
	if o.ScanTimeout <= 0 {
		o.ScanTimeout = defaultScanTimeout
	}
	if o.Bridge == "" {
		o.Bridge = unit.LANBridge
	}
	if o.Ports == nil {
		o.Ports = ethName
	}
	return &Collector{
		opt:     o,
		now:     time.Now,
		ifAddrs: interfaceAddrs,
		sleep:   sleepCtx,
		survey:  map[string]*surveyState{},
		vaps:    map[string]*vapCache{},
	}
}

// Invalidate drops the cached hardware facts (Caps) and VAP identities, so
// the next Collect or Caps reads them again. Call it after changing the
// country, the SSIDs or which BSSes are up.
func (c *Collector) Invalidate() {
	c.capsMu.Lock()
	c.caps = nil
	c.capsMu.Unlock()
	c.mu.Lock()
	c.vaps = map[string]*vapCache{}
	c.mu.Unlock()
}

// wl runs one read-only `wl -i iface args...` call with the per-call timeout.
func (c *Collector) wl(ctx context.Context, iface string, args ...string) ([]byte, error) {
	if !ifaceOK(iface) {
		return nil, fmt.Errorf("wl: bad interface name %q", iface)
	}
	ctx, cancel := context.WithTimeout(ctx, c.opt.CallTimeout)
	defer cancel()
	argv := append([]string{"-i", iface}, args...)
	out, err := c.opt.Run.Run(ctx, "wl", argv...)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil && !errors.Is(err, cerr) {
			// a command killed at the deadline only says "signal: killed":
			// keep why, so callers can tell it from wl's own answer
			err = fmt.Errorf("%w (%w)", err, cerr)
		}
		return out, fmt.Errorf("wl %s: %w", strings.Join(argv, " "), err)
	}
	return out, nil
}

// path joins a device path (absolute, like "/proc/uptime") onto Root.
func (c *Collector) path(p string) string { return filepath.Join(c.opt.Root, p) }

func interfaceAddrs(name string) ([]net.Addr, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return ifc.Addrs()
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ifaceOK accepts kernel interface names only (no option or shell tricks):
// apstate.IfNameChars, and no leading '-', which `wl -i` would read as an
// option.
func ifaceOK(s string) bool { return apstate.IfNameChars(s) && s[0] != '-' }

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(l)
}

// errContains reports whether err's text contains any of the substrings
// (wl reports conditions such as "Not Ready" only as text on stderr).
func errContains(err error, subs ...string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, s := range subs {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

var errNoRadios = errors.New("wl: no Broadcom radios (wl0, wl1, ...) under /sys/class/net")
