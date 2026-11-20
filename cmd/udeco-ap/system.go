// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Process plumbing: PATH, the command runner, logging, the PID file and the
// crash-loop guard.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os/exec"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
)

// agentPATH is set explicitly: persist_shell.sh runs the agent from cron,
// whose PATH lacks /usr/sbin (wl, hostapd, brctl, iptables live there). It
// is the firmware's binary directories in the order decosys searches them
// (decosys.BinDirs), and the PATH of a site login's session on both
// platforms (siteSSHOptions).
var agentPATH = strings.Join(decosys.BinDirs, ":")

// jioPATH: the JCOW414 keeps iwpriv/iwconfig in /userfs/bin and ip in
// /pfrm2.0/bin.
var jioPATH = "/userfs/bin:/pfrm2.0/bin:" + agentPATH

// execRunner runs device commands (wl, hostapd_cli, ubus, iptables, ...).
// It is the Runner of internal/wl, internal/decosys and internal/bcmwifi.
type execRunner struct {
	timeout time.Duration // applied when ctx has no deadline
}

func (r execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok && r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	// hostapd -B daemonises; should a child keep our pipes open, Wait
	// still returns.
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		if msg := firstLine(errb.String()); msg != "" {
			return out.Bytes(), fmt.Errorf("%w: %s", err, msg)
		}
		return out.Bytes(), err
	}
	return out.Bytes(), nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(l)
}

// setupLog sends the standard logger to syslog (logd keeps running under
// decosys) or stderr. It falls back to stderr when /dev/log is unavailable.
func setupLog(dest string, stderr io.Writer) {
	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(stderr)
	if dest != logSyslog {
		return
	}
	w, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "udeco-ap")
	if err != nil {
		log.Printf("udeco-ap: syslog unavailable (%v): logging to stderr", err)
		return
	}
	log.SetFlags(0)
	log.SetOutput(w)
}
