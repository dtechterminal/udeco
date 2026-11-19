// SPDX-License-Identifier: GPL-2.0-or-later

// udeco-ap runs on a rooted TP-Link Deco X20 and presents the unit to UniFi
// Network as a U6-Lite (UAL6) with its own MAC and IP
// (docs/deco/agent-design.md). Usage:
//
//	udeco-ap [-config /tp_data/udeco/udeco-ap.json]
//
// Modes: observe (takeover=false, the default) reads the unit with
// internal/wl and informs; nothing on the unit changes, and controller
// actions and the controller's Wi-Fi plan are only logged. Takeover lets
// internal/decosys stop TP-Link's software (and, with egress, firewall the
// unit's own traffic), then internal/bcmwifi brings up the controller's
// Wi-Fi (apply=true; apply=false only logs the plans) and carries out
// locate, LED, kick, block, scans and restart.
//
// Safety: SSH adoption listens on sshd_port (2222) and only accepts
// console_ip; port 22 (the unit's dropbear, used by TP-Link's mesh) is never
// touched. SIGTERM stops informing and leaves Wi-Fi as it is (rate limits
// and the flow cache off for them included; flowcache.go). When an apply
// or rollback leaves Wi-Fi with TP-Link, TP-Link's services are restored and
// the agent observes until the marker /tp_data/udeco/force-observe is
// removed (it survives reboots); so does a crash loop (5 starts in 10
// minutes). Firmware upgrades are acknowledged and faked, never downloaded.
// Passphrases and keys are never logged.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	cfgPath := flag.String("config", DefaultConfigPath, "agent config (JSON)")
	flag.Parse()
	os.Setenv("PATH", agentPATH)
	log.SetFlags(log.Ldate | log.Ltime)

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("udeco-ap: %v", err)
	}
	setupLog(cfg.Log, os.Stderr)
	if cfg.jio() {
		os.Setenv("PATH", jioPATH)
	}
	if err := run(cfg, filepath.Dir(*cfgPath)); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("udeco-ap: %v", err)
		os.Exit(1)
	}
}

func run(cfg *Config, base string) error {
	lock, err := acquireLock(defaultRunDir)
	if errors.Is(err, errRunning) {
		log.Printf("udeco-ap: %v; exiting", err)
		os.Exit(1) // R6: a second start exits non-zero
	}
	if err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	defer lock.release()
	log.Printf("udeco-ap: %s", applyLimits("/proc"))

	o := options{root: "/", base: base, runDir: defaultRunDir, logf: log.Printf}
	o.forceObserve = startGuard(cfg, "/", base, defaultRunDir, time.Now(), log.Printf)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	a, err := newAgent(cfg, o)
	if err != nil {
		return err
	}
	return a.run(ctx)
}

// startGuard records this start and returns why the agent must observe
// ("" = it may take over): a crash loop (which also writes the persistent
// marker, when takeover is configured) or the marker an earlier run left.
func startGuard(cfg *Config, root, base, runDir string, now time.Time, logf func(string, ...any)) string {
	marker := filepath.Join(root, base, observeMarker)
	up, err := readUptime(root)
	if err != nil {
		logf("udeco-ap: uptime: %v (crash-loop guard off for this start)", err)
	} else if loop, err := recordStart(filepath.Join(root, runDir, "starts"), up); err != nil {
		logf("udeco-ap: start log: %v", err)
	} else if loop {
		why := fmt.Sprintf("crash loop: %d starts within %s", crashStarts, crashWindow)
		if cfg.Takeover && readMarker(marker) == "" {
			if err := writeMarker(marker, why, now); err != nil {
				logf("udeco-ap: writing %s: %v", marker, err)
			}
		}
		return why
	}
	if m := readMarker(marker); m != "" {
		return "marker " + filepath.Join(base, observeMarker) + ": " + m
	}
	return ""
}
