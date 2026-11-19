// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Start-up and self-protection (docs/deco/interference-audit.md §3, the
// cmd/udeco-ap requirements): single instance (R6), memory and CPU limits
// (R3), the crash-loop guard on the uptime clock (R7), the persistent
// forced-observe marker, the boot gate (R1/R2), the resource watchdog (R4)
// and the rare-event ring (R13).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
	"github.com/antoniocosta/unifi-openwrt/internal/device"
)

// ------------------------------------------------------------ R6 lock

// lockName is the single-instance lock in the run directory. flock is
// released by the kernel when the process dies, so a stale file never
// blocks a start (the old PID-file check could race: interference X11).
const lockName = "agent.lock"

type instanceLock struct {
	f       *os.File
	pidPath string
}

var errRunning = errors.New("another udeco-ap is running")

// acquireLock takes LOCK_EX|LOCK_NB on runDir/agent.lock and holds it for
// the life of the process; a second agent gets errRunning. The PID goes
// into the lock file and, for scripts, into runDir/udeco-ap.pid.
func acquireLock(runDir string) (*instanceLock, error) {
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(runDir, lockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		b, _ := os.ReadFile(f.Name())
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (pid %s)", errRunning, strings.TrimSpace(string(b)))
		}
		return nil, err
	}
	pid := []byte(strconv.Itoa(os.Getpid()) + "\n")
	f.Truncate(0)
	f.WriteAt(pid, 0)
	l := &instanceLock{f: f, pidPath: filepath.Join(runDir, "udeco-ap.pid")}
	tmp := l.pidPath + ".tmp"
	if os.WriteFile(tmp, pid, 0o644) == nil {
		os.Rename(tmp, l.pidPath)
	}
	return l, nil
}

// release drops the lock (the kernel would at exit anyway) and the PID
// file if it is still ours.
func (l *instanceLock) release() {
	if l == nil {
		return
	}
	if b, err := os.ReadFile(l.pidPath); err == nil && strings.TrimSpace(string(b)) == strconv.Itoa(os.Getpid()) {
		os.Remove(l.pidPath)
	}
	l.f.Close()
}

// ------------------------------------------------------------ R3 limits

const (
	memoryLimit = 48 << 20 // soft Go heap limit (the unit has about 95 MB available)
	gcPercent   = 50
	maxProcs    = 3   // isolcpus=3: only CPUs 0-2 run user space (X14)
	oomScoreAdj = 300 // die before hostapd or netifd; never negative
)

// applyLimits sets the Go runtime limits and raises our oom_score_adj to at
// least oomScoreAdj (procRoot is "/proc" on the device). It returns what it
// did, for the start log.
func applyLimits(procRoot string) string {
	debug.SetMemoryLimit(memoryLimit)
	debug.SetGCPercent(gcPercent)
	if runtime.GOMAXPROCS(0) > maxProcs {
		runtime.GOMAXPROCS(maxProcs)
	}
	adj := "?"
	p := filepath.Join(procRoot, "self", "oom_score_adj")
	if b, err := os.ReadFile(p); err == nil {
		cur, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		if cur < oomScoreAdj {
			if err := os.WriteFile(p, []byte(strconv.Itoa(oomScoreAdj)), 0o644); err != nil {
				adj = fmt.Sprintf("%d (raising it: %v)", cur, err)
			} else {
				cur = oomScoreAdj
			}
		}
		if adj == "?" {
			adj = strconv.Itoa(cur)
		}
	}
	return fmt.Sprintf("memory limit %d MiB, GOGC %d, GOMAXPROCS %d, oom_score_adj %s",
		memoryLimit>>20, gcPercent, runtime.GOMAXPROCS(0), adj)
}

// ------------------------------------------------------------ R7 clock

// readUptime is /proc/uptime's first field in seconds (root-relative).
func readUptime(root string) (float64, error) {
	b, err := os.ReadFile(filepath.Join(root, "proc", "uptime"))
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, errors.New("empty /proc/uptime")
	}
	return strconv.ParseFloat(f[0], 64)
}

// Crash-loop guard (agent-design.md §3.6): persist_shell.sh restarts the
// agent whenever it is not running; crashStarts starts within crashWindow
// are a crash loop. The start log is kept on the run directory (RAM, gone
// at reboot) and counts in /proc/uptime seconds, so the NTP step from the
// unit's 2025 boot clock cannot hide starts (X9, R7).
const (
	crashStarts = 5
	crashWindow = 10 * time.Minute
)

// recordStart appends uptime to the start log and reports whether this
// start completes a crash loop. Entries later than uptime come from an
// earlier boot and are dropped.
func recordStart(path string, uptime float64) (bool, error) {
	var keep []string
	if b, err := os.ReadFile(path); err == nil {
		for _, l := range strings.Fields(string(b)) {
			t, err := strconv.ParseFloat(l, 64)
			if err != nil {
				continue
			}
			if d := uptime - t; d >= 0 && d < crashWindow.Seconds() {
				keep = append(keep, l)
			}
		}
	}
	keep = append(keep, strconv.FormatFloat(uptime, 'f', 2, 64))
	if len(keep) > crashStarts {
		keep = keep[len(keep)-crashStarts:]
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	err := os.WriteFile(path, []byte(strings.Join(keep, "\n")+"\n"), 0o600)
	return len(keep) >= crashStarts, err
}

// ------------------------------------------------------------ forced observe

// The forced-observe marker lives next to the config on /tp_data
// (persistent): root now survives a reboot, so a reboot no longer returns
// the unit to stock TP-Link and must not end the safety stop either. A
// hand-back or a crash loop writes it; while it exists the agent observes
// whatever the config says. To resume takeover after fixing the cause:
//
//	rm /tp_data/udeco/force-observe; kill $(cat /tmp/udeco/udeco-ap.pid)
//
// (persist_shell.sh starts the agent again within a minute).
const observeMarker = "force-observe"

func writeMarker(path, why string, now time.Time) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(now.UTC().Format(time.RFC3339)+" "+why+"\n"), 0o600)
}

// readMarker returns the marker's reason, "" when there is none.
func readMarker(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if s := strings.TrimSpace(string(b)); s != "" {
		return s
	}
	return "(no reason recorded)"
}

// ------------------------------------------------------------ R1 boot gate

// Boot gate (R1/R2/R26): the agent starts from the firewall include at
// about 31 s into boot, long before TP-Link has finished starting. Until
// the gate opens it informs nothing, stops nothing and applies nothing;
// in takeover mode it only installs the inbound fence (R5).
var gateFiles = []string{"/tmp/done_boot", "/tmp/wifi_set_done", "/tmp/acsd2_channel_select_done"}

// jioGateFiles: the JCOW414's rcS waits for /tmp/svc_load_ok (its service
// hosts loaded) before it finishes booting.
var jioGateFiles = []string{"/tmp/svc_load_ok"}

const (
	gateMinUptime = 120 // s
	// gateGiveUp: with the uptime past this, missing marker files no longer
	// hold the gate (a firmware that never writes one would otherwise keep
	// the agent silent forever); an upgrade in flight still does.
	gateGiveUp = 600 // s
)

// gateStatus says whether the gate may open now and, if not, why. "Upgrade
// in flight" and "boot chain running" are decosys's R17 detector
// (decosys.InFlight), the same one Enforce holds on.
func gateStatus(root string, files []string) (open bool, why string) {
	up, err := readUptime(root)
	if err != nil {
		return false, "uptime: " + err.Error()
	}
	g, err := decosys.InFlight(root)
	if err != nil {
		return false, "reading /proc: " + err.Error()
	}
	if len(g.Upgrade) > 0 {
		return false, "TP-Link firmware upgrade in flight (" + strings.Join(g.Upgrade, "; ") + ")"
	}
	var missing []string
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(root, f)); err != nil {
			missing = append(missing, f)
		}
	}
	// the rc.d boot chain holds like a missing marker file: until the
	// give-up uptime, so one boot script that never ends cannot keep the
	// agent dark
	if len(g.Boot) > 0 {
		missing = append(missing, "the end of the rc.d boot chain ("+g.Boot[0]+")")
	}
	switch {
	case up < gateMinUptime:
		return false, fmt.Sprintf("uptime %.0f s < %d s", up, gateMinUptime)
	case len(missing) > 0 && up < gateGiveUp:
		return false, "waiting for " + strings.Join(missing, ", ")
	case len(missing) > 0:
		return true, fmt.Sprintf("uptime %.0f s: opened although %s never appeared", up, strings.Join(missing, ", "))
	}
	return true, fmt.Sprintf("uptime %.0f s, TP-Link boot finished", up)
}

// waitGate blocks until the boot gate opens (or ctx ends). In takeover
// mode the inbound fence is re-asserted at every check: TP-Link's own
// firewall start, which runs during boot, rebuilds INPUT without it.
func (a *agent) waitGate(ctx context.Context) error {
	last, fenceErr := "", ""
	for {
		files := gateFiles
		if a.cfg.jio() {
			files = jioGateFiles
		}
		open, why := gateStatus(a.o.root, files)
		if open {
			a.event("boot gate open: " + why)
			return nil
		}
		if why != last {
			a.logf("boot gate closed: %s (no inform, no takeover yet; checking every %s)", why, a.t.gateEvery)
			last = why
		}
		if a.sys != nil {
			e := ""
			if err := a.sys.Ingress(ctx, true); err != nil {
				e = err.Error()
			}
			if e != fenceErr && e != "" {
				a.logf("boot gate: inbound fence: %s", e)
			}
			fenceErr = e
		}
		t := time.NewTimer(a.t.gateEvery)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// ------------------------------------------------------------ R4 resources

// Resource watchdog thresholds (R4).
const (
	shedBelowAvailKB = 40 << 10 // MemAvailable below this: no scans, no steering
	exitAvailKB      = 20 << 10 // below this the agent exits (persist_shell restarts it)
	exitRSSKB        = 64 << 10 // our VmRSS above this: exit
	ramfsGrowthKB    = 8 << 10  // /tmp + /etc grown this much since start: alarm
)

type resources struct {
	RSSKB, AvailKB, RAMfsKB int64
}

// readResources reads our VmRSS, MemAvailable and the bytes in /tmp and
// /etc (ramfs: statfs reports nothing there, so the files are walked).
func readResources(root string) (resources, error) {
	var r resources
	kb := func(file, key string) (int64, error) {
		b, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			return 0, err
		}
		for _, l := range bytes.Split(b, []byte("\n")) {
			if v, ok := bytes.CutPrefix(l, []byte(key+":")); ok {
				f := strings.Fields(string(v))
				if len(f) > 0 {
					return strconv.ParseInt(f[0], 10, 64)
				}
			}
		}
		return 0, fmt.Errorf("%s: no %s", file, key)
	}
	var err error
	if r.RSSKB, err = kb("proc/self/status", "VmRSS"); err != nil {
		return r, err
	}
	if r.AvailKB, err = kb("proc/meminfo", "MemAvailable"); err != nil {
		return r, err
	}
	var bytes int64
	for _, d := range []string{"tmp", "etc"} {
		filepath.WalkDir(filepath.Join(root, d), func(_ string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.Type().IsRegular() {
				if i, err := e.Info(); err == nil {
					bytes += i.Size()
				}
			}
			return nil
		})
	}
	r.RAMfsKB = bytes >> 10
	return r, nil
}

// resourceVerdict applies R4 to a reading.
func resourceVerdict(r resources, baseRAMfsKB int64) (shed, exit bool, alarm string) {
	shed = r.AvailKB < shedBelowAvailKB
	switch {
	case r.RSSKB > exitRSSKB:
		exit, alarm = true, fmt.Sprintf("agent VmRSS %d kB > %d kB", r.RSSKB, exitRSSKB)
	case r.AvailKB < exitAvailKB:
		exit, alarm = true, fmt.Sprintf("MemAvailable %d kB < %d kB", r.AvailKB, exitAvailKB)
	case baseRAMfsKB > 0 && r.RAMfsKB-baseRAMfsKB > ramfsGrowthKB:
		alarm = fmt.Sprintf("/tmp + /etc hold %d kB, %d kB more than at start (RAM that cannot be reclaimed)", r.RAMfsKB, r.RAMfsKB-baseRAMfsKB)
	}
	return shed, exit, alarm
}

// errResources ends the agent so persist_shell.sh restarts it with a fresh
// heap (R4).
var errResources = errors.New("resource limit reached: exiting so the agent is restarted")

// resourceLoop checks R4 every t.resourceEvery until ctx ends; on a hard
// limit it cancels the agent through stop.
func (a *agent) resourceLoop(ctx context.Context, stop context.CancelCauseFunc) {
	base := int64(-1)
	lastAlarm, lastShed, readErr := "", false, false
	t := time.NewTicker(a.t.resourceEvery)
	defer t.Stop()
	for {
		r, err := readResources(a.o.root)
		if err != nil && !readErr {
			a.logf("resources: %v (memory watchdog skipped until it reads)", err)
		}
		readErr = err != nil
		if err == nil {
			a.res.Store(&r)
			if base < 0 {
				base = r.RAMfsKB
			}
			shed, exit, alarm := resourceVerdict(r, base)
			if shed != lastShed {
				a.logf("resources: MemAvailable %d kB: %s", r.AvailKB, map[bool]string{true: "shedding scans and band steering", false: "back to normal"}[shed])
				lastShed = shed
			}
			a.shed.Store(shed)
			if alarm != "" && alarm != lastAlarm {
				a.event("RESOURCE ALARM: " + alarm)
			}
			lastAlarm = alarm
			if exit {
				stop(errResources)
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ------------------------------------------------------------ R13 events

// eventMax bounds the rare-event ring on flash (R13).
const eventMax = 64 << 10

// eventLog is a small file of rare events (gate open, reboot, rollback,
// hand-back, alarms) on /tp_data: written only when one happens, never per
// inform, and cut to its newest half past eventMax.
type eventLog struct {
	path   string
	root   string
	clock  func() time.Time
	logf   func(string, ...any)
	failed bool
}

func (e *eventLog) add(msg string) {
	e.logf("EVENT: %s", msg)
	if e.path == "" {
		return
	}
	up, _ := readUptime(e.root)
	now := e.clock()
	ts := "unsynced"
	if !now.Before(device.ClockSane) {
		ts = now.UTC().Format(time.RFC3339)
	}
	line := fmt.Sprintf("%s up=%.0f %s\n", ts, up, strings.ReplaceAll(msg, "\n", " "))
	b, _ := os.ReadFile(e.path)
	b = append(b, line...)
	if len(b) > eventMax {
		b = b[len(b)-eventMax/2:]
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	os.MkdirAll(filepath.Dir(e.path), 0o700)
	tmp := e.path + ".tmp"
	err := os.WriteFile(tmp, b, 0o600)
	if err == nil {
		err = os.Rename(tmp, e.path)
	}
	if err != nil && !e.failed {
		e.logf("event log %s: %v", e.path, err)
		e.failed = true
	}
}

// checkReboot compares the kernel's boot id with the one stored last time
// and records a "rebooted" event when it changed, saying how the previous
// boot ended as far as its alive record tells (R13, alive.go; the cause of
// the unexplained reboots in X9/Q15 is still open).
func (a *agent) checkReboot() {
	cur, err := os.ReadFile(a.dev("/proc/sys/kernel/random/boot_id"))
	if err != nil {
		return
	}
	id := strings.TrimSpace(string(cur))
	a.alive.mu.Lock()
	a.alive.bootID = id
	a.alive.mu.Unlock()
	p := a.dev(filepath.Join(a.o.base, "boot_id"))
	prev, err := os.ReadFile(p)
	if err == nil && strings.TrimSpace(string(prev)) == id {
		return
	}
	up, _ := readUptime(a.o.root)
	if err == nil {
		a.event(fmt.Sprintf("the unit rebooted (up %.0f s): %s", up, a.previousEnd(strings.TrimSpace(string(prev)))))
	}
	os.WriteFile(p, []byte(id+"\n"), 0o600)
}
