package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
)

// The alive record (R13): a small file on flash, rewritten at start, every
// aliveEvery, around every worker job other than the routine Enforce and
// schedule ticks (those only once they change the unit: aliveLazy), and
// when the agent stops. After a reboot, checkReboot
// reads the previous boot's record to say how that boot ended: the agent
// stopped cleanly (a userland stop or reboot: procd sends SIGTERM), or it
// was still running (power loss, a kernel panic or SIGKILL), and if so in
// which job. The units keep no reset reason of their own (Q15).
const (
	aliveFile  = "alive"
	aliveEvery = 5 * time.Minute // /tp_data is UBIFS mounted sync: ~290 small writes a day
)

type aliveRec struct {
	BootID string  `json:"boot_id"`
	Up     float64 `json:"up"`             // /proc/uptime when written
	Wall   string  `json:"wall,omitempty"` // RFC 3339 UTC; empty while the clock is unset
	PID    int     `json:"pid"`
	State  string  `json:"state"`            // "running" or "stopped"
	Job    string  `json:"job,omitempty"`    // the worker job in progress
	JobUp  float64 `json:"job_up,omitempty"` // uptime when that job started
}

type aliveState struct {
	mu     sync.Mutex
	bootID string
	job    string
	jobUp  float64
	failed bool
}

// aliveJob reports whether a worker job is worth a flash write before and
// after it: the 60 s routine ticks are not, unless they change the unit
// (aliveLazy).
func aliveJob(what string) bool { return what != "enforce" && what != "schedules" }

// aliveLazy is a routine tick's mark in the alive record: written at the
// tick's first change to the unit through the Wi-Fi backend (a LAN port
// moved back, a VLAN bridge pruned, a BSS put back in its bridge, a
// schedule's apply), so idle ticks write nothing to flash. runJob puts it
// in the job's context; the backend's change hook (aliveChange) finds it
// there, so changes made outside the worker (the port monitor) never mark
// a tick.
type aliveLazy struct {
	what   string
	once   sync.Once
	marked atomic.Bool
}

type aliveLazyKey struct{}

// aliveChange is the Wi-Fi backend's change hook (mtkwifi OnChange): the
// routine job running in ctx, if any, is marked once.
func (a *agent) aliveChange(ctx context.Context) {
	lz, _ := ctx.Value(aliveLazyKey{}).(*aliveLazy)
	if lz == nil {
		return
	}
	lz.once.Do(func() {
		a.markAlive("running", true, lz.what)
		lz.marked.Store(true)
	})
}

// watchChanges hands the Wi-Fi backend the alive record's change hook
// (jio-mtk; bcmwifi has none).
func (a *agent) watchChanges() {
	if w, ok := a.wifi.(interface{ OnChange(func(context.Context)) }); ok {
		w.OnChange(a.aliveChange)
	}
}

func (a *agent) alivePath() string { return a.dev(filepath.Join(a.o.base, aliveFile)) }

// markAlive rewrites the alive record; job "" keeps the current job,
// setJob replaces it (with job "" clearing it).
func (a *agent) markAlive(state string, setJob bool, job string) {
	if a.o.base == "" { // a bare agent in a unit test: no flash to write to
		return
	}
	s := &a.alive
	s.mu.Lock()
	defer s.mu.Unlock()
	up, _ := readUptime(a.o.root)
	if setJob {
		s.job, s.jobUp = job, 0
		if job != "" {
			s.jobUp = up
		}
	}
	r := aliveRec{BootID: s.bootID, Up: up, PID: os.Getpid(), State: state, Job: s.job, JobUp: s.jobUp}
	now := a.o.now
	if now == nil {
		now = time.Now
	}
	if t := now(); !t.Before(device.ClockSane) {
		r.Wall = t.UTC().Format(time.RFC3339)
	}
	b, _ := json.Marshal(r)
	p := a.alivePath()
	os.MkdirAll(filepath.Dir(p), 0o700)
	tmp := p + ".tmp"
	err := os.WriteFile(tmp, append(b, '\n'), 0o600)
	if err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil && !s.failed {
		a.logf("alive record %s: %v", p, err)
		s.failed = true
	}
}

// aliveLoop rewrites the record every aliveEvery until ctx ends.
func (a *agent) aliveLoop(ctx context.Context) {
	t := time.NewTicker(aliveEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.markAlive("running", false, "")
		}
	}
}

// previousEnd describes how the boot with id prev ended, from the alive
// record it left ("" when there is none from that boot).
func (a *agent) previousEnd(prev string) string {
	b, err := os.ReadFile(a.alivePath())
	if err != nil {
		return "no alive record from the previous boot"
	}
	var r aliveRec
	if json.Unmarshal(b, &r) != nil || prev == "" || r.BootID != prev {
		return "no alive record from the previous boot"
	}
	at := fmt.Sprintf("up=%.0f s", r.Up)
	if r.Wall != "" {
		at += " " + r.Wall
	}
	if r.State == "stopped" {
		return fmt.Sprintf("the agent had stopped cleanly at %s (a userland stop or reboot, or the unit reset while the agent was not running)", at)
	}
	s := fmt.Sprintf("the agent was still running when last seen at %s (no clean stop: power loss, a kernel panic or SIGKILL, at most %s later)", at, aliveEvery)
	if r.Job != "" {
		s += fmt.Sprintf(", in job %q since up=%.0f s", r.Job, r.JobUp)
	}
	return s
}
