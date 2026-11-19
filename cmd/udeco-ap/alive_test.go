package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setBoot(t *testing.T, root, id, uptime string) {
	t.Helper()
	for f, v := range map[string]string{"/proc/sys/kernel/random/boot_id": id, "/proc/uptime": uptime} {
		p := filepath.Join(root, f)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func readAlive(t *testing.T, h *harness) aliveRec {
	t.Helper()
	var r aliveRec
	b, err := os.ReadFile(h.a.alivePath())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("alive %q: %v", b, err)
	}
	return r
}

// The "rebooted" event says how the previous boot ended: still running
// (and in which job), stopped cleanly, or unknown.
func TestRebootCauseFromAlive(t *testing.T) {
	h := newHarness(t, nil)
	events := filepath.Join(h.root, "tp_data/udeco", eventsFile)
	lastEvent := func() string {
		b, _ := os.ReadFile(events)
		l := strings.Split(strings.TrimSpace(string(b)), "\n")
		return l[len(l)-1]
	}

	setBoot(t, h.root, "boot-a", "60.00 100.00")
	h.a.checkReboot() // first start: nothing to compare with
	if b, _ := os.ReadFile(events); strings.Contains(string(b), "rebooted") {
		t.Fatalf("first start logged a reboot: %q", b)
	}
	h.a.markAlive("running", false, "")
	setBoot(t, h.root, "boot-a", "900.00 100.00")
	h.a.markAlive("running", true, "apply system_cfg")
	if r := readAlive(t, h); r.BootID != "boot-a" || r.State != "running" || r.Job != "apply system_cfg" || r.JobUp != 900 || r.PID != os.Getpid() {
		t.Fatalf("alive %+v", r)
	}

	// power loss or panic during the job
	setBoot(t, h.root, "boot-b", "35.00 10.00")
	h.a.checkReboot()
	if e := lastEvent(); !strings.Contains(e, "the unit rebooted (up 35 s): the agent was still running when last seen at up=900 s") ||
		!strings.Contains(e, `in job "apply system_cfg" since up=900 s`) {
		t.Fatalf("event %q", e)
	}

	// a clean stop (SIGTERM from a userland reboot)
	h.a.markAlive("running", true, "")
	h.a.markAlive("stopped", false, "")
	if r := readAlive(t, h); r.BootID != "boot-b" || r.State != "stopped" || r.Job != "" {
		t.Fatalf("alive %+v", r)
	}
	setBoot(t, h.root, "boot-c", "34.00 10.00")
	h.a.checkReboot()
	if e := lastEvent(); !strings.Contains(e, "the unit rebooted (up 34 s): the agent had stopped cleanly at up=35 s") {
		t.Fatalf("event %q", e)
	}

	// running, no job
	h.a.markAlive("running", false, "")
	setBoot(t, h.root, "boot-d", "36.00 10.00")
	h.a.checkReboot()
	if e := lastEvent(); !strings.Contains(e, "still running when last seen at up=34 s") || strings.Contains(e, "in job") {
		t.Fatalf("event %q", e)
	}

	// the record is from an older boot (boot-d never wrote one)
	setBoot(t, h.root, "boot-e", "37.00 10.00")
	h.a.checkReboot()
	if e := lastEvent(); !strings.Contains(e, "(up 37 s): no alive record from the previous boot") {
		t.Fatalf("event %q", e)
	}

	// no record at all
	os.Remove(h.a.alivePath())
	setBoot(t, h.root, "boot-f", "38.00 10.00")
	h.a.checkReboot()
	if e := lastEvent(); !strings.Contains(e, "(up 38 s): no alive record from the previous boot") {
		t.Fatalf("event %q", e)
	}
}

// A running agent keeps the record: "running" from the start, the job
// while a worker job other than the routine ticks runs, "stopped" at exit.
func TestAliveRecordLifecycle(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover = true })
	setBoot(t, h.root, "boot-x", "5000.00 9000.00")
	h.start()
	eventually(t, "alive written", func() bool {
		b, err := os.ReadFile(h.a.alivePath())
		return err == nil && strings.Contains(string(b), `"state":"running"`)
	})
	if r := readAlive(t, h); r.BootID != "boot-x" || r.Job != "" {
		t.Fatalf("alive at start %+v", r)
	}
	in, release := make(chan struct{}), make(chan struct{})
	h.a.submit("test job", func(context.Context) { close(in); <-release })
	<-in
	if r := readAlive(t, h); r.State != "running" || r.Job != "test job" || r.JobUp != 5000 {
		t.Fatalf("alive during job %+v", r)
	}
	close(release)
	eventually(t, "job cleared", func() bool {
		b, _ := os.ReadFile(h.a.alivePath())
		return !strings.Contains(string(b), "test job")
	})
	h.stop()
	if r := readAlive(t, h); r.State != "stopped" || r.Job != "" || r.BootID != "boot-x" {
		t.Fatalf("alive after stop %+v", r)
	}
	if fi, err := os.Stat(h.a.alivePath()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("alive mode %v %v", fi, err)
	}
}
