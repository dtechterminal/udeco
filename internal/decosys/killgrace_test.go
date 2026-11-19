// SPDX-License-Identifier: GPL-2.0-or-later

package decosys

import (
	"context"
	"testing"
	"time"
)

// cloud-proxy on .205 (2026-11-19) survives SIGTERM: the kill step must send
// SIGKILL once the process has outlived a SIGTERM by killGrace, and not
// before.
func TestKillEscalatesAfterGrace(t *testing.T) {
	u := newUnit(t, "205")
	u.setProcs(map[int][]string{1: {"/sbin/procd"}, 8692: {"/usr/bin/cloud-proxy", "-c", "/etc/cloud_config.cfg"}})
	r := newFakeRun()
	m := newManager(u, r, false)
	clock := time.Date(2026, 11, 19, 3, 16, 0, 0, time.UTC)
	m.now = func() time.Time { return clock }
	match := func(argv []string) bool { return len(argv) > 0 && argv[0] == "/usr/bin/cloud-proxy" }
	run := func() []string {
		if err := m.exec(context.Background(), m.killStep("cloud_proxy", "test", []int{8692}, match)); err != nil {
			t.Fatal(err)
		}
		return r.take()
	}
	diff(t, run(), []string{"/bin/kill 8692"})
	clock = clock.Add(killGrace - time.Second)
	diff(t, run(), []string{"/bin/kill 8692"}) // still within the grace
	clock = clock.Add(2 * time.Second)
	diff(t, run(), []string{"/bin/kill -9 8692"})
}
