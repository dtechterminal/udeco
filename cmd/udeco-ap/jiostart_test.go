// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// deploy/jio-start.sh's gateway guard, run without a device: guard.conf
// (sourced by the guard) replaces ping and sleep, and each sleep moves a
// fake uptime 10 s on; the guard stops when the fake start.sh is removed.

type guardRun struct {
	d, r   string
	events string
}

func runGuard(t *testing.T, files map[string]string, conf string, steps int) guardRun {
	t.Helper()
	for _, tool := range []string{"sh", "flock", "md5sum", "nohup"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	d, r := t.TempDir(), t.TempDir()
	up := filepath.Join(t.TempDir(), "uptime")
	os.WriteFile(up, []byte("5000.00 9000.00\n"), 0o644)
	// the supervisor the guard (re)starts: a no-op here
	files["start.sh"] = "exit 0\n"
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stop := 5000 + 10*steps
	// hook <uptime> runs at each sleep; a test's conf may define it
	conf = "hook() { :; }\n" + conf + `
REBOOT=false
sleep() {
	n=$(cut -d. -f1 $UP); n=$((n + 10)); echo "$n.00 0.00" > $UP
	hook $n
	[ $n -ge ` + strconv.Itoa(stop) + ` ] && rm -f $D/start.sh
	return 0
}
`
	os.WriteFile(filepath.Join(d, "guard.conf"), []byte(conf), 0o644)
	cmd := exec.Command("sh", "../../deploy/jio-start.sh", "guard")
	cmd.Env = append(os.Environ(), "UDECO_D="+d, "UDECO_R="+r, "UDECO_UPTIME="+up)
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("guard: %v", err)
		}
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		t.Fatal("guard did not stop")
	}
	ev, _ := os.ReadFile(filepath.Join(d, "guard.events"))
	return guardRun{d: d, r: r, events: string(ev)}
}

func (g guardRun) file(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(g.d, name))
	if err != nil {
		return "<none>"
	}
	return string(b)
}

func md5hex(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }

const (
	guardOldBuild = "old build 737fb8c5\n"
	guardNewBuild = "new build\n"
	guardU7LT     = `{"model":"U7LT"}` + "\n"
	guardUHDIW    = `{"model":"UHDIW","ports_unlocked":[2]}` + "\n"
	guardSilent   = "GW=203.0.113.1\nROLLBACK_AFTER=30\nREBOOT_AFTER=100000\nping() { return 1; }\n"
)

// TestJioGuardRollbackTakesConfig: a new build deployed with a config the
// confirmed build refuses (model UHDIW, ports_unlocked). The gateway goes
// silent: the rollback swaps the confirmed binary back and its config with
// it, or the old build would exit on the new config in a loop and leave the
// unit unmanaged.
func TestJioGuardRollbackTakesConfig(t *testing.T) {
	g := runGuard(t, map[string]string{
		"udeco-ap.gz": guardNewBuild, "udeco-ap.gz.prev": guardOldBuild, "good.md5": md5hex(guardOldBuild) + "\n",
		"udeco-ap.json": guardUHDIW, "udeco-ap.json.prev": guardU7LT,
	}, guardSilent, 8)
	if got := g.file(t, "udeco-ap.gz"); got != guardOldBuild {
		t.Errorf("binary not rolled back: %q", got)
	}
	if got := g.file(t, "udeco-ap.json"); got != guardU7LT {
		t.Errorf("config not rolled back with the binary: %q", got)
	}
	if got := g.file(t, "udeco-ap.json.bad"); got != guardUHDIW {
		t.Errorf("failed config not kept: %q", got)
	}
	if !strings.Contains(g.events, "ROLLBACK") || !strings.Contains(g.events, "udeco-ap.json replaced by udeco-ap.json.prev") {
		t.Errorf("events:\n%s", g.events)
	}
}

// TestJioGuardRollbackWithoutConfigPrev: no udeco-ap.json.prev (a deploy
// that kept the config): the binary alone goes back, as before.
func TestJioGuardRollbackWithoutConfigPrev(t *testing.T) {
	g := runGuard(t, map[string]string{
		"udeco-ap.gz": guardNewBuild, "udeco-ap.gz.prev": guardOldBuild, "good.md5": md5hex(guardOldBuild) + "\n",
		"udeco-ap.json": guardU7LT,
	}, guardSilent, 8)
	if g.file(t, "udeco-ap.gz") != guardOldBuild || g.file(t, "udeco-ap.json") != guardU7LT || g.file(t, "udeco-ap.json.bad") != "<none>" {
		t.Errorf("gz %q json %q json.bad %q", g.file(t, "udeco-ap.gz"), g.file(t, "udeco-ap.json"), g.file(t, "udeco-ap.json.bad"))
	}
	if strings.Contains(g.events, "udeco-ap.json replaced") {
		t.Errorf("events:\n%s", g.events)
	}
}

// TestJioGuardConfirmDropsConfigPrev: once the new build is confirmed, the
// .prev config belongs to a build that is no longer the confirmed one and
// is dropped (a later deploy that forgets to write its own must not pair
// the next .prev build with this stale config).
func TestJioGuardConfirmDropsConfigPrev(t *testing.T) {
	g := runGuard(t, map[string]string{
		"udeco-ap.gz": guardNewBuild, "udeco-ap.gz.prev": guardOldBuild, "good.md5": md5hex(guardOldBuild) + "\n",
		"udeco-ap.json": guardUHDIW, "udeco-ap.json.prev": guardU7LT,
	}, "GW=203.0.113.1\nHEALTHY_AFTER=30\nping() { return 0; }\n", 8)
	if got := strings.TrimSpace(g.file(t, "good.md5")); got != md5hex(guardNewBuild) {
		t.Errorf("good.md5 %q, want the new build", got)
	}
	if g.file(t, "udeco-ap.json.prev") != "<none>" || g.file(t, "udeco-ap.json") != guardUHDIW {
		t.Errorf("json.prev %q json %q", g.file(t, "udeco-ap.json.prev"), g.file(t, "udeco-ap.json"))
	}
}

// TestJioGuardConfirmsEachBuild: a build deployed while the gateway stays
// up (the guard keeps running; only the agent restarts) is confirmed once
// it has run HEALTHY_AFTER, as the boot-time build was. Otherwise good.md5
// stays on the boot-time build, the deploy keeps that one as .prev and the
// build in between is lost as a rollback target.
func TestJioGuardConfirmsEachBuild(t *testing.T) {
	g := runGuard(t, map[string]string{
		"udeco-ap.gz": guardOldBuild, "udeco-ap.gz.prev": "older\n", "good.md5": md5hex("older\n") + "\n",
		"udeco-ap.json": guardU7LT,
	}, "GW=203.0.113.1\nHEALTHY_AFTER=30\nping() { return 0; }\n"+
		// the deploy at uptime 5100: a new file renamed into place
		"hook() { [ $1 = 5100 ] && printf 'new build\\n' > $D/udeco-ap.gz.new && mv $D/udeco-ap.gz.new $D/udeco-ap.gz; return 0; }\n", 20)
	if got := strings.TrimSpace(g.file(t, "good.md5")); got != md5hex(guardNewBuild) {
		t.Errorf("good.md5 %q, want the build deployed at 5100 (%s); events:\n%s", got, md5hex(guardNewBuild), g.events)
	}
	if strings.Count(g.events, "confirmed good") != 2 {
		t.Errorf("want both builds confirmed; events:\n%s", g.events)
	}
}
