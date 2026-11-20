// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/decosys"
	"github.com/dtechterminal/udeco/internal/repotest"
	"github.com/dtechterminal/udeco/internal/unit"
)

// lockRemoval is what a launcher runs to remove the agent's login lock, as
// fakeIptables logs it: in each family the jump from INPUT (once: the fake
// fails -D), then the chain decosys.LockChain flushed and deleted. wait is
// the Deco's -w; the Garage's iptables runs without it.
func lockRemoval(wait bool) string {
	w := ""
	if wait {
		w = "-w "
	}
	var b strings.Builder
	for _, fam := range []string{"iptables", "ip6tables"} {
		fmt.Fprintf(&b, "%[1]s %[2]s-D INPUT -j %[3]s\n%[1]s %[2]s-F %[3]s\n%[1]s %[2]s-X %[3]s\n", fam, w, decosys.LockChain)
	}
	return b.String()
}

// fakeIptables writes iptables and ip6tables into dir that log each call
// ("<name> <args>") to log; -D fails, as with no jump left.
func fakeIptables(t *testing.T, dir, log string) {
	t.Helper()
	os.MkdirAll(dir, 0o755)
	for _, n := range []string{"iptables", "ip6tables"} {
		s := "#!/bin/sh\necho \"" + n + " $*\" >>" + log + "\nfor a in \"$@\"; do [ \"$a\" = -D ] && exit 1; done\nexit 0\n"
		if err := os.WriteFile(filepath.Join(dir, n), []byte(s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// The Deco launcher removes the login lock before it starts the agent,
// never while an agent runs (that agent may hold the lock on purpose).
func TestDeployLauncherUnlocks(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	root := t.TempDir()
	dir := filepath.Join(root, unit.DecoDir)
	bin := filepath.Join(root, "bin")
	for _, d := range []string{dir, filepath.Dir(filepath.Join(root, unit.RAMDir)), bin} {
		os.MkdirAll(d, 0o755)
	}
	log := filepath.Join(root, "calls")
	os.WriteFile(filepath.Join(bin, "pidof"), []byte("#!/bin/sh\n[ \"$FAKE_RUNNING\" = 1 ] && echo 42\n"), 0o755)
	os.WriteFile(filepath.Join(bin, "logger"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	fakeIptables(t, bin, log)
	os.WriteFile(filepath.Join(dir, "udeco-ap"), []byte("#!/bin/sh\necho start >>"+log+"\n"), 0o755)
	script := filepath.Join(root, "start.sh")
	os.WriteFile(script, []byte(launcher(t, root)), 0o755)
	run := func(running bool) string {
		os.Remove(log)
		cmd := exec.Command(sh, script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "FAKE_RUNNING="+map[bool]string{true: "1", false: "0"}[running])
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Logf("launcher: %v %s", err, out)
		}
		b, _ := os.ReadFile(log)
		return string(b)
	}
	want := lockRemoval(true) + "start\n"
	if got := run(false); got != want {
		t.Errorf("calls:\n%s\nwant:\n%s", got, want)
	}
	if got := run(true); got != "" {
		t.Errorf("an agent runs, yet: %q", got)
	}
}

// The Garage launcher removes the login lock before each (re)start of the
// agent, with the iptables of the directory $IPT (busybox sh, errors
// ignored). The directory's default is the one jiosys looks in first:
// internal/jiosys TestJioStartIptablesDir.
func TestJioStartUnlocks(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	b := repotest.Read(t, jioStart)
	fn := repotest.ShellFunc(t, b, "unlock")
	i := strings.LastIndex(b, "while [ -f $D/start.sh ]; do")
	loop := b[i:]
	u, start := strings.Index(loop, "\n\tunlock\n"), strings.Index(loop, "$R/udeco-ap -config")
	if i < 0 || u < 0 || start < 0 || u > start {
		t.Errorf("unlock is not run before each start in the supervisor loop:\n%s", loop)
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	fakeIptables(t, filepath.Join(dir, "bin"), log)
	cmd := exec.Command(sh, "-c", fn+"unlock; echo rc=$?")
	cmd.Env = append(os.Environ(), "IPT="+filepath.Join(dir, "bin"))
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "rc=0" {
		t.Errorf("unlock: %v %q", err, out)
	}
	got, _ := os.ReadFile(log)
	want := lockRemoval(false)
	if string(got) != want {
		t.Errorf("calls:\n%s\nwant:\n%s", got, want)
	}
	// no iptables at all: nothing printed, no failure
	cmd = exec.Command(sh, "-c", fn+"unlock; echo rc=$?")
	cmd.Env = append(os.Environ(), "IPT="+filepath.Join(dir, "none"))
	if out, _ := cmd.CombinedOutput(); strings.TrimSpace(string(out)) != "rc=0" {
		t.Errorf("unlock without iptables: %q", out)
	}
}

// Both deploy scripts say what to do when the login port does not answer,
// in the same words (each prints them itself: the Garage's from its telnet
// helper), and the login lock's document shows those words.
func TestDeployLoginLockHint(t *testing.T) {
	m := regexp.MustCompile(`echo "deco-ap: (login lock: [^"$]+)" >&2\n`).FindStringSubmatch(repotest.ShellFunc(t, repotest.Read(t, decoDeploy), "login_lock_hint"))
	if m == nil {
		t.Fatal("deploy/deco-ap.sh login_lock_hint prints no hint")
	}
	hint := m[1]
	for _, w := range []string{"Device SSH", "wait", "retry"} {
		if !strings.Contains(hint, w) {
			t.Errorf("the hint %q does not say %q", hint, w)
		}
	}
	if !strings.Contains(repotest.Read(t, jioDeploy), `sys.stderr.write("jio-ap: `+hint+`\n")`) {
		t.Errorf("deploy/jio-ap.sh does not print the hint of deploy/deco-ap.sh: %s", hint)
	}
	doc := repotest.Read(t, "docs/deco/features/login-lock.md")
	for n := 0; ; n++ {
		body, ok := repotest.Fenced(doc, "", n)
		if !ok {
			t.Errorf("docs/deco/features/login-lock.md does not show the hint the scripts print: %s", hint)
			break
		}
		if body == hint {
			break
		}
	}
}

// The Deco's hint follows ssh's own words for a refused or silent :22, and
// stays quiet on other failures.
func TestDeployLoginLockHintMatches(t *testing.T) {
	bash := bashPath(t)
	fn := repotest.ShellFunc(t, repotest.Read(t, decoDeploy), "login_lock_hint")
	for msg, want := range map[string]bool{
		"ssh: connect to host 192.168.0.241 port 22: Connection refused":    true,
		"ssh: connect to host 192.168.0.241 port 22: Operation timed out":   true,
		"ssh: connect to host 192.168.0.241 port 22: Connection timed out":  true,
		"root@192.168.0.241: Permission denied (publickey,password).":       false,
		"ssh: Could not resolve hostname x: nodename nor servname provided": false,
	} {
		out, _ := exec.Command(bash, "-c", fn+`login_lock_hint "$1"`, "x", msg).CombinedOutput()
		if got := strings.Contains(string(out), "Device SSH"); got != want {
			t.Errorf("%q: hint %v, want %v", msg, got, want)
		}
	}
}
