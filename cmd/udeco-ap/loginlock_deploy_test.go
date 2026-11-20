// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

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
	dir := filepath.Join(root, "tp_data/udeco")
	bin := filepath.Join(root, "bin")
	for _, d := range []string{dir, filepath.Join(root, "tmp"), bin} {
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
	want := "iptables -w -D INPUT -j UDECO-LOCK\niptables -w -F UDECO-LOCK\niptables -w -X UDECO-LOCK\n" +
		"ip6tables -w -D INPUT -j UDECO-LOCK\nip6tables -w -F UDECO-LOCK\nip6tables -w -X UDECO-LOCK\nstart\n"
	if got := run(false); got != want {
		t.Errorf("calls:\n%s\nwant:\n%s", got, want)
	}
	if got := run(true); got != "" {
		t.Errorf("an agent runs, yet: %q", got)
	}
}

// The Garage launcher removes the login lock before each (re)start of the
// agent, with /pfrm2.0/bin's iptables (busybox sh, errors ignored).
func TestJioStartUnlocks(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	b := string(readFixture(t, "../../deploy", "jio-start.sh"))
	if !strings.Contains(b, "IPT=${UDECO_IPT:-/pfrm2.0/bin}") {
		t.Error("the unlock does not default to /pfrm2.0/bin")
	}
	fn := regexp.MustCompile(`(?ms)^unlock\(\) \{\n.*?^\}\n`).FindString(b)
	if fn == "" {
		t.Fatal("no unlock() in deploy/jio-start.sh")
	}
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
	want := "iptables -D INPUT -j UDECO-LOCK\niptables -F UDECO-LOCK\niptables -X UDECO-LOCK\n" +
		"ip6tables -D INPUT -j UDECO-LOCK\nip6tables -F UDECO-LOCK\nip6tables -X UDECO-LOCK\n"
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

// Both deploy scripts say what to do when the login port does not answer.
func TestDeployLoginLockHint(t *testing.T) {
	const hint = "login lock: turn on Device SSH in UniFi (Settings > System > Advanced > Device SSH Authentication), wait ~1 min, retry"
	for _, s := range []string{"deco-ap.sh", "jio-ap.sh"} {
		if !strings.Contains(string(readFixture(t, "../../deploy", s)), hint) {
			t.Errorf("deploy/%s lacks the login lock hint", s)
		}
	}
}

// The Deco's hint follows ssh's own words for a refused or silent :22, and
// stays quiet on other failures.
func TestDeployLoginLockHintMatches(t *testing.T) {
	bash := bashPath(t)
	b := string(readFixture(t, "../../deploy", "deco-ap.sh"))
	fn := regexp.MustCompile(`(?ms)^login_lock_hint\(\) \{\n.*?^\}\n`).FindString(b)
	if fn == "" {
		t.Fatal("no login_lock_hint() in deploy/deco-ap.sh")
	}
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
