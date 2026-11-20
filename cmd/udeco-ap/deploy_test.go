// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/repotest"
	"github.com/dtechterminal/udeco/internal/unit"
)

// deploy/deco-ap.sh, judged without a device: --preflight-file feeds the
// verdict a saved answer of the unit's read-only probe.

// pf205 is .205's real preflight answer (2026-11-19, read-only probe):
// the persist file's guard greps for what it appends, the crontab has the
// line, the firewall include is there.
const pf205 = `ARCH armv7l
TPDATA 1
PERSIST 1
CRON * * * * * sh /data/persist_shell.sh
GUARD grep -q '/data/persist_shell' /etc/crontabs/root 2>/dev/null || {
GUARD     echo '* * * * * sh /data/persist_shell.sh' >> /etc/crontabs/root
EXIT 0
INCLUDE /etc/firewall.user
INCLUDE /usr/share/miniupnpd/firewall.include
INCLUDE /data/persist_shell.sh
AVAIL 11108
MAC b0:a7:b9:3e:17:00
RUNNING 0
OLD none - 0
`

func bashPath(t *testing.T) string {
	t.Helper()
	b, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	return b
}

func judge(t *testing.T, answer string, newKB int, args ...string) (string, bool) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "pf.txt")
	if err := os.WriteFile(f, []byte(answer), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bashPath(t), append([]string{"../../deploy/deco-ap.sh", "--preflight-file", f}, args...)...)
	cmd.Env = append(os.Environ(), "PREFLIGHT_NEW_KB="+strconv.Itoa(newKB))
	out, err := cmd.CombinedOutput()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatal(err)
		}
	}
	return string(out), err == nil
}

func TestDeployPreflight(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "udeco.json")
	os.WriteFile(cfg, []byte(`{"units":[{"ip":"192.168.0.205","mac":"B0:A7:B9:3E:17:00"}]}`), 0o600)
	other := filepath.Join(t.TempDir(), "udeco.json")
	os.WriteFile(other, []byte(`{"units":[{"ip":"192.168.0.241","mac":"b0:a7:b9:00:00:01"}]}`), 0o600)
	for _, c := range []struct {
		name, answer string
		newKB        int
		args         []string
		ok           bool
		want         string
	}{
		{"205 as it is", pf205, 3016, nil, true, "preflight OK"},
		{".241's guard", strings.Replace(pf205, "grep -q '/data/persist_shell'", "grep -q '/data/dropbear'", 1), 3016, nil, false,
			"guards with grep '/data/dropbear' but appends"},
		{"one-line guard (.241 shape) that matches", strings.Replace(pf205,
			"GUARD grep -q '/data/persist_shell' /etc/crontabs/root 2>/dev/null || {\nGUARD     echo",
			"GUARD grep -q '/data/persist_shell' /etc/crontabs/root || echo", 1), 3016, nil, true, "preflight OK"},
		{"no cron line", strings.Replace(pf205, "CRON * * * * * sh /data/persist_shell.sh\n", "", 1), 3016, nil, false,
			"has no line running /data/persist_shell.sh"},
		{"commented cron line", strings.Replace(pf205, "CRON * * *", "CRON #* * *", 1), 3016, nil, false, "has no line running"},
		{"no re-add", strings.Replace(pf205, "GUARD     echo '* * * * * sh /data/persist_shell.sh' >> /etc/crontabs/root\n", "", 1), 3016, nil, false,
			"does not re-add its cron line"},
		{"unguarded append", strings.Replace(pf205, "GUARD grep -q '/data/persist_shell' /etc/crontabs/root 2>/dev/null || {\n", "", 1), 3016, nil, false,
			"without a grep guard"},
		{"no firewall include", strings.Replace(pf205, "INCLUDE /data/persist_shell.sh\n", "", 1), 3016, nil, false,
			"no firewall include"},
		{"1 MiB must stay free", strings.Replace(pf205, "AVAIL 11108", "AVAIL 4000", 1), 3016, nil, false, "would keep 984 kB free"},
		{"the old agent's space counts", strings.Replace(strings.Replace(pf205, "AVAIL 11108", "AVAIL 4000", 1), "OLD none - 0", "OLD bin 0123 7428", 1), 3016, nil, true, "preflight OK"},
		{"not armv7", strings.Replace(pf205, "ARCH armv7l", "ARCH mips", 1), 3016, nil, false, "not armv7"},
		{"no persist file", strings.Replace(pf205, "PERSIST 1", "PERSIST 0", 1), 3016, nil, false, "no /data/persist_shell.sh"},
		{"udeco models the MAC: warn only", pf205, 3016, []string{"--udeco-config", cfg}, true, "WARNING: " + cfg + " lists b0:a7:b9:3e:17:00"},
		{"udeco models other units", pf205, 3016, []string{"--udeco-config", other}, true, "preflight OK"},
	} {
		out, ok := judge(t, c.answer, c.newKB, c.args...)
		if ok != c.ok || !strings.Contains(out, c.want) {
			t.Errorf("%s: ok=%v, output:\n%s", c.name, ok, out)
		}
		if c.name == "udeco models other units" && strings.Contains(out, "WARNING") {
			t.Errorf("%s: warned:\n%s", c.name, out)
		}
	}
}

// The script changes /data/persist_shell.sh only under --edit-persist; by
// default it prints the one line to approve.
func TestDeployPersistOnlyWithFlag(t *testing.T) {
	b := repotest.Read(t, decoDeploy)
	i := strings.Index(b, `elif [ "$edit_persist" = 1 ]; then`)
	j := strings.Index(b[i:], "\nelse\n")
	if i < 0 || j < 0 {
		t.Fatal("no --edit-persist branch")
	}
	branch, rest := b[i:i+j], b[:i]+b[i+j:]
	if !strings.Contains(branch, `mv "\$T" "\$P"`) {
		t.Error("the --edit-persist branch does not write the file")
	}
	for _, w := range []string{`"\$P"`, "$PERSIST\n", ">>$PERSIST", "> $PERSIST", ">$PERSIST"} {
		for _, l := range strings.Split(rest, "\n") {
			if strings.Contains(l, w) && (strings.Contains(l, "mv ") || strings.Contains(l, ">")) && !strings.Contains(l, "rollback=") {
				t.Errorf("writes the persist file outside --edit-persist: %s", l)
			}
		}
	}
	// the line itself, the documents that quote it and the rollback that
	// deletes it: TestDeploySuperviseLine
	if !strings.Contains(b[i+j:], `echo "$LINE"`) {
		t.Error("the default branch does not print the line to approve")
	}
}

// launcher renders the start.sh deploy/deco-ap.sh writes on a unit (its
// LAUNCH template, as the shell expands it), with the unit's paths, which
// are the script's own, moved under root ("" for the unit's). The tests
// that run it find its files under root by internal/unit's names;
// TestUnitLayout holds the script's paths to those.
func launcher(t *testing.T, root string) string {
	t.Helper()
	paths := scriptVars(t, decoDeploy, "DIR", "BIN", "GZ", "SUM", "START", "RAMDIR", "CFG", "TAG")
	under := map[string]string{"TAG": paths["TAG"]} // the syslog tag, not a path
	for _, n := range []string{"DIR", "BIN", "GZ", "SUM", "START", "RAMDIR", "CFG"} {
		under[n] = root + paths[n]
	}
	text, unknown := repotest.HeredocText(repotest.Heredoc(t, repotest.Read(t, decoDeploy), "LAUNCH"), under)
	if len(unknown) != 0 {
		t.Fatalf("the launcher uses %q, which are not variables of deploy/deco-ap.sh this test knows:\n%s", unknown, text)
	}
	return text + "\n"
}

// The launcher unpacks a gzip-shipped agent to ramfs, checks it against
// the deployed md5, reuses a good unpacked copy, refuses a bad one, starts
// a plain binary as it is, and does nothing while an agent runs.
func TestDeployLauncher(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	root := t.TempDir()
	dir := filepath.Join(root, unit.DecoDir)
	ram := filepath.Join(root, unit.RAMDir)
	bin := filepath.Join(root, "bin")
	for _, d := range []string{dir, filepath.Dir(ram), bin} {
		os.MkdirAll(d, 0o755)
	}
	// fake pidof (FAKE_RUNNING=1: an agent runs) and, where the host has
	// none, md5sum
	os.WriteFile(filepath.Join(bin, "pidof"), []byte("#!/bin/sh\n[ \"$FAKE_RUNNING\" = 1 ] && echo 42\n"), 0o755)
	fakeIptables(t, bin, filepath.Join(root, "iptables.log")) // the login lock's removal never reaches the host's firewall
	if _, err := exec.LookPath("md5sum"); err != nil {
		os.WriteFile(filepath.Join(bin, "md5sum"), []byte("#!/bin/sh\nh=$(md5 -q \"$1\" 2>/dev/null) || exit 1\necho \"$h  $1\"\n"), 0o755)
	}
	marker := filepath.Join(root, "started")
	agent := []byte("#!/bin/sh\necho \"$0 $*\" >" + marker + "\necho agent-stdout $$\n")
	sum := md5.Sum(agent)
	writeGz := func(b []byte) {
		f, _ := os.Create(filepath.Join(dir, "udeco-ap.gz"))
		z := gzip.NewWriter(f)
		z.Write(b)
		z.Close()
		f.Close()
	}
	script := filepath.Join(root, "start.sh")
	os.WriteFile(script, []byte(launcher(t, root)), 0o755)
	run := func(running bool) (string, bool) {
		os.Remove(marker)
		cmd := exec.Command(sh, script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "FAKE_RUNNING="+map[bool]string{true: "1", false: "0"}[running])
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("launcher: %v %s", err, out)
		}
		m, _ := os.ReadFile(marker)
		return string(m), err == nil
	}

	// gzip-shipped, good md5: unpacked to ramfs and started from there
	writeGz(agent)
	os.WriteFile(filepath.Join(dir, "udeco-ap.md5"), []byte(hex.EncodeToString(sum[:])+"\n"), 0o644)
	got, _ := run(false)
	if want := filepath.Join(ram, "udeco-ap") + " -config " + filepath.Join(dir, "udeco-ap.json"); strings.TrimSpace(got) != want {
		t.Fatalf("started %q, want %q", got, want)
	}
	if b, _ := os.ReadFile(filepath.Join(ram, "udeco-ap")); string(b) != string(agent) {
		t.Fatal("unpacked agent differs")
	}
	// its output goes to the RAM log, and agent.pid is the agent's own pid
	// (the launcher execs it)
	logb, _ := os.ReadFile(filepath.Join(ram, "agent.log"))
	pidb, _ := os.ReadFile(filepath.Join(ram, "agent.pid"))
	if pid := strings.TrimSpace(string(pidb)); pid == "" || strings.TrimSpace(string(logb)) != "agent-stdout "+pid {
		t.Errorf("agent.log %q, agent.pid %q", logb, pidb)
	}
	// an agent runs: nothing happens
	if got, _ := run(true); got != "" {
		t.Errorf("started while an agent runs: %q", got)
	}
	// the unpacked copy is good: reused, the archive not read again
	writeGz([]byte("#!/bin/sh\necho other >" + marker + "\n"))
	if got, _ := run(false); !strings.HasPrefix(got, filepath.Join(ram, "udeco-ap")) {
		t.Errorf("good unpacked copy not reused: %q", got)
	}
	// the deployed md5 does not match what the archive holds: not started,
	// nothing left behind
	os.Remove(filepath.Join(ram, "udeco-ap"))
	if got, ok := run(false); got != "" || ok {
		t.Errorf("a bad archive started: %q ok=%v", got, ok)
	}
	ents, _ := os.ReadDir(ram)
	for _, e := range ents {
		if n := e.Name(); n != "agent.log" && n != "agent.pid" {
			t.Errorf("left in ramfs: %s", n)
		}
	}
	// plain binary (at or below 6 MiB): started where it is
	os.Remove(filepath.Join(dir, "udeco-ap.gz"))
	os.WriteFile(filepath.Join(dir, "udeco-ap"), agent, 0o755)
	if got, _ := run(false); !strings.HasPrefix(got, filepath.Join(dir, "udeco-ap")+" -config") {
		t.Errorf("plain binary: %q", got)
	}
}
