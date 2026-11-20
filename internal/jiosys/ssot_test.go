// SPDX-License-Identifier: GPL-2.0-or-later

package jiosys

import (
	"regexp"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/repotest"
	"github.com/dtechterminal/udeco/internal/unit"
)

const jioStart = "deploy/jio-start.sh"

// The Garage's supervisor (deploy/jio-start.sh) removes the login lock
// with the iptables of one directory, which it cannot ask this package
// for: its default is where the Manager looks first (binDirs), and the
// login lock's document names it.
func TestJioStartIptablesDir(t *testing.T) {
	got := repotest.ShellVar(t, repotest.Read(t, jioStart), "IPT")
	if got != binDirs[0] {
		t.Errorf("deploy/jio-start.sh takes iptables from %q by default, jiosys from %q first", got, binDirs[0])
	}
	doc := strings.Join(strings.Fields(repotest.Read(t, "docs/deco/features/login-lock.md")), " ")
	for _, want := range []string{
		"`UDECO_IPT` overrides the default `" + binDirs[0] + "`.",
		"with `" + binDirs[0] + "/iptables` and `ip6tables`.",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/deco/features/login-lock.md does not have %q", want)
		}
	}
}

// KeepOnly stops every process it does not list, and the supervisor and
// its gateway guard are sh processes: only the script's path in their
// arguments tells them from any other shell. The list has that path as
// the supervisor starts itself under its default directory.
func TestSupervisorIsKept(t *testing.T) {
	script := repotest.Read(t, jioStart)
	dir := repotest.ShellVar(t, script, "D")
	if dir != unit.JioDir {
		t.Fatalf("deploy/jio-start.sh installs in %q by default, unit.JioDir is %q", dir, unit.JioDir)
	}
	starts := regexp.MustCompile(`(?m)^\s*nohup (sh \$D/\S+(?: guard)?) `).FindAllStringSubmatch(script, -1)
	if len(starts) != 2 {
		t.Fatalf("deploy/jio-start.sh starts itself %d times, want the supervisor and the guard: %q", len(starts), starts)
	}
	guard := 0
	for _, m := range starts {
		argv := strings.Fields(repotest.Expand(m[1], map[string]string{"D": dir}))
		if argv[1] != unit.JioDir+"/"+unit.Launcher {
			t.Errorf("deploy/jio-start.sh starts %q, not its own %s", m[1], unit.Launcher)
		}
		if !keeps(argv, DefaultKeepOnly) {
			t.Errorf("DefaultKeepOnly would stop %q, which deploy/jio-start.sh starts as %q", argv, m[1])
		}
		if argv[len(argv)-1] == "guard" {
			guard++
		}
	}
	if guard != 1 {
		t.Errorf("want one of the two starts to be the guard: %q", starts)
	}
	// the agent it starts is kept by its name
	if !keeps([]string{unit.RAMDir + "/udeco-ap", "-config", unit.JioDir + "/" + unit.ConfigFile}, DefaultKeepOnly) {
		t.Error("DefaultKeepOnly would stop the agent")
	}
	// Known gap, left as it is: a supervisor installed elsewhere (UDECO_D)
	// is not in the list, and the agent passes this list as it is.
	if keeps([]string{"sh", "/somewhere/else/" + unit.Launcher}, DefaultKeepOnly) {
		t.Error("DefaultKeepOnly now keeps a supervisor outside unit.JioDir: say so above")
	}
}
