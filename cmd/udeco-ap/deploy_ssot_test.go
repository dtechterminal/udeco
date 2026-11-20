// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
	"github.com/antoniocosta/unifi-openwrt/internal/inform"
	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
	"github.com/antoniocosta/unifi-openwrt/internal/unit"
)

// Tests that hold the deploy scripts (deploy/*.sh) to each other, to the
// agent and to the documents. deploy/jio-start.sh and the launcher
// deploy/deco-ap.sh writes run on a unit and cannot read anything of this
// repository there, so what they share with the agent or with the scripts
// on the deploying machine (deploy/lib.sh) is written out in them and
// compared here. Nothing here reaches a unit.

const (
	decoDeploy = "deploy/deco-ap.sh"
	jioDeploy  = "deploy/jio-ap.sh"
	jioStart   = "deploy/jio-start.sh"
	unraidSh   = "deploy/unraid.sh"
	deployLib  = "deploy/lib.sh"
	sourceLib  = `. "$(dirname "$0")/lib.sh"` + "\n"
)

// scriptVars reads the named top-level variables of the script at rel, in
// the order given, each expanded with the ones before it. A script that
// sources deploy/lib.sh starts from the variables it gets there.
func scriptVars(t *testing.T, rel string, names ...string) map[string]string {
	t.Helper()
	text := repotest.Read(t, rel)
	vars := map[string]string{}
	if strings.Contains(text, sourceLib) {
		lib := repotest.Read(t, deployLib)
		for _, n := range []string{"SITE_GATEWAY", "WAIT_EXIT"} {
			vars[n] = repotest.ShellVar(t, lib, n)
		}
	}
	for _, n := range names {
		vars[n] = repotest.Expand(repotest.ShellVar(t, text, n), vars)
	}
	return vars
}

// The three scripts of the deploying machine read deploy/lib.sh before
// they change directory ($0 may be relative), and none keeps a copy of
// what it holds: the helpers, the agent's build command, the two values.
func TestDeployScriptsShareLib(t *testing.T) {
	lib := repotest.Read(t, deployLib)
	shared := []string{"header_text", "is_ipv4", "md5_local", "size_local", "kb_local", "build_agent"}
	for _, fn := range shared {
		repotest.ShellFunc(t, lib, fn) // fails when lib.sh has none
	}
	for _, rel := range []string{decoDeploy, jioDeploy, unraidSh} {
		text := repotest.Read(t, rel)
		src, cd := strings.Index(text, "\n"+sourceLib), strings.Index(text, "\ncd ")
		if src < 0 || cd < 0 || src > cd {
			t.Errorf("%s does not read lib.sh before its cd", rel)
		}
		for _, fn := range shared {
			if strings.Contains(text, "\n"+fn+"() {") {
				t.Errorf("%s defines %s itself; deploy/lib.sh has it", rel, fn)
			}
		}
		for _, v := range []string{"SITE_GATEWAY", "WAIT_EXIT"} {
			if strings.Contains(text, "\n"+v+"=") {
				t.Errorf("%s sets %s itself; deploy/lib.sh has it", rel, v)
			}
		}
		if strings.Contains(text, "go build") {
			t.Errorf("%s has a go build of its own; build_agent in deploy/lib.sh is the agent's build", rel)
		}
	}
	if n := strings.Count(lib, "go build "); n != 1 {
		t.Errorf("deploy/lib.sh has %d go build commands, want the agent's one", n)
	}
	// both builds go through it, each with its own target
	for rel, call := range map[string]string{
		decoDeploy: `build_agent "$OUT" GOARCH=arm GOARM=7` + "\n",
		jioDeploy:  `build_agent "$OUT" GOARCH=mipsle GOMIPS=softfloat` + "\n",
	} {
		if !strings.Contains(repotest.Read(t, rel), call) {
			t.Errorf("%s does not build with %q", rel, strings.TrimSpace(call))
		}
	}
	// the README sends a build by hand through the same command: a go
	// build typed there once lacked -buildid=, so its binary had another
	// md5 than the deploy's build of the same source
	readme := repotest.Read(t, "README.md")
	out := scriptVars(t, decoDeploy, "OUT")["OUT"]
	if want := "deploy/deco-ap.sh --build-only   # writes " + out + "\n"; !strings.Contains(readme, want) {
		t.Errorf("README.md does not build with %q", strings.TrimSpace(want))
	}
	for _, l := range strings.Split(readme, "\n") {
		if strings.Contains(l, "go build") && strings.Contains(l, "cmd/udeco-ap") {
			t.Errorf("README.md has its own build of the agent: %s", l)
		}
	}
}

// The README's Layout table names every file of deploy/ (it once had two
// of five).
func TestReadmeListsDeployFiles(t *testing.T) {
	row := ""
	for _, l := range strings.Split(repotest.Read(t, "README.md"), "\n") {
		if strings.HasPrefix(l, "| `deploy/` |") {
			row = l
		}
	}
	if row == "" {
		t.Fatal("README.md's Layout table has no deploy/ row")
	}
	ents, err := os.ReadDir(filepath.Join(repotest.Root(t), "deploy"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) < 6 {
		t.Fatalf("deploy/ has %d entries", len(ents))
	}
	for _, e := range ents {
		if !strings.Contains(row, "`"+e.Name()+"`") {
			t.Errorf("README.md's deploy/ row does not name %s", e.Name())
		}
	}
	for _, m := range regexp.MustCompile("`([a-z0-9.-]+\\.(?:sh|json))`").FindAllStringSubmatch(row, -1) {
		if !slices.ContainsFunc(ents, func(e os.DirEntry) bool { return e.Name() == m[1] }) {
			t.Errorf("README.md's deploy/ row names %s, which deploy/ does not have", m[1])
		}
	}
}

// WAIT_EXIT is how long the deploy scripts wait for a stopping agent, and
// the agent finishes the Wi-Fi job it is in before it exits: the wait
// covers one whole job and half a minute more.
func TestDeployWaitsForAJob(t *testing.T) {
	lib := repotest.Read(t, deployLib)
	n, err := strconv.Atoi(repotest.ShellVar(t, lib, "WAIT_EXIT"))
	if err != nil {
		t.Fatalf("WAIT_EXIT in deploy/lib.sh: %v", err)
	}
	if wait, min := time.Duration(n)*time.Second, defaultJobTimeout+30*time.Second; wait < min {
		t.Errorf("deploy/lib.sh WAIT_EXIT is %s; one Wi-Fi job may take %s, so the scripts must wait at least %s", wait, defaultJobTimeout, min)
	}
	var tm timing
	if tm.fill(); tm.jobTimeout != defaultJobTimeout {
		t.Errorf("timing.fill defaults jobTimeout to %s, not defaultJobTimeout (%s)", tm.jobTimeout, defaultJobTimeout)
	}
	if want := fmt.Sprintf("job is at most %d min (defaultJobTimeout", int(defaultJobTimeout/time.Minute)); !strings.Contains(flat(strings.ReplaceAll(lib, "\n# ", " ")), want) {
		t.Errorf("deploy/lib.sh's comment on WAIT_EXIT does not say %q", want)
	}
	// the Deco script sends the wait to the unit, the Garage one counts it
	// in its own loop: both with the variable
	deco := repotest.Read(t, decoDeploy)
	if want := `[ \$i -le $WAIT_EXIT ] || { echo "deco-ap: the agent did not exit within $WAIT_EXIT s; not killing it" >&2; exit 1; }`; !strings.Contains(deco, want) {
		t.Errorf("deploy/deco-ap.sh does not wait WAIT_EXIT for the old agent")
	}
	if jio := repotest.Read(t, jioDeploy); !strings.Contains(jio, "[ \\$i -le $((WAIT_EXIT + 30)) ]") {
		t.Errorf("deploy/jio-ap.sh does not wait WAIT_EXIT for the old agent")
	}
}

// SITE_GATEWAY (deploy/lib.sh) is the default controller of a new Deco
// config and the default host of the Garage download. The Garage guard
// pings the same address by default, and the example config of the
// off-device udeco names it; those two cannot read lib.sh.
func TestDeploySiteGateway(t *testing.T) {
	gw := repotest.ShellVar(t, repotest.Read(t, deployLib), "SITE_GATEWAY")
	deco := scriptVars(t, decoDeploy, "inform_url", "console_ip")
	if deco["console_ip"] != gw || inform.URLHost(deco["inform_url"]) != gw {
		t.Errorf("deploy/deco-ap.sh defaults to console %q and controller %q, SITE_GATEWAY is %q", deco["console_ip"], deco["inform_url"], gw)
	}
	if ucg := scriptVars(t, jioDeploy, "ucg")["ucg"]; ucg != gw {
		t.Errorf("deploy/jio-ap.sh serves from %q by default, SITE_GATEWAY is %q", ucg, gw)
	}
	if got := repotest.ShellFuncVar(t, repotest.Read(t, jioStart), "guard", "GW"); got != gw {
		t.Errorf("deploy/jio-start.sh's guard pings %q by default, SITE_GATEWAY in deploy/lib.sh is %q", got, gw)
	}
	var ex struct {
		InformURL string `json:"inform_url"`
		ConsoleIP string `json:"console_ip"`
		Gateway   string `json:"gateway"`
	}
	if err := json.Unmarshal([]byte(repotest.Read(t, "deploy/udeco.example.json")), &ex); err != nil {
		t.Fatal(err)
	}
	if ex.ConsoleIP != gw || ex.Gateway != gw || inform.URLHost(ex.InformURL) != gw {
		t.Errorf("deploy/udeco.example.json has console_ip %q, gateway %q, inform_url %q; SITE_GATEWAY in deploy/lib.sh is %q",
			ex.ConsoleIP, ex.Gateway, ex.InformURL, gw)
	}
}

// Each script's help is its whole leading comment block, however long it
// has grown: a range of line numbers typed into usage once cut the last
// line off deploy/unraid.sh's.
func TestDeployUsage(t *testing.T) {
	bash := bashPath(t)
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("no awk")
	}
	for _, c := range []struct {
		rel    string
		first  int // the header's first line the help prints
		args   []string
		stdout bool // where the help goes
	}{
		{decoDeploy, 3, []string{"--help"}, false},
		{jioDeploy, 3, []string{"--help"}, false},
		{unraidSh, 4, nil, true},
	} {
		text := repotest.Read(t, c.rel)
		// the header ends where the code starts
		end := strings.Index(text, "\nset -euo pipefail\n")
		if end < 0 {
			t.Fatalf("%s: no set -euo pipefail after the header", c.rel)
		}
		header := strings.Split(text[:end], "\n")
		last := strings.TrimPrefix(header[len(header)-1], "# ")
		cmd := exec.Command(bash, append([]string{filepath.Join(repotest.Root(t), filepath.FromSlash(c.rel))}, c.args...)...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 2 {
			t.Errorf("%s %v: %v, want exit status 2", c.rel, c.args, err)
		}
		help, other := stderr.String(), stdout.String()
		if c.stdout {
			help, other = other, help
		}
		if other != "" {
			t.Errorf("%s: besides the help: %q", c.rel, other)
		}
		if !strings.HasSuffix(help, "\n"+last+"\n") {
			t.Errorf("%s: the help does not end with the header's last line %q:\n%s", c.rel, last, help)
		}
		if want := repotest.Header(text, c.first); help != want {
			t.Errorf("%s: the help is not the header from line %d:\n%s\nwant:\n%s", c.rel, c.first, help, want)
		}
	}
}

// What a script's header says of a default is the value its variable
// starts with, and the header states no other default.
func TestDeployHeaderDefaults(t *testing.T) {
	stated := regexp.MustCompile(`\(default ([^;)]+)[;)]`)
	check := func(rel string, first int, defaults map[string]string, phrases ...string) {
		t.Helper()
		header := flat(repotest.Header(repotest.Read(t, rel), first))
		var got, want []string
		for _, m := range stated.FindAllStringSubmatch(header, -1) {
			got = append(got, m[1])
		}
		for name, v := range defaults {
			want = append(want, v)
			if !regexp.MustCompile(`\(default ` + regexp.QuoteMeta(v) + `[;)]`).MatchString(header) {
				t.Errorf("%s: the header does not give %s's default as %q", rel, name, v)
			}
		}
		sort.Strings(got)
		sort.Strings(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: the header states the defaults %q, the variables start as %q", rel, got, want)
		}
		for _, p := range phrases {
			if !strings.Contains(header, p) {
				t.Errorf("%s: the header does not have %q", rel, p)
			}
		}
	}

	deco := scriptVars(t, decoDeploy, "ALLOWED_HOST", "KEY", "inform_url", "console_ip", "GZ_ABOVE", "MIN_FREE_KB")
	// GZ_ABOVE is bytes, written as a shift; MIN_FREE_KB is kB
	m := regexp.MustCompile(`^\$\(\((\d+) << 20\)\)$`).FindStringSubmatch(deco["GZ_ABOVE"])
	if m == nil {
		t.Fatalf("deploy/deco-ap.sh GZ_ABOVE is %q, no longer a number of MiB written $((N << 20))", deco["GZ_ABOVE"])
	}
	freeKB, err := strconv.Atoi(deco["MIN_FREE_KB"])
	if err != nil || freeKB%1024 != 0 {
		t.Fatalf("deploy/deco-ap.sh MIN_FREE_KB is %q, not whole MiB", deco["MIN_FREE_KB"])
	}
	check(decoDeploy, 3, map[string]string{
		"inform_url": deco["inform_url"],
		"console_ip": deco["console_ip"],
		"KEY":        strings.Replace(deco["KEY"], "$HOME", "~", 1),
	},
		"allow a unit other than "+deco["ALLOWED_HOST"]+" (",
		"Above "+m[1]+" MiB it also makes a gzip -9 copy",
		"At or below "+m[1]+" MiB the plain binary ships",
		fmt.Sprintf("/tp_data keeps at least %d MiB free after the install", freeKB/1024),
	)

	jio := scriptVars(t, jioDeploy, "ALLOWED_HOST", "host", "ucg", "port")
	check(jioDeploy, 3, map[string]string{"host": jio["host"], "ucg": jio["ucg"], "port": jio["port"]},
		"allow a unit other than "+jio["ALLOWED_HOST"])

	unraid := scriptVars(t, unraidSh, "HOST", "APPDATA", "SRC", "IMAGE")
	check(unraidSh, 4, map[string]string{"HOST": unraid["HOST"], "APPDATA": unraid["APPDATA"], "SRC": unraid["SRC"]},
		"UNRAID_HOST (default ", "APPDATA (default ", "UDECO_SRC (default ", "build "+unraid["IMAGE"]+" there")
}

// namesUnder lists the file names the script text uses under the directory
// variable ref ("$DIR"), sorted. Comment lines are not read.
func namesUnder(text, ref string) []string {
	re := regexp.MustCompile(regexp.QuoteMeta(ref) + `/([A-Za-z0-9_.-]+)`)
	seen := map[string]bool{}
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(l, -1) {
			seen[strings.TrimRight(m[1], ".")] = true
		}
	}
	var out []string
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// The directories and file names of an install are written in the three
// scripts and in internal/unit: the agent's own defaults come from there,
// and the scripts must name the same places.
func TestUnitLayout(t *testing.T) {
	deco := scriptVars(t, decoDeploy, "DIR", "BIN", "GZ", "SUM", "START", "RAMDIR", "CFG")
	jio := scriptVars(t, jioDeploy, "DIR", "GZ", "RAM")
	start := scriptVars(t, jioStart, "D", "R")
	for _, c := range []struct{ what, got, want string }{
		{"deploy/deco-ap.sh DIR", deco["DIR"], unit.DecoDir},
		{"deploy/deco-ap.sh RAMDIR", deco["RAMDIR"], unit.RAMDir},
		{"deploy/deco-ap.sh CFG", deco["CFG"], DefaultConfigPath},
		{"deploy/deco-ap.sh START", deco["START"], unit.DecoDir + "/" + unit.Launcher},
		{"deploy/jio-ap.sh DIR", jio["DIR"], unit.JioDir},
		{"deploy/jio-ap.sh RAM", jio["RAM"], unit.RAMDir},
		{"deploy/jio-start.sh D", start["D"], unit.JioDir},
		{"deploy/jio-start.sh R", start["R"], unit.RAMDir},
	} {
		if c.got != c.want {
			t.Errorf("%s is %q, internal/unit (and so the agent) has %q", c.what, c.got, c.want)
		}
	}
	if DefaultConfigPath != unit.DecoDir+"/"+unit.ConfigFile {
		t.Errorf("DefaultConfigPath %q", DefaultConfigPath)
	}
	// the agent's run directory is not the launcher's: the launcher's
	// holds the unpacked agent and must not be where the agent writes
	if unit.RunDir == unit.RAMDir {
		t.Errorf("unit.RunDir and unit.RAMDir are both %q", unit.RunDir)
	}

	// the Garage's two scripts work on the same files: what the deploy
	// reads or writes on the unit is what the supervisor there handles
	js, ss := repotest.Read(t, jioDeploy), repotest.Read(t, jioStart)
	gz := strings.TrimPrefix(jio["GZ"], jio["DIR"]+"/")
	flash := namesUnder(js, "$DIR")
	for _, m := range regexp.MustCompile(`\$GZ((?:\.[a-z]+)?)`).FindAllStringSubmatch(js, -1) {
		if n := gz + m[1]; !slices.Contains(flash, n) {
			flash = append(flash, n)
		}
	}
	// the deploy's own download, renamed into place before it counts
	own := []string{gz + ".new"}
	onFlash, inRAM := namesUnder(ss, "$D"), namesUnder(ss, "$R")
	if len(flash) < 5 || len(onFlash) < 5 || len(inRAM) < 3 {
		t.Fatalf("file names read: deploy/jio-ap.sh %q, deploy/jio-start.sh %q and %q", flash, onFlash, inRAM)
	}
	for _, n := range flash {
		if !slices.Contains(onFlash, n) && !slices.Contains(own, n) {
			t.Errorf("deploy/jio-ap.sh uses $DIR/%s, which deploy/jio-start.sh has no $D/%s for", n, n)
		}
	}
	for _, n := range own {
		if !slices.Contains(flash, n) {
			t.Errorf("deploy/jio-ap.sh no longer uses $DIR/%s", n)
		}
	}
	for _, n := range namesUnder(js, "$RAM") {
		if !slices.Contains(inRAM, n) {
			t.Errorf("deploy/jio-ap.sh uses $RAM/%s, which deploy/jio-start.sh has no $R/%s for", n, n)
		}
	}
	for _, n := range []string{unit.ConfigFile, unit.Launcher} {
		if !slices.Contains(onFlash, n) || !slices.Contains(flash, n) {
			t.Errorf("the Garage scripts do not both use %s in the install directory", n)
		}
	}
	// the supervisor starts the agent with the config next to it, and the
	// deploy looks for the supervisor as it starts itself
	if want := "$R/udeco-ap -config $D/" + unit.ConfigFile + " "; !strings.Contains(ss, want) {
		t.Errorf("deploy/jio-start.sh does not start the agent with %q", want)
	}
	if want := "grep -q '[s]h $DIR/" + unit.Launcher + "'"; !strings.Contains(js, want) || !strings.Contains(ss, "nohup sh $D/"+unit.Launcher+" ") {
		t.Errorf("deploy/jio-ap.sh does not look for the supervisor as deploy/jio-start.sh starts itself (%s)", want)
	}
}

// The single-instance lock has one name: the documents that name the file
// name the agent's (the audit's requirement once said udeco-ap.lock).
func TestDocsLockName(t *testing.T) {
	lock := "`" + unit.RunDir + "/" + lockName + "`"
	repotest.MustContain(t, "docs/deco/agent-design.md", "on "+lock)
	repotest.MustContain(t, "docs/deco/interference-audit.md", "on "+lock)
	other := regexp.MustCompile(regexp.QuoteMeta(unit.RunDir) + `/[A-Za-z0-9_.-]*\.lock`)
	for _, rel := range repotest.Markdown(t) {
		for _, m := range other.FindAllString(repotest.Read(t, rel), -1) {
			if m != unit.RunDir+"/"+lockName {
				t.Errorf("%s names the lock %s; the agent's is %s", rel, m, unit.RunDir+"/"+lockName)
			}
		}
	}
}

// unlockLoop is a launcher's removal of the login lock: the loop over the
// two iptables in text, from its "for T in" line to its "done", without
// the indentation of the first line.
func unlockLoop(t *testing.T, what, text string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		body := strings.TrimLeft(l, "\t")
		if !strings.HasPrefix(body, "for T in ") {
			continue
		}
		indent := l[:len(l)-len(body)]
		for j := i + 1; j < len(lines); j++ {
			if lines[j] == indent+"done" {
				out := lines[i : j+1]
				for k := range out {
					out[k] = strings.TrimPrefix(out[k], indent)
				}
				return strings.Join(out, "\n")
			}
		}
	}
	t.Fatalf("%s: no loop that removes the login lock", what)
	return ""
}

// The two launchers are separate files on two platforms, and each does the
// same two things in its own words: it removes the login lock before a
// start, and it caps the agent's RAM log. The README and the login lock's
// document quote them.
func TestLaunchersAgree(t *testing.T) {
	deco := launcher(t, "")
	garage := repotest.Read(t, jioStart)

	// the log cap and what is kept of the log
	capRe := regexp.MustCompile(`-gt (\d+) \]; then\n\t*tail -c (\d+) `)
	d, g := capRe.FindAllStringSubmatch(deco, -1), capRe.FindAllStringSubmatch(garage, -1)
	if len(d) != 1 || len(g) != 1 {
		t.Fatalf("log caps found: the Deco launcher %q, deploy/jio-start.sh %q", d, g)
	}
	if d[0][1] != g[0][1] || d[0][2] != g[0][2] {
		t.Errorf("the Deco launcher caps the log at %s (keeps %s), deploy/jio-start.sh at %s (keeps %s)", d[0][1], d[0][2], g[0][1], g[0][2])
	}
	capBytes, _ := strconv.Atoi(d[0][1])
	if capBytes == 0 || capBytes%(1<<20) != 0 {
		t.Fatalf("log cap %s is not whole MiB", d[0][1])
	}
	mb := fmt.Sprintf("%d MB", capBytes>>20)
	if want := "`" + unit.RAMDir + "/agent.log` (RAM, capped at " + mb + ")"; !strings.Contains(flat(repotest.Read(t, "README.md")), want) {
		t.Errorf("README.md does not have %q", want)
	}
	for what, text := range map[string]string{"the Deco launcher": deco, "deploy/jio-start.sh": garage} {
		if !strings.Contains(text, "under "+mb+" (the agent") {
			t.Errorf("%s: its comment on the log cap does not say %s", what, mb)
		}
	}

	// the unlock: the same lines, the Deco's with -w (its iptables has the
	// lock wait), the Garage's with the directory of Jio's iptables
	dl := unlockLoop(t, "the Deco launcher", deco)
	gl := unlockLoop(t, "deploy/jio-start.sh unlock()", repotest.ShellFunc(t, garage, "unlock"))
	if a, b := strings.ReplaceAll(dl, "$T -w -", "$T -"), strings.ReplaceAll(gl, "$IPT/", ""); a != b {
		t.Errorf("the launchers remove the login lock differently:\n%s\nand:\n%s", dl, gl)
	}
	if n := strings.Count(dl, decosys.LockChain); n != 3 {
		t.Errorf("the Deco launcher names the chain %s %d times, want 3:\n%s", decosys.LockChain, n, dl)
	}
	// the document shows the Deco's lines
	doc := repotest.Read(t, "docs/deco/features/login-lock.md")
	shown := ""
	for n := 0; ; n++ {
		body, ok := repotest.Fenced(doc, "sh", n)
		if !ok {
			break
		}
		if strings.Contains(body, decosys.LockChain) {
			shown = body
			break
		}
	}
	if shown != dl {
		t.Errorf("docs/deco/features/login-lock.md shows the unlock as:\n%s\nthe launcher in deploy/deco-ap.sh has:\n%s", shown, dl)
	}
}

// The launcher logs under the agent's own syslog tag only: deploy/deco-ap.sh
// holds it once (TAG, decosys.SyslogTag), every logger line of the
// launcher uses it, and the deploy shows the agent's first lines by it. A
// filter on the tag sees the launcher's "starting udeco-ap" line with the
// agent's.
func TestDeployLauncherTags(t *testing.T) {
	if tag := scriptVars(t, decoDeploy, "TAG")["TAG"]; tag != decosys.SyslogTag {
		t.Errorf("deploy/deco-ap.sh TAG=%s, want decosys.SyslogTag %s", tag, decosys.SyslogTag)
	}
	text := launcher(t, "")
	tags := regexp.MustCompile(`logger -t (\S+) `).FindAllStringSubmatch(text, -1)
	if len(tags) == 0 || len(tags) != strings.Count(text, "logger") {
		t.Fatalf("the launcher has %d logger lines with a tag, %d mentions of logger:\n%s", len(tags), strings.Count(text, "logger"), text)
	}
	for _, m := range tags {
		if m[1] != decosys.SyslogTag {
			t.Errorf("the launcher logs with the tag %q, want decosys.SyslogTag %q", m[1], decosys.SyslogTag)
		}
	}
	if !strings.Contains(text, `logger -t `+decosys.SyslogTag+` "starting udeco-ap"`) {
		t.Errorf("the launcher no longer logs its start under %s:\n%s", decosys.SyslogTag, text)
	}
	// every logger and logread filter of the script names the tag by $TAG
	script := repotest.Read(t, decoDeploy)
	for _, l := range strings.Split(script, "\n") {
		if (strings.Contains(l, "logger -t ") || strings.Contains(l, "logread")) && !strings.Contains(l, "$TAG") {
			t.Errorf("deploy/deco-ap.sh names a syslog tag other than by $TAG:\n%s", l)
		}
	}
	if want := "logread 2>/dev/null | grep '$TAG' | tail"; !strings.Contains(script, want) {
		t.Errorf("deploy/deco-ap.sh no longer has %q", want)
	}
}

// The persist file's supervise line is deploy/deco-ap.sh's LINE: the
// design document quotes it whole, no document shows another way to run
// the launcher from there, and the rollback the script prints deletes
// exactly that line.
func TestDeploySuperviseLine(t *testing.T) {
	script := repotest.Read(t, decoDeploy)
	vars := scriptVars(t, decoDeploy, "DIR", "START", "PERSIST", "MARK", "LINE")
	line := vars["LINE"]
	if !strings.HasPrefix(line, "[ -f "+vars["START"]+" ] && sh "+vars["START"]+" ") || !strings.HasSuffix(line, " "+vars["MARK"]) || strings.Contains(line, "$") {
		t.Fatalf("supervise line %q", line)
	}
	if !strings.Contains(repotest.Read(t, "docs/deco/agent-design.md"), "\n`"+line+"`,\n") {
		t.Errorf("docs/deco/agent-design.md does not quote the supervise line of deploy/deco-ap.sh:\n%s", line)
	}
	for _, rel := range repotest.Markdown(t) {
		for _, l := range strings.Split(repotest.Read(t, rel), "\n") {
			if strings.Contains(l, "sh "+vars["START"]) && !strings.Contains(l, line) {
				t.Errorf("%s runs the launcher with a line that is not the script's (the script would not find it by its marker):\n%s", rel, l)
			}
		}
	}

	// the rollback, built as the script builds it
	i, j := strings.Index(script, "\nmark_re="), strings.Index(script, "\nif [ \"$no_start\" = 1 ]; then\n")
	if i < 0 || j < i || !strings.Contains(script[i:j], "\nrollback=") {
		t.Fatal("deploy/deco-ap.sh no longer builds its rollback from $MARK")
	}
	out, err := exec.Command(bashPath(t), "-c", `MARK=$1 PERSIST=$2 START=$3 KEY=key ip=192.0.2.1`+script[i:j]+"\n"+`printf %s "$rollback"`,
		"x", vars["MARK"], vars["PERSIST"], vars["START"]).Output()
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`^ssh -i key root@192\.0\.2\.1 "sed -i '(/.+/d)' ` + regexp.QuoteMeta(vars["PERSIST"]) + `; rm -f ` + regexp.QuoteMeta(vars["START"]) + `; `).FindSubmatch(out)
	if m == nil {
		t.Fatalf("rollback: %s", out)
	}
	if !strings.Contains(strings.ReplaceAll(string(m[1]), `\/`, "/"), strings.TrimPrefix(vars["MARK"], "# ")) {
		t.Errorf("the rollback's sed %s does not have the marker %q", m[1], vars["MARK"])
	}
	sed, err := exec.LookPath("sed")
	if err != nil {
		t.Skip("no sed")
	}
	others := "#!/bin/sh\n/data/dropbear -p 22 # udeco-ap is not on this line's mind\n[ -f /data/other.sh ] && sh /data/other.sh & # supervise something else\nexit 0\n"
	persist := filepath.Join(t.TempDir(), "persist_shell.sh")
	if err := os.WriteFile(persist, []byte(strings.Replace(others, "exit 0\n", line+"\nexit 0\n", 1)), 0o755); err != nil {
		t.Fatal(err)
	}
	left, err := exec.Command(sed, "-e", string(m[1]), persist).Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != others {
		t.Errorf("the rollback's sed %s leaves:\n%s\nwant the file without the supervise line:\n%s", m[1], left, others)
	}
}
