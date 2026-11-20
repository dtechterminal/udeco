// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/deco"
	"github.com/dtechterminal/udeco/internal/repotest"
)

// What surrounds the daemon and cannot read its code: the image
// (Dockerfile), the script that builds and runs it on the host
// (deploy/unraid.sh), the example config and the documents. The tests
// below read them and fail when one of them and the code stop agreeing.
const (
	dockerfile   = "Dockerfile"
	unraidScript = "deploy/unraid.sh"
	exampleFile  = "deploy/udeco.example.json"
	deployDoc    = "docs/deco/README.md"
	designDoc    = "docs/deco/design.md"
)

// jsonKeys are the JSON keys of the struct type ty, in field order; a
// nested struct's keys come as "outer.key", those of a list of structs as
// "outer[].key".
func jsonKeys(ty reflect.Type) []string {
	var out []string
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if tag == "" || tag == "-" {
			continue
		}
		switch ft := f.Type; {
		case ft.Kind() == reflect.Struct:
			for _, k := range jsonKeys(ft) {
				out = append(out, tag+"."+k)
			}
		case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct:
			for _, k := range jsonKeys(ft.Elem()) {
				out = append(out, tag+"[]."+k)
			}
		default:
			out = append(out, tag)
		}
	}
	return out
}

// jsonKey is the JSON key of Config's field.
func jsonKey(t *testing.T, field string) string {
	t.Helper()
	f, ok := reflect.TypeOf(Config{}).FieldByName(field)
	if !ok {
		t.Fatalf("Config has no field %s", field)
	}
	tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	return tag
}

// mdTable is the body of the Markdown table of text whose header row is
// header: a row each, its cells without the blanks around them.
func mdTable(t *testing.T, rel, text, header string) [][]string {
	t.Helper()
	_, rest, ok := strings.Cut(text, "\n"+header+"\n")
	if !ok {
		t.Fatalf("%s has no table headed %s", rel, header)
	}
	var rows [][]string
	for i, l := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(l, "|") {
			break
		}
		if i == 0 { // |---|---|
			continue
		}
		var cells []string
		for _, c := range strings.Split(strings.Trim(l, "|"), "|") {
			cells = append(cells, strings.TrimSpace(c))
		}
		rows = append(rows, cells)
	}
	if len(rows) == 0 {
		t.Fatalf("%s: the table headed %s has no rows", rel, header)
	}
	return rows
}

func minimalConfig(t *testing.T) *Config {
	t.Helper()
	c, err := parseConfig([]byte(`{"inform_url":"http://192.168.0.1:8080/inform","units":[{"ip":"192.168.0.241","mac":"b0:a7:b9:3e:16:94"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func exampleConfig(t *testing.T) *Config {
	t.Helper()
	c, err := loadConfig(filepath.Join(repotest.Root(t), filepath.FromSlash(exampleFile)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// trimDur writes a duration as a config or a document does: "15s", "10m".
func trimDur(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	return s
}

// The key table of docs/deco/README.md is the readers' list of the config:
// it has a row for every key of Config, MeshSection and UnitConfig and no
// row for anything else, and the defaults it gives are the code's.
func TestDocsConfigKeys(t *testing.T) {
	doc := repotest.Read(t, deployDoc)
	rows := map[string][]string{}
	var listed []string
	for _, r := range mdTable(t, deployDoc, doc, "| Key | Default | Meaning |") {
		if len(r) != 3 {
			t.Fatalf("%s: key table row %q does not have three cells", deployDoc, r)
		}
		key := strings.Trim(r[0], "`")
		if !strings.HasSuffix(key, "[]") {
			listed = append(listed, key)
			rows[key] = r
			continue
		}
		// a list's row names the keys of an entry in its Meaning cell
		for _, m := range regexp.MustCompile("`([a-z0-9_]+)`").FindAllStringSubmatch(r[2], -1) {
			listed = append(listed, key+"."+m[1])
			rows[key+"."+m[1]] = r
		}
	}
	keys := jsonKeys(reflect.TypeOf(Config{}))
	sort.Strings(keys)
	sort.Strings(listed)
	if strings.Join(listed, " ") != strings.Join(keys, " ") {
		t.Errorf("%s key table lists\n%q\nConfig has\n%q", deployDoc, listed, keys)
	}

	// defaults: what a config that leaves the key out ends up with
	c := minimalConfig(t)
	for key, want := range map[string]string{
		jsonKey(t, "Netmask"):         "`" + c.Netmask + "`",
		jsonKey(t, "Model"):           "`" + c.Model + "`",
		jsonKey(t, "WifiCaps"):        fmt.Sprint(c.WifiCaps),
		jsonKey(t, "Apply"):           fmt.Sprintf("`%v`", c.Apply),
		jsonKey(t, "ReportIP"):        "`" + c.ReportIP + "`",
		jsonKey(t, "OnRemove"):        "`" + c.OnRemove + "`",
		jsonKey(t, "KickEmulation"):   fmt.Sprintf("`%v`", c.KickEmulation),
		jsonKey(t, "HideWired"):       fmt.Sprintf("`%v`", c.HideWired),
		jsonKey(t, "NoClientList"):    fmt.Sprintf("`%v`", c.NoClientList),
		jsonKey(t, "Poll"):            "`" + trimDur(time.Duration(c.Poll)) + "`",
		jsonKey(t, "ClientsEvery"):    "`" + trimDur(deco.MinClientsEvery) + "`",
		jsonKey(t, "TPLinkID"):        "`" + envTPLinkEmail + "`",
		jsonKey(t, "CredentialsFile"): "`<state_dir>/" + credentialsFileName + "`",
	} {
		if r := rows[key]; r != nil && r[1] != want {
			t.Errorf("%s key table: `%s` defaults to %s, the code gives %s", deployDoc, key, r[1], want)
		}
	}
	if time.Duration(c.Poll) != deco.DefaultPoll {
		t.Errorf("poll defaults to %s, deco.DefaultPoll is %s", time.Duration(c.Poll), deco.DefaultPoll)
	}
	// and the bounds the Meaning cells give
	for key, want := range map[string]string{
		jsonKey(t, "Poll"):         fmt.Sprintf("(minimum %d s)", minPoll/time.Second),
		jsonKey(t, "ClientsEvery"): fmt.Sprintf("(minimum %d min)", deco.MinClientsEvery/time.Minute),
		"units[].sshd_port":        fmt.Sprintf("`sshd_port` (default %d + index)", defaultSSHDPort),
	} {
		if r := rows[key]; r != nil && !strings.Contains(r[2], want) {
			t.Errorf("%s key table: the row of `%s` does not say %s", deployDoc, key, want)
		}
	}
	if c.Units[0].SSHDPort != defaultSSHDPort {
		t.Errorf("the first unit's sshd_port defaults to %d, defaultSSHDPort is %d", c.Units[0].SSHDPort, defaultSSHDPort)
	}
	// below the minimum is an error that names it
	if _, err := parseConfig([]byte(`{"inform_url":"http://192.168.0.1:8080/inform","poll":"1s","units":[{"ip":"192.168.0.241","mac":"b0:a7:b9:3e:16:94"}]}`)); err == nil || err.Error() != "poll 1s is below 5s" {
		t.Errorf("poll 1s: %v", err)
	}
}

// deploy/udeco.example.json is the config of the site the documents
// describe. The README repeats its units as a table, names its master and
// its adoption ports, and the example writes the default poll out.
func TestDocsExampleConfig(t *testing.T) {
	c := exampleConfig(t)
	doc := repotest.Read(t, deployDoc)
	rows := mdTable(t, deployDoc, doc, "| Name | IP | MAC | `sshd_port` |")
	if len(rows) != len(c.Units) {
		t.Fatalf("%s lists %d units, %s has %d", deployDoc, len(rows), exampleFile, len(c.Units))
	}
	var ports []string
	for i, u := range c.Units {
		name := u.Name
		if i == c.masterIdx {
			name += " (master)"
		}
		want := []string{name, u.IP, u.MAC, fmt.Sprint(u.SSHDPort)}
		if !reflect.DeepEqual(rows[i], want) {
			t.Errorf("%s unit row %d: %q, %s has %q", deployDoc, i, rows[i], exampleFile, want)
		}
		ports = append(ports, fmt.Sprint(u.SSHDPort))
	}
	for _, p := range []string{
		"it only ever talks to the mesh master (" + c.master().IP + ")",
		"has its own SSH adoption port (" + strings.Join(ports, ", ") + ")",
		"on the Unraid host " + c.DaemonIP + " (`--network host`)",
		"| `daemon_ip` | local IP toward the controller | IP reported to the controller (" + c.DaemonIP + "). |",
	} {
		if !strings.Contains(doc, p) {
			t.Errorf("%s does not have %q (from %s)", deployDoc, p, exampleFile)
		}
	}
	if host := repotest.ShellVar(t, repotest.Read(t, unraidScript), "HOST"); host != "root@"+c.DaemonIP {
		t.Errorf("%s deploys to %s, the example's daemon_ip is %s", unraidScript, host, c.DaemonIP)
	}

	// the example writes these defaults out: they are the code's
	var raw struct {
		Poll  string `json:"poll"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal([]byte(repotest.Read(t, exampleFile)), &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Poll != trimDur(deco.DefaultPoll) {
		t.Errorf("%s: poll %q, the default is %s", exampleFile, raw.Poll, trimDur(deco.DefaultPoll))
	}
	if raw.Model != defaultModel {
		t.Errorf("%s: model %q, the default is %s", exampleFile, raw.Model, defaultModel)
	}
	// section 9 of the design sends the reader to the example and has no
	// config of its own
	design := repotest.Read(t, designDoc)
	if !strings.Contains(design, "(../../"+exampleFile+")") {
		t.Errorf("%s no longer links %s", designDoc, exampleFile)
	}
	if strings.Contains(design, `"inform_url":`) || strings.Contains(design, "docker run -d") {
		t.Errorf("%s has a config or a run command of its own again: the example config and %s hold them", designDoc, unraidScript)
	}
}

// -only's names: one per polled Get (pollNames), written out in the
// Mesh's poll order (onlyNames), and listed by the documents.
func TestOnlyNames(t *testing.T) {
	m, err := deco.NewMesh(deco.MeshConfig{MasterIP: "192.168.0.241", MasterMAC: "b0:a7:b9:3e:16:94", TPLinkID: "a@b.c", Password: "x", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, op := range m.PolledOps() {
		n, ok := pollNames[op]
		if !ok {
			t.Errorf("the Mesh polls 0x%04x, which has no -only name", op)
		}
		names = append(names, n)
	}
	if got := strings.Join(names, ","); got != onlyNames || len(names) != len(pollNames) {
		t.Errorf("onlyNames %q; the Mesh's polls, by pollNames (%d names), are %q", onlyNames, len(pollNames), got)
	}
	repotest.MustContain(t, deployDoc, "`-only` takes `"+onlyNames+"` or opcodes.")
	repotest.MustContain(t, designDoc, "(names: `"+onlyNames+"`)")
}

// The names the TP-Link credentials are found under are constants of
// config.go. The texts that name them read as before, and README section 2
// gives the same names and order as loadSecrets.
func TestCredentialNames(t *testing.T) {
	// texts, as they were when each wrote the names out
	_, err := parseConfig([]byte(`{"password":"x"}`))
	if want := `"password" is not read from the config: use TPLINK_PASSWORD_FILE, password_file or credentials.env`; err == nil || err.Error() != want {
		t.Errorf("password in the config: %v, want %s", err, want)
	}
	dir := t.TempDir()
	noEnv := func(string) string { return "" }
	_, err = loadSecrets(&Config{StateDir: dir}, noEnv, t.Logf)
	if want := "no TP-Link ID: set tplink_id, TPLINK_EMAIL or TPLINK_EMAIL in credentials.env"; err == nil || err.Error() != want {
		t.Errorf("no ID: %v, want %s", err, want)
	}
	_, err = newMesh(minimalConfig(t), Secrets{TPLinkID: "a@b.c"}, hooks{}, false)
	if want := "no TP-Link password: set TPLINK_PASSWORD_FILE, password_file or TPLINK_PASSWORD in credentials.env"; err == nil || err.Error() != want {
		t.Errorf("no password: %v, want %s", err, want)
	}
	envFile := filepath.Join(dir, credentialsFileName)
	if err := os.WriteFile(envFile, []byte("TPLINK_EMAIL=file@x.example\nTPLINK_PASSWORD=pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var warned []string
	s, err := loadSecrets(&Config{StateDir: dir, TPLinkID: "config@x.example"}, noEnv, func(f string, a ...any) { warned = append(warned, fmt.Sprintf(f, a...)) })
	if want := "tplink_id in the config differs from TPLINK_EMAIL in " + envFile + "; using the config's"; err != nil || s.Password != "pw" || len(warned) != 1 || warned[0] != want {
		t.Errorf("config and env file disagree: %v, warnings %q, want %s", err, warned, want)
	}

	// loadSecrets asks the environment for these names and no other
	var asked []string
	loadSecrets(&Config{StateDir: t.TempDir()}, func(k string) string { asked = append(asked, k); return "" }, t.Logf)
	want := []string{envTPLinkEmail, envTPLinkPassword, envTPLinkPasswordFile, envTPLinkPasswordFileAlt}
	sort.Strings(asked)
	sort.Strings(want)
	if strings.Join(asked, " ") != strings.Join(want, " ") {
		t.Errorf("loadSecrets asks the environment for %q, the constants are %q", asked, want)
	}

	// the config keys the texts and the README name are keys of Config
	idKey, pwKey, credKey, stateKey := jsonKey(t, "TPLinkID"), jsonKey(t, "PasswordFile"), jsonKey(t, "CredentialsFile"), jsonKey(t, "StateDir")
	if idKey != "tplink_id" || pwKey != "password_file" {
		t.Errorf("the error texts say tplink_id and password_file; the keys are %s and %s", idKey, pwKey)
	}
	tick := func(s string) string { return "`" + s + "`" }
	inContainer := path.Join(path.Dir(defaultConfigPath), credentialsFileName)
	for _, p := range []string{
		"| TP-Link ID | config " + tick(idKey) + ", " + tick("$"+envTPLinkEmail) + ", " + tick(envTPLinkEmail) + " in the env file |",
		"| Password | " + tick("$"+envTPLinkPassword) + ", then the file named by " + tick("$"+envTPLinkPasswordFile) + " (or " + tick("$"+envTPLinkPasswordFileAlt) +
			"), config " + tick(pwKey) + ", " + tick(envTPLinkPasswordFile) + " in the env file, then " + tick(envTPLinkPassword) + " in the env file |",
		"The env file is " + tick(credKey) + ", by default " + tick("<"+stateKey+">/"+credentialsFileName) + ", which is " + tick(inContainer) + " in the container:",
		"\n" + envTPLinkEmail + "=owner@example.com\n" + envTPLinkPassword + "='the TP-Link password'\n",
		tick(envTPLinkPassword) + " is removed from the environment at start.",
		"| " + tick(path.Base(defaultConfigPath)) + ", " + tick(credentialsFileName) + " | Config and credentials |",
	} {
		repotest.MustContain(t, deployDoc, p)
	}
}

// dockerfileLines are the instructions of the Dockerfile with the given
// name, each without the name.
func dockerfileLines(t *testing.T, instr string) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(repotest.Read(t, dockerfile), "\n") {
		if rest, ok := strings.CutPrefix(l, instr+" "); ok {
			out = append(out, strings.TrimSpace(rest))
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s has no %s", dockerfile, instr)
	}
	return out
}

// dockerfileList is the one instruction of that name, written as a JSON
// list (CMD ["-config", "/data/udeco.json"]).
func dockerfileList(t *testing.T, instr string) []string {
	t.Helper()
	lines := dockerfileLines(t, instr)
	var v []string
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &v) != nil || len(v) == 0 {
		t.Fatalf("%s: want one %s with a JSON list, got %q", dockerfile, instr, lines)
	}
	return v
}

// oneLine is a shell command as the shell reads it: continued lines
// joined, blanks collapsed.
func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\\\n", " ")), " ")
}

// The container's contract is written in the image (the user it runs as,
// its volume, the config its CMD names), in the daemon (-config's
// default), in deploy/unraid.sh (the same user, mount and config on the
// command lines it sends to the host) and in the README's docker run.
func TestContainerContract(t *testing.T) {
	script := repotest.Read(t, unraidScript)
	vars := map[string]string{}
	for _, n := range []string{"HOST", "APPDATA", "IMAGE", "NAME", "RUNAS", "CONFIG"} {
		vars[n] = repotest.ShellVar(t, script, n)
	}

	// the user
	if user := dockerfileLines(t, "USER"); len(user) != 1 || user[0] != vars["RUNAS"] {
		t.Errorf("%s: USER %q, %s runs the container as RUNAS=%s", dockerfile, user, unraidScript, vars["RUNAS"])
	}

	// the config: the image's CMD, the flag's default, the script's variable
	cmd := dockerfileList(t, "CMD")
	flags := repotest.FlagDefaults(t, "cmd/udeco/main.go")
	if len(cmd) != 2 || cmd[0] != "-config" || cmd[1] != defaultConfigPath {
		t.Errorf("%s: CMD %q, want -config %s (the flag's default)", dockerfile, cmd, defaultConfigPath)
	}
	if flags["config"] != "defaultConfigPath" {
		t.Errorf("-config defaults to %s in cmd/udeco/main.go, want the constant defaultConfigPath", flags["config"])
	}
	if vars["CONFIG"] != defaultConfigPath {
		t.Errorf("%s: CONFIG=%s, the daemon's default is %s", unraidScript, vars["CONFIG"], defaultConfigPath)
	}

	// the volume: where the config and the state are, and where the
	// script mounts the host's directory
	data := path.Dir(defaultConfigPath)
	if vol := dockerfileList(t, "VOLUME"); len(vol) != 1 || vol[0] != data {
		t.Errorf("%s: VOLUME %q, the config is in %s", dockerfile, vol, data)
	}
	if c := exampleConfig(t); c.StateDir != data {
		t.Errorf("%s: state_dir %s, the image's volume is %s", exampleFile, c.StateDir, data)
	}
	runs := regexp.MustCompile(`(?s)docker run .*?"\n`).FindAllString(script, -1)
	if len(runs) != 2 {
		t.Fatalf("%s: %d docker run commands found, want the one-shot and the daemon's", unraidScript, len(runs))
	}
	for _, r := range runs {
		for _, want := range []string{" --network host ", " --user $RUNAS ", " -v '$APPDATA:" + data + "' '$IMAGE' -config $CONFIG"} {
			if !strings.Contains(oneLine(r), want) {
				t.Errorf("%s: %q does not have %q", unraidScript, oneLine(r), want)
			}
		}
	}
	// on the host the config has the same name in $APPDATA
	if want := "[ ! -f '$APPDATA/" + path.Base(defaultConfigPath) + "' ]"; !strings.Contains(script, want) {
		t.Errorf("%s does not check for the config as %s", unraidScript, want)
	}

	// the README's docker run is the command the script sends for "run"
	sent := strings.ReplaceAll(repotest.Expand(oneLine(strings.TrimSuffix(runs[1], "\"\n")), vars), "'", "")
	doc := repotest.Read(t, deployDoc)
	shown := ""
	for i := 0; ; i++ {
		block, ok := repotest.Fenced(doc, "sh", i)
		if !ok {
			break
		}
		if strings.HasPrefix(block, "docker run ") {
			shown = oneLine(block)
		}
	}
	if shown != sent {
		t.Errorf("%s shows\n%s\n%s run sends\n%s", deployDoc, shown, unraidScript, sent)
	}
	for _, p := range []string{
		"(`UNRAID_HOST`, default `" + vars["HOST"] + "`) and builds `" + vars["IMAGE"] + "` there. The container runs as " + vars["RUNAS"] + " with `" + vars["APPDATA"] + "` mounted at `" + data + "`.",
		"Copy `" + exampleFile + "` to `" + vars["APPDATA"] + "/" + path.Base(defaultConfigPath) + "`.",
		"# " + vars["APPDATA"] + "/" + credentialsFileName + "  (chown " + vars["RUNAS"] + ", chmod 600)",
		"| `state_dir` | config file's directory | Where state lives (`" + data + "` in the container). |",
		"## State (`" + data + "`)",
	} {
		if !strings.Contains(doc, p) {
			t.Errorf("%s does not have %q", deployDoc, p)
		}
	}
	for _, p := range []string{"**Config** is JSON at `" + defaultConfigPath + "`.", "**Config `" + defaultConfigPath + "`.**", "the volume is `" + data + "`"} {
		repotest.MustContain(t, designDoc, p)
	}
}

// The build runs on the host, from a copy of the files deploy/unraid.sh
// sends: everything the Dockerfile copies into the image must be among
// them, and each must exist.
func TestBuildContextFiles(t *testing.T) {
	m := regexp.MustCompile(`(?m)^\tlocal files=\(([^)]*)\)$`).FindStringSubmatch(repotest.Read(t, unraidScript))
	if m == nil {
		t.Fatalf("%s: the list of files it sends was not found", unraidScript)
	}
	sent := map[string]bool{}
	for _, f := range strings.Fields(m[1]) {
		sent[f] = true
		if _, err := os.Stat(filepath.Join(repotest.Root(t), f)); err != nil {
			t.Errorf("%s sends %s: %v", unraidScript, f, err)
		}
	}
	if !sent[dockerfile] {
		t.Errorf("%s does not send the %s", unraidScript, dockerfile)
	}
	copied := 0
	for _, l := range dockerfileLines(t, "COPY") {
		w := strings.Fields(l)
		if strings.HasPrefix(w[0], "--from=") { // from the build stage, not from the context
			continue
		}
		for _, src := range w[:len(w)-1] {
			copied++
			if !sent[path.Clean(src)] {
				t.Errorf("%s copies %s, which %s does not send to the host", dockerfile, src, unraidScript)
			}
		}
	}
	if copied == 0 {
		t.Fatalf("%s: no COPY from the build context found", dockerfile)
	}
}

// The image is built with the Go release go.mod names.
func TestDockerfileGoVersion(t *testing.T) {
	gomod := regexp.MustCompile(`(?m)^go (\d+\.\d+)(?:\.\d+)?$`).FindStringSubmatch(repotest.Read(t, "go.mod"))
	if gomod == nil {
		t.Fatal("go.mod has no go line")
	}
	var tags []string
	for _, l := range dockerfileLines(t, "FROM") {
		if tag, ok := strings.CutPrefix(strings.Fields(l)[0], "golang:"); ok {
			tags = append(tags, tag)
		}
	}
	if len(tags) != 1 || tags[0] != gomod[1] {
		t.Errorf("%s builds with golang:%q, go.mod says go %s", dockerfile, tags, gomod[1])
	}
	// the design document leaves the number to go.mod
	if regexp.MustCompile(`golang[: ]\d`).MatchString(repotest.Read(t, designDoc)) {
		t.Errorf("%s names a Go version again", designDoc)
	}
}

// The daemon's own timers that the documents quote.
func TestDocsDaemonTimers(t *testing.T) {
	var h hooks
	h.fill()
	if h.printTimeout != defaultPrintTimeout {
		t.Errorf("hooks.fill gives -print %s, defaultPrintTimeout is %s", h.printTimeout, defaultPrintTimeout)
	}
	if got := repotest.FlagDefaults(t, "cmd/udeco/main.go")["print-timeout"]; got != "defaultPrintTimeout" {
		t.Errorf("-print-timeout defaults to %s in cmd/udeco/main.go, want the constant defaultPrintTimeout", got)
	}
	secs := func(d time.Duration) string {
		if d <= 0 || d%time.Second != 0 {
			t.Fatalf("%s is not a whole number of seconds: reword the documents and this test", d)
		}
		return fmt.Sprintf("%d s", d/time.Second)
	}
	for rel, phrases := range map[string][]string{
		deployDoc: {
			"Runners stop informing after the master session has been down for " + secs(h.masterDownMax) + ".",
			"`unit offline` (after " + secs(h.offlineGrace) + " grace)",
		},
		designDoc: {
			"After a " + secs(h.offlineGrace) + " grace period, the runner stops informing",
			"If the master session has been down for more than " + secs(h.masterDownMax) + ", all runners stop informing",
			"whatever `-print-timeout` (default " + secs(defaultPrintTimeout) + ") is",
		},
	} {
		for _, p := range phrases {
			repotest.MustContain(t, rel, p)
		}
	}
	// a list is current for three polls: the daemon asks internal/deco
	for poll, want := range map[time.Duration]time.Duration{
		0:                45 * time.Second, // no poll given: the default's
		deco.DefaultPoll: 45 * time.Second,
		5 * time.Second:  15 * time.Second,
		20 * time.Second: time.Minute,
	} {
		d := &daemon{cfg: &Config{Poll: Duration(poll)}}
		if got := d.maxAge(); got != want || deco.MaxAge(poll) != want {
			t.Errorf("poll %s: maxAge %s, deco.MaxAge %s, want %s", poll, got, deco.MaxAge(poll), want)
		}
	}
	if got := (&daemon{}).maxAge(); got != 45*time.Second {
		t.Errorf("maxAge without a config = %s, want 45s", got)
	}
}
