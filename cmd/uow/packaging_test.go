// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"
	"io/fs"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/openwrt"
	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// The OpenWrt package: files that run on the AP or in the OpenWrt SDK,
// come from upstream and cannot read the Go code or each other. Each must
// stay complete by itself, so the tests below read them and fail when two
// of them, or one of them and this daemon, stop agreeing.
const (
	uciFile      = "packaging/files/etc/config/unifi-openwrt"
	initFile     = "packaging/files/etc/init.d/unifi-openwrt"
	installFile  = "packaging/install.sh"
	makefileFile = "packaging/openwrt/unifi-openwrt/Makefile"
	mkapkFile    = "tools/mkapk.sh"
	buildFile    = "tools/build.sh"
	packagingDoc = "docs/packaging.md"
)

// uciOption is one option of the shipped UCI file; an option written as a
// comment ("#option hostname 'OpenWrt'") is not set.
type uciOption struct {
	value string
	set   bool
}

func shippedUCI(t *testing.T) map[string]uciOption {
	t.Helper()
	out := map[string]uciOption{}
	for _, m := range regexp.MustCompile(`(?m)^\t(#?)option (\w+) '([^']*)'$`).FindAllStringSubmatch(repotest.Read(t, uciFile), -1) {
		if _, dup := out[m[2]]; dup {
			t.Errorf("%s has option %s twice", uciFile, m[2])
		}
		out[m[2]] = uciOption{value: m[3], set: m[1] == ""}
	}
	if len(out) == 0 {
		t.Fatalf("no options found in %s", uciFile)
	}
	return out
}

// initFallbacks are the init script's config_get lines: option -> the
// value it takes when the UCI file does not have the option, as written.
func initFallbacks(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\tconfig_get(?:_bool)? (\w+) main (\w+) (.+)$`).FindAllStringSubmatch(repotest.Read(t, initFile), -1) {
		if m[1] != m[2] {
			t.Errorf("%s reads option %s into $%s; this test takes the two to have one name", initFile, m[2], m[1])
		}
		out[m[2]] = m[3]
	}
	if len(out) == 0 {
		t.Fatalf("no config_get found in %s", initFile)
	}
	return out
}

// daemonCommand is the init script's first procd instance, the daemon:
// its statements, a continued line joined to one.
func daemonCommand(t *testing.T) []string {
	t.Helper()
	_, rest, ok := strings.Cut(repotest.Read(t, initFile), "\tprocd_open_instance\n")
	body, _, ok2 := strings.Cut(rest, "\tprocd_close_instance\n")
	if !ok || !ok2 {
		t.Fatalf("%s: the daemon's procd instance was not found", initFile)
	}
	return strings.Split(strings.ReplaceAll(body, "\\\n", " "), "\n")
}

// uciFlags is how the init script hands each UCI option to the daemon:
// option -> flag. "enabled" is not here: it decides whether the service
// starts at all.
var uciFlags = map[string]string{
	"model":        "model",
	"inform_url":   "url",
	"hostname":     "hostname",
	"apply":        "apply",
	"profile_caps": "profile-caps",
	"locate_beep":  "locate-beep",
	"ssh_port":     "ssh-listen",
	"mesh_uplink":  "mesh-uplink",
	"hw_caps":      "hw-caps",
	"inform_every": "inform-every",
	"led_idle":     "led-idle",
	"uplink_port":  "uplink-port",
}

// packagedOn are the options the package ships turned on although the
// daemon's own flag is off unless given: an installed, enabled package
// applies the controller's settings and claims the model's capabilities,
// while a daemon started by hand only logs its plan and claims nothing.
// That difference is meant; any other is drift.
var packagedOn = []string{"apply", "profile_caps"}

// The settings of the OpenWrt daemon are written three times: the UCI file
// the package ships, the init script's fallback for an option the file
// lacks, and this daemon's flag defaults. The first two must agree
// everywhere; the third agrees with them except for packagedOn.
func TestPackagedDefaults(t *testing.T) {
	shipped, fallback := shippedUCI(t), initFallbacks(t)

	// the UCI file and the init script know the same options
	for o := range shipped {
		if _, ok := fallback[o]; !ok {
			t.Errorf("%s has option %s, which %s never reads", uciFile, o, initFile)
		}
	}
	for o := range fallback {
		if _, ok := shipped[o]; !ok {
			t.Errorf("%s reads option %s, which %s does not have", initFile, o, uciFile)
		}
	}

	// an option the file sets and the script's fallback for it are one value
	const systemHostname = `"$(uci -q get system.@system[0].hostname)"`
	for o, s := range shipped {
		fb, ok := fallback[o]
		if !ok {
			continue
		}
		switch {
		case o == "hostname":
			// not set in the file: the AP's own hostname, then defaultHostname
			if s.set || fb != systemHostname {
				t.Errorf("hostname: set in %s = %v, fallback %s; want it left to the system hostname", uciFile, s.set, fb)
			}
		case !s.set:
			t.Errorf("%s: option %s is a comment; only hostname is expected to be", uciFile, o)
		case strings.Trim(fb, "'") != s.value:
			t.Errorf("option %s: %s ships %q, %s falls back to %s", o, uciFile, s.value, initFile, fb)
		}
	}

	// the daemon's flags: each option reaches one, and the script passes
	// no flag the daemon does not have
	flags := repotest.FlagDefaults(t, "cmd/uow/main.go")
	cmd := daemonCommand(t)
	for o := range shipped {
		if _, ok := uciFlags[o]; !ok && o != "enabled" {
			t.Errorf("option %s of %s is not in uciFlags: which flag does the init script pass it as?", o, uciFile)
		}
	}
	word := func(line, flag string) bool {
		return regexp.MustCompile(`(^|\s)-` + regexp.QuoteMeta(flag) + `([=\s]|$)`).MatchString(line)
	}
	for o, f := range uciFlags {
		if _, ok := shipped[o]; !ok {
			t.Errorf("uciFlags has %s, which is not an option of %s", o, uciFile)
		}
		if _, ok := flags[f]; !ok {
			t.Errorf("option %s: cmd/uow/main.go has no flag -%s", o, f)
		}
		found := false
		for _, l := range cmd {
			if word(l, f) && (strings.Contains(l, "$"+o) || strings.Contains(l, "${"+o)) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s does not pass option %s to the daemon as -%s", initFile, o, f)
		}
	}
	for _, l := range cmd {
		_, args, ok := strings.Cut(l, "_param command ")
		if !ok {
			continue
		}
		for _, m := range regexp.MustCompile(`(?:^|\s)-([a-z][a-z-]*)`).FindAllStringSubmatch(args, -1) {
			if _, ok := flags[m[1]]; !ok {
				t.Errorf("%s starts the daemon with -%s, which cmd/uow/main.go does not have", initFile, m[1])
			}
		}
	}

	// the flag defaults, in the UCI file's writing
	uciForm := map[string]string{
		"defaultModel":     defaultModel,
		"defaultInformURL": defaultInformURL,
		"defaultHostname":  defaultHostname,
		"defaultSSHListen": strings.TrimPrefix(defaultSSHListen, ":"), // the script adds the colon
		"true":             "1",
		"false":            "0",
		"0":                "0",
		`""`:               "",
	}
	on := map[string]bool{}
	for _, o := range packagedOn {
		on[o] = true
	}
	for o, f := range uciFlags {
		bare, known := uciForm[flags[f]]
		if !known {
			t.Errorf("-%s defaults to %s in cmd/uow/main.go: this test cannot say what that is in UCI", f, flags[f])
			continue
		}
		switch got := shipped[o].value; {
		case on[o] && (got != "1" || bare != "0"):
			t.Errorf("option %s: shipped %q, -%s defaults to %s; packagedOn says shipped on, flag off", o, got, f, flags[f])
		case !on[o] && got != bare:
			t.Errorf("option %s: %s ships %q, but -%s defaults to %s", o, uciFile, got, f, flags[f])
		}
	}
	// the named defaults are read through their constants
	for f, want := range map[string]string{"model": "defaultModel", "url": "defaultInformURL", "hostname": "defaultHostname", "ssh-listen": "defaultSSHListen"} {
		if flags[f] != want {
			t.Errorf("-%s defaults to %s in cmd/uow/main.go, want the constant %s", f, flags[f], want)
		}
	}
	if !strings.HasPrefix(defaultSSHListen, ":") {
		t.Errorf("defaultSSHListen %q: want a colon and the port", defaultSSHListen)
	}

	// the two places that write the hostname of last resort out
	script := strings.Join(cmd, "\n")
	if want := `-hostname "${hostname:-` + defaultHostname + `}" `; !strings.Contains(script, want) {
		t.Errorf("%s does not have %s", initFile, want)
	}
	repotest.MustContain(t, installFile, `uci set unifi-openwrt.main.hostname="$(uci -q get system.@system[0].hostname || echo `+defaultHostname+`)"`)
	// the script's own flags that are a constant of the Go code
	if want := fmt.Sprintf(" -portal-listen :%d ", device.PortalPort); !strings.Contains(script, want) {
		t.Errorf("%s does not have%s(device.PortalPort)", initFile, want)
	}
	if want := ` -ssh-listen ":$ssh_port" `; !strings.Contains(script, want) {
		t.Errorf("%s does not have%s", initFile, want)
	}

	// the documents
	repotest.MustContain(t, packagingDoc, "`option enabled '"+shipped["enabled"].value+"'` in\n`/etc/config/"+openwrt.Service+"` is the default")
	repotest.MustContain(t, packagingDoc, "uci set unifi-openwrt.main.inform_url='"+defaultInformURL+"'")
	repotest.MustContain(t, "docs/internals.md", "default port "+shipped["ssh_port"].value+")")
}

func sortedSet(v []string) []string {
	out := append([]string(nil), v...)
	sort.Strings(out)
	return out
}

func sameSet(t *testing.T, what string, got, want []string) {
	t.Helper()
	if g, w := sortedSet(got), sortedSet(want); strings.Join(g, " ") != strings.Join(w, " ") {
		t.Errorf("%s: %q, want %q", what, g, w)
	}
}

// goBin runs the go_bin function of tools/mkapk.sh (OpenWrt arch -> the
// binary's suffix, "" for an arch without one) for each arch.
func goBin(t *testing.T, mkapk string, arches []string) map[string]string {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	script := repotest.ShellFunc(t, mkapk, "go_bin") + `for a in "$@"; do echo "$a=$(go_bin "$a")"; done` + "\n"
	c := exec.Command("sh", append([]string{"-c", script, "go_bin"}, arches...)...)
	b, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("go_bin: %v\n%s", err, b)
	}
	out := map[string]string{}
	for _, l := range strings.Fields(string(b)) {
		a, bin, _ := strings.Cut(l, "=")
		out[a] = bin
	}
	return out
}

// tools/build.sh makes one uow-<suffix> binary per CPU family. The
// installer picks one by the AP's uname, tools/mkapk.sh by the OpenWrt
// arch, and the packaging document lists them: all from build.sh's set.
func TestOpenWrtBinaryNames(t *testing.T) {
	build, install, mkapk := repotest.Read(t, buildFile), repotest.Read(t, installFile), repotest.Read(t, mkapkFile)
	var built []string
	for _, m := range regexp.MustCompile(`(?m)^b \S+ \S+ \S+ (\w+)`).FindAllStringSubmatch(build, -1) {
		built = append(built, m[1])
	}
	if len(built) == 0 || !strings.Contains(build, " -o dist/openwrt/bin/uow-$4 ") {
		t.Fatalf("%s: the build lines were not found (%q)", buildFile, built)
	}

	var picked []string
	for _, m := range regexp.MustCompile(`(?m)^\t\S+\) arch=(\w+) ;;$`).FindAllStringSubmatch(install, -1) {
		picked = append(picked, m[1])
	}
	sameSet(t, installFile+" arch=", picked, built)
	repotest.MustContain(t, installFile, `[ -x "bin/uow-$arch" ]`)

	var mapped []string
	for _, m := range regexp.MustCompile(`\) echo (\w+) ;;`).FindAllStringSubmatch(repotest.ShellFunc(t, mkapk, "go_bin"), -1) {
		mapped = append(mapped, m[1])
	}
	sameSet(t, mkapkFile+" go_bin", mapped, built)
	repotest.MustContain(t, mkapkFile, "bin=dist/openwrt/bin/uow-$b\n")

	m := regexp.MustCompile(`dist/openwrt/bin/uow-\{([\w,]+)\}`).FindStringSubmatch(repotest.Read(t, packagingDoc))
	if m == nil {
		t.Fatalf("%s no longer lists the binaries as uow-{...}", packagingDoc)
	}
	sameSet(t, packagingDoc+" uow-{...}", strings.Split(m[1], ","), built)

	// the arches mkapk.sh packages when none is given each have a binary
	d := regexp.MustCompile(`(?s)\|\| set -- (.*?[^\\])\n`).FindStringSubmatch(mkapk)
	if d == nil {
		t.Fatalf("%s: the default arch list was not found", mkapkFile)
	}
	defaults := strings.Fields(strings.ReplaceAll(d[1], "\\\n", " "))
	// and the kinds the document says are skipped have none: ARMv5, ARMv6,
	// an ARM core without an FPU, mips64, i386
	skipped := []string{"arm_arm926ej-s", "arm_arm1176jzf-s_vfp", "arm_cortex-a7", "mips64_octeonplus", "i386_pentium4"}
	repotest.MustContain(t, packagingDoc, "Arches without a matching binary\n(ARMv5/v6, ARM cores without an FPU, mips64, i386) are skipped")
	got := goBin(t, mkapk, append(append([]string(nil), defaults...), skipped...))
	isBuilt := map[string]bool{}
	for _, b := range built {
		isBuilt[b] = true
	}
	for _, a := range defaults {
		if !isBuilt[got[a]] {
			t.Errorf("%s packages %s by default, for which go_bin gives %q: not a binary of %s", mkapkFile, a, got[a], buildFile)
		}
	}
	for _, a := range skipped {
		if got[a] != "" {
			t.Errorf("go_bin(%s) = %q; %s says such an arch is skipped", a, got[a], packagingDoc)
		}
	}
}

// makeBlock is the body of a "define Package/unifi-openwrt/<name>" block
// of the OpenWrt Makefile, a line each.
func makeBlock(t *testing.T, mk, name string) []string {
	t.Helper()
	_, rest, ok := strings.Cut(mk, "\ndefine Package/"+openwrt.Service+"/"+name+"\n")
	body, _, ok2 := strings.Cut(rest, "\nendef\n")
	if !ok || !ok2 {
		t.Fatalf("%s has no block %s", makefileFile, name)
	}
	return strings.Split(body, "\n")
}

// The package is defined by the SDK Makefile. tools/mkapk.sh builds the
// same package without the SDK and takes version, licence, description
// and the install scripts from the Makefile, but types the name, the
// dependencies, the conffiles and the file list again; packaging/install.sh
// installs the same files and packages by hand.
func TestOpenWrtPackageDefinition(t *testing.T) {
	mk, mkapk, install := repotest.Read(t, makefileFile), repotest.Read(t, mkapkFile), repotest.Read(t, installFile)
	mkvar := func(name string) string {
		m := regexp.MustCompile(`(?m)^\s*` + name + `:=(.*)$`).FindStringSubmatch(mk)
		if m == nil {
			t.Fatalf("%s does not set %s", makefileFile, name)
		}
		return m[1]
	}

	// the Go module and the command the SDK builds
	mod := regexp.MustCompile(`(?m)^module (\S+)$`).FindStringSubmatch(repotest.Read(t, "go.mod"))
	if mod == nil {
		t.Fatal("go.mod has no module line")
	}
	if got := mkvar("GO_PKG"); got != mod[1] {
		t.Errorf("%s: GO_PKG %s, go.mod says module %s", makefileFile, got, mod[1])
	}
	wd, _ := filepath.Abs(".")
	here, _ := filepath.Rel(repotest.Root(t), wd) // this package: the daemon
	if got, want := mkvar("GO_PKG_BUILD_PKG"), mod[1]+"/"+filepath.ToSlash(here); got != want {
		t.Errorf("%s: GO_PKG_BUILD_PKG %s, want %s", makefileFile, got, want)
	}

	// its name: the service's
	name := mkvar("PKG_NAME")
	if name != openwrt.Service {
		t.Errorf("%s: PKG_NAME %s, the service is %s", makefileFile, name, openwrt.Service)
	}
	if got := repotest.ShellVar(t, mkapk, "pkg"); got != name {
		t.Errorf("%s: pkg=%s, the Makefile's PKG_NAME is %s", mkapkFile, got, name)
	}
	repotest.MustContain(t, makefileFile, "$(eval $(call BuildPackage,"+name+"))")

	// dependencies. The Makefile leaves iw and nftables out on purpose (its
	// comment: alternatives a Kconfig select cannot express); mkapk.sh
	// lists them, apk resolves the virtual names.
	var deps []string
	for _, d := range strings.Fields(mkvar("DEPENDS")) {
		if d == "$(GO_ARCH_DEPENDS)" {
			continue
		}
		if !strings.HasPrefix(d, "+") {
			t.Errorf("%s: DEPENDS has %s; this test knows +name and $(GO_ARCH_DEPENDS)", makefileFile, d)
		}
		deps = append(deps, strings.TrimPrefix(d, "+"))
	}
	apkOnly := []string{"iw", "nftables"}
	m := regexp.MustCompile(`--info "depends:([^"]*)"`).FindStringSubmatch(mkapk)
	if m == nil {
		t.Fatalf("%s: the depends line was not found", mkapkFile)
	}
	apkDeps := strings.Fields(m[1])
	sameSet(t, mkapkFile+" depends", apkDeps, append(append([]string(nil), deps...), apkOnly...))
	m = regexp.MustCompile(`(?m)^\tfor p in (.*); do pm_has \$p \|\| pm_add \$p; done$`).FindStringSubmatch(install)
	if m == nil {
		t.Fatalf("%s: the loop that installs the required packages was not found", installFile)
	}
	sameSet(t, installFile+" required packages", strings.Fields(m[1]), deps)
	// the document names both lists
	tick := func(v []string) []string {
		out := make([]string, len(v))
		for i, s := range v {
			out[i] = "`" + s + "`"
		}
		return out
	}
	doc := strings.Join(strings.Fields(repotest.Read(t, packagingDoc)), " ")
	for _, want := range []string{
		"apk installs the dependencies (" + strings.Join(tick(apkDeps), ", ") + ")",
		"Its dependencies are " + strings.Join(tick(deps), " and ") + ". " + strings.Join(tick(apkOnly), " and ") + " come with default images and are left out",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s does not say: %s", packagingDoc, want)
		}
	}

	// conffiles: the UCI file, which the package ships, and the daemon's
	// directory, which it does not (mkapk.sh puts that one on sysupgrade's
	// keep list, as OpenWrt's build does for a conffile it does not ship)
	conf := makeBlock(t, mk, "conffiles")
	sameSet(t, makefileFile+" conffiles", conf, []string{"/etc/config/" + openwrt.Service, openwrt.ConfDir + "/"})
	var kept []string
	for _, re := range []string{`(?m)^echo (\S+) > "\$r/lib/upgrade/keep\.d/\$pkg"$`, `(?m)^echo (\S+) > "\$work/conffiles"$`} {
		m := regexp.MustCompile(re).FindStringSubmatch(mkapk)
		if m == nil {
			t.Fatalf("%s: no line like %s", mkapkFile, re)
		}
		kept = append(kept, m[1])
	}
	sameSet(t, mkapkFile+" conffiles and keep list", kept, conf)

	// the installed files: the daemon and everything under packaging/files
	bin := repotest.ShellVar(t, repotest.Read(t, initFile), "PROG")
	want := []string{bin}
	filesDir := filepath.Join(repotest.Root(t), "packaging", "files")
	err := filepath.WalkDir(filesDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(filesDir, p)
			want = append(want, "/"+filepath.ToSlash(rel))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var fromMk []string
	for _, l := range makeBlock(t, mk, "install") {
		m := regexp.MustCompile(`^\t\$\(INSTALL_(?:BIN|CONF)\) (\S+) \$\(1\)(/\S+)$`).FindStringSubmatch(l)
		if m == nil {
			continue
		}
		dst := m[2]
		if strings.HasSuffix(dst, "/") {
			dst += path.Base(m[1])
		}
		if src, ok := strings.CutPrefix(m[1], "$(PKG_BUILD_DIR)/packaging/files"); ok && src != dst {
			t.Errorf("%s installs packaging/files%s as %s", makefileFile, src, dst)
		}
		fromMk = append(fromMk, dst)
	}
	sameSet(t, makefileFile+" installs", fromMk, want)
	var fromApk []string
	for _, m := range regexp.MustCompile(`(?m)^\t?install -m \d+ (\S+) "\$r(/[^"]+)"$`).FindAllStringSubmatch(mkapk, -1) {
		if src, ok := strings.CutPrefix(m[1], "packaging/files"); ok && src != m[2] {
			t.Errorf("%s installs packaging/files%s as %s", mkapkFile, src, m[2])
		}
		fromApk = append(fromApk, m[2])
	}
	sameSet(t, mkapkFile+" installs", fromApk, want)
	var byHand []string
	for _, m := range regexp.MustCompile(`(?m)^\t?cp (\S+) (/\S+)`).FindAllStringSubmatch(install, -1) {
		dst := m[2]
		if src, ok := strings.CutPrefix(m[1], "files"); ok && src != dst {
			t.Errorf("%s installs files%s as %s", installFile, src, dst)
		}
		if tmp, ok := strings.CutSuffix(dst, ".new"); ok && strings.Contains(install, "mv "+dst+" "+tmp+"\n") {
			dst = tmp // copied beside the old one, then moved over it
		}
		byHand = append(byHand, dst)
	}
	sameSet(t, installFile+" installs", byHand, want)
}
