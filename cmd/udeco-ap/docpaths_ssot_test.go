// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
	"github.com/antoniocosta/unifi-openwrt/internal/unit"
)

// pathDocs restate where the agent lives on a unit: its install directory,
// config, launcher, state and run files.
var pathDocs = []string{"README.md", "docs/deco/agent-design.md", "packaging/deco/README.md"}

// unitPaths is every on-device path of the agent and its launchers a
// document may state, built from the names the code uses: internal/unit's
// directories, the agent's and internal/device's file names, bcmwifi's run
// files, and the names the deploy scripts and launchers write out (which
// TestUnitLayout holds to internal/unit). A placeholder vif or radio is
// written as the documents write it (wlN, wl14).
func unitPaths(t *testing.T) map[string]bool {
	t.Helper()
	known := map[string]bool{}
	add := func(dir string, names ...string) {
		known[dir] = true
		for _, n := range names {
			known[path.Join(dir, n)] = true
		}
	}
	session := []string{sessionSub}
	for _, n := range []string{device.StateFile, device.SystemCfgFile, device.SystemCfgHistoryDir, device.UnhandledFile, device.SSHHostKeyFile} {
		session = append(session, path.Join(sessionSub, n))
	}
	for _, dir := range []string{unit.DecoDir, unit.JioDir} {
		// the agent's files in its config's directory
		add(dir, unit.ConfigFile, unit.Launcher, wifiStateSub, path.Join(wifiStateSub, spectrumFile),
			eventsFile, aliveFile, bootIDFile, observeMarker)
		add(dir, session...)
	}
	// what the deploy scripts and launchers put on flash and in RAM
	deco := scriptVars(t, decoDeploy, "DIR", "BIN", "GZ", "SUM", "START", "RAMDIR", "CFG")
	for _, n := range []string{"BIN", "GZ", "SUM", "START", "CFG"} {
		known[deco[n]] = true
	}
	ds, js, ss := repotest.Read(t, decoDeploy), repotest.Read(t, jioDeploy), repotest.Read(t, jioStart)
	add(unit.DecoDir, namesUnder(ds, "$DIR")...)
	add(unit.JioDir, namesUnder(js, "$DIR")...)
	add(unit.JioDir, namesUnder(ss, "$D")...)
	add(unit.RAMDir, namesUnder(ds, "$RAMDIR")...)
	add(unit.RAMDir, namesUnder(js, "$RAM")...)
	add(unit.RAMDir, namesUnder(ss, "$R")...)
	// the agent's run directory (ramfs)
	add(unit.RunDir, lockName, pidName, startsFile, counterFile, loopFile)
	known[bcmwifi.ConfPath(unit.RunDir, "wlN")] = true
	known[bcmwifi.DenyPath(unit.RunDir, "wl14")] = true
	return known
}

// unitPathRE finds a path under the agent's directories in a document:
// /tp_data/udeco..., /flash2/udeco..., /tmp/udeco... (/tmp/udeco-bin too).
var unitPathRE = regexp.MustCompile(`/(?:tp_data|flash2|tmp)/udeco[A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)*/?`)

// Every agent path the documents state is one the code and the scripts
// use: the install directories and file names come from internal/unit and
// the constants that name each file, so a document cannot put a file in
// another directory (agent.log in the run directory, counters.json on
// flash) or under another name than the agent does.
func TestDocsUnitPaths(t *testing.T) {
	known := unitPaths(t)
	for _, want := range []string{DefaultConfigPath, path.Join(unit.DecoDir, unit.Launcher), unit.RAMDir + "/agent.log"} {
		if !known[want] {
			t.Fatalf("the known paths miss %s: %v", want, known)
		}
	}
	found := map[string]bool{}
	for _, rel := range pathDocs {
		text := repotest.Read(t, rel)
		n := 0
		for _, m := range unitPathRE.FindAllString(text, -1) {
			p := strings.TrimRight(m, "./")
			n++
			found[p] = true
			if !known[p] {
				t.Errorf("%s states %s, which is no path of the agent or its launcher (internal/unit, the agent's file names, deploy/*.sh)", rel, m)
			}
		}
		if n == 0 {
			t.Errorf("%s states no agent path: is it still in pathDocs' scope?", rel)
		}
	}
	// the documents state the install the way the code makes it
	for _, want := range []string{DefaultConfigPath, path.Join(unit.DecoDir, unit.Launcher), unit.RAMDir + "/agent.log",
		path.Join(unit.RunDir, counterFile), path.Join(unit.DecoDir, observeMarker), path.Join(unit.RunDir, pidName)} {
		if !found[want] {
			var got []string
			for p := range found {
				got = append(got, p)
			}
			sort.Strings(got)
			t.Errorf("no document of %v states %s; they state %v", pathDocs, want, got)
		}
	}
	// and the persist file the launcher's supervise line goes in
	persist := scriptVars(t, decoDeploy, "PERSIST")["PERSIST"]
	for _, rel := range pathDocs {
		for _, m := range regexp.MustCompile(`/data/[A-Za-z0-9_.-]*persist[A-Za-z0-9_.-]*`).FindAllString(repotest.Read(t, rel), -1) {
			if m != persist {
				t.Errorf("%s states the persist file as %s, deploy/deco-ap.sh PERSIST is %s", rel, m, persist)
			}
		}
	}
}

// unitPathRE takes each whole path, and only the agent's directories.
func TestUnitPathRE(t *testing.T) {
	text := "in `/tp_data/udeco/udeco-ap.json`, /tmp/udeco-bin/agent.log. /flash2/udeco/state/ and /tmp/udeco; not /tmp/upgrade or /tp_data/x"
	got := unitPathRE.FindAllString(text, -1)
	want := []string{"/tp_data/udeco/udeco-ap.json", "/tmp/udeco-bin/agent.log.", "/flash2/udeco/state/", "/tmp/udeco"}
	if !slices.Equal(got, want) {
		t.Errorf("found %q, want %q", got, want)
	}
}
