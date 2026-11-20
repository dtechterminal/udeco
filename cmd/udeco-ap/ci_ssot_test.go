// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

const ciWorkflow = ".github/workflows/build.yml"

// ciDevice is one entry of the build matrix in ciWorkflow.
type ciDevice struct{ device, script, out string }

// ciDevices reads the build matrix's include entries ("- device:" starts
// one; "script:" and "out:" belong to the entry above them).
func ciDevices(t *testing.T) []ciDevice {
	t.Helper()
	var ds []ciDevice
	for _, line := range strings.Split(repotest.Read(t, ciWorkflow), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		v = strings.TrimSpace(v)
		switch {
		case !ok:
		case k == "- device":
			ds = append(ds, ciDevice{device: v})
		case len(ds) > 0 && k == "script":
			ds[len(ds)-1].script = v
		case len(ds) > 0 && k == "out":
			ds[len(ds)-1].out = v
		}
	}
	if len(ds) == 0 {
		t.Fatalf("%s: no build matrix entries (- device:)", ciWorkflow)
	}
	return ds
}

// Every device deploy script (deploy/*-ap.sh) has its own CI build, and
// every CI build runs a deploy script's --build-only and uploads that
// script's OUT, so the CI binary is the one a deploy ships.
func TestCIBuildsEveryDevice(t *testing.T) {
	root := repotest.Root(t)
	scripts, err := filepath.Glob(filepath.Join(root, "deploy", "*-ap.sh"))
	if err != nil || len(scripts) == 0 {
		t.Fatalf("no deploy/*-ap.sh: %v", err)
	}
	ds := ciDevices(t)
	seen := map[string]bool{}
	for _, d := range ds {
		if d.device == "" || d.script == "" || d.out == "" {
			t.Errorf("%s: matrix entry %+v needs device, script and out", ciWorkflow, d)
			continue
		}
		if seen[d.device] {
			t.Errorf("%s: device %s listed twice", ciWorkflow, d.device)
		}
		seen[d.device] = true
		if _, err := os.Stat(filepath.Join(root, d.script)); err != nil {
			t.Errorf("%s: device %s builds with %s, which does not exist", ciWorkflow, d.device, d.script)
			continue
		}
		text := repotest.Read(t, d.script)
		if !strings.Contains(text, "--build-only)") {
			t.Errorf("%s has no --build-only option for the CI build of %s", d.script, d.device)
		}
		if out := repotest.ShellVar(t, text, "OUT"); out != d.out {
			t.Errorf("%s: device %s uploads %s, but %s builds OUT=%s", ciWorkflow, d.device, d.out, d.script, out)
		}
	}
	for _, s := range scripts {
		rel := filepath.ToSlash(strings.TrimPrefix(s, root+string(filepath.Separator)))
		if !slices.ContainsFunc(ds, func(d ciDevice) bool { return d.script == rel }) {
			t.Errorf("%s is a device deploy script with no build in %s: add a matrix entry for it", rel, ciWorkflow)
		}
	}
}
