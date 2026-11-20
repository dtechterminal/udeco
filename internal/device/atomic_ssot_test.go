// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// takeName puts a directory with a file in it at p, so that nothing can be
// written or renamed there.
func takeName(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(p, "in-use"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// State.Save replaces state.json through "state.json.tmp" (the name it has
// always used; atomicfile.Write now), mode 0600, and leaves one file. With
// the temporary name unusable the save fails and the state stays.
func TestStateSaveThroughTmp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	s := NewState("http://192.0.2.1:8080/inform")
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	s.CfgVersion = "abc"
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	got, ok, err := Load(p)
	if err != nil || !ok || got.CfgVersion != "abc" {
		t.Fatalf("load: %+v %v %v", got, ok, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if names := dirNames(t, dir); len(names) != 1 {
		t.Errorf("files left: %v", names)
	}
	takeName(t, p+".tmp")
	s.CfgVersion = "def"
	if err := s.Save(p); err == nil {
		t.Error("saved although state.json.tmp is taken: the temporary name changed")
	}
	if got, _, _ := Load(p); got.CfgVersion != "abc" {
		t.Errorf("a failed save left cfgversion %q", got.CfgVersion)
	}
}

// A save whose rename fails leaves no state.json.tmp behind (it used to).
func TestStateSaveFailureLeavesNoTmp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	takeName(t, p)
	if err := NewState("http://192.0.2.1:8080/inform").Save(p); err == nil {
		t.Fatal("saved over a directory")
	}
	if names := dirNames(t, dir); len(names) != 1 {
		t.Errorf("files left: %v", names)
	}
}

// The ledger is written the same way: through "<file>.tmp", mode 0600,
// one file left; a write that cannot happen is dropped without a trace.
func TestLedgerWriteThroughTmp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "unhandled.json")
	l := OpenLedger(p)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if !l.Note("cmd", "one", "{}", now) {
		t.Fatal("first note not new")
	}
	if got := OpenLedger(p).Entries(); len(got) != 1 || got[0].Name != "one" {
		t.Fatalf("ledger file: %+v", got)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if names := dirNames(t, dir); len(names) != 1 {
		t.Errorf("files left: %v", names)
	}
	takeName(t, p+".tmp")
	l.Note("cmd", "two", "{}", now)
	if got := OpenLedger(p).Entries(); len(got) != 1 {
		t.Errorf("written although unhandled.json.tmp is taken: the temporary name changed: %+v", got)
	}
}
