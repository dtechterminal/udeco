// SPDX-License-Identifier: GPL-2.0-or-later

package atomicfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/repotest"
)

func names(t *testing.T, dir string) []string {
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

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// Write is os.WriteFile to the temporary name and os.Rename, nothing
// more: the content, the mode a plain os.WriteFile gives, one file left.
func TestWrite(t *testing.T) {
	dir := t.TempDir()
	for _, perm := range []os.FileMode{0o600, 0o644} {
		p, plain := filepath.Join(dir, "state.json"), filepath.Join(dir, "plain")
		if err := Write(p, p+".tmp", []byte("one"), perm); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(plain, nil, perm); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(p); string(b) != "one" || mode(t, p) != mode(t, plain) {
			t.Errorf("perm %v: wrote %q with mode %v, os.WriteFile gives %v", perm, b, mode(t, p), mode(t, plain))
		}
		// over an existing file: the new content, the new file's mode
		if err := Write(p, p+".tmp", []byte("two"), perm); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(p); string(b) != "two" || mode(t, p) != mode(t, plain) {
			t.Errorf("perm %v: replaced with %q, mode %v", perm, b, mode(t, p))
		}
		if got := names(t, dir); len(got) != 2 {
			t.Errorf("perm %v: files left: %v", perm, got)
		}
		os.Remove(p)
		os.Remove(plain)
	}
}

// The temporary file is the name the caller gives, written in place: one
// left by an earlier run is overwritten and keeps its mode (os.WriteFile),
// as at every site before Write.
func TestWriteUsesTheGivenTempName(t *testing.T) {
	dir := t.TempDir()
	p, tmp := filepath.Join(dir, "users"), filepath.Join(dir, ".users.udeco")
	if err := os.WriteFile(tmp, []byte("left by a run that died"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmp, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := Write(p, tmp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" || mode(t, p) != 0o640 {
		t.Errorf("wrote %q with mode %v", b, mode(t, p))
	}
	if got := names(t, dir); len(got) != 1 || got[0] != "users" {
		t.Errorf("files left: %v", got)
	}
}

// A failed write or rename returns that error, leaves the target as it
// was and removes the temporary file (the sites that wrote the sequence
// out themselves mostly left it behind).
func TestWriteFailure(t *testing.T) {
	dir := t.TempDir()

	// no directory is made
	p := filepath.Join(dir, "missing", "state.json")
	err := Write(p, p+".tmp", []byte("x"), 0o600)
	var pe *fs.PathError
	if !errors.As(err, &pe) || !errors.Is(err, fs.ErrNotExist) || pe.Path != p+".tmp" {
		t.Errorf("missing directory: %v", err)
	}
	if got := names(t, dir); len(got) != 0 {
		t.Errorf("missing directory: made %v", got)
	}

	// the rename fails: the target is a directory with something in it
	p = filepath.Join(dir, "target")
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "keep"), []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = Write(p, p+".tmp", []byte("x"), 0o600)
	var le *os.LinkError
	if !errors.As(err, &le) || le.Op != "rename" {
		t.Errorf("rename onto a directory: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(p, "keep")); string(b) != "kept" {
		t.Errorf("the target changed: %q", b)
	}
	if got := names(t, dir); len(got) != 1 || got[0] != "target" {
		t.Errorf("rename failed: files left %v", got)
	}

	// the write fails: the temporary name is taken by a directory in use
	p = filepath.Join(dir, "cfg")
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(p+".tmp", "in-use"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Write(p, p+".tmp", []byte("x"), 0o600); err == nil {
		t.Error("wrote through a directory")
	}
	if b, _ := os.ReadFile(p); string(b) != "old" {
		t.Errorf("a failed write left %q", b)
	}
}

// renameSites are the Go files, other than tests, that call os.Rename, and
// how often: Write, and the three writers the package comment names. A
// new temp-and-rename written out by hand fails here; it should call Write
// (or be added with its reason).
var renameSites = map[string]int{
	"internal/atomicfile/atomicfile.go": 1,
	"internal/bcmwifi/apply.go":         1, // writeFileAtomic: os.CreateTemp, MkdirAll, Chmod on the open file
	"internal/decosys/cron.go":          2, // the temporary file is in the state directory on purpose
	"cmd/udeco-ap/users.go":             1, // replaceKeepMode: the target's mode goes on the temporary file first
}

func TestRenameSites(t *testing.T) {
	root := repotest.Root(t)
	got := map[string]int{}
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if n := strings.Count(string(b), "os.Rename("); n > 0 {
				rel, _ := filepath.Rel(root, p)
				got[filepath.ToSlash(rel)] = n
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var files []string
	for f := range got {
		files = append(files, f)
	}
	for f := range renameSites {
		if _, ok := got[f]; !ok {
			files = append(files, f)
		}
	}
	sort.Strings(files)
	for _, f := range files {
		if got[f] != renameSites[f] {
			t.Errorf("%s calls os.Rename %d times, the list here says %d: replace a file with atomicfile.Write, or list the site with its reason", f, got[f], renameSites[f])
		}
	}
}
