// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// NextEngineBoots saves the count through "<file>.new" (the name it has
// always used; atomicfile.Write now) and leaves one file. With that name
// unusable it returns the error (v3 must not be served) and keeps the old
// count.
func TestEngineBootsThroughNew(t *testing.T) {
	dir := t.TempDir()
	p := BootsFile(dir)
	if n, err := NextEngineBoots(p); n != 1 || err != nil {
		t.Fatalf("boots %d %v", n, err)
	}
	left := func() []string {
		t.Helper()
		ents, err := os.ReadDir(filepath.Dir(p))
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range ents {
			out = append(out, e.Name())
		}
		return out
	}
	if got := left(); len(got) != 1 {
		t.Errorf("files left: %v", got)
	}
	if err := os.MkdirAll(filepath.Join(p+".new", "in-use"), 0o755); err != nil {
		t.Fatal(err)
	}
	if n, err := NextEngineBoots(p); err == nil || n != 0 {
		t.Errorf("boots %d, %v although the .new name is taken: the temporary name changed", n, err)
	}
	if b, _ := os.ReadFile(p); strings.TrimSpace(string(b)) != "1" {
		t.Errorf("a failed save left %q", b)
	}
}
