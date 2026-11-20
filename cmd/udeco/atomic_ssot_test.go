// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// blocks.json is replaced through "blocks.json.tmp" (the name it has
// always used; atomicfile.Write now), mode 0600, one file left. With the
// temporary name unusable the file stays and the failure is logged.
func TestBlocksSaveThroughTmp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "blocks.json")
	var logged []string
	b := &blockSync{path: p, added: map[string]bool{"aa:bb:cc:00:00:01": true},
		logf: func(f string, v ...any) { logged = append(logged, fmt.Sprintf(f, v...)) }}
	b.save()
	first, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(first), `"aa:bb:cc:00:00:01"`) {
		t.Fatalf("blocks.json %q: %v", first, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("%d files left", len(ents))
	}
	if err := os.MkdirAll(filepath.Join(p+".tmp", "in-use"), 0o755); err != nil {
		t.Fatal(err)
	}
	b.added["aa:bb:cc:00:00:02"] = true
	b.save()
	if got, _ := os.ReadFile(p); string(got) != string(first) {
		t.Errorf("saved although blocks.json.tmp is taken: the temporary name changed: %s", got)
	}
	if len(logged) != 1 || !strings.HasPrefix(logged[0], "blocks: saving: ") {
		t.Errorf("logged %q", logged)
	}
}
