package decosys

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// proc is one userspace process from /proc.
type proc struct {
	pid  int
	argv []string
}

// readProcs reads /proc/<pid>/cmdline for every process, once. Kernel threads
// (empty cmdline) and processes that exit mid-scan are skipped. The result is
// sorted by PID so plans are deterministic.
func (m *Manager) readProcs() ([]proc, error) {
	dir := filepath.Join(m.o.Root, "proc")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ps []proc
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if argv := m.cmdline(pid); argv != nil {
			ps = append(ps, proc{pid: pid, argv: argv})
		}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].pid < ps[j].pid })
	return ps, nil
}

// cmdline returns the argv of a process, or nil when it has exited, is a
// zombie or is a kernel thread (all of which have an empty cmdline).
func (m *Manager) cmdline(pid int) []string {
	b, err := os.ReadFile(filepath.Join(m.o.Root, "proc", strconv.Itoa(pid), "cmdline"))
	b = bytes.TrimRight(b, "\x00")
	if err != nil || len(b) == 0 {
		return nil
	}
	var argv []string
	for _, a := range bytes.Split(b, []byte{0}) {
		argv = append(argv, string(a))
	}
	return argv
}

// shells are the interpreters a TP-Link script runs under. The kernel puts
// the interpreter in argv[0] and the script path in argv[1].
var shells = []string{"sh", "ash", "bash"}

// program strips a shell interpreter from argv, so that a script started as
// "/bin/sh /usr/sbin/start_nrd" is seen as "/usr/sbin/start_nrd". An inline
// shell ("sh -c ...") is left as it is.
func program(argv []string) []string {
	if len(argv) > 1 && slices.Contains(shells, path.Base(argv[0])) && !strings.HasPrefix(argv[1], "-") {
		return argv[1:]
	}
	return argv
}

// exists reports whether a device path exists (symlinks are not followed, so
// a dangling busybox link still counts).
func (m *Manager) exists(p string) bool {
	_, err := os.Lstat(filepath.Join(m.o.Root, p))
	return err == nil
}
