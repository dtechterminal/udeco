package decosys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	crontabPath = "/etc/crontabs/root"
	// stateDir holds the Manager's undo records. /etc is a ramfs, so they live
	// exactly as long as the stops they describe (until reboot), survive an
	// agent restart, and the rename into /etc/crontabs stays on one
	// filesystem. Nothing is written to flash.
	stateDir    = "/etc/udeco"
	cronBackup  = stateDir + "/crontab.root.tplink"
	stoppedFile = stateDir + "/decosys.stopped"
)

// firmwarePrefixes are the read-only firmware locations. Every TP-Link cron
// job runs a command from one of them (dwds_tpbr_check, tmpsvr_check,
// deleteToken.sh, report_get_device_status, update_deviceFeatureInfo,
// smart_home_schedule, process_monit, ...), while the user's own jobs live
// in /data or /tp_data (/data/persist_shell.sh keeps SSH :22 alive).
var firmwarePrefixes = []string{"/usr/", "/sbin/", "/bin/", "/lib/", "/etc/", "/www/"}

// cronInterpreters may prefix a cron command; the script after them is what
// the line runs (R15).
var cronInterpreters = []string{"sh", "ash", "bash", "lua"}

// cronCommand returns the command fields of a crontab line (after the
// schedule), or nil for blank lines, comments, variable assignments and
// short lines.
func cronCommand(line string) []string {
	f := strings.Fields(line)
	if len(f) == 0 || strings.HasPrefix(f[0], "#") {
		return nil
	}
	switch {
	case strings.HasPrefix(f[0], "@") && len(f) >= 2:
		return f[1:]
	case len(f) >= 6:
		return f[5:]
	}
	return nil
}

// cronProgram strips a leading interpreter ("sh /lib/x.sh" runs /lib/x.sh).
func cronProgram(cmd []string) string {
	if len(cmd) > 1 && slices.Contains(cronInterpreters, filepath.Base(cmd[0])) && !strings.HasPrefix(cmd[1], "-") {
		return cmd[1]
	}
	return cmd[0]
}

// isTPLinkCron reports whether a crontab line is a TP-Link job. Blank lines,
// comments, variable assignments and anything whose program is not an
// absolute firmware path are kept: an unknown line is more likely the user's.
// TP-Link's literal drop_caches job (app-classifier) is TP-Link's too.
func isTPLinkCron(line string) bool {
	cmd := cronCommand(line)
	if cmd == nil {
		return false
	}
	if strings.ReplaceAll(strings.Join(cmd, ""), " ", "") == "echo3>/proc/sys/vm/drop_caches" {
		return true
	}
	prog := cronProgram(cmd)
	for _, p := range firmwarePrefixes {
		if strings.HasPrefix(prog, p) {
			return true
		}
	}
	return false
}

// persistLine is the supervision line the crontab must hold (R16): cron
// runs /data/persist_shell.sh every minute, which restarts /data/dropbear
// :22 and the agent when they are not running.
const persistLine = "* * * * * sh " + persistScript

// isPersistJob reports whether a line runs persist_shell.sh and nothing else.
func isPersistJob(line string) bool {
	cmd := cronCommand(line)
	if cmd == nil || cronProgram(cmd) != persistScript {
		return false
	}
	return len(cmd) == 1 || len(cmd) == 2 && cmd[1] == persistScript
}

// everyMinute reports whether a line's schedule is "* * * * *".
func everyMinute(line string) bool {
	f := strings.Fields(line)
	return len(f) >= 6 && strings.Join(f[:5], " ") == "* * * * *"
}

// tidyCron applies the crontab invariant to the current file: TP-Link jobs
// out (drop), byte-identical job lines collapsed, exactly one line that runs
// only persist_shell.sh (the first every-minute one, else the first), and
// persistLine appended when no line mentions persist_shell.sh at all. Every
// other line, the user's own and comments included, stays as it is.
func tidyCron(b []byte) (keep, drop, why []string) {
	text := strings.TrimRight(string(b), "\n")
	var lines []string
	if text != "" {
		lines = strings.Split(text, "\n")
	}
	persist := -1
	for i, l := range lines {
		if isPersistJob(l) && (persist < 0 || everyMinute(l) && !everyMinute(lines[persist])) {
			persist = i
		}
	}
	seen := map[string]bool{}
	dups, extra := 0, 0
	mentions := false
	for i, l := range lines {
		switch {
		case isTPLinkCron(l):
			drop = append(drop, l)
			continue
		case cronCommand(l) != nil && seen[l]:
			dups++
			continue
		case isPersistJob(l) && i != persist:
			extra++
			continue
		}
		if cronCommand(l) != nil {
			seen[l] = true
			mentions = mentions || strings.Contains(l, persistScript)
		}
		keep = append(keep, l)
	}
	if len(drop) > 0 {
		var jobs []string
		for _, l := range drop {
			jobs = append(jobs, filepath.Base(cronProgram(cronCommand(l))))
		}
		why = append(why, "remove TP-Link jobs: "+strings.Join(jobs, ", "))
	}
	if dups > 0 {
		why = append(why, fmt.Sprintf("collapse %d duplicate line(s)", dups))
	}
	if extra > 0 {
		why = append(why, fmt.Sprintf("drop %d extra persist_shell.sh line(s)", extra))
	}
	if !mentions {
		keep = append(keep, persistLine)
		why = append(why, "add the persist_shell.sh supervision line")
	}
	return keep, drop, why
}

// cronStep returns a step that brings root's crontab to the invariant, or
// nil when it already holds. A missing crontab gets the persist line.
func (m *Manager) cronStep() (*Step, error) {
	b, err := os.ReadFile(filepath.Join(m.o.Root, crontabPath))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read crontab: %w", err)
	}
	if err != nil && !m.exists(filepath.Dir(crontabPath)) {
		m.note("no-crontabs", "no "+filepath.Dir(crontabPath)+": the crontab invariant (R16) is off")
		return nil, nil
	}
	keep, _, why := tidyCron(b)
	if len(why) == 0 && joinLines(keep) == string(b) {
		return nil, nil
	}
	return &Step{Kind: KindCron, Target: crontabPath, Reason: strings.Join(why, "; "),
		do: func(context.Context) error { return m.rewriteCron() }}, nil
}

// joinLines renders lines as a file.
func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// rewriteCron brings the crontab to the invariant atomically. The new file
// is written next to it and renamed over it only if the crontab did not
// change in the meantime (an 'echo >> crontab' from persist_shell.sh would
// otherwise be lost, audit B3d); a changed file is read again and the
// rewrite retried. The removed TP-Link lines go to the backup Restore uses.
func (m *Manager) rewriteCron() error {
	file := filepath.Join(m.o.Root, crontabPath)
	for range 5 {
		b, err := os.ReadFile(file)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		st1, _ := os.Stat(file)
		keep, drop, _ := tidyCron(b)
		out := joinLines(keep)
		if out == string(b) {
			return nil
		}
		if len(drop) > 0 {
			backup, err := m.readLines(cronBackup)
			if err != nil {
				return err
			}
			for _, l := range drop {
				if !slices.Contains(backup, l) {
					backup = append(backup, l)
				}
			}
			if err := m.writeFile(cronBackup, backup, 0o600); err != nil {
				return err
			}
		}
		tmp, err := m.writeTemp([]byte(out), 0o600)
		if err != nil {
			return err
		}
		if m.beforeCronRename != nil {
			m.beforeCronRename()
		}
		b2, _ := os.ReadFile(file)
		st2, _ := os.Stat(file)
		if !bytes.Equal(b, b2) || !sameStat(st1, st2) {
			os.Remove(tmp)
			continue
		}
		// busybox crond rescans /etc/crontabs when the directory's mtime
		// changes, which the rename does.
		if err := os.Rename(tmp, file); err != nil {
			os.Remove(tmp)
			return err
		}
		return nil
	}
	return errors.New("crontab kept changing during the rewrite; retried next pass")
}

// sameStat reports whether two stats describe the same file contents state.
func sameStat(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// restoreCron puts the backed-up TP-Link jobs back, keeping whatever the
// crontab holds now.
func (m *Manager) restoreCron() error {
	backup, err := m.readLines(cronBackup)
	if err != nil || len(backup) == 0 {
		return err
	}
	cur, err := m.readLines(crontabPath)
	if err != nil {
		return err
	}
	var add []string
	for _, l := range backup {
		if !slices.Contains(cur, l) {
			add = append(add, l)
		}
	}
	if len(add) > 0 {
		if m.o.DryRun {
			m.o.Logf("decosys: dry-run: restore %d TP-Link cron jobs", len(add))
			return nil
		}
		if err := m.writeFile(crontabPath, append(add, cur...), 0o600); err != nil {
			return err
		}
		m.o.Logf("decosys: restored %d TP-Link cron jobs", len(add))
	}
	if m.o.DryRun {
		return nil
	}
	return m.remove(cronBackup)
}

// recordStopped adds service names to the stop record Restore reads.
func (m *Manager) recordStopped(names []string) error {
	cur, err := m.readLines(stoppedFile)
	if err != nil {
		return err
	}
	n := len(cur)
	for _, s := range names {
		if !slices.Contains(cur, s) {
			cur = append(cur, s)
		}
	}
	if len(cur) == n {
		return nil
	}
	return m.writeFile(stoppedFile, cur, 0o644)
}

// readLines reads a device file as lines; a missing file is empty.
func (m *Manager) readLines(p string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(m.o.Root, p))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	b = bytes.TrimRight(b, "\n")
	if len(b) == 0 {
		return nil, nil
	}
	return strings.Split(string(b), "\n"), nil
}

// writeFile atomically replaces a device file with lines.
func (m *Manager) writeFile(p string, lines []string, perm os.FileMode) error {
	return m.writeRaw(p, []byte(joinLines(lines)), perm)
}

// writeRaw atomically replaces a device file: it writes a temporary file in
// stateDir (the same ramfs as the rest of /etc) and renames it into place
// (not atomicfile.Write, whose temporary file is beside the target).
func (m *Manager) writeRaw(p string, data []byte, perm os.FileMode) error {
	tmp, err := m.writeTemp(data, perm)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(m.o.Root, p)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// writeTemp writes data to a new temporary file in stateDir and returns its
// path.
func (m *Manager) writeTemp(data []byte, perm os.FileMode) (string, error) {
	dir := filepath.Join(m.o.Root, stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// remove deletes a device file; a missing file is fine.
func (m *Manager) remove(p string) error {
	err := os.Remove(filepath.Join(m.o.Root, p))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
