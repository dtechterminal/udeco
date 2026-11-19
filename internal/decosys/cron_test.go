package decosys

// Crontab fixtures:
//   crontab-205-live   read on .205 on 2026-11-18 after its reboot
//                      ('sh /data/persist_shell.sh' first, TP-Link jobs back).
//   crontab-232        reconstructed from interference-audit.md B3(a): .232's
//                      crontab without any persist line (TP-Link jobs only).
//   crontab-241-pgrep  reconstructed from B2/B3(a): .241's crontab holding
//                      only its keepalive line, which runs /data/dropbear
//                      but not persist_shell.sh. The exact line is
//                      representative, not captured.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// R15: interpreter-prefixed and literal TP-Link jobs.
func TestCronClassificationR15(t *testing.T) {
	for line, tp := range map[string]bool{
		"*/10 * * * * echo 3 > /proc/sys/vm/drop_caches":                          true,
		"*/10 * * * * echo 3 >/proc/sys/vm/drop_caches":                           true,
		"0 3 * * * sh /lib/snort/checkSnortRules.sh /tmp/rules":                   true,
		"*/1 * * * * sh /lib/netifd/dhcp6c_slaac.sh &":                            true,
		"36 14 29 11 2026 /usr/sbin/report_get_device_status":                     true,
		"*/5 * * * * lua /usr/lib/lua/luci/x.lua":                                 true,
		"*/5 * * * * /bin/sh /usr/sbin/tmpsvr_check":                              true,
		"* * * * * sh /data/persist_shell.sh":                                     false,
		"* * * * * sh -c '/usr/sbin/x'":                                           false,
		"*/10 * * * * echo 1 > /proc/sys/vm/drop_caches":                          false,
		"* * * * * pgrep -f '^/data/dropbear -p 22' >/dev/null || /data/dropbear": false,
	} {
		if got := isTPLinkCron(line); got != tp {
			t.Errorf("isTPLinkCron(%q) = %v, want %v", line, got, tp)
		}
	}
}

// R16: the persist line exists exactly once, duplicates collapse, every
// other user line stays.
func TestCronInvariant(t *testing.T) {
	dup64 := strings.Repeat(persistLine+"\n", 64)
	cases := []struct {
		name, in, want string
	}{
		{"232 adds the line", string(readFixture(t, "crontab-232")), persistLine + "\n"},
		{"241 adds the line and keeps the pgrep line", string(readFixture(t, "crontab-241-pgrep")),
			"* * * * * pgrep -f '^/data/dropbear -p 22' >/dev/null || /data/dropbear -p 22 -r /data/ssh_host_ed25519 -s -j -k\n" +
				persistLine + "\n"},
		{"64 duplicates collapse", dup64, persistLine + "\n"},
		{"205 live keeps its line", string(readFixture(t, "crontab-205-live")), persistLine + "\n"},
		{"205 captured keeps its spelling", string(readFixture(t, "crontab-205")), "* * * * * /data/persist_shell.sh\n"},
		{"spellings: one every-minute line wins", "*/5 * * * * /data/persist_shell.sh\n# mine\n* * * * * sh /data/persist_shell.sh\n* * * * * /data/persist_shell.sh\n",
			"# mine\n" + persistLine + "\n"},
		{"user lines and comments stay, user duplicates collapse",
			"# a\n# a\nPATH=/usr/sbin\n*/5 * * * * /tp_data/x.sh\n*/5 * * * * /tp_data/x.sh\n* * * * * test -x /data/persist_shell.sh && sh /data/persist_shell.sh\n",
			"# a\n# a\nPATH=/usr/sbin\n*/5 * * * * /tp_data/x.sh\n* * * * * test -x /data/persist_shell.sh && sh /data/persist_shell.sh\n"},
		{"empty", "", persistLine + "\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := newUnit(t, "205")
			u.setProcs(map[int][]string{1: {"/sbin/procd"}})
			u.write("etc/crontabs/root", c.in)
			m := New(Options{Root: u.root, Run: newFakeRun()})
			m.triggersClean, m.triggersAt = true, time.Now()
			if _, err := m.Enforce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := u.read("etc/crontabs/root"); got != c.want {
				t.Errorf("crontab =\n%s\nwant\n%s", got, c.want)
			}
			// Holds: the next pass has nothing to do.
			p, err := m.Plan(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range p {
				if s.Kind == KindCron {
					t.Errorf("crontab still planned: %s", s)
				}
			}
		})
	}
}

// R16 / B3(d): a line appended while the rewrite runs is not lost.
func TestCronRewriteKeepsConcurrentAppend(t *testing.T) {
	u := newUnit(t, "205")
	u.setProcs(map[int][]string{1: {"/sbin/procd"}})
	m := New(Options{Root: u.root, Run: newFakeRun()})
	m.triggersClean, m.triggersAt = true, time.Now()
	appended := 0
	m.beforeCronRename = func() {
		if appended == 0 {
			f, err := os.OpenFile(filepath.Join(u.root, "etc/crontabs/root"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			f.WriteString("*/2 * * * * /tp_data/late.sh\n")
			f.Close()
		}
		appended++
	}
	if _, err := m.Enforce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := u.read("etc/crontabs/root"), "* * * * * /data/persist_shell.sh\n*/2 * * * * /tp_data/late.sh\n"; got != want {
		t.Errorf("crontab = %q, want %q", got, want)
	}
	if appended != 2 {
		t.Errorf("rename attempts = %d, want 2 (one retry)", appended)
	}
}

// The crontab is the user's: Restore puts TP-Link's jobs back but keeps
// the supervision line the takeover added.
func TestRestoreKeepsPersistLine(t *testing.T) {
	u := newUnit(t, "205")
	u.setProcs(map[int][]string{1: {"/sbin/procd"}})
	u.write("etc/crontabs/root", string(readFixture(t, "crontab-232")))
	r := newFakeRun()
	for _, b := range []string{ipt, ip6t} {
		r.on(b+" -w -C OUTPUT -j UDECO-OUT", "", errExit1)
		r.on(b+" -w -S UDECO-OUT", "", errExit1)
		r.on(b+" -w -C INPUT -j UDECO-IN", "", errExit1)
		r.on(b+" -w -S UDECO-IN", "", errExit1)
	}
	m := New(Options{Root: u.root, Run: r})
	m.triggersClean, m.triggersAt = true, time.Now()
	if _, err := m.Enforce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := u.read("etc/crontabs/root")
	for _, l := range append(strings.Split(strings.TrimSpace(string(readFixture(t, "crontab-232"))), "\n"), persistLine) {
		if !strings.Contains(got, l+"\n") {
			t.Errorf("restored crontab lacks %q:\n%s", l, got)
		}
	}
}
