package decosys

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestGuardDetects(t *testing.T) {
	cases := []struct {
		name    string
		procs   map[int][]string
		files   []string
		upgrade bool
		boot    bool
		rebuild bool
	}{
		{name: "quiet", procs: map[int][]string{1: {"/sbin/procd"}, 2: {"/usr/sbin/nvrammanager", "-r", "/tmp/x"}}},
		{name: "upgrade script", procs: map[int][]string{9: {"/bin/sh", "/usr/bin/upgrade", "/tmp/fw.bin"}}, upgrade: true},
		{name: "flash write", procs: map[int][]string{9: {"nvrammanager", "-u", "/tmp/fw.bin"}}, upgrade: true},
		{name: "image download", procs: map[int][]string{9: {"/usr/bin/sshhttpget", "192.168.0.241"}}, upgrade: true},
		{name: "flag file", files: []string{"tmp/firmware_upgrade_flag"}, upgrade: true},
		{name: "force pid", files: []string{"var/run/force_upgrade.pid"}, upgrade: true},
		{name: "staged image", files: []string{"tmp/upgrade/fw.bin"}, upgrade: true},
		{name: "empty upgrade dir is normal", files: []string{"tmp/upgrade/"}},
		{name: "boot chain", procs: map[int][]string{9: {"/bin/sh", "/etc/rc.common", "/etc/rc.d/S99zzz", "boot"}}, boot: true},
		{name: "rebuild", procs: map[int][]string{9: {"/bin/sh", "/etc/rc.common", "/etc/init.d/repacd", "restart"}}, rebuild: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := newUnit(t, "205")
			u.setProcs(c.procs)
			for _, f := range c.files {
				if strings.HasSuffix(f, "/") {
					u.write(f+".keep", "")
					u.rm(f + ".keep")
				} else {
					u.write(f, "1")
				}
			}
			g, err := New(Options{Root: u.root, Run: newFakeRun()}).Guard(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if (len(g.Upgrade) > 0) != c.upgrade || (len(g.Boot) > 0) != c.boot || (len(g.Rebuild) > 0) != c.rebuild {
				t.Errorf("guard = %+v", g)
			}
		})
	}
}

// R17: while an upgrade is in flight or the boot chain runs, Enforce does
// not stop tmpsvr or dropbear :20001 (it still stops the rest), and warns.
func TestEnforceHoldsManagement(t *testing.T) {
	for _, c := range []struct {
		name  string
		extra []string
		file  string
		warn  string
	}{
		{name: "upgrade", extra: []string{"/usr/sbin/nvrammanager", "-u", "/tmp/fw.bin"}, warn: WarnUpgrade},
		{name: "upgrade flag", file: "tmp/firmware_upgrade_flag", warn: WarnUpgrade},
		{name: "boot", extra: []string{"/bin/sh", "/etc/rc.common", "/etc/rc.d/S99cloud_client", "boot"}, warn: WarnBoot},
	} {
		t.Run(c.name, func(t *testing.T) {
			u := newUnit(t, "205")
			ps := readProcsFixture(t, "205")
			if c.extra != nil {
				ps[31000] = c.extra
			}
			u.setProcs(ps)
			if c.file != "" {
				u.write(c.file, "1")
			}
			r := newFakeRun()
			r.on("/bin/ubus call service list", string(readFixture(t, "ubus-service-list-205.json")), nil)
			rep, err := newManager(u, r, false).Enforce(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			calls := r.take()
			for _, c := range calls {
				if strings.Contains(c, "tmpsvr") || strings.Contains(c, "dropbear") || strings.Contains(c, " 6244") ||
					strings.Contains(c, " 31000") {
					t.Errorf("ran %q while held", c)
				}
			}
			if !slices.Contains(calls, "/etc/init.d/awn stop") {
				t.Error("the rest of the takeover did not run")
			}
			if !slices.ContainsFunc(rep.Warnings, func(w string) bool { return strings.HasPrefix(w, c.warn) }) {
				t.Errorf("warnings %q lack %q", rep.Warnings, c.warn)
			}
			if !rep.Guard.Hold() {
				t.Error("Report.Guard empty")
			}
		})
	}
}

// Nothing on the flash path is ever signalled, whatever matched it.
func TestKillNeverSignalsProtected(t *testing.T) {
	u := newUnit(t, "205")
	u.setProcs(map[int][]string{1: {"/sbin/procd"}, 50: {"/usr/sbin/nvrammanager", "-r", "/tmp/a"},
		51: {"/bin/sh", "/usr/bin/upgrade"}, 52: {"acsd2"}})
	r := newFakeRun()
	m := newManager(u, r, false)
	s := m.killStep("x", "test", []int{50, 51, 52}, func([]string) bool { return true })
	if err := m.exec(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{"/bin/kill 52"})
}
