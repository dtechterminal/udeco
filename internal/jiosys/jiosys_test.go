// SPDX-License-Identifier: GPL-2.0-or-later

package jiosys

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func fakeProc(t *testing.T, root string, pid int, argv ...string) {
	t.Helper()
	d := filepath.Join(root, "proc", strconv.Itoa(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMatch(t *testing.T) {
	for _, c := range []struct {
		argv []string
		want string
	}{
		{[]string{"/pfrm2.0/bin/dms", "-c", "/var/twine/dms/xml"}, "dms"},
		{[]string{"/pfrm2.0/bin/ras", "-c", "/var/twine/ras/xml"}, "ras"},
		{[]string{"/userfs/bin/svchost", "-c", "/etc/mesh.svc"}, "mesh.svc"},
		{[]string{"/userfs/bin/svchost", "-c", "/etc/cfg.svc"}, ""}, // tcapi's config store
		{[]string{"/pfrm2.0/bin/captivePortald", "/tmp/system.db"}, "captivePortald"},
		{[]string{"/pfrm2.0/bin/rasterize"}, "rasterize"[:0]},            // "ras" is no prefix match (too short)
		{[]string{"/pfrm2.0/bin/smartcableONTAppX"}, "smartcableONTApp"}, // long patterns match a prefix
		{[]string{"/usr/sbin/telnetd"}, ""},
		{[]string{"/pfrm2.0/bin/lighttpd", "-f", "/pfrm2.0/etc/lighttpd.conf"}, "lighttpd"}, // web UI kept down
		{[]string{"/tmp/udeco-bin/udeco-ap", "-config", "/flash2/udeco/udeco-ap.json"}, ""},
	} {
		if got := match(c.argv, DefaultKeepDown); got != c.want {
			t.Errorf("match(%q) = %q, want %q", c.argv, got, c.want)
		}
	}
}

// TestEnforceTermThenKill: SIGTERM first; a process still there on the next
// pass gets SIGKILL (dms, ras and the service hosts ignore SIGTERM).
func TestEnforceTermThenKill(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 1, "init")
	fakeProc(t, root, 100, "/userfs/bin/svchost", "-c", "/etc/cfg.svc")
	fakeProc(t, root, 200, "/pfrm2.0/bin/dms", "-c", "/var/twine/dms/xml")
	fakeProc(t, root, 300, "/usr/sbin/telnetd")
	fakeProc(t, root, 400, "/pfrm2.0/bin/captivePortald", "/tmp/system.db")
	var sent []string
	m := New(Options{Root: root, self: 999, kill: func(pid int, sig syscall.Signal) error {
		sent = append(sent, strconv.Itoa(pid)+":"+strconv.Itoa(int(sig)))
		if pid == 400 {
			os.RemoveAll(filepath.Join(root, "proc", "400")) // exits on SIGTERM
		}
		return nil
	}})
	rep, err := m.Enforce(context.Background())
	if err != nil || len(rep.Steps) != 2 {
		t.Fatalf("first pass: %d steps, %v", len(rep.Steps), err)
	}
	rep, err = m.Enforce(context.Background())
	if err != nil || len(rep.Steps) != 1 || rep.Steps[0].Reason != "ignored SIGTERM" {
		t.Fatalf("second pass: %+v, %v", rep.Steps, err)
	}
	want := "200:15 400:15 200:9"
	if got := strings.Join(sent, " "); got != want {
		t.Errorf("signals %q, want %q", got, want)
	}
	os.RemoveAll(filepath.Join(root, "proc", "200"))
	rep, _ = m.Enforce(context.Background())
	if len(rep.Steps) != 0 || m.Counts()["jio-stopped"] != 2 {
		t.Errorf("third pass: %d steps, counts %v", len(rep.Steps), m.Counts())
	}
	// dms comes back: SIGTERM again, reported as foreign
	fakeProc(t, root, 500, "/pfrm2.0/bin/dms", "-c", "/var/twine/dms/xml")
	rep, _ = m.Enforce(context.Background())
	if len(rep.Steps) != 1 || len(rep.Foreign) != 1 {
		t.Errorf("respawn: %d steps, %d foreign", len(rep.Steps), len(rep.Foreign))
	}
}

// TestKeepOnly: in dumb-AP mode everything stops except the kept programs
// and what they started (a telnet session's commands, the agent's tools).
func TestKeepOnly(t *testing.T) {
	root := t.TempDir()
	proc := func(pid, ppid int, argv ...string) {
		fakeProc(t, root, pid, argv...)
		st := strconv.Itoa(pid) + " (" + filepath.Base(argv[0]) + ") S " + strconv.Itoa(ppid) + " 0 0"
		if err := os.WriteFile(filepath.Join(root, "proc", strconv.Itoa(pid), "stat"), []byte(st), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	proc(1, 0, "init")
	proc(119, 1, "/userfs/bin/svchost", "-c", "/etc/cfg.svc")
	proc(893, 1, "/usr/sbin/telnetd")
	proc(900, 893, "-sh")
	proc(901, 900, "ps")
	proc(1033, 1, "/pfrm2.0/bin/lighttpd", "-f", "/pfrm2.0/etc/lighttpd.conf")
	proc(4411, 1, "/pfrm2.0/bin/udevd", "--daemon")
	proc(4825, 1, "/sbin/getty", "-L", "ttyS0")
	proc(6204, 1, "/pfrm2.0/bin/dnsmasq", "-x", "/var/run/dnsmasq.pid.IF1")
	proc(7000, 1, "/bin/sh", "/flash2/pfrm2.0/etc/customInit")
	proc(7001, 7000, "sleep", "1")
	proc(8000, 1, "sh", "/tmp/other.sh")
	proc(9126, 1, "sh", "/flash2/udeco/start.sh")
	proc(9134, 9126, "/tmp/udeco-bin/udeco-ap", "-config", "/flash2/udeco/udeco-ap.json")
	proc(9200, 9134, "iwpriv", "ra0", "show", "stainfo")
	// the agent's 802.1X authenticator, forked away to init: kept; the
	// vendor's 5 GHz copy is not
	proc(9300, 1, "/userfs/bin/rtdot1xd", "-p", "rai", "-i", "rai0")
	proc(9301, 1, "/userfs/bin/rtdot1xd_AC")
	var got []string
	m := New(Options{Root: root, self: 9134, KeepOnly: DefaultKeepOnly, kill: func(pid int, sig syscall.Signal) error {
		got = append(got, strconv.Itoa(pid))
		return nil
	}})
	rep, err := m.Enforce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := "119 1033 4411 6204 8000 9301"; strings.Join(got, " ") != want {
		t.Errorf("stopped %q, want %q", strings.Join(got, " "), want)
	}
	if len(rep.Steps) != 6 || !strings.Contains(rep.Steps[0].Reason, "dumb AP") {
		t.Errorf("steps %+v", rep.Steps)
	}
}
