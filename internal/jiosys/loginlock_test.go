// SPDX-License-Identifier: GPL-2.0-or-later

package jiosys

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
)

const (
	jipt  = "/pfrm2.0/bin/iptables"
	jip6t = "/pfrm2.0/bin/ip6tables"
)

// garageInput is 'iptables -S INPUT' as read on the Garage (2026-11-20),
// head only.
const garageInput = `-P INPUT DROP
-A INPUT -p tcp -m tcp --dport 23 -m ifgroup --src-group 0x1/0x1 -j ACCEPT
-A INPUT -j fwAntiSpoof
-A INPUT -i lo -j ACCEPT
-A INPUT -j fwLanToBox
`

// fakeRun records commands and answers from a script; the last answer
// repeats.
type fakeRun struct {
	mu    sync.Mutex
	calls []string
	resp  map[string][]fakeResp
}

type fakeResp struct {
	out string
	err error
}

func (f *fakeRun) on(cmd, out string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resp == nil {
		f.resp = map[string][]fakeResp{}
	}
	f.resp[cmd] = append(f.resp[cmd], fakeResp{out, err})
}

func (f *fakeRun) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	rs := f.resp[line]
	if len(rs) == 0 {
		return nil, nil
	}
	r := rs[0]
	if len(rs) > 1 {
		f.resp[line] = rs[1:]
	}
	return []byte(r.out), r.err
}

var errExit1 = errors.New("exit status 1")

func garageRoot(t *testing.T, bins ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, b := range bins {
		p := filepath.Join(root, b)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// The Garage's lock drops new telnet (:23) and SSH (:22) connections, for
// IPv4 and IPv6, with /pfrm2.0/bin's iptables and without -w (not known
// to be supported there); established sessions and loopback RETURN first.
func TestGarageLoginLockInstall(t *testing.T) {
	root := garageRoot(t, jipt, jip6t)
	r := &fakeRun{}
	for _, b := range []string{jipt, jip6t} {
		r.on(b+" -S UDECO-LOCK", "", errExit1)
		r.on(b+" -S INPUT", garageInput, nil)
	}
	m := New(Options{Root: root, Run: r})
	if err := m.LoginLock(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, b := range []string{jipt, jip6t} {
		want = append(want,
			b+" -S UDECO-LOCK",
			b+" -N UDECO-LOCK",
			b+" -A UDECO-LOCK -i lo -j RETURN",
			b+" -A UDECO-LOCK -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
			b+" -A UDECO-LOCK -p tcp -m tcp --dport 23 -j DROP",
			b+" -A UDECO-LOCK -p tcp -m tcp --dport 22 -j DROP",
			b+" -S INPUT",
			b+" -I INPUT 1 -j UDECO-LOCK")
	}
	if !slices.Equal(r.calls, want) {
		t.Errorf("commands\n got: %s\nwant: %s", strings.Join(r.calls, "\n      "), strings.Join(want, "\n      "))
	}
}

// Unlocking, and the hand-back (Restore), remove the jump and the chain.
func TestGarageLoginLockOffAndRestore(t *testing.T) {
	for _, restore := range []bool{false, true} {
		root := garageRoot(t, jipt, jip6t)
		r := &fakeRun{}
		for _, b := range []string{jipt, jip6t} {
			r.on(b+" -S INPUT", "-P INPUT DROP\n-A INPUT -j UDECO-LOCK\n"+strings.TrimPrefix(garageInput, "-P INPUT DROP\n"), nil)
			r.on(b+" -S UDECO-LOCK", "-N UDECO-LOCK\n", nil)
		}
		m := New(Options{Root: root, Run: r})
		var err error
		if restore {
			err = m.Restore(context.Background())
		} else {
			err = m.LoginLock(context.Background(), false)
		}
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, b := range []string{jipt, jip6t} {
			want = append(want, b+" -S INPUT", b+" -D INPUT -j UDECO-LOCK", b+" -S UDECO-LOCK", b+" -F UDECO-LOCK", b+" -X UDECO-LOCK")
		}
		if !slices.Equal(r.calls, want) {
			t.Errorf("restore=%v: commands\n got: %s\nwant: %s", restore, strings.Join(r.calls, "\n      "), strings.Join(want, "\n      "))
		}
	}
}

// A failed append leaves the Garage open: the chain is never jumped to,
// and what was added is removed.
func TestGarageLoginLockFailsOpen(t *testing.T) {
	root := garageRoot(t, jipt, jip6t)
	r := &fakeRun{}
	for _, b := range []string{jipt, jip6t} {
		r.on(b+" -S UDECO-LOCK", "", errExit1)
		r.on(b+" -S INPUT", garageInput, nil)
	}
	r.on(jipt+" -A UDECO-LOCK -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN", "", errExit1)
	r.on(jipt+" -S UDECO-LOCK", "-N UDECO-LOCK\n-A UDECO-LOCK -i lo -j RETURN\n", nil)
	m := New(Options{Root: root, Run: r})
	if err := m.LoginLock(context.Background(), true); err == nil {
		t.Fatal("want an error")
	}
	for _, c := range r.calls {
		if strings.Contains(c, "-j DROP") || strings.Contains(c, "-I INPUT") {
			t.Errorf("ran %q", c)
		}
	}
	if !slices.Contains(r.calls, jipt+" -X UDECO-LOCK") {
		t.Errorf("the half-built chain stayed: %v", r.calls)
	}
}

// No iptables on the unit (or no runner): no lock, and Restore still
// succeeds.
func TestGarageLoginLockNoIptables(t *testing.T) {
	r := &fakeRun{}
	m := New(Options{Root: garageRoot(t), Run: r})
	if err := m.LoginLock(context.Background(), true); !errors.Is(err, decosys.ErrNoIptables) {
		t.Errorf("err %v, want ErrNoIptables", err)
	}
	if err := m.Restore(context.Background()); err != nil {
		t.Errorf("restore: %v", err)
	}
	if len(r.calls) != 0 {
		t.Errorf("ran %v", r.calls)
	}
	if err := New(Options{Root: garageRoot(t, jipt)}).LoginLock(context.Background(), true); err == nil {
		t.Error("no runner: want an error")
	}
}
