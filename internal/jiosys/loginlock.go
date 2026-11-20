// SPDX-License-Identifier: GPL-2.0-or-later

package jiosys

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/dtechterminal/udeco/internal/decosys"
)

// lockPorts are the Garage's root logins: telnetd (:23, the root password
// in clear text) and :22 should an SSH server ever run.
var lockPorts = []int{23, 22}

// binDirs is where the Garage's iptables live: Jio's own build first.
var binDirs = []string{"/pfrm2.0/bin", "/usr/sbin", "/sbin", "/usr/bin", "/bin"}

func (m *Manager) bin(name string) string {
	for _, d := range binDirs {
		if fileExists(filepath.Join(m.o.Root, d, name)) {
			return d + "/" + name
		}
	}
	return name
}

// LoginLock locks (on) or unlocks the Garage's root login ports, IPv4 and
// IPv6, with decosys.LoginLock: the same chain and rules as the Deco's,
// for :23 and :22, run without -w (not known to be supported by Jio's
// iptables). It fails open; no iptables is decosys.ErrNoIptables.
func (m *Manager) LoginLock(ctx context.Context, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loginLock(ctx, on)
}

func (m *Manager) loginLock(ctx context.Context, on bool) error {
	l := decosys.LoginLock{Run: m.o.Run, IPv4: m.bin("iptables"), IPv6: m.bin("ip6tables"), Ports: lockPorts,
		Logf: func(f string, a ...any) { m.o.Logf("jiosys: "+f, a...) }}
	if m.o.Run == nil {
		if !on {
			return nil
		}
		return errors.New("login lock: no command runner")
	}
	_, err := l.Set(ctx, on)
	return err
}

// Restore is the hand-back: the login lock goes; the Jio services stay
// down (the owner's choice).
func (m *Manager) Restore(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loginLock(ctx, false)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
