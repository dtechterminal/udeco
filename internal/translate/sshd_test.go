// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"strings"
	"testing"
)

// The controller's Device SSH switch as system_cfg carries it (on and off
// as seen on 192.168.0.205): the users are sent either way, only the sshd
// section changes.
func TestSSHDSwitch(t *testing.T) {
	users := "users.status=enabled\nusers.1.status=enabled\nusers.1.name=3r4FNrkS\nusers.1.password=$6$s$h\n"
	for _, c := range []struct {
		name, cfg string
		on        bool
		nilIntent bool
	}{
		{"on", "sshd.status=enabled\nsshd.auth.passwd=enabled\nsshd.1.status=enabled\nsshd.1.ifname=br0\n", true, false},
		{"off", "sshd.status=disabled\nsshd.1.status=enabled\nsshd.1.ifname=lo\n", false, false},
		{"enabled on lo", "sshd.status=enabled\nsshd.1.status=enabled\nsshd.1.ifname=lo\n", false, false},
		{"disabled on br0", "sshd.status=disabled\nsshd.1.status=enabled\nsshd.1.ifname=br0\n", false, false},
		{"no ifname", "sshd.status=enabled\n", false, false},
		{"listener disabled", "sshd.status=enabled\nsshd.1.status=disabled\nsshd.1.ifname=br0\n", false, false},
		{"passwords off", "sshd.status=enabled\nsshd.auth.passwd=disabled\nsshd.1.status=enabled\nsshd.1.ifname=br0\n", false, false},
		{"lo and br0", "sshd.status=enabled\nsshd.1.status=enabled\nsshd.1.ifname=lo\nsshd.2.status=enabled\nsshd.2.ifname=br0\n", true, false},
		{"not sent", "", false, true},
	} {
		in, _ := IntentFromCfg(users + c.cfg)
		if got := in.SSHD.LANLogins(); got != c.on {
			t.Errorf("%s: LANLogins %v, want %v (%v)", c.name, got, c.on, in.SSHD)
		}
		if (in.SSHD == nil) != c.nilIntent {
			t.Errorf("%s: intent %v", c.name, in.SSHD)
		}
		if len(in.Users) != 1 {
			t.Errorf("%s: users %v", c.name, in.Users)
		}
		if strings.Contains(in.String(), "$6$") {
			t.Errorf("%s: hash printed: %s", c.name, in)
		}
	}
}

// The site's Device SSH keys (sshd.auth.key.N, as Network 10.6 writes
// them): enabled ones are kept; keys alone open LAN logins even with
// passwords disabled.
func TestSSHDKeys(t *testing.T) {
	cfg := Cfg{"sshd.status": "enabled", "sshd.1.status": "enabled", "sshd.1.ifname": "br0", "sshd.auth.passwd": "disabled",
		"sshd.auth.key.1.status": "enabled", "sshd.auth.key.1.type": "ssh-ed25519", "sshd.auth.key.1.value": "AAAAC3NzaC1lZDI1NTE5AAAAIA", "sshd.auth.key.1.comment": "mac",
		"sshd.auth.key.2.status": "disabled", "sshd.auth.key.2.type": "ssh-rsa", "sshd.auth.key.2.value": "AAAAB3",
		"sshd.auth.key.3.status": "enabled", "sshd.auth.key.3.type": "", "sshd.auth.key.3.value": "x"}
	s := SSHD(cfg)
	if len(s.Keys) != 1 || s.Keys[0].Comment != "mac" || s.Keys[0].AuthorizedKey() != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA" {
		t.Fatalf("keys %+v", s.Keys)
	}
	if s.Passwords || !s.LANLogins() {
		t.Errorf("passwords=%t lan=%t", s.Passwords, s.LANLogins())
	}
	delete(cfg, "sshd.auth.key.1.status")
	delete(cfg, "sshd.auth.key.1.type")
	if SSHD(cfg).LANLogins() {
		t.Error("no password and no key: logins on")
	}
}
