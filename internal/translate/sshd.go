// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"fmt"
	"strings"
)

// SSHDIntent is the controller's device SSH server switch (the site's
// "Device SSH Authentication"). The controller sends the site users
// (users.N) either way; the switch is the sshd section. Seen on Network
// 10.x (192.168.0.205, system_cfg history, 2026-11-19):
//
//	on:  sshd.status=enabled,  sshd.1.status=enabled, sshd.1.ifname=br0
//	off: sshd.status=disabled, sshd.1.status=enabled, sshd.1.ifname=lo
//
// A UniFi AP keeps the accounts while off, but its dropbear then listens
// on the loopback only.
type SSHDIntent struct {
	Enabled   bool      // sshd.status=enabled
	Ifnames   []string  // sshd.N.ifname of the enabled sshd.N, in order
	Passwords bool      // password logins: sshd.auth.passwd is not "disabled"
	Keys      []SSHDKey // the site's Device SSH keys (sshd.auth.key.N)
}

// SSHDKey is one of the site's Device SSH keys. The controller writes them
// as sshd.auth.key.N.{status,type,value,comment} (Network 10.6
// com.ubnt.service.config.RngEFIxepjqE); a UniFi AP's dropbear accepts them
// for the site login. Public keys, not secrets.
type SSHDKey struct {
	Type    string // e.g. ssh-ed25519, ssh-rsa
	Value   string // the base64 key blob
	Comment string
}

// AuthorizedKey is the key as an authorized_keys line.
func (k SSHDKey) AuthorizedKey() string { return k.Type + " " + k.Value }

// SSHD reads the sshd section; nil when the controller sent none.
func SSHD(cfg Cfg) *SSHDIntent {
	if _, ok := cfg["sshd.status"]; !ok {
		return nil
	}
	s := &SSHDIntent{Enabled: cfg["sshd.status"] == "enabled", Passwords: cfg["sshd.auth.passwd"] != "disabled"}
	for _, n := range indices(cfg, "sshd") {
		p := "sshd." + n + "."
		if cfg[p+"status"] == "disabled" {
			continue
		}
		if ifn := strings.TrimSpace(cfg[p+"ifname"]); ifn != "" {
			s.Ifnames = append(s.Ifnames, ifn)
		}
	}
	for _, n := range indices(cfg, "sshd.auth.key") {
		p := "sshd.auth.key." + n + "."
		if cfg[p+"status"] == "disabled" {
			continue
		}
		k := SSHDKey{Type: strings.TrimSpace(cfg[p+"type"]), Value: strings.TrimSpace(cfg[p+"value"]), Comment: cfg[p+"comment"]}
		if k.Type != "" && k.Value != "" {
			s.Keys = append(s.Keys, k)
		}
	}
	return s
}

// LANLogins reports whether the switch lets the site users log in from
// the LAN: the server is enabled, takes passwords or has keys, and one of
// its listeners is a LAN interface (anything but the loopback). A missing
// section (nil) is off.
func (s *SSHDIntent) LANLogins() bool {
	if s == nil || !s.Enabled || !s.Passwords && len(s.Keys) == 0 {
		return false
	}
	for _, ifn := range s.Ifnames {
		if ifn != "lo" && !strings.HasPrefix(ifn, "lo:") {
			return true
		}
	}
	return false
}

func (s SSHDIntent) String() string {
	return fmt.Sprintf("sshd enabled=%t ifnames=%s passwords=%t keys=%d", s.Enabled, strings.Join(s.Ifnames, ","), s.Passwords, len(s.Keys))
}
