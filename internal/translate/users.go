// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"regexp"
	"sort"
	"strings"
)

// User is a device login the controller wants (system_cfg users.N: the
// site's "Device Authentication"). Hash is a crypt(3) hash: a secret.
type User struct {
	Name string
	Hash string
}

var (
	// A login safe for /etc/passwd and busybox: no ':' or whitespace, no
	// leading '-' (option injection). A leading digit is allowed: Network
	// 11.1.50 generates 8-character logins that can start with one. An
	// all-digit name is refused (tools read it as a UID).
	userName  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$`)
	allDigits = regexp.MustCompile(`^[0-9]+$`)
	cryptHash = regexp.MustCompile(`^\$[0-9a-z]+\$[^:\s]+$`)
	// never managed: the AP's own accounts
	systemUsers = map[string]bool{"root": true, "nobody": true, "daemon": true, "ftp": true, "network": true, "dnsmasq": true, "ntp": true, "logd": true, "ubus": true}
)

// LoginNamePattern is the pattern a device login's name must match, as
// text, and SystemUsers the names never taken from the controller. They are
// for the test that holds internal/device's second check of a site login
// (SiteLoginNamePattern, SiteSystemUsers) to this one: the two checks stay
// separate code on purpose.
func LoginNamePattern() string { return userName.String() }

// SystemUsers is a copy of the AP's own accounts, sorted.
func SystemUsers() []string {
	out := make([]string, 0, len(systemUsers))
	for n := range systemUsers {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Users returns the admin logins from system_cfg (enabled, with a valid name
// and crypt hash, not an AP system account) and notes about skipped ones.
func Users(cfg Cfg) ([]User, []string) {
	if cfg["users.status"] != "enabled" {
		return nil, nil
	}
	var out []User
	var notes []string
	for _, n := range indices(cfg, "users") {
		p := "users." + n + "."
		name, hash := cfg[p+"name"], cfg[p+"password"]
		switch {
		case cfg[p+"status"] != "enabled":
		case systemUsers[name]:
			notes = append(notes, "users."+n+": "+name+" is an AP system account: left alone")
		case strings.HasSuffix(cfg[p+"shell"], "/false"):
			notes = append(notes, "users."+n+": "+name+" has no shell: skipped")
		case !userName.MatchString(name) || allDigits.MatchString(name) || !cryptHash.MatchString(hash):
			notes = append(notes, "users."+n+": bad name or password hash: skipped")
		default:
			out = append(out, User{Name: name, Hash: hash})
		}
	}
	return out, notes
}
