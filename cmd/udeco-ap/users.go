// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Site SSH logins (system_cfg users.N, the site's "Device Authentication"),
// as a UniFi AP installs them (ubntconf: uid 0, shell /bin/ash): the agent
// adds and removes only the accounts it manages, marked by their GECOS
// field, in /etc/passwd and /etc/shadow. /etc is a ramfs, so the accounts
// are re-asserted at start (the startup provision) and on every Enforce
// tick. root, the unit's system accounts and any account the agent did not
// create are never touched; a site user with the name of one of those is
// skipped. Takeover mode only. Hashes are never logged.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// userGECOS marks the accounts the agent manages.
const userGECOS = "udeco-ap site user"

// syncUsers makes the managed accounts equal want (worker goroutine);
// verbose also logs the users that were skipped (once per provision, not
// every tick).
func (a *agent) syncUsers(want []translate.User, verbose bool) {
	changes, skipped, err := syncUserFiles(a.dev("/etc/passwd"), a.dev("/etc/shadow"), want, a.o.now())
	if err != nil {
		a.logf("site users: %v", err)
	}
	if verbose {
		changes = append(changes, skipped...)
	}
	for _, c := range changes {
		a.logf("site users: %s", c)
	}
	a.siteInstalled(want) // who may log in on sshd_port (sitessh.go)
}

// syncUserFiles edits passwd and shadow so that exactly the users in want
// carry the agent's mark. It returns what it changed and what it skipped
// (names only); the files are written only when something changed.
func syncUserFiles(passwdPath, shadowPath string, want []translate.User, now time.Time) (changes, skipped []string, err error) {
	pw, err := os.ReadFile(passwdPath)
	if err != nil {
		return nil, nil, err
	}
	sh, err := os.ReadFile(shadowPath)
	if err != nil {
		return nil, nil, err
	}
	pwLines, shLines := splitLines(pw), splitLines(sh)
	ours, foreign := map[string]bool{}, map[string]bool{}
	for _, l := range pwLines {
		f := strings.Split(l, ":")
		if len(f) < 7 || f[0] == "" {
			continue
		}
		if f[4] == userGECOS && f[0] != "root" {
			ours[f[0]] = true
		} else {
			foreign[f[0]] = true
		}
	}
	wanted := map[string]string{}
	for _, u := range want {
		switch {
		case u.Name == "" || u.Name == "root" || foreign[u.Name]:
			skipped = append(skipped, fmt.Sprintf("%s: an account of the unit with that name exists: left alone, not managed", u.Name))
		case strings.ContainsAny(u.Name+u.Hash, ":\n") || !strings.HasPrefix(u.Hash, "$"):
			skipped = append(skipped, u.Name+": unusable name or hash: skipped")
		default:
			wanted[u.Name] = u.Hash
		}
	}
	days := strconv.FormatInt(now.Unix()/86400, 10)
	var newPw, newSh []string
	for _, l := range pwLines {
		name, _, _ := strings.Cut(l, ":")
		if ours[name] && wanted[name] == "" {
			changes = append(changes, name+": removed")
			continue
		}
		newPw = append(newPw, l)
	}
	seenSh := map[string]bool{}
	for _, l := range shLines {
		name, rest, _ := strings.Cut(l, ":")
		if ours[name] {
			h, ok := wanted[name]
			if !ok {
				continue
			}
			seenSh[name] = true
			old, _, _ := strings.Cut(rest, ":")
			if old != h {
				changes = append(changes, name+": password changed")
				l = name + ":" + h + ":" + days + ":0:99999:7:::"
			}
		}
		newSh = append(newSh, l)
	}
	for _, name := range sortedKeys(wanted) {
		if !ours[name] {
			newPw = append(newPw, name+":x:0:0:"+userGECOS+":/root:/bin/ash")
			changes = append(changes, name+": added (uid 0, as on a UniFi AP)")
		}
		if !seenSh[name] {
			newSh = append(newSh, name+":"+wanted[name]+":"+days+":0:99999:7:::")
		}
	}
	if len(changes) == 0 {
		return nil, skipped, nil
	}
	if err := replaceKeepMode(shadowPath, joinLines(newSh)); err != nil {
		return changes, skipped, err
	}
	return changes, skipped, replaceKeepMode(passwdPath, joinLines(newPw))
}

func splitLines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func joinLines(l []string) []byte { return []byte(strings.Join(l, "\n") + "\n") }

func sortedKeys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// replaceKeepMode writes b over path atomically, with path's mode (the
// unit's /etc/passwd and /etc/shadow are 0777 on this firmware; changing
// that is not the agent's call). It is not atomicfile.Write: the mode goes
// on the temporary file before the rename.
func replaceKeepMode(path string, b []byte) error {
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".udeco")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
