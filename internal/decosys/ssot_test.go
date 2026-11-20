// SPDX-License-Identifier: GPL-2.0-or-later

package decosys

import (
	"regexp"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// deploy/deco-ap.sh checks, before it installs anything, that the unit's
// persist file is run by cron and re-adds its cron line: the two files it
// names are the ones this package keeps when it strips TP-Link's cron
// lines (crontabPath, persistScript). The script cannot read them here.
func TestDeployScriptHookPaths(t *testing.T) {
	script := repotest.Read(t, "deploy/deco-ap.sh")
	if got := repotest.ShellVar(t, script, "PERSIST"); got != persistScript {
		t.Errorf("deploy/deco-ap.sh PERSIST is %q, persistScript %q", got, persistScript)
	}
	if got := repotest.ShellVar(t, script, "CRONTAB"); got != crontabPath {
		t.Errorf("deploy/deco-ap.sh CRONTAB is %q, crontabPath %q", got, crontabPath)
	}
}

// The reset wrapper logs each of its three outcomes under the agent's
// syslog tag, and under no other.
func TestResetWrapperTag(t *testing.T) {
	tags := regexp.MustCompile(`(?m)^\s*logger -t (\S+) "reset button `).FindAllStringSubmatch(resetWrapper(resetBackup), -1)
	if len(tags) != 3 {
		t.Fatalf("the wrapper has %d logger lines, want 3:\n%s", len(tags), resetWrapper(resetBackup))
	}
	for _, m := range tags {
		if m[1] != SyslogTag {
			t.Errorf("the wrapper logs with the tag %q, want SyslogTag %q", m[1], SyslogTag)
		}
	}
	if n := strings.Count(resetWrapper(resetBackup), "logger"); n != len(tags) {
		t.Errorf("the wrapper has logger %d times, %d of them with the tag", n, len(tags))
	}
}
