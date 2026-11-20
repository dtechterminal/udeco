// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// Documents that state what this package defines: each fails here when
// the two disagree.

// docs/internals.md lists the cmd names a reply can carry ("Replies to
// handle"). Every name it lists is one Session.cmd has a case for, and
// every case has one of its names in the list (a case's other names are
// aliases): a cmd added to the session is added to the document.
func TestDocsListEveryCmd(t *testing.T) {
	doc := repotest.Read(t, "docs/internals.md")
	i := strings.Index(doc, "\n- `cmd`:")
	if i < 0 {
		t.Fatal("docs/internals.md has no `cmd` bullet")
	}
	bullet := doc[i+len("\n- `cmd`:"):]
	if j := strings.Index(bullet, "\n- "); j >= 0 {
		bullet = bullet[:j]
	}
	// a cmd's arguments are named in brackets after it
	bullet = regexp.MustCompile(`\([^)]*\)`).ReplaceAllString(bullet, "")
	var listed []string
	for _, m := range regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(bullet, -1) {
		listed = append(listed, m[1])
	}
	sw := repotest.SwitchOn(t, "internal/device/session.go", "cmd", "r.Cmd")
	var cases []string
	for _, c := range sw.Cases {
		documented := false
		for _, e := range c {
			name, err := strconv.Unquote(e)
			if err != nil {
				t.Fatalf("Session.cmd has a case %s that is not a string", e)
			}
			cases = append(cases, name)
			documented = documented || slices.Contains(listed, name)
		}
		if !documented {
			t.Errorf("docs/internals.md does not list cmd %s (its `cmd` bullet has %q)", strings.Join(c, " / "), listed)
		}
	}
	for _, name := range listed {
		if !slices.Contains(cases, name) {
			t.Errorf("docs/internals.md lists cmd %q, which Session.cmd has no case for", name)
		}
	}
	if len(listed) < 10 {
		t.Errorf("only %d cmd names read from the document: %q", len(listed), listed)
	}
}

// The documents name the files of a state directory as the constants do.
func TestDocsNameStateFiles(t *testing.T) {
	for doc, names := range map[string][]string{
		"docs/internals.md":         {UnhandledFile},
		"docs/deco/README.md":       {StateFile, SystemCfgFile, SystemCfgHistoryDir + "/"},
		"docs/deco/design.md":       {StateFile, SystemCfgFile, UnhandledFile},
		"docs/deco/agent-design.md": {StateFile, SystemCfgFile, UnhandledFile},
	} {
		for _, n := range names {
			repotest.MustContain(t, doc, "`"+n+"`")
		}
	}
	if StateFile != "state.json" || SystemCfgFile != "system_cfg.txt" || SystemCfgHistoryDir != "system_cfg.history" ||
		UnhandledFile != "unhandled.json" || SSHHostKeyFile != "ssh_host_ed25519.pem" {
		t.Error("a state file was renamed: units in the field hold their adoption under the old name")
	}
}

// The inform loop's timing and the portal ports as the documents give
// them.
func TestDocsTimingAndPorts(t *testing.T) {
	if MinInformWait == time.Second && DefaultInformInterval == 10*time.Second {
		repotest.MustContain(t, "README.md", "1 s / 10 s inform interval")
	} else {
		t.Error("README.md says the daemon follows the controller's 1 s / 10 s inform interval")
	}
	if backoffMax == time.Minute {
		repotest.MustContain(t, "docs/internals.md", "informing, up to a minute apart")
	} else {
		t.Error("docs/internals.md says a daemon keeps informing up to a minute apart after a bad answer")
	}
	var ports []string
	for _, p := range PortalHostPorts() {
		ports = append(ports, strconv.Itoa(p))
	}
	repotest.MustContain(t, "docs/internals.md", "portal ports ("+strings.Join(ports, ", ")+")")
	repotest.MustContain(t, "docs/internals.md", fmt.Sprintf("`http://<host>:%d/redirect?ec=<cookie>`", PortalPort))
	repotest.MustContain(t, "docs/internals.md", fmt.Sprintf("answers it on its own `:%d` (`-portal-listen`)", PortalPort))
	if !slices.Contains(PortalHostPorts(), PortalPort) {
		t.Errorf("PortalHostPorts %v lacks PortalPort %d", PortalHostPorts(), PortalPort)
	}
	if !slices.Equal(PortalHostPorts(), []int{8880, 8843, 8881, 8882}) || PortalPort != 8882 {
		t.Errorf("portal ports %v, %d", PortalHostPorts(), PortalPort)
	}
}

// docs/internals.md gives the size of the ledger of unhandled items and
// how often repeat counts reach its file (unhandled.go).
func TestDocsLedgerLimits(t *testing.T) {
	if ledgerEvery != time.Hour {
		t.Fatalf("ledgerEvery is %s: docs/internals.md says repeat counts are written once an hour; reword it and this test", ledgerEvery)
	}
	repotest.MustHave(t, "docs/internals.md", fmt.Sprintf(
		"at most %d entries, a new one written at once and logged (`unhandled ... (first time)`), repeat counts once an hour.", ledgerMax))
}
