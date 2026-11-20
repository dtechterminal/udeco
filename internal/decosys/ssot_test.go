// SPDX-License-Identifier: GPL-2.0-or-later

package decosys

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/deco"
	"github.com/dtechterminal/udeco/internal/repotest"
)

// The inbound fence names TP-Link's management ports as text for iptables.
// Three of them are the ports the Deco protocol code (internal/deco, the
// off-device daemon's client) dials: dropbear for TMP over SSH, TDP, and
// the TMP endpoint behind the SSH forward. A port that changed there and
// not here would leave the listener open.
func TestIngressFencesTheDecoProtocolPorts(t *testing.T) {
	for name, port := range map[string]int{"deco.DefaultSSHPort": deco.DefaultSSHPort, "deco.TDPPort": deco.TDPPort, "deco.TMPForwardPort": deco.TMPForwardPort} {
		if !slices.Contains(ingressTCP, strconv.Itoa(port)) {
			t.Errorf("ingressTCP %v does not have %s (%d)", ingressTCP, name, port)
		}
	}
	if !slices.Contains(ingressUDP, strconv.Itoa(deco.TDPPort)) {
		t.Errorf("ingressUDP %v does not have deco.TDPPort (%d): TDP discovery is UDP", ingressUDP, deco.TDPPort)
	}
}

// The README tells the reader which ports the fence drops: the list of
// ingressTCP, a run of consecutive ports written as a range.
func TestDocsFencedPorts(t *testing.T) {
	var ports []int
	for _, p := range ingressTCP {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("ingressTCP has %q", p)
		}
		ports = append(ports, n)
	}
	var parts []string
	for i := 0; i < len(ports); {
		j := i
		for j+1 < len(ports) && ports[j+1] == ports[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, strconv.Itoa(ports[i])+"–"+strconv.Itoa(ports[j]))
		} else {
			parts = append(parts, strconv.Itoa(ports[i]))
		}
		i = j + 1
	}
	repotest.MustHave(t, "README.md", "TP-Link's app and web ports ("+strings.Join(parts, ", ")+") are dropped inbound.")
	for _, p := range ingressUDP {
		if !slices.Contains(ingressTCP, p) {
			t.Errorf("ingressUDP has %s, which the README's list (the TCP ports) does not name", p)
		}
	}
}

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
