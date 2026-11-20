// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"regexp"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/inform"
	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// informHost (the host of the -url flag's value, cut by hand) against
// inform.URLHost, the reader the other daemons use. They agree for every
// URL a device accepts and differ where this test says, which is why
// localIPToward keeps its own: with inform.LocalIPToward, a -url with
// user info would start the daemon where it stops today, and one without
// "http://" would stop it where it starts.
func TestInformHostCut(t *testing.T) {
	for _, c := range []struct {
		url, want string
		same      bool // inform.URLHost gives the same
	}{
		{"http://192.168.1.1:8080/inform", "192.168.1.1", true},
		{"http://192.168.1.1/inform", "192.168.1.1", true},
		{"http://192.168.1.1:8080", "192.168.1.1", true},
		{"http://unifi:8080/inform", "unifi", true},
		{"http://[fd00::1]:8080/inform", "fd00::1", true},
		{"http://[fd00::1]/inform", "[fd00::1]", false},                               // no port: the brackets stay
		{"http://user:pw@192.168.1.1:8080/inform", "user:pw@192.168.1.1:8080", false}, // user info is not cut off
		{"https://192.168.1.1:8443/inform", "https", false},                           // only "http://" is known
		{"192.168.1.1:8080/inform", "192.168.1.1", false},                             // no scheme needed
		{"http://192.168.1.1:port/inform", "192.168.1.1", false},                      // the port is not looked at
	} {
		if got := informHost(c.url); got != c.want {
			t.Errorf("informHost(%q) = %q, want %q", c.url, got, c.want)
		}
		if same := inform.URLHost(c.url) == c.want; same != c.same {
			t.Errorf("%q: inform.URLHost gives %q, informHost %q: same=%v, the table says %v", c.url, inform.URLHost(c.url), c.want, same, c.same)
		}
		if device.CheckInformURL(c.url) == nil && !c.same {
			t.Errorf("%q: the readers differ for a URL a device accepts", c.url)
		}
	}
}

// Every action a reply can ask for (device.Actions) has a case in
// runAction's switch, or is listed here as not served by this daemon:
// those fall through the switch without a word.
func TestRunActionHandlesEveryAction(t *testing.T) {
	notHere := []string{device.ActQuickScan, device.ActRateUpdate}
	sw := repotest.SwitchOn(t, "cmd/uow/main.go", "runAction", "verb")
	handled, other := sw.Consts("device", repotest.StringConsts(t, "internal/device/action.go"))
	if len(other) != 0 {
		t.Errorf("runAction has cases that are not device.Act* constants: %q", other)
	}
	repotest.Cover(t, "runAction", device.Actions(), handled, notHere)
}

// uafSyslogLine's output for logread lines, as it was with the daemon's
// own priority tables and tag: the tables and the tag now come from
// internal/device, the line reader stays here.
func TestUAFSyslogLine(t *testing.T) {
	const host, tag = "OnHub", "U7PG2,085566770001,6.8.2.15592:"
	for _, c := range []struct{ in, want string }{
		{"Fri Nov 13 00:35:06 2026 daemon.err uow[550]: msg",
			"<27>Nov 13 00:35:06 OnHub U7PG2,085566770001,6.8.2.15592: uow[550]: msg"},
		{"Thu Nov 19 03:13:11 2026 kern.warn kernel: [ 12.5] eth0: link up",
			"<4>Nov 19 03:13:11 OnHub U7PG2,085566770001,6.8.2.15592: kernel: [ 12.5] eth0: link up"},
		{"Thu Nov 19 03:13:11 2026 authpriv.notice dropbear[1]: Password auth succeeded",
			"<85>Nov 19 03:13:11 OnHub U7PG2,085566770001,6.8.2.15592: dropbear[1]: Password auth succeeded"},
		{"Thu Nov 19 03:13:11 2026 local7.debug x: y", "<191>Nov 19 03:13:11 OnHub U7PG2,085566770001,6.8.2.15592: x: y"},
		{"Thu Nov 19 03:13:11 2026 user.warning x: y", "<12>Nov 19 03:13:11 OnHub U7PG2,085566770001,6.8.2.15592: x: y"},
		// a facility or level it does not know counts as 0 (the agent's reader sends such a line as user.info)
		{"Thu Nov 19 03:13:11 2026 local9.err x: y", "<3>Nov 19 03:13:11 OnHub U7PG2,085566770001,6.8.2.15592: x: y"},
		{"Thu Nov 19 03:13:11 2026 daemon.fatal x: y", "<24>Nov 19 03:13:11 OnHub U7PG2,085566770001,6.8.2.15592: x: y"},
		// no "facility.level" field: user.info
		{"Thu Nov 19 03:13:11 2026 nodot x: y", "<14>Nov 19 03:13:11 OnHub U7PG2,085566770001,6.8.2.15592: x: y"},
	} {
		if got := uafSyslogLine(c.in, host, tag); got != c.want {
			t.Errorf("uafSyslogLine(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	// a line that is no logread line: user.info with the time now
	got := uafSyslogLine("short line", host, tag)
	if !regexp.MustCompile(`^<14>[A-Z][a-z]{2} [ 0-9]\d \d\d:\d\d:\d\d OnHub U7PG2,085566770001,6\.8\.2\.15592: short line$`).MatchString(got) {
		t.Errorf("short line: %q", got)
	}
}
