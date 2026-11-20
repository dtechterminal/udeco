// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/inform"
	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// The config's inform_url rule against device.CheckInformURL, the rule
// for every later change of the URL. Both take the usual URL; the config
// also takes what "wider" lists, and neither takes the rest. A URL moving
// between the lists means one of the two rules changed.
func TestStartInformURL(t *testing.T) {
	both := []string{
		"http://192.168.1.1:8080/inform",
		"http://192.168.1.1/inform",
		"http://192.168.1.1:8080",
	}
	wider := []string{ // the config takes them, CheckInformURL does not
		"https://192.168.1.1:8443/inform",        // TLS: the scheme is taken, though a later change must be http
		"http://[fd00::1]:8080/inform",           // an IPv6 literal (the unit lists then ask for console_ip and gateway)
		"http://[::ffff:192.168.1.1]:8080/",      // an IPv4-mapped one
		"http://user:pw@192.168.1.1:8080/inform", // user info
		"http://192.168.1.1:0/inform",            // any numeric port
		"http://192.168.1.1:99999/inform",
		"http://192.168.1.1:/inform", // an empty port
	}
	neither := []string{
		"http://unifi:8080/inform", // a name
		"ftp://192.168.1.1/inform",
		"192.168.1.1:8080",
		"http://192.168.1.1:port/inform",
		"http://",
		"",
	}
	for _, u := range both {
		if _, err := startInformURL(u); err != nil {
			t.Errorf("config refuses %q: %v", u, err)
		}
		if err := device.CheckInformURL(u); err != nil {
			t.Errorf("CheckInformURL refuses %q: %v", u, err)
		}
	}
	for _, u := range wider {
		if _, err := startInformURL(u); err != nil {
			t.Errorf("config refuses %q (%v): the rule is no longer wider here", u, err)
		}
		if device.CheckInformURL(u) == nil {
			t.Errorf("CheckInformURL takes %q: no longer a difference", u)
		}
	}
	for _, u := range neither {
		if _, err := startInformURL(u); err == nil {
			t.Errorf("config takes %q", u)
		}
		if device.CheckInformURL(u) == nil {
			t.Errorf("CheckInformURL takes %q", u)
		}
	}
	// what the config takes, it reads the host of as inform.URLHost does
	// (console_ip and gateway default to it; daemon_ip is found through it)
	for _, u := range append(both, wider...) {
		p, err := startInformURL(u)
		if err != nil || p.Hostname() != inform.URLHost(u) || p.Hostname() == "" {
			t.Errorf("%q: host %q, inform.URLHost %q (%v)", u, p.Hostname(), inform.URLHost(u), err)
		}
	}
	// the error names what is taken
	_, err := startInformURL("http://unifi:8080/inform")
	if want := `inform_url "http://unifi:8080/inform": want http:// or https:// to an IP-literal host, like http://192.168.1.1:8080/inform`; err == nil || err.Error() != want {
		t.Errorf("error %v, want %s", err, want)
	}
}

// Every action a reply can ask for (device.Actions) has a case in the
// runner's switch, or is listed here as not served on a Deco reached
// through its app protocol: those reach the switch's default and are
// logged as ignored.
func TestRunnerHandlesEveryAction(t *testing.T) {
	notHere := []string{device.ActQuickScan, device.ActRateUpdate}
	sw := repotest.SwitchOn(t, "cmd/udeco/runner.go", "action", "verb")
	handled, other := sw.Consts("device", repotest.StringConsts(t, "internal/device/action.go"))
	if len(other) != 0 {
		t.Errorf("runner.action has cases that are not device.Act* constants: %q", other)
	}
	repotest.Cover(t, "runner.action", device.Actions(), handled, notHere)
}
