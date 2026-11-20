// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"reflect"
	"regexp"
	"strings"
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

// report_ip and on_remove take one of two words each. The default, the
// check and the places that act on the value (runner.go) read the same
// constants; the check's texts and the documents' table are as they were.
func TestConfigWords(t *testing.T) {
	cfg := func(extra string) []byte {
		return []byte(`{"inform_url":"http://192.168.0.1:8080/inform","units":[{"ip":"192.168.0.241","mac":"b0:a7:b9:3e:16:94"}]` + extra + `}`)
	}
	c, err := parseConfig(cfg(""))
	if err != nil || c.ReportIP != reportDaemon || c.OnRemove != onRemoveStop {
		t.Fatalf("defaults: %v, report_ip %q, on_remove %q", err, c.ReportIP, c.OnRemove)
	}
	for extra, want := range map[string][2]string{
		`,"report_ip":"daemon"`:  {reportDaemon, onRemoveStop},
		`,"report_ip":"deco"`:    {reportDeco, onRemoveStop},
		`,"on_remove":"stop"`:    {reportDaemon, onRemoveStop},
		`,"on_remove":"pending"`: {reportDaemon, onRemovePending},
	} {
		c, err := parseConfig(cfg(extra))
		if err != nil || c.ReportIP != want[0] || c.OnRemove != want[1] {
			t.Errorf("%s: %v, report_ip %q, on_remove %q", extra, err, c.ReportIP, c.OnRemove)
		}
	}
	for extra, want := range map[string]string{
		`,"report_ip":"x"`:    `report_ip "x": want daemon or deco`,
		`,"report_ip":"Deco"`: `report_ip "Deco": want daemon or deco`,
		`,"on_remove":"x"`:    `on_remove "x": want stop or pending`,
		`,"on_remove":"Stop"`: `on_remove "Stop": want stop or pending`,
	} {
		if _, err := parseConfig(cfg(extra)); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %s", extra, err, want)
		}
	}
	repotest.MustContain(t, "docs/deco/README.md", "| `report_ip` | `"+reportDaemon+"` | `"+reportDeco+"` reports the Deco's own IP after adoption")
	repotest.MustContain(t, "docs/deco/README.md", "| `on_remove` | `"+onRemoveStop+"` | After the controller forgets a unit, either stop its runner (`"+
		onRemoveStop+"`) or show it as pending again (`"+onRemovePending+"`). |")
}

// deploy/unraid.sh looks into udeco.json for a key by its name (no
// credentials file is needed when the config names a password file): each
// name it greps for is a JSON key of Config.
func TestUnraidScriptConfigKeys(t *testing.T) {
	keys := regexp.MustCompile(`grep -q '\\"([a-z0-9_]+)\\"' '\$APPDATA/udeco\.json'`).FindAllStringSubmatch(repotest.Read(t, "deploy/unraid.sh"), -1)
	if len(keys) == 0 {
		t.Fatal("deploy/unraid.sh no longer greps udeco.json for a key this way")
	}
	tags := map[string]bool{}
	ty := reflect.TypeOf(Config{})
	for i := 0; i < ty.NumField(); i++ {
		if tag, _, _ := strings.Cut(ty.Field(i).Tag.Get("json"), ","); tag != "" {
			tags[tag] = true
		}
	}
	for _, k := range keys {
		if !tags[k[1]] {
			t.Errorf("deploy/unraid.sh greps udeco.json for %q, which is not a key of Config", k[1])
		}
	}
}
