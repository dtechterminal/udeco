// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"strings"
	"testing"
)

const startURL = "http://192.168.1.1:8080/inform"

// URLs no path may adopt: TLS (no client for it), names (inform_ip and
// egress need an address), IPv6 (also an IPv4-mapped one), user info,
// bad ports, non-URLs.
var badInformURLs = []string{
	"https://192.168.1.9:8443/inform",
	"http://unifi:8080/inform",
	"http://unifi.example.com:8080/inform",
	"http://[fd00::1]:8080/inform",
	"http://[::ffff:192.168.1.9]:8080/inform",
	"http://user:pw@192.168.1.9:8080/inform",
	"http://192.168.1.9:99999/inform",
	"http://192.168.1.9:0/inform",
	"http://192.168.1.9:/inform",
	"http:192.168.1.9",
	"ftp://192.168.1.9/inform",
	"192.168.1.9:8080",
	"http://",
	"http://192.168.001.9:8080/inform",
}

func TestCheckInformURL(t *testing.T) {
	for _, ok := range []string{"http://192.168.1.9:8080/inform", "http://10.0.0.2/inform", "http://192.168.1.9:8080"} {
		if err := CheckInformURL(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range badInformURLs {
		if CheckInformURL(bad) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// setparam mgmt_cfg inform_url ("Override inform host"): a bad URL keeps
// the old one and says so in the events.
func TestSetparamInformURLValidated(t *testing.T) {
	for _, bad := range badInformURLs {
		x := newSession(t)
		o := handle(t, x, `{"_type":"setparam","mgmt_cfg":"cfgversion=1\ninform_url=`+bad+`\n"}`)
		if x.S.InformURL != startURL {
			t.Errorf("setparam inform_url %q taken", bad)
		}
		if ev := strings.Join(o.Events, "\n"); !strings.Contains(ev, "ignored inform_url") || !strings.Contains(ev, "keeping "+startURL) {
			t.Errorf("setparam inform_url %q: no log of the refusal:\n%s", bad, ev)
		}
	}
	x := newSession(t)
	handle(t, x, `{"_type":"setparam","mgmt_cfg":"cfgversion=1\ninform_url=http://192.168.1.9:8080/inform\n"}`)
	if x.S.InformURL != "http://192.168.1.9:8080/inform" {
		t.Errorf("a good inform_url refused: %q", x.S.InformURL)
	}
}

// cmd set-adopt uri: same rule. The key handling is unchanged.
func TestCmdSetAdoptURIValidated(t *testing.T) {
	for _, bad := range badInformURLs {
		x := newSession(t)
		o := handle(t, x, `{"_type":"cmd","cmd":"set-adopt","key":"`+newKey+`","uri":"`+bad+`"}`)
		if x.S.InformURL != startURL {
			t.Errorf("cmd set-adopt uri %q taken", bad)
		}
		if ev := strings.Join(o.Events, "\n"); !strings.Contains(ev, "ignored uri") || !strings.Contains(ev, "keeping "+startURL) {
			t.Errorf("cmd set-adopt uri %q: no log of the refusal:\n%s", bad, ev)
		}
	}
	x := newSession(t)
	handle(t, x, `{"_type":"cmd","cmd":"set-adopt","key":"`+newKey+`","uri":"http://192.168.1.9:8080/inform"}`)
	if x.S.InformURL != "http://192.168.1.9:8080/inform" || x.S.Key != newKey {
		t.Errorf("a good set-adopt refused: %q", x.S.InformURL)
	}
}

// SSH set-adopt / set-inform: parsed by SSHAdopt.command, applied by
// ApplyAdopt, which keeps the old URL for a bad one.
func TestSSHInformURLValidated(t *testing.T) {
	for _, bad := range badInformURLs {
		if strings.ContainsAny(bad, " \t") {
			continue
		}
		for _, cmd := range []string{
			"/usr/bin/syswrapper.sh set-inform " + bad,
			"/usr/bin/syswrapper.sh set-adopt " + bad + " " + newKey,
		} {
			s := &SSHAdopt{Requests: make(chan AdoptRequest, 1)}
			s.command(cmd)
			var r AdoptRequest
			select {
			case r = <-s.Requests:
			default:
				continue // not even parsed: nothing to apply
			}
			x := newSession(t)
			o := x.ApplyAdopt(r)
			if x.S.InformURL != startURL {
				t.Errorf("%q: inform URL %q taken", cmd, x.S.InformURL)
			}
			if ev := strings.Join(o.Events, "\n"); !strings.Contains(ev, "ignored inform url") || !strings.Contains(ev, "keeping "+startURL) {
				t.Errorf("%q: no log of the refusal:\n%s", cmd, ev)
			}
		}
	}
	x := newSession(t)
	x.ApplyAdopt(AdoptRequest{URL: "http://192.168.1.9:8080/inform"})
	if x.S.InformURL != "http://192.168.1.9:8080/inform" {
		t.Errorf("a good set-inform refused: %q", x.S.InformURL)
	}
}
