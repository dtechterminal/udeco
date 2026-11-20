// SPDX-License-Identifier: GPL-2.0-or-later

package inform

import (
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// The inform POST's headers are the ones a real UniFi AP sends: the
// strings of the U6 Pro's mcad (docs/reference/u6pro) have both lines.
func TestPostHeadersAsARealAP(t *testing.T) {
	const capture = "docs/reference/u6pro/actions-scans/strings-mcad.txt"
	repotest.MustContain(t, capture, "User-Agent: "+UserAgent+"\n")
	repotest.MustContain(t, capture, "Content-Type: "+ContentType+"\n")
	if UserAgent != "AirControl Agent v1.0" || ContentType != "application/x-binary" || MaxReply != 4<<20 {
		t.Errorf("%q %q %d", UserAgent, ContentType, MaxReply)
	}
}

// urlRows: an IPv4 literal with a port, a host name, no port, IPv6
// literals, user info, and forms no device accepts; host is what URLHost
// gives.
var urlRows = []struct{ url, host string }{
	{"http://192.168.1.1:8080/inform", "192.168.1.1"},
	{"http://unifi:8080/inform", "unifi"},
	{"http://unifi.example.com:8080/inform", "unifi.example.com"},
	{"http://192.168.1.1/inform", "192.168.1.1"},
	{"http://192.168.1.1:8080", "192.168.1.1"},
	{"http://192.168.1.1:/inform", "192.168.1.1"},
	{"http://[fd00::1]:8080/inform", "fd00::1"},
	{"http://[fd00::1]/inform", "fd00::1"},
	{"http://user:pw@192.168.1.1:8080/inform", "192.168.1.1"},
	{"http://user@192.168.1.1/inform", "192.168.1.1"},
	{"https://192.168.1.1:8443/inform", "192.168.1.1"},
	{"HTTP://192.168.1.1:8080/inform", "192.168.1.1"},
	{"192.168.1.1:8080/inform", ""}, // no scheme: not a URL to net/url
	{"http://192.168.1.1:port/inform", ""},
	{"http://", ""},
	{"", ""},
}

func TestURLHost(t *testing.T) {
	for _, r := range urlRows {
		if got := URLHost(r.url); got != r.host {
			t.Errorf("URLHost(%q) = %q, want %q", r.url, got, r.host)
		}
	}
}

// hostOf (informIP's reader) cuts the URL by hand. It agrees with URLHost
// for every URL a device accepts, and differs where this test says: a
// change of either reader shows here. informIP keeps hostOf, because
// URLHost would give an address (and so a payload) for a URL with user
// info, which today fails, and would change the error of the others.
func TestURLHostAndHostOf(t *testing.T) {
	differs := map[string]string{ // url -> hostOf's answer
		"http://[fd00::1]/inform":                "[fd00::1]", // no port: the brackets stay
		"http://user:pw@192.168.1.1:8080/inform": "user:pw@192.168.1.1:8080",
		"http://user@192.168.1.1/inform":         "user@192.168.1.1",
		"192.168.1.1:8080/inform":                "192.168.1.1", // no scheme needed
		"http://192.168.1.1:port/inform":         "192.168.1.1", // the port is not looked at
	}
	for _, r := range urlRows {
		want, ok := differs[r.url]
		if !ok {
			want = r.host
		}
		if got := hostOf(r.url); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", r.url, got, want)
		}
		if ok && want == r.host {
			t.Errorf("%q is listed as a difference and is none", r.url)
		}
	}
}

// LocalIPToward dials nothing: a UDP socket connected to the host tells
// the local address. Loopback only here.
func TestLocalIPToward(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:8080/inform", "http://127.0.0.1/inform", "http://user:pw@127.0.0.1:8080/inform"} {
		if ip, err := LocalIPToward(u); err != nil || ip != "127.0.0.1" {
			t.Errorf("LocalIPToward(%q) = %q, %v", u, ip, err)
		}
	}
	for _, u := range []string{"http://[::1]:8080/inform", "127.0.0.1:8080/inform", "http://127.0.0.1:port/inform"} {
		if ip, err := LocalIPToward(u); err == nil {
			t.Errorf("LocalIPToward(%q) = %q, want an error", u, ip)
		}
	}
}
