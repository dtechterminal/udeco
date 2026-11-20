// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/inform"
	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// Every action a reply can ask for (device.Actions) has a case in the
// agent's takeover switch: nothing is listed as not served here. The
// observe-mode switch before it names only verbs there are.
func TestAgentHandlesEveryAction(t *testing.T) {
	var notHere []string
	names := repotest.StringConsts(t, "internal/device/action.go")
	var onVerb []repotest.Switch
	for _, s := range repotest.Switches(t, "cmd/udeco-ap/actions.go", "action") {
		if s.Tag == "verb" {
			onVerb = append(onVerb, s)
		}
	}
	if len(onVerb) != 2 {
		t.Fatalf("agent.action has %d switches on verb, want the observe-mode one and the takeover one", len(onVerb))
	}
	observe, takeover := onVerb[0], onVerb[1]
	handled, other := takeover.Consts("device", names)
	if len(other) != 0 {
		t.Errorf("agent.action has cases that are not device.Act* constants: %q", other)
	}
	repotest.Cover(t, "agent.action", device.Actions(), handled, notHere)
	if _, other := observe.Consts("device", names); len(other) != 0 {
		t.Errorf("agent.action's observe-mode switch has cases that are not device.Act* constants: %q", other)
	}
}

// The agent reads the host of its inform URL in two places, both with
// net/url as inform.URLHost does: controllerIP (the config's, for egress
// and the uplink check) and informTarget (the POST's address). For every
// URL the POST takes, the three agree; what informTarget refuses is
// refused by device.CheckInformURL too, which the config passed first.
func TestInformURLHosts(t *testing.T) {
	for _, c := range []struct {
		url  string
		post bool // informTarget takes it
	}{
		{"http://192.168.0.1:8080/inform", true},
		{"http://192.168.0.1/inform", true},
		{"http://192.168.0.1:8080", true},
		{"http://unifi:8080/inform", true},     // the POST would take a name; CheckInformURL does not
		{"http://[fd00::1]:8080/inform", true}, // nor an IPv6 literal
		{"http://[fd00::1]/inform", true},
		{"http://user:pw@192.168.0.1:8080/inform", false},
		{"https://192.168.0.1:8443/inform", false},
		{"http:///inform", false},
	} {
		want := inform.URLHost(c.url)
		if got := (&Config{InformURL: c.url}).controllerIP(); got != want {
			t.Errorf("controllerIP(%q) = %q, inform.URLHost %q", c.url, got, want)
		}
		addr, hostHdr, _, err := informTarget(c.url)
		if (err == nil) != c.post {
			t.Errorf("informTarget(%q): %v, want taken=%v", c.url, err, c.post)
			continue
		}
		if err != nil {
			if device.CheckInformURL(c.url) == nil {
				t.Errorf("%q passes CheckInformURL and the POST refuses it", c.url)
			}
			continue
		}
		if h, _, err := net.SplitHostPort(addr); err != nil || h != want {
			t.Errorf("informTarget(%q) dials %q, inform.URLHost %q", c.url, addr, want)
		}
		if !strings.Contains(hostHdr, want) {
			t.Errorf("informTarget(%q): Host header %q lacks %q", c.url, hostHdr, want)
		}
	}
	// a URL that does not parse: no host, where there was a nil dereference
	if got := (&Config{InformURL: "http://192.168.0.1:port/inform"}).controllerIP(); got != "" {
		t.Errorf("controllerIP of an unparsable URL = %q", got)
	}
}

// deploy/deco-ap.sh checks --inform-url with a pattern of its own before
// it writes the agent's config, and the agent checks the URL again when
// it starts (device.CheckInformURL, config.go) and exits on one it
// refuses. So the script must never pass a URL the agent refuses. It may
// refuse more (it wants the /inform path). Both run over one list here.
func TestDeployInformURL(t *testing.T) {
	bashPath(t) // skips without bash
	for _, c := range []struct {
		url           string
		script, agent bool // taken by the script, by the agent
	}{
		{"http://192.168.0.1:8080/inform", true, true},
		{"http://192.168.0.1/inform", true, true},
		{"http://10.0.0.2:1/inform", true, true},
		{"http://10.0.0.2:65535/inform", true, true},
		{"http://10.0.0.2:08080/inform", true, true}, // both read the port as decimal 8080
		{"http://0.0.0.0:8080/inform", true, true},
		// the script wants the /inform path; the agent does not care
		{"http://192.168.0.1:8080", false, true},
		{"http://192.168.0.1:8080/", false, true},
		{"http://192.168.0.1:8080/other", false, true},
		{"http://192.168.0.1:8080/inform?x=1", false, true},
		{"http://192.168.0.1:8080/inform ", false, true},
		// a port out of range
		{"http://192.168.0.1:0/inform", false, false},
		{"http://192.168.0.1:00000/inform", false, false},
		{"http://192.168.0.1:65536/inform", false, false},
		{"http://192.168.0.1:99999/inform", false, false},
		{"http://192.168.0.1:123456/inform", false, false},
		{"http://192.168.0.1:/inform", false, false},
		// not an IPv4 address to Go: an octet with a leading zero, too large, too few, too many
		{"http://192.168.001.9:8080/inform", false, false},
		{"http://192.168.0.01/inform", false, false},
		{"http://00.0.0.0/inform", false, false},
		{"http://256.1.1.1:8080/inform", false, false},
		{"http://192.168.1:8080/inform", false, false},
		{"http://192.168.0.1.5:8080/inform", false, false},
		{"http://1921.68.0.1:8080/inform", false, false},
		// what neither takes
		{"https://192.168.0.1:8443/inform", false, false},
		{"http://unifi:8080/inform", false, false},
		{"http://[fd00::1]:8080/inform", false, false},
		{"http://user:pw@192.168.0.1:8080/inform", false, false},
		{"192.168.0.1:8080/inform", false, false},
		{"", false, false},
	} {
		out, ok := judge(t, pf205, 3016, "--inform-url", c.url)
		refused := strings.Contains(out, "--inform-url "+c.url+": want http://<IPv4>[:port]/inform")
		if ok == refused {
			t.Fatalf("--inform-url %q: the script neither passed the preflight nor refused the URL:\n%s", c.url, out)
		}
		script, agent := !refused, device.CheckInformURL(c.url) == nil
		if script && !agent {
			t.Errorf("the script takes --inform-url %q and the agent would exit on it: %v", c.url, device.CheckInformURL(c.url))
		}
		if script != c.script || agent != c.agent {
			t.Errorf("%q: script takes it=%v agent takes it=%v, the table says %v %v", c.url, script, agent, c.script, c.agent)
		}
	}
}

// docs/deco/agent-design.md describes the agent's own HTTP client with
// its two bounds: the answer (inform.MaxReply) and the header.
func TestDocsPostBounds(t *testing.T) {
	repotest.MustContain(t, "docs/deco/agent-design.md",
		fmt.Sprintf("a %d MiB answer cap, a %d KiB header cap", inform.MaxReply>>20, informMaxHead>>10))
}
