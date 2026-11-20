// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/decosys"
	"github.com/dtechterminal/udeco/internal/models"
	"github.com/dtechterminal/udeco/internal/translate"
)

func TestConfigDefaults(t *testing.T) {
	c, err := parseConfig([]byte(`{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Model != models.DecoAgentModel || c.SSHDPort != decosys.DefaultSSHDPort || c.Takeover || c.Apply || c.Egress || c.Log != logSyslog {
		t.Errorf("defaults %+v", c)
	}
	if c.controllerIP() != "192.168.0.1" {
		t.Errorf("controller ip %q", c.controllerIP())
	}
}

func TestConfigErrors(t *testing.T) {
	base := `"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1"`
	for name, js := range map[string]string{
		"unknown key":           `{` + base + `,"takeover":true,"egres":true}`,
		"trailing data":         `{` + base + `} {}`,
		"inform name":           `{"inform_url":"http://unifi:8080/inform","console_ip":"192.168.0.1"}`,
		"inform scheme":         `{"inform_url":"ftp://192.168.0.1/inform","console_ip":"192.168.0.1"}`,
		"console ip":            `{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"unifi"}`,
		"port 22":               `{` + base + `,"sshd_port":22}`,
		"port range":            `{` + base + `,"sshd_port":70000}`,
		"model":                 `{` + base + `,"model":"U7PG2"}`,
		"apply needs takeover":  `{` + base + `,"apply":true}`,
		"egress needs takeover": `{` + base + `,"egress":true}`,
		"log":                   `{` + base + `,"log":"file"}`,
		"https":                 `{"inform_url":"https://192.168.0.1:8443/inform","console_ip":"192.168.0.1"}`,
		"mgmt source":           `{` + base + `,"mgmt_sources":["192.168.1.0/33"]}`,
		"inform v4-mapped v6":   `{"inform_url":"http://[::ffff:192.168.0.1]:8080/inform","console_ip":"192.168.0.1"}`,
		"inform port range":     `{"inform_url":"http://192.168.0.1:99999/inform","console_ip":"192.168.0.1"}`,
		"inform opaque":         `{"inform_url":"http:192.168.0.1","console_ip":"192.168.0.1"}`,
	} {
		if _, err := parseConfig([]byte(js)); err == nil {
			t.Errorf("%s: accepted %s", name, js)
		}
	}
	if c, err := parseConfig([]byte(`{` + base + `,"model":"ual6","takeover":true,"apply":true,"egress":true,"log":"stderr","mgmt_sources":["192.168.1.0/24","192.168.0.1","fd00::/64"]}`)); err != nil || c.Model != "UAL6" || len(c.MgmtSources) != 3 {
		t.Errorf("full config: %v %+v", err, c)
	}
}

func TestCrashLoop(t *testing.T) {
	p := filepath.Join(t.TempDir(), "run", "starts")
	up := 300.0 // /proc/uptime seconds: the wall clock may jump at the first NTP sync (R7)
	for i := 0; i < crashStarts-1; i++ {
		loop, err := recordStart(p, up+float64(i)*60)
		if err != nil || loop {
			t.Fatalf("start %d: loop=%v err=%v", i+1, loop, err)
		}
	}
	if loop, _ := recordStart(p, up+5*60); !loop {
		t.Error("5 starts in 5 minutes are not a crash loop")
	}
	// starts older than the window no longer count
	if loop, _ := recordStart(p, up+30*60); loop {
		t.Error("a start after a quiet spell counted as a crash loop")
	}
	b, _ := os.ReadFile(p)
	if n := len(strings.Fields(string(b))); n != 1 {
		t.Errorf("start log keeps %d entries", n)
	}
	// entries later than the uptime are from an earlier boot
	os.WriteFile(p, []byte("5000\n5001\n5002\n5003\n"), 0o600)
	if loop, _ := recordStart(p, 40); loop {
		t.Error("starts of an earlier boot counted")
	}
}

func TestDetectUplink(t *testing.T) {
	s := testSnapshot()
	if up := detectUplink(s); up != "eth1" {
		t.Errorf("uplink %q, want eth1 (the gateway's FDB port)", up)
	}
	s.FDB = []apstate.FDBEntry{{MAC: gwMAC, Port: 1}}
	if up := detectUplink(s); up != "eth0" {
		t.Errorf("uplink %q, want eth0", up)
	}
	s.ARP = map[string]string{}
	if up := detectUplink(s); up != "" {
		t.Errorf("uplink %q without the gateway in ARP", up)
	}
	if c := lanCIDR("192.168.0.205", "255.255.255.0"); c != "192.168.0.0/24" {
		t.Errorf("lan %q", c)
	}
}

// desiredFrom carries every field bcmwifi takes, notes the rest, and its
// notes never hold secrets.
func TestDesiredFrom(t *testing.T) {
	cfg := testCfg + "aaa.1.radius.macacl.status=enabled\naaa.1.radius.macacl.format=aa-bb-cc-dd-ee-ff\n" +
		"aaa.1.radius.auth.1.ip=192.168.0.9\naaa.1.radius.auth.1.port=1812\naaa.1.radius.auth.1.secret=" + fakeRadSc + "\n"
	in, _ := translate.IntentFromCfg(cfg)
	d, notes := desiredFrom(in)
	if len(d.SSIDs) != 1 {
		t.Fatalf("ssids %v", d.SSIDs)
	}
	s := d.SSIDs[0]
	if s.Passphrase != fakePSK || s.Security != "wpa2" || s.ID != "w1" {
		t.Errorf("ssid %v", s)
	}
	if r, ok := d.Radios["na"]; !ok || r.Width != 80 {
		t.Errorf("radios %+v", d.Radios)
	}
	joined := strings.Join(notes, "\n")
	if strings.Contains(joined, fakePSK) || strings.Contains(joined, fakeRadSc) {
		t.Error("secret in notes")
	}
	if in.WLANs[0].Radius == nil || !in.WLANs[0].Radius.MACAuth {
		t.Fatalf("fixture: translate did not parse RADIUS MAC auth: %v", in.WLANs[0])
	}
	// carried, so no longer a "not carried" note (bcmwifi notes the format)
	if strings.Contains(joined, "MAC authentication") {
		t.Errorf("MAC auth still noted as not carried: %v", notes)
	}
	if r := s.Radius; r == nil || !r.MACAuth || r.MACFormat != in.WLANs[0].Radius.MACFormat || r.MACFormat == "" {
		t.Errorf("MAC auth not carried: %+v (intent format %q)", s.Radius, in.WLANs[0].Radius.MACFormat)
	}
	if r := s.Radius; r == nil || len(r.Auth) != 1 || r.Auth[0].IP != "192.168.0.9" || r.Auth[0].Port != 1812 || r.Auth[0].Secret != fakeRadSc {
		t.Errorf("radius %v", s.Radius)
	}
}

// TestJioPlatformConfig: platform jio-mtk reports as U7LT, takes min_rates
// and refuses the features its driver or system manager do not have.
func TestJioPlatformConfig(t *testing.T) {
	base := `{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1","takeover":true,"apply":true,"platform":"jio-mtk"`
	if c, err := parseConfig([]byte(base + `,"model":"U7LT"}`)); err != nil || !c.jio() {
		t.Fatalf("jio config refused: %v", err)
	}
	// min_rates: each radio's BasicRate (mtkwifi)
	for _, model := range []string{"U7LT", "UHDIW"} {
		if c, err := parseConfig([]byte(base + `,"model":"` + model + `","min_rates":true}`)); err != nil || !c.MinRates {
			t.Errorf("jio %s min_rates refused: %v", model, err)
		}
	}
	for _, bad := range []string{`}`, `,"model":"U7LT","egress":true}`, `,"model":"U7LT","mdns_bridge":true}`, `,"model":"U7LT","hotspot2":true}`, `,"model":"UAL6"}`} {
		if _, err := parseConfig([]byte(base + bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := parseConfig([]byte(`{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1","platform":"x","model":"UAL6"}`)); err == nil {
		t.Errorf("unknown platform accepted")
	}
}

// TestJioPortsConfig: the JCOW414 may be reported as UHDIW (U7LT stays
// valid), and ports_unlocked takes LAN ports 1-3 on UHDIW only.
func TestJioPortsConfig(t *testing.T) {
	base := `{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1","takeover":true,"apply":true,"platform":"jio-mtk"`
	for _, good := range []string{`,"model":"UHDIW"}`, `,"model":"uhdiw","ports_unlocked":[1]}`, `,"model":"UHDIW","ports_unlocked":[1,2,3]}`, `,"model":"U7LT"}`} {
		c, err := parseConfig([]byte(base + good))
		if err != nil {
			t.Errorf("refused %s: %v", good, err)
			continue
		}
		if !models.JCOW414Models[c.Model] {
			t.Errorf("%s: model %q", good, c.Model)
		}
	}
	for _, bad := range []string{`,"model":"UHDIW","ports_unlocked":[4]}`, `,"model":"UHDIW","ports_unlocked":[0]}`,
		`,"model":"UHDIW","ports_unlocked":[1,1]}`, `,"model":"U7LT","ports_unlocked":[1]}`, `,"model":"U6IW"}`} {
		if _, err := parseConfig([]byte(base + bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := parseConfig([]byte(`{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1","model":"UAL6","ports_unlocked":[1]}`)); err == nil {
		t.Errorf("ports_unlocked accepted on the Deco")
	}
}
