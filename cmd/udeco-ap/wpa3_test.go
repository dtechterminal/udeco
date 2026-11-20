// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/models"
)

func hapdConf(p bcmwifi.Plan, path string) string {
	for _, s := range p.Steps {
		if s.Kind == bcmwifi.StepWrite && s.Path == path {
			return string(s.Data)
		}
	}
	return ""
}

func radioCaps2(t *testing.T, e *e2e) []int {
	t.Helper()
	var out []int
	for _, in := range e.ctl.snapshot() {
		rows, _ := in.payload["radio_table"].([]any)
		for _, r := range rows {
			c2, _ := r.(map[string]any)["radio_caps2"].(float64)
			out = append(out, int(c2))
		}
	}
	if len(out) == 0 {
		t.Fatal("no radio_table rows informed")
	}
	return out
}

// wpa3 off (the default): radio_caps2 is 0 on every radio, as before the
// rename, so the controller sends no SAE; a WPA2/WPA3 WLAN that arrives
// anyway is served as WPA2, with a note.
func TestE2EWPA3OffByDefault(t *testing.T) {
	cfg, _ := mtkCfg(t)
	e := newE2E(t, cfg, true)
	e.adopt()
	eventually(t, "the bcmwifi dry-run apply", func() bool { return strings.Contains(e.logs.all(), "is live") })
	e.stop()
	if e.wifi.opts.WPA3 || e.wifi.opts.FTSAE {
		t.Error("bcmwifi.Options.WPA3 or FTSAE set without the wpa3 key")
	}
	for _, c2 := range radioCaps2(t, e) {
		if c2 != 0 {
			t.Errorf("radio_caps2 %#x without wpa3", c2)
		}
	}
	p, _ := e.wifi.lastPlan()
	conf := hapdConf(p, "/tmp/udeco/hapd-wl1.conf")
	if conf == "" || strings.Contains(conf, "SAE") || !strings.Contains(conf, "wpa_key_mgmt=WPA-PSK FT-PSK\n") {
		t.Errorf("wl1 conf serves SAE (or no WPA2) with wpa3 off:\n%s", conf)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "WPA2/WPA3 served as WPA2: SAE is off (config wpa3)") {
		t.Errorf("notes %q", p.Notes)
	}
}

// wpa3 on (takeover): radio_caps2 WPA3 on both radios and SAE served.
func TestE2EWPA3On(t *testing.T) {
	cfg, _ := mtkCfg(t)
	e := newE2E(t, cfg, true, func(c *Config, o *options) { c.WPA3 = true })
	e.adopt()
	eventually(t, "the bcmwifi dry-run apply", func() bool { return strings.Contains(e.logs.all(), "is live") })
	if !e.wifi.opts.WPA3 {
		t.Error("bcmwifi.Options.WPA3 not set from wpa3")
	}
	// WPA3 and, with ft_sae at its default (on with wpa3), WPA3 fast
	// roaming (0x2: FT-SAE with explicit peers, ftsae.go).
	if c := e.a.radioCaps["na"].RadioCaps2; c != models.RadioCap2WPA3|models.RadioCap2WPA3FT {
		t.Errorf("na radio_caps2 %#x", c)
	}
	if !e.wifi.opts.FTSAE {
		t.Error("bcmwifi.Options.FTSAE not set with wpa3 and ft_sae at its default")
	}
	e.stop()
	for _, c2 := range radioCaps2(t, e) {
		if c2&models.RadioCap2WPA3 == 0 {
			t.Errorf("radio_caps2 %#x lacks WPA3 with wpa3", c2)
		}
	}
	p, _ := e.wifi.lastPlan()
	if conf := hapdConf(p, "/tmp/udeco/hapd-wl1.conf"); !strings.Contains(conf, "SAE") {
		t.Errorf("wl1 conf without SAE:\n%s", conf)
	}
}

func TestConfigWPA3NeedsTakeover(t *testing.T) {
	base := `{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1"`
	if _, err := parseConfig([]byte(base + `,"wpa3":true}`)); err == nil || !strings.Contains(err.Error(), "wpa3 needs takeover") {
		t.Errorf("observe with wpa3: %v", err)
	}
	c, err := parseConfig([]byte(base + `,"takeover":true,"wpa3":true}`))
	if err != nil || !c.WPA3 {
		t.Errorf("takeover with wpa3: %+v %v", c, err)
	}
	if c, err := parseConfig([]byte(base + `}`)); err != nil || c.WPA3 {
		t.Errorf("default: %+v %v", c, err)
	}
}
