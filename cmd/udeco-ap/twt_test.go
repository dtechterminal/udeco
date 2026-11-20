// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"strings"
	"testing"
)

// twt: absent or true turns TWT on (as a U6 Pro), false keeps TP-Link's
// off; it needs takeover and is for the Deco only.
func TestConfigTWT(t *testing.T) {
	base := `{"inform_url":"http://192.168.0.2:8080/inform","console_ip":"192.168.0.3"`
	for _, c := range []struct {
		extra string
		want  bool
		err   string
	}{
		{`,"takeover":true`, true, ""},
		{``, true, ""},
		{`,"takeover":true,"twt":true`, true, ""},
		{`,"takeover":true,"twt":false`, false, ""},
		{`,"twt":false`, false, "twt needs takeover"},
		{`,"takeover":true,"platform":"jio-mtk","model":"U7LT","twt":false`, false, "twt is not supported on platform jio-mtk"},
		{`,"takeover":true,"twt_responder":3`, false, "unknown field"},
	} {
		cfg, err := parseConfig([]byte(base + c.extra + "}"))
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: err %v, want %q", c.extra, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.extra, err)
			continue
		}
		if cfg.twt() != c.want {
			t.Errorf("%s: twt %t, want %t", c.extra, cfg.twt(), c.want)
		}
	}
}

// The agent hands the twt key to bcmwifi (Options.NoTWT) and the plan
// notes report each radio's TWT state.
func TestE2ETWT(t *testing.T) {
	for _, off := range []bool{false, true} {
		cfg, _ := mtkCfg(t)
		e := newE2E(t, cfg, true, func(c *Config, o *options) {
			if off {
				v := false
				c.TWT = &v
			}
		})
		e.adopt()
		eventually(t, "the bcmwifi dry-run apply", func() bool { return strings.Contains(e.logs.all(), "is live") })
		e.stop()
		if e.wifi.opts.NoTWT != off {
			t.Errorf("twt off %t: bcmwifi.Options.NoTWT %t", off, e.wifi.opts.NoTWT)
		}
		p, _ := e.wifi.lastPlan()
		if n := strings.Join(p.Notes, "\n"); !strings.Contains(n, "radio ng: TWT") || !strings.Contains(n, "radio na: TWT") {
			t.Errorf("twt off %t: no TWT note per radio: %q", off, p.Notes)
		}
		// the captures' radios read twt enab 0 (TP-Link's): the takeover's
		// radio down/up turns it on, or leaves it off with twt false
		plan := p.String()
		for _, r := range []string{"wl0", "wl1"} {
			if on := strings.Contains(plan, "wl -i "+r+" twt enab 1"); on == off {
				t.Errorf("twt off %t: %s TWT on in the takeover plan: %t", off, r, on)
			}
		}
		if !strings.Contains(e.logs.all(), "wifi: note: radio na: TWT") {
			t.Errorf("twt off %t: TWT note not logged", off)
		}
	}
}

// rx_desense keeps TP-Link's receiver desense (bcmwifi.Options.KeepDesense);
// absent, the agent clears it as a U6 Pro (ani_enable 0). Takeover, Deco
// only.
func TestConfigRxDesense(t *testing.T) {
	base := `{"inform_url":"http://192.168.0.2:8080/inform","console_ip":"192.168.0.3"`
	for _, c := range []struct {
		extra string
		want  bool
		err   string
	}{
		{`,"takeover":true`, false, ""},
		{`,"takeover":true,"rx_desense":true`, true, ""},
		{`,"rx_desense":true`, false, "rx_desense needs takeover"},
		{`,"takeover":true,"platform":"jio-mtk","model":"U7LT","rx_desense":true`, false, "rx_desense is not supported on platform jio-mtk"},
	} {
		cfg, err := parseConfig([]byte(base + c.extra + "}"))
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: err %v, want %q", c.extra, err, c.err)
			}
			continue
		}
		if err != nil || cfg.RxDesense != c.want {
			t.Errorf("%s: %v rx_desense %t", c.extra, err, cfg.RxDesense)
		}
	}
	for _, keep := range []bool{false, true} {
		cfg, _ := mtkCfg(t)
		e := newE2E(t, cfg, true, func(c *Config, o *options) { c.RxDesense = keep })
		e.adopt()
		eventually(t, "the bcmwifi dry-run apply", func() bool { return strings.Contains(e.logs.all(), "is live") })
		e.stop()
		if e.wifi.opts.KeepDesense != keep {
			t.Errorf("rx_desense %t: bcmwifi.Options.KeepDesense %t", keep, e.wifi.opts.KeepDesense)
		}
	}
}
