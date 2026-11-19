// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/models"
)

// minRateCfg is the captured U6 Pro system_cfg with the minimum-rate keys
// Network 11.1.50 writes for a 6 Mb/s 2.4 GHz minimum (beacons at 11 Mb/s
// CCK) on wireless.1 and a 12 Mb/s 5 GHz minimum on wireless.2.
func minRateCfg(t *testing.T) string {
	t.Helper()
	cfg, _ := u6proSystemCfg(t)
	for _, k := range []string{"minrate_data", "beacon_rate", "mgmt_rate"} {
		if !strings.Contains(cfg, "wireless.1."+k+"=1000\n") {
			t.Fatalf("fixture has no wireless.1.%s=1000", k)
		}
	}
	cfg = strings.NewReplacer("wireless.1.minrate_data=1000\n", "wireless.1.minrate_data=6000\n",
		"wireless.1.beacon_rate=1000\n", "wireless.1.beacon_rate=11000\n",
		"wireless.1.mgmt_rate=1000\n", "wireless.1.mgmt_rate=11000\n").Replace(cfg)
	return cfg + "wireless.2.minrate_data=12000\nwireless.2.beacon_rate=12000\nwireless.2.mgmt_rate=12000\n"
}

func rateSteps(p bcmwifi.Plan) []string {
	var out []string
	for _, s := range p.Steps {
		if cmd := strings.Join(s.Argv, " "); s.Kind == bcmwifi.StepCmd && strings.Contains(cmd, " rateset ") {
			out = append(out, cmd)
		}
	}
	return out
}

// min_rates on (takeover): the controller's minimums reach the driver as
// each BSS's rateset, with the controller's beacon rate as the lowest basic
// rate.
func TestE2EMinRatesApplied(t *testing.T) {
	e := newE2E(t, minRateCfg(t), true, func(c *Config, o *options) { c.MinRates = true })
	e.adopt()
	eventually(t, "a bcmwifi plan", func() bool { _, ok := e.wifi.lastPlan(); return ok })
	e.stop()
	if !e.wifi.opts.MinRates {
		t.Fatal("bcmwifi.Options.MinRates not set from min_rates")
	}
	// takeover with min_rates: MINRATE_CTRL claimed
	if e.a.x.WifiCaps&models.WifiCapMinRateCtrl == 0 {
		t.Errorf("wifi_caps %#x lacks MINRATE_CTRL with min_rates", e.a.x.WifiCaps)
	}
	p, _ := e.wifi.lastPlan()
	got := strings.Join(rateSteps(p), "\n")
	for _, want := range []string{" rateset 6 9 11b 12 18 24 36 48 54", " rateset 12b 18 24b 36 48 54"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in the rateset steps:\n%s\nplan:\n%s", want, got, p)
		}
	}
	if strings.Contains(strings.Join(p.Notes, "\n"), "minimum rate") {
		t.Errorf("notes %q", p.Notes)
	}
	// `wl -i <vif> rateset` with no list reads the rateset (live state and
	// Verify); the captures have no output for it
	var m []string
	for _, c := range e.unit.mutating() {
		if f := strings.Fields(c); !(len(f) == 4 && f[0] == "wl" && f[1] == "-i" && f[3] == "rateset") {
			m = append(m, c)
		}
	}
	if len(m) > 0 {
		t.Errorf("DryRun takeover issued mutating commands: %q", m)
	}
}

// min_rates off (the default): no rateset is planned, and the plan says
// the minimum is not applied.
func TestE2EMinRatesOffByDefault(t *testing.T) {
	e := newE2E(t, minRateCfg(t), true)
	e.adopt()
	eventually(t, "a bcmwifi plan", func() bool { _, ok := e.wifi.lastPlan(); return ok })
	e.stop()
	if e.a.x.WifiCaps&models.WifiCapMinRateCtrl != 0 {
		t.Errorf("wifi_caps %#x claims MINRATE_CTRL without min_rates", e.a.x.WifiCaps)
	}
	p, _ := e.wifi.lastPlan()
	if s := rateSteps(p); len(s) > 0 {
		t.Errorf("rateset planned with min_rates off: %q", s)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "minimum rate ng=6000 kbps not applied") {
		t.Errorf("notes %q", p.Notes)
	}
}

func TestConfigMinRatesNeedsTakeover(t *testing.T) {
	base := `{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1"`
	if _, err := parseConfig([]byte(base + `,"min_rates":true}`)); err == nil || !strings.Contains(err.Error(), "min_rates needs takeover") {
		t.Errorf("observe with min_rates: %v", err)
	}
	c, err := parseConfig([]byte(base + `,"takeover":true,"min_rates":true}`))
	if err != nil || !c.MinRates {
		t.Errorf("takeover with min_rates: %+v %v", c, err)
	}
}
