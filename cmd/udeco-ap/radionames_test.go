// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bufio"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/device"
	"github.com/dtechterminal/udeco/internal/models"
)

// mtkCfg is the U6-Lite system_cfg with MediaTek devnames (two 5 GHz SSIDs
// on Home, one on VLAN 3; WPA2/WPA3 transition). Its passphrases are fakes.
func mtkCfg(t *testing.T) (cfg string, secrets []string) {
	t.Helper()
	cfg = string(readFixture(t, "../../internal/translate/testdata", "system_cfg-ual6-mtk.txt"))
	for _, l := range strings.Split(cfg, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok && strings.HasSuffix(k, ".wpa.psk") && !slices.Contains(secrets, v) {
			secrets = append(secrets, v)
		}
	}
	if len(secrets) != 3 {
		t.Fatalf("fixture: %d passphrases", len(secrets))
	}
	return cfg, secrets
}

// radioRows: "name/band" of an inform's radio_table rows, in order.
func radioRows(m map[string]any) []string {
	var out []string
	rows, _ := m["radio_table"].([]any)
	for _, r := range rows {
		row, _ := r.(map[string]any)
		n, _ := row["name"].(string)
		b, _ := row["radio"].(string)
		out = append(out, n+"/"+b)
	}
	return out
}

func TestChooseRadioNames(t *testing.T) {
	for _, c := range []struct {
		have  string
		found bool
		want  string
		chg   bool
	}{
		{"", false, radioNamesMediaTek, true}, // new unit
		{"", true, radioNamesQualcomm, true},  // state of an earlier build: keep its wifi0/wifi1
		{radioNamesMediaTek, true, radioNamesMediaTek, false},
		{radioNamesQualcomm, true, radioNamesQualcomm, false},
		{"junk", true, radioNamesQualcomm, true},
	} {
		st := device.State{RadioNames: c.have}
		if chg := chooseRadioNames(&st, c.found); chg != c.chg || st.RadioNames != c.want {
			t.Errorf("%q found=%v: %q changed=%v, want %q %v", c.have, c.found, st.RadioNames, chg, c.want, c.chg)
		}
	}
	if m := radioNameMap(radioNamesMediaTek); m["ng"] != models.RadioNameMTK2G || m["na"] != models.RadioNameMTK5G {
		t.Errorf("mediatek map %v", m)
	}
	if m := radioNameMap(radioNamesQualcomm); m != nil {
		t.Errorf("qualcomm map %v", m)
	}
}

// hostapdSSIDs maps each bss= vif of a hostapd conf to its ssid.
func hostapdSSIDs(conf string) map[string]string {
	m := map[string]string{}
	vif := ""
	sc := bufio.NewScanner(strings.NewReader(conf))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "bss":
			vif = v
		case "ssid":
			if vif != "" {
				m[vif] = v
			}
		}
	}
	return m
}

// A new unit reports ra0/rai0 (so the controller names its VAPs ra0, rai0,
// rai1, ...) and, with the wpa3 config key, every radio claims radio_caps2
// WPA3 (so WPA2/WPA3 WLANs arrive as SAE + transition). Given the
// system_cfg the controller then builds, the takeover plan puts each 5 GHz
// SSID on its own bridge: the two Home SSIDs on br-lan, the VLAN 3 one on
// br-v3, and serves SAE.
func TestE2EMediaTekRadioNamesBridges(t *testing.T) {
	cfg, secrets := mtkCfg(t)
	e := newE2E(t, cfg, true, func(c *Config, o *options) { c.WPA3 = true })
	e.adopt()
	eventually(t, "the bcmwifi dry-run apply", func() bool { return strings.Contains(e.logs.all(), "is live") })
	e.stop()

	n := 0
	for _, in := range e.ctl.snapshot() {
		if rows := radioRows(in.payload); !slices.Equal(rows, []string{"ra0/ng", "rai0/na"}) {
			t.Fatalf("%s inform radio_table %v, want ra0/ng rai0/na", in.key, rows)
		}
		rows, _ := in.payload["radio_table"].([]any)
		for _, r := range rows {
			if c2, _ := r.(map[string]any)["radio_caps2"].(float64); int(c2)&models.RadioCap2WPA3 == 0 {
				t.Errorf("radio_caps2 %v lacks WPA3", c2)
			}
		}
		n++
	}
	if n < 4 {
		t.Fatalf("%d informs", n)
	}
	b, err := os.ReadFile(e.unit.path("/tp_data/udeco/session/state.json"))
	if err != nil || !strings.Contains(string(b), `"radio_names": "mediatek"`) {
		t.Errorf("state.json radio_names: %v %s", err, b)
	}

	p, ok := e.wifi.lastPlan()
	if !ok {
		t.Fatal("no bcmwifi plan")
	}
	vlan := map[string]int{}
	for _, s := range p.Desired.SSIDs {
		vlan[s.SSID] = s.VLAN
		if s.Security != "wpa2wpa3" {
			t.Errorf("%s: security %q, want wpa2wpa3", s.SSID, s.Security)
		}
	}
	if vlan["Example Network"] != 0 || vlan["Home 5G"] != 0 || vlan["olive#"] != 3 || len(vlan) != 3 {
		t.Fatalf("desired VLANs %v", vlan)
	}
	var conf string
	for _, s := range p.Steps {
		if s.Kind == bcmwifi.StepWrite && s.Path == "/tmp/udeco/hapd-wl1.conf" {
			conf = string(s.Data)
		}
	}
	bss := hostapdSSIDs(conf)
	vifOf := map[string]string{}
	for vif, ssid := range bss {
		vifOf[ssid] = vif
	}
	steps := p.String()
	for ssid, br := range map[string]string{"Example Network": "br-lan", "Home 5G": "br-lan", "olive#": "br-v3"} {
		vif := vifOf[ssid]
		if vif == "" {
			t.Errorf("%s: no 5 GHz bss in hostapd conf (bss %v)", ssid, bss)
			continue
		}
		if !strings.Contains(steps, "brctl addif "+br+" "+vif+" ") {
			t.Errorf("%s (%s): not added to %s:\n%s", ssid, vif, br, steps)
		}
		other := map[string]string{"br-lan": "br-v3", "br-v3": "br-lan"}[br]
		if strings.Contains(steps, "brctl addif "+other+" "+vif+" ") {
			t.Errorf("%s (%s): also added to %s", ssid, vif, other)
		}
	}
	if !strings.Contains(conf, "wpa_key_mgmt=WPA-PSK FT-PSK SAE\n") {
		t.Errorf("wl1 hostapd conf without WPA2/WPA3 key management")
	}
	if strings.Contains(strings.Join(p.Notes, "\n"), "VAPs (") {
		t.Errorf("devname collision noted: %q", p.Notes)
	}
	e.checkNoSecrets(secrets)
}

// A unit adopted by an earlier build (state.json without radio_names) keeps
// reporting wifi0/wifi1: the controller has those rows and would add, never
// replace, rows of other names. Once the controller forgets it (setdefault)
// the next informs carry ra0/rai0 and the choice is saved.
func TestE2EQualcommRadioNamesUntilForget(t *testing.T) {
	cfg, _ := mtkCfg(t)
	e := newE2E(t, cfg, false)
	st := device.NewState(e.ctl.url())
	st.Key, st.Adopted = e2eAuthkey, true
	b, _ := json.Marshal(st)
	if strings.Contains(string(b), "radio_names") {
		t.Fatal("fixture: an earlier build's state has no radio_names")
	}
	e.unit.write("/tp_data/udeco/session/state.json", string(b))
	devInforms := 0
	e.ctl.reply = func(in e2eInform) string {
		if in.key == "device" {
			devInforms++
		}
		if devInforms >= 4 && e.ctlStep == 0 {
			e.ctlStep = 1
			return `{"_type":"setdefault"}`
		}
		return ""
	}
	e.start()
	eventually(t, "factory-key informs after setdefault", func() bool {
		return e.ctl.countWhere(func(i e2eInform) bool { return i.key == "factory" }) >= 2
	})
	e.stop()

	sawDevice := false
	for _, in := range e.ctl.snapshot() {
		rows := radioRows(in.payload)
		switch in.key {
		case "device":
			sawDevice = true
			if !slices.Equal(rows, []string{"wifi0/ng", "wifi1/na"}) {
				t.Errorf("adopted inform radio_table %v, want the earlier build's wifi0/wifi1", rows)
			}
		case "factory":
			if !slices.Equal(rows, []string{"ra0/ng", "rai0/na"}) {
				t.Errorf("inform after setdefault: radio_table %v, want ra0/rai0", rows)
			}
		}
	}
	if !sawDevice {
		t.Fatal("no inform on the device key")
	}
	got, found, err := device.Load(e.unit.path("/tp_data/udeco/session/state.json"))
	if err != nil || !found || got.RadioNames != radioNamesMediaTek || got.Adopted {
		t.Errorf("state after setdefault: radio_names %q adopted %v (%v)", got.RadioNames, got.Adopted, err)
	}
	logs := e.logs.all()
	for _, want := range []string{"radio names: wifi0/wifi1 (kept from the adoption made by an earlier build)",
		"radio names: ra0/rai0 (MediaTek, as a real U6-Lite) from now on"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %q", want)
		}
	}
	// the session's static radio rows follow (radio_table_stats fallback)
	if r := e.a.x.Dev.Radios; len(r) != 2 || r[0].Name != "ra0" || r[1].Name != "rai0" {
		t.Errorf("session radios %+v", r)
	}
}
