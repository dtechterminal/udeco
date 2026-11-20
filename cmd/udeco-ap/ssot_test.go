// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"reflect"
	"regexp"
	"slices"
	"testing"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/device"
	"github.com/dtechterminal/udeco/internal/models"
	"github.com/dtechterminal/udeco/internal/snmpagent"
	"github.com/dtechterminal/udeco/internal/translate"
)

// Tests that hold facts written in two packages to each other, where this
// package is the one that imports both.

// fillValue sets v (addressable) to a value that is not its zero value, all
// the way down. Strings become "ng" so that a list of bands survives
// desiredFrom's band check.
func fillValue(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		v.SetString("ng")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(7)
	case reflect.Slice:
		e := reflect.New(v.Type().Elem()).Elem()
		fillValue(t, e)
		v.Set(reflect.Append(reflect.MakeSlice(v.Type(), 0, 1), e))
	case reflect.Map:
		k, e := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		fillValue(t, k)
		fillValue(t, e)
		m := reflect.MakeMap(v.Type())
		m.SetMapIndex(k, e)
		v.Set(m)
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		fillValue(t, p.Elem())
		v.Set(p)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			fillValue(t, v.Field(i))
		}
	default:
		t.Fatalf("fillValue: no value for a %s", v.Kind())
	}
}

// desiredFrom names the fields of translate.RadioIntent and WLANIntent one
// by one. A field added to either is either carried into bcmwifi's Desired
// or listed here with where it goes instead: nothing is dropped unnoticed.
func TestDesiredFromCarriesEveryField(t *testing.T) {
	notCarried := map[string]map[string]string{
		"RadioIntent": {
			"Blocked": "read from the Intent by the agent's automatic channel (autochan.go), not a bcmwifi setting",
		},
		"WLANIntent": {
			"Devnames": "the controller's VAP names: nothing to configure (the inform's vap_table names come from system_cfg)",
		},
	}
	check := func(kind, field string, base, got bcmwifi.Desired) {
		t.Helper()
		carried := !reflect.DeepEqual(base, got)
		_, listed := notCarried[kind][field]
		switch {
		case !carried && !listed:
			t.Errorf("translate.%s.%s does not reach bcmwifi.Desired: map it in desiredFrom, or list it here as not carried", kind, field)
		case carried && listed:
			t.Errorf("translate.%s.%s is carried now: take it off the not-carried list", kind, field)
		}
	}

	radio := func(r translate.RadioIntent) bcmwifi.Desired {
		d, _ := desiredFrom(translate.Intent{Radios: map[string]translate.RadioIntent{"ng": r}})
		return d
	}
	rt := reflect.TypeOf(translate.RadioIntent{})
	for i := 0; i < rt.NumField(); i++ {
		var r translate.RadioIntent
		fillValue(t, reflect.ValueOf(&r).Elem().Field(i))
		check("RadioIntent", rt.Field(i).Name, radio(translate.RadioIntent{}), radio(r))
	}

	wlan := func(w translate.WLANIntent) bcmwifi.Desired {
		d, _ := desiredFrom(translate.Intent{WLANs: []translate.WLANIntent{w}})
		return d
	}
	wt := reflect.TypeOf(translate.WLANIntent{})
	for i := 0; i < wt.NumField(); i++ {
		var w translate.WLANIntent
		fillValue(t, reflect.ValueOf(&w).Elem().Field(i))
		check("WLANIntent", wt.Field(i).Name, wlan(translate.WLANIntent{}), wlan(w))
	}
	for kind, fields := range notCarried {
		typ := map[string]reflect.Type{"RadioIntent": rt, "WLANIntent": wt}[kind]
		for f := range fields {
			if _, ok := typ.FieldByName(f); !ok {
				t.Errorf("not-carried list: translate.%s has no field %s", kind, f)
			}
		}
	}

	// the two small per-band types are translate's own, so a whole value
	// comes through (and as a copy: the Intent's maps are not the Desired's)
	var w translate.WLANIntent
	fillValue(t, reflect.ValueOf(&w).Elem())
	w.Radius = nil // RadSec servers hold the WLAN off; not this test's subject
	s := wlan(w).SSIDs[0]
	if !reflect.DeepEqual(s.PerBand, w.PerBand) || !reflect.DeepEqual(s.MinRateOpts, w.MinRateOpts) {
		t.Errorf("per band: %+v and %+v, want %+v and %+v", s.PerBand, s.MinRateOpts, w.PerBand, w.MinRateOpts)
	}
	s.PerBand["na"], s.MinRateOpts["na"] = bcmwifi.BandSettings{}, bcmwifi.RateOpts{}
	if len(w.PerBand) != 1 || len(w.MinRateOpts) != 1 {
		t.Error("the Desired shares its per-band maps with the Intent")
	}
	if s := wlan(translate.WLANIntent{}).SSIDs[0]; s.PerBand != nil || s.MinRateOpts != nil {
		t.Errorf("no per-band settings: %+v %+v, want nil", s.PerBand, s.MinRateOpts)
	}
}

// The model checks of the config say what they said before the codes were
// named in internal/models.
func TestConfigModelErrorTexts(t *testing.T) {
	base := `"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1"`
	for js, want := range map[string]string{
		`{` + base + `,"model":"U7PG2"}`: `config: model "U7PG2": only UAL6 is supported (its capability words are chosen for this hardware)`,
		`{` + base + `,"platform":"jio-mtk"}`: `config: model "UAL6": platform jio-mtk is reported as U7LT (UAP-AC-Lite) or UHDIW (UAP-IW-HD, with its LAN ports): ` +
			`set "model": "U7LT" or "UHDIW"`,
		`{` + base + `,"platform":"jio-mtk","model":"U7LT","ports_unlocked":[1]}`: `config: ports_unlocked needs model UHDIW (the only model reported with LAN ports)`,
		`{` + base + `,"platform":"jio-mtk","model":"u7lt","ports_confirm_s":90}`: `config: ports_confirm_s and ports_loss_s need model UHDIW (the only model reported with LAN ports)`,
		`{` + base + `,"platform":"jio-mtk","model":"U7LT","ports_loss_s":300}`:   `config: ports_confirm_s and ports_loss_s need model UHDIW (the only model reported with LAN ports)`,
	} {
		if _, err := parseConfig([]byte(js)); err == nil || err.Error() != want {
			t.Errorf("%s:\n got  %v\n want %s", js, err, want)
		}
	}
	// the default is the Deco's model, and the port settings pass on the
	// one model with LAN ports
	c, err := parseConfig([]byte(`{` + base + `}`))
	if err != nil || c.Model != models.DecoAgentModel || c.hasLANPorts() {
		t.Errorf("default: %v, model %q, LAN ports %v", err, c.Model, c.hasLANPorts())
	}
	c, err = parseConfig([]byte(`{` + base + `,"platform":"jio-mtk","model":"uhdiw","ports_unlocked":[1],"ports_confirm_s":90,"ports_loss_s":300}`))
	if err != nil || c.Model != models.ModelUHDIW || !c.hasLANPorts() {
		t.Errorf("UHDIW: %v, model %q", err, c.Model)
	}
}

// LAN ports are reported for the configured model exactly when it has a
// rear uplink jack: on platform jio-mtk, the UAP-IW-HD.
func TestHasLANPorts(t *testing.T) {
	for code := range models.JCOW414Models {
		a := &agent{cfg: &Config{Platform: PlatformJio, Model: code}}
		if got, want := a.portsOn(), code == models.ModelUHDIW; got != want {
			t.Errorf("jio-mtk as %s: portsOn %v, want %v", code, got, want)
		}
	}
	if a := (&agent{cfg: &Config{Model: models.DecoAgentModel}}); a.portsOn() {
		t.Error("a Deco reports LAN ports")
	}
	// a Deco never does, whatever its model says
	if a := (&agent{cfg: &Config{Model: models.ModelUHDIW}}); a.portsOn() {
		t.Error("portsOn off platform jio-mtk")
	}
}

// A state of an earlier build was adopted as the code that build used.
func TestLegacyAdoptedModelCodes(t *testing.T) {
	if got := (&agent{cfg: &Config{Platform: PlatformJio, Model: models.ModelUHDIW}}).legacyAdoptedModel(); got != "U7LT" {
		t.Errorf("jio-mtk: %q", got)
	}
	if got := (&agent{cfg: &Config{Model: models.DecoAgentModel}}).legacyAdoptedModel(); got != "UAL6" {
		t.Errorf("Deco: %q", got)
	}
}

// The display name used when none is set (the SNMP view's model, sysDescr,
// the syslog host name) is the catalogue's name of the Deco's model.
func TestDefaultDescrIsTheDecoModelsDisplay(t *testing.T) {
	m, ok := models.Lookup(models.DecoAgentModel)
	if !ok || m.Display != snmpagent.DefaultDescr {
		t.Errorf("snmpagent.DefaultDescr %q, the catalogue's %s is %q (found %v)", snmpagent.DefaultDescr, models.DecoAgentModel, m.Display, ok)
	}
}

// A device login is checked twice, on purpose in separate code: translate
// when it reads the controller's users, internal/device when a site login is
// handed over. The second check allows no name the first refuses: the same
// pattern, and every system account of the first among the second's.
func TestLoginNameRuleTwice(t *testing.T) {
	if a, b := translate.LoginNamePattern(), device.SiteLoginNamePattern(); a != b {
		t.Errorf("login name pattern: translate %q, device %q", a, b)
	}
	if _, err := regexp.Compile(translate.LoginNamePattern()); err != nil {
		t.Fatal(err)
	}
	site := device.SiteSystemUsers()
	base := translate.SystemUsers()
	if len(base) == 0 {
		t.Fatal("translate has no system accounts")
	}
	for _, n := range base {
		if !slices.Contains(site, n) {
			t.Errorf("%q is a system account for translate, and a site login for device", n)
		}
	}
	// the accessors hand out copies
	base[0], site[0] = "x", "x"
	if translate.SystemUsers()[0] == "x" || device.SiteSystemUsers()[0] == "x" {
		t.Error("an accessor returned its own list")
	}
}
