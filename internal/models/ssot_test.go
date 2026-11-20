// SPDX-License-Identifier: GPL-2.0-or-later

package models

import (
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/inform"
	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// The model codes named in agent.go are catalogue entries, and the agent's
// profile exists for exactly them.
func TestAgentModelCodes(t *testing.T) {
	agent := map[string]bool{DecoAgentModel: true}
	for code := range JCOW414Models {
		agent[code] = true
	}
	if len(agent) != 3 || !agent[ModelUAL6] || !agent[ModelU7LT] || !agent[ModelUHDIW] {
		t.Errorf("agent models %v, want %s, %s and %s", agent, ModelUAL6, ModelU7LT, ModelUHDIW)
	}
	for _, m := range All() {
		if _, ok := DecoAgentProfile(m, nil); ok != agent[m.Code] {
			t.Errorf("%s: agent profile %v, want %v", m.Code, ok, agent[m.Code])
		}
		delete(agent, m.Code)
	}
	for code := range agent {
		t.Errorf("%s is not in the catalogue", code)
	}
	// only the in-wall model has LAN ports to report
	for code := range JCOW414Models {
		m, _ := Lookup(code)
		if got, want := m.RearUplinkPort() > 0, code == ModelUHDIW; got != want {
			t.Errorf("%s: LAN ports %v, want %v", code, got, want)
		}
	}
	if m, _ := Lookup(DecoAgentModel); m.RearUplinkPort() != 0 {
		t.Errorf("%s has a rear uplink port", DecoAgentModel)
	}
}

// The default model of the controller-side tools is the measured one, and
// the generated catalogue entry of that model says what inform says.
func TestDefaultModelIsU7PG2(t *testing.T) {
	m, ok := Lookup(DefaultModel)
	if !ok {
		t.Fatalf("%s is not in the catalogue", DefaultModel)
	}
	if DefaultModel != inform.U7PG2.Model {
		t.Errorf("DefaultModel %s, inform.U7PG2 is %s", DefaultModel, inform.U7PG2.Model)
	}
	if m.Display != inform.U7PG2ModelDisplay || m.Version != inform.U7PG2Version {
		t.Errorf("catalogue %q %q, inform %q %q", m.Display, m.Version, inform.U7PG2ModelDisplay, inform.U7PG2Version)
	}
	// Profile ignores the catalogue entry for this code
	if p := Profile(m); p.Display != inform.U7PG2ModelDisplay || p.Version != inform.U7PG2Version {
		t.Errorf("Profile: %q %q", p.Display, p.Version)
	}
}

// The default model is also written where Go cannot be asked: the OpenWrt
// package's own fallback and shipped config (a device script and its UCI
// file, self-contained on purpose), the example config of cmd/udeco, and
// the docs that tell the reader what they get without choosing.
func TestDefaultModelWhereItIsWritten(t *testing.T) {
	code, display, version := DefaultModel, inform.U7PG2ModelDisplay, inform.U7PG2Version
	for rel, phrases := range map[string][]string{
		"packaging/files/etc/init.d/unifi-openwrt": {"config_get model main model '" + code + "'"},
		"packaging/files/etc/config/unifi-openwrt": {"option model '" + code + "'"},
		"deploy/udeco.example.json":                {`"model": "` + code + `",`},
		"docs/internals.md": {"(default `" + code + "`, `" + display + "`, `" + version + "`)",
			"default `" + code + "`, " + display + ")"},
		"docs/deco/README.md": {"(default model `" + code + "`)"},
	} {
		for _, p := range phrases {
			repotest.MustContain(t, rel, p)
		}
	}
}

// The U7PG2's power range and streams are written in three places that do
// not agree on the power:
//
//   - internal/inform/profile.go, U7PG2.Radios (the measured profile, what
//     an adopted device reports through models.Profile): 6..22 dBm on both
//     bands;
//   - internal/inform/u7pg2.go, DefaultU7PG2Radios (the pending inform and a
//     session's default radio_table): 5..22 dBm on 2.4 GHz, 5..23 on 5 GHz;
//   - internal/models/catalog.json, the generated U7PG2 entry (tools/
//     gen-models.py; not used for this code by Profile): 5..22 and 5..23.
//
// Which one the controller sees depends on the code path. Making them one
// changes what is reported, so it is the owner's decision; until then this
// test holds each to today's value, and fails when one of them moves alone.
func TestU7PG2PowerTablesAsToday(t *testing.T) {
	type row struct{ min, max, nss int }
	want := map[string]map[string]row{
		"inform.U7PG2.Radios":       {"ng": {6, 22, 3}, "na": {6, 22, 3}},
		"inform.DefaultU7PG2Radios": {"ng": {5, 22, 3}, "na": {5, 23, 3}},
		"catalog.json":              {"ng": {5, 22, 3}, "na": {5, 23, 3}},
	}
	got := map[string]map[string]row{"inform.U7PG2.Radios": {}, "inform.DefaultU7PG2Radios": {}, "catalog.json": {}}
	for band, r := range inform.U7PG2.Radios {
		got["inform.U7PG2.Radios"][band] = row{r.MinTx, r.MaxTx, r.NSS}
	}
	for _, r := range inform.DefaultU7PG2Radios() {
		got["inform.DefaultU7PG2Radios"][r.Radio] = row{r.MinTxpower, r.MaxTxpower, r.NSS}
	}
	m, _ := Lookup(inform.U7PG2Model)
	for _, r := range m.Radios {
		got["catalog.json"][r.Band] = row{r.MinTx, r.MaxTx, r.NSS}
	}
	for src, bands := range want {
		if len(got[src]) != len(bands) {
			t.Errorf("%s: bands %v, want %v", src, got[src], bands)
		}
		for band, w := range bands {
			if g := got[src][band]; g != w {
				t.Errorf("%s %s: min %d max %d nss %d, want %d %d %d", src, band, g.min, g.max, g.nss, w.min, w.max, w.nss)
			}
		}
	}
	// the streams are the one thing all three agree on
	for src, bands := range got {
		for band, g := range bands {
			if g.nss != inform.U7PG2.Radios[band].NSS {
				t.Errorf("%s %s: %d streams, the measured profile has %d", src, band, g.nss, inform.U7PG2.Radios[band].NSS)
			}
		}
	}
}

// A radio of the agent that is not 802.11ax reports the measured U7PG2's
// ieee_modes word (inform.U7PG2), which this package used to write a second
// time: 10 and 21, the words on the wire before and after.
func TestNonAXIEEEModes(t *testing.T) {
	if nonAXIEEEModes("ng") != 10 || nonAXIEEEModes("na") != 21 {
		t.Errorf("non-ax ieee_modes: ng %d na %d, want 10 and 21", nonAXIEEEModes("ng"), nonAXIEEEModes("na"))
	}
}

// JCOW414MaxTx is the one statement of the unit's power; the agent's
// profile of every JCOW414 model is capped at it.
func TestJCOW414MaxTx(t *testing.T) {
	if JCOW414MaxTx("ng") <= 0 || JCOW414MaxTx("na") <= 0 || JCOW414MaxTx("6e") != 0 {
		t.Fatalf("JCOW414MaxTx ng %d na %d 6e %d", JCOW414MaxTx("ng"), JCOW414MaxTx("na"), JCOW414MaxTx("6e"))
	}
	for code := range JCOW414Models {
		m, _ := Lookup(code)
		p, ok := DecoAgentProfile(m, map[string]bool{})
		if !ok {
			t.Fatalf("%s: no agent profile", code)
		}
		for _, r := range m.Radios {
			if got, want := p.Radios[r.Band].MaxTx, min(r.MaxTx, JCOW414MaxTx(r.Band)); got != want {
				t.Errorf("%s %s: max_tx %d, want %d", code, r.Band, got, want)
			}
		}
	}
}
