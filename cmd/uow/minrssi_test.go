// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"reflect"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/models"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// The minimum RSSI the daemon drops connected clients below is read with the
// rule the plan has for hostapd's rssi_reject_assoc_rssi
// (translate.LegacyStamgr). The wanted values are what the daemon's own
// loop gave before it was translate's.
func TestMinRSSIByRadio(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  string
		want map[string]int
	}{
		{"nothing sent", "", map[string]int{}},
		{"dBm", "stamgr.1.radio=ng\nstamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=-75", map[string]int{"ng": -75}},
		{"above the noise floor", "stamgr.2.radio=na\nstamgr.2.minrssi.status=true\nstamgr.2.minrssi.rssi=20", map[string]int{"na": -75}},
		{"both radios", "stamgr.1.radio=ng\nstamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=-70\n" +
			"stamgr.2.radio=na\nstamgr.2.minrssi.status=true\nstamgr.2.minrssi.rssi=-80", map[string]int{"ng": -70, "na": -80}},
		{"off", "stamgr.1.radio=ng\nstamgr.1.minrssi.status=false\nstamgr.1.minrssi.rssi=-75", map[string]int{}},
		{"status enabled is not true", "stamgr.1.radio=ng\nstamgr.1.minrssi.status=enabled\nstamgr.1.minrssi.rssi=-75", map[string]int{}},
		{"zero", "stamgr.1.radio=ng\nstamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=0", map[string]int{}},
		{"not a number", "stamgr.1.radio=ng\nstamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=low", map[string]int{}},
		{"95 above the noise floor is 0 dBm, and on", "stamgr.1.radio=ng\nstamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=95", map[string]int{"ng": 0}},
		{"section 8 is read, 9 is not", "stamgr.8.radio=ng\nstamgr.8.minrssi.status=true\nstamgr.8.minrssi.rssi=-71\n" +
			"stamgr.9.radio=na\nstamgr.9.minrssi.status=true\nstamgr.9.minrssi.rssi=-72", map[string]int{"ng": -71}},
		{"the later section of a radio wins", "stamgr.1.radio=ng\nstamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=-70\n" +
			"stamgr.3.radio=ng\nstamgr.3.minrssi.status=true\nstamgr.3.minrssi.rssi=-60", map[string]int{"ng": -60}},
		{"stamgr.status is not looked at", "stamgr.status=disabled\nstamgr.1.radio=ng\nstamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=-75",
			map[string]int{"ng": -75}},
		{"no radio", "stamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=-75", map[string]int{"": -75}},
		{"a client limit only", "stamgr.1.radio=ng\nstamgr.1.loadbalance.status=true\nstamgr.1.loadbalance.maxsta=30", map[string]int{}},
	} {
		if got := minRSSIByRadio(translate.ParseCfg(c.cfg)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// The model the daemon is adopted as when none is chosen is the one
// measured model (models.DefaultModel), a catalogue entry.
func TestDefaultModel(t *testing.T) {
	if _, ok := models.Lookup(models.DefaultModel); !ok || models.DefaultModel != "U7PG2" {
		t.Errorf("default model %q (in the catalogue: %v)", models.DefaultModel, ok)
	}
}
