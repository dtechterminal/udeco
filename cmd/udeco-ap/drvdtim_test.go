// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

// driver_dtim_bands sets one radio's DTIM for every SSID it serves, over
// the controller's (whose key may be "2g"), and leaves the other band and
// the plan's own maps alone.
func TestDriverDTIMBands(t *testing.T) {
	shared := map[string]int{"2g": 1, "na": 3}
	d := bcmwifi.Desired{SSIDs: []bcmwifi.SSID{
		{ID: "a", Bands: []string{"ng", "na"}, DTIM: shared},
		{ID: "b", Bands: []string{"2g"}},
		{ID: "c", Bands: []string{"na"}, DTIM: map[string]int{"na": 3}},
	}}
	got, notes := withDriverDTIMBands(d, map[string]int{"ng": 2})
	if g := got.SSIDs[0].DTIM; len(g) != 2 || g["ng"] != 2 || g["na"] != 3 {
		t.Errorf("a: %v", g)
	}
	if g := got.SSIDs[1].DTIM; len(g) != 1 || g["ng"] != 2 {
		t.Errorf("b: %v", g)
	}
	if g := got.SSIDs[2].DTIM; len(g) != 1 || g["na"] != 3 {
		t.Errorf("c (5 GHz only) changed: %v", g)
	}
	if shared["2g"] != 1 || len(shared) != 2 {
		t.Errorf("the plan's map was written: %v", shared)
	}
	if d.SSIDs[1].DTIM != nil {
		t.Errorf("the plan's SSID was written: %v", d.SSIDs[1].DTIM)
	}
	if j := strings.Join(notes, "\n"); !strings.Contains(j, "2.4 GHz radio runs DTIM 2 for its 2 SSID(s)") {
		t.Errorf("notes %q", notes)
	}
	if got, notes := withDriverDTIMBands(d, nil); got.SSIDs[1].DTIM != nil || len(notes) != 0 {
		t.Errorf("no override: %v %q", got.SSIDs[1].DTIM, notes)
	}
}

func TestDriverDTIMBandsConfig(t *testing.T) {
	for _, tc := range []struct {
		m  map[string]int
		ok bool
	}{
		{map[string]int{"ng": 2}, true},
		{map[string]int{"ng": 1, "na": 3}, true},
		{map[string]int{"ng": 0}, false},
		{map[string]int{"ng": 256}, false},
		{map[string]int{"2g": 2}, false},
		{map[string]int{"6e": 2}, false},
	} {
		if err := validDriverDTIMBands(tc.m); (err == nil) != tc.ok {
			t.Errorf("%v: err %v", tc.m, err)
		}
	}
}
