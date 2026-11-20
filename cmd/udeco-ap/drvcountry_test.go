// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

// driver_country overrides the site country; a DFS channel the controller
// sets is then likely refused (US/0 has no 52-144 on an X20): the note says
// to drop the override.
func TestDriverCountryDFSNote(t *testing.T) {
	d := bcmwifi.Desired{Country: "IN", Radios: map[string]bcmwifi.Radio{"na": {Enabled: true, Channel: 100, Width: 80}}}
	got, notes := withDriverCountry(d, "us")
	if got.Country != "US" {
		t.Fatalf("country %q", got.Country)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "remove driver_country") {
		t.Errorf("notes %q", notes)
	}
	d.Radios["na"] = bcmwifi.Radio{Enabled: true, Channel: 149, Width: 80}
	if _, notes := withDriverCountry(d, "US"); strings.Contains(strings.Join(notes, "\n"), "remove driver_country") {
		t.Errorf("non-DFS channel: %q", notes)
	}
	if got, notes := withDriverCountry(d, ""); got.Country != "IN" || len(notes) != 0 {
		t.Errorf("no override: %q %q", got.Country, notes)
	}
}

// driver_country_bands overrides one radio's country (2.4 GHz as US for its
// power, 5 GHz in the site country for DFS); a band override wins over
// driver_country for that band.
func TestDriverCountryBands(t *testing.T) {
	d := bcmwifi.Desired{Country: "IN", Radios: map[string]bcmwifi.Radio{"na": {Enabled: true, Channel: 100, Width: 80}}}
	got, notes := withDriverCountryBands(d, map[string]string{"ng": "us"})
	if got.Country != "IN" || got.BandCountry["ng"] != "US" || got.BandCountry["na"] != "" {
		t.Fatalf("got %q %v", got.Country, got.BandCountry)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "2.4 GHz") {
		t.Errorf("notes %q", notes)
	}
	if got, notes := withDriverCountryBands(d, nil); got.BandCountry != nil || len(notes) != 0 {
		t.Errorf("no override: %v %q", got.BandCountry, notes)
	}
	// same as the site country: nothing to override
	if got, _ := withDriverCountryBands(d, map[string]string{"na": "in"}); len(got.BandCountry) != 0 {
		t.Errorf("same country kept as an override: %v", got.BandCountry)
	}
}

func TestDriverCountryBandsConfig(t *testing.T) {
	for _, tc := range []struct {
		m  map[string]string
		ok bool
	}{
		{map[string]string{"ng": "US"}, true},
		{map[string]string{"na": "IN", "ng": "us"}, true},
		{map[string]string{"6e": "US"}, false},
		{map[string]string{"ng": "USA"}, false},
		{map[string]string{"ng": ""}, false},
	} {
		err := validDriverCountryBands(tc.m)
		if (err == nil) != tc.ok {
			t.Errorf("%v: err %v", tc.m, err)
		}
	}
}
