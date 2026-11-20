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
