// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/rf"
)

// What the agent takes from the shared packages (rf, unit, bcmwifi), as
// its own code sees it.

// A spectrum scan runs 5 GHz first; everything else goes in rf's order.
func TestBandOrders(t *testing.T) {
	if got := bands5GFirst(); !slices.Equal(got, []string{"na", "ng"}) {
		t.Errorf("bands5GFirst() = %v", got)
	}
	if got := rf.Bands(); !slices.Equal(got, []string{"ng", "na"}) {
		t.Errorf("rf.Bands() after bands5GFirst = %v", got)
	}
}

// The auto channel's geometry and thresholds are rf's: the 2.4 GHz
// candidates, the 20 MHz channels and MHz a channel covers, and the level
// from which a neighbour counts.
func TestAutoChannelGeometry(t *testing.T) {
	if !slices.Equal(staticChannels["ng"], []int{1, 6, 11}) {
		t.Errorf("static 2.4 GHz candidates %v", staticChannels["ng"])
	}
	for _, c := range []struct {
		band      string
		ch, width int
		sub       []int
		lo, hi    int
	}{
		{"ng", 1, 20, []int{1}, 2402, 2422},
		{"ng", 6, 40, []int{6}, 2427, 2447}, // 2.4 GHz: the channel itself
		{"ng", 11, 20, []int{11}, 2452, 2472},
		{"na", 36, 20, []int{36}, 5170, 5190},
		{"na", 40, 40, []int{36, 40}, 5170, 5210},
		{"na", 44, 80, []int{36, 40, 44, 48}, 5170, 5250},
		{"na", 149, 40, []int{149, 153}, 5735, 5775},
		{"na", 161, 80, []int{149, 153, 157, 161}, 5735, 5815},
		{"na", 165, 20, []int{165}, 5815, 5835},
	} {
		if got := sub20(c.band, c.ch, c.width); !slices.Equal(got, c.sub) {
			t.Errorf("sub20(%s, %d, %d) = %v, want %v", c.band, c.ch, c.width, got, c.sub)
		}
		if lo, hi := span(c.band, c.ch, c.width); lo != c.lo || hi != c.hi {
			t.Errorf("span(%s, %d, %d) = %d-%d, want %d-%d", c.band, c.ch, c.width, lo, hi, c.lo, c.hi)
		}
	}
	// a neighbour counts by its dB above the floor, and not at all at it
	bss := []apstate.BSS{{Freq: 2412, Signal: -60}, {Freq: 2412, Signal: -95}, {Freq: 2412, Signal: -99}}
	if _, why := pickChannel("ng", []int{1}, nil, 20, bss, nil, 0); why != "auto channel ng: 1 (score 35 of 1 candidates)" {
		t.Errorf("score: %q", why)
	}
	if audibleFloor != rf.NoiseFloorDBm || defaultNoise != rf.NoiseFloorDBm {
		t.Errorf("floors %d %d", audibleFloor, defaultNoise)
	}
}

// "The agent owns Wi-Fi" is bcmwifi's hostapd conf of either radio in the
// run dir.
func TestWifiOwnedFiles(t *testing.T) {
	root := t.TempDir()
	a := &agent{o: options{root: root, runDir: "/tmp/udeco"}}
	dir := filepath.Join(root, "tmp/udeco")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	touch := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if a.wifiOwned() {
		t.Error("owned with an empty run dir")
	}
	touch("hapd-wl2.conf") // no radio's
	touch("hapd-wl1.pid")
	if a.wifiOwned() {
		t.Error("owned without a radio's conf")
	}
	touch("hapd-wl1.conf")
	if !a.wifiOwned() {
		t.Error("not owned with wl1's conf")
	}
	os.Remove(filepath.Join(dir, "hapd-wl1.conf"))
	touch("hapd-wl0.conf")
	if !a.wifiOwned() {
		t.Error("not owned with wl0's conf")
	}
}

// Both platforms' radar notifications are radarPayload's map, whose
// radio_name is the inform's radio_table name of the band's radio
// (reportedRadioName), whichever naming the session reports.
func TestRadarPayload(t *testing.T) {
	for _, naming := range []string{radioNamesMediaTek, radioNamesQualcomm} {
		a := &agent{x: radioSession(naming)}
		a.renameRadios()
		want := map[string]any{"event_string": "EVT_AP_RadarDetected", "radio": "na", "radio_name": radioTableName(t, a, "na"), "channel": 100, "freq": 5500}
		if got := a.radarPayload("na", 100, 5500); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: radarPayload = %v, want %v", naming, got, want)
		}
	}
	if n := (&agent{x: radioSession(radioNamesMediaTek)}).reportedRadioName("6e"); n != "" {
		t.Errorf("no 6 GHz radio named %q", n)
	}
}
