// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// steerBanWifi has the steering and the ban primitives.
type steerBanWifi struct {
	banWifi
}

func (w steerBanWifi) SteerToBand(ctx context.Context, vif, mac, bssid string) error {
	w.rec.add(fmt.Sprintf("steer:%s@%s->%s", mac, vif, bssid))
	return nil
}

func newNo2Unit(t *testing.T, banErr error) *minUnit {
	u := newRoamUnit(t)
	u.h.a.wifi = steerBanWifi{banWifi{roamWifi: roamWifi{fakeWifi: u.h.wifi}, banErr: banErr}}
	u.h.a.policy.Store(&wifiPolicy{steer: map[string]string{}, roam: map[string]int{}, minRSSI: map[string]int{},
		no2ghz: map[string]bool{"net": true}})
	return &minUnit{u}
}

const bss5 = "ba:a7:b9:3e:15:f8"

// A dual-band client of a "restrict to 5 GHz" SSID that was on the 5 GHz
// BSS lately with a usable signal and now sits on the 2.4 GHz twin is
// asked to move (BSS transition request naming the 5 GHz BSS), whatever
// the band steering mode; one that ignores it is kept off the 2.4 GHz BSS
// for no2ghzDeny, then let back.
func TestNo2GHz(t *testing.T) {
	u := newNo2Unit(t, nil)
	u.reading(false, "wl12", -55)
	got := u.reading(false, "wl02", -50)
	if len(got) != 1 || got[0] != "steer:"+roamPhone+"@wl02->"+bss5 {
		t.Fatalf("calls %v", got)
	}
	got = nil
	for d := time.Duration(0); d < no2ghzJudge; d += 10 * time.Second {
		got = append(got, u.reading(false, "wl02", -50)...)
	}
	if len(got) != 1 || got[0] != "ban:"+roamPhone+"@wl02" {
		t.Fatalf("calls %v, want the ban once the request was ignored", got)
	}
	got = nil
	for d := time.Duration(0); d < no2ghzDeny; d += 10 * time.Second {
		got = append(got, u.reading(false, "wl12", -55)...)
	}
	if len(got) != 1 || got[0] != "unban:"+roamPhone+"@wl02" {
		t.Fatalf("calls %v, want the ban lifted", got)
	}
	// back on 2.4 GHz: a request again only after no2ghzEvery, never a
	// second ban within no2ghzDenyEvery
	got = nil
	for d := time.Duration(0); d < no2ghzDenyEvery-time.Minute; d += 20 * time.Second { // two readings
		got = append(got, u.reading(false, "wl02", -50)...)
		u.reading(false, "wl12", -55)
	}
	for _, c := range got {
		if strings.HasPrefix(c, "ban:") {
			t.Fatalf("banned again within %s: %v", no2ghzDenyEvery, got)
		}
	}
	if n := len(got); n < 2 || n > int(no2ghzDenyEvery/no2ghzEvery)+1 {
		t.Fatalf("%d requests in %s: %v", n, no2ghzDenyEvery, got)
	}
}

// A client that moves after the request is never banned.
func TestNo2GHzMoved(t *testing.T) {
	u := newNo2Unit(t, nil)
	u.reading(false, "wl12", -55)
	u.reading(false, "wl02", -50)
	var got []string
	for i := 0; i < 30; i++ {
		got = append(got, u.reading(false, "wl12", -55)...)
	}
	if len(got) != 0 {
		t.Fatalf("calls %v", got)
	}
}

// Never refused: a client never seen on the 5 GHz BSS, seen there too weak,
// or seen too long ago; a 2.4 GHz signal too weak for 5 GHz to hold; a
// stale reading; an SSID without the setting; observe mode.
func TestNo2GHzLeftAlone(t *testing.T) {
	quiet := func(t *testing.T, u *minUnit, n int, bss string, sig int, stale bool) {
		t.Helper()
		for i := 0; i < n; i++ {
			if got := u.reading(stale, bss, sig); len(got) != 0 {
				t.Fatalf("reading %d on %s: %v", i, bss, got)
			}
		}
	}
	t.Run("never on 5 GHz", func(t *testing.T) {
		quiet(t, newNo2Unit(t, nil), 30, "wl02", -40, false)
	})
	t.Run("weak on 5 GHz", func(t *testing.T) {
		u := newNo2Unit(t, nil)
		quiet(t, u, 1, "wl12", no2ghzMin5-1, false)
		quiet(t, u, 30, "wl02", -40, false)
	})
	t.Run("5 GHz long ago", func(t *testing.T) {
		u := newNo2Unit(t, nil)
		quiet(t, u, 1, "wl12", -50, false)
		u.now = u.now.Add(no2ghzRecent)
		quiet(t, u, 30, "wl02", -40, false)
	})
	t.Run("weak on 2.4 GHz", func(t *testing.T) {
		u := newNo2Unit(t, nil)
		quiet(t, u, 1, "wl12", -50, false)
		quiet(t, u, 30, "wl02", no2ghzMin24-1, false)
	})
	t.Run("stale", func(t *testing.T) {
		u := newNo2Unit(t, nil)
		quiet(t, u, 1, "wl12", -50, false)
		quiet(t, u, 30, "wl02", -40, true)
	})
	t.Run("setting off", func(t *testing.T) {
		u := newNo2Unit(t, nil)
		u.h.a.policy.Store(&wifiPolicy{steer: map[string]string{}, roam: map[string]int{}, minRSSI: map[string]int{}, no2ghz: map[string]bool{}})
		quiet(t, u, 1, "wl12", -50, false)
		quiet(t, u, 30, "wl02", -40, false)
	})
	t.Run("observe", func(t *testing.T) {
		u := newNo2Unit(t, nil)
		u.h.a.takeover.Store(false)
		quiet(t, u, 1, "wl12", -50, false)
		quiet(t, u, 30, "wl02", -40, false)
	})
}

// An allow-list SSID cannot take a ban: the request only, logged once.
func TestNo2GHzAllowList(t *testing.T) {
	u := newNo2Unit(t, bcmwifi.ErrAllowList)
	u.reading(false, "wl12", -55)
	var got []string
	for i := 0; i < 20; i++ {
		got = append(got, u.reading(false, "wl02", -50)...)
	}
	// (the lift that follows is refused the same way, unlogged)
	if len(got) < 2 || !strings.HasPrefix(got[0], "steer:") || !strings.HasPrefix(got[1], "ban:") ||
		strings.Count(" "+strings.Join(got, " "), " ban:") != 1 {
		t.Fatalf("calls %v", got)
	}
	if n := strings.Count(u.h.logs.all(), "allow list"); n != 1 {
		t.Errorf("logged %d times:\n%s", n, u.h.logs.all())
	}
}

// The policy carries the setting only for an enabled SSID on both bands.
func TestNo2GHzPolicy(t *testing.T) {
	p := policyFrom(bcmwifi.Desired{SSIDs: []bcmwifi.SSID{
		{SSID: "a", Enabled: true, No2GHz: true, Bands: []string{"ng", "na"}},
		{SSID: "b", Enabled: true, No2GHz: true, Bands: []string{"ng"}},
		{SSID: "c", Enabled: false, No2GHz: true, Bands: []string{"ng", "na"}},
		{SSID: "d", Enabled: true, Bands: []string{"ng", "na"}},
	}})
	if len(p.no2ghz) != 1 || !p.no2ghz["a"] {
		t.Fatalf("%v", p.no2ghz)
	}
}

// The spec's usable signal (-70 dBm or better on 2.4 GHz), and a ban only
// with a 5 GHz sighting minutes old: a client at the cell edge, or one
// seen on 5 GHz long ago, is never kept off 2.4 GHz.
func TestNo2GHzSpecFloors(t *testing.T) {
	t.Run("-72 on 2.4 GHz", func(t *testing.T) {
		u := newNo2Unit(t, nil)
		u.reading(false, "wl12", -55)
		for i := 0; i < 30; i++ {
			if got := u.reading(false, "wl02", -72); len(got) != 0 {
				t.Fatalf("reading %d: %v", i, got)
			}
		}
	})
	t.Run("5 GHz 40 minutes ago: request, no ban", func(t *testing.T) {
		u := newNo2Unit(t, nil)
		u.reading(false, "wl12", -55)
		u.now = u.now.Add(40 * time.Minute)
		var got []string
		for i := 0; i < 12; i++ {
			got = append(got, u.reading(false, "wl02", -60)...)
		}
		for _, c := range got {
			if strings.HasPrefix(c, "ban:") {
				t.Fatalf("banned on a 40-minute-old 5 GHz sighting: %v", got)
			}
		}
	})
}
