// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"reflect"
	"testing"
	"time"
)

func TestWLANSchedule(t *testing.T) {
	// schedule_invert=enabled: down during the windows (UAP within_schedule
	// mode "down" when the schedule_invert.<vap> file exists)
	c := ParseCfg("wireless.6.schedule_enabled=enabled\nwireless.6.schedule_invert=enabled\nwireless.6.schedule_mon.0=0800-0900\nwireless.6.schedule_mon.1=1800-1900\nwireless.6.schedule_sun.0=bad\n")
	s := wlanSchedule(c, "wireless.6.", "sec")
	if s == nil || s.OnDuring || !reflect.DeepEqual(s.Windows["mon"], []string{"0800-0900", "1800-1900"}) || len(s.Windows["sun"]) != 0 {
		t.Fatalf("%+v", s)
	}
	// no schedule_invert (the default): up during the windows
	for _, inv := range []string{"", "wireless.6.schedule_invert=disabled\n"} {
		c := ParseCfg("wireless.6.schedule_enabled=enabled\n" + inv + "wireless.6.schedule_tue.0=0000-2359\n")
		if s := wlanSchedule(c, "wireless.6.", "sec"); s == nil || !s.OnDuring {
			t.Fatalf("%q: %+v", inv, s)
		}
	}
	if wlanSchedule(ParseCfg("wireless.1.schedule_enabled=disabled\n"), "wireless.1.", "x") != nil {
		t.Fatal("disabled schedule")
	}
}

// IntentFromCfg sets Schedule.OnDuring itself (intent.go); it must agree
// with wlanSchedule, which Plan (and the OpenWrt schedule script) uses.
func TestScheduleAgreesWithIntent(t *testing.T) {
	base := "radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght20\nwireless.1.ssid=s\nwireless.1.parent=wifi0\nwireless.1.usage=user\naaa.1.ssid=s\n" +
		"wireless.1.schedule_enabled=enabled\nwireless.1.schedule_mon.0=0800-0859\nwireless.1.schedule_wed.0=0000-2359\n"
	for _, inv := range []string{"", "wireless.1.schedule_invert=disabled\n", "wireless.1.schedule_invert=enabled\n"} {
		cfg := ParseCfg(base + inv)
		s := wlanSchedule(cfg, "wireless.1.", "")
		want, _ := scheduleOn(s)
		in, _ := IntentFromCfg(base + inv)
		if len(in.WLANs) != 1 {
			t.Fatalf("%q: wlans %+v", inv, in.WLANs)
		}
		if !reflect.DeepEqual(in.WLANs[0].Schedule, want) {
			t.Errorf("%q: intent %q, schedule.go %q", inv, in.WLANs[0].Schedule, want)
		}
	}
	// and the polarity itself: not inverted = up 08:00-09:00 Monday
	// (end minute 08:59 inclusive) and all Wednesday
	s := wlanSchedule(ParseCfg(base), "wireless.1.", "")
	got, _ := scheduleOn(s)
	if !reflect.DeepEqual(got, []string{"mon 0800-0900", "wed 0000-2400"}) {
		t.Fatalf("%q", got)
	}
}

// ScheduleOn reads the windows of a WLANIntent.Schedule (the agent's worker
// calls it; this test came with it from cmd/udeco-ap).
func TestScheduleOnNow(t *testing.T) {
	mon := time.Date(2026, 11, 16, 0, 0, 0, 0, time.Local) // a Monday
	w := []string{"mon 0800-1730", "tue 0000-2400"}
	for _, c := range []struct {
		at time.Time
		on bool
	}{
		{mon.Add(7*time.Hour + 59*time.Minute), false},
		{mon.Add(8 * time.Hour), true},
		{mon.Add(17*time.Hour + 29*time.Minute), true},
		{mon.Add(17*time.Hour + 30*time.Minute), false},
		{mon.Add(24*time.Hour + 23*time.Hour + 59*time.Minute), true},
		{mon.Add(48 * time.Hour), false},
	} {
		if got := ScheduleOn(w, c.at); got != c.on {
			t.Errorf("%s: %v", c.at.Format("Mon 15:04"), got)
		}
	}
	// no window, and text that is no window: off
	for _, w := range [][]string{nil, {}, {"mon"}, {"mon 0800"}, {"mon 0800-"}, {"mon -0900"}, {"mon 0900-0800"}, {"MON 0000-2400"},
		{"monday 0000-2400"}, {" mon 0000-2400"}, {"mon 0000-2401"}, {"mon 0060-2400"}, {"mon 000-2400"}, {"mon -123-2400"}} {
		if ScheduleOn(w, mon.Add(8*time.Hour+30*time.Minute)) {
			t.Errorf("%q: on", w)
		}
	}
	// every day's name is the one scheduleOn writes
	for i, d := range days {
		at := mon.AddDate(0, 0, i).Add(12 * time.Hour)
		for _, e := range days {
			if got := ScheduleOn([]string{e + " 0000-2400"}, at); got != (d == e) {
				t.Errorf("%s at %s: %v", e, at.Format("Mon"), got)
			}
		}
	}
}

// hhmm is the one reader of "HHMM" (scheduleOn and ScheduleOn; the agent
// had its own, which gave the same number for every input). A caller takes
// any negative number as invalid.
func TestHHMM(t *testing.T) {
	for s, want := range map[string]int{
		"0000": 0, "0059": 59, "0100": 60, "0800": 480, "1730": 1050, "2359": 1439, "2400": 1440,
		"+800": 480, // strconv takes a sign: four characters, 08:00
	} {
		if got := hhmm(s); got != want {
			t.Errorf("hhmm(%q) = %d, want %d", s, got, want)
		}
	}
	for _, s := range []string{"", "0", "800", "08000", "0060", "0099", "2401", "2460", "2500", "9999", "08:0", "ab00", " 800", "080 ", "-123", "-001"} {
		if got := hhmm(s); got >= 0 {
			t.Errorf("hhmm(%q) = %d, want a negative number", s, got)
		}
	}
}

// The text scheduleOn writes is the text ScheduleOn reads: for every minute
// of a week, ScheduleOn of the written windows says what the controller's
// windows mean (a UAP's within_schedule: from <= now <= end, a window that
// ends before it starts runs into the next day; inverted = off during them).
func TestScheduleOnReadsWhatScheduleOnWrites(t *testing.T) {
	raw := map[string][]string{
		"mon": {"0800-0859", "1200-1200"},
		"tue": {"0000-2359"},
		"wed": {"2300-0059"}, // into Thursday
		"fri": {"0000-0000", "2359-2359", "1000-1100", "1030-1130"},
		"sun": {"2200-0159"}, // into Monday
	}
	in := func(d string, m int) bool { // the controller's meaning
		prev := days[(indexOf(days, d)+len(days)-1)%len(days)]
		for _, w := range raw[d] {
			a, b := hhmm(w[:4]), hhmm(w[5:])
			if a <= b && a <= m && m <= b || a > b && m >= a {
				return true
			}
		}
		for _, w := range raw[prev] {
			if a, b := hhmm(w[:4]), hhmm(w[5:]); a > b && m <= b {
				return true
			}
		}
		return false
	}
	mon := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC) // a Monday
	for _, during := range []bool{true, false} {
		windows, never := scheduleOn(&Schedule{OnDuring: during, Windows: raw})
		if windows == nil || never {
			t.Fatalf("OnDuring %v: windows %v never %v", during, windows, never)
		}
		for i, d := range days {
			for m := 0; m < 24*60; m++ {
				at := mon.AddDate(0, 0, i).Add(time.Duration(m) * time.Minute)
				if got, want := ScheduleOn(windows, at), in(d, m) == during; got != want {
					t.Fatalf("OnDuring %v, %s %02d:%02d: on %v, want %v (windows %q)", during, d, m/60, m%60, got, want, windows)
				}
			}
		}
	}
}

func indexOf(list []string, v string) int {
	for i, s := range list {
		if s == v {
			return i
		}
	}
	return -1
}
