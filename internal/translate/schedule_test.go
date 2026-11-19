// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"reflect"
	"testing"
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
