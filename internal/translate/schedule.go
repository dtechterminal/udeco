// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"regexp"
	"sort"
	"strconv"
)

// Schedule is a WLAN's broadcast schedule on one AP interface. As on a UAP
// (unifi_util_funcs.sh within_schedule: mode "up" unless the
// schedule_invert.<vap> file exists, which ubntbox writes for
// schedule_invert=enabled), the interface is up during the windows, and
// down during them when the controller sends schedule_invert=enabled.
//
// A window's end is inclusive: within_schedule tests from <= now <= end
// (minutes), so "0800-0900" covers 09:00, and all day is "0000-2359".
type Schedule struct {
	Section  string              // UCI wifi-iface section
	OnDuring bool                // true: up only in the windows (schedule_invert not enabled)
	Windows  map[string][]string // day (mon..sun) -> "HHMM-HHMM", end inclusive
}

var window = regexp.MustCompile(`^[0-2][0-9][0-5][0-9]-[0-2][0-9][0-5][0-9]$`)

var days = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

// wlanSchedule reads wireless.N.schedule_* (nil when not scheduled).
func wlanSchedule(cfg Cfg, w, section string) *Schedule {
	if cfg[w+"schedule_enabled"] != "enabled" {
		return nil
	}
	s := &Schedule{Section: section, OnDuring: cfg[w+"schedule_invert"] != "enabled", Windows: map[string][]string{}}
	for _, d := range days {
		for i := 0; i < 32; i++ { // schedule_<day>.<i> (leaf keys)
			if v := cfg[w+"schedule_"+d+"."+strconv.Itoa(i)]; window.MatchString(v) {
				s.Windows[d] = append(s.Windows[d], v)
			}
		}
		// A controller that thinks the AP lacks multi-block schedules
		// (fw_caps 0x1000) writes one un-indexed schedule_<day> key instead.
		if v := cfg[w+"schedule_"+d]; len(s.Windows[d]) == 0 && window.MatchString(v) {
			s.Windows[d] = append(s.Windows[d], v)
		}
		sort.Strings(s.Windows[d])
	}
	return s
}
