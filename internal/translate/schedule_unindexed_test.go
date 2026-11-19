// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"reflect"
	"testing"
)

// A controller that does not see fw_caps 0x1000 writes un-indexed
// schedule_<day> keys; they must still give the WLAN its windows instead of
// "never on" (WLAN off).
func TestWlanScheduleUnindexed(t *testing.T) {
	cfg := Cfg{
		"wireless.1.schedule_enabled": "enabled",
		"wireless.1.schedule_mon":     "0800-1659",
		"wireless.1.schedule_sat.0":   "2200-0159",
		"wireless.1.schedule_sat":     "0100-0200", // ignored: the indexed form wins
	}
	s := wlanSchedule(cfg, "wireless.1.", "")
	if s == nil {
		t.Fatal("schedule not parsed")
	}
	want := map[string][]string{"mon": {"0800-1659"}, "sat": {"2200-0159"}}
	for d, w := range want {
		if !reflect.DeepEqual(s.Windows[d], w) {
			t.Errorf("%s windows = %v, want %v", d, s.Windows[d], w)
		}
	}
	if on, never := scheduleOn(s); never || len(on) == 0 {
		t.Errorf("scheduleOn = %v never=%v, want on windows", on, never)
	}
}
