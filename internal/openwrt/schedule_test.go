// SPDX-License-Identifier: GPL-2.0-or-later

package openwrt

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

func TestScheduleConf(t *testing.T) {
	c, err := scheduleConf([]translate.Schedule{{Section: "unifi_radio0_12", OnDuring: true, Windows: map[string][]string{"mon": {"0800-0900"}, "sun": {"2200-0200"}}}})
	if err != nil {
		t.Fatal(err)
	}
	want := "unifi_radio0_12 on - 0 0\nunifi_radio0_12 on mon 0800 0900\nunifi_radio0_12 on sun 2200 0200\n"
	if c != want {
		t.Fatalf("got\n%s", c)
	}
	if _, err := scheduleConf([]translate.Schedule{{Section: "x; reboot"}}); err == nil {
		t.Fatal("bad section accepted")
	}
	if !strings.Contains(scheduleScript, "wifi reload") {
		t.Fatal("script")
	}
}

// The script's awk decides up/down per section; a window's end minute is
// inclusive (UAP within_schedule: now <= end), including across midnight.
func TestScheduleScriptInclusiveEnd(t *testing.T) {
	awk, err := exec.LookPath("awk")
	if err != nil {
		t.Skip("no awk")
	}
	_, rest, ok := strings.Cut(scheduleScript, `-v t="$t" '`)
	prog, _, ok2 := strings.Cut(rest, `' "$C"`)
	if !ok || !ok2 {
		t.Fatal("awk program not found in the script")
	}
	conf, err := scheduleConf([]translate.Schedule{
		{Section: "on1", OnDuring: true, Windows: map[string][]string{"mon": {"0800-0900"}}},
		{Section: "wrap", OnDuring: true, Windows: map[string][]string{"mon": {"2200-0159"}}},
		{Section: "off1", OnDuring: false, Windows: map[string][]string{"mon": {"0800-0900"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "schedule.conf")
	if err := os.WriteFile(f, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ tm, want string }{
		{"0759", "off1:1 on1:0 wrap:0"},
		{"0800", "off1:0 on1:1 wrap:0"},
		{"0900", "off1:0 on1:1 wrap:0"}, // end inclusive
		{"0901", "off1:1 on1:0 wrap:0"},
		{"0159", "off1:1 on1:0 wrap:1"}, // wrapped end inclusive
		{"0200", "off1:1 on1:0 wrap:0"},
	} {
		out, err := exec.Command(awk, "-v", "d=mon", "-v", "t="+tc.tm, prog, f).Output()
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Fields(string(out))
		sort.Strings(got)
		if g := strings.Join(got, " "); g != tc.want {
			t.Errorf("%s: %q, want %q", tc.tm, g, tc.want)
		}
	}
}
