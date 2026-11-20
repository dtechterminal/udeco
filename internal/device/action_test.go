// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"slices"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/repotest"
)

// Actions() is the list the agents' tests walk: it must have every Act*
// constant of action.go, once.
func TestActionsListsEveryVerb(t *testing.T) {
	all := Actions()
	n := 0
	for name, v := range repotest.StringConsts(t, "internal/device/action.go") {
		if !strings.HasPrefix(name, "Act") {
			continue
		}
		n++
		if !slices.Contains(all, v) {
			t.Errorf("Actions() lacks %s (%q)", name, v)
		}
	}
	if n != len(all) || n == 0 {
		t.Errorf("action.go has %d Act* constants, Actions() has %d entries: %q", n, len(all), all)
	}
	slices.Sort(all)
	if len(slices.Compact(all)) != len(Actions()) {
		t.Errorf("Actions() names a verb twice: %q", Actions())
	}
}

func TestActionSplit(t *testing.T) {
	for _, c := range []struct{ act, verb, arg string }{
		{Action(ActReboot), "reboot", ""},
		{Action(ActLED, ArgOn), "led", "on"},
		{Action(ActLocate, ArgOff), "locate", "off"},
		{Action(ActKick, "02:00:00:00:00:a2"), "kick", "02:00:00:00:00:a2"}, // the MAC's colons stay
		{Action(ActQuickScan, "na", "80"), "quick-scan", "na:80"},
	} {
		if v, a := SplitAction(c.act); v != c.verb || a != c.arg {
			t.Errorf("SplitAction(%q) = %q, %q, want %q, %q", c.act, v, a, c.verb, c.arg)
		}
	}
	for _, v := range Actions() {
		if strings.Contains(v, ":") {
			t.Errorf("verb %q has the separator in it", v)
		}
	}
}

// The text of every action, as it was before the verbs had names: logs
// print it and the agents' tests compare it. Each reply is handled by a
// new session.
func TestActionTexts(t *testing.T) {
	const mac = "02:00:00:00:00:a2"
	for _, c := range []struct {
		reply string
		want  []string
	}{
		{`{"_type":"reboot"}`, []string{"reboot"}},
		{`{"_type":"cmd","cmd":"reboot"}`, []string{"reboot"}},
		{`{"_type":"cmd","cmd":"restart"}`, []string{"reboot"}},
		{`{"_type":"setparam","mgmt_cfg":"led_enabled=true\n"}`, []string{"led:on"}},
		{`{"_type":"setparam","mgmt_cfg":"led_enabled=false\n"}`, []string{"led:off"}},
		{`{"_type":"cmd","cmd":"set-locate"}`, []string{"locate:on"}},
		{`{"_type":"cmd","cmd":"locate"}`, []string{"locate:on"}},
		{`{"_type":"cmd","cmd":"unset-locate"}`, []string{"locate:off"}},
		{`{"_type":"cmd","cmd":"kick-sta","mac":"` + mac + `"}`, []string{"kick:" + mac}},
		{`{"_type":"cmd","cmd":"block-sta","mac":"` + mac + `"}`, []string{"block"}},
		{`{"_type":"setparam","blocked_sta":"` + mac + `"}`, []string{"block"}},
		{`{"_type":"cmd","cmd":"scan"}`, []string{"scan"}},
		{`{"_type":"cmd","cmd":"spectrum-scan"}`, []string{"spectrum-scan"}},
		{`{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":80}`, []string{"quick-scan:na:80"}},
		{`{"_type":"cmd","cmd":"quick-scan","scan-band":0}`, []string{"quick-scan:ng:0"}},
		{`{"_type":"cmd","cmd":"authorize-guest","mac":"` + mac + `","minutes":5}`, []string{"guest-auth:" + mac}},
		{`{"_type":"cmd","cmd":"unauthorize-guest","mac":"` + mac + `"}`, []string{"guest-unauth:" + mac}},
		{`{"_type":"cmd","cmd":"rate-update","mac":"` + mac + `","dl_max":4000,"ul_max":-1}`, []string{"rate-update:" + mac}},
	} {
		if o := handle(t, newSession(t), c.reply); !slices.Equal(o.Actions, c.want) {
			t.Errorf("%s: actions %q, want %q", c.reply, o.Actions, c.want)
		}
	}
	// a client leaves the blocked list: its unblock comes before the list
	x := newSession(t)
	handle(t, x, `{"_type":"setparam","blocked_sta":"`+mac+`"}`)
	if o := handle(t, x, `{"_type":"cmd","cmd":"unblock-sta","mac":"`+mac+`"}`); !slices.Equal(o.Actions, []string{"unblock:" + mac, "block"}) {
		t.Errorf("unblock-sta: actions %q", o.Actions)
	}
}
