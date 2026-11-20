// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/translate"
)

func nb(ch, freq, width, center, signal int) apstate.BSS {
	return apstate.BSS{Channel: ch, Freq: freq, Width: width, CenterFreq: center, Signal: signal}
}

// The one-shot auto channel: 2.4 GHz only 1, 6 or 11, 5 GHz no DFS, the
// controller's blocked channels never, the quietest by neighbours (louder
// counts more) and the spectrum table's utilization; a tie keeps the live
// channel.
func TestPickChannel(t *testing.T) {
	all24 := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	all5 := []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 149, 153, 157, 161}
	for _, c := range []struct {
		name    string
		band    string
		allowed []int
		blocked []int
		width   int
		bss     []apstate.BSS
		util    map[int]int
		cur     int
		want    int
	}{
		{"ng quiet 11", "ng", all24, nil, 20, []apstate.BSS{nb(1, 2412, 20, 2412, -50), nb(6, 2437, 20, 2437, -60)}, nil, 1, 11},
		{"ng 11 blocked", "ng", all24, []int{11}, 20, []apstate.BSS{nb(1, 2412, 20, 2412, -50), nb(6, 2437, 20, 2437, -80)}, nil, 1, 6},
		{"ng tie keeps live", "ng", all24, nil, 20, nil, nil, 6, 6},
		{"ng live off the grid", "ng", all24, nil, 20, nil, nil, 3, 1},
		{"ng utilization", "ng", all24, nil, 20, nil, map[int]int{1: 40, 6: 10, 11: 30}, 1, 6},
		{"na 80 avoids a neighbour block", "na", all5, nil, 80, []apstate.BSS{nb(36, 5180, 80, 5210, -55)}, nil, 36, 149},
		{"na never DFS", "na", all5, []int{149, 153, 157, 161}, 80, []apstate.BSS{nb(36, 5180, 80, 5210, -55)}, nil, 36, 36},
		{"na 20 utilization", "na", all5, nil, 20, nil, map[int]int{36: 50, 40: 50, 44: 5, 48: 50, 149: 50, 153: 50, 157: 50, 161: 50}, 36, 44},
	} {
		blocked := map[int]bool{}
		for _, b := range c.blocked {
			blocked[b] = true
		}
		got, _ := pickChannel(c.band, c.allowed, blocked, c.width, c.bss, c.util, c.cur)
		if got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	if got, note := pickChannel("ng", []int{2, 3}, nil, 20, nil, nil, 2); got != 0 || note == "" {
		t.Errorf("no candidate: %d %q", got, note)
	}
}

// At the takeover (a radio restart anyway) an auto 2.4 GHz radio off the
// 1/6/11 grid (the capture's 2l) gets a channel of it; a provision that
// restarts nothing keeps the live channel.
func TestE2EAutoChannel(t *testing.T) {
	cfg, _ := mtkCfg(t)
	cfg = autoNG(cfg)
	e := newE2E(t, cfg, true)
	e.adopt()
	eventually(t, "the bcmwifi dry-run apply", func() bool { return strings.Contains(e.logs.all(), "is live") })
	e.stop()
	var plan string
	e.wifi.mu.Lock()
	for _, p := range e.wifi.plans {
		plan += p.String() + "\n"
	}
	e.wifi.mu.Unlock()
	if !strings.Contains(plan, "wl -i wl0 chanspec 1") && !strings.Contains(plan, "wl -i wl0 chanspec 6") && !strings.Contains(plan, "wl -i wl0 chanspec 11") {
		t.Errorf("no 1/6/11 chanspec for the auto 2.4 GHz radio:\n%s", plan)
	}
	if !strings.Contains(e.logs.all(), "auto channel ng:") {
		t.Error("pick not logged")
	}
}

// autoNG sets the system_cfg's 2.4 GHz radio to auto.
func autoNG(cfg string) string {
	var out []string
	for _, l := range strings.Split(cfg, "\n") {
		if k, _, ok := strings.Cut(l, "="); ok && strings.HasPrefix(k, "radio.") && strings.HasSuffix(k, ".channel") {
			l = k + "=auto"
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// The auto pick rides only a restart of the same radio: a plan that
// restarts the 2.4 GHz radio alone leaves the 5 GHz auto radio on its live
// channel (no restart made for the pick).
func TestAutoChannelsOnlyRestartingRadios(t *testing.T) {
	a := &agent{cfg: &Config{}, o: options{col: &fakeCol{rec: &recorder{}}}, scans: newScanner()}
	d := bcmwifi.Desired{Country: "IN", Radios: map[string]bcmwifi.Radio{
		"ng": {Enabled: true, Width: 20}, "na": {Enabled: true, Width: 80}}}
	out, _ := a.autoChannels(context.Background(), d, translate.Intent{}, func(band string) bool { return band == "ng" })
	if out.Radios["na"].Channel != 0 {
		t.Errorf("5 GHz auto radio picked %d although only 2.4 GHz restarts", out.Radios["na"].Channel)
	}
	if out.Radios["ng"].Channel == 0 {
		t.Error("2.4 GHz auto radio got no pick")
	}
}
