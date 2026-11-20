// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// rateWifi is fakeWifi with bcmwifi's per-client limits; it records each
// list it is handed as "rates:<mac>=<down>/<up>,..." ("rates:" = empty).
type rateWifi struct{ *fakeWifi }

func (w rateWifi) SetClientRates(ctx context.Context, rates map[string]bcmwifi.RateLimit) (int, error) {
	var l []string
	for m, r := range rates {
		l = append(l, fmt.Sprintf("%s=%d/%d", m, r.DownKbps, r.UpKbps))
	}
	sort.Strings(l)
	w.rec.add("rates:" + strings.Join(l, ","))
	return len(rates), nil
}

const otherSta = "02:00:00:00:00:c1"

func rateUpdate(mac string, down, up int) string {
	return fmt.Sprintf(`{"_type":"cmd","cmd":"rate-update","mac":"%s","ul_max":%d,"ul_min":64,"dl_max":%d,"dl_min":64}`, mac, up, down)
}

// The controller's rate-update reaches bcmwifi as the whole list, at once;
// a listed client that re-joins gets it handed over again; -1/-1 clears the
// client's entry; the list is kept in the session across a restart and
// handed over at startup.
func TestClientRateUpdate(t *testing.T) {
	var mu sync.Mutex
	present := true
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	rw := rateWifi{h.wifi}
	h.a.o.newWifi = func(bcmwifi.Options) wifiApplier { h.built++; return rw }
	h.col.snap = func() *apstate.Snapshot {
		mu.Lock()
		defer mu.Unlock()
		s := testSnapshot()
		if !present {
			s.Radios[1].VAPs[0].Stations = nil
		}
		return s
	}
	h.ctl.queue(adoptReply, rateUpdate(strings.ToUpper(staMAC), 4000, 1000), rateUpdate(otherSta, 2500, -1))
	h.start()
	want := "rates:" + otherSta + "=2500/0," + staMAC + "=4000/1000"
	eventually(t, "both limits handed over", func() bool { return h.rec.index(want) >= 0 })
	if i := h.rec.index("rates:" + staMAC + "=4000/1000"); i < 0 || i > h.rec.index(want) {
		t.Errorf("first rate-update not applied on its own: %v", h.rec.list())
	}
	// the limited client leaves and re-joins: handed over again
	n := h.rec.count(want)
	mu.Lock()
	present = false
	mu.Unlock()
	c := h.ctl.count()
	eventually(t, "a reading without the client", func() bool { return h.ctl.count() > c+2 })
	mu.Lock()
	present = true
	mu.Unlock()
	eventually(t, "re-join hands the list over", func() bool { return h.rec.count(want) > n })
	if !strings.Contains(h.logs.all(), "per-client speed limits (joined "+staMAC+")") {
		t.Error("re-join not the reason")
	}
	if !strings.Contains(h.logs.all(), "cmd rate-update "+staMAC+" down=4000kbit up=1000kbit") {
		t.Error("rate-update not logged")
	}
	// the controller clears staMAC (back to an unlimited group)
	h.ctl.queue(rateUpdate(staMAC, -1, -1))
	eventually(t, "cleared", func() bool { return h.rec.index("rates:"+otherSta+"=2500/0") >= 0 })
	h.stop()
	if r := h.a.x.S.ClientRates; len(r) != 1 || r[otherSta].DownKbps != 2500 || r[otherSta].UpKbps != 0 {
		t.Errorf("session list %+v", r)
	}

	// restart: the session's list is handed over at startup
	h2 := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true; o.root = h.root })
	rw2 := rateWifi{h2.wifi}
	h2.a.o.newWifi = func(bcmwifi.Options) wifiApplier { h2.built++; return rw2 }
	h2.start()
	eventually(t, "handed over at startup", func() bool { return h2.rec.index("rates:"+otherSta+"=2500/0") >= 0 })
	h2.stop()
}

// A Wi-Fi backend without per-client limits (jio-mtk) logs the cmd as not
// supported, once; the session still keeps the list.
func TestClientRateUpdateUnsupported(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	h.ctl.queue(adoptReply, rateUpdate(staMAC, 4000, 1000), rateUpdate(otherSta, 100, 100))
	h.start()
	eventually(t, "replies used", func() bool { return h.ctl.pending() == 0 && h.ctl.count() > 4 })
	h.stop()
	logs := h.logs.all()
	if c := strings.Count(logs, "not supported on platform deco; not applied"); c != 1 {
		t.Errorf("not-supported note logged %d times:\n%s", c, logs)
	}
	if strings.Contains(logs, `action "rate-update`) {
		t.Error("rate-update fell through to the ignored actions")
	}
	if len(h.a.x.S.ClientRates) != 2 {
		t.Errorf("session list %+v", h.a.x.S.ClientRates)
	}
}

// Observe mode keeps the list and changes nothing.
func TestClientRateUpdateObserve(t *testing.T) {
	h := newHarness(t, nil)
	rw := rateWifi{h.wifi}
	h.a.o.newWifi = func(bcmwifi.Options) wifiApplier { h.built++; return rw }
	h.ctl.queue(adoptReply, rateUpdate(staMAC, 4000, 1000))
	h.start()
	eventually(t, "replies used", func() bool { return h.ctl.pending() == 0 && h.ctl.count() > 3 })
	h.stop()
	for _, c := range h.rec.list() {
		if strings.HasPrefix(c, "rates:") {
			t.Errorf("observe mode: %s", c)
		}
	}
	if !strings.Contains(h.logs.all(), "observe mode: per-client speed limit for "+staMAC+" kept") {
		t.Error("observe mode: rate-update not logged")
	}
	if len(h.a.x.S.ClientRates) != 1 {
		t.Errorf("session list %+v", h.a.x.S.ClientRates)
	}
}
