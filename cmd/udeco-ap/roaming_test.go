// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// roamWifi is fakeWifi with bcmwifi's Roaming Assistant primitive; err is
// what it returns (a refusal: the request is recorded all the same).
type roamWifi struct {
	*fakeWifi
	err error
}

func (w roamWifi) RoamAssist(ctx context.Context, r bcmwifi.RoamRequest) error {
	var to []string
	for _, n := range r.Candidates {
		to = append(to, fmt.Sprintf("%s/%s/%d", n.BSSID, n.Band, n.Channel))
	}
	w.rec.add(fmt.Sprintf("roam:%s@%s->%s t=%d", r.MAC, r.Vif, strings.Join(to, ","), r.DisassocTBTT))
	return w.err
}

// roamAssistCfg: WLAN "net" on both bands with 802.11v, and the Roaming
// Assistant on its 5 GHz VAP exactly as Network 11.1.50 writes it.
func roamAssistCfg(extra ...string) string {
	return "radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght20\nradio.2.phyname=wifi1\nradio.2.ieee_mode=11acvht80\n" +
		"wireless.1.ssid=net\nwireless.1.id=w1\nwireless.1.parent=wifi1\nwireless.1.devname=wifi1ap1\n" +
		"wireless.2.ssid=net\nwireless.2.id=w1\nwireless.2.parent=wifi0\nwireless.2.devname=wifi0ap1\n" +
		"aaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\naaa.1.wpa.psk=" + fakePSK + "\naaa.1.bss_transition=enabled\n" +
		"aaa.2.wpa=2\naaa.2.wpa.key.1.mgmt=WPA-PSK\naaa.2.wpa.psk=" + fakePSK + "\naaa.2.bss_transition=enabled\n" +
		strings.Join(extra, "\n") + "\n"
}

// roamHarness: takeover with a backend that has the primitive; the
// station's 5 GHz signal comes from *signal.
func roamHarness(t *testing.T, mu *sync.Mutex, signal *int) *harness {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	rw := roamWifi{fakeWifi: h.wifi}
	h.a.o.newWifi = func(bcmwifi.Options) wifiApplier { h.built++; return rw }
	h.col.snap = func() *apstate.Snapshot {
		mu.Lock()
		defer mu.Unlock()
		s := testSnapshot()
		s.Radios[1].VAPs[0].Stations[0].Signal = *signal
		s.Radios[0].VAPs = []apstate.Radio{{Iface: "wl02", Band: "ng", SSID: "net", BSSID: "b2:a7:b9:00:00:02"}}
		return s
	}
	h.a.scans.addBSS("na", apstate.ScanResult{Band: "na", Time: time.Now(), BSS: []apstate.BSS{
		{BSSID: "b2:a7:b9:00:00:07", SSID: "net", Channel: 36, Signal: -20},  // our own: never a candidate
		{BSSID: "aa:00:00:00:00:01", SSID: "net", Channel: 149, Signal: -60}, // a sibling AP
		{BSSID: "aa:00:00:00:00:09", SSID: "other", Channel: 44, Signal: -40},
	}})
	return h
}

// A station below the controller's threshold on the 5 GHz BSS gets one
// BSS transition request (disassociation timer set) naming the sibling AP
// heard by a scan, never this unit's own 2.4 GHz BSS; then it is held.
func TestRoamingAssistant(t *testing.T) {
	var mu sync.Mutex
	signal := -60
	h := roamHarness(t, &mu, &signal)
	h.a.t.roamSustain = time.Millisecond
	h.ctl.queue(adoptReply, provisionReply(roamAssistCfg("wireless.1.btm_disassoc.status=enabled", "wireless.1.btm_disassoc.threshold=-75")))
	h.start()
	eventually(t, "provisioned", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c1" })
	time.Sleep(50 * time.Millisecond) // readings above the threshold: nothing
	if c := roamCalls(h); len(c) != 0 {
		t.Fatalf("roamed a station above the threshold: %v", c)
	}
	mu.Lock()
	signal = -80
	mu.Unlock()
	want := "roam:" + staMAC + "@wl12->aa:00:00:00:00:01/na/149 t=100"
	eventually(t, "roaming assistant request", func() bool { return h.rec.index(want) >= 0 })
	time.Sleep(50 * time.Millisecond) // more weak readings: held
	h.stop()
	if c := roamCalls(h); len(c) != 1 {
		t.Errorf("requests %v (want 1 per %s)", c, roamHold)
	}
}

// Without the controller's btm_disassoc nothing is sent, however weak.
func TestRoamingAssistantOff(t *testing.T) {
	for name, cfg := range map[string]string{
		"not sent": roamAssistCfg(),
		"disabled": roamAssistCfg("wireless.1.btm_disassoc.status=disabled"),
		// on 5 GHz but the WLAN has no 802.11v: translate leaves it off
		"no 802.11v": roamAssistCfg("wireless.1.btm_disassoc.status=enabled", "wireless.1.btm_disassoc.threshold=-75",
			"aaa.1.bss_transition=disabled"),
	} {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			signal := -85
			h := roamHarness(t, &mu, &signal)
			h.ctl.queue(adoptReply, provisionReply(cfg))
			h.start()
			eventually(t, "provisioned", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c1" })
			time.Sleep(80 * time.Millisecond)
			h.stop()
			if c := roamCalls(h); len(c) != 0 {
				t.Errorf("roamed: %v", c)
			}
		})
	}
}

// Observe mode owns no hostapd: nothing is sent.
func TestRoamingAssistantObserve(t *testing.T) {
	var mu sync.Mutex
	signal := -85
	h := roamHarness(t, &mu, &signal)
	h.a.takeover.Store(false)
	h.ctl.queue(adoptReply, provisionReply(roamAssistCfg("wireless.1.btm_disassoc.status=enabled", "wireless.1.btm_disassoc.threshold=-75")))
	h.start()
	time.Sleep(100 * time.Millisecond)
	h.stop()
	if c := roamCalls(h); len(c) != 0 {
		t.Errorf("roamed in observe mode: %v", c)
	}
}

func TestRoamPolicy(t *testing.T) {
	d := bcmwifi.Desired{SSIDs: []bcmwifi.SSID{
		{SSID: "net", Enabled: true, Bands: []string{"ng", "na"}, RoamAssist: map[string]int{"na": -72}},
		{SSID: "off", Enabled: false, Bands: []string{"na"}, RoamAssist: map[string]int{"na": -72}},
		{SSID: "gone", Enabled: true, Bands: []string{"ng"}, RoamAssist: map[string]int{"na": -72}}, // na not broadcast
	}}
	got := roamPolicy(d)
	if len(got) != 1 || got["net|na"] != -72 {
		t.Errorf("policy %v", got)
	}
}

func roamCalls(h *harness) []string {
	var out []string
	for _, c := range h.rec.list() {
		if strings.HasPrefix(c, "roam:") {
			out = append(out, c)
		}
	}
	return out
}

// roamUnit drives roamReading directly with a clock of its own: the
// Bedroom unit, WLAN "net" on wl02 (2.4 GHz, aa:a7:b9:3e:15:f8) and wl12
// (5 GHz), the Roaming Assistant on 5 GHz at -75 dBm.
type roamUnit struct {
	t   *testing.T
	h   *harness
	now time.Time
}

const roamPhone = "d2:f7:e5:58:6f:89"

func newRoamUnit(t *testing.T) *roamUnit {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover, c.Apply = true, true })
	h.a.wifi = roamWifi{fakeWifi: h.wifi}
	h.a.policy.Store(&wifiPolicy{steer: map[string]string{}, roam: map[string]int{"net|na": -75}})
	return &roamUnit{t: t, h: h, now: time.Date(2026, 11, 19, 23, 0, 0, 0, time.UTC)}
}

// read is one reading with the phone at signal on bss ("wl12", "wl02", or
// "" when it is not on this unit), d after the last one; it returns the
// requests sent.
func (u *roamUnit) read(d time.Duration, bss string, signal int) []string {
	u.now = u.now.Add(d)
	s := testSnapshot()
	s.Radios[0].VAPs = []apstate.Radio{{Iface: "wl02", Band: "ng", SSID: "net", BSSID: "aa:a7:b9:3e:15:f8"}}
	s.Radios[1].VAPs[0].BSSID = "ba:a7:b9:3e:15:f8"
	s.Radios[1].VAPs[0].Stations = nil
	ph := apstate.Station{MAC: roamPhone, Signal: signal}
	switch bss {
	case "wl12":
		s.Radios[1].VAPs[0].Stations = []apstate.Station{ph}
	case "wl02":
		s.Radios[0].VAPs[0].Stations = []apstate.Station{ph}
	}
	before := len(roamCalls(u.h))
	u.h.a.roamReading(s, u.now)
	for {
		select {
		case j := <-u.h.a.jobs:
			j.fn(context.Background())
			continue
		default:
		}
		break
	}
	return roamCalls(u.h)[before:]
}

// heard puts what the unit's scans heard on 5 GHz, age ago.
func (u *roamUnit) heard(age time.Duration, bss ...apstate.BSS) {
	u.h.a.scans.addBSS("na", apstate.ScanResult{Band: "na", Time: u.now.Add(-age), BSS: bss})
}

// The live bug (Bedroom unit, 2026-11-19): an iPhone at -76 dBm on the
// 5 GHz BSS was asked every ~6 minutes to move to aa:a7:b9:3e:15:f8, the
// same unit's 2.4 GHz BSS; the disassociation timer dropped it and it came
// straight back. This AP's own BSSes (any band, any variant of their
// address) are never a candidate, and with no other AP heard the client
// is left alone, logged once.
func TestRoamNeverOwnBSS(t *testing.T) {
	u := newRoamUnit(t)
	u.heard(0,
		apstate.BSS{BSSID: "aa:a7:b9:3e:15:f8", SSID: "net", Channel: 6, Signal: -30},    // own 2.4 GHz (as a scan might list it)
		apstate.BSS{BSSID: "a2:a7:b9:3e:15:f8", SSID: "net", Channel: 36, Signal: -25},   // own, another first octet
		apstate.BSS{BSSID: "02:00:00:00:77:09", SSID: "other", Channel: 44, Signal: -40}, // another SSID
	)
	for i := 0; i < 120; i++ { // 20 minutes of readings at -76 dBm
		if got := u.read(10*time.Second, "wl12", -76); len(got) != 0 {
			t.Fatalf("reading %d: %v", i, got)
		}
	}
	if n := strings.Count(u.h.logs.all(), "left alone"); n != 1 {
		t.Errorf("logged %d times:\n%s", n, u.h.logs.all())
	}
}

// A candidate on another AP must have been heard by this unit lately and
// at the threshold plus roamCandMargin or better.
func TestRoamCandidateHeardWell(t *testing.T) {
	for name, c := range map[string]struct {
		age    time.Duration
		signal int
		want   bool
	}{
		"heard well":  {0, -60, true},
		"at margin":   {0, -75 + roamCandMargin, true},
		"too weak":    {0, -75 + roamCandMargin - 1, false},
		"stale":       {roamCandAge + time.Minute, -50, false},
		"recent scan": {roamCandAge - 3*time.Minute, -50, true},
	} {
		t.Run(name, func(t *testing.T) {
			u := newRoamUnit(t)
			u.heard(c.age, apstate.BSS{BSSID: "02:00:00:00:77:01", SSID: "net", Channel: 149, Signal: c.signal})
			var got []string
			for i := 0; i < 12; i++ {
				got = append(got, u.read(10*time.Second, "wl12", -80)...)
			}
			if (len(got) == 1) != c.want || len(got) > 1 {
				t.Fatalf("requests %v, want one: %v", got, c.want)
			}
			if c.want && got[0] != "roam:"+roamPhone+"@wl12->02:00:00:00:77:01/na/149 t=100" {
				t.Errorf("request %v", got)
			}
		})
	}
}

// One weak reading is not enough: the signal has to stay below the
// threshold for roamSustain and roamBelow readings. After a request the
// client is not asked again for roamHold; a client that ignored it (or
// came back to the same BSS) waits twice as long each time, up to
// roamHoldMax; one that stayed away is back to roamHold.
func TestRoamSustainAndBackoff(t *testing.T) {
	u := newRoamUnit(t)
	u.heard(0, apstate.BSS{BSSID: "02:00:00:00:77:01", SSID: "net", Channel: 149, Signal: -60})
	// dips that do not last
	for i := 0; i < 30; i++ {
		sig := -80
		if i%3 == 2 {
			sig = -70
		}
		if got := u.read(10*time.Second, "wl12", sig); len(got) != 0 {
			t.Fatalf("asked on a dip (reading %d): %v", i, got)
		}
	}
	u.read(10*time.Second, "wl12", -70)
	var at time.Duration
	asked := func(limit time.Duration, bss string) (time.Duration, bool) {
		for d := time.Duration(0); d <= limit; d += 10 * time.Second {
			u.heard(0, apstate.BSS{BSSID: "02:00:00:00:77:01", SSID: "net", Channel: 149, Signal: -60})
			if len(u.read(10*time.Second, bss, -80)) > 0 {
				return d + 10*time.Second, true
			}
		}
		return 0, false
	}
	at, ok := asked(5*time.Minute, "wl12")
	if !ok || at < roamSustain {
		t.Fatalf("first request after %s (%v), want at least %s of weak readings", at, ok, roamSustain)
	}
	// it stays: the next one only after 2*roamHold, then 4*roamHold
	for i, want := range []time.Duration{2 * roamHold, 4 * roamHold} {
		d, ok := asked(roamHoldMax, "wl12")
		if !ok || d < want-10*time.Second || d > want+roamSustain {
			t.Fatalf("request %d after %s (%v), want about %s", i+2, d, ok, want)
		}
	}
	// it leaves for good after a request: the backoff ends
	for d := time.Duration(0); d < roamReturn+time.Minute; d += time.Minute {
		u.read(time.Minute, "", 0)
	}
	d, ok := asked(roamHoldMax, "wl12")
	if !ok || d > roamSustain+20*time.Second {
		t.Fatalf("after a move that held: request after %s (%v)", d, ok)
	}
	// none ever more often than roamHold
	if d, ok := asked(roamHold-time.Minute, "wl12"); ok {
		t.Fatalf("asked again after %s", d)
	}
}

// A reading that fails reports the last one again: it is no new look at
// the client, so it does not count toward the readings below the
// threshold (nor judge a request).
func TestRoamStaleReading(t *testing.T) {
	var mu sync.Mutex
	signal := -60
	h := roamHarness(t, &mu, &signal)
	h.a.t.roamSustain = time.Millisecond
	weak, used := false, false
	col := &scriptCol{fakeCol: h.col, fn: func(int) (*apstate.Snapshot, error) {
		mu.Lock()
		w := weak
		mu.Unlock()
		if w {
			// one weak reading, then the unit cannot be read
			if used {
				return nil, errors.New("wl: timeout")
			}
			used = true
		}
		return h.col.snap(), nil
	}}
	h.a.o.col = col
	h.ctl.queue(adoptReply, provisionReply(roamAssistCfg("wireless.1.btm_disassoc.status=enabled", "wireless.1.btm_disassoc.threshold=-75")))
	h.start()
	eventually(t, "provisioned", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c1" })
	mu.Lock()
	signal, weak = -80, true
	mu.Unlock()
	n := col.calls()
	eventually(t, "readings", func() bool { return col.calls() >= n+3*roamBelow })
	time.Sleep(20 * time.Millisecond) // the worker
	h.stop()
	if c := roamCalls(h); len(c) != 0 {
		t.Fatalf("asked on stale readings: %v", c)
	}
}

// A request bcmwifi refuses is no request: a client that does not
// advertise BSS transition is held long and logged once (never asked every
// roamHold), and a request left without a usable candidate is the "no
// candidate" case. Neither counts as ignored, nor keeps band steering off
// the client.
func TestRoamRefused(t *testing.T) {
	sib := apstate.BSS{BSSID: "02:00:00:00:77:01", SSID: "net", Channel: 149, Signal: -60}
	run := func(t *testing.T, refuse error, d time.Duration) (*roamUnit, int) {
		u := newRoamUnit(t)
		u.h.a.wifi = roamWifi{fakeWifi: u.h.wifi, err: refuse}
		u.h.a.steer.last = map[string]time.Time{}
		n := 0
		for e := time.Duration(0); e < d; e += 10 * time.Second {
			u.heard(0, sib)
			n += len(u.read(10*time.Second, "wl12", -80))
		}
		return u, n
	}
	t.Run("no BSS transition", func(t *testing.T) {
		u, n := run(t, bcmwifi.ErrNoBTM, 4*time.Hour)
		if n != 1 {
			t.Errorf("%d requests in 4 h, want 1", n)
		}
		logs := u.h.logs.all()
		if c := strings.Count(logs, "does not support BSS transition"); c != 1 {
			t.Errorf("logged %d times:\n%s", c, logs)
		}
		if strings.Contains(logs, "after the request") || strings.Contains(logs, "asked "+roamPhone) {
			t.Errorf("counted as a request:\n%s", logs)
		}
		if _, ok := u.h.a.steer.last[roamPhone]; ok {
			t.Errorf("band steering held off a client that was never asked")
		}
	})
	t.Run("no usable candidate", func(t *testing.T) {
		u, n := run(t, bcmwifi.ErrNoCandidate, 30*time.Minute)
		if n < 2 {
			t.Errorf("%d requests in 30 min: the client is held as if asked", n)
		}
		c := u.h.a.roam.c[roamPhone]
		logs := u.h.logs.all()
		if c == nil || c.fails != 0 || !c.asked.IsZero() || strings.Contains(logs, "after the request") {
			t.Errorf("counted as ignored: %+v\n%s", c, logs)
		}
		if k := strings.Count(logs, "no usable candidate"); k != 1 {
			t.Errorf("logged %d times:\n%s", k, logs)
		}
		if _, ok := u.h.a.steer.last[roamPhone]; ok {
			t.Errorf("band steering held off a client that was never asked")
		}
	})
}

// steerRoamWifi is fakeWifi with both the band steering and the Roaming
// Assistant primitives.
type steerRoamWifi struct{ roamWifi }

func (w steerRoamWifi) SteerToBand(ctx context.Context, vif, mac, bssid string) error {
	w.rec.add(fmt.Sprintf("steer:%s@%s->%s", mac, vif, bssid))
	return nil
}

// A Roaming Assistant request that succeeded keeps band steering off the
// client from the very next reading: the worker's outcome is applied before
// band steering looks at that reading (review finding: the stamp came one
// reading late, so a client that went to this unit's 2.4 GHz BSS instead of
// the other AP was asked straight back to 5 GHz).
func TestSteerAfterRoam(t *testing.T) {
	u := newRoamUnit(t)
	u.h.a.wifi = steerRoamWifi{roamWifi{fakeWifi: u.h.wifi}}
	u.h.a.policy.Store(&wifiPolicy{steer: map[string]string{"ng": "prefer_5g"}, roam: map[string]int{"net|na": -75}})
	sib := apstate.BSS{BSSID: "02:00:00:00:77:01", SSID: "net", Channel: 149, Signal: -60}
	read := func(stale bool, bss string, signal int) {
		u.now = u.now.Add(10 * time.Second)
		s := testSnapshot()
		s.Radios[0].VAPs = []apstate.Radio{{Iface: "wl02", Band: "ng", SSID: "net", BSSID: "aa:a7:b9:3e:15:f8"}}
		s.Radios[1].VAPs[0].BSSID = "ba:a7:b9:3e:15:f8"
		s.Radios[1].VAPs[0].Stations = nil
		ph := apstate.Station{MAC: roamPhone, Signal: signal}
		if bss == "wl12" {
			s.Radios[1].VAPs[0].Stations = []apstate.Station{ph}
		} else {
			s.Radios[0].VAPs[0].Stations = []apstate.Station{ph}
		}
		u.h.a.stale = stale
		u.h.a.clientsReading(s, u.now)
		for {
			select {
			case j := <-u.h.a.jobs:
				j.fn(context.Background())
				continue
			default:
			}
			break
		}
	}
	for i := 0; i < 12 && len(roamCalls(u.h)) == 0; i++ {
		u.heard(0, sib)
		read(false, "wl12", -80)
	}
	if len(roamCalls(u.h)) != 1 {
		t.Fatalf("no Roaming Assistant request: %v", u.h.rec.list())
	}
	for _, stale := range []bool{true, false} { // a stale reading first: the outcome still counts
		read(stale, "wl02", -50)
	}
	for _, c := range u.h.rec.list() {
		if strings.HasPrefix(c, "steer:") {
			t.Fatalf("band steering right after a Roaming Assistant request: %v", u.h.rec.list())
		}
	}
}
