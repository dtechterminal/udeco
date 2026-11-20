// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/hapdmon"
	"github.com/antoniocosta/unifi-openwrt/internal/stasnoop"
)

// While the uplink-loss hold stands, a reading with only one other port
// up (a wired client on eth0) and no gateway evidence must not re-elect
// that port as the uplink and lift the hold: the network is still gone.
// A real cable move (the gateway's MAC learned on eth0) still does.
func TestUplinkHoldNotLiftedByOtherPort(t *testing.T) {
	u := newUpUnit(t, nil)
	carr := map[string]bool{"eth0": true, "eth1": true}
	u.h.a.o.carrier = func(dev string) (bool, bool) { v, ok := carr[dev]; return v, ok }
	u.h.a.o.now = func() time.Time { return u.now }
	u.h.a.topo.uplink = "eth1"
	wantCalls(t, "steady", u.step(30*time.Second, true))
	carr["eth1"] = false
	wantCalls(t, "lost", u.step(5*time.Second, false), "ssids-down")
	// eth1 down flushed the gateway's FDB entry; only eth0 has carrier
	u.h.a.observeReading(&apstate.Snapshot{Gateway: "192.168.0.1", Ports: []apstate.Port{
		{Name: "eth0", Up: true, BridgePort: 1}, {Name: "eth1", Up: false, BridgePort: 2}}}, map[string]any{})
	wantCalls(t, "other port with carrier", u.step(30*time.Second, false))
	if up, _ := u.h.a.topo.uplinkName.Load().(string); up != "eth1" {
		t.Errorf("uplink moved to %q during the hold without gateway evidence", up)
	}
	// the cable moved: the gateway answers on eth0
	u.h.a.observeReading(fdbReading(true, 1), map[string]any{})
	wantCalls(t, "cable moved", u.step(11*time.Second, false), "ssids-up")
}

// A hold change whose job the full worker queue dropped is a failed
// change: it is tried again, not taken as done.
func TestUplinkDroppedJobRetried(t *testing.T) {
	u := newUpUnit(t, nil)
	wantCalls(t, "steady", u.step(30*time.Second, true))
	wantCalls(t, "4 s lost", u.step(4*time.Second, false))
	for len(u.h.a.jobs) < cap(u.h.a.jobs) {
		u.h.a.jobs <- job{"filler", func(context.Context) {}}
	}
	u.now = u.now.Add(time.Second)
	u.h.a.uplinkPass(u.now) // the down job is dropped
	for len(u.h.a.jobs) > 0 {
		(<-u.h.a.jobs).fn(context.Background())
	}
	wantCalls(t, "retried", u.step(15*time.Second, false), "ssids-down")
}

// A fixup carries the soft failure's event_id: the controller finds the
// cached event by it (deco-crosscheck: "unique per attempt; reused for
// fixup").
func TestConnFixupReusesEventID(t *testing.T) {
	r := newConnRig()
	r.anchor(0, anchorAssoc)
	r.sock(40, hapdmon.Connected)
	r.frame(300, dhcpObs(stasnoop.DHCPAck, true))
	r.frame(400, dnsObs(1, false))
	got := r.judge(int(staConnJudge/time.Millisecond) + 100)
	if len(got) != 1 || got[0]["event_type"] != "soft failure" {
		t.Fatalf("events %v", got)
	}
	id := got[0]["event_id"]
	r.frame(40000, dnsObs(2, false))
	r.frame(40030, dnsObs(2, true))
	got = r.judge(45000)
	if len(got) != 1 || got[0]["event_type"] != "fixup" {
		t.Fatalf("events %v", got)
	}
	if got[0]["event_id"] != id {
		t.Errorf("fixup event_id %v, soft failure's %v", got[0]["event_id"], id)
	}
}

// An attempt authorized while its BSS had no tap (a hostapd restart
// recreated the vif and the old tap died) is not judged when the tap is
// back: its DHCP and DNS went unseen.
func TestConnTapGapNoSoftFailure(t *testing.T) {
	r := newConnRig()
	r.snoop = map[string]bool{}
	r.anchor(0, anchorAssoc)
	r.sock(40, hapdmon.Connected)
	if got := r.judge(10000); len(got) != 0 {
		t.Fatalf("early %v", got)
	}
	r.snoop = map[string]bool{"wl12": true}
	r.since = map[string]time.Time{"wl12": r.at(61000)}
	if got := r.judge(61000); len(got) != 0 {
		t.Fatalf("an attempt from before the tap opened was judged: %v", got)
	}
	if got := r.judge(200000); len(got) != 0 {
		t.Fatalf("later: %v", got)
	}
}

// An FT roam: hostapd logs "associated" and the FT line in the same call as
// AP-STA-CONNECTED, and logread delivers them a few ms after the socket
// event. They belong to the authorized attempt: one success, no soft
// failure.
func TestConnLateSyslogAnchorsFT(t *testing.T) {
	r := newConnRig()
	r.sock(0, hapdmon.Connected)
	r.anchor(3, anchorAssoc)
	r.anchor(4, anchorFT)
	r.frame(50, arpObs(false))
	r.frame(60, dnsObs(3, false))
	r.frame(70, dnsObs(3, true))
	got := r.judge(5000)
	if len(got) != 1 || got[0]["event_type"] != "success" || got[0]["auth_algo"] != "ft" {
		t.Fatalf("events %v", got)
	}
	if got := r.judge(int(staConnJudge/time.Millisecond) * 3); len(got) != 0 {
		t.Fatalf("later: %v", got)
	}
}

// The first line a fresh `logread -f -l 1` prints is a replay of the
// newest buffered one: skipped when it is older than the follower.
func TestReplayedLogLine(t *testing.T) {
	start := time.Date(2026, 11, 20, 12, 0, 10, 0, time.Local)
	old := "Fri Nov 20 12:00:00 2026 daemon.info hostapd: wl12: STA " + cSta + " IEEE 802.11: associated (aid 1)"
	fresh := "Fri Nov 20 12:00:10 2026 daemon.info hostapd: wl12: STA " + cSta + " IEEE 802.11: associated (aid 1)"
	if !replayedLine(old, start) || replayedLine(fresh, start) || replayedLine("garbage", start) {
		t.Error("replay detection")
	}
}

// With the connection-timing events on (the Deco), the association event
// carries auth_algo and no auth_rssi: without wifi_caps2 0x2000 the
// controller's detector would otherwise write each roam twice (deco-
// crosscheck capability rule).
func TestAssociationAuthAlgo(t *testing.T) {
	e := staEvents{algo: func(mac, ssid string) string {
		if mac == "c8:5c:cc:d1:2e:c7" {
			return "ft"
		}
		return "open"
	}}
	e.observe(staReading(100, map[string][][2]any{"ra0": {}}), nil)
	e.observe(staReading(110, map[string][][2]any{"ra0": {{"c8:5c:cc:d1:2e:c7", -55}, {"f4:cf:a2:1e:72:64", -60}}}), nil)
	if len(e.queue) != 2 {
		t.Fatalf("queue %v", e.queue)
	}
	for i, want := range []string{"ft", "open"} {
		a := e.queue[i]
		if a["event_type"] != "association" || a["auth_algo"] != want {
			t.Errorf("association %v, want auth_algo %s", a, want)
		}
		if _, ok := a["auth_rssi"]; ok {
			t.Errorf("auth_rssi on the association: %v", a)
		}
	}
}

// The agent's auth_algo: "ft" when the station's attempt is a fast
// transition (its FT syslog line, in the tracker or still in the ring),
// "sae" on a WPA3-only SSID served with wpa3, else "open".
func TestAuthAlgo(t *testing.T) {
	a := &agent{cfg: &Config{WPA3: true}, conn: &connState{t: newConnTracker(), anchors: &anchorRing{}}}
	a.policy.Store(&wifiPolicy{sae: map[string]bool{"wpa3net": true}})
	if got := a.authAlgo(cSta, "net"); got != "open" {
		t.Errorf("plain: %q", got)
	}
	if got := a.authAlgo(cSta, "wpa3net"); got != "sae" {
		t.Errorf("wpa3: %q", got)
	}
	a.conn.anchors.add(connIn{at: time.Now(), anchor: &staAnchor{Vif: "wl12", MAC: cSta, Kind: anchorFT}})
	if got := a.authAlgo(cSta, "net"); got != "ft" {
		t.Errorf("FT anchor in the ring: %q", got)
	}
	a.conn.anchors.take()
	a.conn.t.open(cSta, "wl12", time.Now()).ft = true
	if got := a.authAlgo(cSta, "net"); got != "ft" {
		t.Errorf("FT attempt: %q", got)
	}
}

// A station never seen in a reading has no signal: its failure carries
// neither auth_rssi nor avg_rssi, never 0 (which the controller's -75 dBm
// gate takes as a strong signal and counts).
func TestConnUnknownRSSIOmitted(t *testing.T) {
	r := newConnRig()
	r.signal = map[string]int{}
	r.anchor(0, anchorAssoc)
	r.sock(30, hapdmon.PSKMismatch)
	r.anchor(40, anchorLeave)
	got := r.judge(int(staConnJudge/time.Millisecond) + 1000)
	if len(got) != 1 || got[0]["event_type"] != "failure" {
		t.Fatalf("events %v", got)
	}
	for _, k := range []string{"auth_rssi", "avg_rssi"} {
		if v, ok := got[0][k]; ok {
			t.Errorf("%s = %v on a station with no signal", k, v)
		}
	}
}

// An authorization after the reading started rides the next reading's
// association event (staevents holds it): its success waits for that
// reading too, so the controller never gets the success first.
func TestConnSuccessAfterAssociation(t *testing.T) {
	r := newConnRig()
	r.anchor(0, anchorAssoc)
	r.anchor(40, anchorWPA)
	r.sock(41, hapdmon.Connected)
	r.frame(100, dhcpObs(stasnoop.DHCPAck, true))
	r.frame(300, arpObs(false))
	r.frame(400, dnsObs(5, false))
	r.frame(410, dnsObs(5, true))
	r.read = 20 // the reading began before the authorization
	if got := r.judge(5000); len(got) != 0 {
		t.Fatalf("success before its association event: %v", got)
	}
	r.read = 9000
	if got := r.judge(10000); len(got) != 1 || got[0]["event_type"] != "success" {
		t.Fatalf("next reading: %v", got)
	}
}

// The Garage has its own minimum RSSI kick (mtkwifi KickWeak, settle-
// guarded): the Deco's agent-side loop never runs there, so no second
// kicker with other timers and no live iwpriv inside a settle time.
func TestMinRSSIDecoOnly(t *testing.T) {
	u := newMinUnit(t, banWifi{banErr: bcmwifi.ErrAllowList})
	u.h.a.cfg.Platform = PlatformJio
	var got []string
	for i := 0; i < 3*minRSSIBelow; i++ {
		got = append(got, u.reading(false, "wl12", -85)...)
	}
	if len(got) != 0 {
		t.Fatalf("Deco min-RSSI loop on the Garage: %v", got)
	}
}
