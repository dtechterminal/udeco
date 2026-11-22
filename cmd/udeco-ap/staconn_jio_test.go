// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/hapdmon"
	"github.com/dtechterminal/udeco/internal/mtkwifi"
	"github.com/dtechterminal/udeco/internal/stasnoop"
)

// jioRig is connRig on a Garage BSS: the driver steps go through drvStep,
// the frames are tapped on rai1 (or ra1), the reading lists the station
// there.
type jioRig struct {
	*connRig
	vif string
}

func newJioRig(vif string) *jioRig {
	r := &jioRig{connRig: newConnRig(), vif: vif}
	r.c.frameAuth = true
	r.snoop = map[string]bool{vif: true}
	return r
}

func (r *jioRig) step(ms int, k mtkwifi.DrvKind, ifname string, reason int) {
	in, ok := drvStep(mtkwifi.DrvEvent{Kind: k, Ifname: ifname, MAC: cSta, Reason: reason, At: r.at(ms)})
	if ok {
		r.c.add(in)
	}
}

func (r *jioRig) frame(ms int, o stasnoop.Obs) {
	o.Vif = r.vif
	r.c.add(connIn{at: r.at(ms), frame: &o})
}

func (r *jioRig) judge(ms int, listed bool) []map[string]any {
	n := len(r.queue)
	var read time.Time
	if r.read != 0 {
		read = r.at(r.read)
	}
	staVif := map[string]string{}
	if listed {
		staVif[cSta] = r.vif
	}
	r.c.judge(connReading{now: r.at(ms), read: read, up: 1000 + int64(ms/1000), vifs: map[string]string{r.vif: "rai1"},
		snooped: r.snoop, snoopSince: r.since, signal: r.signal, assoc: r.assoc, staVif: staVif, gwMAC: cGW, gwIP: cGWIP},
		func(ev map[string]any) { r.queue = append(r.queue, ev) })
	return r.queue[n:]
}

func (r *jioRig) traffic(from int) {
	r.frame(from, dhcpObs(stasnoop.DHCPDiscover, false))
	r.frame(from+200, dhcpObs(stasnoop.DHCPAck, true))
	r.frame(from+300, dnsObs(1, false))
	r.frame(from+320, dnsObs(1, true))
}

// 5 GHz (the MT7663): Insert on rai1, the system log's association and
// key done on rai0 (the radio's netdev, put on the attempt's BSS): one
// success with the same timing fields a Deco sends.
func TestJioConnSuccess5G(t *testing.T) {
	r := newJioRig("rai1")
	r.step(0, mtkwifi.DrvInsert, "rai1", 0)
	r.step(12, mtkwifi.DrvAssoc, "rai0", 0)
	r.step(60, mtkwifi.DrvKeyDone, "rai0", 0)
	r.traffic(100)
	got := r.judge(5000, true)
	if len(got) != 1 {
		t.Fatalf("events %v", got)
	}
	wantFields(t, got[0], map[string]any{"event_type": "success", "vap": "rai1", "assoc_delta": 12000,
		"wpa_auth_delta": 48000, "ip_delta": 240000, "traffic_delta": 40000, "ip_assign_type": "dhcp",
		"dns_responses": 1, "wpa_auth_failures": 0})
	// the group rekey's key done (and the WAPP event) an hour later
	// start no attempt
	r.step(3600000, mtkwifi.DrvKeyDone, "rai0", 0)
	r.step(3600001, mtkwifi.DrvAuthorized, "rai1", 0)
	r.traffic(3600100)
	if got := r.judge(3700000, true); len(got) != 0 {
		t.Errorf("a rekey made an event: %v", got)
	}
}

// 2.4 GHz (the rebuilt MT7603: Insert only): the first frame on the tap
// authorizes the attempt; assoc_delta and wpa_auth_delta are 0 (not
// measured), the address and DNS timings are the tap's.
func TestJioConnSuccess24ByFrame(t *testing.T) {
	r := newJioRig("ra1")
	r.step(0, mtkwifi.DrvInsert, "ra1", 0)
	r.traffic(80)
	got := r.judge(5000, true)
	if len(got) != 1 {
		t.Fatalf("events %v", got)
	}
	wantFields(t, got[0], map[string]any{"event_type": "success", "assoc_delta": 0, "wpa_auth_delta": 0,
		"ip_delta": 200000, "traffic_delta": 1, "ip_assign_type": "dhcp"})
	// a station's frames without an attempt (connected before the
	// agent started) authorize nothing
	r = newJioRig("ra1")
	r.traffic(0)
	if got := r.judge(60000, true); len(got) != 0 {
		t.Errorf("frames without an Insert: %v", got)
	}
}

// A wrong passphrase on 5 GHz: the system log's MIC failures (ECNT's report
// of one is deduplicated by mtkwifi.Events before it gets here) and the
// handshake timeout count as wpa_auth_failures, as hostapd's PSK
// mismatches and EAPOL-Key timeouts do, in one failure.
func TestJioConnFailure(t *testing.T) {
	r := newJioRig("rai1")
	for i := 0; i < 2; i++ {
		r.step(i*2000, mtkwifi.DrvInsert, "rai1", 0)
		r.step(i*2000+10, mtkwifi.DrvAssoc, "rai0", 0)
		r.step(i*2000+30, mtkwifi.DrvMICDiff, "rai0", 0)
	}
	r.step(5000, mtkwifi.DrvHSTimeout, "rai0", 0)
	got := r.judge(int(staConnJudge/time.Millisecond)+6000, false)
	if len(got) != 1 {
		t.Fatalf("events %v", got)
	}
	wantFields(t, got[0], map[string]any{"event_type": "failure", "wpa_auth_failures": 3, "vap": "rai1"})
}

// drvStep: what becomes which tracker input; a radio-wide event's BSS is
// left to the tracker; leaves, proxy ARP requests and other ECNT reasons
// are no steps.
func TestDrvStep(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	for _, c := range []struct {
		e      mtkwifi.DrvEvent
		anchor anchorKind
		sock   hapdmon.Kind
		vif    string
	}{
		{mtkwifi.DrvEvent{Kind: mtkwifi.DrvInsert, Ifname: "ra2"}, anchorAuth, 0, "ra2"},
		{mtkwifi.DrvEvent{Kind: mtkwifi.DrvAssoc, Ifname: "rai0"}, anchorAssoc, 0, ""},
		{mtkwifi.DrvEvent{Kind: mtkwifi.DrvKeyDone, Ifname: "rai0"}, 0, hapdmon.Connected, ""},
		{mtkwifi.DrvEvent{Kind: mtkwifi.DrvAuthorized, Ifname: "rai3"}, 0, hapdmon.Connected, "rai3"},
		{mtkwifi.DrvEvent{Kind: mtkwifi.DrvMICDiff, Ifname: "rai0"}, 0, hapdmon.PSKMismatch, ""},
		{mtkwifi.DrvEvent{Kind: mtkwifi.DrvHSTimeout, Ifname: "rai0"}, anchorEAPOLTimeout, 0, ""},
		{mtkwifi.DrvEvent{Kind: mtkwifi.DrvFailure, Ifname: "rai1", Reason: 14}, 0, hapdmon.PSKMismatch, "rai1"},
		{mtkwifi.DrvEvent{Kind: mtkwifi.DrvFailure, Ifname: "rai1", Reason: 15}, anchorEAPOLTimeout, 0, "rai1"},
	} {
		c.e.MAC, c.e.At = cSta, at
		in, ok := drvStep(c.e)
		switch {
		case !ok:
			t.Errorf("%+v: no step", c.e)
		case c.anchor != 0 && (in.anchor == nil || in.anchor.Kind != c.anchor || in.anchor.Vif != c.vif || !in.drv):
			t.Errorf("%+v: %+v", c.e, in.anchor)
		case c.sock != 0 && (in.sock == nil || in.sock.Kind != c.sock || in.sock.Vif != c.vif || !in.drv || !in.at.Equal(at)):
			t.Errorf("%+v: %+v", c.e, in.sock)
		}
	}
	for _, e := range []mtkwifi.DrvEvent{{Kind: mtkwifi.DrvDelete, Ifname: "ra0", MAC: cSta},
		{Kind: mtkwifi.DrvFailure, Ifname: "rai1", MAC: cSta, Reason: 3}, {Kind: mtkwifi.DrvInsert, Ifname: "apcli0", MAC: cSta},
		{Kind: mtkwifi.DrvInsert, Ifname: "ra0", MAC: "D2:F7:E5:58:6F:89"}, {Kind: mtkwifi.DrvProxyARP, Ifname: "rai0", MAC: cSta}} {
		if _, ok := drvStep(e); ok {
			t.Errorf("%+v is a step", e)
		}
	}
}
