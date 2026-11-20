// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/hapdmon"
	"github.com/antoniocosta/unifi-openwrt/internal/stasnoop"
)

const (
	cSta  = "d2:f7:e5:58:6f:89"
	cGW   = "9c:05:d6:00:00:01"
	cGWIP = "192.168.1.1"
	cIP   = "192.168.1.50"
)

func TestParseAnchor(t *testing.T) {
	pre := "Fri Nov 20 12:00:00 2026 daemon.info hostapd: "
	for in, want := range map[string]staAnchor{
		pre + "wl12: STA D2:F7:E5:58:6F:89 IEEE 802.11: authenticated":                                              {Vif: "wl12", MAC: cSta, Kind: anchorAuth},
		pre + "wl12: STA d2:f7:e5:58:6f:89 IEEE 802.11: associated (aid 3)":                                         {Vif: "wl12", MAC: cSta, Kind: anchorAssoc},
		pre + "wl02: STA d2:f7:e5:58:6f:89 IEEE 802.11: reassociated (aid 1)":                                       {Vif: "wl02", MAC: cSta, Kind: anchorAssoc},
		pre + "wl12: STA d2:f7:e5:58:6f:89 WPA: pairwise key handshake completed (RSN)":                             {Vif: "wl12", MAC: cSta, Kind: anchorWPA},
		pre + "wl12: STA d2:f7:e5:58:6f:89 WPA: FT authentication already completed - do not start 4-way handshake": {Vif: "wl12", MAC: cSta, Kind: anchorFT},
		pre + "wl12: STA d2:f7:e5:58:6f:89 IEEE 802.11: disassociated":                                              {Vif: "wl12", MAC: cSta, Kind: anchorLeave},
		pre + "wl12: STA d2:f7:e5:58:6f:89 IEEE 802.11: deauthenticated due to local deauth request":                {Vif: "wl12", MAC: cSta, Kind: anchorLeave},
		pre + "wl12: STA d2:f7:e5:58:6f:89 WPA: EAPOL-Key timeout":                                                  {Vif: "wl12", MAC: cSta, Kind: anchorEAPOLTimeout},
		pre + "wl12: STA d2:f7:e5:58:6f:89 WPA: group key handshake completed (RSN)":                                {},
		pre + "wl12: STA d2:f7:e5:58:6f IEEE 802.11: associated":                                                    {},
		"Fri Nov 20 12:00:00 2026 daemon.info dnsmasq: wl12: STA d2:f7:e5:58:6f:89 IEEE 802.11: associated":         {},
		pre + "wl12: interface state ENABLED->ENABLED":                                                              {},
	} {
		got, ok := parseAnchor(in)
		if ok != (want.Kind != 0) || ok && (got.Vif != want.Vif || got.MAC != want.MAC || got.Kind != want.Kind) {
			t.Errorf("%q: %+v %v, want %+v", in, got, ok, want)
		}
	}
}

// connRig drives a connTracker as the inform loop does.
type connRig struct {
	c      *connTracker
	t0     time.Time
	queue  []map[string]any
	snoop  map[string]bool
	since  map[string]time.Time
	signal map[string]int
	assoc  map[string]bool
	read   int // the reading's start, ms (0: none)
}

func newConnRig() *connRig {
	return &connRig{c: newConnTracker(), t0: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC),
		snoop: map[string]bool{"wl12": true}, signal: map[string]int{cSta: -58}, assoc: map[string]bool{}}
}

func (r *connRig) at(ms int) time.Time { return r.t0.Add(time.Duration(ms) * time.Millisecond) }

func (r *connRig) anchor(ms int, k anchorKind) {
	r.c.add(connIn{at: r.at(ms), anchor: &staAnchor{Vif: "wl12", MAC: cSta, Kind: k}})
}

func (r *connRig) sock(ms int, k hapdmon.Kind) {
	r.c.add(connIn{at: r.at(ms), sock: &hapdmon.Event{Vif: "wl12", MAC: cSta, Kind: k}})
}

func (r *connRig) frame(ms int, o stasnoop.Obs) {
	o.Vif = "wl12"
	r.c.add(connIn{at: r.at(ms), frame: &o})
}

// judge is one reading at ms.
func (r *connRig) judge(ms int) []map[string]any {
	n := len(r.queue)
	var read time.Time
	if r.read != 0 {
		read = r.at(r.read)
	}
	r.c.judge(connReading{now: r.at(ms), read: read, up: 1000 + int64(ms/1000), vifs: map[string]string{"wl12": "wifi1ap1"},
		snooped: r.snoop, snoopSince: r.since, signal: r.signal, assoc: r.assoc, gwMAC: cGW, gwIP: cGWIP},
		func(ev map[string]any) { r.queue = append(r.queue, ev) })
	return r.queue[n:]
}

func dhcpObs(k stasnoop.Kind, out bool) stasnoop.Obs {
	o := stasnoop.Obs{Kind: k, Out: out, Client: cSta, ID: 7}
	if out {
		o.Src, o.Dst, o.YourIP = cGW, cSta, cIP
	} else {
		o.Src, o.Dst = cSta, "ff:ff:ff:ff:ff:ff"
	}
	return o
}

func dnsObs(id uint32, resp bool) stasnoop.Obs {
	if resp {
		return stasnoop.Obs{Kind: stasnoop.DNSResponse, Out: true, Src: cGW, Dst: cSta, SrcIP: cGWIP, DstIP: cIP, ID: id}
	}
	return stasnoop.Obs{Kind: stasnoop.DNSQuery, Src: cSta, Dst: cGW, SrcIP: cIP, DstIP: cGWIP, ID: id}
}

func arpObs(reply bool) stasnoop.Obs {
	if reply {
		return stasnoop.Obs{Kind: stasnoop.ARPReply, Out: true, Src: cGW, Dst: cSta, SrcIP: cGWIP, DstIP: cIP}
	}
	return stasnoop.Obs{Kind: stasnoop.ARPRequest, Src: cSta, Dst: "ff:ff:ff:ff:ff:ff", SrcIP: cIP, DstIP: cGWIP}
}

func wantFields(t *testing.T, ev map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if fmt.Sprint(ev[k]) != fmt.Sprint(v) {
			t.Errorf("%s = %v (%T), want %v", k, ev[k], ev[k], v)
		}
	}
}

// A WPA2-PSK client that associates, gets its address by DHCP and has its
// DNS answered: one "success" with the controller's fields, deltas in
// microseconds.
func TestConnSuccess(t *testing.T) {
	r := newConnRig()
	r.anchor(0, anchorAuth)
	r.anchor(10, anchorAssoc)
	r.anchor(50, anchorWPA)
	r.sock(51, hapdmon.Connected)
	r.frame(100, dhcpObs(stasnoop.DHCPDiscover, false))
	r.frame(200, dhcpObs(stasnoop.DHCPRequest, false))
	r.frame(300, dhcpObs(stasnoop.DHCPAck, true))
	r.frame(310, arpObs(false))
	r.frame(312, arpObs(true))
	r.frame(400, dnsObs(1, false))
	r.frame(420, dnsObs(1, true))
	got := r.judge(5000)
	if len(got) != 1 {
		t.Fatalf("events %v", got)
	}
	ev := got[0]
	wantFields(t, ev, map[string]any{
		"message_type": staTracker, "event_type": "success", "mac": cSta, "vap": "wifi1ap1",
		"auth_ts": float64(r.t0.UnixMicro()) / 1e6, "auth_rssi": -58, "avg_rssi": -58,
		"assoc_delta": 10000, "wpa_auth_delta": 40000, "ip_delta": 250000, "traffic_delta": 50000,
		"assoc_failures": 0, "auth_failures": 0, "wpa_auth_failures": 0, "ip_failures": 0, "traffic_failures": 0,
		"ip_assign_type": "dhcp", "arp_reply_gw_seen": "yes", "dns_resp_seen": "yes", "dns_timeouts": 0, "dns_responses": 1,
		"last_seen": 1005, "assoc_status": 0,
	})
	for _, k := range []string{"assoc_delta", "wpa_auth_delta", "ip_delta", "traffic_delta"} {
		if _, ok := ev[k].(int64); !ok {
			t.Errorf("%s is %T, want an integer", k, ev[k])
		}
	}
	if _, ok := ev["auth_delta"]; ok {
		t.Error("auth_delta on a PSK connection (the spec omits it)")
	}
	if id, _ := ev["event_id"].(string); id == "" {
		t.Error("no event_id")
	}
	if _, ok := ev["auth_algo"]; ok {
		t.Error("auth_algo on a plain association")
	}
	if got := r.judge(60000); len(got) != 0 {
		t.Fatalf("judged twice: %v", got)
	}
	if ip, ok := r.c.ipOf(cSta, "", r.at(60000)); !ok || ip != cIP {
		t.Errorf("ipOf %q %v", ip, ok)
	}
}

// No DNS answer within staConnJudge: a "soft failure" (dns_resp_seen no,
// the unanswered query a timeout); an answer later turns it into a
// "fixup" with the completed values.
func TestConnSoftFailureFixup(t *testing.T) {
	r := newConnRig()
	r.anchor(0, anchorAssoc)
	r.sock(40, hapdmon.Connected)
	r.frame(100, dhcpObs(stasnoop.DHCPDiscover, false))
	r.frame(300, dhcpObs(stasnoop.DHCPAck, true))
	r.frame(400, dnsObs(1, false))
	if got := r.judge(10000); len(got) != 0 {
		t.Fatalf("judged early: %v", got)
	}
	got := r.judge(int(staConnJudge/time.Millisecond) + 100)
	if len(got) != 1 {
		t.Fatalf("events %v", got)
	}
	wantFields(t, got[0], map[string]any{"event_type": "soft failure", "dns_resp_seen": "no", "dns_timeouts": 1,
		"dns_responses": 0, "ip_assign_type": "dhcp", "assoc_delta": 0, "wpa_auth_delta": 40000})
	id := got[0]["event_id"]
	r.frame(40000, dnsObs(2, false))
	r.frame(40030, dnsObs(2, true))
	got = r.judge(45000)
	if len(got) != 1 {
		t.Fatalf("events %v", got)
	}
	wantFields(t, got[0], map[string]any{"event_type": "fixup", "dns_resp_seen": "yes", "dns_responses": 1,
		"auth_ts": float64(r.t0.UnixMicro()) / 1e6})
	if got[0]["event_id"] != id {
		t.Error("fixup with another event_id than its soft failure")
	}
	if got := r.judge(200000); len(got) != 0 {
		t.Fatalf("more: %v", got)
	}
}

// A wrong passphrase: associations and PSK mismatches, never authorized:
// one "failure" carrying the count; a station the reading shows associated
// (an attempt the agent saw only part of) is no failure.
func TestConnFailure(t *testing.T) {
	r := newConnRig()
	for i := 0; i < 3; i++ {
		r.anchor(i*2000, anchorAssoc)
		r.sock(i*2000+30, hapdmon.PSKMismatch)
		r.anchor(i*2000+40, anchorLeave)
	}
	if got := r.judge(10000); len(got) != 0 {
		t.Fatalf("early: %v", got)
	}
	got := r.judge(int(staConnJudge/time.Millisecond) + 1000)
	if len(got) != 1 {
		t.Fatalf("events %v", got)
	}
	wantFields(t, got[0], map[string]any{"event_type": "failure", "wpa_auth_failures": 3, "assoc_failures": 0, "vap": "wifi1ap1"})
	if _, ok := got[0]["dns_resp_seen"]; ok {
		t.Errorf("dns on a failure: %v", got[0])
	}

	r = newConnRig()
	r.anchor(0, anchorAssoc)
	r.assoc[cSta] = true
	if got := r.judge(int(staConnJudge/time.Millisecond) + 1000); len(got) != 0 {
		t.Fatalf("associated station judged a failure: %v", got)
	}
}

// 802.1X: EAP progress gives radius_auth_status and its delta; a rejected
// client is a failure with radius_auth_status "failure".
func TestConnEAP(t *testing.T) {
	r := newConnRig()
	r.anchor(0, anchorAssoc)
	r.sock(20, hapdmon.EAPStarted)
	r.sock(220, hapdmon.EAPSuccess)
	r.anchor(260, anchorWPA)
	r.sock(261, hapdmon.Connected)
	r.frame(300, arpObs(false))
	r.frame(400, dnsObs(5, false))
	r.frame(410, dnsObs(5, true))
	got := r.judge(5000)
	if len(got) != 1 {
		t.Fatalf("events %v", got)
	}
	// auth_delta EAP-STARTED -> EAP-SUCCESS, wpa_auth_delta from the end
	// of EAP-SUCCESS (deco-crosscheck)
	wantFields(t, got[0], map[string]any{"event_type": "success", "radius_auth_status": "success", "radius_auth_delta": 200000,
		"auth_delta": 200000, "wpa_auth_delta": 40000, "ip_assign_type": "static", "ip_delta": 0, "traffic_delta": 40000, "auth_failures": 0})

	r = newConnRig()
	r.anchor(0, anchorAssoc)
	r.sock(20, hapdmon.EAPStarted)
	r.sock(3020, hapdmon.EAPFailure)
	got = r.judge(int(staConnJudge/time.Millisecond) + 1000)
	if len(got) != 1 {
		t.Fatalf("events %v", got)
	}
	wantFields(t, got[0], map[string]any{"event_type": "failure", "radius_auth_status": "failure", "auth_failures": 1, "wpa_auth_failures": 0})

	// a RADIUS timeout is an authentication failure, not a 4-way one
	r = newConnRig()
	r.anchor(0, anchorAssoc)
	r.sock(20, hapdmon.EAPStarted)
	r.sock(30020, hapdmon.EAPTimeout)
	got = r.judge(int(staConnJudge/time.Millisecond) + 31000)
	if len(got) != 1 {
		t.Fatalf("events %v", got)
	}
	wantFields(t, got[0], map[string]any{"event_type": "failure", "radius_auth_status": "failure", "auth_failures": 1, "wpa_auth_failures": 0})
}

// A fast transition: auth_algo "ft", and the address the client kept is a
// roam (the controller counts a roam's soft failure as a success).
func TestConnFT(t *testing.T) {
	r := newConnRig()
	r.anchor(0, anchorAssoc)
	r.anchor(5, anchorFT)
	r.sock(6, hapdmon.Connected)
	r.frame(50, arpObs(false))
	got := r.judge(int(staConnJudge/time.Millisecond) + 100)
	if len(got) != 1 {
		t.Fatalf("events %v", got)
	}
	wantFields(t, got[0], map[string]any{"event_type": "soft failure", "auth_algo": "ft", "ip_assign_type": "roam",
		"traffic_delta": 44000})
	if _, ok := got[0]["dns_resp_seen"]; ok {
		t.Errorf("no query, yet dns_resp_seen: %v", got[0])
	}
}

// Nothing is judged for a BSS that is not snooped (no tap: the success
// needs the DNS answer), nor without a vap_table name.
func TestConnNotSnooped(t *testing.T) {
	r := newConnRig()
	r.snoop = map[string]bool{}
	r.anchor(0, anchorAssoc)
	r.sock(40, hapdmon.Connected)
	if got := r.judge(int(staConnJudge/time.Millisecond) * 3); len(got) != 0 {
		t.Fatalf("events %v", got)
	}
}

// Every auth_ts is unique per AP (the controller keys its metrics on it):
// two stations authorized in the same microsecond get distinct ones.
func TestConnUniqueAuthTS(t *testing.T) {
	r := newConnRig()
	other := "aa:bb:cc:00:00:01"
	r.signal[other] = -60
	for _, m := range []string{cSta, other} {
		r.c.add(connIn{at: r.at(0), anchor: &staAnchor{Vif: "wl12", MAC: m, Kind: anchorAssoc}})
		r.c.add(connIn{at: r.at(10), sock: &hapdmon.Event{Vif: "wl12", MAC: m, Kind: hapdmon.Connected}})
	}
	got := r.judge(int(staConnJudge/time.Millisecond) + 100)
	if len(got) != 2 || got[0]["auth_ts"] == got[1]["auth_ts"] {
		t.Fatalf("events %v", got)
	}
}

// The tracker keeps at most staConnMax attempts.
func TestConnBounded(t *testing.T) {
	r := newConnRig()
	for i := 0; i < staConnMax+50; i++ {
		m := fmt.Sprintf("02:00:00:00:%02x:%02x", i>>8, i&0xff)
		r.c.add(connIn{at: r.at(i), anchor: &staAnchor{Vif: "wl12", MAC: m, Kind: anchorAssoc}})
	}
	if n := len(r.c.att); n > staConnMax {
		t.Fatalf("%d attempts", n)
	}
}

// A station that leaves (or starts again) while authorized is judged at
// the next reading, whatever its age: complete, a success; else a soft
// failure.
func TestConnLeft(t *testing.T) {
	r := newConnRig()
	r.anchor(0, anchorAssoc)
	r.sock(40, hapdmon.Connected)
	r.frame(100, dhcpObs(stasnoop.DHCPDiscover, false))
	r.sock(2000, hapdmon.Disconnected)
	got := r.judge(3000)
	if len(got) != 1 {
		t.Fatalf("events %v", got)
	}
	wantFields(t, got[0], map[string]any{"event_type": "soft failure", "ip_failures": 1, "traffic_delta": 60000})
	// a quick reconnect: the first attempt complete, the second judged later
	r.anchor(10000, anchorAssoc)
	r.sock(10040, hapdmon.Connected)
	r.frame(10100, dhcpObs(stasnoop.DHCPAck, true))
	r.frame(10150, dnsObs(3, false))
	r.frame(10160, dnsObs(3, true))
	r.anchor(10500, anchorAssoc)
	r.sock(10540, hapdmon.Connected)
	got = r.judge(11000)
	if len(got) != 1 {
		t.Fatalf("events %v", got)
	}
	wantFields(t, got[0], map[string]any{"event_type": "success", "auth_ts": float64(r.at(10000).UnixMicro()) / 1e6})
}

// chanSrc hands its frames over once armed.
type chanSrc struct {
	mu     sync.Mutex
	frames [][2]any // frame, outgoing
	opened chan struct{}
}

func (s *chanSrc) Recv(b []byte) (int, bool, error) {
	s.mu.Lock()
	if len(s.frames) == 0 {
		s.mu.Unlock()
		time.Sleep(2 * time.Millisecond)
		return 0, false, stasnoop.ErrTimeout
	}
	f := s.frames[0]
	s.frames = s.frames[1:]
	s.mu.Unlock()
	return copy(b, f[0].([]byte)), f[1].(bool), nil
}

func (s *chanSrc) Close() error { return nil }

func (s *chanSrc) push(frame []byte, out bool) {
	s.mu.Lock()
	s.frames = append(s.frames, [2]any{frame, out})
	s.mu.Unlock()
}

// End to end: the hostapd socket's authorization, the tap's DHCP and DNS
// frames: a "success" reaches the controller in a notification inform of
// its own, with the vap_table name of the BSS.
func TestConnEventsFromTaps(t *testing.T) {
	mon := &fakeStaMon{}
	src := &chanSrc{opened: make(chan struct{})}
	var once sync.Once
	pr, pw := io.Pipe()
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		o.staMon = mon
		o.snoopOpen = func(vif string) (stasnoop.Source, error) {
			if vif != "wl12" {
				return nil, errors.New("no such tap")
			}
			once.Do(func() { close(src.opened) })
			return src, nil
		}
		o.logFollow = func(ctx context.Context) (io.ReadCloser, error) { return pr, nil }
	})
	defer pw.Close()
	h.ctl.queue(adoptReply, provisionReply(testCfg))
	h.start()
	defer h.stop()
	eventually(t, "provisioned", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c1" })
	select {
	case <-src.opened:
	case <-time.After(5 * time.Second):
		t.Fatal("no tap on wl12")
	}
	fmt.Fprintf(pw, "%s daemon.info hostapd: wl12: STA %s IEEE 802.11: associated (aid 1)\n", time.Now().Format(time.ANSIC), staMAC)
	time.Sleep(20 * time.Millisecond)
	mon.mu.Lock()
	mon.evs = []hapdmon.Event{{Vif: "wl12", MAC: staMAC, Kind: hapdmon.Connected, At: time.Now()}}
	mon.mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	ack := ethFrame(staMAC, cGW, udpFrame(cGWIP, cIP, 67, 68, dhcpPayload(2, staMAC, cIP, 5)))
	q := ethFrame(cGW, staMAC, udpFrame(cIP, cGWIP, 40000, 53, dnsPayload(9, false)))
	resp := ethFrame(staMAC, cGW, udpFrame(cGWIP, cIP, 53, 40000, dnsPayload(9, true)))
	src.push(ack, true)
	src.push(q, false)
	src.push(resp, true)
	var ev map[string]any
	eventually(t, "a success event", func() bool {
		for _, m := range h.ctl.all() {
			if p, ok := m["notif_payload"].(map[string]any); ok && p["message_type"] == staTracker && p["event_type"] == "success" {
				ev = p
				return true
			}
		}
		return false
	})
	if ev["mac"] != staMAC || ev["vap"] == "" || ev["dns_responses"] != float64(1) || ev["ip_assign_type"] != "dhcp" {
		t.Fatalf("event %v", ev)
	}
}

func ethFrame(dst, src string, ip []byte) []byte {
	d, _ := net.ParseMAC(dst)
	s, _ := net.ParseMAC(src)
	return append(append(append(append([]byte{}, d...), s...), 0x08, 0x00), ip...)
}

func udpFrame(src, dst string, sport, dport uint16, payload []byte) []byte {
	h := make([]byte, 28)
	h[0], h[8], h[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(h[2:], uint16(28+len(payload)))
	copy(h[12:], net.ParseIP(src).To4())
	copy(h[16:], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(h[20:], sport)
	binary.BigEndian.PutUint16(h[22:], dport)
	binary.BigEndian.PutUint16(h[24:], uint16(8+len(payload)))
	return append(h, payload...)
}

func dhcpPayload(op byte, chaddr, yiaddr string, mt byte) []byte {
	b := make([]byte, 240)
	b[0], b[1], b[2] = op, 1, 6
	copy(b[16:], net.ParseIP(yiaddr).To4())
	m, _ := net.ParseMAC(chaddr)
	copy(b[28:], m)
	copy(b[236:], []byte{99, 130, 83, 99})
	return append(b, 53, 1, mt, 255)
}

func dnsPayload(id uint16, resp bool) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, id)
	if resp {
		b[2] = 0x81
	}
	return b
}

// The keys: sta_snoop and assoc_garp (both default on) need takeover, are
// refused on the Garage, and assoc_garp true needs sta_snoop.
func TestConnConfig(t *testing.T) {
	f, tr := false, true
	base := func() Config {
		return Config{InformURL: "http://192.168.1.10:8080/inform", ConsoleIP: "192.168.1.10", Model: "UAL6",
			SSHDPort: 2222, Log: "stderr", Takeover: true}
	}
	c := base()
	if err := c.validate(); err != nil || !c.staSnoopOn() || !c.assocGARPOn() {
		t.Fatalf("defaults: %v", err)
	}
	c.StaSnoop = &f
	if err := c.validate(); err != nil || c.staSnoopOn() {
		t.Fatalf("snoop off: %v", err)
	}
	c.AssocGARP = &tr
	if err := c.validate(); err == nil {
		t.Error("assoc_garp without sta_snoop accepted")
	}
	c = base()
	c.Takeover, c.StaSnoop = false, &tr
	if err := c.validate(); err == nil {
		t.Error("sta_snoop without takeover accepted")
	}
	c = base()
	c.Platform, c.Model, c.AssocGARP = PlatformJio, "U7LT", &f
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "assoc_garp") {
		t.Errorf("jio: %v", err)
	}
}
