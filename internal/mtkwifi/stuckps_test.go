// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

// fakeProber answers for the learner: addresses and heard times are set
// by the test.
type fakeProber struct {
	vifs  []string
	stas  map[string][]string
	ip    map[string]net.IP
	heard map[string]time.Time
	self  bool
}

func (p *fakeProber) SetVifs(v []string)             { p.vifs = v }
func (p *fakeProber) Stations(m map[string][]string) { p.stas = m }
func (p *fakeProber) Replied(mac string, self net.HardwareAddr, ip net.IP) time.Time {
	if self.String() != "b4:a7:c6:17:e3:f3" || !ip.Equal(net.IPv4(192, 168, 0, 51)) {
		return time.Time{}
	}
	return p.heard[mac]
}
func (p *fakeProber) Neighbor(mac string) (net.IP, bool) {
	ip, ok := p.ip[mac]
	return ip, ok
}
func (p *fakeProber) Self(br string) (net.HardwareAddr, net.IP, bool) {
	if !p.self || br != "bdg2" {
		return nil, nil, false
	}
	hw, _ := net.ParseMAC("b4:a7:c6:17:e3:f3")
	return hw, net.IPv4(192, 168, 0, 51).To4(), true
}

const pumpMAC = "fc:3c:d7:31:00:cd"

type stuckFrame struct {
	dev string
	b   []byte
}

func pumpSnap(at time.Time, vif string, ps bool, rx, conn int64) *apstate.Snapshot {
	return &apstate.Snapshot{Time: at, Radios: []apstate.Radio{{Band: "ng", VAPs: []apstate.Radio{
		{Iface: vif, Stations: []apstate.Station{{MAC: strings.ToUpper(pumpMAC), PowerSave: ps, RxPackets: rx, Connected: conn}}},
	}}}}
}

type stuckRig struct {
	t      *testing.T
	f      *fakeDev
	a      *Applier
	now    *time.Duration
	p      *fakeProber
	frames []stuckFrame
	t0     time.Time
	cur    time.Time // the reading's time (the probes' wall clock)
}

func newStuckRig(t *testing.T, d bcmwifi.Desired) *stuckRig {
	f := newFakeDev(t)
	a, now := clocked(f)
	ctx := context.Background()
	pl, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, pl); err != nil {
		t.Fatal(err)
	}
	*now += time.Minute // past the settle time
	r := &stuckRig{t: t, f: f, a: a, now: now, t0: time.Unix(1_800_000_000, 0),
		p: &fakeProber{ip: map[string]net.IP{pumpMAC: net.IPv4(192, 168, 0, 26)}, heard: map[string]time.Time{}, self: true}}
	a.down = r.p
	a.o.wall = func() time.Time { return r.cur.Add(100 * time.Millisecond) }
	a.o.sendFrame = func(dev string, b []byte) error {
		r.frames = append(r.frames, stuckFrame{dev, append([]byte(nil), b...)})
		return nil
	}
	return r
}

// at runs a reading s seconds after t0; answer: the station replies to the
// probe in flight (heard 100 ms after it).
func (r *stuckRig) at(s int, ps bool, rx int64, answer bool) []string {
	return r.atMs(s*1000, ps, rx, answer)
}

func (r *stuckRig) atMs(ms int, ps bool, rx int64, answer bool) []string {
	at := r.t0.Add(time.Duration(ms) * time.Millisecond)
	if answer && len(r.frames) > 0 {
		r.p.heard[pumpMAC] = at.Add(-500 * time.Millisecond)
	}
	r.cur = at
	return r.a.KickStuck(context.Background(), pumpSnap(at, "ra0", ps, rx, int64(100+ms/1000)))
}

// TestKickStuckProbe: the probe is a unicast ARP request for the
// station's own address from the unit's bridge identity, sent on the
// bridge; a station that answers is probed again only every
// stuckProbeEvery and never kicked, dozing or not.
func TestKickStuckProbe(t *testing.T) {
	r := newStuckRig(t, home())
	if k := r.at(0, true, 10, false); len(k) > 0 || len(r.frames) != 1 {
		t.Fatalf("first reading: kicked %v, frames %d", k, len(r.frames))
	}
	fr := r.frames[0]
	if fr.dev != "bdg2" {
		t.Errorf("sent on %s", fr.dev)
	}
	b := fr.b
	if net.HardwareAddr(b[0:6]).String() != pumpMAC || net.HardwareAddr(b[6:12]).String() != "b4:a7:c6:17:e3:f3" ||
		binary.BigEndian.Uint16(b[12:]) != 0x0806 || binary.BigEndian.Uint16(b[20:]) != 1 ||
		!net.IP(b[28:32]).Equal(net.IPv4(192, 168, 0, 51)) || !net.IP(b[38:42]).Equal(net.IPv4(192, 168, 0, 26)) {
		t.Errorf("probe frame % x", b[:42])
	}
	if !strings.Contains(strings.Join(r.p.vifs, ","), "ra0") || len(r.p.stas["ra0"]) != 1 || r.p.stas["ra0"][0] != pumpMAC {
		t.Errorf("learner vifs %v stations %v", r.p.vifs, r.p.stas)
	}
	// answered: no new probe for stuckProbeEvery, then one
	for s := 5; s < 30; s += 5 {
		if k := r.at(s, true, int64(10+s), s == 5); len(k) > 0 {
			t.Fatalf("kicked a station that answers: %v", k)
		}
	}
	if len(r.frames) != 1 {
		t.Fatalf("probed %d times within %s", len(r.frames), stuckProbeEvery)
	}
	r.at(36, true, 50, false)
	if len(r.frames) != 2 {
		t.Errorf("no probe after %s: %d", stuckProbeEvery, len(r.frames))
	}
}

// TestKickStuckKick: a proven station that then misses stuckMisses probes
// in a row over stuckAfter, read dozing and still sending, is
// disconnected once, then left alone for its back-off.
func TestKickStuckKick(t *testing.T) {
	r := newStuckRig(t, home())
	r.at(0, false, 10, false)
	r.at(5, false, 15, true) // proven
	var kicked []string
	s := 40 // the next probe goes out after stuckProbeEvery
	for i := 0; i < 8 && len(kicked) == 0; i++ {
		kicked = append(kicked, r.at(s, true, int64(20+s), false)...)
		s += 5
	}
	if len(kicked) != 1 || kicked[0] != pumpMAC {
		t.Fatalf("kicked %v", kicked)
	}
	if c := cmdsFrom(r.f, 0, "iwpriv ra0 set DisConnectSta=FC:3C:D7:31:00:CD"); len(c) != 1 {
		t.Errorf("disconnect commands %v", c)
	}
	// the stall began with the probe at 40 s: stuckMisses misses, at least stuckAfter
	if got := s - 5; got < 40+int(stuckAfter/time.Second) {
		t.Errorf("kicked at %d s", got)
	}
	// it re-associates after each kick, proves itself, and stalls again
	// at once: the back-off doubles (kickBackoff, then 2x, 4x), so the
	// gaps between kicks grow past the detection time
	kicks := []time.Time{r.t0.Add(time.Duration(s-5) * time.Second)}
	conn, answer, sentBefore := int64(0), true, len(r.frames)
	for at := kicks[0].Add(5 * time.Second); len(kicks) < 4 && at.Before(kicks[0].Add(time.Hour)); at = at.Add(5 * time.Second) {
		conn += 5
		if answer && len(r.frames) > sentBefore { // this association's first probe is out
			r.p.heard[pumpMAC] = at.Add(-500 * time.Millisecond)
			answer = false
		}
		r.cur = at
		if k := r.a.KickStuck(context.Background(), pumpSnap(at, "ra0", true, conn*10, conn)); len(k) > 0 {
			kicks = append(kicks, at)
			conn, answer, sentBefore = 0, true, len(r.frames)
		}
	}
	if len(kicks) < 4 {
		t.Fatalf("kicks %v", kicks)
	}
	for i, want := range []time.Duration{kickBackoff, 2 * kickBackoff, 4 * kickBackoff} {
		if g := kicks[i+1].Sub(kicks[i]); g < want {
			t.Errorf("kick %d came %s after the last (back-off %s)", i+2, g, want)
		}
	}
	if g := kicks[3].Sub(kicks[2]); g < 4*kickBackoff {
		t.Errorf("back-off not doubling: %v", kicks)
	}
}

// TestKickStuckGuards: no kick for a station that never answered, one read
// awake, one no longer sending, or while a restart settles.
func TestKickStuckGuards(t *testing.T) {
	run := func(name string, proven, ps, sending bool) {
		r := newStuckRig(t, home())
		r.at(0, ps, 10, false)
		r.at(5, ps, 10, proven)
		var kicked []string
		for s := 40; s <= 120; s += 5 {
			rx := int64(10)
			if sending {
				rx = int64(s)
			}
			kicked = append(kicked, r.at(s, ps, rx, false)...)
		}
		if len(kicked) > 0 {
			t.Errorf("%s: kicked %v", name, kicked)
		}
	}
	run("never answered", false, true, true)
	run("awake", true, false, true)
	run("silent", true, true, false)

	r := newStuckRig(t, home())
	*r.now -= 50 * time.Second // back inside the settle time
	for s := 0; s < 120; s += 5 {
		if k := r.at(s, true, int64(s), s == 5); len(k) > 0 {
			t.Fatalf("kicked while settling: %v", k)
		}
	}
	if len(r.frames) > 0 {
		t.Errorf("probed while settling: %d", len(r.frames))
	}
}

// TestKickStuckAfter: misses counted 2 s apart still wait stuckAfter from
// the first unanswered probe.
func TestKickStuckAfter(t *testing.T) {
	r := newStuckRig(t, home())
	r.at(0, true, 10, false)
	r.at(5, true, 11, true) // proven
	var at int
	for ms := 40_000; ms < 80_000 && at == 0; ms += 2100 {
		if k := r.atMs(ms, true, int64(ms/100), false); len(k) > 0 {
			at = ms
		}
	}
	if at == 0 || at-40_000 < int(stuckAfter/time.Millisecond) {
		t.Errorf("kicked at %d ms (first miss probed at 40000)", at)
	}
}

// TestKickStuckNoCounts: without RxPackets ("still sending" unknown) there
// is no kick; a 5 GHz station (no station counters there) is not watched.
func TestKickStuckNoCounts(t *testing.T) {
	r := newStuckRig(t, home())
	r.at(0, true, 0, false)
	r.at(5, true, 0, true)
	for s := 40; s <= 120; s += 5 {
		if k := r.at(s, true, 0, false); len(k) > 0 {
			t.Fatalf("kicked without counters: %v", k)
		}
	}
	r = newStuckRig(t, home())
	r.cur = r.t0
	r.a.KickStuck(context.Background(), &apstate.Snapshot{Time: r.t0, Radios: []apstate.Radio{{Band: "na", VAPs: []apstate.Radio{
		{Iface: "rai0", Stations: []apstate.Station{{MAC: pumpMAC, PowerSave: true, RxPackets: 5, Connected: 9}}},
	}}}})
	if len(r.frames) > 0 || strings.Contains(strings.Join(r.p.vifs, ","), "rai") {
		t.Errorf("5 GHz watched: vifs %v frames %d", r.p.vifs, len(r.frames))
	}
}

// TestKickStuckVLAN: a BSS on a VLAN (no address of the unit there) is not
// watched; without the bridge's address nothing is probed.
func TestKickStuckVLAN(t *testing.T) {
	d := home()
	for i := range d.SSIDs {
		d.SSIDs[i].VLAN = 4
	}
	r := newStuckRig(t, d)
	r.at(0, true, 10, false)
	if len(r.frames) > 0 || len(r.p.vifs) > 0 {
		t.Errorf("VLAN BSS watched: vifs %v frames %d", r.p.vifs, len(r.frames))
	}
	r = newStuckRig(t, home())
	r.p.self = false
	r.at(0, true, 10, false)
	if len(r.frames) > 0 {
		t.Errorf("probed without the bridge's address")
	}
}

// TestMacTablePSM: stainfo's PSM column (3 before RSSI) is read.
func TestMacTablePSM(t *testing.T) {
	log := `MAC                MODE AID  BSS PSM WMM MIMOPS RSSI0/1/2 PhMd  BW  MCS   SGI   STBC  Idle   Rate   QosMap
FC:3C:D7:31:00:CD  200013    1   1   1   3      -49/-53/0  HTMIX 20M 7     0   1    300    65     0         , 6007, 100%
NO                                                              MaxCap:HTMIX     20M   7     1   1    -    72
1C:53:F9:79:81:35  200014    0   0   1   0      -60/-69/0  HTMIX 20M 7     1   1    300    72     0         , 4029673, 100%
`
	got := parseMacTable(log)
	if len(got) != 2 || !got[0].PowerSave || got[1].PowerSave || got[0].bss != 1 || got[1].bss != 0 {
		t.Fatalf("%+v", got)
	}
}

// learnFrame stamps a station's ARP reply by its target; its requests and
// replies to others are not an answer to the unit.
func TestARPTableReplies(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	tb := arpTable{now: func() time.Time { return at }}
	self, selfIP := mac("b4:a7:c6:17:e3:f3"), net.IPv4(192, 168, 0, 51)
	tb.setStations(map[string][]string{"ra1": {pumpMAC}})
	tb.learnFrame("ra1", testARP(1, "ff:ff:ff:ff:ff:ff", pumpMAC, "192.168.0.26", "00:00:00:00:00:00", "192.168.0.1"))
	tb.learnFrame("ra1", testARP(2, "1e:6a:1b:c5:04:c2", pumpMAC, "192.168.0.26", "1e:6a:1b:c5:04:c2", "192.168.0.1"))
	if h := tb.lastReply(pumpMAC, self, selfIP); !h.IsZero() {
		t.Fatalf("a request or a reply to the gateway counted: %v", h)
	}
	tb.learnFrame("ra1", testARP(2, "b4:a7:c6:17:e3:f3", pumpMAC, "192.168.0.26", "b4:a7:c6:17:e3:f3", "192.168.0.51"))
	if h := tb.lastReply(pumpMAC, self, selfIP); !h.Equal(at) {
		t.Errorf("reply %v", h)
	}
	if ip, ok := tb.neighbor(pumpMAC); !ok || ip.String() != "192.168.0.26" {
		t.Errorf("neighbor %v %v", ip, ok)
	}
	tb.setStations(nil)
	if h := tb.lastReply(pumpMAC, self, selfIP); !h.IsZero() {
		t.Errorf("kept after leaving: %v", h)
	}
}
