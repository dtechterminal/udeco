// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/hapdmon"
)

// rtnlFrame is an RTM_NEWLINK message for ifname carrying one IWEVCUSTOM
// iw_event (events spec: {u16 len, u16 cmd 0x8C02, u16 dlen, u16 flags,
// data}) inside IFLA_WIRELESS, as the drivers' RtmpOSWrielessEventSend
// sends it (little-endian: the EN7528 is mipsle).
func rtnlFrame(ifname string, ifindex int, flags uint16, data []byte) []byte {
	le := binary.LittleEndian
	attr := func(typ uint16, v []byte) []byte {
		b := make([]byte, 4, 4+len(v)+3)
		le.PutUint16(b[0:], uint16(4+len(v)))
		le.PutUint16(b[2:], typ)
		b = append(b, v...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	iw := make([]byte, 8, 8+len(data))
	le.PutUint16(iw[0:], uint16(8+len(data)))
	le.PutUint16(iw[2:], 0x8C02)
	le.PutUint16(iw[4:], uint16(len(data)))
	le.PutUint16(iw[6:], flags)
	iw = append(iw, data...)
	ifi := make([]byte, 16)
	le.PutUint32(ifi[4:], uint32(ifindex))
	body := append(ifi, attr(3, append([]byte(ifname), 0))...)
	body = append(body, attr(11, iw)...)
	h := make([]byte, 16)
	le.PutUint32(h[0:], uint32(16+len(body)))
	le.PutUint16(h[4:], 16) // RTM_NEWLINK
	return append(h, body...)
}

func mac(s string) []byte { m, _ := net.ParseMAC(s); return m }

func ecntFrame(sub uint32, sta, bssid string, arg uint32, ifname string) []byte {
	le := binary.LittleEndian
	p := make([]byte, 0xe0)
	le.PutUint32(p[0:], sub)
	copy(p[4:], mac(sta))
	copy(p[10:], mac(bssid))
	if sub == 0xe {
		copy(p[16:32], ifname)
	} else {
		le.PutUint32(p[16:], arg)
		copy(p[20:36], ifname)
	}
	h := make([]byte, 16)
	le.PutUint32(h[0:], uint32(16+len(p)))
	le.PutUint16(h[4:], 0x0A00)
	return append(h, p...)
}

func TestParseRTNL(t *testing.T) {
	sta := "a6:7b:63:9f:25:40"
	ins := parseRTNL(rtnlFrame("rai1", 12, 3, mac(sta)))
	if len(ins) != 1 || ins[0].Kind != DrvInsert || ins[0].Ifname != "rai1" || ins[0].MAC != sta {
		t.Errorf("insert %+v", ins)
	}
	del := parseRTNL(append(rtnlFrame("ra0", 9, 4, mac(sta)), rtnlFrame("ra2", 10, 4, mac("02:00:00:00:00:01"))...))
	if len(del) != 2 || del[0].Kind != DrvDelete || del[0].Ifname != "ra0" || del[1].Ifname != "ra2" {
		t.Errorf("deletes %+v", del)
	}
	auth := make([]byte, 22)
	auth[5] = 6
	copy(auth[6:], mac(sta))
	copy(auth[12:], mac("b6:a7:c6:ee:e3:f5"))
	if a := parseRTNL(rtnlFrame("rai0", 11, 0x953, auth)); len(a) != 1 || a[0].Kind != DrvAuthorized || a[0].MAC != sta || a[0].BSSID != "b6:a7:c6:ee:e3:f5" {
		t.Errorf("authorized %+v", a)
	}
	auth[5] = 7
	if a := parseRTNL(rtnlFrame("rai0", 11, 0x953, auth)); len(a) != 1 || a[0].Kind != DrvMboLeave || a[0].MAC != sta {
		t.Errorf("mbo leave %+v", a)
	}
	wapp := make([]byte, 14)
	wapp[1] = 9
	copy(wapp[8:], mac(sta))
	if a := parseRTNL(rtnlFrame("ra1", 13, 0x647, wapp)); len(a) != 1 || a[0].Kind != DrvWappLeave || a[0].MAC != sta {
		t.Errorf("wapp leave %+v", a)
	}
	// proxy ARP request (0x93b, 29 bytes)
	pa := make([]byte, 29)
	binary.LittleEndian.PutUint32(pa[0:], 12)
	pa[4], pa[5], pa[6] = 0, 1, 0
	copy(pa[7:], mac("00:11:22:33:44:55"))
	copy(pa[13:], mac(sta))
	copy(pa[19:], net.IPv4(192, 168, 0, 10).To4())
	copy(pa[23:], net.IPv4(192, 168, 0, 77).To4())
	p := parseRTNL(rtnlFrame("rai1", 12, 0x93b, pa))
	if len(p) != 1 || p[0].Kind != DrvProxyARP || p[0].ARP == nil {
		t.Fatalf("proxy arp %+v", p)
	}
	if r := p[0].ARP; r.Ifindex != 12 || !r.FromDS || r.DAD || r.ReqMAC.String() != "00:11:22:33:44:55" ||
		r.StaMAC.String() != sta || r.ReqIP.String() != "192.168.0.10" || r.StaIP.String() != "192.168.0.77" {
		t.Errorf("proxy arp request %+v", r)
	}
	// other flags, other commands, truncated frames: nothing
	for _, b := range [][]byte{rtnlFrame("ra0", 9, 0x0200, []byte("text event")), rtnlFrame("ra0", 9, 4, mac(sta))[:30], {1, 2, 3}} {
		if x := parseRTNL(b); len(x) != 0 {
			t.Errorf("parsed %+v", x)
		}
	}
}

func TestParseECNT(t *testing.T) {
	sta, bss := "a6:7b:63:9f:25:40", "b6:a7:c6:ee:e3:f5"
	e := parseECNT(ecntFrame(1, sta, bss, 14, "rai0"))
	if len(e) != 1 || e[0].Kind != DrvFailure || e[0].Reason != 14 || e[0].Ifname != "rai0" || e[0].MAC != sta || e[0].BSSID != bss {
		t.Errorf("wrong PSK %+v", e)
	}
	if e := parseECNT(ecntFrame(4, sta, bss, 8, "ra1")); len(e) != 1 || e[0].Kind != DrvClientLeave || e[0].Reason != 8 {
		t.Errorf("client leave %+v", e)
	}
	if e := parseECNT(ecntFrame(0xe, sta, bss, 0, "junk")); len(e) != 1 || e[0].Kind != DrvAPLeave || e[0].BSSID != bss {
		t.Errorf("ap leave %+v", e)
	}
	if e := parseECNT(ecntFrame(1, sta, bss, 14, "rai0")[:100]); len(e) != 0 {
		t.Errorf("short frame %+v", e)
	}
}

func TestParseKmsg(t *testing.T) {
	ev, ok := parseKmsg("4,9123,81234567,-;Del Sta:c0:f8:53:17:23:a7, Chip:0x7603, Phy_Mode:4, RSSI:-70/-83\n")
	if !ok || ev.Kind != DrvDelete || ev.MAC != "c0:f8:53:17:23:a7" || ev.Ifname != AnyNG {
		t.Errorf("Del Sta: %+v %t", ev, ok)
	}
	if _, ok := parseKmsg("4,9124,81234567,-;New Sta:c0:f8:53:17:23:a7\n"); ok {
		t.Error("New Sta parsed as a leave")
	}
}

type evClock struct{ t time.Time }

func (c *evClock) now() time.Time { return c.t }

func newTestEvents(busy *bool) (*Events, *evClock) {
	ck := &evClock{t: time.Unix(1_800_000_000, 0)}
	e := NewEvents(EventsOptions{Now: ck.now, Busy: func() bool { return *busy }})
	return e, ck
}

// TestEventsLeaves: a driver Delete becomes a Disconnected after
// leaveHold; a burst on one BSS (a restart, a kick of everyone) is not;
// events while the radios change are dropped; a WAPP/MBO leave stands in
// only for a Delete that never came; the kernel log's Del Sta of a
// station the netlink Delete already reported is not repeated.
func TestEventsLeaves(t *testing.T) {
	busy := false
	e, ck := newTestEvents(&busy)
	a, b := "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"
	e.handle(DrvEvent{Kind: DrvDelete, Ifname: "rai1", MAC: a})
	e.flush()
	if evs, _ := e.Take(); len(evs) != 0 {
		t.Fatalf("released before leaveHold: %v", evs)
	}
	ck.t = ck.t.Add(leaveHold)
	e.flush()
	evs, _ := e.Take()
	if len(evs) != 1 || evs[0].Kind != hapdmon.Disconnected || evs[0].Vif != "rai1" || evs[0].MAC != a {
		t.Fatalf("released %v", evs)
	}
	// the kernel log line for the same leave, a moment later
	e.handle(DrvEvent{Kind: DrvDelete, Ifname: AnyNG, MAC: a})
	ck.t = ck.t.Add(leaveHold)
	e.flush()
	if evs, _ := e.Take(); len(evs) != 0 {
		t.Errorf("Del Sta repeated a reported leave: %v", evs)
	}

	// burst: 4 Deletes on ra0 within a second
	for i := 0; i < 4; i++ {
		e.handle(DrvEvent{Kind: DrvDelete, Ifname: "ra0", MAC: "02:00:00:00:00:0" + string(rune('1'+i))})
		ck.t = ck.t.Add(100 * time.Millisecond)
	}
	ck.t = ck.t.Add(leaveHold)
	e.flush()
	if evs, _ := e.Take(); len(evs) != 0 {
		t.Errorf("burst released: %v", evs)
	}

	// busy: dropped at once
	busy = true
	e.handle(DrvEvent{Kind: DrvDelete, Ifname: "ra1", MAC: b})
	busy = false
	ck.t = ck.t.Add(leaveHold)
	e.flush()
	if evs, _ := e.Take(); len(evs) != 0 {
		t.Errorf("event from a radio change released: %v", evs)
	}

	// MBO leave with no Delete: stands in after fallbackHold
	e.handle(DrvEvent{Kind: DrvMboLeave, Ifname: "rai0", MAC: b})
	ck.t = ck.t.Add(leaveHold)
	e.flush()
	if evs, _ := e.Take(); len(evs) != 0 {
		t.Errorf("fallback released early: %v", evs)
	}
	ck.t = ck.t.Add(fallbackHold)
	e.flush()
	if evs, _ := e.Take(); len(evs) != 1 || evs[0].MAC != b || evs[0].Vif != "rai0" {
		t.Errorf("fallback: %v", evs)
	}
	// MBO leave followed by its Delete: one leave
	e.handle(DrvEvent{Kind: DrvMboLeave, Ifname: "rai0", MAC: a})
	e.handle(DrvEvent{Kind: DrvDelete, Ifname: "rai0", MAC: a})
	ck.t = ck.t.Add(fallbackHold + leaveHold)
	e.flush()
	if evs, _ := e.Take(); len(evs) != 1 {
		t.Errorf("MBO and Delete: %v", evs)
	}
}

type closingSource struct{}

func (c *closingSource) Read([]byte) (int, error) { return 0, errors.New("socket gone") }
func (c *closingSource) Close() error             { return nil }

// TestEventsDown: the rtnetlink listener dying calls Down (proxy ARP's
// driver flag goes off at once).
func TestEventsDown(t *testing.T) {
	down := make(chan struct{}, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	never := func() (packetSource, error) { return nil, errors.New("no") }
	m := NewEvents(EventsOptions{Down: func() { down <- struct{}{} },
		openRTNL: func() (packetSource, error) { return &closingSource{}, nil }, openECNT: never, openKmsg: never})
	go m.Run(ctx)
	select {
	case <-down:
	case <-time.After(5 * time.Second):
		t.Fatal("Down not called")
	}
}
