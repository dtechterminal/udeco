// SPDX-License-Identifier: GPL-2.0-or-later

package lldp

import (
	"context"
	"encoding/binary"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

var apMAC = net.HardwareAddr{0xb0, 0xa7, 0xb9, 0x00, 0x00, 0x05}

func apInfo() Info {
	return Info{ChassisMAC: apMAC, PortID: "eth0", TTL: 120, SysName: "X20",
		SysDescr: "U6-Lite 6.7.54.15663", Caps: CapBridge | CapWLANAP, MgmtIPv4: net.ParseIP("192.168.0.205"), IfIndex: 9}
}

func TestEncodeDecode(t *testing.T) {
	f, err := Encode(apMAC, apInfo())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(net.HardwareAddr(f[:6]), MulticastMAC) || binary.BigEndian.Uint16(f[12:]) != EtherType {
		t.Fatalf("header % x", f[:14])
	}
	n, err := Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	want := Neighbor{SrcMAC: apMAC.String(), ChassisID: "b0:a7:b9:00:00:05", ChassisIDSubtype: ChassisMAC,
		PortID: "eth0", PortIDSubtype: PortIfName, PortDescr: "eth0", TTL: 120, SysName: "X20",
		SysDescr: "U6-Lite 6.7.54.15663", Caps: 0x0c, CapsOn: 0x0c, MgmtIPs: []string{"192.168.0.205"}}
	if !reflect.DeepEqual(n, want) {
		t.Errorf("decoded\n%+v\nwant\n%+v", n, want)
	}
	if _, err := Encode(apMAC, Info{ChassisMAC: apMAC}); err == nil {
		t.Error("empty port ID accepted")
	}
}

// tlv builds one TLV.
func tlv(typ int, v ...byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(typ)<<9|uint16(len(v))), v...)
}

// ucgFrame is shaped like the UCG's LLDPDU heard on the Decos'
// uplinks (topology-and-tplink-scrub.md): chassis subtype local holding the
// MAC as text, port ID subtype MAC (the UCG port's MAC), TTL 120, an IPv4
// and an IPv6 management address, behind an 802.1Q tag.
func ucgFrame(ttl uint16) []byte {
	f := append([]byte{}, MulticastMAC...)
	f = append(f, 0x1c, 0x6a, 0x1b, 0xc5, 0x04, 0xc3)
	f = append(f, 0x81, 0x00, 0x00, 0x00, 0x88, 0xcc)
	f = append(f, tlv(tlvChassisID, append([]byte{ChassisLocal}, "1c:6a:1b:c5:04:c1"...)...)...)
	f = append(f, tlv(tlvPortID, ChassisPort, 0x1c, 0x6a, 0x1b, 0xc5, 0x04, 0xc3)...)
	f = append(f, tlv(tlvTTL, byte(ttl>>8), byte(ttl))...)
	f = append(f, tlv(tlvSysName, []byte("UCG\x00")...)...)
	f = append(f, tlv(tlvMgmtAddr, 5, 1, 192, 168, 0, 1, 2, 0, 0, 0, 4, 0)...)
	f = append(f, tlv(tlvMgmtAddr, append(append([]byte{17, 2}, net.ParseIP("2001:db8::1").To16()...), 2, 0, 0, 0, 4, 0)...)...)
	f = append(f, tlv(tlvEnd)...)
	return f
}

func TestDecodeGateway(t *testing.T) {
	n, err := Decode(ucgFrame(120))
	if err != nil {
		t.Fatal(err)
	}
	if n.ChassisID != "1c:6a:1b:c5:04:c1" || ChassisSubtypeName(n.ChassisIDSubtype) != "local" ||
		n.PortID != "1c:6a:1b:c5:04:c3" || n.TTL != 120 || n.SysName != "UCG" ||
		!reflect.DeepEqual(n.MgmtIPs, []string{"192.168.0.1", "2001:db8::1"}) || n.SrcMAC != "1c:6a:1b:c5:04:c3" {
		t.Errorf("%+v", n)
	}
	for _, bad := range [][]byte{nil, ucgFrame(120)[:20], append(append([]byte{}, ucgFrame(120)[:18]...), 0x02, 0xff)} {
		if _, err := Decode(bad); err == nil {
			t.Errorf("accepted % x", bad)
		}
	}
}

// fakeConn delivers queued frames and records sent ones.
type fakeConn struct {
	mu     sync.Mutex
	in     [][]byte
	out    [][]byte
	closed bool
}

func (c *fakeConn) Recv(b []byte) (int, error) {
	c.mu.Lock()
	if len(c.in) == 0 {
		c.mu.Unlock()
		time.Sleep(time.Millisecond)
		return 0, ErrTimeout
	}
	f := c.in[0]
	c.in = c.in[1:]
	c.mu.Unlock()
	return copy(b, f), nil
}

func (c *fakeConn) Send(f []byte) error {
	c.mu.Lock()
	c.out = append(c.out, append([]byte{}, f...))
	c.mu.Unlock()
	return nil
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *fakeConn) sent() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.out)
}

func TestServiceListensAndAnnounces(t *testing.T) {
	conns := map[string]*fakeConn{"eth0": {}, "eth1": {in: [][]byte{ucgFrame(120)}}}
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s := New(Options{Ports: []string{"eth0", "eth1"}, Every: 5 * time.Millisecond, Now: clock,
		Open: func(p string) (Conn, error) { return conns[p], nil },
		Self: func() (string, net.HardwareAddr, Info, bool) { return "eth1", apMAC, apInfo(), true }})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for (len(s.Neighbors("eth1")) == 0 || conns["eth1"].sent() < 2) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if got := s.Neighbors("eth1"); len(got) != 1 || got[0].ChassisID != "1c:6a:1b:c5:04:c1" {
		t.Fatalf("neighbours %+v", got)
	}
	if len(s.Neighbors("eth0")) != 0 {
		t.Error("neighbour on the wrong port")
	}
	if conns["eth0"].sent() != 0 || conns["eth1"].sent() < 2 {
		t.Errorf("sent eth0 %d eth1 %d: only the uplink announces", conns["eth0"].sent(), conns["eth1"].sent())
	}
	if n, err := Decode(conns["eth1"].out[0]); err != nil || n.ChassisID != apMAC.String() {
		t.Errorf("sent frame %+v %v", n, err)
	}
	// a gateway heard on both ports is found by its chassis, frame source
	// or management address
	s.Heard("eth0", mustDecode(t, ucgFrame(120)))
	for _, id := range []string{"1C:6A:1B:C5:04:C1", "1c:6a:1b:c5:04:c3", "192.168.0.1"} {
		if got := s.PortsHearing(id); !reflect.DeepEqual(got, []string{"eth0", "eth1"}) {
			t.Errorf("PortsHearing(%s) = %v", id, got)
		}
	}
	// the TTL runs out
	mu.Lock()
	now = now.Add(121 * time.Second)
	mu.Unlock()
	if len(s.Neighbors("")) != 0 || len(s.PortsHearing("192.168.0.1")) != 0 {
		t.Error("neighbour outlived its TTL")
	}
	// a shutdown LLDPDU (TTL 0) removes it at once
	s.Heard("eth0", mustDecode(t, ucgFrame(120)))
	s.Heard("eth0", mustDecode(t, ucgFrame(0)))
	if len(s.Neighbors("eth0")) != 0 {
		t.Error("TTL 0 kept the neighbour")
	}
}

func mustDecode(t *testing.T, f []byte) Neighbor {
	t.Helper()
	n, err := Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
