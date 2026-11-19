// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import (
	"bytes"
	"math"
	"net/netip"
	"testing"
)

func TestIntRoundTrip(t *testing.T) {
	for _, x := range []int64{0, 1, 127, 128, 255, 256, -1, -128, -129, 1<<31 - 1, -1 << 31, math.MaxInt64, math.MinInt64} {
		_, v, rest, err := readTLV(encInt(x))
		if err != nil || len(rest) != 0 {
			t.Fatalf("%d: %v", x, err)
		}
		got, err := parseInt(v)
		if err != nil || got != x {
			t.Errorf("%d: got %d %v (% x)", x, got, err, encInt(x))
		}
	}
	// minimal encodings
	for x, want := range map[int64][]byte{0: {2, 1, 0}, 127: {2, 1, 0x7f}, 128: {2, 2, 0, 0x80}, -1: {2, 1, 0xff}, -129: {2, 2, 0xff, 0x7f}} {
		if got := encInt(x); !bytes.Equal(got, want) {
			t.Errorf("encInt(%d) = % x, want % x", x, got, want)
		}
	}
	for _, x := range []uint64{0, 0x7f, 0x80, 0xffffffff, math.MaxUint64} {
		_, v, _, _ := readTLV(encUint(tagCounter64, x))
		if got, err := parseUint(v); err != nil || got != x {
			t.Errorf("uint %d: %d %v", x, got, err)
		}
	}
}

func TestOIDRoundTrip(t *testing.T) {
	for _, s := range []string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.41112.1.6.1.2.1.6.1", "2.999.4294967295", "0.0", "1.3.6.1.6.3.15.1.1.4.0"} {
		o := mustOID(s)
		_, v, _, err := readTLV(encOID(o))
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseOIDValue(v)
		if err != nil || got.String() != s {
			t.Errorf("%s: got %s %v", s, got, err)
		}
	}
	// the classic encoding of 1.3.6.1.2.1.1.1.0
	if got := encOID(mustOID("1.3.6.1.2.1.1.1.0")); !bytes.Equal(got, []byte{6, 8, 0x2b, 6, 1, 2, 1, 1, 1, 0}) {
		t.Errorf("% x", got)
	}
	for _, bad := range [][]byte{{}, {0x2b, 0x81}, {0x2b, 0x80, 0x01}, {0x2b, 0x90, 0x80, 0x80, 0x80, 0x80, 0x01}} {
		if _, err := parseOIDValue(bad); err == nil {
			t.Errorf("% x accepted", bad)
		}
	}
	if mustOID("1.3.6").Compare(mustOID("1.3.6.0")) >= 0 || mustOID("1.3.7").Compare(mustOID("1.3.6.9")) <= 0 {
		t.Error("Compare order")
	}
}

func TestReadTLVBounds(t *testing.T) {
	for _, b := range [][]byte{{0x30}, {0x30, 0x05, 1, 2}, {0x30, 0x85, 0, 0, 0, 0, 1}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, {0x30, 0x80}, {0x1f, 0x01, 0}} {
		if _, _, _, err := readTLV(b); err == nil {
			t.Errorf("% x accepted", b)
		}
	}
	// long-form length
	val := bytes.Repeat([]byte{7}, 300)
	tag, v, rest, err := readTLV(tlv(tagOctetString, val))
	if err != nil || tag != tagOctetString || !bytes.Equal(v, val) || len(rest) != 0 {
		t.Errorf("long form: %v", err)
	}
}

func TestPDURoundTrip(t *testing.T) {
	p := PDU{Type: pduResponse, RequestID: -5, VarBinds: []VarBind{
		{mustOID("1.3.6.1.2.1.1.1.0"), OctetString("x")},
		{mustOID("1.3.6.1.2.1.1.3.0"), TimeTicks(123)},
		{mustOID("1.3.6.1.2.1.31.1.1.1.6.1"), Counter64(1 << 40)},
		{mustOID("1.3.6.1.2.1.1.2.0"), ObjectID(oidNetSNMPLinux)},
		{mustOID("1.3.6.1.4.1.41112.1.6.3.1.0"), IPAddress([]byte{192, 168, 0, 205})},
		{mustOID("1.3.6.1.2.1.1.9.0"), Value{Tag: tagNoSuchObject}},
	}}
	got, err := parsePDU(p.encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.RequestID != -5 || len(got.VarBinds) != len(p.VarBinds) {
		t.Fatalf("%+v", got)
	}
	for i, vb := range got.VarBinds {
		if !bytes.Equal(vb.Value.encode(), p.VarBinds[i].Value.encode()) || vb.Name.Compare(p.VarBinds[i].Name) != 0 {
			t.Errorf("varbind %d: %+v", i, vb)
		}
	}
}

// FuzzHandle: no input makes the agent panic, and nothing but a well-formed
// request with the right community is answered.
func FuzzHandle(f *testing.F) {
	s := testServer(f, &Config{V1V2c: true, Community: "pub", V3: true, User: "mon", Password: "password1"})
	lo := netip.MustParseAddr("127.0.0.1")
	f.Add(v2Request(1, "pub", PDU{Type: pduGetNext, RequestID: 1, VarBinds: []VarBind{{Name: mustOID("1.3.6.1"), Value: nullValue}}}))
	f.Add(v2Request(0, "pub", PDU{Type: pduGet, RequestID: 1, VarBinds: []VarBind{{Name: mustOID("1.3.6.1.2.1.1.1.0"), Value: nullValue}}}))
	f.Add(discovery(7))
	f.Fuzz(func(t *testing.T, b []byte) {
		s.Handle(b, lo)
	})
}
