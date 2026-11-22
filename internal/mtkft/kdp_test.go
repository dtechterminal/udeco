// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// signalFrame builds a KDP frame as FT_KDP_EventInform (0x80541d14) does:
// a 0x41c-byte signal, Sig at 0x12, {EventLen, PeerIp} at 0x1c, the body
// at 0x24, 0x24 + EventLen bytes after a 14-byte Ethernet header
// (destination the BSSID, source 00:00:00:00:00:01, type 0xEEEE).
func signalFrame(bssid MAC, sig byte, seq uint16, sta MAC, peerIP uint32, body []byte) []byte {
	f := make([]byte, 14+0x24+len(body))
	copy(f, bssid[:])
	f[11] = 1
	binary.BigEndian.PutUint16(f[12:], EtherTypeKDP)
	s := f[14:]
	binary.LittleEndian.PutUint16(s[4:], seq)
	copy(s[6:], sta[:])
	s[0x12] = sig
	binary.LittleEndian.PutUint32(s[0x1c:], uint32(len(body)))
	binary.LittleEndian.PutUint32(s[0x20:], peerIP)
	copy(s[0x24:], body)
	return f
}

func TestParseSignalAssoc(t *testing.T) {
	bss, sta := mustMAC(t, "a8:42:a1:00:00:01"), mustMAC(t, "02:11:22:33:44:55")
	// FT_ASSOCIATION from PeerPairMsg4Action: body {u16 seq = 0, STA}
	body := append([]byte{0, 0}, sta[:]...)
	s, err := ParseSignal(signalFrame(bss, SigFTAssoc, 0, sta, 0, body))
	if err != nil {
		t.Fatal(err)
	}
	if s.BSSID != bss || s.Sig != SigFTAssoc || s.STA != sta || len(s.Body) != 8 {
		t.Fatalf("%+v", s)
	}
	a, err := s.ParseAssoc()
	if err != nil || a.STA != sta {
		t.Errorf("%+v %v", a, err)
	}
	old := mustMAC(t, "a8:42:a1:00:00:09")
	s, _ = ParseSignal(signalFrame(bss, SigFTReassoc, 7, sta, 0, append(append([]byte{7, 0}, sta[:]...), old[:]...)))
	if a, err := s.ParseAssoc(); err != nil || a.Seq != 7 || a.OldAP != old {
		t.Errorf("reassoc %+v %v", a, err)
	}
	s.Sig = SigKeyRspAuto
	if _, err := s.ParseAssoc(); err == nil {
		t.Error("key response parsed as an association")
	}
}

func TestParseSignalRejects(t *testing.T) {
	bss, sta := mustMAC(t, "a8:42:a1:00:00:01"), mustMAC(t, "02:11:22:33:44:55")
	good := signalFrame(bss, SigFTAssoc, 0, sta, 0, make([]byte, 8))
	if _, err := ParseSignal(good[:14+0x23]); err == nil {
		t.Error("short frame accepted")
	}
	b := append([]byte(nil), good...)
	b[11] = 2 // another source: a real station's frame
	if _, err := ParseSignal(b); err == nil {
		t.Error("source other than 00:00:00:00:00:01 accepted")
	}
	b = append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(b[14+0x1c:], 9) // EventLen beyond the frame
	if _, err := ParseSignal(b); err == nil {
		t.Error("event length beyond the frame accepted")
	}
	b = append([]byte(nil), good...)
	b[13] = 0xED
	if _, err := ParseSignal(b); err == nil {
		t.Error("other EtherType accepted")
	}
}

func testElement(t *testing.T) KeyElement {
	e := KeyElement{
		STA:             mustMAC(t, "02:11:22:33:44:55"),
		R0KHID:          []byte("a842a1000003"),
		R1KHID:          mustMAC(t, "a8:42:a1:00:00:01"),
		S1KHID:          mustMAC(t, "02:11:22:33:44:55"),
		R0KHMAC:         mustMAC(t, "a8:42:a1:00:00:03"),
		Pairwise:        CipherCCMP,
		AKM:             AKMFTSAE,
		KeyLifeTime:     43200,
		ReassocDeadline: 20,
	}
	copy(e.PMKR0Name[:], seqOf(0))
	copy(e.PMKR1[:], append(seqOf(32), seqOf(48)...))
	e.PMKR1Name = PMKR1Name(e.PMKR0Name, e.R1KHID, e.S1KHID)
	return e
}

// The offsets FT_KDP_KeyResponseToUs (0x805431d4) reads from its buffer
// (PeerIP 4 + nonce 8 + element): ElmId 0xc, OUI 0x10, MacAddr 0x13,
// R0KHID 0x1c, R0KHIDLen 0x4c, PMKR0Name 0x4d, R1KHID 0x5d, S1KHID 0x63,
// PMKR1Name 0x6d, PMKR1 0x7d, R0KH_MAC 0x9d, pairwise 0xa3, AKM 0xa7,
// lifetime 0xab, deadline 0xaf.
func TestKeyResponseLayout(t *testing.T) {
	e := testElement(t)
	r, err := KeyResponse(e)
	if err != nil {
		t.Fatal(err)
	}
	if r.Flags != OIDKeyRsp|OIDSet || len(r.Buf) != 12+KeyElementLen {
		t.Fatalf("flags %#x len %d", r.Flags, len(r.Buf))
	}
	b := r.Buf
	if binary.LittleEndian.Uint32(b) == 0 {
		t.Error("PeerIP 0")
	}
	at := func(off int, want []byte) {
		t.Helper()
		if !bytes.Equal(b[off:off+len(want)], want) {
			t.Errorf("at %#x: % x, want % x", off, b[off:off+len(want)], want)
		}
	}
	at(0xc, []byte{0xff, 0xff, 0xa3, 0x00, 0x00, 0x0e, 0x2e})
	at(0x13, e.STA[:])
	at(0x1c, e.R0KHID)
	at(0x4c, []byte{byte(len(e.R0KHID))})
	at(0x4d, e.PMKR0Name[:])
	at(0x5d, e.R1KHID[:])
	at(0x63, e.S1KHID[:])
	at(0x6d, e.PMKR1Name[:])
	at(0x7d, e.PMKR1[:])
	at(0x9d, e.R0KHMAC[:])
	at(0xa3, CipherCCMP[:])
	at(0xa7, AKMFTSAE[:])
	at(0xab, []byte{0xc0, 0xa8, 0, 0})
	at(0xaf, []byte{20, 0, 0, 0})

	var back KeyElement
	if err := back.UnmarshalBinary(b[12:]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.R0KHID, e.R0KHID) || back.PMKR1 != e.PMKR1 || back.AKM != e.AKM || back.KeyLifeTime != e.KeyLifeTime {
		t.Errorf("round trip %+v", back)
	}

	bad := e
	bad.R1KHID = mustMAC(t, "a8:42:a1:00:00:02") // the name was for ...:01
	if _, err := KeyResponse(bad); err == nil {
		t.Error("PMKR1Name for another R1KH accepted")
	}
	bad = e
	bad.R0KHID = nil
	if _, err := KeyResponse(bad); err == nil {
		t.Error("empty R0KH-ID accepted")
	}
}

// A key request carries the station and the target R1KH (FT_QueryKeyInfoForKDP
// reads MacAddr and KeyInfo.R1KHID) under a non-zero PeerIP the driver echoes.
func TestKeyRequest(t *testing.T) {
	sta, r1kh := mustMAC(t, "02:11:22:33:44:55"), mustMAC(t, "a8:42:a1:00:00:03")
	r, err := KeyRequest(0x01020304, sta, r1kh)
	if err != nil {
		t.Fatal(err)
	}
	if r.Flags != OIDKeyReq|OIDSet || binary.LittleEndian.Uint32(r.Buf) != 0x01020304 {
		t.Fatalf("%#x %x", r.Flags, r.Buf[:4])
	}
	if !bytes.Equal(r.Buf[0x13:0x19], sta[:]) || !bytes.Equal(r.Buf[0x5d:0x63], r1kh[:]) || !bytes.Equal(r.Buf[0x63:0x69], sta[:]) {
		t.Error("station / R1KH-ID / S1KH-ID misplaced")
	}
	if _, err := KeyRequest(0, sta, r1kh); err == nil {
		t.Error("PeerIP 0 accepted (the driver ignores it)")
	}
	// the driver's answer: SigKeyRspAuto with the element filled
	e := testElement(t)
	el, _ := e.MarshalBinary()
	s, err := ParseSignal(signalFrame(r1kh, SigKeyRspAuto, 0, sta, 0x01020304, el))
	if err != nil {
		t.Fatal(err)
	}
	var got KeyElement
	if err := got.UnmarshalBinary(s.Body); err != nil || s.PeerIP != 0x01020304 || got.PMKR1Name != e.PMKR1Name {
		t.Errorf("%v %#x", err, s.PeerIP)
	}
}

func TestUnmarshalRejects(t *testing.T) {
	var e KeyElement
	el, _ := testElement(t).MarshalBinary()
	if err := e.UnmarshalBinary(el[:KeyElementLen-1]); err == nil {
		t.Error("short element accepted")
	}
	b := append([]byte(nil), el...)
	b[5] = 0x0f
	if err := e.UnmarshalBinary(b); err == nil {
		t.Error("other OUI accepted")
	}
	b = append([]byte(nil), el...)
	b[0x40] = 49
	if err := e.UnmarshalBinary(b); err == nil {
		t.Error("R0KH-ID length 49 accepted")
	}
}

func TestCiphers(t *testing.T) {
	s, err := CipherFromHostapd(0x10)
	if err != nil || s != CipherCCMP {
		t.Errorf("%x %v", s, err)
	}
	if b, err := HostapdCipher(CipherCCMP); err != nil || b != 0x10 {
		t.Errorf("%#x %v", b, err)
	}
	if _, err := CipherFromHostapd(0x18); err == nil {
		t.Error("two cipher bits accepted")
	}
	if _, err := HostapdCipher(Suite{0x00, 0x0f, 0xac, 0x03}); err == nil {
		t.Error("WRAP (suite 3) mapped to a hostapd cipher")
	}
}
