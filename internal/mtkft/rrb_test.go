// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Frames built by hand from hostapd 2.9's wpa_ft_rrb_build /
// wpa_ft_generate_pmk_r1 / wpa_ft_rrb_rx_seq_req layouts, sealed with
// pyca/cryptography's AESSIV, under the RRBKey of iapp_key 10..1f.
const (
	pushVector    = "001374000103360001000c00111111112222222233333333040018006138343261313030303030312d6d74373636332d72306b6805000600a842a10000028f0a7edec967f7b9cf3aafdf2d50e75d8b829f08c451c512ede3ced21a9a6828eafe446748a71a05ed51dcf658cc42f9dff056988c461162e9b5831130cf662a7ac85824981f593297fc31bc0616468497ae9762df4395fb0ac7c3a2d503474f5a44d9269d059ba950d3dda108aadce60f12cfb3d17a525f0ef87859ae1229a3c5e9"
	seqRespVector = "0013740001054a0002001000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf01000c00111111112222222233333333040018006138343261313030303030312d6d74373636332d72306b6805000600a842a100000250e5081ba13197d3e212ef455e106b4b"
	paddedVector  = "0013740001042e0002001000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf0000160000000000000000000000000000000000000000000000258aec2e136f871c3408f140d11eb760"
)

func rrbTestKey(t *testing.T) [32]byte {
	k, err := RRBKey("101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func seqOf(n byte) []byte {
	b := make([]byte, 16)
	for i := range b {
		b[i] = n + byte(i)
	}
	return b
}

func testPush(t *testing.T) Push {
	p := Push{
		Seq:    Seq{0x11111111, 0x22222222, 0x33333333},
		R0KHID: []byte("a842a1000001-mt7663-r0kh"),
		R1KHID: mustMAC(t, "a8:42:a1:00:00:02"),
		S1KHID: mustMAC(t, "02:11:22:33:44:55"),
		// hostapd sends PAIRWISE as WPA_CIPHER_CCMP
		Pairwise: 0x10,
	}
	copy(p.PMKR0Name[:], seqOf(0))
	copy(p.PMKR1[:], append(seqOf(32), seqOf(48)...))
	copy(p.PMKR1Name[:], seqOf(64))
	return p
}

func TestSealPushVector(t *testing.T) {
	key, src := rrbTestKey(t), mustMAC(t, "a8:42:a1:00:00:01")
	got, err := SealPush(key, src, testPush(t))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != pushVector {
		t.Fatalf("push\n got %x\nwant %s", got, pushVector)
	}
}

// A push received from a Deco: Split, Open with the peer's key and
// source, ParsePush. The vector's PMKR1Name is not derived from its
// PMKR0Name, so ParsePush refuses it; a consistent push goes through.
func TestOpenParsePush(t *testing.T) {
	key, src := rrbTestKey(t), mustMAC(t, "a8:42:a1:00:00:01")
	f, sealed, err := Split(unhex(t, pushVector))
	if err != nil {
		t.Fatal(err)
	}
	if f.Subtype != SubPush {
		t.Fatalf("subtype %d", f.Subtype)
	}
	if r0, _ := find(f.Auth, TLVR0KHID); string(r0) != "a842a1000001-mt7663-r0kh" {
		t.Errorf("auth R0KH-ID %q readable before decryption", r0)
	}
	if err := f.Open(key, mustMAC(t, "a8:42:a1:00:00:09"), sealed); err == nil {
		t.Fatal("opened with another source address (SIV AD)")
	}
	if err := f.Open(key, src, sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePush(f); err == nil {
		t.Error("accepted a PMKR1Name that does not match")
	}

	p := testPush(t)
	p.PMKR1Name = PMKR1Name(p.PMKR0Name, p.R1KHID, p.S1KHID)
	b, err := SealPush(key, src, p)
	if err != nil {
		t.Fatal(err)
	}
	// an Ethernet driver's two octets of padding (wpa_ft_rrb_decrypt retries)
	b = append(b, 0, 0)
	f, sealed, _ = Split(b)
	if err := f.Open(key, src, sealed); err != nil {
		t.Fatal(err)
	}
	got, err := ParsePush(f)
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != p.Seq || !bytes.Equal(got.R0KHID, p.R0KHID) || got.R1KHID != p.R1KHID || got.S1KHID != p.S1KHID ||
		got.PMKR0Name != p.PMKR0Name || got.PMKR1 != p.PMKR1 || got.PMKR1Name != p.PMKR1Name || got.Pairwise != 0x10 {
		t.Errorf("round trip: %+v", got)
	}
}

func TestSeqResp(t *testing.T) {
	key, src := rrbTestKey(t), mustMAC(t, "a8:42:a1:00:00:01")
	q := SeqReq{R0KHID: []byte("a842a1000001-mt7663-r0kh"), R1KHID: mustMAC(t, "a8:42:a1:00:00:02")}
	copy(q.Nonce[:], seqOf(0xa0))
	got, err := SealSeqResp(key, src, q, Seq{0x11111111, 0x22222222, 0x33333333})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != seqRespVector {
		t.Fatalf("seq resp\n got %x\nwant %s", got, seqRespVector)
	}
	// a SEQ_REQ as a Deco sends it parses back to q
	req, err := Seal(key, mustMAC(t, "a8:42:a1:00:00:02"), SubSeqReq,
		[]TLV{{TLVNonce, q.Nonce[:]}, {TLVR0KHID, q.R0KHID}, {TLVR1KHID, q.R1KHID[:]}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, sealed, err := Split(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Open(key, mustMAC(t, "a8:42:a1:00:00:02"), sealed); err != nil {
		t.Fatal(err)
	}
	back, err := ParseSeqReq(f)
	if err != nil || back.Nonce != q.Nonce || !bytes.Equal(back.R0KHID, q.R0KHID) || back.R1KHID != q.R1KHID {
		t.Errorf("seq req %+v %v", back, err)
	}
	if _, err := ParsePush(f); err == nil {
		t.Error("a sequence request parsed as a push")
	}
}

// hostapd pads a payload under 64 bytes with an empty TLV in the
// authenticated part.
func TestSealPadding(t *testing.T) {
	key, src := rrbTestKey(t), mustMAC(t, "a8:42:a1:00:00:01")
	got, err := Seal(key, src, SubSeqReq, []TLV{{TLVNonce, seqOf(0xa0)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != paddedVector {
		t.Fatalf("padded\n got %x\nwant %s", got, paddedVector)
	}
	if len(got)-ouiHeaderLen != rrbMinMsgLen {
		t.Errorf("payload %d bytes, want %d", len(got)-ouiHeaderLen, rrbMinMsgLen)
	}
}

func TestSplitRejects(t *testing.T) {
	for _, b := range [][]byte{nil, {0, 0x13, 0x74, 0, 1}, {0, 0x13, 0x75, 0, 1, 3, 0, 0}, {0, 0x13, 0x74, 3, 9, 0, 0, 0}, {0, 0x13, 0x74, 0, 1, 3, 9, 0}} {
		if _, _, err := Split(b); err == nil {
			t.Errorf("Split(%x) accepted", b)
		}
	}
}

func TestTxSeq(t *testing.T) {
	var s TxSeq
	a, b := s.Next(100), s.Next(101)
	if a.Dom == 0 || a.Dom&1 == 0 || a.Dom != b.Dom || b.Seq != a.Seq+1 || b.TS != 101 {
		t.Errorf("%+v %+v", a, b)
	}
}

func TestRxSeq(t *testing.T) {
	var r RxSeq
	ok := func(dom, seq uint32, want bool) {
		t.Helper()
		if got := r.Accept(Seq{Dom: dom, Seq: seq}); got != want {
			t.Errorf("Accept(%#x, %#x) = %v", dom, seq, got)
		}
	}
	ok(1, 100, true)
	ok(1, 100, false) // replay
	ok(1, 101, true)
	ok(1, 99, true) // older, within the window, not seen
	ok(1, 99, false)
	ok(1, 100+0x50000000, false) // far ahead
	ok(3, 5, true)               // peer restarted: new domain
	ok(3, 5, false)
}
