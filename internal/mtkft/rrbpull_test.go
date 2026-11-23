// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Built independently from hostapd 2.9's wpa_ft_pull_pmk_r1 and
// wpa_ft_rrb_rx_pull / wpa_ft_rrb_build_r0 TLV lists and sealed with
// pyca/cryptography's AESSIV (work/vec/pullresp.py), under the RRBKey of
// iapp_key 10..1f.
const (
	pullVector     = "0013740001013e0002001000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf01000c0011111111222222223333333304000c0061383432613130303030303105000600a842a100000213e82dc9b41470932c5ef8ccba718d1f2df932b103f7ffc11959723fde3ae7814ab5d4e988865984dc0fe2f8fafe"
	respVector     = "0013740001023e0002001000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf01000c0044444444555555556666666604000c0061383432613130303030303105000600a842a100000267ef2a9c295f3aad9c7b83235e79bc456021b6702d1c8edafd1d93537933901f3313964818ad33080fd947c2bd168c11e74d63031f95df895cab8e75d08b7170c4e48daab6972fcacdb61a420c91b8ea4d47c874db50054779fe468feb8051fa88aed85a0cccc75dfed8d366ff6e"
	respMissVector = "0013740001023e0002001000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf01000c0044444444555555556666666604000c0061383432613130303030303105000600a842a100000262005ca849d2064a210fb2b5859c912ce86035bc7f0f28f018f9"
)

func testPull(t *testing.T) Pull {
	p := Pull{Seq: Seq{0x11111111, 0x22222222, 0x33333333}, R0KHID: []byte("a842a1000001"),
		R1KHID: mustMAC(t, "a8:42:a1:00:00:02"), S1KHID: mustMAC(t, "02:11:22:33:44:55")}
	copy(p.Nonce[:], seqOf(0xa0))
	copy(p.PMKR0Name[:], seqOf(0))
	return p
}

func testResp(t *testing.T, found bool) Resp {
	r := Resp{Seq: Seq{0x44444444, 0x55555555, 0x66666666}, R0KHID: []byte("a842a1000001"),
		R1KHID: mustMAC(t, "a8:42:a1:00:00:02"), S1KHID: mustMAC(t, "02:11:22:33:44:55"), Found: found, Pairwise: 0x10}
	copy(r.Nonce[:], seqOf(0xa0))
	if found {
		copy(r.PMKR1[:], append(seqOf(32), seqOf(48)...))
		copy(r.PMKR1Name[:], seqOf(64))
	}
	return r
}

func TestPullRespVectors(t *testing.T) {
	key := rrbTestKey(t)
	r1, r0 := mustMAC(t, "a8:42:a1:00:00:02"), mustMAC(t, "a8:42:a1:00:00:01")
	for _, c := range []struct {
		name string
		got  func() ([]byte, error)
		want string
	}{
		{"pull", func() ([]byte, error) { return SealPull(key, r1, testPull(t)) }, pullVector},
		{"resp", func() ([]byte, error) { return SealResp(key, r0, testResp(t, true)) }, respVector},
		{"resp miss", func() ([]byte, error) { return SealResp(key, r0, testResp(t, false)) }, respMissVector},
	} {
		got, err := c.got()
		if err != nil {
			t.Fatal(c.name, err)
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("%s\n got %x\nwant %s", c.name, got, c.want)
		}
	}
}

func openVec(t *testing.T, v string, src MAC) Frame {
	b, _ := hex.DecodeString(v)
	f, sealed, err := Split(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Open(rrbTestKey(t), src, sealed); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestParsePullResp(t *testing.T) {
	r1, r0 := mustMAC(t, "a8:42:a1:00:00:02"), mustMAC(t, "a8:42:a1:00:00:01")
	p, err := ParsePull(openVec(t, pullVector, r1))
	if err != nil {
		t.Fatal(err)
	}
	want := testPull(t)
	if p.Nonce != want.Nonce || p.Seq != want.Seq || !bytes.Equal(p.R0KHID, want.R0KHID) || p.R1KHID != want.R1KHID ||
		p.PMKR0Name != want.PMKR0Name || p.S1KHID != want.S1KHID {
		t.Fatalf("pull %+v", p)
	}
	r, err := ParseResp(openVec(t, respVector, r0))
	if err != nil {
		t.Fatal(err)
	}
	wr := testResp(t, true)
	if !r.Found || r.PMKR1 != wr.PMKR1 || r.PMKR1Name != wr.PMKR1Name || r.Pairwise != 0x10 || r.Nonce != wr.Nonce || r.S1KHID != wr.S1KHID {
		t.Fatalf("resp %+v", r)
	}
	m, err := ParseResp(openVec(t, respMissVector, r0))
	if err != nil || m.Found {
		t.Fatalf("miss %+v %v", m, err)
	}
	// a push is neither
	f := openVec(t, pushVector, r0)
	if _, err := ParsePull(f); err == nil {
		t.Fatal("push parsed as a pull")
	}
	if _, err := ParseResp(f); err == nil {
		t.Fatal("push parsed as a response")
	}
	if id, r1h, ok := f.R0KHIDOf(); !ok || string(id) != "a842a1000001-mt7663-r0kh" || r1h != r1 {
		t.Fatalf("R0KHIDOf %q %v %v", id, r1h, ok)
	}
}

func TestUDFTR1Layout(t *testing.T) {
	r := UDFTR1{NameGiven: true, STA: mustMAC(t, "02:11:22:33:44:55"), R1KHID: mustMAC(t, "a8:42:a1:00:00:02"),
		R0KHID: []byte("a842a1000001"), AKM: AKMFTSAE, Pairwise: CipherCCMP, Lifetime: 43200}
	copy(r.PMKR0Name[:], seqOf(0))
	copy(r.PMKR1Name[:], seqOf(64))
	copy(r.PMKR1[:], append(seqOf(32), seqOf(48)...))
	b, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// ft.h UDFT_R1 (GNU_PACKED): version, r0kh_id_len, flags, reserved,
	// sta 4, r1kh_id 10, r0kh_id 16, pmk_r0_name 64, pmk_r1_name 80,
	// pmk_r1 96, akm 128, pairwise 132, lifetime_s 136
	if len(b) != 140 || b[0] != 1 || b[1] != 12 || b[2] != 1 || b[4] != 0x02 || b[10] != 0xa8 ||
		string(b[16:28]) != "a842a1000001" || b[64] != 0 || b[80] != 64 || b[96] != 32 ||
		!bytes.Equal(b[128:132], AKMFTSAE[:]) || !bytes.Equal(b[132:136], CipherCCMP[:]) ||
		binary.LittleEndian.Uint32(b[136:]) != 43200 {
		t.Fatalf("layout %x", b)
	}
	var back UDFTR1
	if err := back.UnmarshalBinary(b); err != nil || back.PMKR1 != r.PMKR1 || string(back.R0KHID) != "a842a1000001" || !back.NameGiven {
		t.Fatalf("round trip %+v %v", back, err)
	}
	q := UDFTR1Request(r.STA, r.R1KHID, r.PMKR0Name)
	if len(q) != UDFTR1Len || q[0] != 1 || q[4] != 0x02 || q[10] != 0xa8 || q[16] != 0 || q[31] != 15 {
		t.Fatalf("request %x", q)
	}
	if _, err := (UDFTR1{}).MarshalBinary(); err == nil {
		t.Fatal("empty R0KH-ID accepted")
	}
}

func TestParseUDFTEvents(t *testing.T) {
	ev := func(typ byte, seq uint32) []byte {
		b := make([]byte, UDFTEventLen)
		b[0], b[1], b[2], b[3] = 1, typ, 12, 1
		copy(b[4:], []byte{2, 0x11, 0x22, 0x33, 0x44, 0x55})
		copy(b[10:], []byte{0xa8, 0x42, 0xa1, 0, 0, 2})
		copy(b[16:], "a842a1000001")
		copy(b[64:], seqOf(0))
		copy(b[80:], seqOf(64))
		copy(b[96:], AKMFTSAE[:])
		binary.LittleEndian.PutUint32(b[100:], seq)
		return b
	}
	es, err := ParseUDFTEvents(append(ev(UDFTR0Created, 7), ev(UDFTR1Miss, 8)...))
	if err != nil || len(es) != 2 {
		t.Fatal(es, err)
	}
	if es[0].Type != UDFTR0Created || es[0].APIdx != 1 || string(es[0].R0KHID) != "a842a1000001" || es[1].Seq != 8 ||
		es[1].AKM != AKMFTSAE || es[1].BSSID != mustMAC(t, "a8:42:a1:00:00:02") || es[1].PMKR1Name[0] != 64 {
		t.Fatalf("%+v", es)
	}
	if _, err := ParseUDFTEvents(make([]byte, 50)); err == nil {
		t.Fatal("short accepted")
	}
	bad := ev(9, 1)
	if _, err := ParseUDFTEvent(bad); err == nil {
		t.Fatal("unknown type accepted")
	}
}
