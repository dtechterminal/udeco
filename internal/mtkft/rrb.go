// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// hostapd 2.9's R0KH-R1KH protocol over RRB-OUI (src/ap/wpa_auth_ft.c,
// wpa_auth.h), what the Decos speak with explicit r0kh/r1kh peers and
// pmk_r1_push=1 (docs/deco/features/ft-sae.md). A frame is Ethernet with
// EtherType 0x88b7 (IEEE 802 OUI Extended), OUI 00:13:74, one subtype
// octet, then:
//
//	u16 authlen (LE) || authenticated TLVs (authlen) || AES-SIV(encrypted TLVs)
//
// The SIV associated data are the Ethernet source, the authenticated TLVs
// and the subtype octet; a TLV is {u16 type, u16 len} LE and the data.
// hostapd pads a payload shorter than 64 bytes with an empty TLV (type 0)
// at the end of the authenticated part.

// EtherTypeOUI is ETH_P_OUI.
const EtherTypeOUI = 0x88b7

// FTOUI is hostapd's RRB-OUI OUI (eth_p_oui.c global_oui).
var FTOUI = [3]byte{0x00, 0x13, 0x74}

// RRB-OUI subtypes (FT_PACKET_R0KH_R1KH_*).
const (
	SubPull    = 0x01
	SubResp    = 0x02
	SubPush    = 0x03
	SubSeqReq  = 0x04
	SubSeqResp = 0x05
)

// TLV types (FT_RRB_*).
const (
	TLVLastEmpty      = 0
	TLVSeq            = 1
	TLVNonce          = 2
	TLVTimestamp      = 3
	TLVR0KHID         = 4
	TLVR1KHID         = 5
	TLVS1KHID         = 6
	TLVPMKR0Name      = 7
	TLVPMKR0          = 8
	TLVPMKR1Name      = 9
	TLVPMKR1          = 10
	TLVPairwise       = 11
	TLVExpiresIn      = 12
	TLVVLANUntagged   = 13
	TLVVLANTagged     = 14
	TLVIdentity       = 15
	TLVRadiusCUI      = 16
	TLVSessionTimeout = 17
)

const (
	nonceLen      = 16 // FT_RRB_NONCE_LEN
	rrbMinMsgLen  = 64 // RRB_MIN_MSG_LEN
	ouiHeaderLen  = 4  // OUI and subtype
	tlvHeaderLen  = 4
	seqLen        = 12 // struct ft_rrb_seq
	seqTimeoutSec = 10 // ftRRBseqTimeout
)

// TLV is one ft_rrb_tlv.
type TLV struct {
	Type uint16
	Data []byte
}

func linTLVs(ts []TLV) []byte {
	var b []byte
	for _, t := range ts {
		b = binary.LittleEndian.AppendUint16(b, t.Type)
		b = binary.LittleEndian.AppendUint16(b, uint16(len(t.Data)))
		b = append(b, t.Data...)
	}
	return b
}

// parseTLVs reads TLVs as wpa_ft_rrb_get_tlv walks them (a truncated last
// one ends the list).
func parseTLVs(b []byte) []TLV {
	var ts []TLV
	for len(b) >= tlvHeaderLen {
		t := binary.LittleEndian.Uint16(b)
		n := int(binary.LittleEndian.Uint16(b[2:]))
		b = b[tlvHeaderLen:]
		if n > len(b) {
			break
		}
		ts = append(ts, TLV{Type: t, Data: b[:n]})
		b = b[n:]
	}
	return ts
}

// find is the first TLV of type t (wpa_ft_rrb_get_tlv).
func find(ts []TLV, t uint16) ([]byte, bool) {
	for _, v := range ts {
		if v.Type == t {
			return v.Data, true
		}
	}
	return nil, false
}

// Seal builds an RRB-OUI payload (from the OUI on: what follows the
// Ethernet header) as wpa_ft_rrb_build does: key is RRBKey, src the frame's
// Ethernet source (this BSS's address, as hostapd's wpa_auth->addr).
func Seal(key [32]byte, src MAC, subtype byte, auth, enc []TLV) ([]byte, error) {
	a := linTLVs(auth)
	p := linTLVs(enc)
	n := 2 + len(a) + len(p) + 16
	if n < rrbMinMsgLen {
		pad := max(rrbMinMsgLen-n, tlvHeaderLen)
		a = append(a, linTLVs([]TLV{{Type: TLVLastEmpty, Data: make([]byte, pad-tlvHeaderLen)}})...)
	}
	vc, err := sivSeal(key[:], p, src[:], a, []byte{subtype})
	clear(p)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, ouiHeaderLen+2+len(a)+len(vc))
	out = append(out, FTOUI[:]...)
	out = append(out, subtype)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(a)))
	out = append(out, a...)
	return append(out, vc...), nil
}

// Frame is an opened RRB-OUI payload.
type Frame struct {
	Subtype byte
	Auth    []TLV
	Enc     []TLV
	// authRaw is the authenticated part as received (the SIV AD).
	authRaw []byte
}

var errRRB = errors.New("mtkft: not an RRB-OUI frame")

// Split reads the subtype and the authenticated TLVs of payload without a
// key (a receiver picks the key by the R0KH-ID / R1KH-ID in them, as
// hostapd does), and returns the sealed rest for Open.
func Split(payload []byte) (Frame, []byte, error) {
	if len(payload) < ouiHeaderLen+2 || [3]byte(payload[:3]) != FTOUI {
		return Frame{}, nil, errRRB
	}
	sub := payload[3]
	p := payload[ouiHeaderLen:]
	n := int(binary.LittleEndian.Uint16(p))
	if 2+n > len(p) {
		return Frame{}, nil, fmt.Errorf("mtkft: RRB authlen %d beyond %d bytes", n, len(p))
	}
	a := p[2 : 2+n]
	return Frame{Subtype: sub, Auth: parseTLVs(a), authRaw: a}, p[2+n:], nil
}

// Open decrypts the sealed part of f (from Split) under key, with src the
// frame's Ethernet source. Like wpa_ft_rrb_decrypt it retries without the
// last two octets, for Ethernet drivers that pad.
func (f *Frame) Open(key [32]byte, src MAC, sealed []byte) error {
	ad := [][]byte{src[:], f.authRaw, {f.Subtype}}
	p, err := sivOpen(key[:], sealed, ad...)
	if err != nil && len(sealed) >= 18 {
		p, err = sivOpen(key[:], sealed[:len(sealed)-2], ad...)
	}
	if err != nil {
		return err
	}
	f.Enc = parseTLVs(p)
	return nil
}

// Seq is struct ft_rrb_seq.
type Seq struct{ Dom, Seq, TS uint32 }

func (s Seq) bytes() []byte {
	b := make([]byte, seqLen)
	binary.LittleEndian.PutUint32(b, s.Dom)
	binary.LittleEndian.PutUint32(b[4:], s.Seq)
	binary.LittleEndian.PutUint32(b[8:], s.TS)
	return b
}

func parseSeq(b []byte) (Seq, bool) {
	if len(b) != seqLen {
		return Seq{}, false
	}
	return Seq{binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:]), binary.LittleEndian.Uint32(b[8:])}, true
}

// TxSeq numbers the frames sent to one peer (wpa_ft_new_seq): a random
// domain (odd) and start, the sequence counting up, TS a monotonic clock
// in seconds that must stay consistent for the peer's lifetime (hostapd
// accepts a frame whose TS is within ftRRBseqTimeout of what the peer's
// SEQ_RESP clock offset predicts).
type TxSeq struct {
	dom, seq uint32
}

// Next is the sequence for the next frame; now is the monotonic seconds.
func (t *TxSeq) Next(now uint32) Seq {
	if t.dom == 0 {
		var b [8]byte
		_, _ = rand.Read(b[:])
		t.seq = binary.LittleEndian.Uint32(b[:])
		t.dom = binary.LittleEndian.Uint32(b[4:]) | 1
	}
	s := Seq{Dom: t.dom, Seq: t.seq, TS: now}
	t.seq++
	return s
}

// RxSeq is a light replay filter for frames from one peer: a frame of a
// new domain resets it (the peer restarted); within a domain a sequence
// already seen or not within 2^30 of the newest is refused. hostapd
// additionally asks a new peer for its sequence (SEQ_REQ) before
// accepting; a PMK-R1 push replayed within the window only reinstalls an
// SA the peer did push.
type RxSeq struct {
	dom    uint32
	newest uint32
	seen   []uint32
}

const rxBacklog = 8 // FT_REMOTE_SEQ_BACKLOG

// Accept reports whether s is new, and records it.
func (r *RxSeq) Accept(s Seq) bool {
	if r.seen == nil || s.Dom != r.dom {
		r.dom, r.newest, r.seen = s.Dom, s.Seq, []uint32{s.Seq}
		return true
	}
	for _, v := range r.seen {
		if v == s.Seq {
			return false
		}
	}
	switch d := s.Seq - r.newest; {
	case d <= 0x40000000:
		r.newest = s.Seq
	case d < 0xC0000000:
		return false // neither ahead nor within 2^30 behind
	}
	r.seen = append(r.seen, s.Seq)
	if len(r.seen) > rxBacklog {
		r.seen = r.seen[1:]
	}
	return true
}

// Push is a PMK-R1 push (wpa_ft_generate_pmk_r1): auth SEQ, R0KH_ID,
// R1KH_ID; encrypted S1KH_ID, PMK_R0_NAME and the session TLVs PMK_R1,
// PMK_R1_NAME, PAIRWISE, EXPIRES_IN, IDENTITY, RADIUS_CUI, SESSION_TIMEOUT.
type Push struct {
	Seq            Seq
	R0KHID         []byte
	R1KHID         MAC
	S1KHID         MAC
	PMKR0Name      [16]byte
	PMKR1          [32]byte
	PMKR1Name      [16]byte
	Pairwise       uint16 // hostapd WPA_CIPHER_* bit
	ExpiresIn      uint16 // seconds; 0 = no expiry
	SessionTimeout uint32
}

// SealPush builds p as hostapd sends it, identity and CUI empty (hostapd
// lists them with length 0 for a PSK or SAE station).
func SealPush(key [32]byte, src MAC, p Push) ([]byte, error) {
	if len(p.R0KHID) == 0 || len(p.R0KHID) > MaxR0KHIDLen {
		return nil, errors.New("mtkft: push R0KH-ID must be 1-48 octets")
	}
	le16 := func(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
	auth := []TLV{
		{TLVSeq, p.Seq.bytes()},
		{TLVR0KHID, p.R0KHID},
		{TLVR1KHID, p.R1KHID[:]},
	}
	enc := []TLV{
		{TLVS1KHID, p.S1KHID[:]},
		{TLVPMKR0Name, p.PMKR0Name[:]},
		{TLVPMKR1, p.PMKR1[:]},
		{TLVPMKR1Name, p.PMKR1Name[:]},
		{TLVPairwise, le16(p.Pairwise)},
		{TLVExpiresIn, le16(p.ExpiresIn)},
		{TLVIdentity, nil},
		{TLVRadiusCUI, nil},
		{TLVSessionTimeout, binary.LittleEndian.AppendUint32(nil, p.SessionTimeout)},
	}
	return Seal(key, src, SubPush, auth, enc)
}

// ParsePush reads an opened push frame with the checks of wpa_ft_rrb_rx_r1:
// required R0KH_ID, R1KH_ID (6), SEQ, S1KH_ID (6), PAIRWISE (2),
// PMK_R1_NAME (16), PMK_R1 (32: SHA-384 SAs are refused, the driver
// cannot hold them); PMK_R0_NAME (16, which hostapd does not need but the
// MT7663's R1KH entry does).
func ParsePush(f Frame) (Push, error) {
	var p Push
	if f.Subtype != SubPush {
		return p, fmt.Errorf("mtkft: RRB subtype %d is not a push", f.Subtype)
	}
	get := func(ts []TLV, t uint16, n int) ([]byte, error) {
		v, ok := find(ts, t)
		if !ok || n >= 0 && len(v) != n {
			return nil, fmt.Errorf("mtkft: push without a valid TLV %d", t)
		}
		return v, nil
	}
	v, err := get(f.Auth, TLVSeq, seqLen)
	if err != nil {
		return p, err
	}
	p.Seq, _ = parseSeq(v)
	if v, err = get(f.Auth, TLVR0KHID, -1); err != nil {
		return p, err
	}
	if len(v) == 0 || len(v) > MaxR0KHIDLen {
		return p, errors.New("mtkft: push R0KH-ID length")
	}
	p.R0KHID = append([]byte(nil), v...)
	for _, c := range []struct {
		ts  []TLV
		t   uint16
		dst []byte
	}{
		{f.Auth, TLVR1KHID, p.R1KHID[:]},
		{f.Enc, TLVS1KHID, p.S1KHID[:]},
		{f.Enc, TLVPMKR0Name, p.PMKR0Name[:]},
		{f.Enc, TLVPMKR1Name, p.PMKR1Name[:]},
		{f.Enc, TLVPMKR1, p.PMKR1[:]},
	} {
		v, err := get(c.ts, c.t, len(c.dst))
		if err != nil {
			return p, err
		}
		copy(c.dst, v)
	}
	if v, err = get(f.Enc, TLVPairwise, 2); err != nil {
		return p, err
	}
	p.Pairwise = binary.LittleEndian.Uint16(v)
	if v, ok := find(f.Enc, TLVExpiresIn); ok && len(v) == 2 {
		p.ExpiresIn = binary.LittleEndian.Uint16(v)
	}
	if v, ok := find(f.Enc, TLVSessionTimeout); ok && len(v) == 4 {
		p.SessionTimeout = binary.LittleEndian.Uint32(v)
	}
	if PMKR1Name(p.PMKR0Name, p.R1KHID, p.S1KHID) != p.PMKR1Name {
		return p, errors.New("mtkft: push PMKR1Name does not match its PMKR0Name")
	}
	return p, nil
}

// SeqReq is a sequence number request (wpa_ft_rrb_seq_req): auth NONCE,
// R0KH_ID, R1KH_ID, nothing encrypted. A Deco sends one to the Garage the
// first time it hears a push from it, and processes the push only after
// the Garage's SEQ_RESP (within ftRRBseqTimeout).
type SeqReq struct {
	Nonce  [nonceLen]byte
	R0KHID []byte
	R1KHID MAC
}

// ParseSeqReq reads an opened SEQ_REQ.
func ParseSeqReq(f Frame) (SeqReq, error) {
	var q SeqReq
	if f.Subtype != SubSeqReq {
		return q, fmt.Errorf("mtkft: RRB subtype %d is not a sequence request", f.Subtype)
	}
	n, ok1 := find(f.Auth, TLVNonce)
	r0, ok2 := find(f.Auth, TLVR0KHID)
	r1, ok3 := find(f.Auth, TLVR1KHID)
	if !ok1 || !ok2 || !ok3 || len(n) != nonceLen || len(r1) != 6 || len(r0) == 0 || len(r0) > MaxR0KHIDLen {
		return q, errors.New("mtkft: malformed sequence request")
	}
	copy(q.Nonce[:], n)
	q.R0KHID = append([]byte(nil), r0...)
	copy(q.R1KHID[:], r1)
	return q, nil
}

// SealSeqResp answers q (wpa_ft_rrb_rx_seq_req): auth NONCE, SEQ, R0KH_ID,
// R1KH_ID in that order, nothing encrypted, with this side's next
// sequence to that peer.
func SealSeqResp(key [32]byte, src MAC, q SeqReq, s Seq) ([]byte, error) {
	auth := []TLV{
		{TLVNonce, q.Nonce[:]},
		{TLVSeq, s.bytes()},
		{TLVR0KHID, q.R0KHID},
		{TLVR1KHID, q.R1KHID[:]},
	}
	return Seal(key, src, SubSeqResp, auth, nil)
}
