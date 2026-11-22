// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// PMK-R1 pull and response (hostapd 2.9 wpa_auth_ft.c): an R1KH that has
// no PMK-R1 for an FT authentication asks the station's R0KH for one.
//
//   - PULL (wpa_ft_pull_pmk_r1): auth NONCE, SEQ, R0KH_ID, R1KH_ID;
//     encrypted PMK_R0_NAME, S1KH_ID.
//   - RESP (wpa_ft_rrb_rx_pull): auth NONCE (the pull's), SEQ, R0KH_ID,
//     R1KH_ID; encrypted S1KH_ID, then, when the R0KH holds the PMK-R0,
//     the session TLVs of a push (wpa_ft_rrb_build_r0: PMK_R1,
//     PMK_R1_NAME, PAIRWISE, EXPIRES_IN, IDENTITY, RADIUS_CUI,
//     SESSION_TIMEOUT). A RESP with S1KH_ID only is "no such PMK-R0".
//     A RESP has no PMK_R0_NAME: the R1KH knows it from its pull.
//
// hostapd asks a peer it has no sequence state for with a SEQ_REQ first
// (wpa_ft_rrb_seq_chk: FT_RRB_SEQ_DEFER), and processes the deferred frame
// after the SEQ_RESP: a Garage pull to a Deco is answered after the Deco's
// SEQ_REQ to the Garage and the Garage's SEQ_RESP.

// NonceLen is FT_RRB_NONCE_LEN.
const NonceLen = nonceLen

// Pull is a PMK-R1 pull request.
type Pull struct {
	Nonce     [NonceLen]byte
	Seq       Seq
	R0KHID    []byte
	R1KHID    MAC
	PMKR0Name [16]byte
	S1KHID    MAC
}

// SealPull builds p as hostapd sends it (src: the R1KH's BSSID).
func SealPull(key [32]byte, src MAC, p Pull) ([]byte, error) {
	if len(p.R0KHID) == 0 || len(p.R0KHID) > MaxR0KHIDLen {
		return nil, errors.New("mtkft: pull R0KH-ID must be 1-48 octets")
	}
	auth := []TLV{
		{TLVNonce, p.Nonce[:]},
		{TLVSeq, p.Seq.bytes()},
		{TLVR0KHID, p.R0KHID},
		{TLVR1KHID, p.R1KHID[:]},
	}
	enc := []TLV{
		{TLVPMKR0Name, p.PMKR0Name[:]},
		{TLVS1KHID, p.S1KHID[:]},
	}
	return Seal(key, src, SubPull, auth, enc)
}

// authHead reads the auth TLVs every pull and response carries.
func authHead(f Frame, what string) (nonce [NonceLen]byte, s Seq, r0 []byte, r1 MAC, err error) {
	n, ok1 := find(f.Auth, TLVNonce)
	sq, ok2 := find(f.Auth, TLVSeq)
	r0v, ok3 := find(f.Auth, TLVR0KHID)
	r1v, ok4 := find(f.Auth, TLVR1KHID)
	if !ok1 || !ok2 || !ok3 || !ok4 || len(n) != NonceLen || len(r1v) != 6 || len(r0v) == 0 || len(r0v) > MaxR0KHIDLen {
		err = fmt.Errorf("mtkft: malformed %s", what)
		return
	}
	if s, ok2 = parseSeq(sq); !ok2 {
		err = fmt.Errorf("mtkft: malformed %s sequence", what)
		return
	}
	copy(nonce[:], n)
	r0 = append([]byte(nil), r0v...)
	copy(r1[:], r1v)
	return
}

// ParsePull reads an opened pull (wpa_ft_rrb_rx_pull's checks).
func ParsePull(f Frame) (Pull, error) {
	var p Pull
	if f.Subtype != SubPull {
		return p, fmt.Errorf("mtkft: RRB subtype %d is not a pull", f.Subtype)
	}
	var err error
	if p.Nonce, p.Seq, p.R0KHID, p.R1KHID, err = authHead(f, "pull"); err != nil {
		return p, err
	}
	n, ok1 := find(f.Enc, TLVPMKR0Name)
	s, ok2 := find(f.Enc, TLVS1KHID)
	if !ok1 || !ok2 || len(n) != 16 || len(s) != 6 {
		return p, errors.New("mtkft: pull without PMK_R0_NAME or S1KH_ID")
	}
	copy(p.PMKR0Name[:], n)
	copy(p.S1KHID[:], s)
	return p, nil
}

// Resp is a pull response. Found: it carries a PMK-R1 (else the R0KH
// had no PMK-R0 of that name and the station does a full association).
type Resp struct {
	Nonce          [NonceLen]byte
	Seq            Seq
	R0KHID         []byte
	R1KHID         MAC
	S1KHID         MAC
	Found          bool
	PMKR1          [32]byte
	PMKR1Name      [16]byte
	Pairwise       uint16 // hostapd WPA_CIPHER_* bit
	ExpiresIn      uint16
	SessionTimeout uint32
}

// sessTLVs are a push's and a response's session TLVs (wpa_ft_rrb_build_r0).
func sessTLVs(r1 [32]byte, name [16]byte, pairwise, expires uint16, sessTimeout uint32) []TLV {
	le16 := func(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
	return []TLV{
		{TLVPMKR1, r1[:]},
		{TLVPMKR1Name, name[:]},
		{TLVPairwise, le16(pairwise)},
		{TLVExpiresIn, le16(expires)},
		{TLVIdentity, nil},
		{TLVRadiusCUI, nil},
		{TLVSessionTimeout, binary.LittleEndian.AppendUint32(nil, sessTimeout)},
	}
}

// SealResp builds r as hostapd's wpa_ft_rrb_rx_pull answers (src: the
// R0KH's BSSID).
func SealResp(key [32]byte, src MAC, r Resp) ([]byte, error) {
	if len(r.R0KHID) == 0 || len(r.R0KHID) > MaxR0KHIDLen {
		return nil, errors.New("mtkft: response R0KH-ID must be 1-48 octets")
	}
	auth := []TLV{
		{TLVNonce, r.Nonce[:]},
		{TLVSeq, r.Seq.bytes()},
		{TLVR0KHID, r.R0KHID},
		{TLVR1KHID, r.R1KHID[:]},
	}
	enc := []TLV{{TLVS1KHID, r.S1KHID[:]}}
	if r.Found {
		enc = append(enc, sessTLVs(r.PMKR1, r.PMKR1Name, r.Pairwise, r.ExpiresIn, r.SessionTimeout)...)
	}
	return Seal(key, src, SubResp, auth, enc)
}

// ParseResp reads an opened response (wpa_ft_rrb_rx_resp, then
// wpa_ft_rrb_rx_r1's checks when it carries a key: PMK_R1 of 32 octets,
// PMK_R1_NAME, PAIRWISE). The caller checks the nonce against its pull and
// the PMKR1Name against PMKR1Name(pull's PMKR0Name, R1KH-ID, S1KH-ID).
func ParseResp(f Frame) (Resp, error) {
	var r Resp
	if f.Subtype != SubResp {
		return r, fmt.Errorf("mtkft: RRB subtype %d is not a pull response", f.Subtype)
	}
	var err error
	if r.Nonce, r.Seq, r.R0KHID, r.R1KHID, err = authHead(f, "pull response"); err != nil {
		return r, err
	}
	s, ok := find(f.Enc, TLVS1KHID)
	if !ok || len(s) != 6 {
		return r, errors.New("mtkft: pull response without S1KH_ID")
	}
	copy(r.S1KHID[:], s)
	k, ok := find(f.Enc, TLVPMKR1)
	if !ok {
		return r, nil // no PMK-R0 at the R0KH
	}
	n, ok1 := find(f.Enc, TLVPMKR1Name)
	pw, ok2 := find(f.Enc, TLVPairwise)
	if len(k) != 32 || !ok1 || len(n) != 16 || !ok2 || len(pw) != 2 {
		return r, errors.New("mtkft: pull response with a malformed PMK-R1")
	}
	r.Found = true
	copy(r.PMKR1[:], k)
	copy(r.PMKR1Name[:], n)
	r.Pairwise = binary.LittleEndian.Uint16(pw)
	if v, ok := find(f.Enc, TLVExpiresIn); ok && len(v) == 2 {
		r.ExpiresIn = binary.LittleEndian.Uint16(v)
	}
	if v, ok := find(f.Enc, TLVSessionTimeout); ok && len(v) == 4 {
		r.SessionTimeout = binary.LittleEndian.Uint32(v)
	}
	return r, nil
}

// R0KHIDOf returns the R0KH-ID and R1KH-ID of a split frame's auth TLVs
// (how a receiver picks the peer and key before Open).
func (f Frame) R0KHIDOf() (r0 []byte, r1 MAC, ok bool) {
	r0v, ok1 := find(f.Auth, TLVR0KHID)
	r1v, ok2 := find(f.Auth, TLVR1KHID)
	if !ok1 || !ok2 || len(r1v) != 6 || len(r0v) == 0 || len(r0v) > MaxR0KHIDLen {
		return nil, MAC{}, false
	}
	copy(r1[:], r1v)
	return r0v, r1, true
}
