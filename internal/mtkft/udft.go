// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The rebuilt MT7603 module's agent interface for 802.11r key holders
// (mt7603roam, drv2g ft_udft.c; docs/deco/features/garage-ft.md "2.4 GHz").
// Unlike the MT7663 it derives FT-PSK itself (FT_UDFT_R1Miss) and has no
// KDP frames: the agent reads events and installs or derives PMK-R1s with
// three OIDs on SIOCIWFIRSTPRIV+1.

// OIDs.
const (
	OIDUDFTR1Set  = 0x0960 // set (flags 0x8960): one UDFTR1 in
	OIDUDFTEvents = 0x0961 // query: whole UDFTEvent records out; also the IWEVCUSTOM flags of each event
	OIDUDFTR1Get  = 0x0962 // query: a UDFTR1Request in, a UDFTR1 out (the same buffer)
)

// Sizes and values (ft.h).
const (
	UDFTVersion  = 1
	UDFTR1Len    = 140
	UDFTReqLen   = 32
	UDFTEventLen = 104
	UDFTRing     = 32 // UDFT_EVENT_RING: the driver keeps this many events

	UDFTR0Created = 1 // an FT-SAE (or FT-802.1X) initial association here: the R0 is cached
	UDFTR1Miss    = 2 // an FT authentication with an unknown PMKR1Name: pull it
)

// UDFTR1 is UDFT_R1: one PMK-R1 SA for R1_SET (R1KHID one of this
// radio's FT BSSIDs) or from R1_GET (R1KHID the peer's).
type UDFTR1 struct {
	NameGiven bool // flags bit 0: the driver checks PMKR1Name against its own derivation
	STA       MAC
	R1KHID    MAC
	R0KHID    []byte // 1..48
	PMKR0Name [16]byte
	PMKR1Name [16]byte
	PMKR1     [32]byte
	AKM       Suite  // zero: FT-SAE
	Pairwise  Suite  // zero: CCMP
	Lifetime  uint32 // seconds; SET 0: the BSS's PMKCachePeriod; GET: remaining
}

// MarshalBinary is the 140-byte record.
func (r UDFTR1) MarshalBinary() ([]byte, error) {
	if len(r.R0KHID) == 0 || len(r.R0KHID) > MaxR0KHIDLen {
		return nil, errors.New("mtkft: UDFT R0KH-ID must be 1-48 octets")
	}
	b := make([]byte, UDFTR1Len)
	b[0], b[1] = UDFTVersion, byte(len(r.R0KHID))
	if r.NameGiven {
		b[2] = 1
	}
	copy(b[4:], r.STA[:])
	copy(b[10:], r.R1KHID[:])
	copy(b[16:64], r.R0KHID)
	copy(b[64:], r.PMKR0Name[:])
	copy(b[80:], r.PMKR1Name[:])
	copy(b[96:], r.PMKR1[:])
	copy(b[128:], r.AKM[:])
	copy(b[132:], r.Pairwise[:])
	binary.LittleEndian.PutUint32(b[136:], r.Lifetime)
	return b, nil
}

// UnmarshalBinary reads an R1_GET answer.
func (r *UDFTR1) UnmarshalBinary(b []byte) error {
	if len(b) < UDFTR1Len || b[0] != UDFTVersion || b[1] == 0 || b[1] > MaxR0KHIDLen {
		return errors.New("mtkft: not a UDFT R1 record")
	}
	*r = UDFTR1{NameGiven: b[2]&1 != 0, R0KHID: append([]byte(nil), b[16:16+b[1]]...)}
	copy(r.STA[:], b[4:])
	copy(r.R1KHID[:], b[10:])
	copy(r.PMKR0Name[:], b[64:])
	copy(r.PMKR1Name[:], b[80:])
	copy(r.PMKR1[:], b[96:])
	copy(r.AKM[:], b[128:])
	copy(r.Pairwise[:], b[132:])
	r.Lifetime = binary.LittleEndian.Uint32(b[136:])
	return nil
}

// UDFTR1Request is the R1_GET buffer: a UDFT_R1_REQ in the first 32 bytes
// of a UDFTR1Len buffer (the driver wants room for its answer). The
// driver derives the PMK-R1 for r1kh from the PMK-R0 it cached for sta
// under r0name (ENOENT: none).
func UDFTR1Request(sta, r1kh MAC, r0name [16]byte) []byte {
	b := make([]byte, UDFTR1Len)
	b[0] = UDFTVersion
	copy(b[4:], sta[:])
	copy(b[10:], r1kh[:])
	copy(b[16:], r0name[:])
	return b
}

// UDFTEvent is UDFT_EVENT.
type UDFTEvent struct {
	Type      byte
	APIdx     byte
	STA       MAC
	BSSID     MAC    // this BSS (the R1KH-ID of a miss)
	R0KHID    []byte // R0_CREATED: this BSS's; R1_MISS: the station's R0KH
	PMKR0Name [16]byte
	PMKR1Name [16]byte // R0_CREATED: this BSS's own R1; R1_MISS: the wanted one
	AKM       Suite
	Seq       uint32
}

// ParseUDFTEvent reads one record (an IWEVCUSTOM's data or an EVENT_GET
// slot).
func ParseUDFTEvent(b []byte) (UDFTEvent, error) {
	var e UDFTEvent
	if len(b) < UDFTEventLen || b[0] != UDFTVersion || b[2] > MaxR0KHIDLen {
		return e, errors.New("mtkft: not a UDFT event")
	}
	if b[1] != UDFTR0Created && b[1] != UDFTR1Miss {
		return e, fmt.Errorf("mtkft: UDFT event type %d", b[1])
	}
	e.Type, e.APIdx = b[1], b[3]
	copy(e.STA[:], b[4:])
	copy(e.BSSID[:], b[10:])
	e.R0KHID = append([]byte(nil), b[16:16+b[2]]...)
	copy(e.PMKR0Name[:], b[64:])
	copy(e.PMKR1Name[:], b[80:])
	copy(e.AKM[:], b[96:])
	e.Seq = binary.LittleEndian.Uint32(b[100:])
	return e, nil
}

// ParseUDFTEvents reads an EVENT_GET answer of n bytes.
func ParseUDFTEvents(b []byte) ([]UDFTEvent, error) {
	if len(b)%UDFTEventLen != 0 {
		return nil, fmt.Errorf("mtkft: UDFT events of %d bytes", len(b))
	}
	var out []UDFTEvent
	for ; len(b) > 0; b = b[UDFTEventLen:] {
		e, err := ParseUDFTEvent(b[:UDFTEventLen])
		if err != nil {
			return out, err
		}
		out = append(out, e)
	}
	return out, nil
}
