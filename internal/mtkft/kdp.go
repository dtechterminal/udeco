// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// The MT7663 driver's key distribution protocol (KDP) with its IAPP
// daemon, the part iappd would do: the Garage's /usr/bin/iappd is a
// symlink to tf1Main, which has no IAPP applet ("functionality is
// unavailable"), so the agent takes its place. Built with
// FT_KDP_FUNC_SOCK_COMM (padavan mt7615 embedded/ap/ap_ftkd.c, checked
// against the Garage kernel's FT_KDP_EventInform at 0x80541d14):
//
//   - driver -> daemon: FT_KDP_EventInform puts a fake Ethernet frame up the
//     stack on the BSS's interface (announce_802_3_packet): destination the
//     BSSID, source 00:00:00:00:00:01, EtherType 0xEEEE, then the 0x1c-byte
//     signal header, the 8-byte event header and the event body.
//   - daemon -> driver: SIOCIWFIRSTPRIV+1 (0x8BE1) with flags OID | 0x8000
//     (RTMPAPSetInformation, cmd & 0x7fff); the buffer is PeerIP (4) ||
//     nonce (8) || body for the key messages.
//
// Every multi-byte field is little-endian (the unit is MIPS32 LE).

// EtherTypeKDP is the EtherType of the driver's KDP signals.
const EtherTypeKDP = 0xEEEE

// kdpSource is the Ethernet source of every KDP signal.
var kdpSource = MAC{0, 0, 0, 0, 0, 1}

// Signals (FT_KDP_SIG_*), the Sig octet of a KDP frame.
const (
	SigFTAssoc      = 0x50 // FT initial mobility domain association done (4-way msg 4): body {u16 seq, STA}
	SigFTReassoc    = 0x51 // FT reassociation: body {u16 seq, STA, old AP}
	SigKeyTimeout   = 0x52 // an FT-802.1X R1KH entry aged out: body STA
	SigKeyReq       = 0x53
	SigAction       = 0x54 // over-the-DS FT action frame for another AP (RRB)
	SigKeyReqAuto   = 0xA0 // R1KH table miss on an FT authentication: body KeyElement (R0KH-ID not filled)
	SigKeyRspAuto   = 0xA1 // answer to OIDKeyReq: body KeyElement with the PMK-R1
	SigInfoBcast    = 0xB0
	SigDebugTrace   = 0xC0
	sigHeaderLen    = 0x1c // RT_SIGNAL_STRUC up to Content
	evtHeaderLen    = 8    // FT_KDP_EVT_HEADER {EventLen, PeerIpAddr}
	maxSignalLength = 1024 // Content[1024]
)

// Set OIDs of the KDP (oid.h RT_SET_FT_*), sent with OIDSet.
const (
	OIDStationNotify = 0x0408
	OIDKeyReq        = 0x0409 // FT_KDP_KeyRequestToUs (0x80542330)
	OIDKeyRsp        = 0x040a // FT_KDP_KeyResponseToUs (0x805431d4)
	OIDKeySet        = 0x040b // the over-the-DS encryption key: not used
	OIDActionForward = 0x0411
	// OIDSet is OID_GET_SET_TOGGLE: the OID goes to RTMPAPSetInformation.
	OIDSet = 0x8000
)

// Request is one private ioctl: SIOCIWFIRSTPRIV+1 on the BSS's interface
// with iw_point flags Flags and the buffer Buf (mtkwifi's privIO.OID).
type Request struct {
	Flags uint16
	Buf   []byte
}

// Signal is one KDP frame from the driver.
type Signal struct {
	BSSID  MAC    // the Ethernet destination: the BSS that raised it
	Seq    uint16 // Sequence (for SigAction: the request type)
	STA    MAC    // MacAddr (for SigAction: the frame's destination)
	CurrAP MAC    // CurrAPAddr (for SigAction: the target AP)
	Sig    uint8
	SA     MAC    // MacAddrSa (for SigAction: the frame's source)
	PeerIP uint32 // the event header's PeerIpAddr (OIDKeyReq's tag, echoed in SigKeyRspAuto)
	Body   []byte // EventLen bytes
}

var errNotKDP = errors.New("mtkft: not a KDP signal")

// ParseSignal reads a KDP frame as a packet socket on the interface sees
// it (Ethernet header included).
func ParseSignal(frame []byte) (Signal, error) {
	var s Signal
	if len(frame) < 14+sigHeaderLen+evtHeaderLen || binary.BigEndian.Uint16(frame[12:]) != EtherTypeKDP {
		return s, errNotKDP
	}
	if !bytes.Equal(frame[6:12], kdpSource[:]) {
		return s, errNotKDP
	}
	copy(s.BSSID[:], frame[0:6])
	p := frame[14:]
	s.Seq = binary.LittleEndian.Uint16(p[4:])
	copy(s.STA[:], p[6:12])
	copy(s.CurrAP[:], p[0xc:0x12])
	s.Sig = p[0x12]
	copy(s.SA[:], p[0x13:0x19])
	n := binary.LittleEndian.Uint32(p[0x1c:])
	s.PeerIP = binary.LittleEndian.Uint32(p[0x20:])
	body := p[sigHeaderLen+evtHeaderLen:]
	if n > maxSignalLength || int(n) > len(body) {
		return s, fmt.Errorf("mtkft: KDP signal %#x: event length %d, %d bytes left", s.Sig, n, len(body))
	}
	s.Body = body[:n]
	return s, nil
}

// AssocEvent is the body of SigFTAssoc and SigFTReassoc
// (FT_KDP_EVT_ASSOC / FT_KDP_EVT_REASSOC).
type AssocEvent struct {
	Seq   uint16
	STA   MAC
	OldAP MAC // SigFTReassoc only
}

// ParseAssoc reads s's body for SigFTAssoc or SigFTReassoc.
func (s Signal) ParseAssoc() (AssocEvent, error) {
	var e AssocEvent
	want := 8
	if s.Sig == SigFTReassoc {
		want = 14
	} else if s.Sig != SigFTAssoc {
		return e, fmt.Errorf("mtkft: signal %#x is not an association", s.Sig)
	}
	if len(s.Body) < want {
		return e, fmt.Errorf("mtkft: association signal of %d bytes", len(s.Body))
	}
	e.Seq = binary.LittleEndian.Uint16(s.Body)
	copy(e.STA[:], s.Body[2:8])
	if want == 14 {
		copy(e.OldAP[:], s.Body[8:14])
	}
	return e, nil
}

// Suite is an RSN suite selector (OUI and type), as the driver keeps a
// pairwise cipher and an AKM in its R1KH entries and KDP elements.
type Suite [4]byte

// Suites the Garage serves.
var (
	CipherCCMP = Suite{0x00, 0x0f, 0xac, 0x04}
	CipherTKIP = Suite{0x00, 0x0f, 0xac, 0x02}
	CipherGCMP = Suite{0x00, 0x0f, 0xac, 0x08}
	AKMFT8021X = Suite{0x00, 0x0f, 0xac, 0x03}
	AKMFTPSK   = Suite{0x00, 0x0f, 0xac, 0x04}
	AKMFTSAE   = Suite{0x00, 0x0f, 0xac, 0x09}
)

// hostapd's WPA_CIPHER_* bits (src/common/defs.h), the RRB PAIRWISE TLV.
var hostapdCiphers = map[uint16]Suite{
	1 << 3: CipherTKIP,
	1 << 4: CipherCCMP,
	1 << 6: CipherGCMP,
	1 << 8: {0x00, 0x0f, 0xac, 0x09}, // GCMP-256
	1 << 9: {0x00, 0x0f, 0xac, 0x0a}, // CCMP-256
}

// CipherFromHostapd is the suite of one hostapd WPA_CIPHER_* bit.
func CipherFromHostapd(bits uint16) (Suite, error) {
	s, ok := hostapdCiphers[bits]
	if !ok {
		return Suite{}, fmt.Errorf("mtkft: hostapd pairwise cipher %#x has no suite", bits)
	}
	return s, nil
}

// HostapdCipher is the hostapd WPA_CIPHER_* bit of a pairwise suite.
func HostapdCipher(s Suite) (uint16, error) {
	for b, v := range hostapdCiphers {
		if v == s {
			return b, nil
		}
	}
	return 0, fmt.Errorf("mtkft: pairwise suite % x has no hostapd cipher", s[:])
}

// KeyElementLen is sizeof(FT_KDP_EVT_KEY_ELM): the element of OIDKeyReq,
// OIDKeyRsp, SigKeyReqAuto and SigKeyRspAuto.
const KeyElementLen = 0xa7

const (
	keyElmID  = 0xffff
	keyElmLen = KeyElementLen - 4
)

var ralinkOUI = [3]byte{0x00, 0x0e, 0x2e}

// KeyElement is FT_KDP_EVT_KEY_ELM. Offsets (from the element's start):
// MacAddr 0x07, KeyInfo 0x10 {R0KHID[48] 0x10, R0KHIDLen 0x40, PMKR0Name
// 0x41, R1KHID 0x51, S1KHID 0x57, RSV[4]}, PMKR1Name 0x61, PMKR1 0x71,
// R0KH_MAC 0x91, PairwisChipher 0x97, AkmSuite 0x9b, KeyLifeTime 0x9f,
// ReassocDeadline 0xa3 (FT_KDP_KeyResponseToUs reads them at these offsets
// + 0xc, after PeerIP and the nonce).
type KeyElement struct {
	STA             MAC
	R0KHID          []byte // 1..48 octets
	PMKR0Name       [16]byte
	R1KHID          MAC
	S1KHID          MAC
	PMKR1Name       [16]byte
	PMKR1           [32]byte
	R0KHMAC         MAC
	Pairwise        Suite
	AKM             Suite
	KeyLifeTime     uint32 // seconds
	ReassocDeadline uint32 // time units
}

// MarshalBinary is the element as the driver reads it.
func (e KeyElement) MarshalBinary() ([]byte, error) {
	if len(e.R0KHID) > MaxR0KHIDLen {
		return nil, fmt.Errorf("mtkft: R0KH-ID of %d octets", len(e.R0KHID))
	}
	b := make([]byte, KeyElementLen)
	binary.LittleEndian.PutUint16(b[0:], keyElmID)
	binary.LittleEndian.PutUint16(b[2:], keyElmLen)
	copy(b[4:7], ralinkOUI[:])
	copy(b[0x07:], e.STA[:])
	copy(b[0x10:0x40], e.R0KHID)
	b[0x40] = byte(len(e.R0KHID))
	copy(b[0x41:], e.PMKR0Name[:])
	copy(b[0x51:], e.R1KHID[:])
	copy(b[0x57:], e.S1KHID[:])
	copy(b[0x61:], e.PMKR1Name[:])
	copy(b[0x71:], e.PMKR1[:])
	copy(b[0x91:], e.R0KHMAC[:])
	copy(b[0x97:], e.Pairwise[:])
	copy(b[0x9b:], e.AKM[:])
	binary.LittleEndian.PutUint32(b[0x9f:], e.KeyLifeTime)
	binary.LittleEndian.PutUint32(b[0xa3:], e.ReassocDeadline)
	return b, nil
}

// UnmarshalBinary reads an element from a signal body, checking the
// header the driver checks (ElmId, OUI).
func (e *KeyElement) UnmarshalBinary(b []byte) error {
	if len(b) < KeyElementLen {
		return fmt.Errorf("mtkft: key element of %d bytes", len(b))
	}
	if binary.LittleEndian.Uint16(b) != keyElmID || !bytes.Equal(b[4:7], ralinkOUI[:]) {
		return errors.New("mtkft: not a Ralink key element")
	}
	n := int(b[0x40])
	if n > MaxR0KHIDLen {
		return fmt.Errorf("mtkft: key element R0KH-ID length %d", n)
	}
	*e = KeyElement{R0KHID: append([]byte(nil), b[0x10:0x10+n]...)}
	copy(e.STA[:], b[0x07:])
	copy(e.PMKR0Name[:], b[0x41:])
	copy(e.R1KHID[:], b[0x51:])
	copy(e.S1KHID[:], b[0x57:])
	copy(e.PMKR1Name[:], b[0x61:])
	copy(e.PMKR1[:], b[0x71:])
	copy(e.R0KHMAC[:], b[0x91:])
	copy(e.Pairwise[:], b[0x97:])
	copy(e.AKM[:], b[0x9b:])
	e.KeyLifeTime = binary.LittleEndian.Uint32(b[0x9f:])
	e.ReassocDeadline = binary.LittleEndian.Uint32(b[0xa3:])
	return nil
}

// keyMessage is PeerIP || nonce (8, unused by the driver) || element.
func keyMessage(oid uint16, tag uint32, e KeyElement) (Request, error) {
	el, err := e.MarshalBinary()
	if err != nil {
		return Request{}, err
	}
	buf := make([]byte, 12, 12+len(el))
	binary.LittleEndian.PutUint32(buf, tag)
	return Request{Flags: oid | OIDSet, Buf: append(buf, el...)}, nil
}

// KeyRequest asks the driver, as R0KH, for the PMK-R1 of a station that
// completed an FT initial association on this unit (SigFTAssoc) for the
// R1KH r1kh (a Deco BSSID). The answer is a SigKeyRspAuto with PeerIP ==
// tag. The driver drops the request when tag is 0 or the station is not
// in its MAC table any more; it needs the station's PMK-R0 (PMKID cache,
// PMKCachePeriod) and its own R1KH entry (FT_QueryKeyInfoForKDP).
func KeyRequest(tag uint32, sta, r1kh MAC) (Request, error) {
	if tag == 0 {
		return Request{}, errors.New("mtkft: the driver ignores a key request with PeerIP 0")
	}
	return keyMessage(OIDKeyReq, tag, KeyElement{STA: sta, R1KHID: r1kh, S1KHID: sta})
}

// KeyResponse installs a PMK-R1 SA in the driver's R1KH table
// (FT_R1khEntryInsert after deleting an entry of the same PMKR1Name). The
// station need not be associated: this is how an SA from another AP is
// put in place before the station arrives. R1KHID must be the BSSID of the
// Garage BSS the station will authenticate to, and PMKR1Name the one the
// driver computes from it (PMKR1Name(PMKR0Name, R1KHID, STA)).
func KeyResponse(e KeyElement) (Request, error) {
	if len(e.R0KHID) == 0 {
		return Request{}, errors.New("mtkft: key response without R0KH-ID")
	}
	if PMKR1Name(e.PMKR0Name, e.R1KHID, e.S1KHID) != e.PMKR1Name {
		return Request{}, errors.New("mtkft: PMKR1Name does not match PMKR0Name, R1KH-ID and S1KH-ID")
	}
	return keyMessage(OIDKeyRsp, 1, e)
}

// R1KHTableSize is FT_R1KH_ENTRY_TABLE_SIZE: the driver's R1KH table holds
// this many SAs for all BSSes of the radio, and refuses inserts beyond it.
// An FT-PSK or FT-SAE entry never ages (FT_R1KHInfoMaintenance ages only
// entries whose AKM map has FT-802.1X) and is freed only by an insert of
// the same PMKR1Name or by the radio going down (FT_Release in
// APStopByBss).
const R1KHTableSize = 64
