// SPDX-License-Identifier: GPL-2.0-or-later

package ftpeer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
)

// Announcement is one frame's content: the key holders of one WLAN (one
// key) on one bridge of one unit. It is the complete list: a receiver
// replaces what it had from that unit for that key on that bridge, and an
// empty list withdraws them.
type Announcement struct {
	Unit    string // the sender's unit MAC (its br-lan MAC)
	Epoch   uint64 // the sender's start (unix ns): a restarted sender is newer
	Seq     uint64 // per sender, increases with every frame
	KeyID   string // KeyID of the WLAN key (16 hex)
	Holders []Holder
}

// Payload layout (big endian), after the 14-byte Ethernet header:
//
//	0   "UDFT"
//	4   version (1)
//	5   flags (0)
//	6   unit MAC (6)
//	12  epoch (8)
//	20  seq (8)
//	28  key id (8)
//	36  holder count (1)
//	37  holders: band (1: 2 or 5), mdid (2), BSSID (6), R1KH-ID (6),
//	    R0KH-ID length (1), R0KH-ID
//	... HMAC-SHA256 over everything before it, truncated to 16 bytes
const (
	magic      = "UDFT"
	version    = 1
	headerLen  = 37
	holderMin  = 1 + 2 + 6 + 6 + 1
	macLen     = 16
	ethHdrLen  = 14
	maxPayload = headerLen + MaxHolders*(holderMin+MaxR0KHIDLen) + macLen
)

// Errors from Parse.
var (
	errShort   = errors.New("short frame")
	errMagic   = errors.New("not an announcement")
	errVersion = errors.New("unknown version")
	errHolder  = errors.New("bad holder")
)

func bandByte(b string) byte {
	if b == "ng" {
		return 2
	}
	return 5
}

func byteBand(b byte) string {
	switch b {
	case 2:
		return "ng"
	case 5:
		return "na"
	}
	return ""
}

func mac6(s string) ([]byte, error) {
	m := NormMAC(s)
	if m == "" {
		return nil, fmt.Errorf("MAC %q", s)
	}
	hw, _ := net.ParseMAC(m)
	return hw, nil
}

// Encode returns the payload of a under the WLAN key key (the HMAC key is
// derived from it; key itself is not in the output).
func Encode(a Announcement, key string) ([]byte, error) {
	if len(a.Holders) > MaxHolders {
		return nil, fmt.Errorf("%d holders, at most %d", len(a.Holders), MaxHolders)
	}
	unit, err := mac6(a.Unit)
	if err != nil {
		return nil, fmt.Errorf("unit: %w", err)
	}
	kid, err := hex.DecodeString(a.KeyID)
	if err != nil || len(kid) != 8 {
		return nil, fmt.Errorf("key id %q", a.KeyID)
	}
	var b bytes.Buffer
	b.WriteString(magic)
	b.WriteByte(version)
	b.WriteByte(0)
	b.Write(unit)
	_ = binary.Write(&b, binary.BigEndian, a.Epoch)
	_ = binary.Write(&b, binary.BigEndian, a.Seq)
	b.Write(kid)
	b.WriteByte(byte(len(a.Holders)))
	for _, h := range a.Holders {
		if err := h.Valid(); err != nil {
			return nil, fmt.Errorf("holder: %w", err)
		}
		bssid, _ := mac6(h.BSSID)
		r1, _ := mac6(h.R1KHID)
		b.WriteByte(bandByte(h.Band))
		_ = binary.Write(&b, binary.BigEndian, h.MDID)
		b.Write(bssid)
		b.Write(r1)
		b.WriteByte(byte(len(h.R0KHID)))
		b.WriteString(h.R0KHID)
	}
	m := hmac.New(sha256.New, macKey(key))
	m.Write(b.Bytes())
	b.Write(m.Sum(nil)[:macLen])
	return b.Bytes(), nil
}

// Parse decodes a payload without checking its HMAC (Verify does, once
// the key id has named the key). Every field is bounds-checked and every
// holder validated, so an unauthenticated frame cannot make it misbehave.
func Parse(p []byte) (Announcement, error) {
	var a Announcement
	if len(p) < headerLen+macLen || len(p) > maxPayload {
		return a, errShort
	}
	if string(p[:4]) != magic {
		return a, errMagic
	}
	if p[4] != version {
		return a, errVersion
	}
	a.Unit = net.HardwareAddr(p[6:12]).String()
	a.Epoch = binary.BigEndian.Uint64(p[12:20])
	a.Seq = binary.BigEndian.Uint64(p[20:28])
	a.KeyID = hex.EncodeToString(p[28:36])
	n := int(p[36])
	if n > MaxHolders {
		return a, errHolder
	}
	body := p[:len(p)-macLen]
	off := headerLen
	for i := 0; i < n; i++ {
		if off+holderMin > len(body) {
			return a, errShort
		}
		h := Holder{Band: byteBand(body[off]), MDID: binary.BigEndian.Uint16(body[off+1 : off+3]),
			BSSID: net.HardwareAddr(body[off+3 : off+9]).String(), R1KHID: net.HardwareAddr(body[off+9 : off+15]).String()}
		l := int(body[off+15])
		off += holderMin
		if off+l > len(body) {
			return a, errShort
		}
		h.R0KHID = string(body[off : off+l])
		off += l
		if h.Valid() != nil {
			return a, errHolder
		}
		a.Holders = append(a.Holders, h)
	}
	if off != len(body) {
		return a, errShort
	}
	if NormMAC(a.Unit) == "" {
		return a, errHolder
	}
	return a, nil
}

// Verify reports whether p's HMAC is right for the WLAN key key (constant
// time).
func Verify(p []byte, key string) bool {
	if len(p) < headerLen+macLen {
		return false
	}
	body, sum := p[:len(p)-macLen], p[len(p)-macLen:]
	m := hmac.New(sha256.New, macKey(key))
	m.Write(body)
	return hmac.Equal(m.Sum(nil)[:macLen], sum)
}

// Frame wraps a payload in an Ethernet header from src to GroupMAC.
func Frame(src net.HardwareAddr, payload []byte) []byte {
	f := make([]byte, 0, ethHdrLen+len(payload))
	f = append(f, GroupMAC...)
	f = append(f, src[:6]...)
	f = append(f, EtherType>>8, EtherType&0xff)
	return append(f, payload...)
}

// unframe returns the Ethernet source and the payload of a frame to
// GroupMAC with our EtherType.
func unframe(f []byte) (src string, payload []byte, ok bool) {
	if len(f) < ethHdrLen || !bytes.Equal(f[:6], GroupMAC) || f[12] != EtherType>>8 || f[13] != EtherType&0xff {
		return "", nil, false
	}
	return net.HardwareAddr(f[6:12]).String(), f[ethHdrLen:], true
}
