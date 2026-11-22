// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// The 802.11r key hierarchy (IEEE 802.11-2016 12.7.1.7), SHA-256 only:
// the MT7663 driver has no SHA-384 path for FT (FT_R1HK_ENTRY.PmkR1Key is
// 32 bytes; FT_DerivePMKR0 at 0x8053a4d8 in the Garage kernel takes a 32-byte
// XXKey), and hostapd 2.9 uses SHA-256 for FT-PSK and FT-SAE (AKM 4 and 9).
// Each function is hostapd's src/common/wpa_common.c of that name.

// MAC is a station or BSS address (R1KH-ID, S0KH-ID, S1KH-ID).
type MAC [6]byte

// ParseMAC reads aa:bb:cc:dd:ee:ff (or with dashes).
func ParseMAC(s string) (MAC, error) {
	var m MAC
	h := strings.NewReplacer(":", "", "-", "").Replace(s)
	if len(h) != 12 {
		return m, fmt.Errorf("mtkft: bad MAC %q", s)
	}
	if _, err := hex.Decode(m[:], []byte(h)); err != nil {
		return m, fmt.Errorf("mtkft: bad MAC %q", s)
	}
	return m, nil
}

func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// Hex is the MAC as 12 lower-case hex digits (a Deco's R0KH-ID, its
// nas_identifier).
func (m MAC) Hex() string { return hex.EncodeToString(m[:]) }

// MDID is a mobility domain as its two on-air MDIE octets, in hostapd's
// mobility_domain notation: 0xd530 is "d530" and the octets d5 30.
type MDID uint16

func (d MDID) octets() [2]byte { return [2]byte{byte(d >> 8), byte(d)} }

// KDF is the IEEE 802.11 KDF-Hash-Length with SHA-256 (12.7.1.7.2):
// HMAC-SHA256(key, i || label || context || bits), i and bits 16-bit
// little-endian, i from 1, output truncated to bits (a multiple of 8).
func KDF(key []byte, label string, context []byte, bits int) []byte {
	n := bits / 8
	out := make([]byte, 0, n+sha256.Size)
	var le [2]byte
	for i := 1; len(out) < n; i++ {
		m := hmac.New(sha256.New, key)
		binary.LittleEndian.PutUint16(le[:], uint16(i))
		m.Write(le[:])
		m.Write([]byte(label))
		m.Write(context)
		binary.LittleEndian.PutUint16(le[:], uint16(bits))
		m.Write(le[:])
		out = m.Sum(out)
	}
	return out[:n]
}

// MaxR0KHIDLen is FT_R0KH_ID_MAX_LEN (hostapd) and FT_ROKH_ID_LEN (MTK).
const MaxR0KHIDLen = 48

// PMKR0 is a PMK-R0 security association as the R0KH holds it.
type PMKR0 struct {
	Key  [32]byte
	Name [16]byte // PMKR0Name
}

// DerivePMKR0 is wpa_derive_pmk_r0 (SHA-256): R0-Key-Data =
// KDF-384(XXKey, "FT-R0", SSIDlength || SSID || MDID || R0KHlength ||
// R0KH-ID || S0KH-ID); PMK-R0 is its first 256 bits, PMKR0Name =
// Truncate-128(SHA-256("FT-R0N" || the last 128 bits)). XXKey is the PSK
// (FT-PSK) or the SAE PMK (FT-SAE), 32 bytes.
func DerivePMKR0(xxkey, ssid []byte, md MDID, r0khID []byte, s0kh MAC) (PMKR0, error) {
	var r PMKR0
	if len(xxkey) != 32 {
		return r, errors.New("mtkft: XXKey must be 32 bytes")
	}
	if len(ssid) == 0 || len(ssid) > 32 {
		return r, errors.New("mtkft: SSID must be 1-32 bytes")
	}
	if len(r0khID) == 0 || len(r0khID) > MaxR0KHIDLen {
		return r, fmt.Errorf("mtkft: R0KH-ID must be 1-%d bytes", MaxR0KHIDLen)
	}
	o := md.octets()
	ctx := make([]byte, 0, 1+len(ssid)+2+1+len(r0khID)+6)
	ctx = append(ctx, byte(len(ssid)))
	ctx = append(ctx, ssid...)
	ctx = append(ctx, o[:]...)
	ctx = append(ctx, byte(len(r0khID)))
	ctx = append(ctx, r0khID...)
	ctx = append(ctx, s0kh[:]...)
	data := KDF(xxkey, "FT-R0", ctx, 384)
	copy(r.Key[:], data[:32])
	h := sha256.New()
	h.Write([]byte("FT-R0N"))
	h.Write(data[32:48])
	copy(r.Name[:], h.Sum(nil))
	clear(data)
	return r, nil
}

// PMKR1 is a PMK-R1 security association as an R1KH holds it.
type PMKR1 struct {
	Key  [32]byte
	Name [16]byte // PMKR1Name
}

// PMKR1Name is wpa_derive_pmk_r1_name: Truncate-128(SHA-256("FT-R1N" ||
// PMKR0Name || R1KH-ID || S1KH-ID)). The MT7663 computes it for every FT
// authentication and looks the result up in its R1KH table
// (FT_AuthReqRsnValidation).
func PMKR1Name(pmkR0Name [16]byte, r1kh, s1kh MAC) [16]byte {
	h := sha256.New()
	h.Write([]byte("FT-R1N"))
	h.Write(pmkR0Name[:])
	h.Write(r1kh[:])
	h.Write(s1kh[:])
	var n [16]byte
	copy(n[:], h.Sum(nil))
	return n
}

// DerivePMKR1 is wpa_derive_pmk_r1: PMK-R1 = KDF-256(PMK-R0, "FT-R1",
// R1KH-ID || S1KH-ID), with its PMKR1Name.
func DerivePMKR1(r0 PMKR0, r1kh, s1kh MAC) PMKR1 {
	var r PMKR1
	ctx := append(append([]byte(nil), r1kh[:]...), s1kh[:]...)
	k := KDF(r0.Key[:], "FT-R1", ctx, 256)
	copy(r.Key[:], k)
	clear(k)
	r.Name = PMKR1Name(r0.Name, r1kh, s1kh)
	return r
}

// PSK is the WPA2 pre-shared key of a passphrase (8-63 characters,
// PBKDF2-SHA1, 4096 rounds, salted with the SSID) or of 64 hex digits.
func PSK(passphrase string, ssid []byte) ([32]byte, error) {
	var k [32]byte
	if len(passphrase) == 64 {
		if _, err := hex.Decode(k[:], []byte(passphrase)); err == nil {
			return k, nil
		}
	}
	if len(passphrase) < 8 || len(passphrase) > 63 {
		return k, errors.New("mtkft: passphrase must be 8-63 characters or 64 hex digits")
	}
	b, err := pbkdf2.Key(sha1.New, passphrase, ssid, 4096, 32)
	if err != nil {
		return k, err
	}
	copy(k[:], b)
	clear(b)
	return k, nil
}

// FTPSKR1 is what hostapd's ft_psk_generate_local computes on a target AP
// (wpa_ft_psk_pmk_r1) and what the Garage must hold for a station that
// joined another AP with FT-PSK: the PMK-R0 of (PSK, SSID, MDID, that AP's
// R0KH-ID, station) and the PMK-R1 for this BSS (r1kh = its BSSID).
func FTPSKR1(psk [32]byte, ssid []byte, md MDID, r0khID []byte, sta, r1kh MAC) (PMKR0, PMKR1, error) {
	r0, err := DerivePMKR0(psk[:], ssid, md, r0khID, sta)
	if err != nil {
		return PMKR0{}, PMKR1{}, err
	}
	return r0, DerivePMKR1(r0, r1kh, sta), nil
}

// hmacSHA256KDF is hostapd's hmac_sha256_kdf (RFC 5869 expand with the
// label's NUL included): T(i) = HMAC(secret, T(i-1) || label || NUL ||
// seed || i), i a single octet from 1.
func hmacSHA256KDF(secret []byte, label string, seed []byte, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	var t []byte
	for i := 1; len(out) < n; i++ {
		m := hmac.New(sha256.New, secret)
		m.Write(t)
		m.Write([]byte(label))
		m.Write([]byte{0})
		m.Write(seed)
		m.Write([]byte{byte(i)})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

// RRBKey is the 256-bit AES-SIV key hostapd 2.9 uses for an r0kh/r1kh
// line's key (hostapd/config_file.c rkh_derive_key): 64 hex digits as they
// are; 32 hex digits (the controller's iapp_key) stretched with
// hmac_sha256_kdf(key, "FT OLDKEY"). Decos (bcmwifi) write the iapp_key into
// those lines, so this is the key their RRB frames are sealed with.
func RRBKey(iappKey string) ([32]byte, error) {
	var k [32]byte
	b, err := hex.DecodeString(iappKey)
	switch {
	case err != nil:
		return k, errors.New("mtkft: the RRB key must be hex")
	case len(b) == 32:
		copy(k[:], b)
	case len(b) == 16:
		copy(k[:], hmacSHA256KDF(b, "FT OLDKEY", nil, 32))
	default:
		return k, errors.New("mtkft: the RRB key must be 32 or 64 hex digits")
	}
	clear(b)
	return k, nil
}
