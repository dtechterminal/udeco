// SPDX-License-Identifier: GPL-2.0-or-later

// Package ftpeer lets the agents of one site learn each other's 802.11r key
// holders, so each unit's hostapd can list the others explicitly for FT-SAE.
//
// Why (docs/deco/features/ft-sae.md): FT-SAE moves the PMK-R1 between APs
// over RRB (ethertype 0x88b7 on the BSS's bridge), encrypted with a key the
// APs share, the controller's per-WLAN iapp_key. A UniFi AP lists every
// other AP as a wildcard (r0kh=ff:ff:ff:ff:ff:ff * <key>), which hostapd
// 2.9, the Deco's, cannot use as the target AP: it hands the broadcast PULL
// to another BSS of its own process and never sends it. Explicit entries,
// r0kh=<peer BSSID> <peer R0KH-ID> <key> and r1kh=<peer BSSID> <peer R1KH-ID>
// <key>, make the PULL and the PMK-R1 push unicast, which 2.9 does send.
// That needs every unit to know the others' BSSIDs and key holder ids.
//
// How: each agent announces, on each bridge that carries one of its FT-SAE
// BSSes, one frame per WLAN key: its unit MAC, the key holders of that WLAN
// on that bridge (band, BSSID, R0KH-ID, R1KH-ID, mobility domain), and an
// HMAC under a key derived from the WLAN's iapp_key. The key itself is
// never on the wire; a frame says which key it is under by a key id, also
// derived from the key (HMAC, so it tells nothing about the key). A
// receiver accepts a frame only for a key it serves on the bridge it heard
// it on (the bridge its own RRB uses), with a valid HMAC, from another unit,
// newer than the last frame of that unit under that key (epoch, sequence),
// and within per-source and global rate limits. Peers expire when their
// announcements stop.
//
// Transport: raw Ethernet frames, EtherType 0x88b5 (IEEE 802 local
// experimental) to the locally administered group 03:75:64:66:74:31, sent
// and received on the bridge itself, the same L2 path RRB takes (a VLAN
// SSID's bridge br-vN is the VLAN). No IP, so the egress and inbound
// firewalls (iptables) neither help nor hinder.
package ftpeer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// EtherType is the announcements' EtherType: IEEE 802 Local Experimental
// EtherType 1.
const EtherType = 0x88b5

// GroupMAC is the announcements' destination: a locally administered
// multicast address (bridges flood it; no IGMP snooping applies to non-IP).
var GroupMAC = net.HardwareAddr{0x03, 0x75, 0x64, 0x66, 0x74, 0x31}

// Defaults.
const (
	DefaultInterval = 20 * time.Second
	// MaxHolders bounds the holders of one announcement (one WLAN on one
	// bridge of one unit: two radios, so two in practice).
	MaxHolders = 16
	// MaxR0KHIDLen is hostapd's FT_R0KH_ID_MAX_LEN.
	MaxR0KHIDLen = 48
)

// Holder is one BSS's FT key holder identity, as announced.
type Holder struct {
	Band   string // "ng" or "na"
	BSSID  string // lower-case aa:bb:cc:dd:ee:ff
	R0KHID string // nas_identifier: 1..48 of [0-9A-Za-z._:-]
	R1KHID string // r1_key_holder as a MAC, lower-case
	MDID   uint16 // mobility domain
}

func (h Holder) String() string {
	return fmt.Sprintf("%s %s r0kh-id %s r1kh-id %s mdid %04x", h.Band, h.BSSID, h.R0KHID, h.R1KHID, h.MDID)
}

// Local is one of this unit's FT-SAE BSSes.
type Local struct {
	Holder
	Bridge string // where its RRB runs (br-lan, br-vN)
	// Key is the WLAN's FT key (the controller's iapp_key). Secret: never
	// logged, never sent; String and %v leave it out.
	Key string
}

// String leaves the key out (fmt uses it for %v and %+v).
func (l Local) String() string { return l.Bridge + " " + l.Holder.String() }

// GoString leaves the key out (%#v).
func (l Local) GoString() string { return "ftpeer.Local{" + l.String() + "}" }

// Peer is another unit's key holder, learnt from an authenticated
// announcement.
type Peer struct {
	Holder
	KeyID  string    // which WLAN key (KeyID of it)
	Unit   string    // the announcing unit's MAC
	Bridge string    // the local bridge it was heard on
	Seen   time.Time // last announcement
}

// derivations counts derive calls (tests: no cryptography before the
// rate limits).
var derivations atomic.Uint64

// derive is HMAC-SHA256(key, label). The key is the controller's hex
// string, lower-cased, so every unit derives the same values.
func derive(key, label string) []byte {
	derivations.Add(1)
	m := hmac.New(sha256.New, []byte(strings.ToLower(strings.TrimSpace(key))))
	m.Write([]byte(label))
	return m.Sum(nil)
}

// KeyID names a WLAN key without revealing it: 16 hex digits of
// HMAC-SHA256(key, "udeco ft-sae key id v1").
func KeyID(key string) string { return hex.EncodeToString(derive(key, "udeco ft-sae key id v1")[:8]) }

// macKey is the announcements' HMAC key for a WLAN key.
func macKey(key string) []byte { return derive(key, "udeco ft-sae announce v1") }

// NormMAC returns mac lower-case with colons, or "" when it is not a
// unicast, non-zero 48-bit MAC.
func NormMAC(mac string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) != 6 || hw[0]&1 != 0 {
		return ""
	}
	zero := true
	for _, b := range hw {
		if b != 0 {
			zero = false
		}
	}
	if zero {
		return ""
	}
	return hw.String()
}

// ValidR0KHID reports an R0KH-ID hostapd's conf parser and SET take as one
// field: 1..48 characters, no space or control character (the line is
// space separated), restricted to what nas_identifier needs.
func ValidR0KHID(id string) bool {
	if id == "" || len(id) > MaxR0KHIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '.', c == '_', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}

// Valid checks h as a receiver must before writing it into a hostapd conf.
func (h Holder) Valid() error {
	if h.Band != "ng" && h.Band != "na" {
		return fmt.Errorf("band %q", h.Band)
	}
	if NormMAC(h.BSSID) == "" {
		return fmt.Errorf("BSSID %q", h.BSSID)
	}
	if NormMAC(h.R1KHID) == "" {
		return fmt.Errorf("R1KH-ID %q", h.R1KHID)
	}
	if !ValidR0KHID(h.R0KHID) {
		return fmt.Errorf("R0KH-ID %q", h.R0KHID)
	}
	return nil
}

// sortHolders orders holders by BSSID (then band) for stable output.
func sortHolders(hs []Holder) {
	sort.Slice(hs, func(i, j int) bool {
		if hs[i].BSSID != hs[j].BSSID {
			return hs[i].BSSID < hs[j].BSSID
		}
		return hs[i].Band < hs[j].Band
	})
}
