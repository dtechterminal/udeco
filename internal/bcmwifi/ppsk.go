// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"fmt"
	"path"
	"strings"
)

// Private pre-shared keys (PPSK), docs/deco/features/ppsk.md.
//
// hostapd 2.9 on the X20 reads a wpa_psk_file (binary strings: wpa_psk_file,
// keyid, vlanid, "PSK keyid too long"): one key per line,
//
//	[keyid=<id> ]<station MAC, 00:00:00:00:00:00 = any> <passphrase or 64 hex>
//
// and tries every key that matches the station in the 4-way handshake, which
// hostapd (not the Broadcom firmware) runs here ("WPA: pairwise key
// handshake completed" in its log). The file is read when hostapd starts, so
// a key change restarts the radio's hostapd (the conf reconcile treats it like
// the conf).
//
// Per-key VLANs are not possible: this hostapd has no dynamic_vlan,
// vlan_file or vlan_naming keys at all (0 occurrences in /sbin/hostapd), so
// its VLAN list stays empty and a station whose key carries a vlanid would be
// refused ("Invalid VLAN"). A key is therefore served only when its VLAN is
// the SSID's own VLAN, and written without vlanid; a key for another VLAN is
// dropped (its stations cannot join) instead of putting them on the wrong
// network.

// PSK is one private pre-shared key (translate.PSK). Passphrase is a secret:
// it is written only to the 0600 key file and to last-good.secrets.json.
type PSK struct {
	Passphrase string // 8..63 printable ASCII or 64 hex
	VLAN       int    // 0 = untagged; must equal the SSID's VLAN to be served
	MAC        string // only this station; "" = any
	KeyID      string // hostapd keyid; "" = none
}

// String describes p with the passphrase masked.
func (p PSK) String() string {
	return fmt.Sprintf("psk=%s vlan=%d mac=%q keyid=%q", maskSecret(p.Passphrase), p.VLAN, p.MAC, p.KeyID)
}

// GoString keeps %#v from printing the passphrase.
func (p PSK) GoString() string { return "bcmwifi.PSK{" + p.String() + "}" }

// pskPath is a vif's hostapd wpa_psk_file in RunDir.
func pskPath(runDir, vif string) string { return path.Join(runDir, vif+".psk") }

// normalizePSKs validates s.PSKs (s.Security already normalized) and keeps
// the keys hostapd can serve on this SSID. Notes never contain a
// passphrase. The SSID itself is judged by normalizeSSID: a WPA2 SSID with no
// passphrase of its own needs at least one key left.
func normalizePSKs(s SSID, notes []string) (SSID, []string) {
	if len(s.PSKs) == 0 {
		return s, notes
	}
	in := s.PSKs
	s.PSKs = nil
	switch s.Security {
	case SecWPA2:
	case SecWPA2WPA3:
		notes = append(notes, fmt.Sprintf("ssid %s: private pre-shared keys work for WPA2 clients only; WPA3 (SAE) clients use the WLAN passphrase", s.ID))
	default:
		return s, append(notes, fmt.Sprintf("ssid %s: %d private pre-shared keys ignored: hostapd's key file is WPA2-PSK only (security %s)", s.ID, len(in), s.Security))
	}
	otherVLAN, bad := 0, 0
	for _, k := range in {
		if !validPSK(k.Passphrase, true) {
			bad++
			continue
		}
		if k.VLAN != s.VLAN {
			otherVLAN++
			continue
		}
		if k.MAC != "" {
			if k.MAC = normMAC(k.MAC); k.MAC == "" {
				bad++
				continue
			}
		}
		if len(k.KeyID) > 32 || strings.IndexFunc(k.KeyID, func(r rune) bool { return r <= ' ' || r >= 0x7f }) >= 0 {
			k.KeyID = ""
		}
		k.VLAN = 0 // written without vlanid: the SSID's own bridge
		s.PSKs = append(s.PSKs, k)
	}
	if bad > 0 {
		notes = append(notes, fmt.Sprintf("ssid %s: %d invalid private pre-shared keys dropped", s.ID, bad))
	}
	if otherVLAN > 0 {
		notes = append(notes, fmt.Sprintf("ssid %s: %d private pre-shared keys for another VLAN than the SSID's (%d) dropped: this hostapd has no dynamic VLANs, their stations cannot join", s.ID, otherVLAN, s.VLAN))
	}
	return s, notes
}

// pskFile renders s.PSKs as a hostapd wpa_psk_file.
func pskFile(keys []PSK) []byte {
	var b strings.Builder
	for _, k := range keys {
		if k.KeyID != "" {
			b.WriteString("keyid=" + k.KeyID + " ")
		}
		mac := k.MAC
		if mac == "" {
			mac = "00:00:00:00:00:00"
		}
		b.WriteString(mac + " " + k.Passphrase + "\n")
	}
	return []byte(b.String())
}

// pskSteps writes a vif's key file (0600) when its SSID has private keys,
// and removes a stale one otherwise (so no step at all in the usual case,
// which keeps the live ACL update path, acllive.go, available).
func pskSteps(runDir, vif string, s SSID, exists func(string) bool) []Step {
	p := pskPath(runDir, vif)
	if len(s.PSKs) > 0 && (s.Security == SecWPA2 || s.Security == SecWPA2WPA3) {
		return []Step{writeStep("write private key file "+vif, p, 0o600, pskFile(s.PSKs))}
	}
	if exists(p) {
		return []Step{{Kind: StepRemove, Desc: "remove private key file " + vif, Path: p}}
	}
	return nil
}

// writePSKFile references the vif's key file in its bss= section.
func writePSKFile(w func(string, any), r hapdRadio, x hapdBSS) {
	if len(x.SSID.PSKs) > 0 {
		w("wpa_psk_file", pskPath(r.RunDir, x.Vif))
	}
}

// isPSKPath tells whether p is a vif key file (pskPath).
func isPSKPath(p string) bool { return strings.HasSuffix(p, ".psk") }
