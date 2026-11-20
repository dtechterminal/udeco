// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Private pre-shared keys (PPSK), docs/deco/features/ppsk.md.
//
// With wifi_caps WPA_PSK_FILE (0x100000, the controller's supportWpaPpsk) a
// WLAN that has private pre-shared keys is sent; without it the controller
// skips the WLAN altogether ("PPSK is not supported by ... will be skipped").
// Its PPSK config factory writes, for every key whose network is a local
// layer-2 network:
//
//	aaa.N.dynamic_vlan=1
//	aaa.N.wpa.psk_file.status=enabled
//	aaa.N.wpa.psk_file.M.psk=<passphrase>
//	aaa.N.wpa.psk_file.M.vlanid=<the key's network VLAN>   (omitted for VLAN 1, the untagged LAN)
//
// next to the WLAN's own wpa.key.1.mgmt / wpa.psk. A UAP's ubntbox also
// reads aaa.N.wpa.psk_file.M.mac and .keyid (hostapd's wpa_psk_file
// "keyid=<id> vlanid=<vid> <mac> <passphrase>" lines); they are carried too.

// PSK is one private pre-shared key. Passphrase is a secret.
type PSK struct {
	Passphrase string // 8-63 printable ASCII, or 64 hex digits
	VLAN       int    // the key's 802.1Q id; 0 = untagged (the controller omits vlanid for VLAN 1)
	MAC        string // only this station may use the key (lower case); "" = any station
	KeyID      string // hostapd keyid (reported on association); "" = none
}

// String describes p with the passphrase masked.
func (p PSK) String() string {
	return fmt.Sprintf("psk=%s vlan=%d mac=%q keyid=%q", Mask(p.Passphrase), p.VLAN, p.MAC, p.KeyID)
}

// GoString is String: %#v must not print the passphrase either.
func (p PSK) GoString() string { return p.String() }

// wlanPSKFile reads aaa.N.wpa.psk_file.M.* into x.PSKs. Entries that cannot
// be used are dropped with a note naming only their index (never the
// passphrase). It returns a reason when the WLAN must stay off.
func wlanPSKFile(cfg Cfg, a string, x *WLANIntent, note func(string, ...any)) string {
	if x.Security != SecWPA2 && x.Security != SecWPA2WPA3 {
		// SAE has no key list in hostapd 2.9 (wpa_psk_file is WPA-PSK only):
		// a WPA3-only WLAN cannot use the keys.
		return fmt.Sprintf("private pre-shared keys with %s: hostapd's key file is WPA2-PSK only", x.Security)
	}
	idx := indices(cfg, a+"wpa.psk_file")
	sort.Slice(idx, func(i, j int) bool { ni, _ := strconv.Atoi(idx[i]); nj, _ := strconv.Atoi(idx[j]); return ni < nj })
	for _, m := range idx {
		p := a + "wpa.psk_file." + m + "."
		if cfg[p+"status"] == "disabled" {
			continue
		}
		k := PSK{Passphrase: cfg[p+"psk"]}
		switch {
		case k.Passphrase == "":
			note("private pre-shared key %s has no passphrase: dropped", m)
			continue
		case !ValidWPAPassphrase(k.Passphrase):
			note("private pre-shared key %s is not 8-63 characters (or 64 hex digits): dropped", m)
			continue
		}
		if v := cfg[p+"vlanid"]; v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 4094 {
				note("private pre-shared key %s: VLAN %q not recognised: dropped", m, v)
				continue
			}
			if n != 1 { // VLAN 1 is the untagged LAN (the controller omits it)
				k.VLAN = n
			}
		}
		if mac := strings.TrimSpace(cfg[p+"mac"]); mac != "" {
			hw, err := net.ParseMAC(mac)
			if err != nil || len(hw) != 6 {
				note("private pre-shared key %s: station MAC not recognised: dropped", m)
				continue
			}
			if s := hw.String(); s != "00:00:00:00:00:00" && s != "ff:ff:ff:ff:ff:ff" {
				k.MAC = s
			}
		}
		if id := cfg[p+"keyid"]; id != "" {
			// hostapd: no whitespace (the line is split on it), at most 32
			if len(id) > 32 || strings.IndexFunc(id, func(r rune) bool { return r <= ' ' || r >= 0x7f }) >= 0 {
				note("private pre-shared key %s: key id not usable by hostapd: left out", m)
			} else {
				k.KeyID = id
			}
		}
		x.PSKs = append(x.PSKs, k)
	}
	if len(x.PSKs) == 0 && cfg[a+"wpa.psk"] == "" {
		return "private pre-shared keys: none usable and no WLAN passphrase"
	}
	return ""
}
