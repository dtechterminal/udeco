// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"fmt"
	"strconv"
	"strings"
)

// Profile keys of the MT7663's 802.11r (FT_rtmp_read_parameters_from_file,
// 0x8053d3e4 in the Garage kernel). FtSupport, FtRic and FtOtd are
// ";"-separated per BSS; FtMdId<n> and FtR0khId<n> are per BSS with n from
// 1. Read when the radio starts: APSecInit adds the FT AKMs (FT-802.1X for
// WPA2, FT-PSK for WPA2PSK, FT-SAE for SAE) only then, so turning FT on or
// off is a radio restart.

// R0KHIDLen is the R0KH-ID length the driver uses whatever the profile
// says: FT_CfgInitial (0x8053834c) sets FtR0khIdLen to the length of its
// random "Ralink:xx:xx:xx:xx:xx:xx" (24), and the profile's FtR0khId<n>
// copies the string without updating the length (`iwpriv <if> set
// ftr0khid=` does update it). A profile R0KH-ID of exactly this length is
// on the air as written from the first beacon.
const R0KHIDLen = 24

// r0khSuffix pads the 12-hex BSSID to R0KHIDLen with characters the Decos'
// announcement check accepts (ftpeer.ValidR0KHID).
const r0khSuffix = "-mt7663-r0kh"

// R0KHID is the Garage BSS's R0KH-ID: its BSSID as 12 hex digits (as a
// Deco's nas_identifier), padded to R0KHIDLen.
func R0KHID(bssid MAC) string { return bssid.Hex() + r0khSuffix }

// MDIDValue is the FtMdId<n> value for md. The driver parses "<hex>:H"
// with simple_strtol and stores the integer's two low octets as they lie
// in memory (little-endian), so the on-air MDIE octets m0 m1 are written
// "m1m0:H": hostapd's mobility_domain=d530 is FtMdId=30d5:H. (Without
// ":H" the value is two ASCII characters; the default is "RT".)
func MDIDValue(md MDID) string {
	o := md.octets()
	return fmt.Sprintf("%02x%02x:H", o[1], o[0])
}

// BSSFT is one BSS slot's 802.11r profile settings.
type BSSFT struct {
	On     bool
	MDID   MDID
	R0KHID string // R0KHID(bssid); ignored when !On
}

// ProfileKeys returns the FT keys for slots (one per BSS, index 0 =
// FtMdId1). Over the DS and RIC stay off (FtOtd, FtRic 0): over-the-DS
// RRB on this driver is MediaTek's own encrypted format (RT_FT_DATA_ENCRYPT),
// not hostapd's, and the Decos run ft_over_ds=0. A slot that is off keeps
// the driver defaults for its MDID and R0KH-ID (no key written).
func ProfileKeys(slots []BSSFT) (map[string]string, error) {
	kv := map[string]string{}
	sup := make([]string, len(slots))
	off := make([]string, len(slots))
	for i, s := range slots {
		sup[i], off[i] = "0", "0"
		if !s.On {
			continue
		}
		if len(s.R0KHID) != R0KHIDLen {
			return nil, fmt.Errorf("mtkft: slot %d: R0KH-ID must be %d characters (the driver keeps that length)", i+1, R0KHIDLen)
		}
		sup[i] = "1"
		kv["FtMdId"+strconv.Itoa(i+1)] = MDIDValue(s.MDID)
		kv["FtR0khId"+strconv.Itoa(i+1)] = s.R0KHID
	}
	kv["FtSupport"] = strings.Join(sup, ";")
	kv["FtRic"] = strings.Join(off, ";")
	kv["FtOtd"] = strings.Join(off, ";")
	return kv, nil
}

// SetR0KHID is the live `iwpriv <if> set` argument that sets the BSS's
// R0KH-ID with its length (Set_FT_R0khid, 0x8053dd9c), for an R0KH-ID
// that is not R0KHIDLen long. A radio restart rereads the profile.
func SetR0KHID(id string) (string, error) {
	if len(id) == 0 || len(id) > MaxR0KHIDLen {
		return "", fmt.Errorf("mtkft: R0KH-ID must be 1-%d characters", MaxR0KHIDLen)
	}
	return "ftr0khid=" + id, nil
}
