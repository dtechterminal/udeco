// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/translate"
)

// desiredPSKs maps a WLAN's private pre-shared keys (translate.PSK, from
// aaa.N.wpa.psk_file) onto bcmwifi's. bcmwifi decides which it can serve
// (docs/deco/features/ppsk.md): keys for another VLAN than the SSID's are
// dropped there, with a note.
func desiredPSKs(in []translate.PSK) []bcmwifi.PSK {
	if len(in) == 0 {
		return nil
	}
	out := make([]bcmwifi.PSK, 0, len(in))
	for _, k := range in {
		out = append(out, bcmwifi.PSK{Passphrase: k.Passphrase, VLAN: k.VLAN, MAC: k.MAC, KeyID: k.KeyID})
	}
	return out
}
