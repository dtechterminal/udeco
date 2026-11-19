// SPDX-License-Identifier: GPL-2.0-or-later
package apstate

import "strings"

// SecInfo is what a scan result says about a neighbour's security: which
// security elements it carries (WPA1, RSN, the Privacy capability bit), its
// AKM suites and its pairwise and group ciphers, as the scanner printed them
// (wl: "WPA2-PSK SAE", "AES-CCMP TKIP"; iw: "PSK SAE", "CCMP TKIP").
type SecInfo struct {
	WPA, RSN, Privacy bool
	AKMs              []string
	Ciphers           []string
}

// SecurityLabel renders a neighbour's security the way a UniFi AP reports it
// in scan_table "security": a label the controller's
// com.ubnt.i.e.A.aoUDgXMlCqEvTSIrOtq enum matches by prefix
// ("WPA2+WPA3-Personal", "WPA2-Enterprise+WPA3-Enterprise", "WPA2-Personal",
// "WPA3-Personal", "WPA2-Enterprise", "WPA3-Enterprise", "WEP", "Open"),
// followed by the ciphers, as the U6 Pro sends them:
// "WPA2-Personal (AES/CCMP)", "WPA2-Personal (TKIP/AES/CCMP)",
// "WPA2+WPA3-Personal (AES/CCMP)", "Open".
//
// A WPA1-only network is "WPA-Personal"/"WPA-Enterprise": the controller has
// no filter for it, but calling it WPA2 would be wrong. A mixed WPA/WPA2
// network is WPA2 with TKIP listed, as the U6 Pro shows it. OWE has no label
// in the controller; it is shown as "Open (OWE)", which the Open filter
// matches.
func SecurityLabel(s SecInfo) string {
	var psk, sae, eap2, eap3, owe bool
	for _, a := range s.AKMs {
		switch k := strings.ToUpper(strings.TrimSpace(a)); k {
		case "":
		case "WPA-PSK", "WPA2-PSK", "PSK", "PSK-SHA256", "FT-PSK", "FT/PSK", "PSK/SHA-256":
			psk = true
		case "SAE", "SAE-FT", "FT-SAE", "FT/SAE", "WPA3-SAE", "SAE-EXT-KEY", "FT-SAE-EXT-KEY":
			sae = true
		case "1X-SHA256", "802.1X-SHA256", "IEEE 802.1X/SHA-256", "802.1X/SHA-256", "EAP-SHA256",
			"SUITE-B", "SUITE-B-192", "802.1X-SUITE-B", "802.1X-SUITE-B-192", "FT-802.1X-SHA384":
			eap3 = true
		case "OWE":
			owe = true
		default:
			if strings.Contains(k, "802.1X") || k == "WPA" || k == "WPA2" || k == "UNSPECIFIED" || strings.Contains(k, "EAP") {
				eap2 = true
			}
		}
	}
	wpaAny := s.WPA || s.RSN
	ver := "WPA2"
	if s.WPA && !s.RSN {
		ver = "WPA"
	}
	var label string
	switch {
	case psk && sae:
		label = "WPA2+WPA3-Personal"
	case sae:
		label = "WPA3-Personal"
	case psk:
		label = ver + "-Personal"
	case eap2 && eap3:
		label = "WPA2-Enterprise+WPA3-Enterprise"
	case eap3:
		label = "WPA3-Enterprise"
	case eap2:
		label = ver + "-Enterprise"
	case owe:
		return "Open (OWE)"
	case wpaAny:
		label = ver + "-Personal" // an RSN/WPA element without a readable AKM line
	case s.Privacy:
		return "WEP"
	default:
		return "Open"
	}
	if c := cipherList(s.Ciphers); c != "" {
		label += " (" + c + ")"
	}
	return label
}

// cipherList orders and names ciphers the UniFi way: TKIP first, then
// AES/CCMP, then the rest; duplicates dropped.
func cipherList(cs []string) string {
	var tkip, ccmp bool
	var other []string
	seen := map[string]bool{}
	for _, c := range cs {
		switch k := strings.ToUpper(strings.TrimSpace(c)); k {
		case "":
		case "TKIP":
			tkip = true
		case "AES-CCMP", "CCMP", "CCMP-128", "AES", "AES/CCMP":
			ccmp = true
		case "TKIPAES":
			tkip, ccmp = true, true
		case "WEP", "WEP40", "WEP104", "WEP64", "WEP128", "WEP1", "NONE", "WPA-NONE":
		default:
			n := k
			switch k {
			case "AES-GCMP", "GCMP", "GCMP-128":
				n = "AES/GCMP"
			case "AES-GCMP256", "GCMP-256":
				n = "AES/GCMP-256"
			case "CCMP-256":
				n = "AES/CCMP-256"
			}
			if !seen[n] {
				seen[n] = true
				other = append(other, n)
			}
		}
	}
	var out []string
	if tkip {
		out = append(out, "TKIP")
	}
	if ccmp {
		out = append(out, "AES/CCMP")
	}
	return strings.Join(append(out, other...), "/")
}
