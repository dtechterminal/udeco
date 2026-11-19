// SPDX-License-Identifier: GPL-2.0-or-later
package apstate

import "testing"

// The labels are the ones a real U6 Pro reported to Network 11.1.50
// (stat/rogueap "security", 2026-11-19) for the same kinds of network.
func TestSecurityLabel(t *testing.T) {
	cases := []struct {
		name string
		in   SecInfo
		want string
	}{
		{"open", SecInfo{}, "Open"},
		{"wep", SecInfo{Privacy: true}, "WEP"},
		{"wpa2 psk", SecInfo{RSN: true, Privacy: true, AKMs: []string{"WPA2-PSK"}, Ciphers: []string{"AES-CCMP", "AES-CCMP"}}, "WPA2-Personal (AES/CCMP)"},
		{"wpa/wpa2 mixed", SecInfo{WPA: true, RSN: true, AKMs: []string{"WPA-PSK", "WPA2-PSK"}, Ciphers: []string{"TKIP", "AES-CCMP", "TKIP"}}, "WPA2-Personal (TKIP/AES/CCMP)"},
		{"wl cipher order", SecInfo{RSN: true, AKMs: []string{"WPA2-PSK"}, Ciphers: []string{"AES-CCMP", "TKIP"}}, "WPA2-Personal (TKIP/AES/CCMP)"},
		{"transition", SecInfo{RSN: true, AKMs: []string{"WPA2-PSK", "SAE"}, Ciphers: []string{"AES-CCMP"}}, "WPA2+WPA3-Personal (AES/CCMP)"},
		{"transition iw", SecInfo{RSN: true, AKMs: []string{"PSK", "SAE", "FT/PSK", "FT/SAE"}, Ciphers: []string{"CCMP"}}, "WPA2+WPA3-Personal (AES/CCMP)"},
		{"wpa3 only", SecInfo{RSN: true, AKMs: []string{"SAE"}, Ciphers: []string{"AES-CCMP"}}, "WPA3-Personal (AES/CCMP)"},
		{"enterprise wl", SecInfo{RSN: true, AKMs: []string{"WPA2-802.1x"}, Ciphers: []string{"AES-CCMP"}}, "WPA2-Enterprise (AES/CCMP)"},
		{"enterprise iw", SecInfo{RSN: true, AKMs: []string{"IEEE", "802.1X"}, Ciphers: []string{"CCMP"}}, "WPA2-Enterprise (AES/CCMP)"},
		{"wpa3 enterprise", SecInfo{RSN: true, AKMs: []string{"1X-SHA256"}, Ciphers: []string{"AES-CCMP"}}, "WPA3-Enterprise (AES/CCMP)"},
		{"wpa2+wpa3 enterprise", SecInfo{RSN: true, AKMs: []string{"WPA2-802.1x", "1X-SHA256"}, Ciphers: []string{"AES-CCMP"}}, "WPA2-Enterprise+WPA3-Enterprise (AES/CCMP)"},
		{"wpa1 only", SecInfo{WPA: true, AKMs: []string{"WPA-PSK"}, Ciphers: []string{"TKIP"}}, "WPA-Personal (TKIP)"},
		{"rsn without akm line", SecInfo{RSN: true}, "WPA2-Personal"},
		{"owe", SecInfo{RSN: true, AKMs: []string{"OWE"}, Ciphers: []string{"CCMP"}}, "Open (OWE)"},
		{"gcmp", SecInfo{RSN: true, AKMs: []string{"SAE"}, Ciphers: []string{"AES-GCMP256"}}, "WPA3-Personal (AES/GCMP-256)"},
	}
	for _, c := range cases {
		if got := SecurityLabel(c.in); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
