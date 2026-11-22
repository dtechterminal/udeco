// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"encoding/hex"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustMAC(t *testing.T, s string) MAC {
	t.Helper()
	m, err := ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The vectors below were printed by verbatim copies of hostapd 2.9's
// sha256_prf_bits, hmac_sha256_kdf, wpa_derive_pmk_r0, wpa_derive_pmk_r1
// and wpa_derive_pmk_r1_name (padavan trunk/user/wpa_supplicant, compiled
// with CommonCrypto for HMAC/SHA-256), for XXKey 00..1f, SSID
// "udeco-test", MDID d5 30, R0KH-ID "a842a1000001", S0KH = S1KH
// 02:11:22:33:44:55, R1KH a8:42:a1:00:00:02.
func TestFTKeyHierarchyHostapd(t *testing.T) {
	xx := make([]byte, 32)
	for i := range xx {
		xx[i] = byte(i)
	}
	sta := mustMAC(t, "02:11:22:33:44:55")
	r1kh := mustMAC(t, "a8:42:a1:00:00:02")
	r0, err := DerivePMKR0(xx, []byte("udeco-test"), 0xd530, []byte("a842a1000001"), sta)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(r0.Key[:]); got != "acb873d76ff6fb084b580eb6c240d4f32c268fa81fd108940027a865bffdc6b3" {
		t.Errorf("PMK-R0 %s", got)
	}
	if got := hex.EncodeToString(r0.Name[:]); got != "5e315462246413987ce56efc7d3db56f" {
		t.Errorf("PMKR0Name %s", got)
	}
	r1 := DerivePMKR1(r0, r1kh, sta)
	if got := hex.EncodeToString(r1.Key[:]); got != "d2350f73120a2f0a95f1ae8cca54fdba5ba3ae9c7d753c02119274980f160504" {
		t.Errorf("PMK-R1 %s", got)
	}
	if got := hex.EncodeToString(r1.Name[:]); got != "9a76dc122b196ab21ee83ba792233a87" {
		t.Errorf("PMKR1Name %s", got)
	}
	if got := hex.EncodeToString(KDF(xx, "label", []byte("context"), 384)); got != "7ff8c88aa1220f2dd5a6c309da0aab3404dbdf6baf6b6efffe819298fadc6f12c1d683cc55d5d3490e1cae1a115390ee" {
		t.Errorf("KDF-384 %s", got)
	}
}

func TestDerivePMKR0Limits(t *testing.T) {
	var sta MAC
	xx := make([]byte, 32)
	long := make([]byte, MaxR0KHIDLen+1)
	for _, c := range []struct {
		xx, ssid, r0 []byte
	}{
		{xx[:16], []byte("s"), []byte("r")},
		{xx, nil, []byte("r")},
		{xx, make([]byte, 33), []byte("r")},
		{xx, []byte("s"), nil},
		{xx, []byte("s"), long},
	} {
		if _, err := DerivePMKR0(c.xx, c.ssid, 1, c.r0, sta); err == nil {
			t.Errorf("accepted xxkey %d ssid %d r0kh %d", len(c.xx), len(c.ssid), len(c.r0))
		}
	}
}

// IEEE 802.11-2016 J.4.2 (passphrase "password", SSID "IEEE") and the
// second vector of that annex.
func TestPSK(t *testing.T) {
	for _, c := range []struct{ pass, ssid, want string }{
		{"password", "IEEE", "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"},
		{"ThisIsAPassword", "ThisIsASSID", "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af"},
	} {
		k, err := PSK(c.pass, []byte(c.ssid))
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(k[:]); got != c.want {
			t.Errorf("PSK(%q, %q) = %s", c.pass, c.ssid, got)
		}
	}
	raw := "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
	if k, err := PSK(raw, []byte("x")); err != nil || hex.EncodeToString(k[:]) != raw {
		t.Errorf("64 hex digits are the PSK itself: %x %v", k, err)
	}
	if _, err := PSK("short", []byte("x")); err == nil {
		t.Error("accepted a 5-character passphrase")
	}
}

// FTPSKR1 is the derivation a Deco's ft_psk_generate_local makes and the
// one the Garage pre-installs: same as the explicit chain.
func TestFTPSKR1(t *testing.T) {
	psk, _ := PSK("password", []byte("IEEE"))
	sta, r1kh := mustMAC(t, "02:11:22:33:44:55"), mustMAC(t, "a8:42:a1:00:00:02")
	r0, r1, err := FTPSKR1(psk, []byte("IEEE"), 0xd530, []byte("a842a1000001"), sta, r1kh)
	if err != nil {
		t.Fatal(err)
	}
	r0b, _ := DerivePMKR0(psk[:], []byte("IEEE"), 0xd530, []byte("a842a1000001"), sta)
	if r0 != r0b || r1 != DerivePMKR1(r0b, r1kh, sta) {
		t.Error("FTPSKR1 differs from DerivePMKR0 + DerivePMKR1")
	}
	// another R0KH-ID is another SA: the Garage needs one per possible R0KH
	_, r1c, _ := FTPSKR1(psk, []byte("IEEE"), 0xd530, []byte("a842a1000003"), sta, r1kh)
	if r1c.Name == r1.Name {
		t.Error("R0KH-ID does not enter PMKR1Name")
	}
}

// RRBKey: a 32-hex iapp_key is stretched as hostapd's rkh_derive_key
// (vector from hostapd's hmac_sha256_kdf above, key 10..1f); 64 hex digits
// are used as they are.
func TestRRBKey(t *testing.T) {
	k, err := RRBKey("101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(k[:]); got != "256491dc8b964ba587e538a4adc08889ad876c3a0bd471f2693912b8910052e3" {
		t.Errorf("RRBKey %s", got)
	}
	full := "256491dc8b964ba587e538a4adc08889ad876c3a0bd471f2693912b8910052e3"
	if k, _ := RRBKey(full); hex.EncodeToString(k[:]) != full {
		t.Error("a 64-hex key must be used as it is")
	}
	for _, bad := range []string{"", "xyz", "1011"} {
		if _, err := RRBKey(bad); err == nil {
			t.Errorf("RRBKey(%q) accepted", bad)
		}
	}
}

func TestParseMAC(t *testing.T) {
	m := mustMAC(t, "A8-42-a1-00-00-02")
	if m.String() != "a8:42:a1:00:00:02" || m.Hex() != "a842a1000002" {
		t.Errorf("%s %s", m, m.Hex())
	}
	for _, bad := range []string{"", "a8:42:a1:00:00", "zz:42:a1:00:00:02"} {
		if _, err := ParseMAC(bad); err == nil {
			t.Errorf("ParseMAC(%q) accepted", bad)
		}
	}
}
