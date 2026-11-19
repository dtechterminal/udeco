// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Fake private pre-shared keys (never real ones).
const (
	ppskLAN   = "ppsk-lan-pass-1"
	ppskMAC   = "ppsk-mac-pass-2"
	ppskVLAN  = "ppsk-vlan20-pass"
	ppskOther = "ppsk-other-pass-3"
)

func ppskDesired(mainPass string) Desired {
	return Desired{
		Country: "US",
		Radios:  map[string]Radio{"na": {Enabled: true, Channel: 44, Width: 80}},
		SSIDs: []SSID{{ID: "p", SSID: "Home PPSK", Bands: []string{"na"}, Enabled: true, Security: SecWPA2, Passphrase: mainPass, FT: true,
			PSKs: []PSK{
				{Passphrase: ppskLAN},
				{Passphrase: ppskMAC, MAC: "AA-BB-CC-00-00-07", KeyID: "kid-2"},
				{Passphrase: ppskVLAN, VLAN: 20}, // another VLAN: cannot be served
			}}},
	}
}

// confValue returns the value of the first key= line of conf (or "").
func confValue(conf, key string) string {
	m := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `=(.*)$`).FindStringSubmatch(conf)
	if m == nil {
		return ""
	}
	return m[1]
}

// TestPPSKApply: controller keys in, hostapd conf + 0600 key file out; a key
// for another VLAN is dropped (never served on the SSID's network); secrets
// stay out of plan text and the public last-good; a key change restarts the
// radio's hostapd; removing the keys removes the file.
func TestPPSKApply(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := ppskDesired(testPSK)
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(p.Notes, "\n")
	if !strings.Contains(notes, "1 private pre-shared keys for another VLAN than the SSID's (0) dropped") {
		t.Errorf("VLAN note missing:\n%s", notes)
	}
	for _, s := range []string{testPSK, ppskLAN, ppskMAC, ppskVLAN} {
		if strings.Contains(p.String(), s) || strings.Contains(fmt.Sprintf("%v %+v %#v", d.SSIDs, d.SSIDs, d.SSIDs), s) {
			t.Fatalf("secret printed:\n%s", p)
		}
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(f.path("/tmp/udeco/hapd-wl1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	conf := string(b)
	conf = conf[strings.Index(conf, "\nbss="):] // the SSID's section, not the placeholder's
	file := confValue(conf, "wpa_psk_file")
	if !regexp.MustCompile(`^/tmp/udeco/wl1\d\.psk$`).MatchString(file) {
		t.Fatalf("wpa_psk_file %q in conf:\n%s", file, conf)
	}
	if confValue(conf, "wpa_passphrase") == "" || !strings.Contains(confValue(conf, "wpa_key_mgmt"), "FT-PSK") ||
		confValue(conf, "ft_psk_generate_local") != "1" {
		t.Errorf("conf lacks the WLAN passphrase or FT-PSK with local key generation:\n%s", conf)
	}
	for _, bad := range []string{"vlanid", "dynamic_vlan", "vlan_file"} {
		if strings.Contains(conf, bad) {
			t.Errorf("conf has %q, which this hostapd cannot parse", bad)
		}
	}
	key, err := os.ReadFile(f.path(file))
	if err != nil {
		t.Fatal(err)
	}
	want := "00:00:00:00:00:00 " + ppskLAN + "\nkeyid=kid-2 aa:bb:cc:00:00:07 " + ppskMAC + "\n"
	if string(key) != want {
		t.Errorf("key file:\n%q\nwant\n%q", key, want)
	}
	if st, _ := os.Stat(f.path(file)); st.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %o", st.Mode().Perm())
	}
	pub, _ := os.ReadFile(f.path("/tp_data/udeco/state/last-good.json"))
	sec, _ := os.ReadFile(f.path("/tp_data/udeco/state/last-good.secrets.json"))
	for _, s := range []string{ppskLAN, ppskMAC} {
		if strings.Contains(string(pub), s) {
			t.Errorf("public last-good has a private key:\n%s", pub)
		}
		if !strings.Contains(string(sec), s) {
			t.Errorf("secrets file lacks a private key")
		}
	}
	// Last-good comes back with its keys (a rollback re-renders the same file).
	lg, err := a.loadLastGood()
	if err != nil || lg == nil || len(lg.SSIDs) != 1 || len(lg.SSIDs[0].PSKs) != 3 || lg.SSIDs[0].PSKs[1].Passphrase != ppskMAC {
		t.Fatalf("last-good keys not restored: %v %v", lg, err)
	}

	f.reset()
	if p2, err := a.Plan(ctx, d); err != nil || !p2.Empty() {
		t.Fatalf("second plan not empty (%v):\n%s", err, p2)
	}
	// A changed key: hostapd 2.9 reads the file only at start.
	d.SSIDs[0].PSKs[0].Passphrase = ppskOther
	p3, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	stepIndex(t, p3, "write private key file")
	stepIndex(t, p3, "stop hostapd from /tmp/udeco/hapd-wl1.pid")
	if err := a.Apply(ctx, p3); err != nil {
		t.Fatal(err)
	}
	if key, _ := os.ReadFile(f.path(file)); !strings.Contains(string(key), ppskOther) || strings.Contains(string(key), ppskLAN) {
		t.Errorf("key file not rewritten")
	}
	// Keys removed: the file goes, the conf no longer names it.
	d.SSIDs[0].PSKs = nil
	p4, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	stepIndex(t, p4, "remove private key file")
	if err := a.Apply(ctx, p4); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.path(file)); !os.IsNotExist(err) {
		t.Errorf("key file left behind: %v", err)
	}
	if b, _ := os.ReadFile(f.path("/tmp/udeco/hapd-wl1.conf")); strings.Contains(string(b), "wpa_psk_file") {
		t.Error("conf still names a key file")
	}
}

// TestPPSKOnlyKeys: a WPA2 SSID whose only passphrases are private keys is
// served from the key file alone; with no key it can serve, it is skipped
// (never built without a key).
func TestPPSKOnlyKeys(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := ppskDesired("")
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.path("/tmp/udeco/hapd-wl1.conf"))
	conf := string(b)
	// the placeholder BSS (interface=) has its own random passphrase; the
	// SSID's bss= section must have none
	ssidPart := conf[strings.Index(conf, "\nbss="):]
	if confValue(ssidPart, "wpa_psk_file") == "" || confValue(ssidPart, "wpa_passphrase") != "" || confValue(ssidPart, "wpa_psk") != "" {
		t.Errorf("bss section:\n%s", ssidPart)
	}

	only20 := ppskDesired("")
	only20.SSIDs[0].PSKs = []PSK{{Passphrase: ppskVLAN, VLAN: 20}}
	_, notes, ok := normalizeSSID(only20.SSIDs[0])
	if ok {
		t.Errorf("SSID with only another VLAN's key served: %q", notes)
	}
}

func TestNormalizePSKs(t *testing.T) {
	base := SSID{ID: "n", SSID: "x", Security: SecWPA2, Passphrase: testPSK}
	for _, c := range []struct {
		name  string
		s     SSID
		keys  int
		ok    bool
		note  string
		vlan0 bool
	}{
		{"same VLAN kept, written untagged", func() SSID {
			s := base
			s.VLAN = 30
			s.PSKs = []PSK{{Passphrase: ppskLAN, VLAN: 30}, {Passphrase: ppskMAC}}
			return s
		}(), 1, true, "another VLAN than the SSID's (30)", true},
		{"invalid keys dropped", func() SSID {
			s := base
			s.PSKs = []PSK{{Passphrase: "short"}, {Passphrase: ppskLAN, MAC: "nope"}, {Passphrase: ppskMAC, KeyID: "has space"}}
			return s
		}(), 1, true, "2 invalid private pre-shared keys dropped", true},
		{"wpa3 ignores keys", func() SSID {
			s := base
			s.Security = SecWPA3
			s.PSKs = []PSK{{Passphrase: ppskLAN}}
			return s
		}(), 0, true, "WPA2-PSK only", true},
		{"transition: WPA2 clients only", func() SSID {
			s := base
			s.Security = SecWPA2WPA3
			s.PSKs = []PSK{{Passphrase: ppskLAN}}
			return s
		}(), 1, true, "WPA2 clients only", true},
		{"transition needs its own passphrase", func() SSID {
			s := base
			s.Security, s.Passphrase = SecWPA2WPA3, ""
			s.PSKs = []PSK{{Passphrase: ppskLAN}}
			return s
		}(), 1, false, "SAE", true},
	} {
		got, notes, ok := normalizeSSID(c.s)
		n := strings.Join(notes, "\n")
		if ok != c.ok || len(got.PSKs) != c.keys || !strings.Contains(n, c.note) {
			t.Errorf("%s: ok=%t keys=%d notes=%q", c.name, ok, len(got.PSKs), n)
		}
		for _, k := range got.PSKs {
			if k.VLAN != 0 || strings.ContainsAny(k.KeyID, " ") {
				t.Errorf("%s: key %v", c.name, k)
			}
		}
		for _, k := range c.s.PSKs {
			if strings.Contains(n, k.Passphrase) {
				t.Errorf("%s: note leaks a key", c.name)
			}
		}
	}
}
