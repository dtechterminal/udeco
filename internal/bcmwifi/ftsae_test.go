// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"fmt"
	"math/bits"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/ftpeer"
)

// testFTKey stands in for the controller's per-WLAN iapp_key (32 hex digits,
// x_iapp_key in WlanConf): a fake, never a real one.
const testFTKey = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

// ftTransition is a WPA2/WPA3 transition SSID as the controller sends it
// with fast roaming and WPA3 fast roaming on (radio_caps2 0x2 claimed).
func ftTransition() SSID {
	return SSID{ID: "2", SSID: "Example Network", Bands: []string{"na"}, Enabled: true, Security: SecWPA2WPA3,
		Passphrase: testPSK, PMF: "optional", FT: true, FTSAE: true, FTKey: testFTKey, BSSTransition: true}
}

// bssSection returns the conf lines of the first bss= section (the SSID's,
// not the placeholder's).
func bssSection(t *testing.T, conf string) string {
	t.Helper()
	i := strings.Index(conf, "\nbss=")
	if i < 0 {
		t.Fatalf("no bss= section:\n%s", conf)
	}
	return conf[i+1:]
}

// checkFTLines parses the FT lines of a BSS the way hostapd 2.9 does
// (hostapd/config_file.c add_r0kh, add_r1kh, rkh_derive_key) and returns
// the r0kh and r1kh keys: a line it would refuse aborts the whole radio.
func checkFTLines(t *testing.T, sec string) (r0key, r1key string) {
	t.Helper()
	key := func(k string) {
		if !(len(k) == 64 || len(k) == 32) || !isHex(k) {
			t.Errorf("key %d chars: hostapd 2.9 takes 64 hex digits, or 32 (FT OLDKEY)", len(k))
		}
	}
	for _, l := range strings.Split(sec, "\n") {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "r0kh":
			f := strings.Split(v, " ")
			if len(f) != 3 {
				t.Fatalf("r0kh has %d fields", len(f))
			}
			if _, err := net.ParseMAC(f[0]); err != nil || len(f[1]) < 1 || len(f[1]) > 48 {
				t.Errorf("r0kh address/id not parseable: %q %q", f[0], f[1])
			}
			key(f[2])
			r0key = f[2]
		case "r1kh":
			f := strings.Split(v, " ")
			if len(f) != 3 {
				t.Fatalf("r1kh has %d fields", len(f))
			}
			for _, m := range f[:2] {
				if _, err := net.ParseMAC(m); err != nil {
					t.Errorf("r1kh MAC %q: %v", m, err)
				}
			}
			key(f[2])
			r1key = f[2]
		case "r1_key_holder":
			if len(v) != 12 || !isHex(v) {
				t.Errorf("r1_key_holder %q: hostapd wants 12 hex digits", v)
			}
		case "mobility_domain":
			if len(v) != 4 || !isHex(v) {
				t.Errorf("mobility_domain %q", v)
			}
		case "nas_identifier":
			if v == "" || len(v) > 48 {
				t.Errorf("nas_identifier %q: R0KH-ID is 1..48 octets", v)
			}
		}
	}
	return r0key, r1key
}

// ftPeer is another unit's key holder for key, as ftpeer reports it.
func ftPeer(bssid, band, ssid, key, bridge string) ftpeer.Peer {
	s := SSID{SSID: ssid, FT: true, FTSAE: true}
	return ftpeer.Peer{Holder: ftpeer.Holder{Band: band, BSSID: bssid, R0KHID: strings.ReplaceAll(bssid, ":", ""), R1KHID: bssid,
		MDID: ssidMDID(s, band)}, KeyID: ftpeer.KeyID(key), Unit: "02:00:00:00:0b:01", Bridge: bridge}
}

// renderFTCase is renderCase with the FT-SAE peers an Applier holding
// peers would list (peersFor), this unit's BSSIDs known to it.
func renderFTCase(t *testing.T, band string, r Radio, ssids []SSID, peers []ftpeer.Peer) (string, *layout) {
	t.Helper()
	exists := func(n string) bool { return regexp.MustCompile(`^wl[01][1-6]?$`).MatchString(n) }
	l := planLayout(Desired{Country: "US", Radios: map[string]Radio{band: r}, SSIDs: ssids}, exists, layoutOpts{anyVifOnLAN: true, guestOK: true})
	rl := l.radio(band)
	a := New(Options{})
	a.SetFTPeers(peers)
	hr := hapdRadio{Band: band, Channel: r.Channel, Country: "US", MaxSta: defaultMaxSta, RunDir: DefaultRunDir,
		Placeholder: hapdPlaceholder{Vif: bandPrimary[band] + "1", SSID: "udeco-0123456789ab", Passphrase: testPlaceholderPSK}}
	for i, u := range rl.Used {
		a.macs[u.Vif] = "be:a7:b9:3e:17:0" + string(rune('5'+i))
	}
	for _, u := range rl.Used {
		hr.BSS = append(hr.BSS, hapdBSS{Vif: u.Vif, BSSID: a.macs[u.Vif], Bridge: u.Bridge, SSID: u.SSID, FTPeers: a.peersFor(u.SSID, band, u.Bridge)})
	}
	conf, err := renderHostapd(hr)
	if err != nil {
		t.Fatal(err)
	}
	return conf, l
}

// A WPA2/WPA3 transition SSID with fast roaming and WPA3 fast roaming:
// WPA2 clients roam with FT-PSK (keys generated locally), SAE clients with
// FT-SAE, whose PMK-R1 moves between APs over RRB with the controller's
// key. hostapd 2.9 cannot use UniFi's wildcard holders (its broadcast PULL
// never leaves the process), so each peer BSS is listed explicitly: one
// r0kh (BSSID, its nas_identifier) and one r1kh (BSSID, its r1_key_holder)
// per peer of the same WLAN key, mobility domain and bridge, never this
// unit's own BSSes; the mobility domain is the band's.
func TestFTSAETransitionConf(t *testing.T) {
	peers := []ftpeer.Peer{
		ftPeer("02:11:22:33:44:66", "na", "Example Network", testFTKey, "br-lan"),
		ftPeer("02:11:22:33:44:55", "na", "Example Network", testFTKey, "br-lan"),
		ftPeer("02:11:22:33:44:55", "na", "Example Network", testFTKey, "br-lan"),         // twice: listed once
		ftPeer("02:11:22:33:44:44", "ng", "Example Network", testFTKey, "br-lan"),         // 2.4 GHz: another MDID
		ftPeer("02:11:22:33:44:77", "na", "Example Network", testFTKey[1:]+"0", "br-lan"), // another WLAN's key
		ftPeer("02:11:22:33:44:88", "na", "Example Network", testFTKey, "br-v20"),         // another L2 network
		ftPeer("be:a7:b9:3e:17:05", "na", "Example Network", testFTKey, "br-lan"),         // this unit's own BSS
	}
	conf, l := renderFTCase(t, "na", Radio{Enabled: true, Channel: 44}, []SSID{ftTransition()}, peers)
	if n := strings.Join(l.Notes, "\n"); strings.Contains(n, "802.11r") || strings.Contains(n, testFTKey) {
		t.Errorf("notes: %q", l.Notes)
	}
	sec := bssSection(t, conf)
	want := map[string]string{
		"wpa_key_mgmt":           "WPA-PSK FT-PSK SAE FT-SAE",
		"ieee80211w":             "1",
		"sae_require_mfp":        "1",
		"mobility_domain":        fmt.Sprintf("%04x", bandMobilityDomain("Example Network", "na")),
		"nas_identifier":         "bea7b93e1705",
		"r1_key_holder":          "bea7b93e1705",
		"ft_over_ds":             "0",
		"ft_psk_generate_local":  "1",
		"reassociation_deadline": "1000",
		"pmk_r1_push":            "1",
	}
	for k, v := range want {
		if got := confValue(sec, k); got != v {
			t.Errorf("%s=%q, want %q", k, got, v)
		}
	}
	if r0, r1 := checkFTLines(t, sec); r0 != testFTKey || r1 != testFTKey {
		t.Errorf("r0kh/r1kh keys are not the controller's")
	}
	got := regexp.MustCompile(`(?m)^r[01]kh=.*$`).FindAllString(sec, -1)
	wantLines := []string{
		"r0kh=02:11:22:33:44:55 021122334455 " + testFTKey,
		"r1kh=02:11:22:33:44:55 02:11:22:33:44:55 " + testFTKey,
		"r0kh=02:11:22:33:44:66 021122334466 " + testFTKey,
		"r1kh=02:11:22:33:44:66 02:11:22:33:44:66 " + testFTKey,
	}
	if strings.Join(got, "\n") != strings.Join(wantLines, "\n") {
		t.Errorf("peer lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantLines, "\n"))
	}
	if strings.Contains(sec, "ff:ff:ff:ff:ff:ff") || strings.Contains(sec, "00:00:00:00:00:00") {
		t.Errorf("wildcard key holder written (hostapd 2.9 never sends its PULL):\n%s", sec)
	}
	// The placeholder BSS never gets FT.
	if ph := conf[:strings.Index(conf, "\nbss=")]; strings.Contains(ph, "r0kh") || strings.Contains(ph, "FT-") {
		t.Errorf("placeholder has FT:\n%s", ph)
	}
	// No peer known yet: FT-SAE is still built (a station's first SAE
	// works, and a peer added later goes in live), no r0kh/r1kh line.
	conf, _ = renderFTCase(t, "na", Radio{Enabled: true, Channel: 44}, []SSID{ftTransition()}, nil)
	sec = bssSection(t, conf)
	if confValue(sec, "wpa_key_mgmt") != "WPA-PSK FT-PSK SAE FT-SAE" || strings.Contains(sec, "kh=") || confValue(sec, "pmk_r1_push") != "1" {
		t.Errorf("FT-SAE without peers:\n%s", sec)
	}
}

// The two bands of one SSID get different mobility domains under FT-SAE
// (one unit's radios cannot pass a PMK-R1 between their two hostapds, so a
// cross-band roam must not be an FT attempt), and every unit derives the
// same ones; FT-PSK alone keeps the one SSID-wide domain it always had.
func TestFTSAEPerBandMobilityDomain(t *testing.T) {
	for _, ssid := range []string{"Example Network", "olive#", "Home 5G", "x"} {
		ng, na := bandMobilityDomain(ssid, "ng"), bandMobilityDomain(ssid, "na")
		if ng == na || ng == 0 || na == 0 {
			t.Errorf("%q: ng %04x na %04x", ssid, ng, na)
		}
		s := SSID{SSID: ssid, FT: true, FTSAE: true}
		if ssidMDID(s, "ng") != ng || ssidMDID(s, "na") != na {
			t.Errorf("%q: ssidMDID does not use the band", ssid)
		}
		s.FTSAE = false
		if ssidMDID(s, "ng") != mobilityDomain(ssid) || ssidMDID(s, "na") != mobilityDomain(ssid) {
			t.Errorf("%q: FT-PSK mobility domain changed", ssid)
		}
		s.FTSAE, s.MobilityDomain = true, "c0de"
		if ssidMDID(s, "ng") != 0xc0de || ssidMDID(s, "na") != 0xc0de {
			t.Errorf("%q: the controller's mobility domain is not used as sent", ssid)
		}
	}
}

// WPA3 only: SAE and FT-SAE, PMF required, no PSK key generation.
func TestFTSAEWPA3OnlyConf(t *testing.T) {
	s := ftTransition()
	s.Security, s.PMF = SecWPA3, ""
	conf, l := renderFTCase(t, "na", Radio{Enabled: true}, []SSID{s}, []ftpeer.Peer{ftPeer("02:11:22:33:44:55", "na", s.SSID, testFTKey, "br-lan")})
	sec := bssSection(t, conf)
	if got := confValue(sec, "wpa_key_mgmt"); got != "SAE FT-SAE" {
		t.Errorf("wpa_key_mgmt=%q (notes %q)", got, l.Notes)
	}
	if confValue(sec, "ieee80211w") != "2" || confValue(sec, "sae_require_mfp") != "1" {
		t.Errorf("SAE without required PMF:\n%s", sec)
	}
	if strings.Contains(sec, "ft_psk_generate_local") || strings.Contains(sec, "WPA-PSK") {
		t.Errorf("PSK lines on a WPA3-only BSS:\n%s", sec)
	}
	if r0, r1 := checkFTLines(t, sec); r0 != testFTKey || r1 != testFTKey {
		t.Errorf("no peer lines with the key:\n%s", sec)
	}
	if confValue(sec, "pmk_r1_push") != "1" {
		t.Error("no pmk_r1_push")
	}
}

// Without the controller's WPA3 fast roaming or without a usable key, no
// FT-SAE: a transition SSID keeps FT-PSK, a WPA3-only one loses 802.11r.
// The key is never in a note.
func TestFTSAEFallbacks(t *testing.T) {
	cases := []struct {
		name     string
		mod      func(*SSID)
		mgmt     string
		note     string
		noFTKeys bool
	}{
		{"no wpa3 fast roaming", func(s *SSID) { s.FTSAE = false }, "WPA-PSK FT-PSK SAE", "radio_caps2 0x2", true},
		{"no key", func(s *SSID) { s.FTKey = "" }, "WPA-PSK FT-PSK SAE", "none sent", true},
		{"bad key", func(s *SSID) { s.FTKey = testFTKey[:30] + "zz" }, "WPA-PSK FT-PSK SAE", "not 32 or 64 hex", true},
		{"wpa3 only no key", func(s *SSID) { s.Security, s.FTKey = SecWPA3, "" }, "SAE", "802.11r off", true},
		{"wpa2 with key", func(s *SSID) { s.Security = SecWPA2 }, "WPA-PSK FT-PSK", "", true},
		{"64 hex key", func(s *SSID) { s.FTKey = strings.ToUpper(testFTKey + testFTKey) }, "WPA-PSK FT-PSK SAE FT-SAE", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := ftTransition()
			c.mod(&s)
			// Peers for both keys are known: a BSS without FT-SAE must
			// list none of them (the key stays out of its conf).
			peers := []ftpeer.Peer{ftPeer("02:11:22:33:44:55", "na", s.SSID, testFTKey, "br-lan"),
				ftPeer("02:11:22:33:44:66", "na", s.SSID, testFTKey+testFTKey, "br-lan")}
			conf, l := renderFTCase(t, "na", Radio{Enabled: true}, []SSID{s}, peers)
			sec := bssSection(t, conf)
			if got := confValue(sec, "wpa_key_mgmt"); got != c.mgmt {
				t.Errorf("wpa_key_mgmt=%q, want %q", got, c.mgmt)
			}
			notes := strings.Join(l.Notes, "\n")
			if c.note != "" && !strings.Contains(notes, c.note) {
				t.Errorf("no note %q in %q", c.note, notes)
			}
			if strings.Contains(notes, testFTKey[:16]) || strings.Contains(strings.ToLower(notes), testFTKey[:16]) {
				t.Fatalf("key in a note: %q", notes)
			}
			if has := strings.Contains(sec, "r0kh=") || strings.Contains(sec, "r1kh=") || strings.Contains(sec, "pmk_r1_push"); has == c.noFTKeys {
				t.Errorf("r0kh/r1kh/push present=%t:\n%s", has, sec)
			}
			if !c.noFTKeys {
				if r0, _ := checkFTLines(t, sec); r0 != testFTKey+testFTKey {
					t.Errorf("key not lower-cased as written: %d chars", len(r0))
				}
			}
		})
	}
}

// The controller's mobility domain and FT over the DS reach hostapd and the
// driver (wl fbt_mdid, fbtoverds); a bad MDID falls back to the derived one.
func TestFTSAEMobilityDomainOverDS(t *testing.T) {
	s := ftTransition()
	s.MobilityDomain, s.FTOverDS = "A1B2", true
	conf, l := renderCase(t, "na", Radio{Enabled: true}, []SSID{s}, nil)
	sec := bssSection(t, conf)
	if confValue(sec, "mobility_domain") != "a1b2" || confValue(sec, "ft_over_ds") != "1" {
		t.Errorf("mdid/over-DS:\n%s", sec)
	}
	u := l.radio("na").Used[0]
	d := driverFor(u, "be:a7:b9:3e:17:05", 128, nil, false)
	if d.MDID != 0xb2a1 || d.OverDS != 1 {
		t.Errorf("driver %+v", d)
	}
	var argv []string
	for _, st := range driverSteps(d) {
		argv = append(argv, strings.Join(st.Argv, " "))
	}
	all := strings.Join(argv, "\n")
	if !strings.Contains(all, "fbt_mdid 45729") || !strings.Contains(all, "fbtoverds 1") {
		t.Errorf("driver steps:\n%s", all)
	}

	// Over the air only: fbtoverds untouched (a fresh vif reads 0).
	s.FTOverDS = false
	_, l = renderCase(t, "na", Radio{Enabled: true}, []SSID{s}, nil)
	d = driverFor(l.radio("na").Used[0], "be:a7:b9:3e:17:05", 128, nil, false)
	for _, st := range driverSteps(d) {
		if strings.Contains(strings.Join(st.Argv, " "), "fbtoverds") {
			t.Errorf("fbtoverds set with over-DS off: %v", st.Argv)
		}
	}

	s.MobilityDomain = "a1b2c3"
	conf, l = renderCase(t, "na", Radio{Enabled: true}, []SSID{s}, nil)
	if got := confValue(bssSection(t, conf), "mobility_domain"); got != fmt.Sprintf("%04x", bandMobilityDomain(s.SSID, "na")) {
		t.Errorf("bad MDID used: %s", got)
	}
	if !strings.Contains(strings.Join(l.Notes, "\n"), "not 4 hex digits") {
		t.Errorf("notes %q", l.Notes)
	}
}

// End to end on the fake unit: the key lands in the 0600 hostapd conf and
// the secrets half of last-good only, never in plan text, notes, the public
// last-good, drv-wlN.json (the key id only) or a printed Desired; each band
// lists the peers of its own mobility domain with the controller's key.
func TestFTSAEApplyKeepsKeySecret(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	a.o.WPA3 = true // SAE served (config wpa3); without it the SSID is WPA2 only
	a.o.FTSAE = true
	d := Desired{Country: "IN", Radios: map[string]Radio{"ng": {Enabled: true, Channel: 6}, "na": {Enabled: true, Channel: 44, Width: 80}}}
	s := ftTransition()
	s.Bands = []string{"ng", "na"}
	d.SSIDs = []SSID{s}
	a.SetFTPeers([]ftpeer.Peer{ftPeer("02:11:22:33:44:24", "ng", s.SSID, testFTKey, "br-lan"),
		ftPeer("02:11:22:33:44:50", "na", s.SSID, testFTKey, "br-lan")})
	p := applyOK(t, a, d)
	printed := p.String() + strings.Join(p.Notes, "\n") + fmt.Sprintf("%v %+v %#v", d.SSIDs, d.SSIDs, d.SSIDs)
	if strings.Contains(printed, testFTKey) {
		t.Fatalf("key printed:\n%s", printed)
	}
	r0 := map[string]string{}
	md := map[string]string{}
	peerOf := map[string]string{}
	for _, radio := range []string{"wl0", "wl1"} {
		path := f.path("/tmp/udeco/hapd-" + radio + ".conf")
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %o", radio, st.Mode().Perm())
		}
		sec := bssSection(t, string(b))
		r0[radio], _ = checkFTLines(t, sec)
		md[radio] = confValue(sec, "mobility_domain")
		peerOf[radio] = strings.Fields(confValue(sec, "r0kh") + " -")[0]
		drv, _ := os.ReadFile(f.path("/tmp/udeco/drv-" + radio + ".json"))
		if strings.Contains(string(drv), testFTKey) || !strings.Contains(string(drv), `"ft_key_id": "`+ftpeer.KeyID(testFTKey)+`"`) {
			t.Errorf("%s driver state: key in it, or no key id:\n%s", radio, drv)
		}
		if !regexp.MustCompile(`(?m)^wpa_key_mgmt=WPA-PSK FT-PSK SAE FT-SAE$`).MatchString(sec) {
			t.Errorf("%s: no FT-SAE:\n%s", radio, sec)
		}
	}
	if r0["wl0"] != testFTKey || r0["wl1"] != testFTKey {
		t.Errorf("peer lines without the controller's key")
	}
	if md["wl0"] != fmt.Sprintf("%04x", bandMobilityDomain(s.SSID, "ng")) || md["wl1"] != fmt.Sprintf("%04x", bandMobilityDomain(s.SSID, "na")) || md["wl0"] == md["wl1"] {
		t.Errorf("mobility domains %v: want one per band", md)
	}
	if peerOf["wl0"] != "02:11:22:33:44:24" || peerOf["wl1"] != "02:11:22:33:44:50" {
		t.Errorf("each band lists its own band's peer: %v", peerOf)
	}
	for _, band := range []string{"ng", "na"} {
		// the driver gets the byte-swapped MDID (it beacons little-endian)
		if !f.called("fbt_mdid " + fmt.Sprint(bits.ReverseBytes16(bandMobilityDomain(s.SSID, band)))) {
			t.Errorf("driver fbt_mdid for %s not the band's (byte-swapped)", band)
		}
	}
	if !f.called("fbt 1") {
		t.Error("driver FBT not set")
	}
	pub, _ := os.ReadFile(f.path("/tp_data/udeco/state/last-good.json"))
	sec, _ := os.ReadFile(f.path("/tp_data/udeco/state/last-good.secrets.json"))
	if strings.Contains(string(pub), testFTKey) {
		t.Errorf("public last-good has the key:\n%s", pub)
	}
	if !strings.Contains(string(sec), testFTKey) {
		t.Error("secrets half lacks the key: a rollback could not rebuild FT-SAE")
	}
	lg, err := a.loadLastGood()
	if err != nil || lg == nil || lg.SSIDs[0].FTKey != testFTKey {
		t.Fatalf("last-good key not restored: %v", err)
	}
	f.reset()
	if p2, err := a.Plan(ctx, d); err != nil || !p2.Empty() {
		t.Fatalf("second plan not empty (%v):\n%s", err, p2)
	}

	// Config wpa3 off: the SSID is WPA2 only, so no FT-SAE and no key in the
	// conf (the agent then does not claim radio_caps2 0x2 either).
	a.o.WPA3 = false
	p3, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range p3.Steps {
		if st.Kind == StepWrite && strings.HasPrefix(st.Path, "/tmp/udeco/hapd-") && strings.Contains(string(st.Data), testFTKey) {
			t.Errorf("%s keeps the FT key with SAE off", st.Path)
		}
	}
}

// FT-SAE is not served by default, even with SAE on and the controller
// sending wpa3.ft.status and a key: hostapd 2.9 keeps a wildcard R0KH's
// broadcast PMK-R1 PULL inside its own process (hostapd_wpa_auth_oui_iter
// hands it to the first other BSS, here the placeholder, and returns 1, so
// eth_p_oui_send never runs), so a target AP never gets the PMK-R1 and every
// FT-SAE roam would wait out rkh_pull_timeout and fail. The SSID keeps
// FT-PSK, SAE without FT, and no key in any file.
func TestFTSAEOffByDefault(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	a.o.WPA3 = true
	if a.ServesFTSAE() {
		t.Fatal("ServesFTSAE with the default options: the agent would claim radio_caps2 0x2")
	}
	d := Desired{Country: "IN", Radios: map[string]Radio{"ng": {Enabled: true, Channel: 6}, "na": {Enabled: true, Channel: 44, Width: 80}}}
	s := ftTransition()
	s.Bands = []string{"ng", "na"}
	d.SSIDs = []SSID{s}
	p := applyOK(t, a, d)
	if n := strings.Join(p.Notes, "\n"); !strings.Contains(n, "FT-SAE not built") || strings.Contains(n, testFTKey) {
		t.Errorf("notes %q", p.Notes)
	}
	for _, radio := range []string{"wl0", "wl1"} {
		b, err := os.ReadFile(f.path("/tmp/udeco/hapd-" + radio + ".conf"))
		if err != nil {
			t.Fatal(err)
		}
		sec := bssSection(t, string(b))
		if !regexp.MustCompile(`(?m)^wpa_key_mgmt=WPA-PSK FT-PSK SAE$`).MatchString(sec) {
			t.Errorf("%s: want FT-PSK and SAE without FT-SAE:\n%s", radio, sec)
		}
		for _, k := range []string{"\nr0kh=", "\nr1kh=", "\npmk_r1_push=", testFTKey} {
			if strings.Contains(sec, k) {
				t.Errorf("%s: %q in the conf without FT-SAE", radio, strings.TrimSpace(k))
			}
		}
	}
	if pub, _ := os.ReadFile(f.path("/tp_data/udeco/state/last-good.json")); strings.Contains(string(pub), testFTKey) {
		t.Error("key in the public last-good")
	}
	a.o.FTSAE = true
	if !a.ServesFTSAE() {
		t.Error("ServesFTSAE off with Options.WPA3 and Options.FTSAE")
	}
	a.o.WPA3 = false
	if a.ServesFTSAE() {
		t.Error("ServesFTSAE without SAE")
	}
}
