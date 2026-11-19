// SPDX-License-Identifier: GPL-2.0-or-later

package hs20

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// controllerCfg is what Network 11.1.50's generator (XHjguBsIf, the
// hotspot2conf writer) sends for a WPA-Enterprise WLAN at section 1 with a
// full hotspot2conf: key names, index placement and value shapes as it
// writes them (booleans as enabled/disabled, network_availability already
// combined as (v4<<2)+v6, the roaming consortium index before the key).
func controllerCfg(extra ...string) map[string]string {
	lines := []string{
		"aaa.1.hs20.status=enabled",
		"aaa.1.hs20.access_network_type=2",
		"aaa.1.hs20.internet=enabled",
		"aaa.1.hs20.asra=disabled",
		"aaa.1.hs20.esr=disabled",
		"aaa.1.hs20.uesa=disabled",
		"aaa.1.hs20.venue_group=2",
		"aaa.1.hs20.venue_type=8",
		"aaa.1.hs20.disable_dgaf=disabled",
		"aaa.1.hs20.deauth_req_timeout=60",
		"aaa.1.hs20.osu_ssid=OSU Sign-up",
		"aaa.1.hs20.gas_comeback_delay=10",
		"aaa.1.hs20.gas_frag_limit=1000",
		"aaa.1.hs20.network_availability=14",
		"aaa.1.hs20.network_auth_type=0",
		"aaa.1.hs20.network_auth_url=https://portal.example.com/tc",
		"aaa.1.hs20.anqp_domain_id=1234",
		"aaa.1.hs20.hessid=02:00:00:00:00:01",
		"aaa.1.hs20.venue_name.1.lang=eng",
		"aaa.1.hs20.venue_name.1.name=Example Cafe: Main Hall",
		"aaa.1.hs20.venue_name.1.url=https://example.com/venue",
		"aaa.1.hs20.venue_name.2.lang=fin",
		"aaa.1.hs20.venue_name.2.name=Esimerkki",
		"aaa.1.hs20.hs20_domain_name_list=example.com,example.net",
		"aaa.1.hs20.nai_realm.1.status=enabled",
		"aaa.1.hs20.nai_realm.1.encoding=0",
		"aaa.1.hs20.nai_realm.1.name=example.com",
		"aaa.1.hs20.nai_realm.1.eap_method=21",
		"aaa.1.hs20.nai_realm.1.eap_method.auth.1.id=2",
		"aaa.1.hs20.nai_realm.1.eap_method.auth.1.val=4",
		"aaa.1.hs20.nai_realm.1.eap_method.auth.2.id=5",
		"aaa.1.hs20.nai_realm.1.eap_method.auth.2.val=7",
		"aaa.1.hs20.nai_realm.2.status=disabled",
		"aaa.1.hs20.nai_realm.2.name=off.example",
		"aaa.1.hs20.nai_realm.2.eap_method=13",
		"aaa.1.hs20.1.roaming_consortium=506F9A",
		"aaa.1.hs20.2.roaming_consortium=001bc504bd",
		"aaa.1.hs20.3gpp.1.mcc=310",
		"aaa.1.hs20.3gpp.1.mnc=026",
		"aaa.1.hs20.3gpp.2.mcc=244",
		"aaa.1.hs20.3gpp.2.mnc=91",
		"aaa.1.hs20.friendly_name.1.language=eng",
		"aaa.1.hs20.friendly_name.1.text=Example Operator",
		"aaa.1.hs20.capab.1.protocol=6",
		"aaa.1.hs20.capab.1.port=443",
		"aaa.1.hs20.capab.1.status=open",
		"aaa.1.hs20.capab.2.protocol=17",
		"aaa.1.hs20.capab.2.port=500",
		"aaa.1.hs20.capab.2.status=unknown",
		"aaa.1.hs20.metrics.status=enabled",
		"aaa.1.hs20.metrics.info=1",
		"aaa.1.hs20.metrics.downlink_speed=100000",
		"aaa.1.hs20.metrics.uplink_speed=20000",
		"aaa.1.hs20.metrics.downlink_load=0",
		"aaa.1.hs20.metrics.uplink_load=0",
		"aaa.1.hs20.metrics.measurement=0",
		"aaa.1.osu.1.server_uri=https://osu.example.com/osu",
		"aaa.1.osu.1.nai=anonymous@example.com",
		"aaa.1.osu.1.nai2=anonymous@example.net",
		"aaa.1.osu.1.operating_class=517376",
		"aaa.1.osu.1.method_soap_xml_spp=enabled",
		"aaa.1.osu.1.method_oma_dm=disabled",
		"aaa.1.osu.1.friendly_name.1.language=eng",
		"aaa.1.osu.1.friendly_name.1.text=SP Red",
		"aaa.1.osu.1.description.1.language=eng",
		"aaa.1.osu.1.description.1.text=Free service for test purpose",
		"wireless.1.dgaf_disable=enabled",
	}
	cfg := map[string]string{}
	for _, l := range append(lines, extra...) {
		k, v, _ := strings.Cut(l, "=")
		cfg[k] = v
	}
	return cfg
}

const wantConf = `interworking=1
access_network_type=2
internet=1
asra=0
esr=0
uesa=0
venue_group=2
venue_type=8
hessid=02:00:00:00:00:01
venue_name=eng:Example Cafe: Main Hall
venue_name=fin:Esimerkki
venue_url=1:https://example.com/venue
network_auth_type=00https://portal.example.com/tc
ipaddr_type_availability=0e
domain_name=example.com,example.net
roaming_consortium=506f9a
roaming_consortium=001bc504bd
anqp_3gpp_cell_net=310,026;244,91
nai_realm=0,example.com,21[2:4][5:7]
gas_frag_limit=1000
gas_comeback_delay=10
hs20=1
disable_dgaf=1
anqp_domain_id=1234
hs20_deauth_req_timeout=60
hs20_oper_friendly_name=eng:Example Operator
hs20_wan_metrics=01:100000:20000:0:0:0
hs20_conn_capab=6:443:1
hs20_conn_capab=17:500:2
hs20_operating_class=517376
osu_ssid=4f5355205369676e2d7570
osu_server_uri=https://osu.example.com/osu
osu_friendly_name=eng:SP Red
osu_nai=anonymous@example.com
osu_nai2=anonymous@example.net
osu_method_list=1
osu_service_desc=eng:Free service for test purpose
`

func render(t *testing.T, c *Config) string {
	t.Helper()
	lines, err := c.Lines()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.Key + "=" + l.Value + "\n")
	}
	return b.String()
}

func TestParseControllerConfig(t *testing.T) {
	c, notes, off := Parse(controllerCfg(), "aaa.1.", "wireless.1.")
	if off != "" || c == nil {
		t.Fatalf("off=%q c=%v", off, c)
	}
	if len(notes) != 0 {
		t.Errorf("notes: %q", notes)
	}
	if got := render(t, c); got != wantConf {
		t.Errorf("conf:\n%s\nwant:\n%s", got, wantConf)
	}
}

// Every key written is one this hostapd parses (Keys: strings of the X20's
// /sbin/hostapd), and every line passes CheckLine.
func TestLinesUseOnlyKnownKeys(t *testing.T) {
	c, _, _ := Parse(controllerCfg(), "aaa.1.", "wireless.1.")
	lines, err := c.Lines()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, l := range lines {
		if !slices.Contains(Keys, l.Key) {
			t.Errorf("key %q is not in Keys", l.Key)
		}
		seen[l.Key] = true
	}
	for _, k := range Keys {
		if !seen[k] {
			t.Errorf("Keys lists %q but the full controller config does not write it", k)
		}
	}
}

func TestParseOff(t *testing.T) {
	for _, st := range []string{"", "disabled"} {
		cfg := map[string]string{"aaa.1.hs20.status": st, "aaa.1.hs20.venue_group": "2"}
		if c, notes, off := Parse(cfg, "aaa.1.", "wireless.1."); c != nil || notes != nil || off != "" {
			t.Errorf("status %q: c=%v notes=%q off=%q", st, c, notes, off)
		}
	}
}

// Terms and Conditions would need the AP to filter the station's traffic
// until it accepts; the VAP stays off instead of running unfiltered.
func TestTermsAndConditionsKeepsWLANOff(t *testing.T) {
	c, _, off := Parse(controllerCfg("aaa.1.hs20.t_c_filename=terms.html", "aaa.1.hs20.t_c_timestamp=1700000000"), "aaa.1.", "wireless.1.")
	if c != nil || !strings.Contains(off, "Terms and Conditions") {
		t.Fatalf("c=%v off=%q", c, off)
	}
}

// DGAF is disabled when either the hotspot2conf or the WLAN says so.
func TestDGAF(t *testing.T) {
	cfg := controllerCfg()
	delete(cfg, "wireless.1.dgaf_disable")
	c, _, _ := Parse(cfg, "aaa.1.", "wireless.1.")
	if c.DisableDGAF {
		t.Error("DGAF disabled with both flags off")
	}
	cfg["aaa.1.hs20.disable_dgaf"] = "enabled"
	if c, _, _ = Parse(cfg, "aaa.1.", "wireless.1."); !c.DisableDGAF {
		t.Error("aaa disable_dgaf ignored")
	}
}

// Entries hostapd would refuse are dropped with a note naming the index
// only; what is left still renders.
func TestBadEntriesDropped(t *testing.T) {
	cfg := controllerCfg(
		"aaa.1.hs20.3.roaming_consortium=xyz",
		"aaa.1.hs20.4.roaming_consortium=0011",
		"aaa.1.hs20.venue_name.3.lang=english",
		"aaa.1.hs20.venue_name.3.name=x",
		"aaa.1.hs20.venue_name.4.lang=eng",
		"aaa.1.hs20.venue_name.4.name=line\nbreak",
		"aaa.1.hs20.nai_realm.3.name=a,b",
		"aaa.1.hs20.nai_realm.3.eap_method=21",
		"aaa.1.hs20.nai_realm.4.name=ok.example",
		"aaa.1.hs20.nai_realm.4.eap_method=21",
		"aaa.1.hs20.nai_realm.4.eap_method.auth.1.id=2",
		"aaa.1.hs20.nai_realm.4.eap_method.auth.1.val=300",
		"aaa.1.hs20.3gpp.3.mcc=31",
		"aaa.1.hs20.3gpp.3.mnc=26",
		"aaa.1.hs20.capab.3.protocol=6",
		"aaa.1.hs20.capab.3.port=99999",
		"aaa.1.hs20.capab.3.status=open",
		"aaa.1.hs20.access_network_type=16",
		"aaa.1.hs20.hessid=not-a-mac",
		"aaa.1.hs20.icon.1.name=logo",
		"aaa.1.hs20.icon.1.data=data:image/png;base64,AAAA",
		"aaa.1.hs20.qos.status=enabled",
		"aaa.1.hs20.qos.map.1.low=0",
		"aaa.1.hs20.qos.map.1.high=63",
		"aaa.1.osu.1.icon.1.name=logo",
		"aaa.1.osu.2.server_uri=",
	)
	c, notes, off := Parse(cfg, "aaa.1.", "wireless.1.")
	if off != "" {
		t.Fatal(off)
	}
	got := render(t, c)
	for _, bad := range []string{"xyz", "=0011", "english", "break", "a,b", "300", "=31,", "99999", "hessid", "access_network_type=16", "logo", "qos"} {
		if strings.Contains(got, bad) {
			t.Errorf("conf contains %q:\n%s", bad, got)
		}
	}
	all := strings.Join(notes, "\n")
	for _, want := range []string{"roaming consortium 3", "roaming consortium 4", "venue name 3", "venue name 4", "NAI realm 3", "NAI realm 4",
		"3GPP network 3", "connection capability 3", "access_network_type", "HESSID", "1 icon(s)", "QoS map", "OSU provider 1: 1 icon", "OSU provider 2"} {
		if !strings.Contains(all, want) {
			t.Errorf("notes lack %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, "line\nbreak") || strings.Contains(all, "data:image") {
		t.Errorf("a note carries a value: %s", all)
	}
	if c.AccessNetworkType != 0 {
		t.Errorf("access network type %d", c.AccessNetworkType)
	}
}

func TestOSUWithoutSSIDDropped(t *testing.T) {
	cfg := controllerCfg()
	delete(cfg, "aaa.1.hs20.osu_ssid")
	c, notes, _ := Parse(cfg, "aaa.1.", "wireless.1.")
	if len(c.OSUProviders) != 0 || !strings.Contains(strings.Join(notes, "\n"), "without an OSU SSID") {
		t.Errorf("providers %v notes %q", c.OSUProviders, notes)
	}
	if strings.Contains(render(t, c), "osu_") {
		t.Error("OSU lines written without an OSU SSID")
	}
}

// CheckLine mirrors hostapd 2.9 config_file.c for the keys Lines writes.
func TestCheckLine(t *testing.T) {
	good := [][2]string{
		{"roaming_consortium", "506f9a"}, {"roaming_consortium", strings.Repeat("ab", 15)},
		{"venue_name", "eng:x"}, {"venue_name", "de:" + strings.Repeat("y", 252)},
		{"nai_realm", "0,example.com"}, {"nai_realm", "1,a.example;b.example,13[5:6],21[2:4][5:7]"},
		{"anqp_3gpp_cell_net", "244,91;310,026"}, {"network_auth_type", "00https://x"}, {"network_auth_type", "01"},
		{"ipaddr_type_availability", "0e"}, {"hs20_wan_metrics", "01:8000:1000:80:240:3000"},
		{"hs20_conn_capab", "1:0:0"}, {"osu_ssid", "6f7375"}, {"osu_method_list", "1 0"}, {"hessid", "02:00:00:00:00:01"},
		{"venue_url", "1:http://example.com/"}, {"gas_frag_limit", "1"},
	}
	for _, g := range good {
		if err := CheckLine(g[0], g[1]); err != nil {
			t.Errorf("%s=%s: %v", g[0], g[1], err)
		}
	}
	bad := [][2]string{
		{"roaming_consortium", "0011"}, {"roaming_consortium", "506f9"}, {"roaming_consortium", strings.Repeat("ab", 16)},
		{"venue_name", "x:name"}, {"venue_name", "english:x"}, {"venue_name", "eng:" + strings.Repeat("y", 253)}, {"venue_name", "eng"},
		{"nai_realm", "2,example.com"}, {"nai_realm", "0,"}, {"nai_realm", "0,a;;b"}, {"nai_realm", "0,x,21[1:2][1:2][1:2][1:2][1:2]"},
		{"nai_realm", "0,x,1,2,3,4,5,6"}, {"nai_realm", "0,x,21[1]"},
		{"anqp_3gpp_cell_net", "24,91"}, {"anqp_3gpp_cell_net", "244,9"}, {"network_auth_type", "1https://x"}, {"network_auth_type", "01https://x"},
		{"ipaddr_type_availability", "e"}, {"hs20_wan_metrics", "1:8000:1000:80:240:3000"}, {"hs20_conn_capab", "1:0"},
		{"osu_ssid", "OSU"}, {"osu_ssid", ""}, {"osu_method_list", "2"}, {"hessid", "0200.0000.0001"}, {"gas_frag_limit", "0"},
		{"venue_name", "eng:a\nb"}, {"domain_name", "a,,b"}, {"access_network_type", "16"}, {"no_such_key", "1"},
	}
	for _, b := range bad {
		if err := CheckLine(b[0], b[1]); err == nil {
			t.Errorf("%s=%q accepted", b[0], b[1])
		}
	}
}

func TestCloneIsDeep(t *testing.T) {
	c, _, _ := Parse(controllerCfg(), "aaa.1.", "wireless.1.")
	d := c.Clone()
	if !reflect.DeepEqual(c, d) {
		t.Fatal("clone differs")
	}
	d.NAIRealms[0].EAP[0].Auth[0].Val = 9
	d.OSUProviders[0].FriendlyNames[0].Text = "changed"
	d.Venue.Group = 9
	d.RoamingConsortia[0] = "ffffff"
	if reflect.DeepEqual(c, d) {
		t.Fatal("clone shares memory")
	}
	if (*Config)(nil).Clone() != nil {
		t.Fatal("nil clone")
	}
}

// Whatever the controller sends, Parse never yields a config Lines refuses:
// a refused line would stop every SSID of the radio.
func FuzzParseRendersOrDrops(f *testing.F) {
	f.Add("eng", "Name", "example.com", "21", "2", "4", "506f9a", "310", "026", "https://x", "6", "443", "open", "OSU")
	f.Add("e", "a\nb", "a,b;c", "x", "-1", "999", "zz", "3100", "2", "\x00", "-6", "70000", "maybe", "")
	f.Fuzz(func(t *testing.T, lang, name, realm, eap, aid, aval, rc, mcc, mnc, url, proto, port, status, osu string) {
		cfg := map[string]string{
			"aaa.1.hs20.status": "enabled", "aaa.1.hs20.venue_name.1.lang": lang, "aaa.1.hs20.venue_name.1.name": name,
			"aaa.1.hs20.venue_name.1.url": url, "aaa.1.hs20.nai_realm.1.name": realm, "aaa.1.hs20.nai_realm.1.eap_method": eap,
			"aaa.1.hs20.nai_realm.1.eap_method.auth.1.id": aid, "aaa.1.hs20.nai_realm.1.eap_method.auth.1.val": aval,
			"aaa.1.hs20.1.roaming_consortium": rc, "aaa.1.hs20.3gpp.1.mcc": mcc, "aaa.1.hs20.3gpp.1.mnc": mnc,
			"aaa.1.hs20.network_auth_type": aid, "aaa.1.hs20.network_auth_url": url, "aaa.1.hs20.hs20_domain_name_list": realm,
			"aaa.1.hs20.friendly_name.1.language": lang, "aaa.1.hs20.friendly_name.1.text": name,
			"aaa.1.hs20.capab.1.protocol": proto, "aaa.1.hs20.capab.1.port": port, "aaa.1.hs20.capab.1.status": status,
			"aaa.1.hs20.osu_ssid": osu, "aaa.1.osu.1.server_uri": url, "aaa.1.osu.1.nai": name, "aaa.1.osu.1.operating_class": rc,
			"aaa.1.osu.1.friendly_name.1.language": lang, "aaa.1.osu.1.friendly_name.1.text": name, "aaa.1.hs20.hessid": name,
			"aaa.1.hs20.metrics.status": "enabled", "aaa.1.hs20.metrics.info": aid, "aaa.1.hs20.metrics.downlink_speed": port,
		}
		c, _, off := Parse(cfg, "aaa.1.", "wireless.1.")
		if off != "" {
			return
		}
		lines, err := c.Lines()
		if err != nil {
			t.Fatalf("Parse kept a config Lines refuses: %v", err)
		}
		for _, l := range lines {
			if strings.ContainsAny(l.Value, "\x00\r\n") {
				t.Fatalf("line %s=%q", l.Key, l.Value)
			}
		}
	})
}
