// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// u6proCfg is the system_cfg a real U6 Pro got from Network 11.1.50
// (docs/reference/u6pro/config-apply/tmp_system.cfg.redacted), with the
// redacted secrets replaced by fakes and the controller ids shortened.
const u6proCfg = `# unifi
unifi.version=11.1.50
unifi.siteid=67c759ccaf278441021cd20d
unifi.key=fake-unifi-key
unifi.cfgcap_info=0x7
# system
system.analytics.status=disabled
system.timezone=IST-5:30
locale.timezone=IST-5:30
# users
users.status=enabled
users.1.name=3r4FNrkS
users.1.password=$6$fakesalt$fakehashfakehash
users.1.status=enabled
users.2.name=nobody
users.2.password=$6$x$y
users.2.shell=/bin/false
users.2.status=enabled
# wlans (radio)
radio.status=enabled
radio.countrycode=356
aaa.status=enabled
wireless.status=enabled
radio.outdoor=disabled
radio.1.phyname=wifi0
radio.1.ack.auto=disabled
radio.1.acktimeout=64
radio.1.ampdu.status=enabled
radio.1.clksel=1
radio.1.countrycode=356
radio.1.cwm.enable=0
radio.1.cwm.mode=0
radio.1.forbiasauto=0
radio.1.mode=master
radio.1.rate.auto=enabled
radio.1.rate.mcs=auto
radio.1.rfscan=disabled
radio.1.bcmc_l2_filter.status=enabled
radio.1.bgscan.status=disabled
radio.1.antenna.gain=4
radio.1.antenna=-1
radio.1.txpower_mode=medium
radio.1.txpower=6
radio.1.channel=13
radio.1.ieee_mode=11nght20
radio.1.hard_noisefloor.status=disabled
radio.1.devname=wifi0ap0
radio.1.status=enabled
radio.2.phyname=wifi1
radio.2.ack.auto=disabled
radio.2.acktimeout=64
radio.2.ampdu.status=enabled
radio.2.clksel=1
radio.2.countrycode=356
radio.2.cwm.enable=0
radio.2.cwm.mode=0
radio.2.forbiasauto=0
radio.2.mode=master
radio.2.rate.auto=enabled
radio.2.rate.mcs=auto
radio.2.rfscan=disabled
radio.2.bcmc_l2_filter.status=enabled
radio.2.bgscan.status=disabled
radio.2.antenna.gain=6
radio.2.antenna=-1
radio.2.txpower_mode=high
radio.2.txpower=6
radio.2.channel=40
radio.2.ieee_mode=11naht160
radio.2.acsdfs=enabled
radio.2.hard_noisefloor.status=disabled
radio.2.devname=wifi1ap1
radio.2.status=enabled
aaa.1.pmf.status=disabled
aaa.1.pmf.mode=0
aaa.1.ft.status=disabled
aaa.1.country_beacon=disabled
aaa.1.11k.status=disabled
aaa.1.br.devname=br0.2
aaa.1.devname=wifi0ap0
aaa.1.driver=madwifi
aaa.1.ssid=EXN IOT
aaa.1.status=enabled
aaa.1.verbose=2
aaa.1.wpa=2
aaa.1.eapol_version=2
aaa.1.wpa.group_rekey=0
aaa.1.p2p=disabled
aaa.1.p2p_cross_connect=disabled
aaa.1.proxy_arp=disabled
aaa.1.is_guest=false
aaa.1.tdls_prohibit=disabled
aaa.1.bss_transition=disabled
aaa.1.id=3
aaa.1.wpa.key.1.mgmt=WPA-PSK
aaa.1.wpa.psk=iot-secret-pass
aaa.1.wpa.1.pairwise=CCMP
aaa.1.pmf.cipher=AES-128-CMAC
aaa.1.radius.macacl.status=disabled
aaa.1.hide_ssid=false
wireless.1.mode=master
wireless.1.devname=wifi0ap0
wireless.1.id=3
wireless.1.status=enabled
wireless.1.authmode=1
wireless.1.l2_isolation=enabled
wireless.1.is_guest=false
wireless.1.security=none
wireless.1.addmtikie=disabled
wireless.1.ssid=EXN IOT
wireless.1.hide_ssid=false
wireless.1.mac_acl.status=enabled
wireless.1.mac_acl.policy=deny
wireless.1.wmm=enabled
wireless.1.uapsd=enabled
wireless.1.parent=wifi0
wireless.1.puren=0
wireless.1.pureg=0
wireless.1.usage=user
wireless.1.wds=disabled
wireless.1.mcast.enhance=0
wireless.1.multicast.inspect=true
wireless.1.autowds=disabled
wireless.1.vport=disabled
wireless.1.vwire=disabled
wireless.1.schedule_enabled=disabled
wireless.1.no2ghz_oui=disabled
wireless.1.element_adopt=disabled
wireless.1.iot=enabled
wireless.1.qbssload=disabled
wireless.1.advertise_ap_name=disabled
wireless.1.mcastrate=auto
wireless.1.bga_filter=enabled
wireless.1.dtim_period=1
wireless.1.minrate_data=1000
wireless.1.beacon_rate=1000
wireless.1.mgmt_rate=1000
wireless.1.minrate_cck_rates.status=true
aaa.1.iapp_key=fake-iapp-key-1
aaa.2.pmf.status=enabled
aaa.2.pmf.mode=1
aaa.2.ft.status=disabled
aaa.2.country_beacon=disabled
aaa.2.11k.status=disabled
aaa.2.br.devname=br0
aaa.2.devname=wifi1ap1
aaa.2.driver=madwifi
aaa.2.ssid=Example Network
aaa.2.status=enabled
aaa.2.verbose=2
aaa.2.wpa=2
aaa.2.eapol_version=2
aaa.2.wpa.group_rekey=3600
aaa.2.p2p=disabled
aaa.2.p2p_cross_connect=disabled
aaa.2.proxy_arp=enabled
aaa.2.is_guest=false
aaa.2.tdls_prohibit=disabled
aaa.2.bss_transition=disabled
aaa.2.id=1
aaa.2.wpa3.support=enabled
aaa.2.wpa3.transition=enabled
aaa.2.wpa3.ft.status=disabled
aaa.2.sae.anti_clogging=5
aaa.2.sae.sync=5
aaa.2.wpa.psk=home-secret-pass
aaa.2.wpa.key.1.mgmt=SAE
aaa.2.wpa.psk=home-secret-pass
aaa.2.wpa.1.pairwise=CCMP
aaa.2.pmf.cipher=AES-128-CMAC
aaa.2.radius.macacl.status=disabled
aaa.2.hide_ssid=false
wireless.2.mode=master
wireless.2.devname=wifi1ap1
wireless.2.id=1
wireless.2.status=enabled
wireless.2.authmode=1
wireless.2.l2_isolation=disabled
wireless.2.is_guest=false
wireless.2.security=none
wireless.2.addmtikie=disabled
wireless.2.ssid=Example Network
wireless.2.hide_ssid=false
wireless.2.mac_acl.status=enabled
wireless.2.mac_acl.policy=deny
wireless.2.wmm=enabled
wireless.2.uapsd=enabled
wireless.2.parent=wifi1
wireless.2.puren=0
wireless.2.pureg=1
wireless.2.usage=user
wireless.2.wds=disabled
wireless.2.mcast.enhance=1
wireless.2.multicast.inspect=true
wireless.2.autowds=disabled
wireless.2.vport=disabled
wireless.2.vwire=disabled
wireless.2.schedule_enabled=disabled
wireless.2.no2ghz_oui=disabled
wireless.2.element_adopt=disabled
wireless.2.advertise_ap_name=disabled
wireless.2.mcastrate=auto
wireless.2.bga_filter=enabled
wireless.2.dtim_period=3
wireless.2.btm_disassoc.status=disabled
aaa.2.iapp_key=fake-iapp-key-2
# mesh
mesh.status=enabled
mesh.version=3
mesh.essid=vwire-4f1f98f27eaa55d0
mesh.psk=fake-mesh-psk
# bandsteering
bandsteering.status=disabled
# stamgr
stamgr.status=disabled
# connectivity
connectivity.status=disabled
# vlan
vlan.status=enabled
vlan.1.devname=eth0
vlan.1.id=2
# bridge
bridge.status=enabled
bridge.1.devname=br0
bridge.1.fd=1
bridge.1.stp.status=disabled
bridge.1.port.1.devname=eth0
bridge.1.port.3.devname=wifi1ap1
bridge.2.devname=br0.2
bridge.2.fd=1
bridge.2.stp.status=disabled
bridge.2.port.1.devname=wifi0ap0
bridge.2.port.2.devname=eth0.2
# mark
mark.1.name=guest
mark.1.bits=2
# qos
qos.status=disabled
# netconf
netconf.status=enabled
netconf.1.status=enabled
netconf.1.devname=br0
netconf.1.ip=0.0.0.0
netconf.1.up=enabled
# mac acl
macacl.status=disabled
# dhcpc
dhcpc.status=enabled
dhcpc.1.status=enabled
dhcpc.1.devname=br0
# route
route.status=enabled
# resolv
resolv.status=enabled
resolv.host.1.name=U6Pro
# ebtables
ebtables.status=enabled
ebtables.1.cmd=-t broute -A BROUTING -i wifi0ap0 -p 802_1Q -j DROP
# iptables
iptables.status=disabled
ip6tables.status=disabled
# redirector
redirector.status=disabled
# ipset
ipset.status=disabled
# dnsmasq
dnsmasq.status=disabled
# syslog
syslog.status=enabled
syslog.level=7
syslog.remote.encrypt=enabled
syslog.remote.key=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
syslog.remote.ip=192.168.1.1
syslog.remote.port=5514
syslog.remote.status=enabled
netconsole.host=192.168.1.1
netconsole.port=5514
netconsole.status=enabled
# sshd
sshd.status=enabled
sshd.auth.passwd=enabled
sshd.1.status=enabled
sshd.1.ifname=br0
# ntpclient
ntpclient.status=enabled
ntpclient.1.status=enabled
ntpclient.1.server=0.ubnt.pool.ntp.org
# switch
switch.status=disabled
# pathmon
pathmon.status=enabled
pathmon.interval=5
pathmon.target.1.type=gateway
pathmon.target.2.type=uplink
# DPI Fingerprint
dpi.ip=192.168.1.1
dpi.port=10101
`

// u6proSecrets are the secret values in u6proCfg.
var u6proSecrets = []string{"fake-unifi-key", "$6$fakesalt", "iot-secret-pass", "home-secret-pass",
	"fake-iapp-key", "fake-mesh-psk", "00112233445566778899aabbccddeeff"}

func TestIntentU6Pro(t *testing.T) {
	in, notes := IntentFromCfg(u6proCfg)
	if in.Country != "IN" {
		t.Errorf("country %q", in.Country)
	}
	wantRadios := map[string]RadioIntent{
		"ng": {Enabled: true, Channel: 13, Width: 20, TxPowerMode: "medium"},
		"na": {Enabled: true, Channel: 40, Width: 160, TxPowerMode: "high"},
	}
	if !reflect.DeepEqual(in.Radios, wantRadios) {
		t.Errorf("radios:\n got %+v\nwant %+v", in.Radios, wantRadios)
	}
	wantWLANs := []WLANIntent{{
		ID: "3", SSID: "EXN IOT", Bands: []string{"ng"}, Enabled: true,
		Security: "wpa2", Passphrase: "iot-secret-pass", PMF: "disabled",
		VLAN: 2, Isolation: true, UAPSD: true, DTIM: map[string]int{"ng": 1},
		Devnames: map[string]string{"ng": "wifi0ap0"},
		// the enhanced-IoT WLAN: the controller turns its BSS Load element off
		NoBSSLoad: true,
	}, {
		ID: "1", SSID: "Example Network", Bands: []string{"na"}, Enabled: true,
		Security: "wpa2wpa3", Passphrase: "home-secret-pass", PMF: "optional", GroupRekey: 3600,
		UAPSD: true, ProxyARP: true, MulticastToUnicast: true, DTIM: map[string]int{"na": 3},
		Devnames: map[string]string{"na": "wifi1ap1"},
	}}
	if !reflect.DeepEqual(in.WLANs, wantWLANs) {
		t.Errorf("wlans:\n got %v\nwant %v", in.WLANs, wantWLANs)
	}
	// The controller's generated login starts with a digit: carried
	// (users.go accepts a leading digit, refuses all-digit names).
	if len(in.Users) != 1 || in.Users[0].Name != "3r4FNrkS" {
		t.Errorf("users %v", in.Users)
	}
	if in.LED != nil {
		t.Errorf("led %v", *in.LED)
	}
	if s := in.Syslog; s == nil || s.Host != "192.168.1.1" || s.Port != 5514 || !s.Encrypted || s.Level != 7 || len(s.Key) != 64 {
		t.Errorf("syslog %v", s)
	}
	for _, want := range []string{
		"users.2: nobody is an AP system account: left alone",
		`wireless.1 ("EXN IOT"): not supported, ignored: iot=enabled`,
		"mesh: wireless meshing is not supported (wired uplink only)",
		"netconsole: kernel log streaming is not supported",
		"sshd: the controller's SSH server settings are not applied",
		"ntpclient: NTP servers are not applied (time comes from the gateway)",
		"dpi: client fingerprint export is not supported",
		"system.timezone: not applied",
	} {
		if !contains(notes, want) {
			t.Errorf("missing note %q", want)
		}
	}
	// the real config's ordinary keys are all accounted for: nothing else
	// (pathmon is run by the agent: no note)
	if len(notes) != 8 {
		t.Errorf("%d notes:\n%s", len(notes), strings.Join(notes, "\n"))
	}
	assertNoSecrets(t, in, notes, u6proSecrets)
}

// wlan builds a one-radio system_cfg: a 2.4 and a 5 GHz radio and the
// given aaa.1/wireless.1 (and any other) lines.
func wlan(lines ...string) string {
	return "radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght20\nradio.2.phyname=wifi1\nradio.2.ieee_mode=11acvht80\n" +
		"wireless.1.ssid=net\nwireless.1.id=w1\nwireless.1.parent=wifi1\nwireless.1.devname=ath1\n" +
		strings.Join(lines, "\n") + "\n"
}

const psk = "aaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\naaa.1.wpa.psk=good-pass-1"

func TestIntentSecurity(t *testing.T) {
	tests := []struct {
		name, cfg      string
		sec, pmf, pass string // sec "" = left off
		radius         *Radius
		note           string // a note that must be present
	}{
		{name: "open", cfg: wlan(), sec: "open", pmf: "disabled"},
		{name: "wpa2", cfg: wlan(psk), sec: "wpa2", pmf: "disabled", pass: "good-pass-1"},
		{name: "wpa2 pmf required", cfg: wlan(psk, "aaa.1.pmf.status=enabled", "aaa.1.pmf.mode=2"), sec: "wpa2", pmf: "required", pass: "good-pass-1"},
		{name: "wpa3", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=SAE", "aaa.1.wpa.psk=s", "aaa.1.pmf.status=enabled", "aaa.1.pmf.mode=2"),
			sec: "wpa3", pmf: "required", pass: "s"},
		{name: "wpa3 pmf raised", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=SAE", "aaa.1.wpa.psk=s3cret-sae"),
			sec: "wpa3", pmf: "required", pass: "s3cret-sae", note: "PMF disabled raised to required (wpa3 needs it)"},
		{name: "wpa2wpa3", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=SAE", "aaa.1.wpa3.support=enabled", "aaa.1.wpa3.transition=enabled",
			"aaa.1.wpa.psk=good-pass-1", "aaa.1.pmf.status=enabled", "aaa.1.pmf.mode=1"), sec: "wpa2wpa3", pmf: "optional", pass: "good-pass-1"},
		{name: "wpa2wpa3 pmf raised", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=SAE WPA-PSK", "aaa.1.wpa.psk=good-pass-1"),
			sec: "wpa2wpa3", pmf: "optional", pass: "good-pass-1", note: "raised to optional"},
		{name: "no key mgmt", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.psk=good-pass-1"), sec: "wpa2", pmf: "disabled", pass: "good-pass-1", note: "no key mgmt listed, assumed WPA2-PSK"},
		{name: "wpa/wpa2 mixed", cfg: wlan(strings.Replace(psk, "wpa=2", "wpa=3", 1)), sec: "wpa2", pmf: "disabled", pass: "good-pass-1", note: "WPA/WPA2 mixed mode: built as WPA2 only"},
		{name: "tkip", cfg: wlan(psk, "aaa.1.wpa.1.pairwise=TKIP CCMP"), sec: "wpa2", pmf: "disabled", pass: "good-pass-1", note: "TKIP is not supported: CCMP only"},
		{name: "wpa1", cfg: wlan(strings.Replace(psk, "wpa=2", "wpa=1", 1)), note: "WPA1 (TKIP) only is not supported: left off"},
		{name: "short passphrase", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-PSK", "aaa.1.wpa.psk=short"), note: "passphrase is not 8-63 characters"},
		{name: "hex psk", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-PSK", "aaa.1.wpa.psk="+strings.Repeat("ab", 32)),
			sec: "wpa2", pmf: "disabled", pass: strings.Repeat("ab", 32)},
		{name: "no passphrase", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-PSK"), note: "WPA personal without a passphrase: left off"},
		{name: "ppsk", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-PSK", "aaa.1.wpa.psk_radius=enabled"), note: "(PPSK) are not supported: left off"},
		{name: "ppsk radius is not enterprise", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-PSK", "aaa.1.wpa.psk_radius=enabled",
			"aaa.1.radius.auth.1.ip=10.0.0.5", "aaa.1.radius.auth.1.secret=radius-secret-1"), note: "(PPSK) are not supported: left off"},
		{name: "ppsk file with passphrase", cfg: wlan(psk, "aaa.1.wpa.psk_file.status=enabled", "aaa.1.wpa.psk_file.1.keyid=ppsk-key-1", "aaa.1.wpa.psk_file.1.vlanid=7"),
			sec: "wpa2", pmf: "disabled", pass: "good-pass-1", note: "private pre-shared key 1 has no passphrase: dropped"},
		{name: "ppsk file never open", cfg: wlan("aaa.1.wpa.psk_file.status=enabled", "aaa.1.wpa.psk_file.1.keyid=ppsk-key-1"), note: "not built as open"},
		{name: "sae password ids never open", cfg: wlan("aaa.1.sae.psk.1.id=ppsk-key-1", "aaa.1.sae.psk.1.vlan=7"), note: "not built as open"},
		{name: "sae control characters", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=SAE", "aaa.1.wpa.psk=s3cret-sae\t"), note: "control characters: left off"},
		{name: "wep", cfg: wlan("aaa.1.security=wep128", "aaa.1.wep.key=0123456789"), note: `security "wep128" (WEP) is not supported`},
		{name: "owe", cfg: wlan("aaa.1.wpa3.support=enabled"), sec: "owe", pmf: "required", note: "PMF disabled raised to required (owe needs it)"},
		{name: "owe mgmt", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=OWE", "aaa.1.pmf.status=enabled", "aaa.1.pmf.mode=2", "aaa.1.owe_devname=ath9"),
			sec: "owe", pmf: "required", note: "OWE transition"},
		{name: "wpa2 enterprise", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-EAP", "aaa.1.nas_identifier=ap1",
			"aaa.1.radius.auth.1.ip=10.0.0.5", "aaa.1.radius.auth.1.secret=radius-secret-1", "aaa.1.radius.auth.1.status=enabled",
			"aaa.1.radius.auth.2.ip=10.0.0.6", "aaa.1.radius.auth.2.port=11812", "aaa.1.radius.auth.2.secret=radius-secret-2",
			"aaa.1.radius.auth.3.ip=10.0.0.7", "aaa.1.radius.auth.3.status=disabled",
			"aaa.1.radius.acct.1.ip=10.0.0.5", "aaa.1.radius.acct.1.secret=radius-secret-3"),
			sec: "wpa2-enterprise", pmf: "disabled",
			radius: &Radius{NASID: "ap1",
				Auth: []RadiusServer{{"10.0.0.5", 1812, "radius-secret-1", nil}, {"10.0.0.6", 11812, "radius-secret-2", nil}},
				Acct: []RadiusServer{{"10.0.0.5", 1813, "radius-secret-3", nil}}}},
		{name: "wpa3 enterprise", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-EAP-SHA256", "aaa.1.pmf.status=enabled", "aaa.1.pmf.mode=2",
			"aaa.1.radius.auth.1.ip=10.0.0.5", "aaa.1.radius.auth.1.secret=radius-secret-1"),
			sec: "wpa3-enterprise", pmf: "required", radius: &Radius{Auth: []RadiusServer{{"10.0.0.5", 1812, "radius-secret-1", nil}}}},
		{name: "wpa2/wpa3 enterprise", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-EAP", "aaa.1.wpa3.support=enabled", "aaa.1.wpa3.transition=enabled",
			"aaa.1.radius.auth.1.ip=10.0.0.5", "aaa.1.radius.auth.1.secret=radius-secret-1", "aaa.1.pmf.status=enabled", "aaa.1.pmf.mode=1"),
			sec: "wpa2-enterprise", pmf: "optional", radius: &Radius{Auth: []RadiusServer{{"10.0.0.5", 1812, "radius-secret-1", nil}}},
			note: "WPA2/WPA3-Enterprise transition: built as wpa2-enterprise"},
		{name: "enterprise without wpa key", cfg: wlan("aaa.1.radius.auth.1.ip=10.0.0.5", "aaa.1.radius.auth.1.secret=radius-secret-1"),
			sec: "wpa2-enterprise", pmf: "disabled", radius: &Radius{Auth: []RadiusServer{{"10.0.0.5", 1812, "radius-secret-1", nil}}}},
		{name: "enterprise without server", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-EAP"), note: "WPA-Enterprise without a RADIUS auth server: left off"},
		{name: "suite b", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-EAP-SUITE-B-192", "aaa.1.radius.auth.1.ip=10.0.0.5"), note: "Suite B"},
		{name: "enhanced 192", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-EAP-SHA256", "aaa.1.wpa3.support=enabled", "aaa.1.wpa3.enhanced_192=enabled",
			"aaa.1.radius.auth.1.ip=10.0.0.5"), note: "Suite B"},
		{name: "radsec", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-EAP", "aaa.1.radius.auth.1.ip=10.0.0.5", "aaa.1.radius.auth.1.tls=enabled",
			"aaa.1.radius.auth.1.private_key_passwd=tls-key-pass"), note: "RadSec"},
		{name: "mac auth", cfg: wlan(psk, "aaa.1.radius.macacl.status=enabled", "aaa.1.radius.macacl.format=xx-xx-xx-xx-xx-xx",
			"aaa.1.radius.auth.1.ip=10.0.0.5", "aaa.1.radius.auth.1.secret=radius-secret-1"),
			sec: "wpa2", pmf: "disabled", pass: "good-pass-1",
			radius: &Radius{Auth: []RadiusServer{{"10.0.0.5", 1812, "radius-secret-1", nil}}, MACAuth: true, MACFormat: "xx-xx-xx-xx-xx-xx"}},
		{name: "mac auth open", cfg: wlan("aaa.1.radius.macacl.status=enabled", "aaa.1.radius.auth.1.ip=10.0.0.5"),
			sec: "open", pmf: "disabled", radius: &Radius{Auth: []RadiusServer{{"10.0.0.5", 1812, "", nil}}, MACAuth: true}},
		{name: "mac auth without server", cfg: wlan(psk, "aaa.1.radius.macacl.status=enabled"), note: "RADIUS MAC authentication without a RADIUS auth server: left off"},
	}
	secrets := []string{"good-pass-1", "radius-secret", "s3cret-sae", "tls-key-pass", "0123456789", "ppsk-key-1"}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, notes := IntentFromCfg(tc.cfg)
			if tc.sec == "" {
				if len(in.WLANs) != 0 {
					t.Fatalf("not left off: %v", in.WLANs)
				}
			} else {
				if len(in.WLANs) != 1 {
					t.Fatalf("wlans %v, notes %q", in.WLANs, notes)
				}
				w := in.WLANs[0]
				if w.Security != tc.sec || w.PMF != tc.pmf || w.Passphrase != tc.pass || !reflect.DeepEqual(w.Radius, tc.radius) {
					t.Errorf("got %s pmf=%s pass=%q radius=%v, want %s pmf=%s pass=%q radius=%v (notes %q)",
						w.Security, w.PMF, w.Passphrase, w.Radius, tc.sec, tc.pmf, tc.pass, tc.radius, notes)
				}
			}
			if tc.note != "" && !hasNote(notes, tc.note) {
				t.Errorf("no note containing %q in %q", tc.note, notes)
			}
			assertNoSecrets(t, in, notes, secrets)
		})
	}
}

func TestIntentWLANFeatures(t *testing.T) {
	tests := []struct {
		name  string
		cfg   string
		check func(w WLANIntent) bool
		note  string
	}{
		{"hidden", wlan("aaa.1.hide_ssid=true"), func(w WLANIntent) bool { return w.Hidden }, ""},
		{"hidden wireless", wlan("wireless.1.hide_ssid=true"), func(w WLANIntent) bool { return w.Hidden }, ""},
		{"guest", wlan("aaa.1.is_guest=true"), func(w WLANIntent) bool { return w.Guest }, "guest network"},
		{"isolation", wlan("wireless.1.l2_isolation=enabled"), func(w WLANIntent) bool { return w.Isolation }, ""},
		{"uapsd", wlan("wireless.1.uapsd=enabled"), func(w WLANIntent) bool { return w.UAPSD }, ""},
		{"proxy arp", wlan("aaa.1.proxy_arp=enabled"), func(w WLANIntent) bool { return w.ProxyARP }, ""},
		{"multicast enhancement", wlan("wireless.1.mcast.enhance=1"), func(w WLANIntent) bool { return w.MulticastToUnicast }, ""},
		{"multicast enhancement off", wlan("wireless.1.mcast.enhance=0"), func(w WLANIntent) bool { return !w.MulticastToUnicast }, ""},
		{"802.11k", wlan("aaa.1.11k.status=enabled"), func(w WLANIntent) bool { return w.RRM }, ""},
		{"802.11v", wlan("aaa.1.bss_transition=enabled"), func(w WLANIntent) bool { return w.BSSTransition }, ""},
		{"802.11r", wlan(psk, "aaa.1.ft.status=enabled", "aaa.1.mobility_domain=a1b2"),
			func(w WLANIntent) bool { return w.FT && w.MobilityDomain == "a1b2" }, ""},
		{"802.11r open", wlan("aaa.1.ft.status=enabled"), func(w WLANIntent) bool { return !w.FT }, "802.11r on an open/OWE network"},
		{"802.11r wpa3 without ft-sae", wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=SAE", "aaa.1.wpa.psk=x", "aaa.1.ft.status=enabled", "aaa.1.wpa3.ft.status=disabled"),
			func(w WLANIntent) bool { return !w.FT }, "FT-SAE"},
		{"group rekey", wlan(psk, "aaa.1.wpa.group_rekey=3600"), func(w WLANIntent) bool { return w.GroupRekey == 3600 }, ""},
		{"group rekey bad", wlan(psk, "aaa.1.wpa.group_rekey=soon"), func(w WLANIntent) bool { return w.GroupRekey == 0 }, "group rekey interval not recognised"},
		{"vlan from aaa bridge", wlan("aaa.1.br.devname=br0.77"), func(w WLANIntent) bool { return w.VLAN == 77 }, ""},
		{"vlan from bridge sections", wlan("vlan.1.devname=eth0", "vlan.1.id=30", "bridge.2.devname=br0.30",
			"bridge.2.port.1.devname=ath1", "bridge.2.port.2.devname=eth0.30"), func(w WLANIntent) bool { return w.VLAN == 30 }, ""},
		{"untagged", wlan("aaa.1.br.devname=br0"), func(w WLANIntent) bool { return w.VLAN == 0 }, ""},
		{"vlan out of range", wlan("aaa.1.br.devname=br0.5000"), func(w WLANIntent) bool { return w.VLAN == 0 }, "out of range"},
		{"dtim", wlan("wireless.1.dtim_period=3"), func(w WLANIntent) bool { return reflect.DeepEqual(w.DTIM, map[string]int{"na": 3}) }, ""},
		{"dtim bad", wlan("wireless.1.dtim_period=0"), func(w WLANIntent) bool { return w.DTIM == nil }, "dtim_period"},
		{"min rate", wlan("wireless.1.minrate_data=12000"), func(w WLANIntent) bool { return reflect.DeepEqual(w.MinRateKbps, map[string]int{"na": 12000}) }, ""},
		{"min rate default", wlan("wireless.1.minrate_data=6000"), func(w WLANIntent) bool { return w.MinRateKbps == nil }, ""},
		{"min rate 2.4 no cck", strings.Replace(wlan("wireless.1.minrate_data=1000", "wireless.1.minrate_cck_rates.status=false"), "parent=wifi1", "parent=wifi0", 1),
			func(w WLANIntent) bool { return reflect.DeepEqual(w.MinRateKbps, map[string]int{"ng": 6000}) }, ""},
		{"mac filter", wlan("macacl.status=enabled", "macacl.1.devname=ath1", "macacl.1.status=enabled", "macacl.1.acl.status=enabled",
			"macacl.1.acl.policy=allow", "macacl.1.acl.1.mac=AA:BB:CC:00:00:01", "macacl.1.acl.2.mac=aa:bb:cc:00:00:02", "macacl.1.acl.3.mac=aa:bb:cc:00:00:03", "macacl.1.acl.3.status=disabled"),
			func(w WLANIntent) bool {
				return reflect.DeepEqual(w.MACFilter, &MACFilter{Policy: "allow", MACs: []string{"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"}})
			}, ""},
		{"mac filter empty deny", wlan("wireless.1.mac_acl.status=enabled", "wireless.1.mac_acl.policy=deny", "macacl.status=disabled"),
			func(w WLANIntent) bool { return w.MACFilter == nil }, ""},
		{"mac filter empty allow", wlan("wireless.1.mac_acl.status=enabled", "wireless.1.mac_acl.policy=allow"),
			func(w WLANIntent) bool { return reflect.DeepEqual(w.MACFilter, &MACFilter{Policy: "allow"}) }, "MAC allow list is empty: no client can join"},
		{"mac filter in wireless section", wlan("wireless.1.mac_acl.status=enabled", "wireless.1.mac_acl.policy=allow",
			"wireless.1.mac_acl.1.mac=AA:BB:CC:00:00:01", "wireless.1.mac_acl.2.mac=aa:bb:cc:00:00:02"),
			func(w WLANIntent) bool {
				return reflect.DeepEqual(w.MACFilter, &MACFilter{Policy: "allow", MACs: []string{"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"}})
			}, ""},
		{"mac deny list in wireless section", wlan("wireless.1.mac_acl.status=enabled", "wireless.1.mac_acl.policy=deny", "wireless.1.mac_acl.1.mac=aa:bb:cc:00:00:09"),
			func(w WLANIntent) bool {
				return reflect.DeepEqual(w.MACFilter, &MACFilter{Policy: "deny", MACs: []string{"aa:bb:cc:00:00:09"}})
			}, ""},
		{"mac filter deny default with macacl list", wlan("wireless.1.mac_acl.status=enabled", "wireless.1.mac_acl.policy=deny",
			"macacl.status=enabled", "macacl.1.devname=ath1", "macacl.1.status=enabled", "macacl.1.acl.status=enabled",
			"macacl.1.acl.policy=allow", "macacl.1.acl.1.mac=aa:bb:cc:00:00:01"),
			func(w WLANIntent) bool {
				return reflect.DeepEqual(w.MACFilter, &MACFilter{Policy: "allow", MACs: []string{"aa:bb:cc:00:00:01"}})
			}, ""},
		{"802.11r bad mobility domain", wlan(psk, "aaa.1.ft.status=enabled", "aaa.1.mobility_domain=a1b2c3"),
			func(w WLANIntent) bool { return w.FT && w.MobilityDomain == "" }, "not 4 hex digits"},
		// A UAP is up during the windows; schedule_invert=enabled: down during them.
		{"schedule on during", wlan("wireless.1.schedule_enabled=enabled",
			"wireless.1.schedule_mon.0=0800-1659", "wireless.1.schedule_mon.1=1600-1759", "wireless.1.schedule_sat.0=2200-0159"),
			func(w WLANIntent) bool {
				return reflect.DeepEqual(w.Schedule, []string{"mon 0800-1800", "sat 2200-2400", "sun 0000-0200"}) && w.Enabled
			}, ""},
		{"schedule off during", wlan("wireless.1.schedule_enabled=enabled", "wireless.1.schedule_invert=enabled", "wireless.1.schedule_tue.0=0100-0459"),
			func(w WLANIntent) bool {
				return len(w.Schedule) == 8 && w.Schedule[1] == "tue 0000-0100" && w.Schedule[2] == "tue 0500-2400" && w.Schedule[0] == "mon 0000-2400"
			}, ""},
		{"schedule all day every day", wlan("wireless.1.schedule_enabled=enabled", "wireless.1.schedule_mon.0=0000-2359", "wireless.1.schedule_tue.0=0000-2359",
			"wireless.1.schedule_wed.0=0000-2359", "wireless.1.schedule_thu.0=0000-2359", "wireless.1.schedule_fri.0=0000-2359",
			"wireless.1.schedule_sat.0=0000-2359", "wireless.1.schedule_sun.0=0000-2359"),
			func(w WLANIntent) bool { return w.Schedule == nil && w.Enabled }, ""},
		{"schedule off during nothing", wlan("wireless.1.schedule_enabled=enabled", "wireless.1.schedule_invert=enabled"),
			func(w WLANIntent) bool { return w.Schedule == nil && w.Enabled }, ""},
		{"schedule never on", wlan("wireless.1.schedule_enabled=enabled"),
			func(w WLANIntent) bool { return !w.Enabled }, "broadcast schedule never on"},
		{"rate limit", wlan("qos.status=enabled", "qos.vap.1.devname=ath1", "qos.vap.1.dwnlink.maxspeed=10000", "qos.vap.1.uplink.1.maxspeed=2000"),
			func(w WLANIntent) bool {
				return reflect.DeepEqual(w.RateLimit, &RateLimit{DownKbps: 10000, UpKbps: 2000})
			}, ""},
		{"disabled", wlan("wireless.1.status=disabled"), func(w WLANIntent) bool { return !w.Enabled && reflect.DeepEqual(w.Bands, []string{"na"}) }, ""},
		{"aaa disabled", wlan("aaa.1.status=disabled"), func(w WLANIntent) bool { return !w.Enabled }, ""},
		{"all wlans off", wlan("wireless.status=disabled"), func(w WLANIntent) bool { return !w.Enabled }, "wireless.status=disabled"},
		{"id from aaa", strings.Replace(wlan("aaa.1.id=a7"), "wireless.1.id=w1\n", "", 1), func(w WLANIntent) bool { return w.ID == "a7" }, ""},
		{"id from ssid", strings.Replace(wlan(), "wireless.1.id=w1\n", "", 1), func(w WLANIntent) bool { return w.ID == "net" }, ""},
		{"devname", wlan(), func(w WLANIntent) bool { return reflect.DeepEqual(w.Devnames, map[string]string{"na": "ath1"}) }, ""},
		{"pure g on 2.4", strings.Replace(wlan("wireless.1.pureg=1"), "parent=wifi1", "parent=wifi0", 1), func(w WLANIntent) bool { return true }, "pureg=1"},
		{"unsupported key", wlan("wireless.1.multicast.suppressor=enabled"), func(w WLANIntent) bool { return true },
			`wireless.1 ("net"): not supported, ignored: multicast.suppressor=enabled`},
		{"unknown keys", wlan("wireless.1.frobnicate=7", "aaa.1.ppsk.1.value=hunter2-pass"), func(w WLANIntent) bool { return true },
			`aaa.1: unrecognised keys, ignored: ppsk.1.value`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, notes := IntentFromCfg(tc.cfg)
			if len(in.WLANs) != 1 {
				t.Fatalf("wlans %v, notes %q", in.WLANs, notes)
			}
			if !tc.check(in.WLANs[0]) {
				t.Errorf("got %v (notes %q)", in.WLANs[0], notes)
			}
			if tc.note != "" && !hasNote(notes, tc.note) {
				t.Errorf("no note containing %q in %q", tc.note, notes)
			}
			assertNoSecrets(t, in, notes, []string{"good-pass-1", "hunter2-pass"})
		})
	}
}

// TestIntentBands: a WLAN is one wireless.N/aaa.N pair per radio, merged by id.
func TestIntentBands(t *testing.T) {
	two := func(extra ...string) string {
		return "radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght20\nradio.2.phyname=wifi1\nradio.2.ieee_mode=11acvht80\n" + psk + "\n" +
			"aaa.2.wpa=2\naaa.2.wpa.key.1.mgmt=WPA-PSK\naaa.2.wpa.psk=good-pass-1\n" +
			"wireless.1.ssid=home\nwireless.1.id=w1\nwireless.1.parent=wifi0\nwireless.1.devname=ath0\nwireless.1.dtim_period=1\n" +
			"wireless.2.ssid=home\nwireless.2.id=w1\nwireless.2.parent=wifi1\nwireless.2.devname=ath1\nwireless.2.dtim_period=3\nwireless.2.minrate_data=24000\n" +
			strings.Join(extra, "\n") + "\n"
	}
	in, notes := IntentFromCfg(two())
	want := []WLANIntent{{ID: "w1", SSID: "home", Bands: []string{"ng", "na"}, Enabled: true, Security: "wpa2", Passphrase: "good-pass-1",
		PMF: "disabled", DTIM: map[string]int{"ng": 1, "na": 3}, MinRateKbps: map[string]int{"na": 24000},
		MinRateOpts: map[string]MinRateOpts{"na": {}}, Devnames: map[string]string{"ng": "ath0", "na": "ath1"}}}
	if !reflect.DeepEqual(in.WLANs, want) || len(notes) != 0 {
		t.Fatalf("got %v\nwant %v\nnotes %q", in.WLANs, want, notes)
	}

	in, _ = IntentFromCfg(two("wireless.1.status=disabled"))
	if w := in.WLANs[0]; !w.Enabled || !reflect.DeepEqual(w.Bands, []string{"na"}) {
		t.Errorf("one band off: %v", w)
	}
	in, _ = IntentFromCfg(two("wireless.1.status=disabled", "wireless.2.status=disabled"))
	if w := in.WLANs[0]; w.Enabled || !reflect.DeepEqual(w.Bands, []string{"ng", "na"}) {
		t.Errorf("both off: %v", w)
	}
	in, notes = IntentFromCfg(two("wireless.2.hide_ssid=true", "aaa.2.wpa.psk=other-pass-2"))
	if w := in.WLANs[0]; w.Hidden || w.Passphrase != "good-pass-1" {
		t.Errorf("first band's settings not used: %v", w)
	}
	// hidden is a per-band setting: kept for na as sent; the passphrase is not
	if w := in.WLANs[0]; !w.PerBand["na"].Hidden || w.PerBand["ng"].Hidden {
		t.Errorf("per-band hidden: %+v", w.PerBand)
	}
	if !contains(notes, `wlan "home": passphrase differ on na: the ng settings are used`) {
		t.Errorf("notes %q", notes)
	}
	// WPA3 on one radio only (an AP that claims SAE on 5 GHz alone): each
	// band keeps the controller's own security, PMF and 802.11r/k
	in, notes = IntentFromCfg(two("aaa.2.wpa3.support=enabled", "aaa.2.wpa3.transition=enabled",
		"aaa.2.wpa.key.1.mgmt=SAE", "aaa.2.pmf.status=enabled", "aaa.2.pmf.mode=1", "aaa.2.11k.status=enabled"))
	if w := in.WLANs[0]; w.Security != "wpa2" || w.PerBand["na"].Security != "wpa2wpa3" || w.PerBand["na"].PMF != "optional" ||
		!w.PerBand["na"].RRM || w.PerBand["ng"].Security != "wpa2" || w.PerBand["ng"].RRM {
		t.Errorf("per-band security: %+v", w.PerBand)
	}
	if hasNote(notes, "differ") {
		t.Errorf("per-band settings noted as dropped: %q", notes)
	}
	assertNoSecrets(t, in, notes, []string{"good-pass-1", "other-pass-2"})
	// an unsupported band is left off; the other still comes up
	in, notes = IntentFromCfg(two("aaa.2.wpa=1"))
	if w := in.WLANs[0]; !reflect.DeepEqual(w.Bands, []string{"ng"}) || !hasNote(notes, "WPA1") {
		t.Errorf("got %v notes %q", w, notes)
	}
}

func TestIntentSkippedWLANs(t *testing.T) {
	in, notes := IntentFromCfg(wlansCfg) // wlans_test.go
	var ssids []string
	for _, w := range in.WLANs {
		ssids = append(ssids, w.SSID)
	}
	if !reflect.DeepEqual(ssids, []string{"home", "visitors"}) {
		t.Errorf("wlans %v", in.WLANs)
	}
	if v := in.WLANs[1]; !v.Guest || v.Enabled || !v.Hidden || !v.Isolation {
		t.Errorf("visitors %v", v)
	}
	if !in.WLANs[0].FT || in.WLANs[0].Security != "wpa2wpa3" {
		t.Errorf("home %v", in.WLANs[0])
	}
	for _, want := range []string{
		`wireless.3 ("vwire-x"): mesh/uplink VAP: not supported (wired uplink only)`,
		`wireless.4 ("corp"): radio "wifi2" is not on this AP: ignored`,
		`wireless.5 ("element-x"): element-adopt SSID (adopting UniFi devices over Wi-Fi): not supported`,
	} {
		if !contains(notes, want) {
			t.Errorf("missing note %q in %q", want, notes)
		}
	}
	if in.Radios["na"].Enabled || !in.Radios["ng"].Enabled {
		t.Errorf("radios %+v", in.Radios)
	}
	assertNoSecrets(t, in, notes, []string{"s3cret-pass", "guest-pass-1"})

	// translate_test.go's cfg: the element-adopt and vwire VAPs are left out
	in, notes = IntentFromCfg(cfg)
	if len(in.WLANs) != 1 || in.WLANs[0].SSID != "home" || in.Country != "US" {
		t.Errorf("wlans %v country %q", in.WLANs, in.Country)
	}
	assertNoSecrets(t, in, notes, []string{"s3cret-pass", "elem-pass-1"})
}

func TestIntentRadios(t *testing.T) {
	base := "radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght40\nradio.2.phyname=wifi1\nradio.2.ieee_mode=11naht80\n"
	tests := []struct {
		name string
		cfg  string
		band string
		want RadioIntent
		note string
	}{
		{"auto", base + "radio.2.channel=auto\nradio.2.txpower=auto", "na", RadioIntent{Enabled: true, Width: 80, TxPowerMode: "auto"}, ""},
		{"channel", base + "radio.1.channel=6", "ng", RadioIntent{Enabled: true, Channel: 6, Width: 40, TxPowerMode: "auto"}, ""},
		{"bad channel", base + "radio.1.channel=6+", "ng", RadioIntent{Enabled: true, Width: 40, TxPowerMode: "auto"}, `channel "6+" not recognised`},
		{"he width", "radio.1.phyname=wifi1\nradio.1.ieee_mode=11axhe80", "na", RadioIntent{Enabled: true, Width: 80, TxPowerMode: "auto"}, ""},
		{"vht width", "radio.1.phyname=wifi1\nradio.1.ieee_mode=11acvht160", "na", RadioIntent{Enabled: true, Width: 160, TxPowerMode: "auto"}, ""},
		{"no width", "radio.1.phyname=wifi1\nradio.1.ieee_mode=11ax", "na", RadioIntent{Enabled: true, TxPowerMode: "auto"}, "has no channel width"},
		{"tx dBm", base + "radio.2.txpower=17", "na", RadioIntent{Enabled: true, Width: 80, TxPowerMode: "custom", TxPower: 17}, ""},
		{"tx custom", base + "radio.2.txpower_mode=custom\nradio.2.txpower=12", "na", RadioIntent{Enabled: true, Width: 80, TxPowerMode: "custom", TxPower: 12}, ""},
		{"tx preset", base + "radio.2.txpower_mode=low\nradio.2.txpower=12", "na", RadioIntent{Enabled: true, Width: 80, TxPowerMode: "low"}, ""},
		{"tx bad", base + "radio.2.txpower_mode=custom\nradio.2.txpower=max", "na", RadioIntent{Enabled: true, Width: 80, TxPowerMode: "auto"}, `tx power "max" not recognised`},
		{"tx unknown mode", base + "radio.2.txpower_mode=turbo", "na", RadioIntent{Enabled: true, Width: 80, TxPowerMode: "auto"}, `txpower_mode "turbo"`},
		{"disabled", base + "radio.2.status=disabled", "na", RadioIntent{Width: 80, TxPowerMode: "auto"}, ""},
		{"all disabled", base + "radio.status=disabled", "ng", RadioIntent{Width: 40, TxPowerMode: "auto"}, ""},
		{"min rssi", base + "stamgr.1.radio=na\nstamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=-75", "na",
			RadioIntent{Enabled: true, Width: 80, TxPowerMode: "auto", MinRSSI: -75}, ""},
		{"min rssi above noise", base + "stamgr.1.radio=ng\nstamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=20", "ng",
			RadioIntent{Enabled: true, Width: 40, TxPowerMode: "auto", MinRSSI: -75}, ""},
		{"min rssi off", base + "stamgr.1.radio=ng\nstamgr.1.minrssi.status=false\nstamgr.1.minrssi.rssi=-70", "ng",
			RadioIntent{Enabled: true, Width: 40, TxPowerMode: "auto"}, ""},
		{"stamgr disabled", base + "stamgr.status=disabled\nstamgr.1.radio=ng\nstamgr.1.minrssi.status=true\nstamgr.1.minrssi.rssi=-70", "ng",
			RadioIntent{Enabled: true, Width: 40, TxPowerMode: "auto"}, ""},
		{"max clients", base + "stamgr.2.radio=na\nstamgr.2.loadbalance.status=true\nstamgr.2.loadbalance.maxsta=30", "na",
			RadioIntent{Enabled: true, Width: 80, TxPowerMode: "auto", MaxClients: 30}, ""},
		{"stamgr other radio", base + "stamgr.3.radio=6e\nstamgr.3.loadbalance.status=true", "na",
			RadioIntent{Enabled: true, Width: 80, TxPowerMode: "auto"}, "stamgr.3: no 6e radio here"},
		{"band steering", base + "wireless.1.ssid=x\nwireless.1.parent=wifi0\nwireless.1.devname=ath0\nwireless.2.ssid=x\nwireless.2.parent=wifi1\nwireless.2.devname=ath1\n" +
			"bandsteering.status=enabled\nbandsteering.mode=prefer_5g\nbandsteering.1.status=enabled\nbandsteering.1.vap.1.devname=ath0\nbandsteering.1.vap.2.devname=ath1",
			"ng", RadioIntent{Enabled: true, Width: 40, TxPowerMode: "auto", BandSteer: "prefer_5g"}, ""},
		{"outdoor", base + "radio.outdoor=enabled", "ng", RadioIntent{Enabled: true, Width: 40, TxPowerMode: "auto"}, "outdoor mode is not supported"},
		{"fixed rate", base + "radio.1.rate.auto=disabled\nradio.1.rate.mcs=7", "ng", RadioIntent{Enabled: true, Width: 40, TxPowerMode: "auto"},
			"radio.1: not supported, ignored: rate.auto=disabled, rate.mcs=7"},
		{"unknown radio key", base + "radio.1.zap=1", "ng", RadioIntent{Enabled: true, Width: 40, TxPowerMode: "auto"}, "radio.1: unrecognised keys, ignored: zap"},
		{"second radio same band", base + "radio.3.phyname=wifi2\nradio.3.ieee_mode=11naht40", "na", RadioIntent{Enabled: true, Width: 80, TxPowerMode: "auto"},
			"a second na radio"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, notes := IntentFromCfg(tc.cfg)
			if got := in.Radios[tc.band]; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %+v, want %+v (notes %q)", got, tc.want, notes)
			}
			if tc.note != "" && !hasNote(notes, tc.note) {
				t.Errorf("no note containing %q in %q", tc.note, notes)
			}
		})
	}
}

func TestIntentCountry(t *testing.T) {
	tests := []struct{ cfg, want, note string }{
		{"radio.countrycode=840", "US", ""},
		{"radio.1.phyname=wifi0\nradio.1.countrycode=276", "DE", ""},
		{"radio.countrycode=356\nradio.1.phyname=wifi0\nradio.1.countrycode=840", "IN", "country US differs from IN"},
		{"radio.countrycode=9999", "", `radio.countrycode "9999": unknown country code`},
		{"", "", ""},
	}
	for _, tc := range tests {
		in, notes := IntentFromCfg(tc.cfg)
		if in.Country != tc.want || tc.note != "" && !hasNote(notes, tc.note) {
			t.Errorf("%q: country %q notes %q", tc.cfg, in.Country, notes)
		}
	}
}

func TestIntentDevice(t *testing.T) {
	yes, no := true, false
	tests := []struct {
		name   string
		cfg    string
		led    *bool
		syslog *SyslogIntent
		users  []User
		note   string
	}{
		{name: "nothing"},
		{name: "led on", cfg: "ledbar.status=enabled", led: &yes},
		{name: "led off", cfg: "ledbar.status=disabled\nledbar.brightness=100", led: &no},
		{name: "led colour", cfg: "ledbar.status=enabled\nledbar.color.1.r=255", led: &yes, note: "LED colour and brightness are not supported"},
		{name: "syslog plain", cfg: "syslog.status=enabled\nsyslog.remote.status=enabled\nsyslog.remote.ip=10.0.0.2",
			syslog: &SyslogIntent{Host: "10.0.0.2", Port: 514}},
		{name: "syslog off", cfg: "syslog.status=enabled\nsyslog.remote.status=disabled\nsyslog.remote.ip=10.0.0.2"},
		{name: "syslog encrypted", cfg: "syslog.status=enabled\nsyslog.level=5\nsyslog.remote.status=enabled\nsyslog.remote.ip=10.0.0.2\nsyslog.remote.port=5514\nsyslog.remote.encrypt=enabled\nsyslog.remote.key=" + strings.Repeat("ab", 32),
			syslog: &SyslogIntent{Host: "10.0.0.2", Port: 5514, Encrypted: true, Key: strings.Repeat("ab", 32), Level: 5}},
		{name: "syslog bad key", cfg: "syslog.status=enabled\nsyslog.remote.status=enabled\nsyslog.remote.ip=10.0.0.2\nsyslog.remote.encrypt=enabled\nsyslog.remote.key=nothex-key",
			note: "encrypted remote syslog without a valid key"},
		{name: "users", cfg: "users.status=enabled\nusers.1.name=admin\nusers.1.password=$6$s$h\nusers.1.status=enabled\nusers.2.name=root\nusers.2.password=$6$s$h\nusers.2.status=enabled",
			users: []User{{Name: "admin", Hash: "$6$s$h"}}, note: "users.2: root is an AP system account"},
		{name: "users off", cfg: "users.status=disabled\nusers.1.name=admin\nusers.1.password=$6$s$h\nusers.1.status=enabled"},
		{name: "static ip", cfg: "netconf.status=enabled\nnetconf.1.devname=br0\nnetconf.1.ip=10.0.0.9\nnetconf.1.netmask=255.255.255.0",
			note: "a static management address is not applied"},
		{name: "unknown section", cfg: "frobnicator.status=enabled", note: "frobnicator.*: section not recognised: ignored"},
		// served by the agent (internal/snmpagent), no note
		{name: "snmp", cfg: "snmp.status=enabled\nsnmp.community=snmp-secret"},
		// run by the agent (internal/mdnsbr), no note
		{name: "mdns_sd", cfg: "mdns_sd.status=enabled\nmdns_sd.filter.1.vlan=1\nmdns_sd.filter.1.policy=deny"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, notes := IntentFromCfg(tc.cfg)
			if !reflect.DeepEqual(in.LED, tc.led) || !reflect.DeepEqual(in.Syslog, tc.syslog) || !reflect.DeepEqual(in.Users, tc.users) {
				t.Errorf("led %v syslog %v users %v", in.LED, in.Syslog, in.Users)
			}
			if tc.note != "" && !hasNote(notes, tc.note) {
				t.Errorf("no note containing %q in %q", tc.note, notes)
			}
			if tc.note == "" && len(notes) != 0 {
				t.Errorf("unexpected notes %q", notes)
			}
			assertNoSecrets(t, in, notes, []string{"$6$s$h", "nothex-key", "snmp-secret", strings.Repeat("ab", 32)})
		})
	}
}

func TestScheduleOn(t *testing.T) {
	s := &Schedule{OnDuring: true, Windows: map[string][]string{"sun": {"2300-0059"}, "wed": {"0000-2400"}, "fri": {"2400-2400"}}}
	got, never := scheduleOn(s)
	if want := []string{"mon 0000-0100", "wed 0000-2400", "sun 2300-2400"}; !reflect.DeepEqual(got, want) || never {
		t.Errorf("got %v %v, want %v", got, never, want)
	}
	all := map[string][]string{}
	for _, d := range days {
		all[d] = []string{"0000-2400"}
	}
	if got, never := scheduleOn(&Schedule{OnDuring: true, Windows: all}); got != nil || never {
		t.Errorf("always on: %v %v", got, never)
	}
	if got, never := scheduleOn(&Schedule{Windows: all}); got != nil || !never {
		t.Errorf("always off: %v %v", got, never)
	}
}

// TestIntentPrintsNoSecrets: every way of printing an Intent masks secrets.
func TestIntentPrintsNoSecrets(t *testing.T) {
	in, _ := IntentFromCfg(wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-EAP", "aaa.1.radius.auth.1.ip=10.0.0.5",
		"aaa.1.radius.auth.1.secret=radius-secret-1") + "aaa.2.wpa=2\naaa.2.wpa.psk=good-pass-1\nwireless.2.ssid=b\nwireless.2.parent=wifi0\n" + u6proCfg)
	if len(in.WLANs) < 2 || in.Syslog == nil {
		t.Fatalf("fixture: %v", in)
	}
	assertNoSecrets(t, in, nil, append([]string{"radius-secret-1", "good-pass-1"}, u6proSecrets...))
}

func assertNoSecrets(t *testing.T, in Intent, notes []string, secrets []string) {
	t.Helper()
	texts := append([]string{}, notes...)
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		texts = append(texts, fmt.Sprintf(f, in), fmt.Sprintf(f, &in), fmt.Sprintf(f, in.WLANs))
		for _, w := range in.WLANs {
			texts = append(texts, fmt.Sprintf(f, w))
			if w.Radius != nil {
				texts = append(texts, fmt.Sprintf(f, w.Radius), fmt.Sprintf(f, *w.Radius))
			}
		}
		if in.Syslog != nil {
			texts = append(texts, fmt.Sprintf(f, in.Syslog))
		}
	}
	for _, s := range secrets {
		for _, x := range texts {
			if strings.Contains(x, s) {
				t.Fatalf("secret %q printed: %s", s, x)
			}
		}
	}
}

func hasNote(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// TestIntentAAAByDevname: an aaa section is matched by devname when its index
// differs from the wireless section's; an aaa section nothing uses is noted.
func TestIntentAAAByDevname(t *testing.T) {
	in, notes := IntentFromCfg(wlan("aaa.1.devname=ath0", "aaa.1.ssid=old",
		"aaa.2.devname=ath1", "aaa.2.wpa=2", "aaa.2.wpa.key.1.mgmt=WPA-PSK", "aaa.2.wpa.psk=good-pass-1"))
	if len(in.WLANs) != 1 || in.WLANs[0].Security != "wpa2" || in.WLANs[0].Passphrase != "good-pass-1" {
		t.Fatalf("wlans %v", in.WLANs)
	}
	if !contains(notes, `aaa.1 ("old"): no wireless section uses it: ignored`) {
		t.Errorf("notes %q", notes)
	}
}

// TestIntentAAAMismatch: a wireless section whose aaa.N names another VAP,
// with no aaa section for its own devname, is left off rather than built
// with the other VAP's security.
func TestIntentAAAMismatch(t *testing.T) {
	in, notes := IntentFromCfg(wlan("aaa.1.devname=ath0", "aaa.1.ssid=open-guest"))
	if len(in.WLANs) != 0 {
		t.Fatalf("built with another VAP's security: %v", in.WLANs)
	}
	if !hasNote(notes, "aaa.1 is for another VAP and no aaa section names ath1: left off") {
		t.Errorf("notes %q", notes)
	}
}

// TestIntentSameBandTwice: two VAPs of one WLAN on one band (an OWE
// transition pair) give one BSS, the secured one, whichever comes first.
func TestIntentSameBandTwice(t *testing.T) {
	for _, order := range []string{"open first", "owe first"} {
		openN, oweN := "1", "2"
		if order == "owe first" {
			openN, oweN = "2", "1"
		}
		cfg := "radio.1.phyname=wifi1\nradio.1.ieee_mode=11acvht80\n" +
			"wireless." + openN + ".ssid=cafe\nwireless." + openN + ".id=w1\nwireless." + openN + ".parent=wifi1\nwireless." + openN + ".devname=ath1\n" +
			"aaa." + openN + ".devname=ath1\naaa." + openN + ".owe_devname=ath2\n" +
			"wireless." + oweN + ".ssid=cafe\nwireless." + oweN + ".id=w1\nwireless." + oweN + ".parent=wifi1\nwireless." + oweN + ".devname=ath2\n" +
			"aaa." + oweN + ".devname=ath2\naaa." + oweN + ".wpa3.support=enabled\naaa." + oweN + ".owe_devname=ath1\n"
		in, notes := IntentFromCfg(cfg)
		if len(in.WLANs) != 1 {
			t.Fatalf("%s: wlans %v", order, in.WLANs)
		}
		w := in.WLANs[0]
		if w.Security != "owe" || !reflect.DeepEqual(w.Bands, []string{"na"}) || w.Devnames["na"] != "ath2" {
			t.Errorf("%s: %v %v", order, w, w.Devnames)
		}
		if !hasNote(notes, "wireless."+openN+` ("cafe" on na): another VAP of WLAN w1 on this band (wireless.`+oweN+") is used: left off") {
			t.Errorf("%s: notes %q", order, notes)
		}
	}
}

// qbssload and bga_filter are carried: absent or enabled is the default
// (BSS Load advertised, BPDUs filtered), disabled turns them off.
func TestIntentQBSSLoadBGA(t *testing.T) {
	for _, c := range []struct {
		lines           []string
		nobss, nofilter bool
	}{
		{nil, false, false},
		{[]string{"wireless.1.qbssload=disabled"}, true, false},
		{[]string{"wireless.1.bga_filter=disabled"}, false, true},
		{[]string{"wireless.1.bga_filter=enabled", "wireless.1.qbssload=enabled"}, false, false},
	} {
		in, notes := IntentFromCfg(wlan(append([]string{"aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-PSK", "aaa.1.wpa.psk=good-pass-1"}, c.lines...)...))
		if len(in.WLANs) != 1 {
			t.Fatalf("%v: %v %q", c.lines, in.WLANs, notes)
		}
		w := in.WLANs[0]
		if w.NoBSSLoad != c.nobss || w.NoBGAFilter != c.nofilter {
			t.Errorf("%v: nobssload %t nobga %t", c.lines, w.NoBSSLoad, w.NoBGAFilter)
		}
		for _, n := range notes {
			if strings.Contains(n, "qbssload") || strings.Contains(n, "bga_filter") {
				t.Errorf("%v: note %q", c.lines, n)
			}
		}
	}
}
