// SPDX-License-Identifier: GPL-2.0-or-later

package models

import "github.com/dtechterminal/udeco/internal/inform"

// Capability words the on-device Deco agent (cmd/udeco-ap) claims when it
// presents a Deco X20 as a U6-Lite. The reasoning, bit by bit, is in
// docs/deco/agent-design.md §3.5 ("UAL6 capability words"). The rule: claim
// a bit only when its meaning is known AND the agent implements the feature;
// an unknown bit is never claimed. A bit we do not claim only makes the
// controller hold a setting back; a bit we claim wrongly makes it send
// configuration nothing applies.
//
// Bit names come from docs/internals.md (the U7PG2 word 559857373 lists its
// 18 named bits; read in ascending order they put WPA3 at bit 17, which
// matches the independently known WPA3 bit 131072).
//
// Bit meanings for the feature bits below come from the Network 11.1.50
// controller code (com.ubnt.data device class, support*() methods), not
// from the name list.
const (
	WifiCapBandSteer = 1 << 2 // BANDSTEER: claimed only with DecoAgentFeatures.BandSteer (802.11v steering available)
	WifiCapRFScan    = 1 << 4 // RF_SCAN: claimed only with DecoAgentFeatures.RFScan (scan / spectrum-scan / quick-scan run)
	// WifiCapMinRateCtrl (bit 9, supportMinRateCtrl): the agent applies the
	// controller's minimum data rates as wl ratesets (bcmwifi rates.go).
	// Network 11.1.50 never consults the bit (it sends the minrate keys to
	// every UAP); claimed with DecoAgentFeatures.MinRate so the word says
	// what the agent does.
	WifiCapMinRateCtrl = 1 << 9
	// WifiCapRadiusMACAuth (bit 12, supportRadiusMacAuth): NOT claimed. The
	// Broadcom driver does 802.11 auth/association itself, so hostapd 2.9
	// checks the station in hostapd_notif_assoc, where macaddr_acl=2 is
	// PENDING and the station is refused before any RADIUS query
	// (docs/deco/features/radius-macauth-hs20-radsec.md).
	WifiCapRadiusMACAuth = 1 << 12
	WifiCapWPA3          = 1 << 17 // WPA3: SAE / WPA2+WPA3 transition via hostapd 2.9
	// WifiCapWPAPSKFile (bit 20, supportWpaPpsk): private pre-shared keys
	// through hostapd wpa_psk_file. Without it the controller does not send
	// a PPSK WLAN at all. Only keys on the WLAN's own VLAN are served (this
	// hostapd has no dynamic VLANs; docs/deco/features/ppsk.md).
	WifiCapWPAPSKFile = 1 << 20
	// WifiCapLockAP (bit 24, supportLockAp): Lock to Access Point. The
	// controller puts a client locked elsewhere in this AP's MAC filter
	// (macacl type=lock2ap); bcmwifi applies it in place (acllive.go).
	WifiCapLockAP     = 1 << 24
	DecoAgentWifiCaps = WifiCapWPA3 // the base word; features add bits

	// WifiCap2RoamAssist (wifi_caps2 0x20, supportsAssistedRoaming): the
	// controller sends wireless.N.btm_disassoc.{status,threshold} for 5/6
	// GHz VAPs; the agent sends 802.11v BSS transition requests to weak
	// stations (cmd/udeco-ap/roaming.go).
	WifiCap2RoamAssist = 0x20

	// FWCapSyslogEncryption (fw_caps 0x1000000, supportSyslogEncryption):
	// the agent forwards logread to the controller sealed with
	// device.SealSyslog (cmd/udeco-ap/syslogfwd.go). Without the bit an
	// "encrypted only" logging setting sends no syslog section at all.
	FWCapSyslogEncryption = 0x1000000
	// FWCapRadiusFilter (fw_caps 0x20000000, supportsRadiusFilter): the
	// controller sends aaa.N.filter_id for WPA-EAP WLANs on the console's
	// RADIUS server; bcmwifi writes radius_auth_req_attr=11:s:<id>.
	FWCapRadiusFilter = 0x20000000
	// FWCapSNMPv3 (fw_caps 0x4000, supportsSNMPv3): with it the controller
	// adds snmp.version=3|all and snmp.user.1.{name,password} to the snmp
	// section (v1/v2c needs no bit). The agent's read-only SNMP agent
	// (internal/snmpagent, cmd/udeco-ap/snmp.go) serves USM authPriv. It
	// only reads the unit, so both modes claim it.
	FWCapSNMPv3 = 0x4000
	// FWCapHotspot2 (fw_caps 0x800000, supportHotspot2): the controller
	// sends aaa.N.hs20.* / aaa.N.osu.* for a WPA-EAP WLAN with Hotspot 2.0;
	// internal/hs20 renders hostapd interworking/hs20 lines (bcmwifi
	// hs20.go). Takeover with the hotspot2 config key only, until the
	// Interworking IE and GAS path through wl is verified live
	// (docs/deco/features/hotspot2.md).
	FWCapHotspot2 = 0x800000

	// FW2CapRadSec (fw2_caps 0x80000, supportsRadSec): the controller sends
	// certs.* and aaa.N.radius.*.M.tls/ca_cert/client_cert/private_key; the
	// agent's internal/radsec proxy carries hostapd's UDP RADIUS over TLS
	// (docs/deco/features/radsec.md). Takeover only.
	FW2CapRadSec = 0x80000
	// FW2CapMdnsSdBridge (fw2_caps 0x10000000, supportsMdnsSdBridge): the
	// controller sends mdns_sd.* (proxies and per-VAP service filters) for
	// WLANs with mdns_proxy_mode auto/custom; internal/mdnsbr runs it.
	// Takeover with apply and the mdns_bridge config key only
	// (docs/deco/features/mdns-bridge.md).
	FW2CapMdnsSdBridge = 0x10000000

	// FW3CapPathMonitoring (fw3_caps 0x40, supportsPathMonitoring): the
	// controller sends the pathmon section and asks for the inform's
	// pathmon block; internal/pathmon probes gateway and uplink with ICMP.
	FW3CapPathMonitoring = 0x40
	// FW3CapMulticastInspect (fw3_caps 0x80, supportsMulticastInspect):
	// wireless.N.multicast.inspect=true and the sta_table[].multicast
	// block, from AF_PACKET taps on the agent's vifs (internal/mcinspect).
	FW3CapMulticastInspect = 0x80

	// FWCapQCASwitch (fw_caps 0x10, the controller's hasQCASwitch): the
	// AP has a managed switch. Network 10.6.109 (XHjguBsIf, the UAP
	// system_cfg builder) writes only "switch.status=disabled" without it;
	// with it the device keeps switch_vlan_enabled (the device panel's
	// "Enable Port VLAN", shown for the uidb hybrid uap+usw models) and its
	// port_overrides, and system_cfg gets switch.vlan.* and switch.port.*
	// (internal/jioports reads them). Claimed only with
	// DecoAgentFeatures.PortVLAN.
	FWCapQCASwitch = 0x10
	// FWCapOWRTSwitch (fw_caps 0x100, hasOWRTSwitch): the switch tags
	// VLANs. Without it the controller refuses a port override whose
	// forward is "all" or "customize" on a QCA-switch AP
	// (VLAN_TAGGING_UNSUPPORTED, com.ubnt.ace.api.e.CqACYAR) and allows
	// native-only ports; with it an in-wall AP takes up to 96 VLANs.
	// Claimed only with DecoAgentFeatures.PortVLAN.
	FWCapOWRTSwitch = 0x100

	// DecoAgentTakeover* are the bits that need the agent to own Wi-Fi: a
	// drop to observe mode clears them from the session at once.
	DecoAgentTakeoverWifiCaps  = WifiCapRFScan | WifiCapMinRateCtrl | WifiCapWPAPSKFile | WifiCapLockAP
	DecoAgentTakeoverWifiCaps2 = WifiCap2RoamAssist
	DecoAgentTakeoverFWCaps    = FWCapRadiusFilter | FWCapHotspot2 | FWCapQCASwitch | FWCapOWRTSwitch
	DecoAgentTakeoverFW2Caps   = FW2CapRadSec | FW2CapMdnsSdBridge
	DecoAgentTakeoverFW3Caps   = FW3CapMulticastInspect
	// FWCapSHA512SSH (fw_caps 0x400, docs/internals.md "Capability words"):
	// the device takes SHA-512 crypt ("$6$") SSH password hashes in
	// users.N.password. The agent verifies them (device.VerifyCrypt, for
	// ssh-adopt once adopted) and installs them (glibc 2.26 on the Deco
	// supports $6$).
	FWCapSHA512SSH = 0x400
	// FWCapWlanScheduleMultiBlock (fw_caps 0x1000, the controller's
	// supportMultiBlockWlanSchedule): the controller writes each schedule
	// window as wireless.N.schedule_<day>.<i>. Without it, it writes them all
	// to one un-indexed schedule_<day> key, so only the last window of a day
	// survives in system_cfg. translate.wlanSchedule reads the indexed form.
	FWCapWlanScheduleMultiBlock = 0x1000
	// FWCapWlanScheduleInvert (fw_caps 0x400000, supportWlanScheduleInvert):
	// the controller sends an "off during" schedule as is, with
	// schedule_invert=enabled, instead of inverting it itself.
	// translate.wlanSchedule handles schedule_invert.
	FWCapWlanScheduleInvert = 0x400000
	// DecoAgentFWCaps keeps the placeholder bits 0 and 1 the inform has
	// always carried (inform.PlaceholderFWCaps) and adds SHA-512 SSH
	// passwords, the two WLAN-schedule bits (the agent applies schedules:
	// cmd/udeco-ap/schedule.go), encrypted syslog (both modes: logread
	// is only read) and SNMPv3 (both modes: the SNMP agent only reads).
	DecoAgentFWCaps = inform.PlaceholderFWCaps | FWCapSHA512SSH | FWCapWlanScheduleMultiBlock | FWCapWlanScheduleInvert |
		FWCapSyslogEncryption | FWCapSNMPv3
	// DecoAgentFW3Caps: path monitoring in both modes (ICMP echoes only).
	DecoAgentFW3Caps     = FW3CapPathMonitoring
	decoAgentIEEEModesNG = 90 // measured U6-Pro (11ax) 2.4 GHz value: b, n, ac-rates, ax
	decoAgentIEEEModesNA = 85 // measured U6-Pro (11ax) 5 GHz value: a, n, ac, ax
)

// nonAXIEEEModes is the ieee_modes word of a radio that is not 802.11ax:
// the measured U7PG2's (inform.U7PG2: 10 on 2.4 GHz, 21 on 5 GHz).
func nonAXIEEEModes(band string) int64 { return inform.U7PG2.Radios[band].IEEEModes }

// The model codes cmd/udeco-ap reports (catalog.json has their entries).
const (
	ModelUAL6  = "UAL6"  // U6-Lite: what a Deco X20 is reported as
	ModelU7LT  = "U7LT"  // UAP-AC-Lite: a JCOW414 without its LAN ports
	ModelUHDIW = "UHDIW" // UAP-IW-HD: a JCOW414 with its LAN ports
	// DecoAgentModel is the one model a Deco is reported as, the agent's
	// default: its capability words (above) are chosen for that hardware.
	DecoAgentModel = ModelUAL6
	// DefaultModel is what the controller-side tools (cmd/udeco, upstream's uow)
	// report an AP as unless told otherwise: the one model with fully
	// measured capability words (inform.U7PG2).
	DefaultModel = inform.U7PG2Model
)

// DecoAgentProfile is the profile cmd/udeco-ap reports for model code m
// (UAL6 on the Deco, U7LT or UHDIW on the JCOW414; ok is false otherwise).
// Identity, firmware version and power range come from the catalogue entry
// (a JCOW414 model's power is capped at the unit's own); the capability
// words are the deliberately reduced set above:
//
//   - fw_caps 3 | 0x400 | 0x1000 | 0x4000 | 0x400000 | 0x1000000: the
//     placeholder bits plus SHA-512 SSH passwords (the agent verifies and
//     installs $6$ hashes), SNMPv3, multi-block / inverted WLAN schedules
//     and encrypted syslog; RADIUS filter (0x20000000) with f.RadiusFilter
//     and Hotspot 2.0 (0x800000) with f.Hotspot2; QCA switch and OWRT
//     switch (0x10 | 0x100) with f.PortVLAN on a model with LAN ports;
//     no RADIUS DAE;
//   - fw2_caps RadSec (0x80000) with f.RadSec and mDNS service bridge
//     (0x10000000) with f.MdnsBridge, else 0 (not sent);
//   - fw3_caps 0x40 (path monitoring), plus multicast inspect (0x80) with
//     f.MulticastInspect;
//   - wifi_caps2 ROAMING_ASSISTANT (0x20) with f.RoamAssist, else 0 (not
//     sent); hw_caps 0 (not sent);
//   - wifi_caps = WPA3, plus RF_SCAN when f.RFScan (the agent runs the
//     controller's scans: takeover mode only), BANDSTEER when f.BandSteer
//     (the agent can send 802.11v BSS transition requests), and the
//     takeover features MINRATE_CTRL, WPA_PSK_FILE and LOCK_AP;
//   - per radio: ieee_modes from the measured 11ax rows; radio_caps only
//     the MIMO bit for the radio's spatial streams (RadioCapsMIMO; the
//     other bits have no known name), radio_caps2 WPA3 with f.WPA3 (plus
//     WPA3 fast roaming with f.WPA3FT), else 0
//     (RadioCap2WPA3: SAE per radio, without which the controller downgrades
//     WPA2/WPA3 WLANs to WPA2); has_dfs/has_fccdfs on 5 GHz with f.DFS
//     (bcmwifi serves DFS channels: 802.11h, CAC, radar moves and the
//     controller's dfs-reset, internal/bcmwifi dfs.go), else false.
//
// heAX tells, per band, whether the hardware is 802.11ax (wl.Caps HE); a
// non-ax radio gets the measured non-ax ieee_modes instead.
// radio_caps MIMO bits, from the Network 11.1.50 web UI (the device panel's
// MIMO column tests them in this order): 1x1, 2x2, 3x3, 4x4. A real U6 Pro
// sends 0x4014 (2.4 GHz, 2x2) and 0xc024004 (5 GHz, 4x4).
const (
	RadioCapMIMO1 = 0x8
	RadioCapMIMO2 = 0x10
	RadioCapMIMO3 = 0x20
	RadioCapMIMO4 = 0x4000000
)

// radio_caps2 bits, from the controller's RadioTableEntry (Network 10.6.109,
// com.ubnt.i.g.e.mMObEXELV: "radioCapabilitiesExtended" = radio_caps2) and
// its per-device WLAN filter (com.ubnt.service.config.ubntconf.qemBJTmR). A
// real U6 Pro sends 0x1f on both radios.
//
//   - 0x1 WPA3: the radio does SAE (and WPA3-Enterprise). Without it a
//     WPA2/WPA3 transition WLAN is sent as WPA2 only (wpa3_support and
//     wpa3_transition cleared, wpa.key.1.mgmt=WPA-PSK, no wpa3.* keys) and a
//     WPA3-only one is not sent at all ("SAE cannot provision"), whatever
//     wifi_caps says.
//   - 0x2 WPA3 fast roaming: FT-SAE; without it the controller clears
//     wpa3_fast_roaming (and 802.11r on a WPA3-only WLAN).
//   - 0x4 WPA3-Enterprise 192-bit (GCMP-256, BIP-GMAC-256).
//   - 0x8 OWE (Enhanced Open).
//
// The agent can claim WPA3 (DecoAgentRadioCaps2) and WPA3 fast roaming:
// hostapd 2.9 on the Deco does SAE and FT-SAE, and bcmwifi builds wpa3 /
// wpa2wpa3 (and wpa3-enterprise) and FT-SAE with the controller's iapp_key
// for the PMK-R1 transfers between APs; it builds neither OWE nor Suite-B.
// It claims them only with DecoAgentFeatures.WPA3 (takeover with the config
// key wpa3, off by default until SAE is verified live), 0x2 also only with
// DecoAgentFeatures.WPA3FT; without WPA3 radio_caps2 is 0.
const (
	RadioCap2WPA3       = 0x1
	RadioCap2WPA3FT     = 0x2
	RadioCap2WPA3Ent192 = 0x4
	RadioCap2OWE        = 0x8
	DecoAgentRadioCaps2 = RadioCap2WPA3
)

// MediaTek radio names. The controller derives a U6-Lite's VAP devnames
// from the radio_table names the AP reports (UAL6 is a MediaTek model:
// com.ubnt.service.config.ubntconf.rKjGTvdyNuMoNj): the radio name minus
// its last character plus the VAP's index on the radio, and the first VAP
// of a radio is named like the radio (config meta, ubntconf.meta
// rKjGTvdyNuMoNj). With the real names ra0 (2.4 GHz) and rai0 (5 GHz) that
// gives ra0, ra1, ... and rai0, rai1, ...: one devname per SSID. With
// Qualcomm names (wifi0, wifi1) it gives wifi0, wifi1, ... on 2.4 GHz and
// wifi1, wifi1, wifi2, ... on 5 GHz, so the first two 5 GHz SSIDs (and a
// second 2.4 GHz one) share a devname and the controller's bridge port
// lists cannot tell them apart.
const (
	RadioNameMTK2G = "ra0"
	RadioNameMTK5G = "rai0"
)

// DecoAgentRadioNames maps a band to the radio_table name the agent
// reports with MediaTek naming.
func DecoAgentRadioNames() map[string]string {
	return map[string]string{"ng": RadioNameMTK2G, "na": RadioNameMTK5G}
}

// RadioCapsMIMO is the radio_caps MIMO bit for nss spatial streams (0 when
// nss is not 1-4).
func RadioCapsMIMO(nss int) int64 {
	switch nss {
	case 1:
		return RadioCapMIMO1
	case 2:
		return RadioCapMIMO2
	case 3:
		return RadioCapMIMO3
	case 4:
		return RadioCapMIMO4
	}
	return 0
}

func DecoAgentProfile(m Model, heAX map[string]bool) (inform.Profile, bool) {
	return DecoAgentProfileWith(m, heAX, DecoAgentFeatures{})
}

// DecoAgentFeatures are agent features that depend on what the running
// build can do; each adds a capability bit.
type DecoAgentFeatures struct {
	// BandSteer: the Wi-Fi backend sends 802.11v BSS transition requests,
	// so the agent's band steering works (wifi_caps BANDSTEER).
	BandSteer bool
	// RFScan: the agent runs the controller's scan, spectrum-scan and
	// quick-scan (wifi_caps RF_SCAN). Observe mode runs no scans, so it
	// does not claim the bit.
	RFScan bool
	// The rest need the agent to own Wi-Fi (takeover mode); observe mode
	// never sets them.
	//
	// MinRate: bcmwifi applies minimum data rates (takeover with the
	// min_rates config key): wifi_caps MINRATE_CTRL.
	MinRate bool
	// PPSK: hostapd wpa_psk_file private keys: wifi_caps WPA_PSK_FILE.
	PPSK bool
	// LockAP: lock2ap MAC-filter entries applied in place: wifi_caps
	// LOCK_AP.
	LockAP bool
	// RoamAssist: the Wi-Fi backend sends BSS transition requests for the
	// Roaming Assistant: wifi_caps2 ROAMING_ASSISTANT.
	RoamAssist bool
	// RadiusFilter: hostapd sends Filter-Id in Access-Requests: fw_caps
	// RADIUS filter.
	RadiusFilter bool
	// MulticastInspect: per-client multicast blocks from the agent's
	// vifs: fw3_caps multicast inspect.
	MulticastInspect bool
	// WPA3: bcmwifi serves SAE (takeover with the wpa3 config key):
	// radio_caps2 WPA3 on every radio. Without it radio_caps2 is 0 and the
	// controller sends WPA2/WPA3 WLANs as WPA2 and no WPA3-only WLAN.
	WPA3 bool
	// WPA3FT: the Wi-Fi backend builds FT-SAE (bcmwifi ftsae.go, with the
	// WLAN's iapp_key as UniFi APs do). With WPA3 it adds radio_caps2
	// WPA3 fast roaming (RadioCap2WPA3FT), so the controller keeps
	// wpa3_fast_roaming and sends wpa3.ft.status enabled.
	WPA3FT bool
	// WPA3NG: the JCOW414's 2.4 GHz driver serves SAE too (the rebuilt
	// MT7603 module, mtkwifi.WithDriverSAE). With WPA3 it adds radio_caps2
	// WPA3 on its ng radio; without it the JCOW414 claims WPA3 on na only.
	WPA3NG bool
	// RadSec: the agent's RadSec proxy serves RADIUS/TLS servers: fw2_caps
	// RadSec.
	RadSec bool
	// MdnsBridge: internal/mdnsbr runs the controller's mDNS proxies and
	// service filters (takeover, apply and the mdns_bridge config key):
	// fw2_caps mDNS service bridge.
	MdnsBridge bool
	// Hotspot2: bcmwifi renders the WLAN's Hotspot 2.0 config (takeover
	// with the hotspot2 config key): fw_caps Hotspot 2.0.
	Hotspot2 bool
	// PortVLAN: the agent applies the controller's per-port VLANs to the
	// unit's LAN ports (internal/jioports; takeover on a JCOW414 reported
	// as UHDIW): fw_caps QCA switch and OWRT switch.
	PortVLAN bool
	// DFS: bcmwifi serves the controller's DFS channels on 5 GHz
	// (takeover on the Deco): has_dfs and has_fccdfs on the na radio, as
	// a U6 Pro reports them.
	DFS bool
}

// JCOW414Models are the models a JioFiber JCOW414 (MT7603 2x2 2.4 GHz,
// MT7663 2x2 5 GHz, four switch ports) can be reported as: the
// UAP-AC-Lite (no ports) and the UAP-IW-HD (four front ports and the rear
// uplink, the only Wi-Fi 5 UniFi AP with four LAN ports).
var JCOW414Models = map[string]bool{ModelU7LT: true, ModelUHDIW: true}

// jcow414MaxTx: the JCOW414's power at TxPower=100 %; a model's larger
// catalogue maximum is not claimed.
var jcow414MaxTx = map[string]int{"ng": 20, "na": 23}

// JCOW414MaxTx is the JCOW414's transmit power (dBm) on band ("ng", "na")
// at the driver's TxPower=100 %; 0 for any other band. internal/mtkwifi's
// layout (JCOW414) takes its MaxTxDBm from here.
func JCOW414MaxTx(band string) int { return jcow414MaxTx[band] }

// DecoAgentProfileWith is DecoAgentProfile with the optional features f.
func DecoAgentProfileWith(m Model, heAX map[string]bool, f DecoAgentFeatures) (inform.Profile, bool) {
	jcow := JCOW414Models[m.Code]
	if m.Code != DecoAgentModel && !jcow {
		return inform.Profile{}, false
	}
	p := inform.Profile{Model: m.Code, Display: m.Display, Version: m.Version,
		WifiCaps: DecoAgentWifiCaps, FWCaps: DecoAgentFWCaps, FW3Caps: DecoAgentFW3Caps,
		Radios: map[string]inform.RadioProfile{}}
	if jcow {
		// the JCOW414 (UAP-AC-Lite or UAP-IW-HD profile): SAE in its 5 GHz
		// driver, and in its 2.4 GHz one only with the rebuilt MT7603
		// module (WPA3NG), so WPA3 is claimed only when the feature says
		// so, and on ng only with WPA3NG
		p.WifiCaps = 0
		if f.WPA3 {
			p.WifiCaps = WifiCapWPA3
		}
	}
	// the switch bits: only a model with LAN ports, and only when the
	// agent applies their VLANs
	if f.PortVLAN && m.RearUplinkPort() > 0 {
		p.FWCaps |= FWCapQCASwitch | FWCapOWRTSwitch
	}
	set := func(on bool, word *int64, bit int64) {
		if on {
			*word |= bit
		}
	}
	set(f.BandSteer, &p.WifiCaps, WifiCapBandSteer)
	set(f.RFScan, &p.WifiCaps, WifiCapRFScan)
	set(f.MinRate, &p.WifiCaps, WifiCapMinRateCtrl)
	set(f.PPSK, &p.WifiCaps, WifiCapWPAPSKFile)
	set(f.LockAP, &p.WifiCaps, WifiCapLockAP)
	set(f.RoamAssist, &p.WifiCaps2, WifiCap2RoamAssist)
	set(f.RadiusFilter, &p.FWCaps, FWCapRadiusFilter)
	set(f.MulticastInspect, &p.FW3Caps, FW3CapMulticastInspect)
	set(f.Hotspot2, &p.FWCaps, FWCapHotspot2)
	set(f.RadSec, &p.FW2Caps, FW2CapRadSec)
	set(f.MdnsBridge, &p.FW2Caps, FW2CapMdnsSdBridge)
	for _, r := range m.Radios {
		rp := inform.RadioProfile{NSS: r.NSS, MinTx: r.MinTx, MaxTx: r.MaxTx, Is11ac: r.Band == "na",
			RadioCaps: RadioCapsMIMO(r.NSS)}
		if hw := jcow414MaxTx[r.Band]; jcow && hw > 0 && rp.MaxTx > hw {
			rp.MaxTx = hw
		}
		rp.HasDFS = f.DFS && r.Band == "na"
		rp.HasFCCDFS = rp.HasDFS
		wpa3 := f.WPA3 && !(jcow && r.Band == "ng" && !f.WPA3NG)
		set(wpa3, &rp.RadioCaps2, DecoAgentRadioCaps2)
		set(wpa3 && f.WPA3FT, &rp.RadioCaps2, RadioCap2WPA3FT)
		ax := heAX == nil || heAX[r.Band]
		switch {
		case r.Band == "ng" && ax:
			rp.IEEEModes = decoAgentIEEEModesNG
		case r.Band == "ng":
			rp.IEEEModes = nonAXIEEEModes("ng")
		case ax:
			rp.IEEEModes = decoAgentIEEEModesNA
		default:
			rp.IEEEModes = nonAXIEEEModes("na")
		}
		p.Radios[r.Band] = rp
	}
	return p, true
}
