// SPDX-License-Identifier: GPL-2.0-or-later

// Package mtkwifi runs the controller's Wi-Fi on a MediaTek SoftAP driver
// (MT7603 2.4 GHz + MT7663 5 GHz on the JioFiber JCOW414, platform
// "jio-mtk"), and reads its radios and stations for the inform.
//
// The driver is configured the way the vendor does it: a profile per radio
// (/etc/Wireless/*/RT2860AP.dat, read when the radio's first BSS netdev is
// brought up) plus iwpriv for the settings it takes live. Verified on the
// unit 2026-11-19:
//   - ifconfig down/up of a radio's BSS netdevs re-reads its profile
//     (SSIDn, WPAPSKn, the ;-lists, Channel); it drops that radio's clients.
//   - a BSS beacons only while its netdev is up; BssidNum stays 4 (ra0-ra3,
//     rai0-rai3 always exist).
//   - iwpriv <bss> set SSID / HideSSID / NoForwarding / MaxStaNum work live.
//   - VLAN N reaches the gateway as <port>.N on the switch port device
//     (eth0.4.N), not on the bridge member eth0.4.1 (which is VID 1).
//   - The vendor MT7603 module (2.4 GHz, mt7603eap.ko) has no WPA3/SAE:
//     WPA2/WPA3 WLANs are served there as WPA2-PSK, WPA3-only ones are not
//     served. The rebuilt MT7603 module (padavan 4.1.2.0 with SAE and PMF,
//     cross-built for the unit's EcoNet kernel; loaded as mt76x3_ap) has
//     the MT7663's AuthMode words and PMF keys: with it loaded the 2.4 GHz
//     radio serves SAE too (WithDriverSAE). Verified on the unit
//     2026-11-22: a WPA3-only BSS on ra3 took an SAE client (group 19,
//     PMF required, BIP).
//   - The MT7663 driver (5 GHz, built into the kernel) has SAE: AuthMode
//     WPA2PSKWPA3PSK (transition, needs PMFMFPC=1) and WPA3PSK (PMF
//     required). It is used only when the agent claims WPA3 (config wpa3).
package mtkwifi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/models"
	"github.com/dtechterminal/udeco/internal/rf"
	"github.com/dtechterminal/udeco/internal/translate"
)

// RadioDef is one radio of the unit.
type RadioDef struct {
	Band string // "ng" or "na"
	// Ifaces are the BSS netdevs in profile slot order; [0] reads the
	// profile. Their number is the most SSIDs the radio serves.
	Ifaces    []string
	Dat       string // driver profile (device path)
	MaxStaKey string // per-BSS client limit list in the profile
	MaxTxDBm  int    // TxPower=100 (%)
	MinTxDBm  int    // the lowest power reported to the controller (min_txpower)
	NSS       int    // spatial streams
	// TxLive is the iwpriv set key that changes the power at once: the
	// MT7603's TxPower (CmdSetTxPowerCtrl), the MT7663's PowerDropCtrl
	// (its `set TxPower` only stores the value)
	TxLive string
	HWName string
	SAE    bool // the driver serves WPA3-Personal (SAE) and has the PMF keys
	UAPSD  bool // the driver has U-APSD (APSDCapable, per BSS)
	// DFS: the agent may serve 52-64 on this radio (Options.DFS; dfs.go)
	DFS bool
	// HSFlag: the driver does proxy ARP itself (hs_flag bit 1, the
	// MT7663; proxyarp.go)
	HSFlag bool
	// Spectrum is the radio's spectrum backend: SpectrumOffChan (the
	// MT7603's ApOffChanScan sweep, offchan.go), SpectrumChanInfo (the
	// MT7663's Channel_Info visits, offchan5.go), or "" for none (the
	// band's spectrum commands run the neighbour survey: SpectrumBySurvey)
	Spectrum string
	// Dot1X: the driver serves WPA2/WPA3-Enterprise with Jio's rtdot1xd
	// (802.1X authenticator in userland, the driver holding the keys and
	// the port; dot1x.go). The MT7663 always; the MT7603 only as the
	// rebuilt module (WithDriverSAE). Cleared when rtdot1xd is missing
	// or the agent's enterprise key is off (New).
	Dot1X bool
	// RadiusKeyList: the driver reads every BSS's RADIUS secret from one
	// ;-list in RADIUS_Key1 (the MT7603's "prev format",
	// rtmp_read_radius_parms_from_file); else RADIUS_Key<n> per BSS (the
	// MT7663, ReadRadiusParameterFromFile)
	RadiusKeyList bool
	// FT: the agent serves 802.11r on this radio (roam.go,
	// docs/deco/features/garage-ft.md): the MT7663 always has it (built
	// into the kernel); the MT7603 only as the rebuilt mt7603roam module
	// (WithDriverFT). Cleared by New when the agent's ft key is
	// off; NoFTWhy then says why.
	FT      bool
	NoFTWhy string `json:"-"`
	// FTSAE: the agent's wpa3 and ft_sae keys are on (the Decos' view of
	// the mobility domain, bcmwifi.SSIDMDID, and FT-SAE where the radio
	// serves SAE and FT)
	FTSAE bool
}

// JCOW414 is the JioFiber JCOW414 layout: two 2x2 radios with four BSS
// netdevs each. The power at TxPower=100 % is models.JCOW414MaxTx (what the
// unit's profile is capped at); the tests hold the rest that the reported
// models also state (streams, lowest power, SAE, the radio names) to
// internal/models.
var JCOW414 = []RadioDef{
	{Band: "ng", Ifaces: []string{"ra0", "ra1", "ra2", "ra3"}, Dat: "/etc/Wireless/RT2860AP/RT2860AP.dat",
		MaxStaKey: "MaxStaNum", MaxTxDBm: models.JCOW414MaxTx("ng"), MinTxDBm: 5, NSS: 2, TxLive: "TxPower", HWName: "MT7603E",
		Spectrum: SpectrumOffChan},
	{Band: "na", Ifaces: []string{"rai0", "rai1", "rai2", "rai3"}, Dat: "/etc/Wireless/RT2860AP_AC/RT2860AP.dat",
		MaxStaKey: "MbssMaxStaNum", MaxTxDBm: models.JCOW414MaxTx("na"), MinTxDBm: 5, NSS: 2, TxLive: "PowerDropCtrl", HWName: "MT7663",
		SAE: true, UAPSD: true, HSFlag: true, Dot1X: true, FT: true, Spectrum: SpectrumChanInfo},
}

// SAEModule2G is the rebuilt 2.4 GHz module's name in /sys/module: the
// MT7603 driver that serves SAE (the vendor's mt7603eap does not).
const SAEModule2G = "mt76x3_ap"

// WithDriverSAE returns layout with SAE, PMF and 802.1X (Dot1X, with
// the MT7603's RADIUS_Key1 list) on the 2.4 GHz radio when the rebuilt
// MT7603 module (SAEModule2G) is loaded under root; else layout itself.
// The vendor's mt7603eap is never given enterprise SSIDs: its RADIUS
// profile format is unverified.
func WithDriverSAE(root string, layout []RadioDef) []RadioDef {
	if _, err := os.Stat(filepath.Join(root, "sys/module", SAEModule2G)); err != nil {
		return layout
	}
	l := append([]RadioDef(nil), layout...)
	for i := range l {
		if l[i].Band == "ng" {
			l[i].SAE, l[i].Dot1X, l[i].RadiusKeyList = true, true, true
		}
	}
	return l
}

// FTSymbol2G is a function only the rebuilt MT7603 module with the
// agent's FT interface has (mt7603roam, drv2g ft_udft.c): the SAE-only
// build (mt7603wpa3) has the same module name and no 802.11r.
const FTSymbol2G = "FT_UDFT_GetEvents"

// WithDriverFT returns layout with FT on the 2.4 GHz radio when the
// loaded MT7603 module has the FT interface (FTSymbol2G among its
// symbols in /proc/kallsyms under root); else layout itself. A read of
// /proc/kallsyms only: nothing is sent to the driver.
func WithDriverFT(root string, layout []RadioDef) []RadioDef {
	b, err := os.ReadFile(filepath.Join(root, "proc/kallsyms"))
	if err != nil || !kallsymsHas(b, FTSymbol2G, SAEModule2G) {
		return layout
	}
	l := append([]RadioDef(nil), layout...)
	for i := range l {
		if l[i].Band == "ng" {
			l[i].FT = true
		}
	}
	return l
}

// kallsymsHas: /proc/kallsyms lists sym in module mod ("<addr> <type>
// <sym>\t[<mod>]").
func kallsymsHas(b []byte, sym, mod string) bool {
	for _, l := range bytes.Split(b, []byte("\n")) {
		f := strings.Fields(string(l))
		if len(f) >= 4 && f[2] == sym && f[3] == "["+mod+"]" {
			return true
		}
	}
	return false
}

// Channels the units' country (IN, CountryRegion 0 / CountryRegionABand 10)
// allows; the profile's region keys are left as the vendor set them.
var (
	chans24 = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	chans5  = []int{36, 40, 44, 48, 149, 153, 157, 161, 165}
)

const maxStaDefault = 32 // per BSS when the controller sets no limit

// BSS is one served SSID on one radio. PSK is a secret.
type BSS struct {
	ID      string
	SSID    string
	Auth    string // OPEN, WPA2PSK, WPA2PSKWPA3PSK, WPA3PSK, WPA2 (802.1X: Radius set)
	Encr    string // NONE, AES
	PMF     int    // 0 off, 1 capable (PMFMFPC), 2 required (PMFMFPR too)
	PSK     string `json:",omitempty"`
	Hidden  bool
	Isolate bool
	MaxSta  int
	VLAN    int // 0 = the LAN bridge
	// omitempty: a plan asking for none of them marshals (and hashes) as
	// one saved by an older agent did
	RRM   bool `json:",omitempty"` // 802.11k (RRMEnable)
	BTM   bool `json:",omitempty"` // 802.11v BSS transition management (WNMEnable)
	UAPSD bool `json:",omitempty"` // U-APSD (APSDCapable); only where RadioDef.UAPSD
	// GroupRekey is the GTK rekey interval in seconds (RekeyMethod TIME
	// and RekeyInterval); 0 = never (DISABLE), always 0 for an open BSS
	GroupRekey int `json:",omitempty"`
	// M2U is the SSID's multicast enhancement: the MT7663's per-BSS
	// IgmpSnEnable (the MT7603 has one value per radio: RadioPlan.IgmpSn)
	M2U bool `json:",omitempty"`
	// Guest: a guest SSID, isolated by the agent's ebtables chains
	// (guest.go)
	Guest bool `json:",omitempty"`
	// Sched: the WLAN has a schedule (it comes and goes): never pinned
	// to slot 0 while an always-on WLAN can be (slots.go)
	Sched bool `json:",omitempty"`
	// ProxyARP: the controller's proxy ARP (proxyarp.go; live, never a
	// restart)
	ProxyARP bool `json:",omitempty"`
	// NoBGA: the controller's bga_filter=disabled; the agent's BPDU
	// filter (bga.go; ebtables, never a restart) leaves the BSS alone
	NoBGA bool `json:",omitempty"`
	// Radius: WPA2/WPA3-Enterprise through rtdot1xd (dot1x.go); its
	// Secret is a secret (as PSK)
	Radius *Dot1X `json:",omitempty"`
	// FT: 802.11r (FT-PSK; with FTSAE also FT-SAE) in mobility domain
	// MDID, the Decos' (bcmwifi.SSIDMDID). R0KHID is the 5 GHz BSS's
	// R0KH-ID (mtkft.R0KHID of its netdev's address, filled by ftIDs);
	// the 2.4 GHz driver uses its BSSID's 12 hex digits itself (roam.go).
	FT     bool   `json:",omitempty"`
	FTSAE  bool   `json:",omitempty"`
	MDID   uint16 `json:",omitempty"`
	R0KHID string `json:",omitempty"`
}

// RadioPlan is what one radio serves. The zero value of each per-radio
// setting after BSS keeps the vendor's profile value, so a last-good plan
// saved by an older agent still writes a working profile (its BSSes then
// have 802.11k/v and U-APSD off).
type RadioPlan struct {
	Band    string
	On      bool
	Channel int // 0 = the driver's automatic choice
	Width   int // 20, 40, 80
	TxPct   int // TxPower (% of the maximum)
	BSS     []BSS
	// DTIM is DtimPeriod (one per radio in both drivers); 0 = the vendor's.
	DTIM int `json:",omitempty"`
	// BasicRate is the driver's BasicRate bitmap (bit 0 = 1 Mb/s ... bit
	// 11 = 54 Mb/s, basicRateKbps); 0 = the vendor's (351 on 2.4 GHz).
	// 2.4 GHz only: on 5 GHz the driver forces 6, 12 and 24 Mb/s basic.
	BasicRate int `json:",omitempty"`
	// IgmpSn writes IgmpSnEnable=1 (multicast enhancement). false keeps
	// the vendor's value (1 on both radios): never written as 0.
	IgmpSn bool `json:",omitempty"`
	// MinRSSI is the controller's minimum RSSI (dBm, -100..-1; 0 = off):
	// each BSS's AssocReqRssiThres (live only, never in the profile) and
	// the agent's weak-station kick (minrssi.go)
	MinRSSI int `json:",omitempty"`
	// TxMode is the controller's power mode (translate.TxAuto ...
	// TxCustom), reported back with the power (collector.go radioTx)
	TxMode string `json:",omitempty"`
	// Slots is each BSS's profile slot (its netdev Ifaces[slot]), parallel
	// to BSS; nil = positional (BSS[i] in slot i). Set by BSS pinning
	// (slots.go).
	Slots []int `json:",omitempty"`
}

// slot is the profile slot of rp.BSS[i].
func (rp RadioPlan) slot(i int) int {
	if i < len(rp.Slots) {
		return rp.Slots[i]
	}
	return i
}

// structural is everything that may need the radio restarted: the BSS
// list with names, security, keys and 802.11k/v/U-APSD, the channel,
// width, DTIM, basic rates and IGMP snooping (profile() patches the
// vendor baseline, read only when a radio's BSSes come up). Hidden,
// Isolate and MaxSta are live. The applier restarts a radio only when what
// it would write differs (restartKey); structural is the fallback without
// a baseline profile.
func (r RadioPlan) structural() string {
	c := r
	c.BSS = nil
	c.TxPct, c.MinRSSI, c.TxMode = 0, 0, "" // live (applyLive), reported only
	for _, b := range r.BSS {
		b.Hidden, b.Isolate, b.MaxSta, b.NoBGA = false, false, 0, false
		c.BSS = append(c.BSS, b)
	}
	j, _ := json.Marshal(c)
	return string(j)
}

// restartKey is what a restart of the radio would make live: the profile
// rendered from base without the live settings (Hidden, Isolate, MaxSta,
// the power, which applyLive sets with the driver's live command),
// with the netdevs brought up and the bridges they go in. Two plans with
// the same key need no restart between them, whatever else differs in
// them (a setting the vendor's profile already has, such as IGMP snooping
// on or DTIM 2).
func restartKey(base []byte, rd RadioDef, r RadioPlan) string {
	if !r.On {
		return "off"
	}
	c := r
	c.BSS = nil
	c.TxPct = 0
	var vlans []string
	for _, b := range r.BSS {
		b.Hidden, b.Isolate, b.MaxSta = false, false, 0
		c.BSS = append(c.BSS, b)
		vlans = append(vlans, strconv.Itoa(b.VLAN))
	}
	return strings.Join(vlans, ",") + "\n" + string(profile(base, rd, c))
}

func (r RadioPlan) hash() string {
	j, _ := json.Marshal(r)
	h := sha256.Sum256(j)
	return hex.EncodeToString(h[:8])
}

// plans builds each radio's plan from d. Notes say what is not served.
// sae: WPA3 may be served on the radios whose driver has it.
func plans(d bcmwifi.Desired, layout []RadioDef, sae bool) (map[string]RadioPlan, []string) {
	var notes []string
	note := func(f string, a ...any) { notes = append(notes, fmt.Sprintf(f, a...)) }
	refused := ssidNotes(d.SSIDs, note)
	out := map[string]RadioPlan{}
	for _, rd := range layout {
		ri, ok := d.Radios[rd.Band]
		pct, tn := txPctNote(ri, rd.MaxTxDBm)
		if tn != "" {
			note("%s: %s", rd.Band, tn)
		}
		rp := RadioPlan{Band: rd.Band, On: ok && ri.Enabled, Width: ri.Width, TxPct: pct, MinRSSI: minRSSI(ri.MinRSSI),
			TxMode: ri.TxPowerMode}
		if rp.TxMode == "" {
			rp.TxMode = translate.TxAuto
		}
		allowed := chans24
		if rd.Band == "na" {
			allowed = chans5
			if rd.DFS {
				allowed = append(append([]int(nil), chans5...), chansDFS...)
			}
		}
		if ri.Channel != 0 {
			if contains(allowed, ri.Channel) {
				rp.Channel = ri.Channel
			} else {
				note("%s: channel %d is not allowed here: automatic channel", rd.Band, ri.Channel)
			}
		}
		switch {
		case rd.Band == "ng" && rp.Width != 20 && rp.Width != 40:
			rp.Width = 20
		case rd.Band == "na" && rp.Width > 80:
			note("na: %d MHz is not supported: 80 MHz", rp.Width)
			rp.Width = 80
		case rd.Band == "na" && rp.Width != 20 && rp.Width != 40 && rp.Width != 80:
			rp.Width = 80
		}
		if rf.Only20MHz(rd.Band, rp.Channel) && rp.Width > 20 {
			rp.Width = 20
		}
		maxSta := ri.MaxClients
		if maxSta <= 0 || maxSta > maxStaDefault {
			maxSta = maxStaDefault
		}
		var served []bcmwifi.SSID // parallel to rp.BSS
		for _, s := range d.SSIDs {
			if !s.Enabled || !onBand(s, rd.Band) || refused[s.ID] {
				continue
			}
			s = s.ForBand(rd.Band) // the controller's own values for this radio
			b := BSS{ID: s.ID, SSID: s.SSID, Hidden: s.Hidden, Isolate: s.Isolation, MaxSta: maxSta, VLAN: s.VLAN,
				RRM: s.RRM, BTM: s.BSSTransition, UAPSD: s.UAPSD && rd.UAPSD, M2U: s.MulticastToUnicast,
				Sched: len(s.Schedule) > 0, ProxyARP: s.ProxyARP, NoBGA: s.NoBGAFilter}
			switch s.Security {
			case translate.SecOpen, "":
				b.Auth, b.Encr = "OPEN", "NONE"
			case translate.SecWPA2WPA3:
				if sae && rd.SAE {
					b.Auth, b.Encr, b.PSK, b.PMF = "WPA2PSKWPA3PSK", "AES", s.Passphrase, 1
				} else {
					b.Auth, b.Encr, b.PSK = "WPA2PSK", "AES", s.Passphrase
				}
			case translate.SecWPA3:
				if !sae || !rd.SAE {
					note("%s: SSID %q: security wpa3 is not supported by this driver: not served", rd.Band, s.SSID)
					continue
				}
				b.Auth, b.Encr, b.PSK, b.PMF = "WPA3PSK", "AES", s.Passphrase, 2
			case translate.SecWPA2:
				b.Auth, b.Encr, b.PSK = "WPA2PSK", "AES", s.Passphrase
				// PMF as the controller sets it, where the driver has it
				// (the MT7663; the MT7603 module has no PMF profile keys).
				// PMF asked and not served is noted by bssNotes.
				switch {
				case !rd.SAE:
				case s.PMF == translate.PMFRequired:
					b.PMF = 2
				case s.PMF == translate.PMFOptional:
					b.PMF = 1
				}
			case translate.SecWPA2Ent, translate.SecWPA3Ent:
				// 802.1X through rtdot1xd (dot1x.go): AuthMode WPA2 on both
				// drivers; WPA3-Enterprise is WPA2 with PMF required, whose
				// RSNE then carries 802.1X-SHA256 only
				why := ""
				if b.Radius, why = dot1xOf(s, rd); b.Radius == nil {
					note("%s: SSID %q: %s: not served", rd.Band, s.SSID, why)
					continue
				}
				b.Auth, b.Encr = "WPA2", "AES"
				switch {
				case s.Security == translate.SecWPA3Ent || s.PMF == translate.PMFRequired:
					b.PMF = 2
				case s.PMF == translate.PMFOptional:
					b.PMF = 1
				}
				dot1xNotes(s, rd, note)
			default:
				note("%s: SSID %q: security %s is not supported by this driver: not served", rd.Band, s.SSID, s.Security)
				continue
			}
			if b.Auth != "OPEN" && s.GroupRekey > 0 {
				b.GroupRekey = s.GroupRekey
			}
			if s.Guest {
				if bcmwifi.GuestEbtables(d.Guest) == nil {
					note("%s: SSID %q: no usable guest policy (the gateway's MAC and IP): not served", rd.Band, s.SSID)
					continue
				}
				b.Guest = true
			}
			if b.VLAN < 0 || b.VLAN > 4094 || b.VLAN == 1 {
				note("%s: SSID %q: VLAN %d cannot be served: not served", rd.Band, s.SSID, b.VLAN)
				continue
			}
			// The length only (8..64 bytes), not translate.ValidWPAPassphrase,
			// which also wants printable ASCII and, at 64, hex digits. What
			// that rule refuses is written to the profile here: 64
			// characters that are not hex, and bytes outside printable ASCII
			// (translate applies the rule to WPA2 and WPA2/WPA3 WLANs before
			// they come here, not to WPA3-only ones). Applying it here would
			// stop serving such an SSID: left to the owner.
			// TestPassphraseLengthOnly shows the difference.
			if b.Auth != "OPEN" && b.Radius == nil && (len(b.PSK) < 8 || len(b.PSK) > 64) {
				note("%s: SSID %q: no valid passphrase: not served", rd.Band, s.SSID)
				continue
			}
			if strings.ContainsAny(b.SSID+b.PSK, "\n\r;") {
				note("%s: SSID %q: a ';' or line break in the SSID or passphrase cannot be written to the driver profile: not served", rd.Band, s.SSID)
				continue
			}
			if len(rp.BSS) == len(rd.Ifaces) {
				note("%s: SSID %q: this radio serves at most %d SSIDs: not served", rd.Band, s.SSID, len(rd.Ifaces))
				continue
			}
			if s.Security == translate.SecWPA2WPA3 && b.Auth == "WPA2PSK" {
				note("%s: SSID %q: served as WPA2 only (no SAE in this driver)", rd.Band, s.SSID)
			}
			ftPlan(&b, s, rd, sae, note) // roam.go
			bssNotes(s, b, rd, note)
			rp.BSS = append(rp.BSS, b)
			served = append(served, s)
		}
		if len(rp.BSS) == 0 {
			rp.On = false
		}
		if rp.On {
			radioFeatures(&rp, rd, ri, served, note)
		} else {
			rp.BSS, rp.Channel = nil, 0
		}
		out[rd.Band] = rp
	}
	return out, notes
}

func onBand(s bcmwifi.SSID, band string) bool {
	for _, b := range s.Bands {
		if rf.Norm(b) == band {
			return true
		}
	}
	return false
}

func contains(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Transmit power. Both drivers turn the profile's TxPower percentage into
// a power drop in the same brackets (MT7663 MtCmdTxPowerDropCtrl, MT7603
// CmdSetTxPowerCtrl; txpower-kick spec): 91-100 % no drop, 61-90 % 1 dB,
// 31-60 % 3 dB, 16-30 % 6 dB, 10-15 % 9 dB, 1-9 % 12 dB. 0 is the largest
// drop on the MT7603 but none on the MT7663, so it is never written. The
// dB unit is inferred from the field names (the MT7603 firmware might
// count half-dB steps; checked only by a live step test).

// txDrops are the drops (dB) a percentage can select, with the percentage
// written for each (the middle of its bracket's top).
var txDrops = []struct{ db, pct int }{{0, 100}, {1, 75}, {3, 50}, {6, 25}, {9, 12}, {12, 6}}

// txPctNote maps the controller's power setting onto the driver's
// percentage, with a note when a custom power is below what the driver
// can drop to. auto/high are the board's maximum, medium and low the 3
// and 6 dB brackets (as the Deco's presets).
func txPctNote(r bcmwifi.Radio, maxDBm int) (int, string) {
	switch r.TxPowerMode {
	case translate.TxMedium:
		return 50, ""
	case translate.TxLow:
		return 25, ""
	case translate.TxCustom:
		if r.TxPower <= 0 || maxDBm <= 0 {
			return 100, ""
		}
		want := maxDBm - r.TxPower
		for _, d := range txDrops {
			if d.db >= want {
				return d.pct, ""
			}
		}
		last := txDrops[len(txDrops)-1]
		return last.pct, fmt.Sprintf("transmit power %d dBm is below what the driver can set: %d dBm (the largest drop, %d dB)",
			r.TxPower, maxDBm-last.db, last.db)
	}
	return 100, "" // auto, high
}

// txPct is txPctNote without the note.
func txPct(r bcmwifi.Radio, maxDBm int) int { p, _ := txPctNote(r, maxDBm); return p }

// dropOf is the power drop (dB) the driver of band applies for a profile
// TxPower of pct (an invalid value is the driver's no-drop default).
func dropOf(pct int, band string) int {
	switch {
	case pct == 0 && band == "ng":
		return 12
	case pct <= 0, pct > 90:
		return 0
	case pct > 60:
		return 1
	case pct > 30:
		return 3
	case pct > 15:
		return 6
	case pct >= 10:
		return 9
	}
	return 12
}

// txDBm is the power rd transmits at for a profile TxPower of pct.
func txDBm(pct int, rd RadioDef) int { return rd.MaxTxDBm - dropOf(pct, rd.Band) }

// minRSSI clamps the controller's minimum RSSI to what the drivers take
// (Set_AP_ASSOC_REQ_RSSI_THRESHOLD: -100..0, 0 = off).
func minRSSI(v int) int {
	switch {
	case v >= 0:
		return 0
	case v < -100:
		return -100
	}
	return v
}

// ---------------------------------------------------------------- profiles

// setKeys rewrites base (a driver profile) with the given keys: an existing
// "key=" line is replaced, a missing key is appended.
func setKeys(base []byte, kv map[string]string) []byte {
	lines := strings.Split(strings.TrimRight(string(base), "\n"), "\n")
	done := map[string]bool{}
	for i, l := range lines {
		k, _, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		if v, want := kv[k]; want && !done[k] {
			lines[i] = k + "=" + v
			done[k] = true
		}
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		if !done[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		lines = append(lines, k+"="+kv[k])
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// getKey reads one key of a profile.
func getKey(b []byte, key string) (string, bool) {
	for _, l := range bytes.Split(b, []byte("\n")) {
		if k, v, ok := bytes.Cut(l, []byte("=")); ok && string(k) == key {
			return strings.TrimRight(string(v), "\r"), true
		}
	}
	return "", false
}

// listKey replaces the first len(vals) entries of a ;-list key of base,
// keeping the vendor's values for the slots not served.
func listKey(base []byte, key string, n int, vals []string, def string) string {
	var parts []string
	if cur, _ := getKey(base, key); cur != "" {
		parts = strings.Split(cur, ";")
	}
	for len(parts) < n {
		parts = append(parts, def)
	}
	parts = parts[:n]
	for i, v := range vals {
		parts[i] = v
	}
	return strings.Join(parts, ";")
}

// slotKey is listKey with each value in its BSS's slot (rp.Slots): the
// slots not served keep the vendor's values.
func slotKey(base []byte, key string, n int, rp RadioPlan, vals []string, def string) string {
	if rp.Slots == nil {
		return listKey(base, key, n, vals, def)
	}
	parts := strings.Split(listKey(base, key, n, nil, def), ";")
	for i, v := range vals {
		if s := rp.slot(i); s < n {
			parts[s] = v
		}
	}
	return strings.Join(parts, ";")
}

// profile is base rewritten for rp.
func profile(base []byte, rd RadioDef, rp RadioPlan) []byte {
	n := len(rd.Ifaces)
	kv := map[string]string{}
	if rp.Channel == 0 {
		kv["AutoChannelSelect"], kv["Channel"] = "3", "0"
	} else {
		kv["AutoChannelSelect"], kv["Channel"] = "0", strconv.Itoa(rp.Channel)
	}
	ht, ext := "0", "0"
	if rp.Width >= 40 {
		ht = "1"
		// secondary channel above for the lower channel of each 40 MHz pair
		if rd.Band == "ng" && rp.Channel != 0 && rp.Channel <= 7 ||
			rd.Band == "na" && rp.Channel != 0 && (rp.Channel/4)%2 == 1 {
			ext = "1"
		}
	}
	kv["HT_BW"], kv["HT_EXTCHA"] = ht, ext
	if rd.Band == "na" {
		kv["VHT_BW"] = "0"
		if rp.Width >= 80 {
			kv["VHT_BW"] = "1"
		}
	}
	kv["TxPower"] = strconv.Itoa(rp.TxPct)
	if rd.Band == "na" && isDFS(rp.Channel) {
		kv[regionA] = dfsRegA // the only region with 52-64 (dfs.go)
	}
	var auth, encr, hide, nofw, maxsta, mfpc, mfpr, sha []string
	for i, b := range rp.BSS {
		kv[fmt.Sprintf("SSID%d", rp.slot(i)+1)] = b.SSID
		if b.PSK != "" {
			kv[fmt.Sprintf("WPAPSK%d", rp.slot(i)+1)] = b.PSK
		}
		auth, encr = append(auth, b.Auth), append(encr, b.Encr)
		hide, nofw = append(hide, b01(b.Hidden)), append(nofw, b01(b.Isolate))
		maxsta = append(maxsta, strconv.Itoa(b.MaxSta))
		mfpc, mfpr = append(mfpc, b01(b.PMF >= 1)), append(mfpr, b01(b.PMF == 2))
		// 802.1X with PMF required: AKM 802.1X-SHA256 only (dot1x.go)
		sha = append(sha, b01(b.Radius != nil && b.PMF == 2))
	}
	kv["AuthMode"] = slotKey(base, "AuthMode", n, rp, auth, "WPA2PSK")
	kv["EncrypType"] = slotKey(base, "EncrypType", n, rp, encr, "AES")
	kv["HideSSID"] = slotKey(base, "HideSSID", n, rp, hide, "0")
	kv["NoForwarding"] = slotKey(base, "NoForwarding", n, rp, nofw, "0")
	kv[rd.MaxStaKey] = slotKey(base, rd.MaxStaKey, n, rp, maxsta, strconv.Itoa(maxStaDefault))
	if rd.SAE {
		// per-BSS lists; the slots not served keep PMF off
		kv["PMFMFPC"] = slotKey(nil, "PMFMFPC", n, rp, mfpc, "0")
		kv["PMFMFPR"] = slotKey(nil, "PMFMFPR", n, rp, mfpr, "0")
		kv["PMFSHA256"] = slotKey(nil, "PMFSHA256", n, rp, sha, "0")
	}
	kv["IEEE8021X"] = slotKey(base, "IEEE8021X", n, rp, []string{"0", "0", "0", "0"}[:len(rp.BSS)], "0")
	profileFeatures(kv, base, rd, rp)
	dot1xKeys(kv, base, rd, rp)
	return setKeys(base, kv)
}

func b01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
