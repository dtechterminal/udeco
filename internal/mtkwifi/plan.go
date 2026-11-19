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
//   - The MT7603 module (2.4 GHz) has no WPA3/SAE: WPA2/WPA3 WLANs are
//     served there as WPA2-PSK, WPA3-only ones are not served.
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
	"sort"
	"strconv"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

// RadioDef is one radio of the unit.
type RadioDef struct {
	Band      string   // "ng" or "na"
	Ifaces    []string // BSS netdevs in profile slot order; [0] reads the profile
	Dat       string   // driver profile (device path)
	MaxStaKey string   // per-BSS client limit list in the profile
	MaxTxDBm  int      // TxPower=100 (%)
	HWName    string
	SAE       bool // the driver serves WPA3-Personal (SAE)
}

// JCOW414 is the JioFiber JCOW414 layout.
var JCOW414 = []RadioDef{
	{Band: "ng", Ifaces: []string{"ra0", "ra1", "ra2", "ra3"}, Dat: "/etc/Wireless/RT2860AP/RT2860AP.dat",
		MaxStaKey: "MaxStaNum", MaxTxDBm: 20, HWName: "MT7603E"},
	{Band: "na", Ifaces: []string{"rai0", "rai1", "rai2", "rai3"}, Dat: "/etc/Wireless/RT2860AP_AC/RT2860AP.dat",
		MaxStaKey: "MbssMaxStaNum", MaxTxDBm: 23, HWName: "MT7663", SAE: true},
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
	Auth    string // OPEN, WPA2PSK, WPA2PSKWPA3PSK, WPA3PSK
	Encr    string // NONE, AES
	PMF     int    // 0 off, 1 capable (PMFMFPC), 2 required (PMFMFPR too)
	PSK     string `json:",omitempty"`
	Hidden  bool
	Isolate bool
	MaxSta  int
	VLAN    int // 0 = the LAN bridge
}

// RadioPlan is what one radio serves.
type RadioPlan struct {
	Band    string
	On      bool
	Channel int // 0 = the driver's automatic choice
	Width   int // 20, 40, 80
	TxPct   int // TxPower (% of the maximum)
	BSS     []BSS
}

// structural is everything that needs the radio restarted: the BSS list
// with names, security and keys, the channel, width and power. Hidden,
// Isolate and MaxSta are live.
func (r RadioPlan) structural() string {
	c := r
	c.BSS = nil
	for _, b := range r.BSS {
		b.Hidden, b.Isolate, b.MaxSta = false, false, 0
		c.BSS = append(c.BSS, b)
	}
	j, _ := json.Marshal(c)
	return string(j)
}

func (r RadioPlan) hash() string {
	j, _ := json.Marshal(r)
	h := sha256.Sum256(j)
	return hex.EncodeToString(h[:8])
}

func normBand(b string) string {
	switch strings.ToLower(b) {
	case "ng", "2g", "2.4g", "2ghz", "2.4ghz":
		return "ng"
	case "na", "5g", "5ghz":
		return "na"
	}
	return ""
}

// plans builds each radio's plan from d. Notes say what is not served.
// sae: WPA3 may be served on the radios whose driver has it.
func plans(d bcmwifi.Desired, layout []RadioDef, sae bool) (map[string]RadioPlan, []string) {
	var notes []string
	note := func(f string, a ...any) { notes = append(notes, fmt.Sprintf(f, a...)) }
	out := map[string]RadioPlan{}
	for _, rd := range layout {
		ri, ok := d.Radios[rd.Band]
		rp := RadioPlan{Band: rd.Band, On: ok && ri.Enabled, Width: ri.Width, TxPct: txPct(ri, rd.MaxTxDBm)}
		allowed := chans24
		if rd.Band == "na" {
			allowed = chans5
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
		if rd.Band == "na" && rp.Channel == 165 && rp.Width > 20 {
			rp.Width = 20
		}
		maxSta := ri.MaxClients
		if maxSta <= 0 || maxSta > maxStaDefault {
			maxSta = maxStaDefault
		}
		for _, s := range d.SSIDs {
			if !s.Enabled || !onBand(s, rd.Band) {
				continue
			}
			s = s.ForBand(rd.Band) // the controller's own values for this radio
			b := BSS{ID: s.ID, SSID: s.SSID, Hidden: s.Hidden, Isolate: s.Isolation, MaxSta: maxSta, VLAN: s.VLAN}
			switch s.Security {
			case "open", "":
				b.Auth, b.Encr = "OPEN", "NONE"
			case "wpa2wpa3":
				if sae && rd.SAE {
					b.Auth, b.Encr, b.PSK, b.PMF = "WPA2PSKWPA3PSK", "AES", s.Passphrase, 1
				} else {
					b.Auth, b.Encr, b.PSK = "WPA2PSK", "AES", s.Passphrase
				}
			case "wpa3":
				if !sae || !rd.SAE {
					note("%s: SSID %q: security wpa3 is not supported by this driver: not served", rd.Band, s.SSID)
					continue
				}
				b.Auth, b.Encr, b.PSK, b.PMF = "WPA3PSK", "AES", s.Passphrase, 2
			case "wpa2":
				b.Auth, b.Encr, b.PSK = "WPA2PSK", "AES", s.Passphrase
				// PMF as the controller sets it, where the driver has it
				// (the MT7663; the MT7603 module has no PMF profile keys)
				switch {
				case s.PMF != "optional" && s.PMF != "required":
				case rd.SAE && s.PMF == "required":
					b.PMF = 2
				case rd.SAE:
					b.PMF = 1
				default:
					note("%s: SSID %q: PMF %s is not supported by this driver: served without PMF", rd.Band, s.SSID, s.PMF)
				}
			default:
				note("%s: SSID %q: security %s is not supported by this driver: not served", rd.Band, s.SSID, s.Security)
				continue
			}
			if s.Guest {
				note("%s: SSID %q: guest networks are not supported here: not served", rd.Band, s.SSID)
				continue
			}
			if b.VLAN < 0 || b.VLAN > 4094 || b.VLAN == 1 {
				note("%s: SSID %q: VLAN %d cannot be served: not served", rd.Band, s.SSID, b.VLAN)
				continue
			}
			if b.Auth != "OPEN" && (len(b.PSK) < 8 || len(b.PSK) > 64) {
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
			if s.Security == "wpa2wpa3" && b.Auth == "WPA2PSK" {
				note("%s: SSID %q: served as WPA2 only (no SAE in this driver)", rd.Band, s.SSID)
			}
			rp.BSS = append(rp.BSS, b)
		}
		if len(rp.BSS) == 0 {
			rp.On = false
		}
		if !rp.On {
			rp.BSS, rp.Channel = nil, 0
		}
		out[rd.Band] = rp
	}
	return out, notes
}

func onBand(s bcmwifi.SSID, band string) bool {
	for _, b := range s.Bands {
		if normBand(b) == band {
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

// txPct maps the controller's power setting onto the driver's percentage
// (TxPower=100 is the board's maximum).
func txPct(r bcmwifi.Radio, maxDBm int) int {
	switch r.TxPowerMode {
	case "medium":
		return 50
	case "low":
		return 25
	case "custom":
		if r.TxPower <= 0 || maxDBm <= 0 {
			return 100
		}
		// each halving of power is -3 dB
		p := 100
		for db := maxDBm - r.TxPower; db >= 3 && p > 10; db -= 3 {
			p /= 2
		}
		return p
	}
	return 100 // auto, high
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
	var auth, encr, hide, nofw, maxsta, mfpc, mfpr []string
	for i, b := range rp.BSS {
		kv[fmt.Sprintf("SSID%d", i+1)] = b.SSID
		if b.PSK != "" {
			kv[fmt.Sprintf("WPAPSK%d", i+1)] = b.PSK
		}
		auth, encr = append(auth, b.Auth), append(encr, b.Encr)
		hide, nofw = append(hide, b01(b.Hidden)), append(nofw, b01(b.Isolate))
		maxsta = append(maxsta, strconv.Itoa(b.MaxSta))
		mfpc, mfpr = append(mfpc, b01(b.PMF >= 1)), append(mfpr, b01(b.PMF == 2))
	}
	kv["AuthMode"] = listKey(base, "AuthMode", n, auth, "WPA2PSK")
	kv["EncrypType"] = listKey(base, "EncrypType", n, encr, "AES")
	kv["HideSSID"] = listKey(base, "HideSSID", n, hide, "0")
	kv["NoForwarding"] = listKey(base, "NoForwarding", n, nofw, "0")
	kv[rd.MaxStaKey] = listKey(base, rd.MaxStaKey, n, maxsta, strconv.Itoa(maxStaDefault))
	if rd.SAE {
		// per-BSS lists; the slots not served keep PMF off
		kv["PMFMFPC"] = listKey(nil, "PMFMFPC", n, mfpc, "0")
		kv["PMFMFPR"] = listKey(nil, "PMFMFPR", n, mfpr, "0")
		kv["PMFSHA256"] = listKey(nil, "PMFSHA256", n, nil, "0")
	}
	kv["IEEE8021X"] = listKey(base, "IEEE8021X", n, []string{"0", "0", "0", "0"}[:len(rp.BSS)], "0")
	return setKeys(base, kv)
}

func b01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
