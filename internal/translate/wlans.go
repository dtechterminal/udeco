// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/rf"
)

// WLAN is one UniFi WLAN on one radio: a wireless.N section and its aaa.N
// security section, as Plan walks them. Backends that do not write UCI (the
// Deco backend) read the controller's Wi-Fi intent from here.
//
// PSK is a secret: print a WLAN with String (or Mask the PSK), never with
// %+v.
type WLAN struct {
	Index   string // N of wireless.N / aaa.N
	ID      string // the controller's WLAN id (wireless.N.id)
	SSID    string
	Radio   string // parent radio name as the controller sends it (wifi0, wifi1)
	Band    string // "2g", "5g", "6g"; "" when the radio is unknown
	Devname string // VAP device name (wireless.N.devname, e.g. ath0 / wifi0ap0)
	Usage   string // wireless.N.usage (user, guest, uplink, ...)

	Enabled      bool // neither wireless.N.status nor aaa.N.status is disabled
	Hidden       bool // hide_ssid
	Guest        bool // aaa.N.is_guest
	Mesh         bool // a mesh/uplink VAP (usage=uplink, vwire, vport): not a user WLAN
	ElementAdopt bool // the controller's hidden adoption SSID
	RadioOff     bool // the parent radio is disabled (radio.N.status=disabled)

	// Encryption as Plan computes it: none, psk2+ccmp, sae, sae-mixed; ""
	// means unsupported (WEP, OWE, enterprise), with the reason in EncNote.
	Encryption string
	EncNote    string
	PSK        string // aaa.N.wpa.psk; secret

	// Features lists the controller settings on this WLAN beyond SSID,
	// security, hidden and enable (802.11r, schedules, VLAN, ...), so a
	// backend that cannot honour them can report them as clamped.
	Features []string
}

// String describes w with the passphrase masked.
func (w WLAN) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "wlan.%s %q on %s", w.Index, w.SSID, w.Radio)
	if w.Band != "" {
		fmt.Fprintf(&b, " (%s)", w.Band)
	}
	enc := w.Encryption
	if enc == "" {
		enc = "unsupported"
	}
	fmt.Fprintf(&b, " enabled=%t hidden=%t guest=%t enc=%s", w.Enabled, w.Hidden, w.Guest, enc)
	if w.PSK != "" {
		fmt.Fprintf(&b, " psk=%s", Mask(w.PSK))
	}
	if w.Mesh {
		b.WriteString(" mesh")
	}
	if w.ElementAdopt {
		b.WriteString(" element-adopt")
	}
	if len(w.Features) > 0 {
		fmt.Fprintf(&b, " features=%s", strings.Join(w.Features, ","))
	}
	return b.String()
}

// Mask renders a secret for logs: a short hash prefix, so a change is
// visible but the value is not. An empty value prints as ”.
func Mask(v string) string { return mask(v, true) }

// secretKeys are system_cfg key suffixes whose values are secrets.
var secretKeys = []string{".psk", "passphrase", "x_passphrase", ".secret", "password", "passwd", "authkey", "community", ".key"}

// IsSecretKey reports whether a system_cfg key holds a secret (passphrases,
// RADIUS secrets, SNMP communities, keys).
func IsSecretKey(k string) bool {
	k = strings.ToLower(k)
	for _, s := range secretKeys {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}

// MaskCfg returns a copy of cfg with every secret value masked.
func MaskCfg(cfg Cfg) Cfg {
	out := make(Cfg, len(cfg))
	for k, v := range cfg {
		if IsSecretKey(k) && v != "" {
			v = Mask(v)
		}
		out[k] = v
	}
	return out
}

// WLANs lists the controller's WLANs, one per wireless.N section, in index
// order. Radios are mapped to bands as Plan does (radio.N.phyname and
// ieee_mode); a parent the radio sections do not name falls back to the
// UniFi convention wifi0 = 2g, wifi1 = 5g. Nothing is skipped: callers
// decide what to do with mesh, element-adopt and unsupported WLANs.
func WLANs(cfg Cfg) []WLAN {
	phyBand := map[string]string{}
	radioOff := map[string]bool{}
	for _, n := range indices(cfg, "radio") {
		p := "radio." + n + "."
		phy, mode := cfg[p+"phyname"], cfg[p+"ieee_mode"]
		if phy == "" {
			continue
		}
		band := "5g"
		byName, _ := qcaRadioBand(phy)
		switch {
		case strings.Contains(mode, "ng") || byName == "ng" && !strings.Contains(mode, "na"):
			band = "2g"
		case strings.Contains(mode, "6e"):
			band = "6g"
		}
		phyBand[phy] = band
		radioOff[phy] = cfg[p+"status"] == "disabled"
	}
	vlanNet, _ := vlanNetworks(cfg)
	var out []WLAN
	for _, n := range indices(cfg, "wireless") {
		w, a := "wireless."+n+".", "aaa."+n+"."
		x := WLAN{
			Index:   n,
			ID:      cfg[w+"id"],
			SSID:    cfg[w+"ssid"],
			Radio:   cfg[w+"parent"],
			Devname: cfg[w+"devname"],
			Usage:   cfg[w+"usage"],
			Enabled: cfg[w+"status"] != "disabled" && cfg[a+"status"] != "disabled",
			Hidden:  cfg[w+"hide_ssid"] == "true" || cfg[a+"hide_ssid"] == "true",
			Guest:   cfg[a+"is_guest"] == "true",
			Mesh:    cfg[w+"usage"] == "uplink" || cfg[w+"vwire"] == "enabled" || cfg[w+"vport"] == "enabled",

			ElementAdopt: cfg[w+"element_adopt"] == "enabled",
			RadioOff:     radioOff[cfg[w+"parent"]],
			PSK:          cfg[a+"wpa.psk"],
		}
		if x.SSID == "" {
			x.SSID = cfg[a+"ssid"]
		}
		if b, ok := phyBand[x.Radio]; ok {
			x.Band = b
		} else {
			byName, _ := qcaRadioBand(x.Radio)
			x.Band = rf.Legacy(byName)
		}
		x.Encryption, x.EncNote = encryption(cfg, a)
		x.Features = wlanFeatures(cfg, w, a, x, vlanNet)
		out = append(out, x)
	}
	return out
}

// wlanFeatures names the settings of one WLAN beyond the basics.
func wlanFeatures(cfg Cfg, w, a string, x WLAN, vlanNet map[string]string) []string {
	var f []string
	on := func(cond bool, name string) {
		if cond {
			f = append(f, name)
		}
	}
	on(cfg[a+"ft.status"] == "enabled", "802.11r")
	on(cfg[a+"11k.status"] == "enabled", "802.11k")
	on(cfg[a+"bss_transition"] == "enabled", "802.11v")
	on(cfg[a+"pmf.status"] == "enabled" && cfg[a+"pmf.mode"] == "2", "pmf-required")
	on(cfg[w+"l2_isolation"] == "enabled", "l2-isolation")
	on(cfg[w+"uapsd"] == "enabled", "uapsd")
	on(cfg[w+"schedule_enabled"] == "enabled", "schedule")
	on(vlanNet[x.Devname] != "", "vlan")
	if sup, _ := wlanRates(cfg, w, x.Band); sup != nil {
		f = append(f, "min-rate")
	}
	if pol, _ := macACL(cfg, x.Devname); pol != "disable" {
		f = append(f, "mac-filter")
	}
	if d := cfg[w+"dtim_period"]; d != "" && d != "1" && d != "3" {
		f = append(f, "dtim-"+d)
	}
	for _, l := range QoSLimits(cfg) {
		if l.Devname != "" && l.Devname == x.Devname {
			f = append(f, "rate-limit")
			break
		}
	}
	sort.Strings(f)
	return f
}
