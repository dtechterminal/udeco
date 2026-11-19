// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Intent is the controller's system_cfg as backend-neutral desired state for
// one AP: what to broadcast and how, with no UCI (or any other backend) in
// it. IntentFromCfg builds it; a backend (bcmwifi on a Deco) maps it onto its
// own primitives and clamps what its hardware cannot do.
//
// Bands are named as the controller names radios: "ng" (2.4 GHz), "na"
// (5 GHz) and "6e" (6 GHz).
//
// Secrets (WLAN passphrases, RADIUS secrets, the syslog key, user password
// hashes) are carried because a backend needs them, but every type here
// prints them masked: log an Intent with %v/%+v/%s, never field by field.
type Intent struct {
	Country string                 // ISO 3166-1 alpha-2; "" = not sent or not recognised
	Radios  map[string]RadioIntent // by band: "ng", "na", "6e"
	WLANs   []WLANIntent           // one per controller WLAN, in system_cfg order
	Users   []User                 // device SSH users (users.N), if present
	LED     *bool                  // ledbar.status; nil = not sent (mgmt_cfg led_enabled decides)
	Syslog  *SyslogIntent          // remote syslog; nil = off
	SSHD    *SSHDIntent            // the device SSH server switch (sshd.*); nil = not sent (sshd.go)
}

// RadioIntent is one radio (radio.N plus its stamgr and bandsteering
// entries).
type RadioIntent struct {
	Enabled     bool
	Channel     int    // primary channel; 0 = auto
	Width       int    // MHz (20, 40, 80, 160) from ieee_mode; 0 = not recognised
	TxPowerMode string // auto, low, medium, high (the controller's presets) or custom
	TxPower     int    // dBm, only for TxPowerMode custom
	MinRSSI     int    // dBm (negative); 0 = off
	MaxClients  int    // per radio (stamgr load balance); 0 = no limit
	BandSteer   string // "prefer_5g", "equal"; "" = off for this radio's WLANs
}

// WLANIntent is one controller WLAN across the bands it is on (the
// controller sends a wireless.N/aaa.N pair per radio; they are merged by
// WLAN id). Settings that the controller sends per radio are maps by band.
//
// Passphrase and Radius secrets are secrets: print a WLANIntent with %v or
// String, never field by field.
type WLANIntent struct {
	ID   string // the controller's WLAN id (wireless.N.id); the SSID when none was sent
	SSID string
	// Bands the WLAN broadcasts on (its enabled VAPs). When no VAP is
	// enabled, Enabled is false and Bands lists every band it is set up for.
	Bands   []string
	Enabled bool
	Hidden  bool
	Guest   bool

	Security   string // open, wpa2, wpa3, wpa2wpa3, wpa2-enterprise, wpa3-enterprise, owe
	Passphrase string // WPA2/WPA3 personal; secret
	PMF        string // disabled, optional, required
	GroupRekey int    // seconds; 0 = never (the controller's default)

	VLAN               int    // 802.1Q id; 0 = untagged (the AP's own LAN)
	Isolation          bool   // client (L2) isolation
	FT                 bool   // 802.11r
	MobilityDomain     string // 802.11r mobility domain (4 hex digits); "" = backend's choice
	FTSAE              bool   // with FT, WPA3 (SAE) clients fast-roam too (aaa.N.wpa3.ft.status)
	FTKey              string // with FT: the WLAN's iapp_key, UniFi's key for PMK-R1 transfers between APs; secret
	FTOverDS           bool   // 802.11r over the DS (aaa.N.ft_over_ds); off = over the air
	BSSTransition      bool   // 802.11v
	RRM                bool   // 802.11k
	UAPSD              bool
	ProxyARP           bool
	MulticastToUnicast bool // multicast enhancement
	// PerBand holds each band's own security and roaming settings when the
	// controller sends them differently per radio (e.g. WPA2/WPA3 on 5 GHz
	// and WPA2 on 2.4 GHz for an AP that claims WPA3 on one radio only).
	// nil when every band's sections agree; the fields above are then the
	// WLAN's for every band.
	PerBand     map[string]BandWLAN
	DTIM        map[string]int // by band; absent = driver default
	MinRateKbps map[string]int // by band: lowest data rate allowed; absent = band default

	// MinRateOpts: by band, with MinRateKbps: beacon rate, CCK (minrate.go)
	MinRateOpts map[string]MinRateOpts
	// RoamAssist: the Roaming Assistant's RSSI threshold (dBm) by band
	// (wireless.N.btm_disassoc, roaming.go); absent = off on that band.
	RoamAssist map[string]int

	MACFilter *MACFilter
	Radius    *Radius   // enterprise WLANs and RADIUS MAC authentication
	PSKs      []PSK     // private pre-shared keys (aaa.N.wpa.psk_file, ppsk.go); secrets
	Hotspot2  *Hotspot2 // Hotspot 2.0 / Passpoint (aaa.N.hs20.*, hs20.go); nil = off
	// Schedule: nil = always on. Otherwise the weekly windows the WLAN is up
	// in, AP local time, as "mon 0800-1730" (end exclusive; 2400 = midnight).
	Schedule  []string
	RateLimit *RateLimit // per-client limit (user group)

	// Devnames: the controller's VAP device name per band (wireless.N.devname,
	// e.g. wifi0ap0); the inform's vap_table reports VAPs under these names.
	Devnames map[string]string
}

// MACFilter is a WLAN's MAC access list.
type MACFilter struct {
	Policy string   // "allow" (only these) or "deny" (all but these)
	MACs   []string // lower case
}

// Radius is a WLAN's RADIUS setup.
type Radius struct {
	Auth      []RadiusServer
	Acct      []RadiusServer
	NASID     string // nas_identifier; "" = backend's choice
	MACAuth   bool   // RADIUS MAC authentication (aaa.N.radius.macacl)
	MACFormat string // the controller's MAC format for MAC authentication, as sent
	FilterID  string // aaa.N.filter_id: Filter-Id sent in every Access-Request (radiusfilter.go)
}

// RadiusServer is one RADIUS server. Secret is a secret.
type RadiusServer struct {
	Host   string
	Port   int
	Secret string
	TLS    *RadSecTLS // RADIUS over TLS (RadSec) when non-nil (radsec.go)
}

// RateLimit is a per-client rate limit in kbit/s; 0 = no limit that way.
type RateLimit struct {
	DownKbps int
	UpKbps   int
}

// SyslogIntent is remote syslog. Encrypted is UniFi's sealed syslog
// (device.SealSyslog) with Key (64 hex digits; a secret).
type SyslogIntent struct {
	Host      string
	Port      int
	Encrypted bool
	Key       string
	Level     int // syslog.level; 0 = not sent
}

// IntentFromCfg turns a system_cfg text into an Intent. The notes list every
// setting that is not carried (unsupported or unrecognised keys, WLANs left
// off and why, settings that differ between bands); nothing is dropped
// silently except the controller's metadata and keys that only tune
// Ubiquiti's own drivers. Notes never contain secrets.
func IntentFromCfg(systemCfg string) (Intent, []string) {
	return IntentFrom(ParseCfg(systemCfg))
}

// IntentFrom is IntentFromCfg for an already parsed system_cfg.
func IntentFrom(cfg Cfg) (Intent, []string) {
	var nb noteList
	in := Intent{Radios: map[string]RadioIntent{}}
	phyBand := intentRadios(cfg, &in, &nb)
	skipped := intentWLANs(cfg, &in, phyBand, &nb)
	intentStamgr(cfg, &in, phyBand, &nb)
	if cfg["users.status"] == "enabled" {
		u, notes := Users(cfg)
		in.Users = u
		nb.add(notes...)
	}
	in.LED = intentLED(cfg, &nb)
	in.Syslog = intentSyslog(cfg, &nb)
	in.SSHD = SSHD(cfg)
	classifyKeys(cfg, phyBand, skipped, &nb)
	devnameNotes(cfg, &nb) // devname.go
	sectionNotes(cfg, &nb)
	return in, nb.list
}

// --- radios ---

// legacyBand maps the intent's band names to the package's older ones
// (wlanRates).
var legacyBand = map[string]string{"ng": "2g", "na": "5g", "6e": "6g"}

var widthRe = regexp.MustCompile(`(?:ht|vht|he|eht)(\d+)`)

// intentRadios fills in.Radios and in.Country and returns phy -> band.
func intentRadios(cfg Cfg, in *Intent, nb *noteList) map[string]string {
	phyBand := map[string]string{}
	global, raw := countryCode("", cfg["radio.countrycode"])
	if global == "" && raw != "" {
		nb.addf("radio.countrycode %q: unknown country code", raw)
	}
	in.Country = global
	for _, n := range indices(cfg, "radio") {
		p := "radio." + n + "."
		phy, mode := cfg[p+"phyname"], cfg[p+"ieee_mode"]
		if phy == "" {
			nb.addf("radio.%s: no phyname: ignored", n)
			continue
		}
		band := "na"
		switch {
		case strings.Contains(mode, "ng") || (phy == "wifi0" || phy == "ra0") && !strings.Contains(mode, "na"):
			band = "ng"
		case strings.Contains(mode, "6e"):
			band = "6e"
		}
		if _, dup := in.Radios[band]; dup {
			nb.addf("radio.%s (%s): a second %s radio: ignored", n, phy, band)
			continue
		}
		phyBand[phy] = band
		r := RadioIntent{Enabled: cfg[p+"status"] != "disabled" && cfg["radio.status"] != "disabled"}
		switch ch := cfg[p+"channel"]; ch {
		case "", "auto", "0":
		default:
			if v, err := strconv.Atoi(ch); err == nil && v > 0 {
				r.Channel = v
			} else {
				nb.addf("radio.%s (%s): channel %q not recognised: auto", n, band, ch)
			}
		}
		if m := widthRe.FindStringSubmatch(mode); m != nil {
			r.Width, _ = strconv.Atoi(m[1])
		} else if mode != "" {
			nb.addf("radio.%s (%s): ieee_mode %q has no channel width: width left to the backend", n, band, mode)
		}
		r.TxPowerMode, r.TxPower = txPower(cfg[p+"txpower_mode"], cfg[p+"txpower"], func(s string) {
			nb.addf("radio.%s (%s): %s", n, band, s)
		})
		if cc, raw := countryCode(cfg[p+"countrycode"], ""); cc != "" {
			if in.Country == "" {
				in.Country = cc
			} else if cc != in.Country {
				nb.addf("radio.%s (%s): country %s differs from %s: %s used", n, band, cc, in.Country, in.Country)
			}
		} else if raw != "" {
			nb.addf("radio.%s (%s): unknown country code %q", n, band, raw)
		}
		in.Radios[band] = r
	}
	if cfg["radio.outdoor"] == "enabled" {
		nb.addf("radio.outdoor: outdoor mode is not supported: indoor channel rules apply")
	}
	return phyBand
}

// txPower: the controller's tx power preset (radio.N.txpower_mode) and
// value. Without a mode, txpower "auto" means auto and a number custom. The
// value is used only for custom (a preset keeps a stale txpower beside it).
func txPower(mode, tp string, note func(string)) (string, int) {
	custom := func() (string, int) {
		v, err := strconv.Atoi(tp)
		if err != nil || v <= 0 {
			note(fmt.Sprintf("tx power %q not recognised: auto", tp))
			return "auto", 0
		}
		return "custom", v
	}
	switch mode {
	case "":
		if tp == "" || tp == "auto" {
			return "auto", 0
		}
		return custom()
	case "auto", "low", "medium", "high":
		return mode, 0
	case "custom":
		return custom()
	default:
		note(fmt.Sprintf("txpower_mode %q not recognised: auto", mode))
		return "auto", 0
	}
}

// intentStamgr adds minimum RSSI, client limits (stamgr.N) and band
// steering (bandsteering) to the radios.
func intentStamgr(cfg Cfg, in *Intent, phyBand map[string]string, nb *noteList) {
	if cfg["stamgr.status"] != "disabled" {
		for _, n := range indices(cfg, "stamgr") {
			p := "stamgr." + n + "."
			band := cfg[p+"radio"]
			r, ok := in.Radios[band]
			if !ok {
				if band != "" {
					nb.addf("stamgr.%s: no %s radio here: ignored", n, band)
				}
				continue
			}
			if cfg[p+"status"] == "disabled" {
				continue
			}
			if cfg[p+"minrssi.status"] == "true" || cfg[p+"minrssi.status"] == "enabled" {
				if v, err := strconv.Atoi(cfg[p+"minrssi.rssi"]); err == nil && v != 0 {
					if v > 0 { // RSSI above the noise floor -> dBm
						v -= 95
					}
					r.MinRSSI = v
				}
			}
			if cfg[p+"loadbalance.status"] == "true" || cfg[p+"loadbalance.status"] == "enabled" {
				if v, err := strconv.Atoi(cfg[p+"loadbalance.maxsta"]); err == nil && v > 0 {
					r.MaxClients = v
				}
			}
			in.Radios[band] = r
		}
	}
	s := BandSteering(cfg)
	if s.Mode == "" {
		return
	}
	devBand := map[string]string{}
	for _, n := range indices(cfg, "wireless") {
		if d := cfg["wireless."+n+".devname"]; d != "" {
			devBand[d] = phyBand[cfg["wireless."+n+".parent"]]
		}
	}
	for _, d := range s.Devnames {
		if r, ok := in.Radios[devBand[d]]; ok {
			r.BandSteer = s.Mode
			in.Radios[devBand[d]] = r
		}
	}
}

// --- WLANs ---

// intentWLANs fills in.WLANs from the wireless.N/aaa.N pairs and returns the
// wireless/aaa sections it left out entirely (already noted), whose keys are
// then not classified one by one.
func intentWLANs(cfg Cfg, in *Intent, phyBand map[string]string, nb *noteList) map[string]bool {
	skipped := map[string]bool{}
	vlanNet, _ := vlanNetworks(cfg)
	limits := map[string]VAPLimit{}
	for _, l := range QoSLimits(cfg) {
		limits[l.Devname] = l
	}
	type vap struct {
		n string // wireless.N
		x WLANIntent
	}
	var order []string
	groups := map[string][]vap{} // WLAN id -> its VAPs, one per band
	for _, n := range indices(cfg, "wireless") {
		w := "wireless." + n + "."
		a := aaaFor(cfg, n)
		ssid := cfg[w+"ssid"]
		if ssid == "" {
			ssid = cfg[a+"ssid"]
		}
		skip := func(why string) {
			nb.addf("wireless.%s (%q): %s", n, ssid, why)
			skipped["wireless."+n] = true
			if a != "" {
				skipped[strings.TrimSuffix(a, ".")] = true
			}
		}
		if a == "" {
			skip(fmt.Sprintf("aaa.%s is for another VAP and no aaa section names %s: left off", n, cfg[w+"devname"]))
			continue
		}
		if cfg[w+"usage"] == "uplink" || cfg[w+"usage"] == "downlink" || cfg[w+"vwire"] == "enabled" || cfg[w+"vport"] == "enabled" {
			skip("mesh/uplink VAP: not supported (wired uplink only)")
			continue
		}
		if cfg[w+"element_adopt"] == "enabled" {
			skip("element-adopt SSID (adopting UniFi devices over Wi-Fi): not supported")
			continue
		}
		band, ok := phyBand[cfg[w+"parent"]]
		if !ok {
			// the UniFi convention when radio sections do not name the parent
			band, ok = map[string]string{"wifi0": "ng", "wifi1": "na", "wifi2": "6e", "ra0": "ng", "rai0": "na"}[cfg[w+"parent"]]
		}
		if _, have := in.Radios[band]; !ok || (!have && len(in.Radios) > 0) {
			skip(fmt.Sprintf("radio %q is not on this AP: ignored", cfg[w+"parent"]))
			continue
		}
		if ssid == "" {
			skip("no SSID: ignored")
			continue
		}
		x, why := intentVAP(cfg, n, w, a, band, ssid, vlanNet, limits, nb)
		if why != "" {
			skip(why + ": left off")
			continue
		}
		if groups[x.ID] == nil {
			order = append(order, x.ID)
		}
		// One BSS per WLAN and band: a second VAP of the same WLAN on a band
		// (e.g. the open half of an OWE transition pair) is left off, keeping
		// the secured one.
		dup := -1
		for i, v := range groups[x.ID] {
			if v.x.Bands[0] == band {
				dup = i
			}
		}
		if dup < 0 {
			groups[x.ID] = append(groups[x.ID], vap{n, x})
			continue
		}
		kept, dropped := groups[x.ID][dup], vap{n, x}
		if kept.x.Security == "open" && x.Security != "open" {
			kept, dropped = dropped, kept
			groups[x.ID][dup] = kept
		}
		nb.addf("wireless.%s (%q on %s): another VAP of WLAN %s on this band (wireless.%s) is used: left off",
			dropped.n, ssid, band, x.ID, kept.n)
	}
	for _, id := range order {
		var vaps []WLANIntent
		for _, v := range groups[id] {
			vaps = append(vaps, v.x)
		}
		x := mergeVAPs(vaps, nb)
		if x.Guest {
			nb.addf("wlan %q: guest network: guest isolation (the controller's ebtables/iptables/ipset rules) and the portal are not part of the intent (see GuestPolicy)", x.SSID)
		}
		in.WLANs = append(in.WLANs, x)
	}
	if cfg["wireless.status"] == "disabled" && len(in.WLANs) > 0 {
		nb.addf("wireless.status=disabled: every WLAN is off")
	}
	return skipped
}

// aaaFor finds the aaa section of wireless.N: aaa.N, unless that one names
// another VAP, in which case the aaa section naming wireless.N's devname. ""
// means aaa.N is another VAP's and none is this one's: using aaa.N would give
// this SSID another WLAN's security (possibly open).
func aaaFor(cfg Cfg, n string) string {
	dev := cfg["wireless."+n+".devname"]
	if d := cfg["aaa."+n+".devname"]; dev == "" || d == "" || d == dev {
		return "aaa." + n + "."
	}
	for _, m := range indices(cfg, "aaa") {
		if cfg["aaa."+m+".devname"] == dev {
			return "aaa." + m + "."
		}
	}
	return ""
}

// intentVAP reads one wireless.N/aaa.N pair (one band of a WLAN). why != ""
// means the VAP must stay off (its security cannot be built as configured).
func intentVAP(cfg Cfg, n, w, a, band, ssid string, vlanNet map[string]string, limits map[string]VAPLimit, nb *noteList) (WLANIntent, string) {
	dev := cfg[w+"devname"]
	if dev == "" {
		dev = cfg[a+"devname"]
	}
	x := WLANIntent{
		ID:                 cfg[w+"id"],
		SSID:               ssid,
		Bands:              []string{band},
		Enabled:            cfg[w+"status"] != "disabled" && cfg[a+"status"] != "disabled" && cfg["wireless.status"] != "disabled",
		Hidden:             cfg[w+"hide_ssid"] == "true" || cfg[a+"hide_ssid"] == "true",
		Guest:              cfg[a+"is_guest"] == "true" || cfg[w+"is_guest"] == "true" || cfg[w+"usage"] == "guest",
		Isolation:          cfg[w+"l2_isolation"] == "enabled",
		BSSTransition:      cfg[a+"bss_transition"] == "enabled",
		RRM:                cfg[a+"11k.status"] == "enabled",
		UAPSD:              cfg[w+"uapsd"] == "enabled",
		ProxyARP:           cfg[a+"proxy_arp"] == "enabled",
		MulticastToUnicast: isOn(cfg[w+"mcast.enhance"]),
		Devnames:           map[string]string{},
	}
	if x.ID == "" {
		x.ID = cfg[a+"id"]
	}
	if x.ID == "" {
		x.ID = ssid
	}
	if dev != "" {
		x.Devnames[band] = dev
	}
	note := func(format string, args ...any) {
		nb.addf("wireless.%s (%q on %s): %s", n, ssid, band, fmt.Sprintf(format, args...))
	}
	if why := wlanSecurity(cfg, w, a, &x, note); why != "" {
		return x, why
	}
	if why := wlanHotspot2(cfg, w, a, &x, note); why != "" { // Hotspot 2.0: hs20.go
		return x, why
	}
	if v := cfg[a+"wpa.group_rekey"]; v != "" && x.Security != "open" {
		if r, err := strconv.Atoi(v); err == nil && r >= 0 {
			x.GroupRekey = r
		} else {
			note("group rekey interval not recognised: default")
		}
	}
	if x.FT = cfg[a+"ft.status"] == "enabled"; x.FT {
		switch {
		case x.Security == "open" || x.Security == "owe":
			note("802.11r on an open/OWE network: not supported, off")
			x.FT = false
		case x.Security == "wpa3" && cfg[a+"wpa3.ft.status"] == "disabled":
			note("802.11r is on but FT-SAE (wpa3.ft.status) is off: 802.11r off")
			x.FT = false
		case x.Security == "wpa2wpa3" && cfg[a+"wpa3.ft.status"] != "enabled":
			note("802.11r is on for WPA2 only (wpa3.ft.status is off): WPA3 clients do not fast-roam")
		}
		x.FTSAE = x.FT && (x.Security == "wpa3" || x.Security == "wpa2wpa3") && cfg[a+"wpa3.ft.status"] == "enabled"
		if x.FT {
			x.FTKey = cfg[a+"iapp_key"]
			x.FTOverDS = isOn(cfg[a+"ft_over_ds"])
		}
		if md := cfg[a+"mobility_domain"]; mobilityDomain.MatchString(md) {
			x.MobilityDomain = strings.ToLower(md)
		} else if md != "" {
			// hostapd refuses to start (every BSS of the radio) on a bad one
			note("mobility domain %q is not 4 hex digits: backend's choice", md)
		}
	}
	x.VLAN = wlanVLAN(cfg, a, dev, vlanNet, note)
	if d := cfg[w+"dtim_period"]; d != "" {
		if v, err := strconv.Atoi(d); err == nil && v >= 1 && v <= 255 {
			x.DTIM = map[string]int{band: v}
		} else {
			note("dtim_period %q not recognised: default", d)
		}
	}
	if v, o, ok := wlanMinRate(cfg, w, band); ok {
		x.MinRateKbps = map[string]int{band: v}
		x.MinRateOpts = map[string]MinRateOpts{band: o}
	}
	if t, ok := roamAssist(cfg, w, band, x.BSSTransition, note); ok {
		x.RoamAssist = map[string]int{band: t}
	}
	x.MACFilter = wlanMACFilter(cfg, w, dev, note)
	if s := wlanSchedule(cfg, w, ""); s != nil {
		// A UAP (unifi_util_funcs.sh within_schedule; ubntbox touches
		// schedule_invert.<vap> for schedule_invert=enabled) is up during
		// the windows, and down during them when inverted. Schedule.OnDuring
		// (schedule.go) reads schedule_invert the other way round.
		s.OnDuring = cfg[w+"schedule_invert"] != "enabled"
		on, never := scheduleOn(s)
		if never {
			note("broadcast schedule never on: WLAN off")
			x.Enabled = false
		}
		x.Schedule = on
	}
	if l, ok := limits[dev]; ok && dev != "" {
		x.RateLimit = &RateLimit{DownKbps: l.DownKbps, UpKbps: l.UpKbps}
	}
	return x, ""
}

var mobilityDomain = regexp.MustCompile(`^[0-9A-Fa-f]{4}$`)

// wlanMACFilter: the WLAN's MAC access list. Network 11 sends it in the
// wireless section (wireless.N.mac_acl.{status,policy,M.mac}; with no filter
// it sends status=enabled, policy=deny and no MACs); older controllers in the
// macacl section keyed by the VAP's devname (macACL). A deny list with no
// MACs is no filter. An allow list with no MACs admits nobody, as on a UAP:
// it is kept, never dropped (that would open the WLAN to every client).
func wlanMACFilter(cfg Cfg, w, dev string, note func(string, ...any)) *MACFilter {
	pol := ""
	var macs []string
	if cfg[w+"mac_acl.status"] == "enabled" {
		pol = cfg[w+"mac_acl.policy"]
		for _, m := range indices(cfg, strings.TrimSuffix(w, ".")+".mac_acl") {
			if v := strings.ToLower(strings.TrimSpace(cfg[w+"mac_acl."+m+".mac"])); v != "" {
				macs = append(macs, v)
			}
		}
		if pol != "allow" && pol != "deny" {
			if pol != "" {
				note("MAC filter policy %q not recognised: no MAC filter", pol)
			}
			pol, macs = "", nil
		}
	}
	if len(macs) > 0 {
		return &MACFilter{Policy: pol, MACs: macs}
	}
	if p, m := macACL(cfg, dev); p != "disable" {
		return &MACFilter{Policy: p, MACs: m}
	}
	if pol == "allow" {
		note("MAC allow list is empty: no client can join")
		return &MACFilter{Policy: "allow"}
	}
	return nil
}

func isOn(v string) bool {
	switch v {
	case "", "0", "false", "disabled", "off":
		return false
	}
	return true
}

// wlanSecurity sets x.Security, Passphrase, PMF and Radius from aaa.N. A
// non-empty result means the security type is not supported (or is
// incomplete) and the WLAN must stay off: it is never built weaker, and
// never open.
func wlanSecurity(cfg Cfg, w, a string, x *WLANIntent, note func(string, ...any)) string {
	var mgmt []string
	for _, m := range indices(cfg, strings.TrimSuffix(a, ".")+".wpa.key") {
		mgmt = append(mgmt, strings.Fields(cfg[a+"wpa.key."+m+".mgmt"])...)
	}
	has := func(names ...string) bool {
		for _, m := range mgmt {
			for _, s := range names {
				if m == s {
					return true
				}
			}
		}
		return false
	}
	wpa, psk := cfg[a+"wpa"], cfg[a+"wpa.psk"]
	auth := radiusServers(cfg, a, "auth", 1812)
	macAuth := cfg[a+"radius.macacl.status"] == "enabled"
	if s := cfg[a+"security"]; s != "" && s != "none" && s != "open" {
		return fmt.Sprintf("security %q (WEP) is not supported", s)
	}
	if s := cfg[w+"security"]; strings.HasPrefix(s, "wep") {
		return fmt.Sprintf("security %q (WEP) is not supported", s)
	}
	if why := radsecCheck(cfg, a); why != "" { // RADIUS over TLS: radsec.go
		return why
	}
	// private pre-shared keys: RADIUS-assigned, a per-client key file, or
	// SAE password identifiers
	ppsk := isOn(cfg[a+"wpa.psk_radius"]) || isOn(cfg[a+"wpa.psk_file.status"]) ||
		len(indices(cfg, strings.TrimSuffix(a, ".")+".sae.psk")) > 0
	eap := has("WPA-EAP", "WPA-EAP-SHA256", "FT-EAP", "FT-EAP-SHA384", "WPA-EAP-SUITE-B", "WPA-EAP-SUITE-B-192")
	switch {
	case has("WPA-EAP-SUITE-B", "WPA-EAP-SUITE-B-192") || isOn(cfg[a+"wpa3.enhanced_192"]):
		return "WPA3-Enterprise 192-bit (Suite B) is not supported"
	case eap || psk == "" && len(auth) > 0 && !macAuth && !ppsk && !has("WPA-PSK", "WPA-PSK-SHA256", "SAE", "FT-PSK", "FT-SAE"):
		if len(auth) == 0 {
			return "WPA-Enterprise without a RADIUS auth server"
		}
		wpa3 := has("WPA-EAP-SHA256") && !has("WPA-EAP") ||
			cfg[a+"wpa3.support"] == "enabled" && cfg[a+"wpa3.transition"] != "enabled"
		x.Security = "wpa2-enterprise"
		if wpa3 {
			x.Security = "wpa3-enterprise"
		} else if cfg[a+"wpa3.support"] == "enabled" || has("WPA-EAP-SHA256") {
			note("WPA2/WPA3-Enterprise transition: built as wpa2-enterprise")
		}
	case has("OWE") || wpa == "" && psk == "" && len(mgmt) == 0 && cfg[a+"wpa3.support"] == "enabled":
		x.Security = "owe"
		if cfg[a+"owe_devname"] != "" {
			note("OWE transition (an open twin of this SSID) is not supported: OWE only")
		}
	case wpa == "" && psk == "" && len(mgmt) == 0:
		if ppsk {
			return "private pre-shared keys without a WPA mode: not built as open"
		}
		x.Security = "open"
	default:
		switch wpa {
		case "1":
			return "WPA1 (TKIP) only is not supported"
		case "3":
			note("WPA/WPA2 mixed mode: built as WPA2 only")
		}
		enc, encNote := encryption(cfg, a)
		switch enc {
		case "sae-mixed":
			x.Security = "wpa2wpa3"
		case "sae":
			x.Security = "wpa3"
		case "psk2+ccmp":
			x.Security = "wpa2"
			if strings.HasPrefix(encNote, "no key mgmt") {
				note("%s", encNote)
			}
		default:
			if encNote == "" {
				encNote = "security not recognised"
			}
			return encNote
		}
		if isOn(cfg[a+"wpa.psk_file.status"]) { // private pre-shared keys: ppsk.go
			if why := wlanPSKFile(cfg, a, x, note); why != "" {
				return why
			}
			ppsk = isOn(cfg[a+"wpa.psk_radius"]) || len(indices(cfg, strings.TrimSuffix(a, ".")+".sae.psk")) > 0
		}
		if psk == "" && len(x.PSKs) == 0 {
			if ppsk {
				return "private pre-shared keys (PPSK) are not supported"
			}
			return "WPA personal without a passphrase"
		}
		if psk != "" && x.Security != "wpa3" && !validWPAPassphrase(psk) {
			return "passphrase is not 8-63 characters (or 64 hex digits) as WPA2 requires"
		}
		if strings.IndexFunc(psk, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return "passphrase has control characters"
		}
		if ppsk {
			note("private pre-shared keys (PPSK) are not supported: the WLAN's passphrase only")
		}
		x.Passphrase = psk
	}
	for _, m := range indices(cfg, strings.TrimSuffix(a, ".")+".wpa") {
		if strings.Contains(cfg[a+"wpa."+m+".pairwise"], "TKIP") {
			note("TKIP is not supported: CCMP only")
		}
	}
	if len(auth) > 0 || macAuth {
		x.Radius = &Radius{
			Auth:      auth,
			Acct:      radiusServers(cfg, a, "acct", 1813),
			NASID:     cfg[a+"nas_identifier"],
			MACAuth:   macAuth,
			MACFormat: cfg[a+"radius.macacl.format"],
			FilterID:  radiusFilterID(cfg[a+"filter_id"], note),
		}
		if macAuth && len(auth) == 0 {
			return "RADIUS MAC authentication without a RADIUS auth server"
		}
	}
	x.PMF = map[string]string{"0": "disabled", "1": "optional", "2": "required"}[pmf(cfg[a+"pmf.status"], cfg[a+"pmf.mode"])]
	switch x.Security {
	case "open":
		x.PMF = "disabled"
	case "wpa3", "owe", "wpa3-enterprise":
		if x.PMF != "required" {
			note("PMF %s raised to required (%s needs it)", x.PMF, x.Security)
			x.PMF = "required"
		}
	case "wpa2wpa3":
		if x.PMF == "disabled" {
			note("PMF disabled raised to optional (WPA2/WPA3 transition needs it)")
			x.PMF = "optional"
		}
	}
	if c := cfg[a+"pmf.cipher"]; c != "" && c != "AES-128-CMAC" && x.PMF != "disabled" {
		note("PMF cipher %q is not supported: AES-128-CMAC", c)
	}
	return ""
}

// validWPAPassphrase: what hostapd accepts as wpa_passphrase or wpa_psk.
func validWPAPassphrase(p string) bool {
	if len(p) == 64 {
		for _, c := range p {
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
		return true
	}
	if len(p) < 8 || len(p) > 63 {
		return false
	}
	for _, c := range p {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// radiusServers reads aaa.N.radius.<kind>.M.{ip,port,secret,status}.
func radiusServers(cfg Cfg, a, kind string, port int) []RadiusServer {
	var out []RadiusServer
	for _, m := range indices(cfg, a+"radius."+kind) {
		p := a + "radius." + kind + "." + m + "."
		if cfg[p+"status"] == "disabled" || cfg[p+"ip"] == "" {
			continue
		}
		s := RadiusServer{Host: cfg[p+"ip"], Port: port, Secret: cfg[p+"secret"]}
		if s.TLS = radsecTLS(cfg, p); s.TLS != nil { // RADIUS over TLS: radsec.go
			s.Port = RadSecPort
		}
		if v, err := strconv.Atoi(cfg[p+"port"]); err == nil && v > 0 && v < 65536 {
			s.Port = v
		}
		out = append(out, s)
	}
	return out
}

var vlanDev = regexp.MustCompile(`\.(\d{1,4})$`)

// wlanVLAN: the WLAN's 802.1Q id from its bridge (aaa.N.br.devname, e.g.
// br0.2, as Network 11 sends it) or from the bridge.N sections holding the VAP.
func wlanVLAN(cfg Cfg, a, dev string, vlanNet map[string]string, note func(string, ...any)) int {
	id := ""
	if m := vlanDev.FindStringSubmatch(cfg[a+"br.devname"]); m != nil {
		id = m[1]
	} else if n := vlanNet[dev]; n != "" {
		id = strings.TrimPrefix(n, "uow")
	}
	if id == "" {
		return 0
	}
	v, _ := strconv.Atoi(id)
	if v < 1 || v > 4094 {
		note("VLAN %s out of range: untagged", id)
		return 0
	}
	return v
}

// BandWLAN is one band's own security and roaming settings of a WLAN
// (WLANIntent.PerBand). Passphrase stays WLAN-wide.
type BandWLAN struct {
	Security           string
	PMF                string
	FT, FTSAE          bool
	FTOverDS           bool
	MobilityDomain     string
	BSSTransition, RRM bool
	UAPSD, ProxyARP    bool
	MulticastToUnicast bool
	Hidden, Isolation  bool
	GroupRekey         int
}

func bandWLAN(v WLANIntent) BandWLAN {
	return BandWLAN{Security: v.Security, PMF: v.PMF, FT: v.FT, FTSAE: v.FTSAE, FTOverDS: v.FTOverDS,
		MobilityDomain: v.MobilityDomain, BSSTransition: v.BSSTransition, RRM: v.RRM, UAPSD: v.UAPSD,
		ProxyARP: v.ProxyARP, MulticastToUnicast: v.MulticastToUnicast, Hidden: v.Hidden,
		Isolation: v.Isolation, GroupRekey: v.GroupRekey}
}

// bandFields are the WLANIntent fields BandWLAN carries per band.
var bandFields = map[string]bool{"security": true, "pmf": true, "ft": true, "ftsae": true, "ftoverds": true,
	"mobilitydomain": true, "bsstransition": true, "rrm": true, "uapsd": true, "proxyarp": true,
	"multicasttounicast": true, "hidden": true, "isolation": true, "grouprekey": true}

// mergeVAPs merges one WLAN's per-band VAPs. Band-wide settings are taken
// from the first VAP. When the bands differ in security or roaming settings,
// each band's own values are kept in PerBand (a backend that can serves every
// band exactly as the controller sent it; one that cannot, bcmwifi, notes
// it); any other difference is noted.
func mergeVAPs(vaps []WLANIntent, nb *noteList) WLANIntent {
	x := vaps[0]
	x.Bands, x.Enabled = nil, false
	x.DTIM, x.MinRateKbps, x.RoamAssist, x.Devnames = nil, nil, nil, map[string]string{}
	x.MinRateOpts = nil
	var all []string
	for _, v := range vaps {
		b := v.Bands[0]
		all = append(all, b)
		if v.Enabled {
			x.Enabled = true
			x.Bands = append(x.Bands, b)
		}
		for k, d := range v.DTIM {
			if x.DTIM == nil {
				x.DTIM = map[string]int{}
			}
			x.DTIM[k] = d
		}
		for k, r := range v.MinRateKbps {
			if x.MinRateKbps == nil {
				x.MinRateKbps = map[string]int{}
			}
			x.MinRateKbps[k] = r
		}
		for k, o := range v.MinRateOpts {
			if x.MinRateOpts == nil {
				x.MinRateOpts = map[string]MinRateOpts{}
			}
			x.MinRateOpts[k] = o
		}
		for k, d := range v.Devnames {
			x.Devnames[k] = d
		}
		x.RoamAssist = mergeBandInts(x.RoamAssist, v.RoamAssist)
		diff := differing(vaps[0], v)
		var other []string
		perBand := false
		for _, f := range diff {
			if bandFields[f] {
				perBand = true
			} else {
				other = append(other, f)
			}
		}
		if perBand {
			if x.PerBand == nil {
				x.PerBand = map[string]BandWLAN{vaps[0].Bands[0]: bandWLAN(vaps[0])}
			}
			x.PerBand[b] = bandWLAN(v)
		}
		if len(other) > 0 {
			nb.addf("wlan %q: %s differ on %s: the %s settings are used", x.SSID, strings.Join(other, ", "), b, vaps[0].Bands[0])
		}
	}
	if !x.Enabled {
		x.Bands = all
	}
	return x
}

// differing names the band-wide fields of a and b that differ (names only:
// some are secrets).
func differing(a, b WLANIntent) []string {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	t := va.Type()
	var out []string
	for i := 0; i < t.NumField(); i++ {
		switch name := t.Field(i).Name; name {
		case "Bands", "Enabled", "DTIM", "MinRateKbps", "MinRateOpts", "Devnames", "RoamAssist", "PerBand":
		default:
			if !reflect.DeepEqual(va.Field(i).Interface(), vb.Field(i).Interface()) {
				out = append(out, strings.ToLower(name))
			}
		}
	}
	return out
}

// scheduleOn turns a schedule into the weekly windows the WLAN is on: the
// windows themselves when OnDuring, else their complement. nil = always on;
// never = no window at all.
//
// A UAP's window includes its last minute (within_schedule tests
// now <= end), so "0000-2359" is the whole day; the windows returned are
// end-exclusive. A window that ends before it starts runs past midnight into
// the next day (a UAP would never match it; the controller splits such
// windows itself).
func scheduleOn(s *Schedule) (windows []string, never bool) {
	const day = 24 * 60
	sent := map[string][][2]int{} // day -> [start, end) minutes
	for i, d := range days {
		for _, w := range s.Windows[d] {
			a, b := hhmm(w[:4]), hhmm(w[5:])
			if a < 0 || b < 0 || a == day {
				continue
			}
			end := min(b+1, day)
			if b >= a {
				sent[d] = append(sent[d], [2]int{a, end})
				continue
			}
			sent[d] = append(sent[d], [2]int{a, day})
			next := days[(i+1)%len(days)]
			sent[next] = append(sent[next], [2]int{0, end})
		}
	}
	full := true
	for _, d := range days {
		iv := mergeIntervals(sent[d])
		if !s.OnDuring {
			iv = complement(iv, day)
		}
		if len(iv) != 1 || iv[0] != [2]int{0, day} {
			full = false
		}
		for _, x := range iv {
			windows = append(windows, fmt.Sprintf("%s %02d%02d-%02d%02d", d, x[0]/60, x[0]%60, x[1]/60, x[1]%60))
		}
	}
	if full {
		return nil, false
	}
	return windows, len(windows) == 0
}

// hhmm parses "HHMM" (00:00-24:00) to minutes; -1 if invalid.
func hhmm(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil || len(s) != 4 {
		return -1
	}
	h, m := v/100, v%100
	if m > 59 || h > 24 || h == 24 && m != 0 {
		return -1
	}
	return h*60 + m
}

func mergeIntervals(iv [][2]int) [][2]int {
	sort.Slice(iv, func(i, j int) bool { return iv[i][0] < iv[j][0] })
	var out [][2]int
	for _, x := range iv {
		if n := len(out); n > 0 && x[0] <= out[n-1][1] {
			out[n-1][1] = max(out[n-1][1], x[1])
			continue
		}
		out = append(out, x)
	}
	return out
}

func complement(iv [][2]int, end int) [][2]int {
	var out [][2]int
	at := 0
	for _, x := range iv {
		if x[0] > at {
			out = append(out, [2]int{at, x[0]})
		}
		at = x[1]
	}
	if at < end {
		out = append(out, [2]int{at, end})
	}
	return out
}

// --- device ---

func intentLED(cfg Cfg, nb *noteList) *bool {
	var led *bool
	switch cfg["ledbar.status"] {
	case "enabled":
		t := true
		led = &t
	case "disabled":
		f := false
		led = &f
	}
	if (led == nil || *led) && (cfg["ledbar.brightness"] != "" || cfg["ledbar.color.1.r"] != "") {
		nb.addf("ledbar: LED colour and brightness are not supported: on/off only")
	}
	return led
}

func intentSyslog(cfg Cfg, nb *noteList) *SyslogIntent {
	if cfg["syslog.status"] != "enabled" || cfg["syslog.remote.status"] != "enabled" || cfg["syslog.remote.ip"] == "" {
		return nil
	}
	s := &SyslogIntent{Host: cfg["syslog.remote.ip"], Port: 514, Encrypted: cfg["syslog.remote.encrypt"] == "enabled"}
	if v, err := strconv.Atoi(cfg["syslog.remote.port"]); err == nil && v > 0 && v < 65536 {
		s.Port = v
	}
	s.Level, _ = strconv.Atoi(cfg["syslog.level"])
	if s.Encrypted {
		k := cfg["syslog.remote.key"]
		if len(k) != 64 || strings.Trim(k, "0123456789abcdefABCDEF") != "" {
			nb.addf("syslog: encrypted remote syslog without a valid key: off")
			return nil
		}
		s.Key = k
	}
	return s
}

// --- key accounting ---

// rule says how a key of a wireless.N, aaa.N or radio.N section (or a
// global radio/aaa/wireless key) is treated.
type rule struct {
	kind    int      // ruleUse, ruleQuiet or ruleNeutral
	neutral []string // ruleNeutral: values that need no note
}

const (
	ruleUse     = iota // read into the intent
	ruleQuiet          // deliberately ignored: driver tuning, or only meaningful on a UAP
	ruleNeutral        // a setting not carried: noted unless its value is neutral
)

var (
	rRead  = rule{kind: ruleUse}
	rQuiet = rule{kind: ruleQuiet}
	// rOff: a setting not carried, silent while not in use
	rOff = rNeutral("", "0", "false", "disabled", "none")
)

func rNeutral(v ...string) rule { return rule{kind: ruleNeutral, neutral: v} }

var wirelessRules = map[string]rule{
	"ssid": rRead, "id": rRead, "parent": rRead, "devname": rRead, "usage": rRead, "status": rRead,
	"hide_ssid": rRead, "is_guest": rRead, "l2_isolation": rRead, "uapsd": rRead, "dtim_period": rRead,
	"minrate_data": rRead, "beacon_rate": rRead, "mgmt_rate": rRead, "minrate_cck_rates.status": rRead,
	"mcast.enhance": rRead, "schedule_enabled": rRead, "schedule_invert": rRead, "element_adopt": rRead,
	"vwire": rRead, "vport": rRead, "mac_acl.status": rRead, "mac_acl.policy": rRead, "security": rRead,

	"mode": rNeutral("master"), "wmm": rNeutral("enabled"), "wds": rOff, "autowds": rOff,
	"authmode": rNeutral("1"), "puren": rNeutral("0"), "pureg": rNeutral("0"),
	"addmtikie": rOff, "no2ghz_oui": rOff, "qbssload": rOff, "advertise_ap_name": rOff,
	"mcastrate": rNeutral("auto"), "bga_filter": rNeutral("enabled"),
	"multicast.suppressor": rOff, "iot": rOff, "btm_disassoc.status": rRead, "btm_disassoc.threshold": rRead,

	"multicast.inspect": rQuiet, // the UAP's own mDNS/multicast inspection for its statistics
	// lower rates are always removed from the rateset here (minrate.go)
	"minrate_below_disable": rQuiet,
}

var aaaRules = map[string]rule{
	"ssid": rRead, "id": rRead, "devname": rRead, "status": rRead, "is_guest": rRead, "hide_ssid": rRead,
	"security": rRead, "wpa": rRead, "wpa.psk": rRead, "wpa3.support": rRead, "wpa3.transition": rRead,
	"wpa3.ft.status": rRead, "pmf.status": rRead, "pmf.mode": rRead, "pmf.cipher": rRead, "ft.status": rRead,
	"mobility_domain": rRead, "11k.status": rRead, "bss_transition": rRead, "proxy_arp": rRead,
	"wpa.group_rekey": rRead, "br.devname": rRead, "nas_identifier": rRead, "radius.macacl.status": rRead,
	"radius.macacl.format": rRead, "owe_devname": rRead, "wpa.psk_radius": rRead,
	"wpa.psk_file.status": rRead, "wpa3.enhanced_192": rRead, "filter_id": rRead,

	"driver": rQuiet, "verbose": rQuiet, "eapol_version": rQuiet, "iapp_key": rQuiet,
	"sae.anti_clogging": rQuiet, "sae.sync": rQuiet, "ft_r0r1_cache_size": rQuiet,
	"ft_r0r1_key_lifetime": rQuiet, "owe_ptk_workaround": rQuiet, "radius.macacl.emptypassword": rQuiet,
	"rsn_preauth_uplinks": rQuiet,

	"p2p": rOff, "p2p_cross_connect": rOff, "tdls_prohibit": rOff, "country_beacon": rOff,
	"ft_over_ds": rOff, "rsn_preauth": rOff, "radius_acct_send_keyid.status": rOff,
	"radius.das.status": rOff, "radius.dad.status": rOff,
	// RADIUS/PPSK-assigned VLANs (this hostapd has no dynamic_vlan):
	// docs/deco/features/ppsk.md. aaa.N.hs20.* and aaa.N.osu.* (Hotspot 2.0)
	// are read in hs20.go.
	"dynamic_vlan": rOff,
}

var radioRules = map[string]rule{
	"phyname": rRead, "ieee_mode": rRead, "channel": rRead, "txpower": rRead, "txpower_mode": rRead,
	"countrycode": rRead, "status": rRead,

	// Ubiquiti driver tuning, or settings the backend derives from its own caps
	"ack.auto": rQuiet, "acktimeout": rQuiet, "ampdu.status": rQuiet, "clksel": rQuiet,
	"cwm.enable": rQuiet, "cwm.mode": rQuiet, "forbiasauto": rQuiet, "antenna": rQuiet,
	"antenna.gain": rQuiet, "bcmc_l2_filter.status": rQuiet, "devname": rQuiet, "rfscan": rQuiet,
	"bgscan.status": rQuiet, "acsdfs": rQuiet, "txpower.max": rQuiet, "txpower.offset": rQuiet,

	"mode": rNeutral("master"), "rate.auto": rNeutral("enabled"), "rate.mcs": rNeutral("auto"),
}

var globalRules = map[string]rule{
	"radio.status": rRead, "radio.countrycode": rRead, "radio.outdoor": rRead,
	"aaa.status": rQuiet, "wireless.status": rRead,
	"aaa.radius.dad.status": rOff, "aaa.radius.dad.port": rQuiet, "aaa.radius.dad.loglevel": rQuiet,
}

var sectionRules = map[string]map[string]rule{"wireless": wirelessRules, "aaa": aaaRules, "radio": radioRules}

var keyPatterns = map[string][]struct {
	re *regexp.Regexp
	r  rule
}{
	"wireless": {
		{regexp.MustCompile(`^schedule_(mon|tue|wed|thu|fri|sat|sun)(\.\d+)?$`), rRead},
		{regexp.MustCompile(`^mac_acl\.\d+\.mac$`), rRead},
	},
	"aaa": {
		{regexp.MustCompile(`^wpa\.key\.\d+\.mgmt$`), rRead},
		{regexp.MustCompile(`^wpa\.\d+\.pairwise$`), rRead},
		{regexp.MustCompile(`^radius\.(auth|acct)\.\d+\.(ip|port|secret|status|tls)$`), rRead},
		{regexp.MustCompile(`^radius\.(auth|acct)\.\d+\.(ca_cert|client_cert|private_key|private_key_passwd)$`), rQuiet},
		{regexp.MustCompile(`^radius\.(das|dad)\.`), rQuiet}, // only used with das/dad status, noted above
		// PPSK key file entries (ppsk.go); sae.psk entries are only checked for presence
		{regexp.MustCompile(`^wpa\.psk_file\.\d+\.(psk|vlanid|mac|keyid|status)$`), rRead},
		{regexp.MustCompile(`^sae\.psk\.\d+\.`), rQuiet},
	},
	"radio": {
		{regexp.MustCompile(`^(hard_noisefloor|antenna)\.`), rQuiet},
	},
}

// classifyKeys notes every wireless/aaa/radio key that is neither read nor
// deliberately ignored, and every unsupported setting in use. Values are
// printed only for enumerated, non-secret settings.
func classifyKeys(cfg Cfg, phyBand map[string]string, skipped map[string]bool, nb *noteList) {
	type inst struct{ unsupported, unknown []string }
	found := map[string]*inst{}
	var names []string
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		top, rest, _ := strings.Cut(k, ".")
		if top != "wireless" && top != "aaa" && top != "radio" {
			continue
		}
		name, sub := top, rest
		var r rule
		known := false
		if n, s, ok := strings.Cut(rest, "."); ok && isIndex(n) {
			name, sub = top+"."+n, s
			if skipped[name] {
				continue
			}
			r, known = sectionRules[top][sub]
			for _, p := range keyPatterns[top] {
				if !known && p.re.MatchString(sub) {
					r, known = p.r, true
				}
			}
		} else {
			r, known = globalRules[k]
		}
		if known && r.kind != ruleNeutral || known && contains(r.neutral, cfg[k]) {
			continue
		}
		if top == "wireless" && sub == "pureg" && phyBand[cfg[name+".parent"]] != "ng" {
			continue // "no 802.11b" means nothing off 2.4 GHz
		}
		f := found[name]
		if f == nil {
			f = &inst{}
			found[name] = f
			names = append(names, name)
		}
		if !known {
			f.unknown = append(f.unknown, sub)
		} else if IsSecretKey(k) || len(cfg[k]) > 32 {
			f.unsupported = append(f.unsupported, sub)
		} else {
			f.unsupported = append(f.unsupported, sub+"="+cfg[k])
		}
	}
	for _, name := range names {
		f := found[name]
		label := name
		if ssid := cfg[name+".ssid"]; ssid != "" {
			label = fmt.Sprintf("%s (%q)", name, ssid)
		}
		if len(f.unsupported) > 0 {
			nb.addf("%s: not supported, ignored: %s", label, strings.Join(f.unsupported, ", "))
		}
		if len(f.unknown) > 0 {
			nb.addf("%s: unrecognised keys, ignored: %s", label, strings.Join(f.unknown, ", "))
		}
	}
	// aaa sections that no wireless section uses
	used := map[string]bool{}
	for _, n := range indices(cfg, "wireless") {
		used[aaaFor(cfg, n)] = true
	}
	for _, n := range indices(cfg, "aaa") {
		if !used["aaa."+n+"."] {
			nb.addf("aaa.%s (%q): no wireless section uses it: ignored", n, cfg["aaa."+n+".ssid"])
		}
	}
}

func isIndex(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// sectionNotes covers the top-level system_cfg sections the intent does not
// carry: a note when they ask for something, nothing for the controller's
// metadata, and a note for sections not recognised at all.
func sectionNotes(cfg Cfg, nb *noteList) {
	enabled := func(sec string) bool { return cfg[sec+".status"] == "enabled" }
	seen := map[string]bool{}
	var secs []string
	for k := range cfg {
		top, _, _ := strings.Cut(k, ".")
		if !seen[top] {
			seen[top] = true
			secs = append(secs, top)
		}
	}
	sort.Strings(secs)
	for _, sec := range secs {
		switch sec {
		case "radio", "aaa", "wireless", "users", "stamgr", "bandsteering", "qos", "macacl",
			"vlan", "bridge", "syslog", "ledbar", "certs":
			// read above (vlan/bridge: WLAN VLANs; qos: rate limits; certs: RadSec, radsec.go)
		case "unifi", "mark", "ebtables", "iptables", "ip6tables", "ipset":
			// metadata; firewall rules for guests and VLANs (noted per guest WLAN)
		case "system", "locale":
			if sec+".timezone" == firstTZ(cfg) {
				nb.addf("%s.timezone: not applied", sec)
			}
		case "mesh":
			if enabled(sec) {
				nb.addf("mesh: wireless meshing is not supported (wired uplink only)")
			}
		case "connectivity":
			if enabled(sec) {
				nb.addf("connectivity: uplink monitoring settings are not applied")
			}
		case "netconsole":
			if enabled(sec) {
				nb.addf("netconsole: kernel log streaming is not supported")
			}
		case "sshd":
			if enabled(sec) {
				nb.addf("sshd: the controller's SSH server settings are not applied")
			}
		case "ntpclient":
			if enabled(sec) {
				nb.addf("ntpclient: NTP servers are not applied (time comes from the gateway)")
			}
		case "pathmon":
			pathmonNotes(cfg, nb) // run by the agent (internal/pathmon)
		case "snmp", "mdns_sd":
			// run by the agent, which logs its own notes: the SNMP agent
			// (internal/snmpagent, cmd/udeco-ap/snmp.go) and the mDNS
			// service bridge (internal/mdnsbr, cmd/udeco-ap/mdnsbr.go)
		case "switch", "dnsmasq", "redirector":
			if enabled(sec) {
				nb.addf("%s: not supported", sec)
			}
		case "dpi":
			if cfg["dpi.ip"] != "" {
				nb.addf("dpi: client fingerprint export is not supported")
			}
		case "netconf", "dhcpc", "route", "resolv":
			if sec == "netconf" && staticIP(cfg) {
				nb.addf("netconf: a static management address is not applied (the unit keeps its DHCP address)")
			}
		default:
			nb.addf("%s.*: section not recognised: ignored", sec)
		}
	}
}

// firstTZ names the key that carries the timezone ("" when none).
func firstTZ(cfg Cfg) string {
	for _, k := range []string{"system.timezone", "locale.timezone"} {
		if cfg[k] != "" {
			return k
		}
	}
	return ""
}

// staticIP reports whether the controller asks for a static address on the
// management bridge.
func staticIP(cfg Cfg) bool {
	bridge := cfg["connectivity.uplink_bridge"]
	if bridge == "" {
		bridge = "br0"
	}
	for _, n := range indices(cfg, "dhcpc") {
		if cfg["dhcpc."+n+".devname"] == bridge && cfg["dhcpc."+n+".status"] == "enabled" {
			return false
		}
	}
	for _, n := range indices(cfg, "netconf") {
		p := "netconf." + n + "."
		if cfg[p+"devname"] == bridge && cfg[p+"ip"] != "" && cfg[p+"ip"] != "0.0.0.0" {
			return true
		}
	}
	return false
}

// noteList collects notes in order, once each.
type noteList struct {
	list []string
	seen map[string]bool
}

func (n *noteList) add(notes ...string) {
	if n.seen == nil {
		n.seen = map[string]bool{}
	}
	for _, s := range notes {
		if !n.seen[s] {
			n.seen[s] = true
			n.list = append(n.list, s)
		}
	}
}

func (n *noteList) addf(format string, args ...any) { n.add(fmt.Sprintf(format, args...)) }

// --- printing with secrets masked ---

// String describes s with the secret masked.
func (s RadiusServer) String() string {
	if s.TLS != nil {
		return fmt.Sprintf("%s:%d secret=%s %v", s.Host, s.Port, Mask(s.Secret), s.TLS)
	}
	return fmt.Sprintf("%s:%d secret=%s", s.Host, s.Port, Mask(s.Secret))
}

// GoString is String: %#v must not print the secret either.
func (s RadiusServer) GoString() string { return s.String() }

// String describes s with the key masked.
func (s SyslogIntent) String() string {
	return fmt.Sprintf("%s:%d encrypted=%t key=%s level=%d", s.Host, s.Port, s.Encrypted, Mask(s.Key), s.Level)
}

// GoString is String: %#v must not print the key either.
func (s SyslogIntent) GoString() string { return s.String() }

// String describes w with the passphrase and RADIUS secrets masked.
func (w WLANIntent) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "wlan %s %q bands=%v enabled=%t hidden=%t guest=%t security=%s pmf=%s",
		w.ID, w.SSID, w.Bands, w.Enabled, w.Hidden, w.Guest, w.Security, w.PMF)
	if w.Passphrase != "" {
		fmt.Fprintf(&b, " psk=%s", Mask(w.Passphrase))
	}
	opt := func(cond bool, s string) {
		if cond {
			b.WriteString(" " + s)
		}
	}
	opt(w.VLAN != 0, fmt.Sprintf("vlan=%d", w.VLAN))
	opt(w.GroupRekey != 0, fmt.Sprintf("rekey=%d", w.GroupRekey))
	opt(w.Isolation, "isolation")
	opt(w.FT, "802.11r")
	opt(w.FTSAE, "ft-sae")
	opt(w.FTOverDS, "ft-over-ds")
	opt(w.BSSTransition, "802.11v")
	opt(w.RRM, "802.11k")
	opt(w.UAPSD, "uapsd")
	opt(w.ProxyARP, "proxy-arp")
	opt(w.MulticastToUnicast, "mcast-enhance")
	opt(len(w.DTIM) > 0, fmt.Sprintf("dtim=%v", w.DTIM))
	opt(len(w.MinRateKbps) > 0, fmt.Sprintf("minrate=%v", w.MinRateKbps))
	opt(len(w.RoamAssist) > 0, fmt.Sprintf("roam-assist=%v", w.RoamAssist))
	opt(w.Hotspot2 != nil, "hotspot2("+w.Hotspot2.String()+")")
	if w.MACFilter != nil {
		fmt.Fprintf(&b, " macfilter=%s(%d)", w.MACFilter.Policy, len(w.MACFilter.MACs))
	}
	if w.Radius != nil {
		fmt.Fprintf(&b, " radius=%v", *w.Radius)
	}
	opt(w.Schedule != nil, fmt.Sprintf("schedule=%v", w.Schedule))
	if w.RateLimit != nil {
		fmt.Fprintf(&b, " limit=%d/%dkbps", w.RateLimit.DownKbps, w.RateLimit.UpKbps)
	}
	return b.String()
}

// GoString is String: %#v must not print secrets either.
func (w WLANIntent) GoString() string { return w.String() }

// String describes in with every secret masked (user password hashes are
// left out).
func (in Intent) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "country=%s", in.Country)
	var bands []string
	for band := range in.Radios {
		bands = append(bands, band)
	}
	sort.Strings(bands)
	for _, band := range bands {
		fmt.Fprintf(&b, " radio[%s]=%+v", band, in.Radios[band])
	}
	for _, w := range in.WLANs {
		fmt.Fprintf(&b, "; %s", w)
	}
	for _, u := range in.Users {
		fmt.Fprintf(&b, "; user %s", u.Name)
	}
	if in.LED != nil {
		fmt.Fprintf(&b, "; led=%t", *in.LED)
	}
	if in.Syslog != nil {
		fmt.Fprintf(&b, "; syslog %s", *in.Syslog)
	}
	if in.SSHD != nil {
		fmt.Fprintf(&b, "; %s", *in.SSHD)
	}
	return b.String()
}

// GoString is String: %#v must not print secrets either.
func (in Intent) GoString() string { return in.String() }
