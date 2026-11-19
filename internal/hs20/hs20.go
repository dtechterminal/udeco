// SPDX-License-Identifier: GPL-2.0-or-later

// Package hs20 carries a WLAN's Hotspot 2.0 / Passpoint advertisement from
// the UniFi controller's system_cfg (aaa.N.hs20.*, aaa.N.osu.*) to hostapd
// 2.9 config lines (interworking=1, hs20=1 and the ANQP data), with no I/O.
//
// The controller (Network 11.1.50, com.ubnt.service.config.XHjguBsIf) sends
// it only to a device that claims fw_caps 0x800000 (supportHotspot2), and
// only for a WPA-Enterprise (or OSEN) WLAN whose hotspot2conf_enabled is
// set; every other WPA-Enterprise WLAN carries aaa.N.hs20.status=disabled.
// The key names and value shapes below come from that generator; the
// hostapd lines follow what a UAP's ubntbox writes for them
// (docs/reference/u6pro, strings-ubntbox) and what hostapd 2.9's
// config_file.c accepts. docs/deco/features/hotspot2.md has the details.
//
// Parse drops what it cannot render (with a note naming only the entry's
// index) and tells the caller to keep the WLAN off for what it must not
// render weaker (Terms and Conditions filtering). Lines re-checks every value
// against hostapd 2.9's parsers: one bad line there makes hostapd refuse its
// whole config, which would take every SSID of the radio down.
package hs20

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Config is one WLAN's Hotspot 2.0 advertisement. It holds no secrets.
type Config struct {
	AccessNetworkType int // access_network_type, 0..15 (controller: 0-5, 14, 15)
	Internet          bool
	ASRA              bool // additional step required for access
	ESR               bool // emergency services reachable
	UESA              bool // unauthenticated emergency service accessible
	Venue             *VenueInfo
	VenueNames        []VenueName
	HESSID            string // aa:bb:cc:dd:ee:ff; "" = the BSSID (hostapd's default)
	// DisableDGAF: no downstream group-addressed forwarding (hostapd gives
	// every station its own random GTK, and the HS 2.0 indication says so).
	DisableDGAF      bool
	DeauthReqTimeout int // hs20_deauth_req_timeout, seconds; 0 = hostapd's 60
	ANQPDomainID     int // anqp_domain_id 0..65535; -1 = not sent (hostapd 0)
	NetworkAuth      *NetworkAuth
	IPAddrAvail      int // ipaddr_type_availability byte ((v4<<2)|v6); -1 = not sent
	DomainNames      []string
	RoamingConsortia []string // lower-case hex OIs, 3..15 octets
	NAIRealms        []NAIRealm
	CellNetworks     []PLMN
	OperatorNames    []LangText
	ConnCapab        []ConnCapab
	WANMetrics       *WANMetrics
	GASFragLimit     int    // octets; 0 = hostapd default
	GASComebackDelay int    // TUs; 0 = hostapd default
	OSUSSID          string // the OSU (sign-up) SSID; "" = none
	OSUProviders     []OSUProvider
	OperatingClass   string // hs20_operating_class, lower-case hex; "" = none
}

// VenueInfo is the venue group and type (IEEE 802.11u Table 9-62/9-63).
type VenueInfo struct{ Group, Type int }

// VenueName is one venue name, with an optional venue URL.
type VenueName struct {
	Lang, Name string
	URL        string
}

// LangText is a language-tagged string (operator / OSU friendly names, OSU
// service descriptions).
type LangText struct{ Lang, Text string }

// NetworkAuth is the Network Authentication Type ANQP element: 0 acceptance
// of terms and conditions, 1 online enrollment, 2 http/https redirection,
// 3 DNS redirection. URL is only carried for 0 and 2 (as hostapd does).
type NetworkAuth struct {
	Type int
	URL  string
}

// NAIRealm is one NAI realm (possibly several, ';'-separated) with its EAP
// method and authentication parameters.
type NAIRealm struct {
	Encoding int    // 0 RFC 4282, 1 UTF-8
	Realm    string // no ','
	EAP      []EAPMethod
}

// EAPMethod is one EAP method of a realm with up to 4 auth parameters.
type EAPMethod struct {
	Method int // EAP type: 13 TLS, 18 SIM, 21 TTLS, 23 AKA, 50 AKA'
	Auth   []AuthParam
}

// AuthParam is one [id:val] authentication parameter of an EAP method.
type AuthParam struct{ ID, Val int }

// PLMN is one 3GPP cellular network (MCC 3 digits, MNC 2 or 3 digits).
type PLMN struct{ MCC, MNC string }

// ConnCapab is one Connection Capability entry: IP protocol, port and status
// (0 closed, 1 open, 2 unknown).
type ConnCapab struct{ Proto, Port, Status int }

// WANMetrics is the HS 2.0 WAN Metrics ANQP element.
type WANMetrics struct {
	Info                   int // link status (1 up, 2 down, 3 test) | 4 symmetric | 8 at capacity
	DownKbps, UpKbps       int64
	DownLoad, UpLoad       int // 0..255
	MeasurementDurationDTU int // LMD, 0..65535
}

// OSUProvider is one online sign-up provider.
type OSUProvider struct {
	ServerURI     string
	FriendlyNames []LangText
	NAI, NAI2     string
	Methods       []int // 1 SOAP-XML SPP, 0 OMA-DM (hostapd's osu_method_list order)
	Descriptions  []LangText
}

// Parse reads the Hotspot 2.0 settings of one controller VAP. aaa and
// wireless are the section prefixes with their trailing dot ("aaa.3.",
// "wireless.3."). c is nil when Hotspot 2.0 is off for the VAP. notes say
// what was not carried and why (indices only, never values); off != ""
// means the VAP must stay off, because a part of it that cannot be carried
// would leave it weaker than configured.
func Parse(cfg map[string]string, aaa, wireless string) (c *Config, notes []string, off string) {
	h := aaa + "hs20."
	if !on(cfg[h+"status"]) {
		return nil, nil, ""
	}
	note := func(f string, a ...any) { notes = append(notes, "Hotspot 2.0: "+fmt.Sprintf(f, a...)) }

	// Terms and Conditions: the RADIUS server then asks the AP to filter a
	// station's traffic until it accepts (HS20-T-C-FILTERING-ADD). hostapd
	// only reports that; nothing here would filter, so the station would be
	// let through unfiltered.
	if cfg[h+"t_c_filename"] != "" {
		return nil, notes, "Hotspot 2.0 Terms and Conditions need per-station traffic filtering, which this AP does not do"
	}

	c = &Config{ANQPDomainID: -1, IPAddrAvail: -1}
	num := func(k string, lo, hi int) (int, bool) {
		v, ok := cfg[h+k]
		if !ok || v == "" {
			return 0, false
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < lo || n > hi {
			note("%s not in %d..%d: not sent", k, lo, hi)
			return 0, false
		}
		return n, true
	}
	if n, ok := num("access_network_type", 0, 15); ok {
		c.AccessNetworkType = n
	}
	c.Internet, c.ASRA, c.ESR, c.UESA = on(cfg[h+"internet"]), on(cfg[h+"asra"]), on(cfg[h+"esr"]), on(cfg[h+"uesa"])
	g, gok := num("venue_group", 0, 255)
	t, tok := num("venue_type", 0, 255)
	if gok || tok {
		c.Venue = &VenueInfo{Group: g, Type: t}
	}
	// The aaa key is the hotspot2conf's own flag; the wireless one defaults
	// to on for a guest WLAN. Either one disables DGAF (the stricter wins).
	c.DisableDGAF = on(cfg[h+"disable_dgaf"]) || on(cfg[wireless+"dgaf_disable"])
	if n, ok := num("deauth_req_timeout", 1, 65535); ok {
		c.DeauthReqTimeout = n
	}
	if v := cfg[h+"osu_ssid"]; v != "" {
		if len(v) > 32 || !printable(v) {
			note("OSU SSID is not 1..32 printable octets: not sent")
		} else {
			c.OSUSSID = v
		}
	}
	if n, ok := num("gas_frag_limit", 1, 65535); ok {
		c.GASFragLimit = n
	}
	if n, ok := num("gas_comeback_delay", 1, 65535); ok {
		c.GASComebackDelay = n
	}
	if n, ok := num("network_availability", 0, 255); ok {
		c.IPAddrAvail = n
	}
	if n, ok := num("network_auth_type", 0, 3); ok {
		na := &NetworkAuth{Type: n}
		if u := cfg[h+"network_auth_url"]; u != "" && (n == 0 || n == 2) {
			if len(u) > 255 || !printable(u) {
				note("network authentication URL is not printable or longer than 255: type sent without it")
			} else {
				na.URL = u
			}
		}
		c.NetworkAuth = na
	}
	if n, ok := num("anqp_domain_id", 0, 65535); ok {
		c.ANQPDomainID = n
	}
	if v := cfg[h+"hessid"]; v != "" {
		if hw, err := net.ParseMAC(v); err != nil || len(hw) != 6 {
			note("HESSID is not a MAC address: the BSSID is used")
		} else {
			c.HESSID = hw.String()
		}
	}

	for _, i := range indices(cfg, h+"venue_name.") {
		p := h + "venue_name." + i + "."
		vn := VenueName{Lang: cfg[p+"lang"], Name: cfg[p+"name"], URL: cfg[p+"url"]}
		if !validLang(vn.Lang) || !validLangText(vn.Name) {
			note("venue name %s: language or name not usable: not sent", i)
			continue
		}
		if vn.URL != "" && (len(vn.URL) > 254 || !printable(vn.URL)) {
			note("venue name %s: URL not usable: name sent without it", i)
			vn.URL = ""
		}
		c.VenueNames = append(c.VenueNames, vn)
	}
	if v := cfg[h+"hs20_domain_name_list"]; v != "" {
		for j, d := range strings.Split(v, ",") {
			if d == "" || len(d) > 255 || !printable(d) {
				note("domain name %d not usable: not sent", j+1)
				continue
			}
			c.DomainNames = append(c.DomainNames, d)
		}
	}
	for _, i := range indices(cfg, h+"nai_realm.") {
		p := h + "nai_realm." + i + "."
		if v, ok := cfg[p+"status"]; ok && !on(v) {
			continue
		}
		r, why := naiRealm(cfg, p)
		if why != "" {
			note("NAI realm %s: %s: not sent", i, why)
			continue
		}
		c.NAIRealms = append(c.NAIRealms, r)
	}
	// aaa.N.hs20.<i>.roaming_consortium (the index comes first here)
	for _, i := range indices(cfg, h) {
		v, ok := cfg[h+i+".roaming_consortium"]
		if !ok {
			continue
		}
		oi := strings.ToLower(strings.NewReplacer(":", "", "-", "", " ", "").Replace(v))
		if len(oi)%2 != 0 || len(oi) < 6 || len(oi) > 30 || !isHex(oi) {
			note("roaming consortium %s is not a 3..15 octet hex OI: not sent", i)
			continue
		}
		c.RoamingConsortia = append(c.RoamingConsortia, oi)
	}
	for _, i := range indices(cfg, h+"3gpp.") {
		p := h + "3gpp." + i + "."
		pl := PLMN{MCC: cfg[p+"mcc"], MNC: cfg[p+"mnc"]}
		if !digits(pl.MCC, 3, 3) || !digits(pl.MNC, 2, 3) {
			note("3GPP network %s: MCC/MNC not 3/2-3 digits: not sent", i)
			continue
		}
		c.CellNetworks = append(c.CellNetworks, pl)
	}
	c.OperatorNames = langTexts(cfg, h+"friendly_name.", "operator friendly name", note)
	for _, i := range indices(cfg, h+"capab.") {
		p := h + "capab." + i + "."
		proto, e1 := strconv.Atoi(cfg[p+"protocol"])
		port, e2 := strconv.Atoi(cfg[p+"port"])
		st, sok := map[string]int{"closed": 0, "open": 1, "unknown": 2}[cfg[p+"status"]]
		if e1 != nil || e2 != nil || !sok || proto < 0 || proto > 255 || port < 0 || port > 65535 {
			note("connection capability %s not usable: not sent", i)
			continue
		}
		c.ConnCapab = append(c.ConnCapab, ConnCapab{Proto: proto, Port: port, Status: st})
	}
	if on(cfg[h+"metrics.status"]) {
		if m, ok := wanMetrics(cfg, h+"metrics."); ok {
			c.WANMetrics = m
		} else {
			note("WAN metrics not usable: not sent")
		}
	}
	if n := len(indices(cfg, h+"icon.")); n > 0 {
		// hostapd reads an icon from a file (hs20_icon=...:<path>); the
		// agent writes no icon files.
		note("%d icon(s) not sent (no icon files on this AP)", n)
	}
	if on(cfg[h+"qos.status"]) {
		// hostapd sets a QoS Map through NL80211_CMD_SET_QOS_MAP at BSS
		// setup, and fails the BSS when the driver refuses it. wl.ko has
		// no set_qos_map cfg80211 op.
		note("QoS map not sent (the Broadcom driver cannot take it)")
	}
	for _, i := range indices(cfg, aaa+"osu.") {
		p := aaa + "osu." + i + "."
		o := OSUProvider{ServerURI: cfg[p+"server_uri"], NAI: cfg[p+"nai"], NAI2: cfg[p+"nai2"]}
		if o.ServerURI == "" || len(o.ServerURI) > 255 || !printable(o.ServerURI) {
			note("OSU provider %s: server URI not usable: provider not sent", i)
			continue
		}
		if o.NAI != "" && (len(o.NAI) > 255 || !printable(o.NAI)) {
			note("OSU provider %s: NAI not usable: left out", i)
			o.NAI = ""
		}
		if o.NAI2 != "" && (len(o.NAI2) > 255 || !printable(o.NAI2)) {
			note("OSU provider %s: NAI2 not usable: left out", i)
			o.NAI2 = ""
		}
		if on(cfg[p+"method_soap_xml_spp"]) {
			o.Methods = append(o.Methods, 1)
		}
		if on(cfg[p+"method_oma_dm"]) {
			o.Methods = append(o.Methods, 0)
		}
		o.FriendlyNames = langTexts(cfg, p+"friendly_name.", "OSU provider "+i+" friendly name", note)
		o.Descriptions = langTexts(cfg, p+"description.", "OSU provider "+i+" description", note)
		if n := len(indices(cfg, p+"icon.")); n > 0 {
			note("OSU provider %s: %d icon reference(s) not sent (no icons)", i, n)
		}
		if oc := strings.ToLower(cfg[p+"operating_class"]); oc != "" && c.OperatingClass == "" {
			// hostapd has one hs20_operating_class per BSS; ubntbox writes
			// the OSU provider's. The first usable one is kept.
			if len(oc)%2 != 0 || len(oc) > 64 || !isHex(oc) {
				note("OSU provider %s: operating class is not hex octets: not sent", i)
			} else {
				c.OperatingClass = oc
			}
		}
		c.OSUProviders = append(c.OSUProviders, o)
	}
	if len(c.OSUProviders) > 0 && c.OSUSSID == "" {
		note("OSU providers without an OSU SSID: providers not sent")
		c.OSUProviders = nil
	}
	return c, notes, ""
}

func naiRealm(cfg map[string]string, p string) (NAIRealm, string) {
	r := NAIRealm{Realm: cfg[p+"name"]}
	switch cfg[p+"encoding"] {
	case "", "0":
	case "1":
		r.Encoding = 1
	default:
		return r, "encoding not 0 or 1"
	}
	if why := checkRealm(r.Realm); why != "" {
		return r, why
	}
	m := cfg[p+"eap_method"]
	if m == "" {
		return r, "" // a realm with no EAP method: realm only
	}
	method, err := strconv.Atoi(m)
	if err != nil || method < 0 || method > 255 {
		return r, "EAP method not a number 0..255"
	}
	e := EAPMethod{Method: method}
	for _, j := range indices(cfg, p+"eap_method.auth.") {
		q := p + "eap_method.auth." + j + "."
		id, e1 := strconv.Atoi(cfg[q+"id"])
		val, e2 := strconv.Atoi(cfg[q+"val"])
		if e1 != nil || e2 != nil || id < 0 || id > 255 || val < 0 || val > 255 {
			return r, "EAP auth parameter " + j + " not two numbers 0..255"
		}
		e.Auth = append(e.Auth, AuthParam{ID: id, Val: val})
	}
	if len(e.Auth) > 4 {
		return r, "more than 4 EAP auth parameters"
	}
	r.EAP = []EAPMethod{e}
	return r, ""
}

func wanMetrics(cfg map[string]string, p string) (*WANMetrics, bool) {
	geti := func(k string, hi int64) (int64, bool) {
		v := cfg[p+k]
		if v == "" {
			return 0, true
		}
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil && n >= 0 && n <= hi
	}
	info, ok1 := geti("info", 255)
	dl, ok2 := geti("downlink_speed", 1<<32-1)
	ul, ok3 := geti("uplink_speed", 1<<32-1)
	dload, ok4 := geti("downlink_load", 255)
	uload, ok5 := geti("uplink_load", 255)
	lmd, ok6 := geti("measurement", 65535)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) {
		return nil, false
	}
	return &WANMetrics{Info: int(info), DownKbps: dl, UpKbps: ul, DownLoad: int(dload), UpLoad: int(uload), MeasurementDurationDTU: int(lmd)}, true
}

// langTexts reads <p><i>.language / <p><i>.text pairs.
func langTexts(cfg map[string]string, p, what string, note func(string, ...any)) []LangText {
	var out []LangText
	for _, i := range indices(cfg, p) {
		lt := LangText{Lang: cfg[p+i+".language"], Text: cfg[p+i+".text"]}
		if !validLang(lt.Lang) || !validLangText(lt.Text) {
			note("%s %s: language or text not usable: not sent", what, i)
			continue
		}
		out = append(out, lt)
	}
	return out
}

// Line is one hostapd config line.
type Line struct{ Key, Value string }

// Lines renders c as hostapd 2.9 bss lines. Every value is checked the way
// hostapd's parser checks it; an error means the config must not be written
// (hostapd would refuse the whole file).
func (c *Config) Lines() ([]Line, error) {
	if c == nil {
		return nil, nil
	}
	var out []Line
	add := func(k string, v any) { out = append(out, Line{k, fmt.Sprint(v)}) }
	b := func(x bool) int {
		if x {
			return 1
		}
		return 0
	}
	add("interworking", 1)
	add("access_network_type", c.AccessNetworkType)
	add("internet", b(c.Internet))
	add("asra", b(c.ASRA))
	add("esr", b(c.ESR))
	add("uesa", b(c.UESA))
	if c.Venue != nil {
		add("venue_group", c.Venue.Group)
		add("venue_type", c.Venue.Type)
	}
	if c.HESSID != "" {
		add("hessid", c.HESSID)
	}
	for _, v := range c.VenueNames {
		add("venue_name", v.Lang+":"+v.Name)
	}
	for i, v := range c.VenueNames {
		if v.URL != "" {
			add("venue_url", strconv.Itoa(i+1)+":"+v.URL)
		}
	}
	if na := c.NetworkAuth; na != nil {
		v := fmt.Sprintf("%02x", na.Type)
		if na.Type == 0 || na.Type == 2 {
			v += na.URL
		}
		add("network_auth_type", v)
	}
	if c.IPAddrAvail >= 0 {
		add("ipaddr_type_availability", fmt.Sprintf("%02x", c.IPAddrAvail))
	}
	if len(c.DomainNames) > 0 {
		add("domain_name", strings.Join(c.DomainNames, ","))
	}
	for _, oi := range c.RoamingConsortia {
		add("roaming_consortium", oi)
	}
	if len(c.CellNetworks) > 0 {
		var p []string
		for _, n := range c.CellNetworks {
			p = append(p, n.MCC+","+n.MNC)
		}
		add("anqp_3gpp_cell_net", strings.Join(p, ";"))
	}
	for _, r := range c.NAIRealms {
		v := strconv.Itoa(r.Encoding) + "," + r.Realm
		for _, e := range r.EAP {
			v += "," + strconv.Itoa(e.Method)
			for _, a := range e.Auth {
				v += fmt.Sprintf("[%d:%d]", a.ID, a.Val)
			}
		}
		add("nai_realm", v)
	}
	if c.GASFragLimit > 0 {
		add("gas_frag_limit", c.GASFragLimit)
	}
	if c.GASComebackDelay > 0 {
		add("gas_comeback_delay", c.GASComebackDelay)
	}
	add("hs20", 1)
	add("disable_dgaf", b(c.DisableDGAF))
	if c.ANQPDomainID >= 0 {
		add("anqp_domain_id", c.ANQPDomainID)
	}
	if c.DeauthReqTimeout > 0 {
		add("hs20_deauth_req_timeout", c.DeauthReqTimeout)
	}
	for _, n := range c.OperatorNames {
		add("hs20_oper_friendly_name", n.Lang+":"+n.Text)
	}
	if m := c.WANMetrics; m != nil {
		add("hs20_wan_metrics", fmt.Sprintf("%02x:%d:%d:%d:%d:%d", m.Info, m.DownKbps, m.UpKbps, m.DownLoad, m.UpLoad, m.MeasurementDurationDTU))
	}
	for _, cc := range c.ConnCapab {
		add("hs20_conn_capab", fmt.Sprintf("%d:%d:%d", cc.Proto, cc.Port, cc.Status))
	}
	if c.OperatingClass != "" {
		add("hs20_operating_class", c.OperatingClass)
	}
	if c.OSUSSID != "" {
		// hex form: wpa_config_parse_string reads it without any quoting
		add("osu_ssid", hex.EncodeToString([]byte(c.OSUSSID)))
		for _, o := range c.OSUProviders {
			add("osu_server_uri", o.ServerURI) // starts the provider
			for _, n := range o.FriendlyNames {
				add("osu_friendly_name", n.Lang+":"+n.Text)
			}
			if o.NAI != "" {
				add("osu_nai", o.NAI)
			}
			if o.NAI2 != "" {
				add("osu_nai2", o.NAI2)
			}
			if len(o.Methods) > 0 {
				var m []string
				for _, x := range o.Methods {
					m = append(m, strconv.Itoa(x))
				}
				add("osu_method_list", strings.Join(m, " "))
			}
			for _, d := range o.Descriptions {
				add("osu_service_desc", d.Lang+":"+d.Text)
			}
		}
	}
	for _, l := range out {
		if err := CheckLine(l.Key, l.Value); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Keys are the config keys Lines can write. Each was found as a config
// keyword in the strings of the X20's /sbin/hostapd (TP-Link build of 2.9,
// 2026-11-19), so this hostapd parses it (CONFIG_INTERWORKING, CONFIG_HS20).
var Keys = []string{
	"interworking", "access_network_type", "internet", "asra", "esr", "uesa", "venue_group", "venue_type",
	"hessid", "venue_name", "venue_url", "network_auth_type", "ipaddr_type_availability", "domain_name",
	"roaming_consortium", "anqp_3gpp_cell_net", "nai_realm", "gas_frag_limit", "gas_comeback_delay",
	"hs20", "disable_dgaf", "anqp_domain_id", "hs20_deauth_req_timeout", "hs20_oper_friendly_name",
	"hs20_wan_metrics", "hs20_conn_capab", "hs20_operating_class", "osu_ssid", "osu_server_uri",
	"osu_friendly_name", "osu_nai", "osu_nai2", "osu_method_list", "osu_service_desc",
}

// CheckLine applies hostapd 2.9's checks (hostapd/config_file.c) for one hs20
// key; it also refuses anything that would not survive the config reader
// (a NUL, CR or LF, or a line of 4096 octets or more, which fgets splits).
func CheckLine(k, v string) error {
	if strings.ContainsAny(v, "\x00\r\n") || len(k)+1+len(v) >= 4095 {
		return fmt.Errorf("%s: value not a single config line", k)
	}
	bad := func(why string) error { return fmt.Errorf("%s=%q: %s", k, v, why) }
	atoi := func(s string) (int, bool) { n, err := strconv.Atoi(s); return n, err == nil }
	switch k {
	case "interworking", "internet", "asra", "esr", "uesa", "hs20", "disable_dgaf":
		if v != "0" && v != "1" {
			return bad("not 0/1")
		}
	case "access_network_type":
		if n, ok := atoi(v); !ok || n < 0 || n > 15 {
			return bad("not 0..15")
		}
	case "venue_group", "venue_type":
		if n, ok := atoi(v); !ok || n < 0 || n > 255 {
			return bad("not 0..255")
		}
	case "anqp_domain_id", "hs20_deauth_req_timeout", "gas_comeback_delay":
		if n, ok := atoi(v); !ok || n < 0 || n > 65535 {
			return bad("not 0..65535")
		}
	case "gas_frag_limit":
		if n, ok := atoi(v); !ok || n <= 0 || n > 65535 {
			return bad("not 1..65535")
		}
	case "hessid":
		if hw, err := net.ParseMAC(v); err != nil || len(hw) != 6 || strings.Count(v, ":") != 5 {
			return bad("not a colon MAC")
		}
	case "roaming_consortium":
		if len(v)%2 != 0 || len(v) < 6 || len(v)/2 > 15 || !isHex(v) {
			return bad("not 3..15 hex octets")
		}
	case "venue_name", "hs20_oper_friendly_name", "osu_friendly_name", "osu_service_desc":
		lang, text, ok := strings.Cut(v, ":")
		if !ok || !validLang(lang) || !validLangText(text) {
			return bad("not <2-3 letter lang>:<at most 252 octets>")
		}
	case "venue_url":
		n, u, ok := strings.Cut(v, ":")
		if i, iok := atoi(n); !ok || !iok || i < 1 || i > 255 || len(u) > 254 {
			return bad("not <venue number>:<url of at most 254>")
		}
	case "network_auth_type":
		if len(v) < 2 || !isHex(v[:2]) {
			return bad("not two hex digits then an optional URL")
		}
		if t, _ := strconv.ParseUint(v[:2], 16, 8); t != 0 && t != 2 && len(v) > 2 {
			return bad("URL only with type 0 or 2")
		}
	case "ipaddr_type_availability":
		if len(v) != 2 || !isHex(v) {
			return bad("not one hex octet")
		}
	case "domain_name":
		for _, d := range strings.Split(v, ",") {
			if d == "" || len(d) > 255 {
				return bad("a domain is empty or longer than 255")
			}
		}
	case "anqp_3gpp_cell_net":
		parts := strings.Split(v, ";")
		if 1+3*len(parts) > 0x7f {
			return bad("too many networks")
		}
		for _, p := range parts {
			mcc, mnc, ok := strings.Cut(p, ",")
			if !ok || !digits(mcc, 3, 3) || !digits(mnc, 2, 3) {
				return bad("not <MCC>,<MNC>[;...]")
			}
		}
	case "nai_realm":
		if err := checkNAIRealm(v); err != nil {
			return bad(err.Error())
		}
	case "hs20_wan_metrics":
		f := strings.Split(v, ":")
		if len(f) != 6 || len(f[0]) != 2 || !isHex(f[0]) {
			return bad("not <info hex>:<dl>:<ul>:<dl load>:<ul load>:<lmd>")
		}
		lim := []int64{0, 1<<32 - 1, 1<<32 - 1, 255, 255, 65535}
		for i := 1; i < 6; i++ {
			if n, err := strconv.ParseInt(f[i], 10, 64); err != nil || n < 0 || n > lim[i] {
				return bad("field out of range")
			}
		}
	case "hs20_conn_capab":
		f := strings.Split(v, ":")
		if len(f) != 3 {
			return bad("not <proto>:<port>:<status>")
		}
		for i, hi := range []int{255, 65535, 2} {
			if n, ok := atoi(f[i]); !ok || n < 0 || n > hi {
				return bad("field out of range")
			}
		}
	case "hs20_operating_class":
		if len(v) < 2 || len(v)%2 != 0 || !isHex(v) {
			return bad("not hex octets")
		}
	case "osu_ssid":
		if len(v) < 2 || len(v)%2 != 0 || len(v)/2 > 32 || !isHex(v) {
			return bad("not 1..32 hex octets")
		}
	case "osu_server_uri", "osu_nai", "osu_nai2":
		if v == "" || len(v) > 255 {
			return bad("empty or longer than 255")
		}
	case "osu_method_list":
		for _, f := range strings.Fields(v) {
			if f != "0" && f != "1" {
				return bad("methods are 0 (OMA-DM) and 1 (SOAP-XML SPP)")
			}
		}
	default:
		return fmt.Errorf("%s: not a Hotspot 2.0 key this AP writes", k)
	}
	return nil
}

// checkNAIRealm mirrors parse_nai_realm: <encoding>,<realm>[,<eap>[<[id:val]>...]]...
func checkNAIRealm(v string) error {
	enc, rest, ok := strings.Cut(v, ",")
	if !ok || (enc != "0" && enc != "1") {
		return fmt.Errorf("encoding not 0 or 1")
	}
	realm, methods, _ := strings.Cut(rest, ",")
	if why := checkRealm(realm); why != "" {
		return fmt.Errorf("%s", why)
	}
	if methods == "" {
		return nil
	}
	ms := strings.Split(methods, ",")
	if len(ms) > 5 {
		return fmt.Errorf("more than 5 EAP methods")
	}
	for _, m := range ms {
		num, auth, _ := strings.Cut(m, "[")
		if n, err := strconv.Atoi(num); err != nil || n < 0 || n > 255 {
			return fmt.Errorf("EAP method %q not 0..255", num)
		}
		if auth == "" {
			continue
		}
		params := strings.Split(strings.TrimSuffix("["+auth, "]"), "][")
		if len(params) > 4 {
			return fmt.Errorf("more than 4 auth parameters")
		}
		for _, p := range params {
			p = strings.TrimPrefix(p, "[")
			id, val, ok := strings.Cut(p, ":")
			a, e1 := strconv.Atoi(id)
			b, e2 := strconv.Atoi(val)
			if !ok || e1 != nil || e2 != nil || a < 0 || a > 255 || b < 0 || b > 255 {
				return fmt.Errorf("auth parameter %q not [id:val]", p)
			}
		}
	}
	return nil
}

// checkRealm: at most 255 octets, at most 10 ';'-separated realms, none
// empty, and no ',', '[' or ']' (the nai_realm line's own separators).
func checkRealm(r string) string {
	if r == "" || len(r) > 255 {
		return "realm empty or longer than 255"
	}
	if strings.ContainsAny(r, ",[]") || !printable(r) {
		return "realm has a ',', '[', ']' or a control character"
	}
	parts := strings.Split(r, ";")
	if len(parts) > 10 {
		return "more than 10 realms"
	}
	for _, p := range parts {
		if p == "" {
			return "empty realm in the list"
		}
	}
	return ""
}

// Clone returns a deep copy of c (nil for nil).
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	x := *c
	if c.Venue != nil {
		v := *c.Venue
		x.Venue = &v
	}
	if c.NetworkAuth != nil {
		n := *c.NetworkAuth
		x.NetworkAuth = &n
	}
	if c.WANMetrics != nil {
		m := *c.WANMetrics
		x.WANMetrics = &m
	}
	x.VenueNames = append([]VenueName(nil), c.VenueNames...)
	x.DomainNames = append([]string(nil), c.DomainNames...)
	x.RoamingConsortia = append([]string(nil), c.RoamingConsortia...)
	x.CellNetworks = append([]PLMN(nil), c.CellNetworks...)
	x.OperatorNames = append([]LangText(nil), c.OperatorNames...)
	x.ConnCapab = append([]ConnCapab(nil), c.ConnCapab...)
	x.NAIRealms = nil
	for _, r := range c.NAIRealms {
		rr := r
		rr.EAP = nil
		for _, e := range r.EAP {
			e.Auth = append([]AuthParam(nil), e.Auth...)
			rr.EAP = append(rr.EAP, e)
		}
		x.NAIRealms = append(x.NAIRealms, rr)
	}
	x.OSUProviders = nil
	for _, o := range c.OSUProviders {
		oo := o
		oo.FriendlyNames = append([]LangText(nil), o.FriendlyNames...)
		oo.Descriptions = append([]LangText(nil), o.Descriptions...)
		oo.Methods = append([]int(nil), o.Methods...)
		x.OSUProviders = append(x.OSUProviders, oo)
	}
	return &x
}

// String is a one-line summary (counts, not values).
func (c *Config) String() string {
	if c == nil {
		return "off"
	}
	return fmt.Sprintf("ant=%d internet=%t dgaf_off=%t venues=%d realms=%d rcois=%d domains=%d plmns=%d osu=%d",
		c.AccessNetworkType, c.Internet, c.DisableDGAF, len(c.VenueNames), len(c.NAIRealms),
		len(c.RoamingConsortia), len(c.DomainNames), len(c.CellNetworks), len(c.OSUProviders))
}

func on(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "enabled", "true", "1", "on":
		return true
	}
	return false
}

// indices lists, in numeric order, the numeric components that directly
// follow prefix p (which ends in '.') in cfg's keys.
func indices(cfg map[string]string, p string) []string {
	set := map[string]bool{}
	for k := range cfg {
		rest, ok := strings.CutPrefix(k, p)
		if !ok {
			continue
		}
		n, _, _ := strings.Cut(rest, ".")
		if _, err := strconv.Atoi(n); err == nil && n != "" && n[0] != '-' && n[0] != '+' {
			set[n] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { a, _ := strconv.Atoi(out[i]); b, _ := strconv.Atoi(out[j]); return a < b })
	return out
}

func validLang(l string) bool {
	if len(l) < 2 || len(l) > 3 {
		return false
	}
	for i := 0; i < len(l); i++ {
		if l[i] < 'a' || l[i] > 'z' {
			return false
		}
	}
	return true
}

// validLangText: the text part of a lang:text value (at most 252 octets).
func validLangText(s string) bool { return s != "" && len(s) <= 252 && printable(s) }

// printable: valid UTF-8 with no control characters.
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func digits(s string, lo, hi int) bool {
	if len(s) < lo || len(s) > hi {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
