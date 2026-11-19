// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/ftpeer"
)

// hapdRadio is the input to renderHostapd for one radio.
type hapdRadio struct {
	Band    string // ng, na
	Channel int    // control channel (informational: wl owns the PHY)
	Country string // country_code; "" omits ieee80211d/h
	MinRSSI int    // rssi_reject_assoc_rssi; 0 = off
	MaxSta  int
	RunDir  string
	// Placeholder is the interface= BSS on the radio's first vif wlN1.
	Placeholder hapdPlaceholder
	BSS         []hapdBSS
}

// hapdPlaceholder is the hidden interface= BSS of the agent's hostapd. This
// hostapd needs interface= to be an existing netdev, and the bss= vifs it
// creates are deleted when it exits (live facts F2, F4), so interface= is
// always wlN1, the vif that survives; it carries no SSID of the controller
// and is kept BSS down. SSID and passphrase are random (crypto/rand), live
// only in the 0600 conf and are never logged.
type hapdPlaceholder struct {
	Vif        string
	SSID       string
	Passphrase string
}

// newPlaceholder returns a fresh placeholder for vif.
func newPlaceholder(vif string) (hapdPlaceholder, error) {
	id := make([]byte, 6)
	pw := make([]byte, 24)
	if _, err := rand.Read(id); err != nil {
		return hapdPlaceholder{}, err
	}
	if _, err := rand.Read(pw); err != nil {
		return hapdPlaceholder{}, err
	}
	return hapdPlaceholder{Vif: vif, SSID: "udeco-" + hex.EncodeToString(id), Passphrase: hex.EncodeToString(pw)}, nil
}

// parsePlaceholder reads the placeholder back from a conf renderHostapd
// wrote, so a radio whose conf is otherwise unchanged keeps it (and its
// hostapd). ok is false when conf has none for vif.
func parsePlaceholder(conf []byte, vif string) (hapdPlaceholder, bool) {
	ph := hapdPlaceholder{}
	for _, line := range strings.Split(string(conf), "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "interface":
			ph.Vif = v
		case "ssid":
			ph.SSID = v
		case "wpa_passphrase":
			ph.Passphrase = v
		case "bss":
			return ph, ph.Vif == vif && ph.SSID != "" && len(ph.Passphrase) >= 8
		}
	}
	return ph, ph.Vif == vif && ph.SSID != "" && len(ph.Passphrase) >= 8
}

// hapdBSS is one BSS: an SSID on a vif.
type hapdBSS struct {
	Vif    string
	BSSID  string // cur_etheraddr, lower-case; written for bss= sections
	Bridge string
	SSID   SSID // normalized
	Deny   bool // a deny_mac_file is written for this BSS
	Accept bool // macaddr_acl=1 with an accept_mac_file
	// FTPeers are the other units' key holders this BSS lists for FT-SAE
	// (explicit r0kh/r1kh, ftsae.go); only with SSID.FTSAE.
	FTPeers []ftpeer.Peer
}

// hostapd file names in RunDir.
func confPath(runDir, primary string) string { return path.Join(runDir, "hapd-"+primary+".conf") }
func pidPath(runDir, primary string) string  { return path.Join(runDir, "hapd-"+primary+".pid") }
func drvPath(runDir, primary string) string  { return path.Join(runDir, "drv-"+primary+".json") }
func denyPath(runDir, vif string) string     { return path.Join(runDir, vif+".deny") }
func acceptPath(runDir, vif string) string   { return path.Join(runDir, vif+".accept") }

// mobilityDomain derives the 802.11r MDID from the SSID, so every unit
// serving the SSID agrees without coordination.
func mobilityDomain(ssid string) uint16 {
	h := sha256.Sum256([]byte("udeco-mdid:" + ssid))
	md := binary.BigEndian.Uint16(h[:2])
	if md == 0 {
		md = 1
	}
	return md
}

// ftReassocMS is TP-Link's fbt_reassoc_time / reassociation_deadline.
const ftReassocMS = 1000

// keyMgmt returns wpa_key_mgmt and ieee80211w for s.
func keyMgmt(s SSID) (mgmt string, pmf int) {
	pmfWant := func(def int) int {
		switch s.PMF {
		case "disabled", "off", "0":
			return 0
		case "optional", "1":
			return 1
		case "required", "2":
			return 2
		}
		return def
	}
	var k []string
	switch s.Security {
	case SecWPA2:
		pmf = pmfWant(0)
		k = append(k, "WPA-PSK")
		if s.FT {
			k = append(k, "FT-PSK")
		}
		if pmf == 2 {
			k = append(k, "WPA-PSK-SHA256")
		}
	case SecWPA3:
		pmf = 2
		k = append(k, "SAE")
		if s.FT && s.FTSAE {
			k = append(k, "FT-SAE")
		}
	case SecWPA2WPA3:
		pmf = max(pmfWant(1), 1)
		k = append(k, "WPA-PSK")
		if s.FT {
			k = append(k, "FT-PSK")
		}
		k = append(k, "SAE")
		if s.FT && s.FTSAE {
			k = append(k, "FT-SAE") // TP-Link's order: "WPA-PSK FT-PSK SAE" + " FT-SAE"
		}
	case SecWPA2Ent:
		pmf = pmfWant(0)
		k = append(k, "WPA-EAP")
		if pmf == 2 {
			k = append(k, "WPA-EAP-SHA256")
		}
	case SecWPA3Ent:
		pmf = 2
		k = append(k, "WPA-EAP", "WPA-EAP-SHA256")
	}
	return strings.Join(k, " "), pmf
}

func hwMode(band string) string {
	if band == "ng" {
		return "g"
	}
	return "a"
}

// renderHostapd writes the hostapd 2.9 config for one radio: global lines
// and the placeholder as interface=, then one bss= section (with bssid=,
// which this hostapd requires: "Invalid BSSID mask" otherwise, F4) per BSS.
// Every line is a bare key=value: hostapd does not strip inline comments.
func renderHostapd(r hapdRadio) (string, error) {
	if len(r.BSS) == 0 {
		return "", fmt.Errorf("no BSS")
	}
	ph := r.Placeholder
	if ph.Vif == "" || ph.SSID == "" || len(ph.Passphrase) < 8 || len(ph.Passphrase) > 63 {
		return "", fmt.Errorf("no placeholder BSS")
	}
	var b strings.Builder
	w := func(k string, v any) { fmt.Fprintf(&b, "%s=%v\n", k, v) }
	w("driver", "nl80211")
	w("ctrl_interface_group", 0)
	w("interface", ph.Vif)
	w("hw_mode", hwMode(r.Band))
	ch := r.Channel
	if ch <= 0 { // hostapd has no ACS here; the value is informational
		ch = map[string]int{"ng": 1, "na": 36}[r.Band]
	}
	w("channel", ch)
	if r.Country != "" {
		w("country_code", r.Country)
		w("ieee80211d", 1)
		w("ieee80211h", 1)
	}
	w("beacon_int", 100)
	w("ctrl_interface", CtrlDir)
	w("ssid", ph.SSID)
	w("ignore_broadcast_ssid", 1)
	w("auth_algs", 1)
	w("wmm_enabled", 1)
	w("wpa", 2)
	w("wpa_key_mgmt", "WPA-PSK")
	w("rsn_pairwise", "CCMP")
	w("wpa_passphrase", ph.Passphrase)
	for _, x := range r.BSS {
		if x.Vif == ph.Vif {
			return "", fmt.Errorf("%s: is the placeholder", x.Vif)
		}
		if normMAC(x.BSSID) == "" {
			return "", fmt.Errorf("%s: no BSSID", x.Vif)
		}
		w("bss", x.Vif)
		w("bssid", x.BSSID)
		if err := renderBSS(w, r, x); err != nil {
			return "", fmt.Errorf("%s: %w", x.Vif, err)
		}
	}
	return b.String(), nil
}

func renderBSS(w func(string, any), r hapdRadio, x hapdBSS) error {
	s := x.SSID
	if strings.ContainsAny(s.SSID, "\x00\r\n") || s.SSID == "" || len(s.SSID) > 32 {
		return fmt.Errorf("invalid SSID")
	}
	w("ctrl_interface", CtrlDir)
	w("bridge", x.Bridge)
	w("ssid", s.SSID)
	for i := 0; i < len(s.SSID); i++ {
		if s.SSID[i] >= 0x80 {
			w("utf8_ssid", 1)
			break
		}
	}
	w("ignore_broadcast_ssid", b2i(s.Hidden))
	w("auth_algs", 1)
	w("wmm_enabled", 1)
	w("uapsd_advertisement_enabled", b2i(s.UAPSD))
	w("ap_isolate", b2i(s.Isolation))
	dtim := s.DTIM[r.Band]
	if dtim <= 0 {
		dtim = 1 // TP-Link's value
	}
	w("dtim_period", min(dtim, 255))
	w("max_num_sta", r.MaxSta)
	if r.MinRSSI < 0 {
		w("rssi_reject_assoc_rssi", r.MinRSSI)
		w("rssi_reject_assoc_timeout", 30)
	}
	if s.BSSTransition {
		w("bss_transition", 1)
	}
	if s.MulticastToUnicast {
		w("multicast_to_unicast", 1)
	}
	// No proxy_arp: its x_snoop needs the vif to be a bridge port at BSS
	// setup, impossible for a vif this hostapd creates (live fact F5: the
	// whole process fails). ARP proxying is the bridge port's
	// proxyarp_wifi instead (proxyARPStep).
	switch {
	case macAuth(s):
		// RADIUS MAC authentication (hostapd 2.9 on the X20 has the RADIUS
		// ACL query: "Failed to send Access-Request for ACL query."). No
		// accept_mac_file: hostapd admits its entries without asking RADIUS,
		// so an allow-list filter is left to the driver (wl macmode 2) and
		// both checks apply.
		if len(s.Radius.Auth) == 0 {
			return fmt.Errorf("RADIUS MAC authentication without an auth server")
		}
		w("macaddr_acl", 2)
	case x.Accept:
		w("macaddr_acl", 1)
		w("accept_mac_file", acceptPath(r.RunDir, x.Vif))
	default:
		w("macaddr_acl", 0)
	}
	// Always referenced (possibly empty) so a block-list change rewrites the
	// file and updates hostapd live, without changing the conf.
	w("deny_mac_file", denyPath(r.RunDir, x.Vif))
	if err := writeHotspot2(w, s); err != nil { // Hotspot 2.0: hs20.go
		return err
	}

	enterprise := s.Security == SecWPA2Ent || s.Security == SecWPA3Ent
	if macAuth(s) && !enterprise {
		writeRadius(w, s.Radius, x.BSSID, !s.FT) // FT writes its own nas_identifier
	}

	mgmt, pmf := keyMgmt(s)
	switch s.Security {
	case SecOpen:
		w("wpa", 0)
		return nil
	case SecWPA2Ent, SecWPA3Ent:
		w("ieee8021x", 1)
		w("eapol_version", 2)
	}
	w("wpa", 2)
	w("wpa_key_mgmt", mgmt)
	w("rsn_pairwise", "CCMP")
	w("wpa_group_rekey", max(s.GroupRekey, 0))
	switch s.Security {
	case SecWPA2:
		writePSKFile(w, r, x) // private pre-shared keys: ppsk.go
		if len(s.Passphrase) == 64 && isHex(s.Passphrase) {
			w("wpa_psk", strings.ToLower(s.Passphrase))
		} else if s.Passphrase != "" {
			w("wpa_passphrase", s.Passphrase)
		}
	case SecWPA3, SecWPA2WPA3:
		writePSKFile(w, r, x)
		w("wpa_passphrase", s.Passphrase)
		w("sae_require_mfp", 1)
	case SecWPA2Ent, SecWPA3Ent:
		writeRadius(w, s.Radius, x.BSSID, true)
	}
	w("ieee80211w", pmf)
	if s.FT {
		// FT-PSK with locally generated PMK-R0/R1 (what TP-Link's psk2ft
		// does); FT-SAE with the controller's key for the PMK-R1 transfers
		// between APs, as a UniFi AP does (ftsae.go).
		return writeFT(w, s, r.Band, strings.ReplaceAll(x.BSSID, ":", ""), x.FTPeers)
	}
	return nil
}

// writeRadius writes the RADIUS client lines: NAS identity, auth and acct
// servers (secrets: this conf only, 0600).
func writeRadius(w func(string, any), rad *Radius, bssid string, nasID bool) {
	if nasID {
		nas := rad.NASID
		if nas == "" {
			nas = strings.ReplaceAll(bssid, ":", "")
		}
		if nas != "" {
			w("nas_identifier", nas)
		}
	}
	writeRadiusFilter(w, rad)
	if rad.OwnIP != "" {
		w("own_ip_addr", rad.OwnIP)
	}
	for _, a := range rad.Auth {
		w("auth_server_addr", a.IP)
		w("auth_server_port", portOr(a.Port, 1812))
		w("auth_server_shared_secret", a.Secret)
	}
	for _, a := range rad.Acct {
		w("acct_server_addr", a.IP)
		w("acct_server_port", portOr(a.Port, 1813))
		w("acct_server_shared_secret", a.Secret)
	}
	if len(rad.Acct) > 0 && rad.InterimSeconds > 0 {
		w("radius_acct_interim_interval", rad.InterimSeconds)
	}
}

func portOr(p, def int) int {
	if p == 0 {
		return def
	}
	return p
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// aclFile renders a hostapd MAC list file (one MAC per line).
func aclFile(macs []string) []byte {
	if len(macs) == 0 {
		return []byte{}
	}
	return []byte(strings.Join(macs, "\n") + "\n")
}

// vifACL is the station filter for one vif after merging the SSID's MAC
// filter with the global block list.
type vifACL struct {
	Accept []string // non-nil only for allow-list SSIDs: allow minus blocked
	Deny   []string // SSID deny list plus blocked
	Allow  bool
}

func computeACL(s SSID, blocked []string) vifACL {
	var a vifACL
	isBlocked := map[string]bool{}
	for _, m := range blocked {
		isBlocked[m] = true
	}
	deny := map[string]bool{}
	for _, m := range blocked {
		deny[m] = true
	}
	if mf := s.MACFilter; mf != nil {
		switch mf.Policy {
		case "allow":
			a.Allow = true
			a.Accept = []string{}
			for _, m := range mf.MACs {
				if !isBlocked[m] {
					a.Accept = append(a.Accept, m)
				}
			}
		case "deny":
			for _, m := range mf.MACs {
				deny[m] = true
			}
		}
	}
	for m := range deny {
		a.Deny = append(a.Deny, m)
	}
	sort.Strings(a.Deny)
	return a
}

// driverMacmode returns the wl macmode and list matching acl: 2 (allow) with
// the accept list, 1 (deny) with the deny list, or 0.
func (a vifACL) driverMacmode() (int, []string) {
	if a.Allow {
		return 2, a.Accept
	}
	if len(a.Deny) > 0 {
		return 1, a.Deny
	}
	return 0, nil
}

// vifDriver is the per-vif driver (wl) state the agent sets next to hostapd.
// It is persisted as drv-wlN.json so Plan can tell when it changed.
type vifDriver struct {
	Vif       string   `json:"vif"`
	SSIDID    string   `json:"ssid_id"`
	DWDS      int      `json:"dwds"` // always 0: a client vif never takes WDS peers (audit D8)
	Closed    int      `json:"closednet"`
	Isolate   int      `json:"ap_isolate"`
	MaxAssoc  int      `json:"bss_maxassoc"`
	WMF       int      `json:"wmf_bss_enable"`
	RRM       string   `json:"rrm"`
	NbrScan   int      `json:"rrm_nbr_scan"`
	FBT       int      `json:"fbt"`
	MDID      int      `json:"fbt_mdid,omitempty"`
	R0KH      string   `json:"fbt_r0kh_id,omitempty"`
	OverDS    int      `json:"fbtoverds,omitempty"` // set only when on: a fresh vif reads 0 (.205)
	Macmode   int      `json:"macmode"`
	Maclist   []string `json:"maclist,omitempty"`
	DenyACL   []string `json:"deny,omitempty"`
	AcceptACL []string `json:"accept,omitempty"`
	Allow     bool     `json:"allow,omitempty"`
	// Rates is the wl rateset for the SSID's minimum rate (Options.MinRates
	// only); empty leaves the driver's rateset alone.
	Rates []string `json:"rateset,omitempty"`

	// FTKeyID names the FT-SAE key hostapd was started with (ftpeer.KeyID,
	// not the key): a key change restarts the radio although the r0kh/r1kh
	// lines, the only ones carrying the key, are left out of the conf
	// comparison (ftpeers.go sameConf).
	FTKeyID string `json:"ft_key_id,omitempty"`
}

func driverFor(u vifAssign, bssid string, maxSta int, blocked []string, minRates bool) vifDriver {
	s := u.SSID
	acl := computeACL(s, blocked)
	mode, list := acl.driverMacmode()
	d := vifDriver{
		Vif: u.Vif, SSIDID: s.ID,
		Closed: b2i(s.Hidden), Isolate: b2i(s.Isolation), MaxAssoc: maxSta,
		WMF: b2i(s.MulticastToUnicast), RRM: "0x0",
		Macmode: mode, Maclist: list,
		DenyACL: acl.Deny, AcceptACL: acl.Accept, Allow: acl.Allow,
	}
	if s.RRM {
		d.RRM, d.NbrScan = "0x33", 1 // TP-Link's client-vif value
	}
	if s.FT {
		d.FBT = 1
		d.MDID = int(ssidMDID(s, u.Band))
		if s.FTSAE {
			d.FTKeyID = ftpeer.KeyID(s.FTKey)
		}
		d.R0KH = strings.ReplaceAll(bssid, ":", "")
		d.OverDS = b2i(s.FTOverDS)
	}
	if minRates {
		d.Rates, _ = ssidRateset(s, u.Band)
	}
	return d
}

// radioDownSteps writes the iovars the driver accepts only while the radio
// is down, dwds and rrm, for the vifs ds of radio, inside one wl down / wl
// up. Seen on .205: both are refused with "Not down" (exit 211) while the
// radio is up, whatever the BSS state and even for an unchanged value; with
// the radio down they are accepted, and after wl up every BSS is back in its
// own up/down state and hostapd stays ENABLED.
// extra are further steps that need the radio down (the placeholder's dwds).
func radioDownSteps(radio string, ds []vifDriver, extra ...Step) []Step {
	if len(ds) == 0 && len(extra) == 0 {
		return nil
	}
	st := []Step{cmdStep("radio "+radio+" down for dwds/rrm", "wl", "-i", radio, "down")}
	st = append(st, extra...)
	for _, d := range ds {
		st = append(st,
			cmdStep("set "+d.Vif+" dwds", "wl", "-i", d.Vif, "dwds", itoa(d.DWDS)),
			cmdStep("set "+d.Vif+" rrm", "wl", "-i", d.Vif, "rrm", d.RRM))
	}
	return append(st, cmdStep("radio "+radio+" up", "wl", "-i", radio, "up"))
}

// driverSteps sets d on its vif, except dwds and rrm (radioDownSteps).
// Run them while the fresh BSS is down (wl applies some of these, fbt in
// particular, only then).
func driverSteps(d vifDriver) []Step {
	v := d.Vif
	wl := func(args ...string) Step {
		return cmdStep("set "+v+" "+args[0], append([]string{"wl", "-i", v}, args...)...)
	}
	st := []Step{ // dwds and rrm: radioDownSteps
		wl("closednet", itoa(d.Closed)),
		wl("ap_isolate", itoa(d.Isolate)),
		wl("bss_maxassoc", itoa(d.MaxAssoc)),
		wl("wmf_bss_enable", itoa(d.WMF)),
		wl("rrm_nbr_scan", itoa(d.NbrScan)),
	}
	if d.FBT == 1 {
		st = append(st,
			wl("fbt", "1"), wl("fbt_ap", "1"),
			wl("fbt_mdid", itoa(d.MDID)),
			wl("fbt_r0kh_id", d.R0KH),
			wl("fbt_reassoc_time", itoa(ftReassocMS)))
		if d.OverDS == 1 {
			st = append(st, wl("fbtoverds", "1"))
		}
	} else {
		st = append(st, wl("fbt_ap", "0"), wl("fbt", "0"))
	}
	st = append(st, macSteps(v, d.Macmode, d.Maclist)...)
	if len(d.Rates) > 0 {
		st = append(st, wl(append([]string{"rateset"}, d.Rates...)...))
	}
	return st
}

// macSteps programs the driver MAC filter the way TP-Link does: macmode,
// flush, then one append per address.
func macSteps(vif string, mode int, list []string) []Step {
	st := []Step{
		cmdStep("set "+vif+" macmode", "wl", "-i", vif, "macmode", itoa(mode)),
		cmdStep("flush "+vif+" mac list", "wl", "-i", vif, "mac", "none"),
	}
	for _, m := range list {
		st = append(st, cmdStep("add "+m+" to "+vif+" mac list", "wl", "-i", vif, "mac", m))
	}
	return st
}

func itoa(i int) string { return strconv.Itoa(i) }
