// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"

	"github.com/dtechterminal/udeco/internal/rf"
	"github.com/dtechterminal/udeco/internal/translate"
	"github.com/dtechterminal/udeco/internal/unit"
	"github.com/dtechterminal/udeco/internal/wl"
)

// Desired is the complete Wi-Fi state the agent wants. It mirrors
// translate.Intent (Country, Radios, WLANs) field for field so the agent can
// map it 1:1 (cmd/udeco-ap desiredFrom; its test lists the Intent fields
// that are not carried). The words in it (security, PMF, tx power and band
// steering modes) are translate's, and the two small per-band types are
// translate's own (BandSettings, RateOpts).
type Desired struct {
	Country string           // ISO 3166 alpha-2 ("US"); "" keeps the live country
	Radios  map[string]Radio // "ng" (2.4 GHz, wl0) and "na" (5 GHz, wl1)
	// BandCountry overrides Country for one radio ("ng" -> "US"): the
	// driver country, the channel table and hostapd's country_code of that
	// radio alone. The X20 runs wl0 as US (24 dBm) beside wl1 in IN/288
	// (DFS), verified on .232 2026-11-20.
	BandCountry map[string]string `json:",omitempty"`
	SSIDs       []SSID
	// Guest is the isolation policy for guest SSIDs (SSID.Guest). A guest
	// SSID is only served when Guest is set and has a valid gateway MAC and
	// IP: without isolation it would be a plain LAN SSID (fail closed).
	Guest *GuestPolicy `json:",omitempty"`
}

// Radio mirrors translate.RadioIntent.
type Radio struct {
	Enabled     bool
	Channel     int    // control channel; 0 = auto (keep the live channel; acsd2 is stopped)
	Width       int    // 20, 40, 80 (160 is clamped to 80); 0 = band default
	TxPowerMode string // translate.TxAuto ... TxCustom; "" is auto, and "middle" is read as medium
	TxPower     int    // dBm, for custom
	MinRSSI     int    // dBm (negative); 0 = off
	MaxClients  int    // per BSS on this radio (bss_maxassoc, max_num_sta); 0 = 128
	BandSteer   string // not implemented here (noted)
}

// SSID mirrors translate.WLANIntent. Passphrase and RADIUS secrets are
// secrets: String masks them, and they are written only to the hostapd conf
// (0600) and last-good.secrets.json (0600).
type SSID struct {
	ID         string
	SSID       string
	Bands      []string // "ng"/"na" (also accepts "2g"/"5g")
	Enabled    bool
	Hidden     bool
	Guest      bool
	Security   string // one of the Sec* modes below
	Passphrase string
	PMF        string // translate.PMFDisabled, PMFOptional or PMFRequired ("" = per security default)
	GroupRekey int    // seconds; 0 = never

	VLAN      int
	Isolation bool
	FT        bool // 802.11r: FT-PSK (keys generated locally), plus FT-SAE with FTSAE
	// FTSAE is the controller's WPA3 fast roaming (aaa.N.wpa3.ft.status):
	// with FT on a WPA3 or WPA2/WPA3 SSID, SAE clients roam with FT-SAE
	// too (ftsae.go). It needs FTKey.
	FTSAE bool
	// FTKey is the controller's per-WLAN key (aaa.N.iapp_key, 32 hex
	// digits; 64 accepted) that protects the PMK-R1 transfers between the
	// APs of the WLAN, used as a UniFi AP uses it: wildcard r0kh/r1kh
	// entries. A secret: written only to the 0600 hostapd conf and
	// last-good.secrets.json.
	FTKey string
	// FTOverDS is FT over the distribution system (aaa.N.ft_over_ds);
	// off = over the air only (hostapd's own default is on).
	FTOverDS bool
	// MobilityDomain is the controller's 802.11r MDID (4 hex digits); ""
	// = derived from the SSID (mobilityDomain), the same on every unit.
	MobilityDomain string

	BSSTransition      bool
	RRM                bool
	UAPSD              bool
	ProxyARP           bool
	MulticastToUnicast bool
	// PerBand: the controller's own values for one band when its bands
	// differ (translate.WLANIntent.PerBand); ForBand applies them (mtkwifi).
	// bcmwifi itself serves every band with the SSID-wide fields and notes
	// the bands that differ (perBandNotes).
	PerBand map[string]BandSettings
	DTIM    map[string]int // band -> period
	// MinRateKbps is the lowest data rate per band (band -> kbps). It is
	// applied as the BSS rateset (wl rateset, beacons at the lowest basic
	// rate) only with Options.MinRates; otherwise it is noted.
	MinRateKbps map[string]int
	// MinRateOpts: per band, the beacon rate and CCK choice that go with
	// MinRateKbps (rates.go).
	MinRateOpts map[string]RateOpts
	MACFilter   *MACFilter
	Radius      *Radius
	PSKs        []PSK    // private pre-shared keys (ppsk.go); secrets
	Schedule    []string // not applied here (noted)
	// RateLimit is the per-client limit (the WLAN's user group): every
	// associated station gets its own tc class (SyncRateLimits).
	RateLimit *RateLimit
	// RoamAssist is the Roaming Assistant's RSSI threshold (dBm) per band
	// (absent = off). Nothing is configured for it here: the agent asks
	// weak stations to move with RoamAssist (roaming.go).
	RoamAssist map[string]int
	// No2GHz: "restrict high-performance clients to 5 GHz". Nothing is
	// configured for it here: the agent steers dual-band stations off the
	// SSID's 2.4 GHz BSS (SteerToBand, TempDeny; cmd/udeco-ap no2ghz.go).
	No2GHz bool `json:",omitempty"`
	// Hotspot2 is the Hotspot 2.0 / Passpoint advertisement (hs20.go); nil = off.
	Hotspot2 *Hotspot2 `json:",omitempty"`
	// NoBSSLoad: the controller turned this WLAN's BSS Load element off
	// (wireless.N.qbssload=disabled, an enhanced-IoT WLAN). The element is
	// per radio in this driver: off only when every SSID on the radio
	// says so (parity.go radioBSSLoad).
	NoBSSLoad bool `json:",omitempty"`
	// NoBGAFilter: the controller turned the WLAN's bridge group address
	// filter off (wireless.N.bga_filter=disabled): its vifs are left out
	// of UDECO-BGA (bga.go).
	NoBGAFilter bool `json:",omitempty"`
}

// MACFilter is a per-SSID station filter.
type MACFilter struct {
	Policy string // "allow" (only these) or "deny" (all but these)
	MACs   []string
}

// Radius configures 802.1X for the enterprise security modes, and RADIUS
// MAC authentication (MACAuth) for any security mode.
type Radius struct {
	Auth           []RadiusServer
	Acct           []RadiusServer
	NASID          string // nas_identifier; "" = the BSSID
	OwnIP          string // own_ip_addr (NAS-IP-Address); "" = hostapd default
	InterimSeconds int    // radius_acct_interim_interval
	// MACAuth asks the Auth servers about every station's MAC before it
	// may associate (translate.Radius.MACAuth, aaa.N.radius.macacl): hostapd
	// macaddr_acl=2. An SSID asking for it without a usable auth server is
	// not served (never served without the check).
	MACAuth bool
	// MACFormat is the controller's MAC format for MAC authentication, as
	// sent (translate.Radius.MACFormat). hostapd 2.9 has no setting for the
	// format it sends; a non-empty value is only noted.
	MACFormat string
	// FilterID is sent as RADIUS Filter-Id in every Access-Request
	// (translate.Radius.FilterID; radiusfilter.go).
	FilterID string
}

// RadiusServer is one RADIUS server. Secret is a secret.
type RadiusServer struct {
	IP     string
	Port   int
	Secret string
}

// RateLimit is a per-client rate limit in kbit/s; 0 = no limit that way.
type RateLimit struct {
	DownKbps, UpKbps int
}

// String describes s with the passphrase and RADIUS secrets masked. It is
// also what %v and %+v print.
func (s SSID) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "ssid %s %q bands=%s enabled=%t sec=%s", s.ID, s.SSID, strings.Join(s.Bands, ","), s.Enabled, s.Security)
	if s.Passphrase != "" {
		fmt.Fprintf(&b, " psk=%s", maskSecret(s.Passphrase))
	}
	if s.VLAN != 0 {
		fmt.Fprintf(&b, " vlan=%d", s.VLAN)
	}
	if s.Radius != nil {
		fmt.Fprintf(&b, " radius=%d/%d", len(s.Radius.Auth), len(s.Radius.Acct))
	}
	return b.String()
}

// GoString keeps %#v from printing secrets.
func (s SSID) GoString() string { return "bcmwifi.SSID{" + s.String() + "}" }

// String describes r with the secret masked.
func (r RadiusServer) String() string {
	return fmt.Sprintf("%s:%d secret=%s", r.IP, r.Port, maskSecret(r.Secret))
}

// GoString keeps %#v from printing the secret.
func (r RadiusServer) GoString() string { return "bcmwifi.RadiusServer{" + r.String() + "}" }

func maskSecret(v string) string {
	if v == "" {
		return "''"
	}
	h := sha256.Sum256([]byte(v))
	return fmt.Sprintf("<%x>", h[:3])
}

// bandPrimary maps a band to its radio's primary interface on the X20
// (verified on .205: wl0 is 2.4 GHz, wl1 is 5 GHz).
var bandPrimary = map[string]string{"ng": "wl0", "na": "wl1"}

// radioOrder is the order radios are planned in.
var radioOrder = rf.Bands()

// bandAlias is the other name of one of this unit's bands (ng <-> 2g,
// na <-> 5g); "" for any other name.
func bandAlias(band string) string {
	for _, b := range radioOrder {
		switch band {
		case b:
			return rf.Legacy(b)
		case rf.Legacy(b):
			return b
		}
	}
	return ""
}

// Security mode names accepted in SSID.Security: translate's, which
// produces them (normalizeSSID also takes a few other spellings).
const (
	SecOpen     = translate.SecOpen
	SecWPA2     = translate.SecWPA2
	SecWPA3     = translate.SecWPA3
	SecWPA2WPA3 = translate.SecWPA2WPA3
	SecWPA2Ent  = translate.SecWPA2Ent
	SecWPA3Ent  = translate.SecWPA3Ent
	SecOWE      = translate.SecOWE
)

const (
	maxVifIndex   = 7 // wlN1..wlN7 (the driver's mbss8 minus the primary)
	firstVifIndex = 2
	defaultMaxSta = 128
	// backhaulIndex is TP-Link's mesh backhaul vif (wlN1: dwds=1, hidden,
	// bss_maxassoc 16). The agent makes it its hostapd's interface=
	// placeholder: it survives hostapd's exit, the bss= vifs do not.
	backhaulIndex = 1
	// reservedVLAN collides with imsnoop's br-iptv (interference audit D5,
	// R23): never used for an SSID.
	reservedVLAN = 491
)

// layoutOpts are the Options that change placement. Plan, Verify and the
// ACL refresh must use the same ones, or they disagree on placement.
type layoutOpts struct {
	// anyVifOnLAN lifts R23: br-lan (VLAN 0) SSIDs may use any vif, not
	// only the TP-Link-typed wlN2/wlN3.
	anyVifOnLAN bool
	// minRates applies SSID.MinRateKbps (Options.MinRates).
	minRates bool
	// anchor: the radio's hostapd interface= vif by primary (anchor.go);
	// nil means wlN1, the satellite layout.
	anchor func(primary string) string
	// guestOK: Desired.Guest is usable, so guest SSIDs may be served.
	guestOK bool
	// prior: vif -> SSID id of the placement in force (and of SSIDs that
	// were placed before and are off now), slots.go. An SSID keeps its vif
	// while it may; nil places by WLAN id alone.
	prior map[string]string
	// noSAE: SAE may not be served (Options.WPA3 off): a WPA2/WPA3 SSID
	// is served as WPA2 and a WPA3-only one is skipped (wpa3.go).
	noSAE bool
	// noFTSAE: FT-SAE may not be served (Applier.ServesFTSAE false): an
	// SSID keeps FT-PSK and SAE without FT (ftsae.go withoutFTSAE).
	noFTSAE bool
}

// vifIndex is N in wlXN (wl02 -> 2); 0 for a primary or a non-vif name.
func vifIndex(v string) int {
	if len(v) != 4 || !strings.HasPrefix(v, "wl") {
		return 0
	}
	return int(v[3] - '0')
}

// isBackhaul reports TP-Link's backhaul vif wlN1.
func isBackhaul(v string) bool { return vifIndex(v) == backhaulIndex }

// lanVif reports a vif TP-Link's tpbr already types for br-lan (R23).
func lanVif(v string) bool { i := vifIndex(v); return i == 2 || i == 3 }

// vifAssign is one SSID placed on one vif.
type vifAssign struct {
	Vif    string
	Band   string
	Bridge string
	SSID   SSID
}

// radioLayout is the per-radio part of a layout.
type radioLayout struct {
	Band    string
	Primary string
	Anchor  string // hostapd's interface= vif: wlN1 on a satellite, wlN on the master (anchor.go)
	Radio   Radio
	HasCfg  bool     // Desired.Radios had an entry for this band
	Vifs    []string // known vifs wlN1..wlN7 (existing, or BSSID known so hostapd can create them), sorted
	Used    []vifAssign
}

// layout is the pure placement of Desired onto the hardware.
type layout struct {
	Radios []*radioLayout
	VLANs  []int
	Notes  []string
	Guest  *guestRules // normalized Desired.Guest; nil = no guest SSIDs served
}

// guestVifs lists the vifs that carry a guest SSID, sorted.
func (l *layout) guestVifs() []string {
	var out []string
	for _, r := range l.Radios {
		for _, u := range r.Used {
			if u.SSID.Guest {
				out = append(out, u.Vif)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (l *layout) radio(band string) *radioLayout {
	for _, r := range l.Radios {
		if r.Band == band {
			return r
		}
	}
	return nil
}

// usedVif returns the assignment for vif, if any.
func (l *layout) usedVif(vif string) (vifAssign, bool) {
	for _, r := range l.Radios {
		for _, u := range r.Used {
			if u.Vif == vif {
				return u, true
			}
		}
	}
	return vifAssign{}, false
}

// vlanBridge names the bridge an SSID on vid joins.
func vlanBridge(vid int) string {
	if vid == 0 {
		return unit.LANBridge
	}
	return unit.VLANBridge(vid)
}

// planLayout validates d and places its SSIDs on vifs. exists reports whether
// a netdev exists. It does no I/O and never fails: invalid or unsupported
// pieces are skipped with a note.
//
// Placement, per radio, stable by WLAN id: an SSID that o.prior places on
// a vif keeps it while that vif may carry it (so adding, removing,
// disabling or scheduling off another SSID never moves it: a move changes
// its BSSID and drops its clients); every other SSID takes the first free vif
// of wlN2..wlN7 (those that exist or whose BSSID is known, see vifKnown),
// preferring vifs o.prior holds for no SSID, so a vif held for an SSID that
// is off now is taken only when no other is free.
// wlN1 never carries an SSID: it is the agent hostapd's interface=
// placeholder (hidden, kept BSS down), the one vif that survives hostapd's
// exit. Until R22 is settled (!o.anyVifOnLAN) a br-lan SSID may
// only use wlN2 or wlN3, the vifs TP-Link's tpbr already types (interference
// audit D4, R23), and the br-lan SSIDs are placed before the VLAN ones. The
// primary wlN (an 8th BSS on a satellite's STA interface) is never used: it
// needs a live test first.
func planLayout(d Desired, exists func(string) bool, o layoutOpts) *layout {
	l := &layout{}
	type cand struct {
		s     SSID
		bands []string
	}
	var cands []cand
	seen := map[string]bool{}
	for i, s := range d.SSIDs {
		s.ID = ssidKey(i, s)
		if seen[s.ID] {
			l.Notes = append(l.Notes, fmt.Sprintf("ssid %s: duplicate WLAN id, skipped", s.ID))
			continue
		}
		seen[s.ID] = true
		if !s.Enabled {
			continue
		}
		if o.noSAE {
			ws, n, ok := withoutSAE(s) // wpa3.go
			if n != "" {
				l.Notes = append(l.Notes, n)
			}
			if !ok {
				continue
			}
			s = ws
		}
		if o.noFTSAE {
			ws, n := withoutFTSAE(s) // ftsae.go
			if n != "" {
				l.Notes = append(l.Notes, n)
			}
			s = ws
		}
		ns, notes, ok := normalizeSSID(s)
		l.Notes = append(l.Notes, notes...)
		if !ok {
			continue
		}
		if ns.Guest && !o.guestOK {
			l.Notes = append(l.Notes, fmt.Sprintf("ssid %s: guest network without a usable guest policy (gateway MAC and IP), not served (no isolation = LAN access)", s.ID))
			continue
		}
		if ns.VLAN == reservedVLAN {
			l.Notes = append(l.Notes, fmt.Sprintf("ssid %s: VLAN %d collides with TP-Link's br-iptv (imsnoop), skipped", s.ID, reservedVLAN))
			continue
		}
		for _, b := range sortedKeys(ns.MinRateKbps) {
			k := ns.MinRateKbps[b]
			if k <= 0 {
				continue
			}
			if !o.minRates {
				l.Notes = append(l.Notes, fmt.Sprintf("ssid %s: minimum rate %s=%d kbps not applied (Options.MinRates is off; untested on hardware)", s.ID, b, k))
			} else if _, n := ssidRateset(ns, rf.Norm(b)); n != "" {
				l.Notes = append(l.Notes, fmt.Sprintf("ssid %s: %s", s.ID, n))
			}
		}
		var bands []string
		for _, b := range s.Bands {
			if nb := rf.Norm(b); nb != "" && !contains(bands, nb) {
				bands = append(bands, nb)
			} else if nb == "" {
				l.Notes = append(l.Notes, fmt.Sprintf("ssid %s: band %q not supported on this unit", s.ID, b))
			}
		}
		cands = append(cands, cand{ns, bands})
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].s.ID < cands[j].s.ID })

	vlans := map[int]bool{}
	for _, band := range radioOrder {
		prim := bandPrimary[band]
		rl := &radioLayout{Band: band, Primary: prim, Radio: Radio{Enabled: true}}
		if r, ok := d.Radios[band]; ok {
			rl.Radio, rl.HasCfg = r, true
		}
		for i := 1; i <= maxVifIndex; i++ {
			if v := fmt.Sprintf("%s%d", prim, i); exists(v) {
				rl.Vifs = append(rl.Vifs, v)
			}
		}
		l.Radios = append(l.Radios, rl)
		if !exists(prim) {
			l.Notes = append(l.Notes, fmt.Sprintf("radio %s: %s missing, no SSIDs placed", band, prim))
			continue
		}
		// the anchor (wlN1 on a satellite, wlN on the master) is hostapd's
		// interface= placeholder, the one vif that survives hostapd's exit
		// (live facts F2/F4): never an SSID.
		rl.Anchor = prim + "1"
		if o.anchor != nil {
			rl.Anchor = o.anchor(prim)
		}
		if !exists(rl.Anchor) {
			l.Notes = append(l.Notes, fmt.Sprintf("radio %s: %s missing (hostapd's interface= vif), no SSIDs placed", band, rl.Anchor))
			continue
		}
		var free []string
		for _, v := range rl.Vifs {
			if vifIndex(v) >= firstVifIndex {
				free = append(free, v)
			}
		}
		// the prior placement on this radio: id -> vif, and the vifs held
		priorOf, held := map[string]string{}, map[string]bool{}
		for v, id := range o.prior {
			if strings.HasPrefix(v, prim) && vifIndex(v) >= firstVifIndex && len(v) == len(prim)+1 {
				priorOf[id], held[v] = v, true
			}
		}
		take := func(ok func(string) bool, want string) (string, bool) {
			pick := func(i int) (string, bool) {
				v := free[i]
				free = append(free[:i:i], free[i+1:]...)
				delete(held, v)
				return v, true
			}
			for i, v := range free {
				if v == want && ok(v) {
					return pick(i)
				}
			}
			for i, v := range free {
				if ok(v) && !held[v] {
					return pick(i)
				}
			}
			for i, v := range free {
				if ok(v) {
					return pick(i)
				}
			}
			return "", false
		}
		// With R23 in force, br-lan SSIDs go first so VLAN SSIDs cannot take
		// the only two vifs they may use; otherwise one pass by WLAN id.
		passes := 2
		if o.anyVifOnLAN {
			passes = 1
		}
		// Within a pass the SSIDs that have a prior vif go first, so a new
		// SSID cannot take it from them.
		order := make([]cand, 0, len(cands))
		for keep := 0; keep < 2; keep++ {
			for _, c := range cands {
				if _, ok := priorOf[c.s.ID]; ok == (keep == 0) {
					order = append(order, c)
				}
			}
		}
		for pass := 0; pass < passes; pass++ {
			for _, c := range order {
				if !contains(c.bands, band) || passes == 2 && (pass == 0) != (c.s.VLAN == 0) {
					continue
				}
				if !rl.Radio.Enabled {
					l.Notes = append(l.Notes, fmt.Sprintf("ssid %s: radio %s disabled, not placed", c.s.ID, band))
					continue
				}
				ok := func(string) bool { return true }
				if c.s.VLAN == 0 && !o.anyVifOnLAN {
					ok = lanVif
				}
				want := priorOf[c.s.ID]
				v, got := take(ok, want)
				if got && want != "" && v != want {
					l.Notes = append(l.Notes, fmt.Sprintf("ssid %s: moved from %s to %s (its vif is not available to it)", c.s.ID, want, v))
				}
				if !got {
					if len(free) > 0 {
						l.Notes = append(l.Notes, fmt.Sprintf("ssid %s: no br-lan vif left on %s (R23: br-lan SSIDs use wl%s2/wl%s3 only until tpbr typing is settled), not placed", c.s.ID, band, prim[2:], prim[2:]))
					} else {
						l.Notes = append(l.Notes, fmt.Sprintf("ssid %s: no free vif on %s (wl%s2..7 in use)", c.s.ID, band, prim[2:]))
					}
					continue
				}
				rl.Used = append(rl.Used, vifAssign{Vif: v, Band: band, Bridge: vlanBridge(c.s.VLAN), SSID: c.s})
				if c.s.VLAN != 0 {
					vlans[c.s.VLAN] = true
				}
			}
		}
		// The hostapd conf lists BSSes in vif order (after the wlN1 placeholder, as
		// in TP-Link's own conf).
		sort.SliceStable(rl.Used, func(i, j int) bool { return rl.Used[i].Vif < rl.Used[j].Vif })
		l.Notes = append(l.Notes, radioNotes(band, rl.Radio)...)
	}
	for v := range vlans {
		l.VLANs = append(l.VLANs, v)
	}
	sort.Ints(l.VLANs)
	return l
}

func radioNotes(band string, r Radio) []string {
	var n []string
	if r.BandSteer != "" && r.BandSteer != translate.BandSteerOff {
		n = append(n, fmt.Sprintf("radio %s: band steering %q not implemented", band, r.BandSteer))
	}
	if r.Width > maxWidth {
		n = append(n, fmt.Sprintf("radio %s: width %d not available, using %d", band, r.Width, maxWidth))
	}
	return n
}

// normalizeSSID validates s and fills defaults. It returns ok=false (with a
// note) when the SSID cannot be served safely. Notes never contain secrets.
func normalizeSSID(s SSID) (SSID, []string, bool) {
	notes := perBandNotes(s)
	skip := func(why string) (SSID, []string, bool) {
		return s, append(notes, fmt.Sprintf("ssid %s: %s, skipped", s.ID, why)), false
	}
	if n := len(s.SSID); n == 0 || n > 32 {
		return skip(fmt.Sprintf("SSID length %d not in 1..32", n))
	}
	if strings.ContainsAny(s.SSID, "\x00\r\n") {
		return skip("SSID contains a control character hostapd cannot read")
	}
	s.Security = strings.ToLower(strings.TrimSpace(s.Security))
	switch s.Security {
	case "", "none":
		s.Security = SecOpen
	case "wpa3-transition", "wpa2-wpa3", "wpa2/wpa3":
		s.Security = SecWPA2WPA3
	}
	s, notes = normalizePSKs(s, notes) // private pre-shared keys: ppsk.go
	switch s.Security {
	case SecOpen:
	case SecWPA2:
		if !validPSK(s.Passphrase, true) && (s.Passphrase != "" || len(s.PSKs) == 0) {
			return skip("passphrase is not 8..63 printable ASCII or 64 hex")
		}
	case SecWPA3, SecWPA2WPA3:
		if !validPSK(s.Passphrase, false) {
			return skip("passphrase is not 8..63 printable ASCII (SAE)")
		}
	case SecWPA2Ent, SecWPA3Ent:
		if err := validRadius(s.Radius); err != nil {
			return skip("radius: " + err.Error())
		}
	case SecOWE:
		return skip("OWE is not supported by this hostapd build (no OWE key management)")
	default:
		return skip(fmt.Sprintf("security %q not supported", s.Security))
	}
	if s.Radius != nil && s.Radius.MACAuth {
		// Fail closed: an SSID that wants RADIUS MAC authentication is never
		// built without it (an open one would be open to every station).
		if err := validRadius(s.Radius); err != nil {
			return skip("RADIUS MAC authentication: " + err.Error())
		}
		if s.Radius.MACFormat != "" {
			notes = append(notes, fmt.Sprintf("ssid %s: RADIUS MAC authentication: MAC format %q not selectable in hostapd 2.9, its own format is sent", s.ID, s.Radius.MACFormat))
		}
	}
	s.PMF = strings.ToLower(s.PMF)
	if why := normalizeHotspot2(&s, &notes); why != "" { // Hotspot 2.0: hs20.go
		return skip(why)
	}
	s, notes = normalizeFT(s, notes) // 802.11r, FT-SAE: ftsae.go
	if s.VLAN < 0 || s.VLAN > 4094 {
		return skip(fmt.Sprintf("VLAN %d out of range", s.VLAN))
	}
	if s.MACFilter != nil {
		mf := *s.MACFilter
		mf.Policy = strings.ToLower(mf.Policy)
		if mf.Policy != "allow" && mf.Policy != "deny" {
			return skip(fmt.Sprintf("MAC filter policy %q not allow/deny", s.MACFilter.Policy))
		}
		macs, bad := normMACs(mf.MACs)
		if bad > 0 {
			notes = append(notes, fmt.Sprintf("ssid %s: %d invalid MAC filter entries dropped", s.ID, bad))
		}
		mf.MACs = macs
		s.MACFilter = &mf
	}
	if len(s.Schedule) > 0 {
		notes = append(notes, fmt.Sprintf("ssid %s: schedule not applied by bcmwifi", s.ID))
	}
	if r := s.RateLimit; r != nil && (r.DownKbps < 0 || r.UpKbps < 0) {
		notes = append(notes, fmt.Sprintf("ssid %s: negative rate limit ignored", s.ID))
		s.RateLimit = nil
	}
	return s, notes, true
}

// validPSK is translate.ValidWPAPassphrase (8..63 printable ASCII, or 64
// hex digits); without hexOK (SAE takes no raw PSK) the 64 hex digits are
// refused too.
func validPSK(p string, hexOK bool) bool {
	return translate.ValidWPAPassphrase(p) && (hexOK || len(p) != 64)
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func validRadius(r *Radius) error {
	if r == nil || len(r.Auth) == 0 {
		return fmt.Errorf("no authentication server")
	}
	check := func(kind string, ss []RadiusServer) error {
		for i, s := range ss {
			if net.ParseIP(s.IP) == nil {
				return fmt.Errorf("%s server %d: bad IP %q", kind, i, s.IP)
			}
			if s.Port < 0 || s.Port > 65535 {
				return fmt.Errorf("%s server %d: bad port %d", kind, i, s.Port)
			}
			if s.Secret == "" || strings.ContainsAny(s.Secret, "\x00\r\n") {
				return fmt.Errorf("%s server %d: empty or unprintable secret", kind, i)
			}
		}
		return nil
	}
	if err := check("auth", r.Auth); err != nil {
		return err
	}
	if err := check("acct", r.Acct); err != nil {
		return err
	}
	if r.OwnIP != "" && net.ParseIP(r.OwnIP) == nil {
		return fmt.Errorf("bad own IP %q", r.OwnIP)
	}
	if strings.ContainsAny(r.NASID, "\x00\r\n") {
		return fmt.Errorf("NAS id contains a control character")
	}
	return nil
}

// normMAC returns mac as lower-case aa:bb:cc:dd:ee:ff, or "" if invalid
// (wl.NormMAC, after trimming).
func normMAC(mac string) string {
	m, _ := wl.NormMAC(strings.TrimSpace(mac))
	return m
}

// normMACs normalizes, de-duplicates and sorts macs; bad counts the
// invalid entries dropped.
func normMACs(macs []string) (out []string, bad int) {
	seen := map[string]bool{}
	for _, m := range macs {
		n := normMAC(m)
		if n == "" {
			bad++
			continue
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, bad
}

// ssidKey is s's WLAN id, or a positional stand-in when the id is empty.
func ssidKey(i int, s SSID) string {
	if s.ID == "" {
		return fmt.Sprintf("idx%02d", i)
	}
	return s.ID
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// secretSet holds the secrets split out of a Desired for storage.
type secretSet struct {
	SSIDs map[string]ssidSecrets `json:"ssids"`
}

type ssidSecrets struct {
	Passphrase string   `json:"passphrase,omitempty"`
	Auth       []string `json:"auth,omitempty"`
	Acct       []string `json:"acct,omitempty"`
	PSKs       []string `json:"psks,omitempty"`   // SSID.PSKs passphrases, by index
	FTKey      string   `json:"ft_key,omitempty"` // SSID.FTKey (the controller's iapp_key)
}

// clone deep-copies d.
func (d Desired) clone() Desired {
	b, err := json.Marshal(d)
	if err != nil {
		panic(err) // Desired has only marshalable fields
	}
	var c Desired
	if err := json.Unmarshal(b, &c); err != nil {
		panic(err)
	}
	return c
}

// splitSecrets returns a copy of d without secrets, and the secrets keyed by
// SSID id.
func splitSecrets(d Desired) (Desired, secretSet) {
	pub := d.clone()
	sec := secretSet{SSIDs: map[string]ssidSecrets{}}
	for i := range pub.SSIDs {
		s := &pub.SSIDs[i]
		var x ssidSecrets
		x.Passphrase, s.Passphrase = s.Passphrase, ""
		x.FTKey, s.FTKey = s.FTKey, ""
		for j := range s.PSKs {
			x.PSKs, s.PSKs[j].Passphrase = append(x.PSKs, s.PSKs[j].Passphrase), ""
		}
		if s.Radius != nil {
			for j := range s.Radius.Auth {
				x.Auth = append(x.Auth, s.Radius.Auth[j].Secret)
				s.Radius.Auth[j].Secret = ""
			}
			for j := range s.Radius.Acct {
				x.Acct = append(x.Acct, s.Radius.Acct[j].Secret)
				s.Radius.Acct[j].Secret = ""
			}
		}
		// planLayout serves the first SSID of a duplicated WLAN id; keep its
		// secrets, not the last duplicate's.
		if _, dup := sec.SSIDs[ssidKey(i, *s)]; !dup && (x.Passphrase != "" || x.FTKey != "" || len(x.Auth) > 0 || len(x.Acct) > 0 || len(x.PSKs) > 0) {
			sec.SSIDs[ssidKey(i, *s)] = x
		}
	}
	return pub, sec
}

// joinSecrets puts sec back into pub (in place).
func joinSecrets(pub *Desired, sec secretSet) {
	for i := range pub.SSIDs {
		s := &pub.SSIDs[i]
		x, ok := sec.SSIDs[ssidKey(i, *s)]
		if !ok {
			continue
		}
		s.Passphrase = x.Passphrase
		s.FTKey = x.FTKey
		for j := range s.PSKs {
			if j < len(x.PSKs) {
				s.PSKs[j].Passphrase = x.PSKs[j]
			}
		}
		if s.Radius != nil {
			for j := range s.Radius.Auth {
				if j < len(x.Auth) {
					s.Radius.Auth[j].Secret = x.Auth[j]
				}
			}
			for j := range s.Radius.Acct {
				if j < len(x.Acct) {
					s.Radius.Acct[j].Secret = x.Acct[j]
				}
			}
		}
	}
}

// BandSettings is one band's own security and roaming settings of an SSID
// (SSID.PerBand): translate's type, so a field added there is carried here.
// ForBand and bandSettings below name each field; a test holds them to the
// type.
type BandSettings = translate.BandWLAN

// ForBand is s as the controller sent it for band ("ng"/"na", or
// "2g"/"5g"): the band's own settings from PerBand when it has them.
func (s SSID) ForBand(band string) SSID {
	b, ok := s.PerBand[band]
	if !ok {
		if b, ok = s.PerBand[bandAlias(band)]; !ok {
			return s
		}
	}
	s.Security, s.PMF, s.FT, s.FTSAE, s.FTOverDS = b.Security, b.PMF, b.FT, b.FTSAE, b.FTOverDS
	s.MobilityDomain, s.BSSTransition, s.RRM = b.MobilityDomain, b.BSSTransition, b.RRM
	s.UAPSD, s.ProxyARP, s.MulticastToUnicast = b.UAPSD, b.ProxyARP, b.MulticastToUnicast
	s.Hidden, s.Isolation, s.GroupRekey = b.Hidden, b.Isolation, b.GroupRekey
	return s
}

// bandSettings is s's SSID-wide security and roaming settings (the ones
// bcmwifi serves on every band).
func (s SSID) bandSettings() BandSettings {
	return BandSettings{Security: s.Security, PMF: s.PMF, FT: s.FT, FTSAE: s.FTSAE, FTOverDS: s.FTOverDS,
		MobilityDomain: s.MobilityDomain, BSSTransition: s.BSSTransition, RRM: s.RRM, UAPSD: s.UAPSD,
		ProxyARP: s.ProxyARP, MulticastToUnicast: s.MulticastToUnicast, Hidden: s.Hidden,
		Isolation: s.Isolation, GroupRekey: s.GroupRekey}
}

// perBandNotes notes each band whose own settings (SSID.PerBand) differ from
// the SSID-wide ones. bcmwifi does not apply PerBand: it serves every band
// with the SSID-wide settings (translate takes them from the first band),
// as it did before PerBand existed, and this keeps the "not carried" note
// translate gave for such a WLAN until then. Field names only, never values.
func perBandNotes(s SSID) []string {
	if len(s.PerBand) == 0 {
		return nil
	}
	bands := make([]string, 0, len(s.PerBand))
	for b := range s.PerBand {
		bands = append(bands, b)
	}
	sort.Strings(bands)
	want := reflect.ValueOf(s.bandSettings())
	var notes []string
	for _, b := range bands {
		got := reflect.ValueOf(s.PerBand[b])
		var diff []string
		for i := 0; i < want.NumField(); i++ {
			if !reflect.DeepEqual(want.Field(i).Interface(), got.Field(i).Interface()) {
				diff = append(diff, strings.ToLower(want.Type().Field(i).Name))
			}
		}
		if len(diff) > 0 {
			notes = append(notes, fmt.Sprintf("ssid %s: %s differ on %s: bcmwifi serves every band with the SSID-wide settings",
				s.ID, strings.Join(diff, ", "), b))
		}
	}
	return notes
}
