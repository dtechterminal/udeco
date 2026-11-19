// SPDX-License-Identifier: GPL-2.0-or-later

package deco

// collect.go maps the Mesh cache to one openwrt.Snapshot per Deco unit, the
// reading the upstream inform code turns into a UniFi AP payload
// (docs/deco/design.md §6). Nothing here does I/O: a runner calls Collect
// with Mesh.Snapshot() on every inform.

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/openwrt"
)

var (
	// ErrNoDeviceList: the Mesh has not read device_list yet; use a skeleton.
	ErrNoDeviceList = errors.New("deco collect: device_list not read yet")
	// ErrUnitAbsent: the unit's MAC is not in device_list.
	ErrUnitAbsent = errors.New("deco collect: unit not in device_list")
)

// Defaults for figures the Deco does not report.
const (
	noiseFloor     = -95 // dBm; rssi = signal - noise, so never 0 (unifi.go:222)
	defaultSignal  = -60 // dBm when neither strength nor level is known
	defaultMaxGap  = 60 * time.Second
	defaultMaxAge  = 45 * time.Second // 3 polls at the default 15 s
	counterExpiry  = time.Hour        // forget a client's byte counters after this long unseen
	defaultPortMbs = 1000
)

// Unit is one Deco presented to UniFi as an AP.
type Unit struct {
	Name string // config name; the hostname when the Deco has no nickname
	MAC  string // configured MAC, any format
	IP   string // the Deco's own IP from the config
}

// RadioSpec carries the per-band figures the Deco does not report (spatial
// streams, tx power range); the runner fills them from the UniFi profile.
type RadioSpec struct {
	NSS, TxMin, TxMax int
}

// CollectOptions tune the mapping. Zero values take the defaults.
type CollectOptions struct {
	Netmask, Gateway string
	// Radios by band ("ng", "na"). Default: a 2x2 AX radio, 6-20 dBm, like
	// the X20.
	Radios map[string]RadioSpec
	// HideWired leaves wired clients out of the port's mac_table. Whether a
	// master in AP mode lists every LAN host as its wired client is OPEN.
	HideWired bool
	// MaxGap caps the time one speed sample is integrated over, so a long
	// polling outage does not add a burst of invented bytes. Default 60 s.
	MaxGap time.Duration
	// MaxAge is how old device_list and the presence lists (0x4014, 0x4040,
	// 0x4012) may be and still be reported as current (see Fresh,
	// LiveClients); past it the unit reports no clients rather than a frozen
	// list. Default 45 s; about 3x the poll.
	MaxAge time.Duration
}

var defaultRadios = map[string]RadioSpec{
	"ng": {NSS: 2, TxMin: 6, TxMax: 20},
	"na": {NSS: 2, TxMin: 6, TxMax: 20},
}

// counter is an integrated byte count from the AP's point of view: tx =
// towards the client (its download), rx = from the client (its upload).
type counter struct {
	rx, tx int64
	seen   time.Time
}

// add integrates one speed sample (kbps) over dt: kbit/s * ms / 8 = bytes.
func (c *counter) add(upKbps, downKbps int64, dt time.Duration) {
	c.rx += max(upKbps, 0) * dt.Milliseconds() / 8
	c.tx += max(downKbps, 0) * dt.Milliseconds() / 8
}

// Collector maps the Mesh cache to Snapshots for one unit. It keeps the
// state a single reading lacks: when the unit was first seen online (uptime
// fallback) and byte counters integrated from the 0x4014 speeds. Not safe for
// concurrent use; each runner owns one.
type Collector struct {
	unit  Unit
	mac   string
	opts  CollectOptions
	start time.Time

	firstOnline time.Time
	lastSpeedAt time.Time
	sta         map[string]*counter // client MAC
	vap         map[string]*counter // band + "|" + main/guest
	port        counter
}

// NewCollector returns a Collector for u. now is the daemon's start, the
// base of the skeleton uptime.
func NewCollector(u Unit, opts CollectOptions, now time.Time) (*Collector, error) {
	mac := NormMAC(u.MAC)
	if mac == "" {
		return nil, fmt.Errorf("deco collect: bad unit mac %q", u.MAC)
	}
	if opts.MaxGap <= 0 {
		opts.MaxGap = defaultMaxGap
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = defaultMaxAge
	}
	r := map[string]RadioSpec{}
	for b, s := range defaultRadios {
		r[b] = s
	}
	for b, s := range opts.Radios {
		if s.NSS > 0 && s.TxMax > 0 {
			r[b] = s
		}
	}
	opts.Radios = r
	return &Collector{unit: u, mac: mac, opts: opts, start: now,
		sta: map[string]*counter{}, vap: map[string]*counter{}}, nil
}

// MAC is the unit's normalised MAC.
func (c *Collector) MAC() string { return c.mac }

// FindUnit returns a copy of the device_list entry with mac, or nil.
func FindUnit(s *MeshState, mac string) *Deco {
	if s == nil || s.Devices.Value == nil {
		return nil
	}
	n := NormMAC(mac)
	for _, d := range s.Devices.Value.DeviceList {
		if n != "" && NormMAC(d.MAC) == n {
			c := d
			return &c
		}
	}
	return nil
}

// UnitOnline reports whether a device_list entry counts as online: its
// inet_status is not offline (absent means online, TMPDeviceBaseBean.java:71-72)
// and its group_status is not disconnected.
func UnitOnline(d *Deco) bool {
	return d != nil && d.IsOnline() && !d.GroupStatus.Is(GroupDisconnected)
}

// Skeleton is the reading for a unit the Mesh has not described yet: identity,
// the uptime since the daemon started, an up eth0 and both radios without
// VAPs, so the UniFi payload stays valid.
func (c *Collector) Skeleton(now time.Time) *openwrt.Snapshot {
	s := c.base(now)
	s.Uptime = int64(now.Sub(c.start) / time.Second)
	s.Radios = []openwrt.Radio{c.radio("ng", nil, nil), c.radio("na", nil, nil)}
	s.Ports = []openwrt.Port{{Name: "eth0", MAC: c.mac, Up: true, Speed: defaultPortMbs, FullDuplex: true, BridgePort: 1}}
	return s
}

func (c *Collector) base(now time.Time) *openwrt.Snapshot {
	return &openwrt.Snapshot{
		Time:       now,
		Model:      "TP-Link Deco",
		Hostname:   c.unit.Name,
		MAC:        c.mac,
		IP:         c.unit.IP,
		Netmask:    c.opts.Netmask,
		Gateway:    c.opts.Gateway,
		ARP:        map[string]string{},
		UplinkName: "eth0",
	}
}

// Collect maps the cached mesh state to this unit's Snapshot. It fails with
// ErrNoDeviceList or ErrUnitAbsent; the runner then reuses its previous
// reading or a Skeleton.
func (c *Collector) Collect(s *MeshState, now time.Time) (*openwrt.Snapshot, error) {
	if s == nil || s.Devices.Value == nil {
		return nil, ErrNoDeviceList
	}
	dev := FindUnit(s, c.mac)
	if dev == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnitAbsent, c.mac)
	}
	snap := c.base(now)
	if dev.DeviceModel != "" {
		snap.Model = "TP-Link Deco " + dev.DeviceModel
		if dev.HardwareVer != "" {
			snap.Model += " v" + dev.HardwareVer
		}
	}
	switch {
	case dev.CustomNickname != "":
		snap.Hostname = string(dev.CustomNickname)
	case dev.Nickname != "" && !dev.Nickname.Is("custom"):
		snap.Hostname = string(dev.Nickname)
	}
	snap.Release = dev.SoftwareVer
	if dev.IP != "" {
		snap.IP = dev.IP
	}

	online := UnitOnline(dev)
	switch {
	case !online:
		c.firstOnline = time.Time{}
	case c.firstOnline.IsZero():
		c.firstOnline = now
	}
	if dev.Runtime != nil && *dev.Runtime > 0 {
		snap.Uptime = int64(*dev.Runtime)
	} else if !c.firstOnline.IsZero() {
		snap.Uptime = int64(now.Sub(c.firstOnline) / time.Second)
	}

	var wi *WirelessInfo
	if s.Wireless.Value != nil {
		wi = s.Wireless.Value
	}
	var tdp *DecoInfo
	if s.Units != nil {
		tdp = s.Units[c.mac]
	}
	ng := c.radio("ng", bandOf(wi, "ng"), tdp)
	na := c.radio("na", bandOf(wi, "na"), tdp)

	stations, wired, arp := c.assign(s, dev, now)
	c.integrate(s, stations, wired, now)
	byBand := map[string]*openwrt.Radio{"ng": &ng, "na": &na}
	for _, st := range stations {
		r := byBand[st.band]
		v := c.vapFor(r, st.guest, bandOf(wi, st.band))
		cnt := c.sta[st.Station.MAC]
		st.Station.RxBytes, st.Station.TxBytes = cnt.rx, cnt.tx
		r.VAPs[v].Stations = append(r.VAPs[v].Stations, st.Station)
	}
	for _, r := range []*openwrt.Radio{&ng, &na} {
		for i := range r.VAPs {
			v := &r.VAPs[i]
			sort.Slice(v.Stations, func(a, b int) bool { return v.Stations[a].MAC < v.Stations[b].MAC })
			if cnt := c.vap[vapKey(r.Band, v.Iface)]; cnt != nil {
				v.Stats["rx_bytes"], v.Stats["tx_bytes"] = cnt.rx, cnt.tx
			}
		}
	}
	snap.Radios = []openwrt.Radio{ng, na}
	snap.Ports, snap.FDB = c.ports(s, dev, wired)
	for mac, ip := range arp {
		snap.ARP[mac] = ip
	}
	// The parent unit, for mesh rendering (design §6.1).
	if p := parentOf(s, dev); p != nil && NormMAC(p.MAC) != "" && p.IP != "" {
		snap.ARP[NormMAC(p.MAC)] = p.IP
	}
	return snap, nil
}

// GuestAuthorized lists every station MAC in snap: a Deco guest network has
// no portal, so every guest that associated is authorized (unifi.go:234-237).
func GuestAuthorized(snap *openwrt.Snapshot) map[string]bool {
	out := map[string]bool{}
	if snap == nil {
		return out
	}
	for _, r := range snap.Radios {
		for _, v := range r.VAPs {
			for _, st := range v.Stations {
				out[strings.ToLower(st.MAC)] = true
			}
		}
	}
	return out
}

// ---- radios and VAPs ----

// bandOf picks the WirelessInfo band for a UniFi radio band.
func bandOf(wi *WirelessInfo, band string) *WirelessBand {
	if wi == nil {
		return nil
	}
	if band == "ng" {
		return wi.Band2G4
	}
	if wi.Band5G1 != nil {
		return wi.Band5G1
	}
	return wi.Band5G2
}

func (c *Collector) radio(band string, wb *WirelessBand, tdp *DecoInfo) openwrt.Radio {
	idx, name := 0, "wifi0"
	if band == "na" {
		idx, name = 1, "wifi1"
	}
	spec := c.opts.Radios[band]
	r := openwrt.Radio{
		Iface: name, Phy: fmt.Sprintf("phy%d", idx), Mode: "Master", Band: band,
		NSS: spec.NSS, TxMin: spec.TxMin, TxMax: spec.TxMax, TxPower: spec.TxMax,
		Noise: noiseFloor, HWName: "Deco", Stats: zeroStats(),
	}
	// Channel: the unit's own TDP figure, else the network-wide radio one.
	if tdp != nil {
		ch := tdp.Channel2G
		if band == "na" {
			ch = tdp.Channel5G
		}
		r.Channel = atoiLenient(string(ch))
	}
	htmode := ""
	if wb != nil && wb.Radio != nil {
		if r.Channel == 0 {
			r.Channel = atoiLenient(string(wb.Radio.Channel)) // "auto" gives 0
		}
		htmode = strings.ToUpper(wb.Radio.HTMode)
	}
	if r.Channel == 0 && wb != nil && wb.Backhaul != nil {
		r.Channel = int(wb.Backhaul.Channel) // the backhaul shares the band's radio (INFERRED)
	}
	r.Width = widthOf(htmode)
	if r.Width == 0 {
		r.Width = 20
		if band == "na" {
			r.Width = 80
		}
	}
	// The X20 is 802.11ax; an explicit HT/VHT htmode says otherwise.
	r.HE = htmode == "" || strings.HasPrefix(htmode, "HE") || strings.HasPrefix(htmode, "EHT")
	r.VHT = band == "na" && (r.HE || strings.HasPrefix(htmode, "VHT"))
	if wb == nil {
		return r
	}
	if h := wb.Host; h != nil && on(h.Enable) {
		r.VAPs = append(r.VAPs, c.vap0(r, "main", b64s(h.SSID), deref(h.EncryptionMode)))
	}
	if g := wb.Guest; g != nil && on(g.Enable) {
		r.VAPs = append(r.VAPs, c.vap0(r, "guest", b64s(g.SSID), deref(g.EncryptionMode)))
	}
	return r
}

// vap0 builds an empty VAP. Iface is "main" or "guest"; the inform names VAPs
// from the controller's devnames, not from this.
func (c *Collector) vap0(r openwrt.Radio, kind, ssid, enc string) openwrt.Radio {
	return openwrt.Radio{
		Iface: kind, Phy: r.Phy, Mode: "Master", Band: r.Band, SSID: ssid,
		BSSID: SyntheticBSSID(c.mac, r.Band, kind == "guest"), Channel: r.Channel, Width: r.Width,
		TxPower: r.TxPower, Noise: r.Noise, Encryption: enc, Stats: zeroStats(),
	}
}

// vapFor returns the index of the VAP for a station, adding one when the
// client list shows a station on a VAP the wireless info did not (stale
// 0x4009, or wireless info not read yet).
func (c *Collector) vapFor(r *openwrt.Radio, guest bool, wb *WirelessBand) int {
	kind := "main"
	if guest {
		kind = "guest"
	}
	for i, v := range r.VAPs {
		if v.Iface == kind {
			return i
		}
	}
	ssid := ""
	if wb != nil {
		if guest && wb.Guest != nil {
			ssid = b64s(wb.Guest.SSID)
		} else if !guest && wb.Host != nil {
			ssid = b64s(wb.Host.SSID)
		}
	}
	r.VAPs = append(r.VAPs, c.vap0(*r, kind, ssid, ""))
	return len(r.VAPs) - 1
}

func vapKey(band, kind string) string { return band + "|" + kind }

// SyntheticBSSID makes a VAP BSSID from the unit MAC: the locally
// administered bit set, bytes 1-4 kept (so UniFi's parentDevice match on
// bytes 1-4 still finds the unit, unifi.go:566-582), and the last byte
// varied per radio and VAP. The Deco exposes no real BSSIDs (P§8.7).
func SyntheticBSSID(unitMAC, band string, guest bool) string {
	n := NormMAC(unitMAC)
	if n == "" {
		return ""
	}
	var b [6]byte
	for i := range b {
		v, _ := strconv.ParseUint(n[i*3:i*3+2], 16, 8)
		b[i] = byte(v)
	}
	b[0] |= 0x02
	off := byte(1)
	if band == "na" {
		off = 2
	}
	if guest {
		off += 2
	}
	b[5] += off
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// ---- stations ----

type assigned struct {
	openwrt.Station
	band  string // ng | na
	guest bool
}

// assign picks the clients connected to this unit now (LiveClients: present
// in a fresh 0x4014/0x4040/0x4012 list and placed on this unit by a
// linked_device_info): wireless ones become stations, wired ones are
// returned by MAC; arp holds every one of them with an IP.
func (c *Collector) assign(s *MeshState, dev *Deco, now time.Time) (st []assigned, wired []string, arp map[string]string) {
	arp = map[string]string{}
	if dev.DeviceID == "" || !Fresh(s, &s.Devices, now, c.opts.MaxAge) {
		return nil, nil, arp
	}
	lv := LiveClients(s, now, c.opts.MaxAge)
	if lv == nil {
		return nil, nil, arp // never a frozen client list
	}
	for _, cl := range lv.Clients {
		ld, mac := cl.Linked, cl.MAC
		if ld == nil || cl.DeviceID != dev.DeviceID {
			continue // another unit's, or unplaced
		}
		key := cl.Link
		band := linkBand(key)
		switch band {
		case "ng", "na":
		case "wired":
			wired = append(wired, mac)
		default:
			continue // band6, zigbee, unknown: no radio to show it on
		}
		if cl.IP != "" {
			arp[mac] = cl.IP
		}
		if band == "wired" {
			continue
		}
		x := assigned{band: band, guest: strings.EqualFold(cl.Interface, "guest")}
		x.MAC = mac
		x.Noise = noiseFloor
		x.Signal = signalOf(ld, key)
		x.SignalAvg = x.Signal
		if v, ok := lookup(ld.TxRateList, key); ok && v > 0 {
			x.TxRate = int(v) * 1000 // Mbps -> kbit/s (INFERRED)
		}
		if v, ok := lookup(ld.RxRateList, key); ok && v > 0 {
			x.RxRate = int(v) * 1000
		}
		x.Connected = connectedFor(cl.OnlineTime, cl.AccessTime, now)
		x.Authorized = true
		x.HT, x.VHT, x.HE = wifiGen(ld.WirelessVer, band)
		x.MHz = widthOf(strings.ToUpper(string(ld.Bandwidth)))
		st = append(st, x)
	}
	sort.Strings(wired)
	return st, wired, arp
}

// integrate adds the latest 0x4014 sample, once per sample, to the byte
// counters of this unit's clients, VAPs and uplink.
func (c *Collector) integrate(s *MeshState, st []assigned, wired []string, now time.Time) {
	for _, x := range st {
		c.counter(c.sta, x.MAC, now)
		c.counter(c.vap, vapKey(x.band, kindOf(x.guest)), now)
	}
	for _, mac := range wired {
		c.counter(c.sta, mac, now)
	}
	for k, cnt := range c.sta {
		if now.Sub(cnt.seen) > counterExpiry {
			delete(c.sta, k)
		}
	}
	at := s.Speeds.At
	if s.Speeds.Value == nil || !at.After(c.lastSpeedAt) {
		return
	}
	prev := c.lastSpeedAt
	c.lastSpeedAt = at
	if prev.IsZero() {
		return // first sample: no interval yet
	}
	dt := min(at.Sub(prev), c.opts.MaxGap)
	speed := map[string]ClientSpeed{}
	for _, sp := range s.Speeds.Value.ClientListSpeed {
		speed[NormMAC(sp.MAC)] = sp
	}
	for _, x := range st {
		sp, ok := speed[x.MAC]
		if !ok {
			continue
		}
		up, down := int64(sp.UpSpeed), int64(sp.DownSpeed)
		c.sta[x.MAC].add(up, down, dt)
		c.vap[vapKey(x.band, kindOf(x.guest))].add(up, down, dt)
		c.port.add(down, up, dt) // uplink rx = clients' downloads
	}
	for _, mac := range wired {
		if sp, ok := speed[mac]; ok {
			c.sta[mac].add(int64(sp.UpSpeed), int64(sp.DownSpeed), dt)
			c.port.add(int64(sp.DownSpeed), int64(sp.UpSpeed), dt)
		}
	}
}

func (c *Collector) counter(m map[string]*counter, k string, now time.Time) {
	if m[k] == nil {
		m[k] = &counter{}
	}
	m[k].seen = now
}

func kindOf(guest bool) string {
	if guest {
		return "guest"
	}
	return "main"
}

// connKey is the client's link key: its first connection_type, lowercase.
func connKey(ct []Enum) string {
	if len(ct) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(string(ct[0])))
}

// linkBand maps a link key to a UniFi radio band: ng, na, wired, or "" for
// links with no radio here (6 GHz, zigbee, bluetooth, unknown). A combo key
// (band2+band5) uses its first part.
func linkBand(key string) string {
	first, _, _ := strings.Cut(key, "+")
	switch first {
	case "band2_4", "band2":
		return "ng"
	case "band5", "band5_1", "band5_2":
		return "na"
	case "wired", "plc":
		return "wired"
	}
	return ""
}

// lookup reads a per-link map by the full key, then its first part, then
// the only entry.
func lookup(m ClientSignalLevel, key string) (int64, bool) {
	if len(m) == 0 {
		return 0, false
	}
	first, _, _ := strings.Cut(key, "+")
	for _, k := range []string{key, first} {
		for mk, v := range m {
			if strings.EqualFold(mk, k) {
				return int64(v), true
			}
		}
	}
	if len(m) == 1 {
		for _, v := range m {
			return int64(v), true
		}
	}
	return 0, false
}

// signalOf: signal_strength when negative (dBm, INFERRED), else bars from
// signal_level, else defaultSignal. Never 0.
func signalOf(ld *LinkedDevice, key string) int {
	if v, ok := lookup(ld.SignalStrength, key); ok && v < 0 && v > -120 {
		return int(v)
	}
	if v, ok := lookup(ld.SignalLevel, key); ok && v > 0 {
		switch {
		case v >= 4:
			return -50
		case v == 3:
			return -60
		case v == 2:
			return -70
		default:
			return -80
		}
	}
	return defaultSignal
}

// connectedFor: online_time (s), else now - access_time (unix s; ms if
// it is too large to be seconds). INFERRED units.
func connectedFor(onlineTime, accessTime *FlexInt, now time.Time) int64 {
	if onlineTime != nil && *onlineTime > 0 {
		return int64(*onlineTime)
	}
	if accessTime != nil && *accessTime > 0 {
		t := int64(*accessTime)
		if t > 1e12 {
			t /= 1000
		}
		if d := now.Unix() - t; d > 0 {
			return d
		}
	}
	return 0
}

// wifiGen reads linked_device_info.wireless_ver ("wifi6", "ax", "11ac", ...).
func wifiGen(ver, band string) (ht, vht, he bool) {
	v := strings.ToLower(ver)
	switch {
	case strings.Contains(v, "be") || strings.Contains(v, "7"),
		strings.Contains(v, "ax") || strings.Contains(v, "6"):
		return true, band == "na", true
	case strings.Contains(v, "ac") || strings.Contains(v, "5"):
		return true, band == "na", false
	}
	return true, false, false
}

// widthOf reads the channel width from an htmode or bandwidth string
// (HE80, VHT40, 80MHz, 160); 0 when it names no valid width.
func widthOf(s string) int {
	digits := strings.TrimLeftFunc(strings.TrimSuffix(strings.ToUpper(s), "MHZ"), func(r rune) bool { return r < '0' || r > '9' })
	switch w := atoiLenient(digits); w {
	case 20, 40, 80, 160, 320:
		return w
	}
	return 0
}

// ---- ports ----

// ports builds eth0 (the uplink) and the other Ethernet ports from 0x4327,
// and the FDB rows that list wired clients on the first LAN port.
func (c *Collector) ports(s *MeshState, dev *Deco, wired []string) ([]openwrt.Port, []openwrt.FDBEntry) {
	type pinfo struct {
		speed      int
		up, uplink bool
	}
	var infos []pinfo
	if s.Ports.Value != nil {
		for _, d := range s.Ports.Value.DeviceList {
			if d.DeviceID != dev.DeviceID {
				continue
			}
			pi := d.PortInfo
			sort.SliceStable(pi, func(a, b int) bool { return pi[a].Port < pi[b].Port })
			for _, p := range pi {
				x := pinfo{}
				for _, st := range p.PortsStatusInfo {
					if !strings.EqualFold(st.Status, "unplugged") {
						x.up = true
					}
					if strings.EqualFold(st.Type, "wan") || strings.EqualFold(st.Type, "eth_bkhl") {
						x.uplink = true
					}
				}
				if p.PortSpeed != nil && *p.PortSpeed > 0 {
					x.speed = int(*p.PortSpeed) // INFERRED Mbps
				}
				infos = append(infos, x)
			}
		}
	}
	// The uplink: a wan/backhaul port that is up, else the first port up.
	up := -1
	for i, x := range infos {
		if x.up && x.uplink {
			up = i
			break
		}
	}
	for i, x := range infos {
		if up < 0 && x.up {
			up = i
		}
	}
	eth0 := openwrt.Port{Name: "eth0", MAC: c.mac, Up: true, Speed: defaultPortMbs, FullDuplex: true, BridgePort: 1,
		RxBytes: c.port.rx, TxBytes: c.port.tx}
	if up >= 0 && infos[up].speed > 0 {
		eth0.Speed = infos[up].speed
	}
	ports := []openwrt.Port{eth0}
	for i, x := range infos {
		if i == up || up < 0 && i == 0 {
			continue // eth0 stands for it
		}
		p := openwrt.Port{Name: fmt.Sprintf("eth%d", len(ports)), MAC: c.mac, Up: x.up, FullDuplex: x.up,
			BridgePort: len(ports) + 1}
		if x.up {
			p.Speed = defaultPortMbs
			if x.speed > 0 {
				p.Speed = x.speed
			}
		}
		ports = append(ports, p)
	}
	if len(wired) == 0 || c.opts.HideWired {
		return ports, nil
	}
	lan := -1
	for i := 1; i < len(ports); i++ {
		if ports[i].Up {
			lan = i
			break
		}
	}
	if lan < 0 && len(ports) > 1 {
		lan = 1
	}
	if lan < 0 {
		ports = append(ports, openwrt.Port{Name: "eth1", MAC: c.mac, Up: true, Speed: defaultPortMbs, FullDuplex: true, BridgePort: 2})
		lan = 1
	}
	var fdb []openwrt.FDBEntry
	for _, mac := range wired {
		fdb = append(fdb, openwrt.FDBEntry{MAC: mac, Port: ports[lan].BridgePort})
	}
	return ports, fdb
}

func parentOf(s *MeshState, dev *Deco) *Deco {
	if dev.ParentDeviceID == "" || dev.ParentDeviceID == dev.DeviceID {
		return nil
	}
	for _, d := range s.Devices.Value.DeviceList {
		if d.DeviceID == dev.ParentDeviceID {
			c := d
			return &c
		}
	}
	return nil
}

// ---- small helpers ----

func zeroStats() map[string]int64 {
	return map[string]int64{"rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0,
		"rx_errors": 0, "tx_errors": 0, "rx_dropped": 0, "tx_dropped": 0}
}

func atoiLenient(s string) int {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	n, _ := strconv.Atoi(s[:end])
	return n
}

func on(b *bool) bool { return b != nil && *b }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
func b64s(b *B64) string {
	if b == nil {
		return ""
	}
	return string(*b)
}
