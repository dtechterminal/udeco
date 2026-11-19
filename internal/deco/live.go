// SPDX-License-Identifier: GPL-2.0-or-later

package deco

// live.go builds the view of the clients that are connected right now from
// the Mesh cache. Nothing here does I/O.
//
// The app has one client list, 0x4012 CLIENT_LIST_GET, and reads online,
// ip and linked_device_info (the access Deco, band, signal) from it
// (tpm5/component/network/client/repository/l0.java:929-936; ClientBean.java:19-96).
// No other opcode lists Wi-Fi or wired clients: the p.java name map has only
// CLIENT_LIST_GET/SET/SPEED_GET/CLIENT_SPEED_GET/BLOCK/REMOVE and the IOT,
// IPV6, MAC_CLONE and LEASE variants (mesh/global/p.java:1313-1481), and
// client_mesh / client_link / client_device are per-client settings on the
// same ClientBean (mesh/context/c.java:337,864-866,906-907,958-959).
//
// Live, on fw 1.3.0 in AP mode, 0x4012 took 62 s and returned only the
// stored per-client settings (all online:false, no ip, no
// linked_device_info). So presence comes from the fast lists that only
// carry clients connected now:
//   - 0x4014 CLIENT_LIST_SPEED_GET: every online client's MAC and speed
//     (l0.java:908-915; joined to the client list by MAC, nr/b.java:147-160);
//   - 0x4040 IOT_CLIENT_LIST_GET: smart-home devices with inet_status and
//     their own linked_device_info (device/viewmodel/l4.java:1550-1560);
//   - 0x4012 entries with online:true, when that reply is itself fresh.
// The access Deco and band come from linked_device_info: of the 0x4040
// entry, else of the session's last 0x4012 entry (it may be as old as the
// 0x4012 interval). An entry with online:true is placed "clients"; the live
// settings-only reply also carried linked_device_info on 10 of 192 entries
// that said online:false, the last known access Deco and band, which place a
// client 0x4014 shows present as "clients_last" (INFERRED: it may predate a
// roam). A present client with neither is "unplaced": the app shows such a
// client on the master (b2.java:2679-2681), but nothing says which radio it
// is on, so Collect does not report it.

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// Presence and placement sources.
const (
	SrcSpeeds  = "speeds"  // 0x4014
	SrcIoT     = "iot"     // 0x4040
	SrcClients = "clients" // 0x4012
	// SrcClientsLast places by the linked_device_info of a 0x4012 entry that
	// said online:false: the last known access Deco and band.
	SrcClientsLast = "clients_last"
)

// LiveClient is one client connected now.
type LiveClient struct {
	MAC        string   `json:"mac"` // NormMAC
	IP         string   `json:"ip,omitempty"`
	Name       string   `json:"name,omitempty"`
	ClientType string   `json:"client_type,omitempty"`
	Interface  string   `json:"interface,omitempty"` // main|guest|iot|mlo; "" unknown
	Seen       []string `json:"seen"`                // presence sources
	DeviceID   string   `json:"device_id,omitempty"` // access Deco; "" = unplaced
	Link       string   `json:"link,omitempty"`      // connection_type[0], lowercase
	PlacedBy   string   `json:"placed_by,omitempty"` // iot | clients | clients_last

	Linked     *LinkedDevice `json:"-"`
	OnlineTime *FlexInt      `json:"-"`
	AccessTime *FlexInt      `json:"-"`
}

// LiveView is every client connected now, sorted by MAC.
type LiveView struct {
	Sources  []string     `json:"sources"` // the presence lists fresh at the time
	Placed   int          `json:"placed"`
	Unplaced int          `json:"unplaced"`
	Clients  []LiveClient `json:"clients"`
}

// LiveClients returns the clients connected at now, or nil when no
// presence list (0x4014, 0x4040, 0x4012) is Fresh within maxAge: then
// nothing is known about who is connected and nothing is reported, never a
// frozen list. The units' own MACs are left out, as the app does (l0.java:872-884).
func LiveClients(s *MeshState, now time.Time, maxAge time.Duration) *LiveView {
	if s == nil {
		return nil
	}
	speeds := Fresh(s, &s.Speeds, now, maxAge)
	iot := Fresh(s, &s.IoT, now, maxAge)
	clients := Fresh(s, &s.Clients, now, maxAge)
	if !speeds && !iot && !clients {
		return nil
	}
	var decos []uint64
	if s.Devices.Value != nil {
		for _, d := range s.Devices.Value.DeviceList {
			if v, ok := macValue(d.MAC); ok {
				decos = append(decos, v)
			}
		}
	}
	lv := &LiveView{}
	by := map[string]*LiveClient{}
	see := func(raw, src string) *LiveClient {
		mac := NormMAC(raw)
		if mac == "" || isDecoMAC(mac, decos) {
			return nil
		}
		c := by[mac]
		if c == nil {
			c = &LiveClient{MAC: mac}
			by[mac] = c
		}
		for _, x := range c.Seen {
			if x == src {
				return c
			}
		}
		c.Seen = append(c.Seen, src)
		return c
	}
	if speeds {
		lv.Sources = append(lv.Sources, SrcSpeeds)
		for _, sp := range s.Speeds.Value.ClientListSpeed {
			see(sp.MAC, SrcSpeeds)
		}
	}
	if iot {
		lv.Sources = append(lv.Sources, SrcIoT)
		for _, d := range s.IoT.Value.IoTClientList {
			if !d.IsOnline() {
				continue
			}
			c := see(d.DetailMAC(), SrcIoT)
			if c == nil {
				continue // no MAC: nothing UniFi could show
			}
			fill(&c.IP, d.DetailIP())
			fill(&c.Name, string(d.Name))
			fill(&c.Interface, string(d.Interface))
			c.place(d.LinkedDeviceInfo, SrcIoT, d.OnlineTime, d.AccessTime)
		}
	}
	if clients {
		lv.Sources = append(lv.Sources, SrcClients)
		for _, cl := range s.Clients.Value.ClientList {
			if cl.IsOnline() {
				see(cl.MAC, SrcClients)
			}
		}
	}
	// Enrichment: the session's last 0x4012 reply, whatever its age, names
	// the present clients and places them: by the entries it saw online,
	// else by the last known linked_device_info.
	if Fresh(s, &s.Clients, now, 0) {
		for _, cl := range s.Clients.Value.ClientList {
			c := by[NormMAC(cl.MAC)]
			if c == nil {
				continue
			}
			fill(&c.IP, cl.IP)
			fill(&c.Name, string(cl.Name))
			ct := cl.ClientType
			if cl.CustomClientType != "" {
				ct = cl.CustomClientType // client_fing (l0.java:717-722)
			}
			fill(&c.ClientType, ct)
			fill(&c.Interface, cl.Interface)
			src := SrcClientsLast
			if cl.IsOnline() {
				src = SrcClients
			}
			c.place(cl.LinkedDeviceInfo, src, cl.OnlineTime, cl.AccessTime)
		}
	}
	for _, c := range by {
		if c.DeviceID != "" {
			lv.Placed++
		} else {
			lv.Unplaced++
		}
		lv.Clients = append(lv.Clients, *c)
	}
	sort.Slice(lv.Clients, func(a, b int) bool { return lv.Clients[a].MAC < lv.Clients[b].MAC })
	return lv
}

// place takes the first linked_device_info that names a Deco.
func (c *LiveClient) place(ld *LinkedDevice, src string, online, access *FlexInt) {
	if c.DeviceID != "" || ld == nil || ld.DeviceID == "" {
		return
	}
	c.DeviceID, c.Link, c.PlacedBy, c.Linked = ld.DeviceID, connKey(ld.ConnectionType), src, ld
	c.OnlineTime, c.AccessTime = online, access
}

func fill(dst *string, v string) {
	if *dst == "" {
		*dst = strings.TrimSpace(v)
	}
}

// macValue parses a MAC in any separator/case into its 48-bit value.
func macValue(s string) (uint64, bool) {
	n := NormMAC(s)
	if n == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.ReplaceAll(n, ":", ""), 16, 64)
	return v, err == nil
}

// isDecoMAC is the app's t1/i0 test (l0.java:622-633, 872-884, E1 :234-256):
// the MAC of a unit, or a MAC that matches the unit MAC + 2 in every hex
// digit but the second (a locally administered variant the Deco uses).
func isDecoMAC(mac string, decos []uint64) bool {
	v, ok := macValue(mac)
	if !ok {
		return false
	}
	const mask = 1<<48 - 1
	const second = 0x0f << 40 // the second hex digit
	for _, d := range decos {
		if v == d || v&^second == ((d+2)&mask)&^second {
			return true
		}
	}
	return false
}
