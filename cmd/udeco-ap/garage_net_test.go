// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/device"
	"github.com/dtechterminal/udeco/internal/inform"
	"github.com/dtechterminal/udeco/internal/models"
	"github.com/dtechterminal/udeco/internal/mtkwifi"
	"github.com/dtechterminal/udeco/internal/translate"
)

type netWifi struct {
	wifiApplier
	stations []map[string][]string
	garps    []string
	neigh    map[string]string
}

func (n *netWifi) ProxyARPStations(m map[string][]string) { n.stations = append(n.stations, m) }
func (n *netWifi) Neighbor(mac string) (net.IP, bool) {
	ip, ok := n.neigh[mac]
	return net.ParseIP(ip), ok
}
func (n *netWifi) AnnounceStation(_ context.Context, vif, mac string, ip net.IP) error {
	n.garps = append(n.garps, vif+" "+mac+" "+ip.String())
	return nil
}

func garageSnap(arp map[string]string, vaps map[string][]string) *apstate.Snapshot {
	r := apstate.Radio{Iface: "rai0", Band: "na"}
	for vif, macs := range vaps {
		v := apstate.Radio{Iface: vif, Band: "na"}
		for _, m := range macs {
			v.Stations = append(v.Stations, apstate.Station{MAC: m})
		}
		r.VAPs = append(r.VAPs, v)
	}
	return &apstate.Snapshot{ARP: arp, Radios: []apstate.Radio{r}}
}

// TestGarageStationsGARP: each reading gives the proxy ARP responder the
// associated stations; a station new on a BSS (not the first reading's)
// is announced with a gratuitous ARP when its address is known (the
// unit's ARP table, an address seen before, the responder's); one moving
// BSS is announced again; one without a known address is not.
func TestGarageStationsGARP(t *testing.T) {
	a := &agent{cfg: &Config{Platform: "jio-mtk", Takeover: true}}
	a.takeover.Store(true)
	w := &netWifi{neigh: map[string]string{"aa:bb:cc:dd:ee:03": "192.168.0.83"}}
	a.wifi = w
	ctx := context.Background()
	a.garageReading(ctx, garageSnap(map[string]string{"aa:bb:cc:dd:ee:01": "192.168.0.81"},
		map[string][]string{"rai0": {"AA:BB:CC:DD:EE:01"}}))
	if len(w.stations) != 1 || len(w.stations[0]["rai0"]) != 1 || w.stations[0]["rai0"][0] != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("stations %v", w.stations)
	}
	if len(w.garps) != 0 {
		t.Errorf("first reading announced %v", w.garps)
	}
	// 01 leaves; 02 (no address) and 03 (the responder's) arrive
	a.garageReading(ctx, garageSnap(nil, map[string][]string{"rai0": {"aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"}}))
	if len(w.garps) != 1 || w.garps[0] != "rai0 aa:bb:cc:dd:ee:03 192.168.0.83" {
		t.Errorf("garps %v", w.garps)
	}
	// 01 comes back on rai1: its address from before
	a.garageReading(ctx, garageSnap(nil, map[string][]string{"rai0": {"aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"}, "rai1": {"aa:bb:cc:dd:ee:01"}}))
	if len(w.garps) != 2 || w.garps[1] != "rai1 aa:bb:cc:dd:ee:01 192.168.0.81" {
		t.Errorf("garps %v", w.garps)
	}
}

// TestGarageGARPOptOut: assoc_garp false (the Deco's key) stops the
// Garage's station GARP, the responder still gets the stations; with the
// connection-event taps on, an address they saw on the BSS's bridge is
// announced too.
func TestGarageGARPOptOut(t *testing.T) {
	f := false
	a := &agent{cfg: &Config{Platform: "jio-mtk", Takeover: true, AssocGARP: &f}}
	a.takeover.Store(true)
	w := &netWifi{neigh: map[string]string{"aa:bb:cc:dd:ee:03": "192.168.0.83"}}
	a.wifi = w
	ctx := context.Background()
	a.garageReading(ctx, garageSnap(nil, nil))
	a.garageReading(ctx, garageSnap(nil, map[string][]string{"rai0": {"aa:bb:cc:dd:ee:03"}}))
	if len(w.garps) != 0 || len(w.stations) != 2 || len(w.stations[1]["rai0"]) != 1 {
		t.Errorf("assoc_garp false: garps %v, stations %v", w.garps, w.stations)
	}
	a = &agent{cfg: &Config{Platform: "jio-mtk", Takeover: true}, conn: &connState{t: newConnTracker()}}
	a.takeover.Store(true)
	w = &netWifi{}
	a.wifi = w
	a.conn.t.setIP("aa:bb:cc:dd:ee:04", "192.168.0.84", a.bridgeName("rai0"), time.Now())
	a.garageReading(ctx, garageSnap(nil, nil))
	a.garageReading(ctx, garageSnap(nil, map[string][]string{"rai0": {"aa:bb:cc:dd:ee:04"}}))
	if len(w.garps) != 1 || w.garps[0] != "rai0 aa:bb:cc:dd:ee:04 192.168.0.84" {
		t.Errorf("tap address: garps %v", w.garps)
	}
}

func TestProxyARPConfig(t *testing.T) {
	base := `{"inform_url":"http://192.168.1.1:8080/inform","console_ip":"192.168.1.2","platform":"jio-mtk","model":"U7LT","takeover":true`
	c, err := parseConfig([]byte(base + `}`))
	if err != nil || !c.proxyARP() {
		t.Errorf("jio default: %v", err)
	}
	if c, _ := parseConfig([]byte(base + `,"proxy_arp":false}`)); c.proxyARP() {
		t.Error("proxy_arp false kept it on")
	}
	if _, err := parseConfig([]byte(`{"inform_url":"http://192.168.1.1:8080/inform","console_ip":"192.168.1.2","takeover":true,"proxy_arp":false}`)); err == nil {
		t.Error("Deco accepted proxy_arp")
	}
	// the MT7663 driver flag: off by default, opt-in, needs proxy_arp
	if c.ProxyARPDriver {
		t.Error("proxy_arp_driver on by default")
	}
	if c, err := parseConfig([]byte(base + `,"proxy_arp_driver":true}`)); err != nil || !c.ProxyARPDriver {
		t.Errorf("proxy_arp_driver true: %v", err)
	}
	if _, err := parseConfig([]byte(base + `,"proxy_arp":false,"proxy_arp_driver":true}`)); err == nil {
		t.Error("proxy_arp_driver accepted without proxy_arp")
	}
	if _, err := parseConfig([]byte(`{"inform_url":"http://192.168.1.1:8080/inform","console_ip":"192.168.1.2","takeover":true,"proxy_arp_driver":true}`)); err == nil {
		t.Error("Deco accepted proxy_arp_driver")
	}
}

type radarWifi struct {
	wifiApplier
	ev []mtkwifi.RadarEvent
}

func (r *radarWifi) TakeRadar() []mtkwifi.RadarEvent { ev := r.ev; r.ev = nil; return ev }

// radioSession is a session whose radio rows are named as setup names
// them (renameRadios) for the naming given.
func radioSession(naming string) *device.Session {
	return &device.Session{S: device.State{RadioNames: naming}, Dev: inform.Device{Radios: []inform.Radio{
		{Name: translate.PositionalRadioName(0), Radio: "ng"}, {Name: translate.PositionalRadioName(1), Radio: "na"}}}}
}

// radioTableName is the name the inform's radio_table reports band's
// radio under.
func radioTableName(t *testing.T, a *agent, band string) string {
	t.Helper()
	for _, r := range a.x.Dev.Radios {
		if r.Radio == band {
			return r.Name
		}
	}
	t.Fatalf("no %s radio in %+v", band, a.x.Dev.Radios)
	return ""
}

// TestGarageRadar: a radar detection the applier saw goes to the
// controller as EVT_AP_RadarDetected (a custom alert, as a U6's), naming
// the 5 GHz radio as the inform's radio_table does (rai0 with MediaTek
// naming, wifi1 kept for an earlier adoption).
func TestGarageRadar(t *testing.T) {
	for _, tc := range []struct{ naming, name string }{
		{radioNamesMediaTek, models.RadioNameMTK5G},
		{radioNamesQualcomm, translate.PositionalRadioName(1)},
	} {
		a := &agent{cfg: &Config{Platform: "jio-mtk", Takeover: true, DFS: true}}
		a.takeover.Store(true)
		a.x = radioSession(tc.naming)
		a.renameRadios()
		a.wifi = &radarWifi{ev: []mtkwifi.RadarEvent{{Channel: 52, MovedTo: 149, Freq: 5260}}}
		root := t.TempDir()
		a.events = &eventLog{path: filepath.Join(root, "events.log"), root: root, clock: time.Now, logf: func(string, ...any) {}}
		a.garageReading(context.Background(), &apstate.Snapshot{})
		if len(a.sta.queue) != 1 {
			t.Fatalf("%s: queue %v", tc.naming, a.sta.queue)
		}
		if n := radioTableName(t, a, "na"); n != tc.name {
			t.Fatalf("%s: radio_table names the 5 GHz radio %s, want %s", tc.naming, n, tc.name)
		}
		// the whole payload as it goes on the wire
		want := map[string]any{"event_string": "EVT_AP_RadarDetected", "radio": "na", "radio_name": radioTableName(t, a, "na"), "channel": 52, "freq": 5260}
		if e := a.sta.queue[0]; !reflect.DeepEqual(e, want) {
			t.Errorf("%s: payload %v, want %v", tc.naming, e, want)
		}
	}
}

// rate_limits: jio-mtk only, off by default, reaching mtkwifi.
func TestRateLimitsConfig(t *testing.T) {
	base := `{"inform_url":"http://192.168.1.1:8080/inform","console_ip":"192.168.1.2","platform":"jio-mtk","model":"U7LT","takeover":true`
	if c, err := parseConfig([]byte(base + `}`)); err != nil || c.RateLimits {
		t.Errorf("default: on=%v, %v", c.RateLimits, err)
	}
	if c, err := parseConfig([]byte(base + `,"rate_limits":true}`)); err != nil || !c.RateLimits {
		t.Errorf("jio: %v", err)
	}
	if _, err := parseConfig([]byte(`{"inform_url":"http://192.168.1.1:8080/inform","console_ip":"192.168.1.2","takeover":true,"rate_limits":true}`)); err == nil {
		t.Error("Deco accepted rate_limits")
	}
}

func TestDFSConfig(t *testing.T) {
	base := `{"inform_url":"http://192.168.1.1:8080/inform","console_ip":"192.168.1.2","platform":"jio-mtk","model":"U7LT","takeover":true`
	if c, err := parseConfig([]byte(base + `,"dfs":true}`)); err != nil || !c.DFS {
		t.Errorf("jio: %v", err)
	}
	if _, err := parseConfig([]byte(`{"inform_url":"http://192.168.1.1:8080/inform","console_ip":"192.168.1.2","takeover":true,"dfs":true}`)); err == nil {
		t.Error("Deco accepted dfs")
	}
}
