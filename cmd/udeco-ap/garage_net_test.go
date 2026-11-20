// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/mtkwifi"
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
}

type radarWifi struct {
	wifiApplier
	ev []mtkwifi.RadarEvent
}

func (r *radarWifi) TakeRadar() []mtkwifi.RadarEvent { ev := r.ev; r.ev = nil; return ev }

// TestGarageRadar: a radar detection the applier saw goes to the
// controller as EVT_AP_RadarDetected (a custom alert, as a U6's).
func TestGarageRadar(t *testing.T) {
	a := &agent{cfg: &Config{Platform: "jio-mtk", Takeover: true, DFS: true}}
	a.takeover.Store(true)
	a.wifi = &radarWifi{ev: []mtkwifi.RadarEvent{{Channel: 52, MovedTo: 149, Freq: 5260}}}
	root := t.TempDir()
	a.events = &eventLog{path: filepath.Join(root, "events.log"), root: root, clock: time.Now, logf: func(string, ...any) {}}
	a.garageReading(context.Background(), &apstate.Snapshot{})
	if len(a.sta.queue) != 1 {
		t.Fatalf("queue %v", a.sta.queue)
	}
	e := a.sta.queue[0]
	if e["event_string"] != "EVT_AP_RadarDetected" || e["radio"] != "na" || e["channel"] != 52 || e["freq"] != 5260 {
		t.Errorf("event %v", e)
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
