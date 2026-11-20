// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/rf"
)

// A peer AP as .205's 5 GHz scan printed .241 (2026-11-19), and a foreign
// network the lists must not name.
const scanPeer = `SSID: "Example Network"
Mode: Managed	RSSI: -80 dBm	SNR: 14 dB	noise: -94 dBm	Flags: FromBcn RSSI on-channel 	Channel: 149/80
BSSID: AE:A7:B9:3E:16:91	Capability: ESS WEP RRM 
Supported Rates: [ 6(b) 9 12(b) 18 24(b) 36 48 54 ]
RSN (WPA2 + WPA3-SAE):
	multicast cipher: AES-CCMP
	unicast ciphers(1): AES-CCMP 
	AKM Suites(3): WPA2-PSK FT-PSK WPA2-PSK SAE 
	Capabilities(0x008c): No Pre-Auth, Pairwise, 16 PTK Replay Ctrs1 GTK Replay Ctr, MFP: Capable
Extended Capabilities: BSS_Transition
HE Capable:
	Chanspec: 5GHz channel 155 80MHz (0xe09b)
	Primary channel: 149

SSID: "Someone Else"
Mode: Managed	RSSI: -70 dBm	SNR: 20 dB	noise: -94 dBm	Flags: FromBcn RSSI on-channel 	Channel: 36/80
BSSID: 11:22:33:44:55:66	Capability: ESS WEP 
`

func TestNeighborListsFromScans(t *testing.T) {
	ctx := context.Background()
	d := twoSSIDs()
	d.SSIDs[1].RRM = true // "Example Network": wl02 + wl12
	f, a := appliedUnit(t, d)
	now := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	tick := func() TickReport {
		t.Helper()
		r, err := a.Tick(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range r.Problems {
			t.Errorf("tick problem: %s", p)
		}
		return r
	}
	list := func(vif string) string { return f.state[vif+" nbr"] }
	own02, _ := a.bssid(ctx, "wl02")
	own12, _ := a.bssid(ctx, "wl12")

	// First tick: scans start, and each band lists the unit's other band.
	r := tick()
	if f.state["wl0 scans"] == "" || f.state["wl1 scans"] == "" {
		t.Fatal("no scan started")
	}
	if !strings.Contains(list("wl12"), strings.ToUpper(own02)) || !strings.Contains(list("wl02"), strings.ToUpper(own12)) {
		t.Errorf("own other-band BSS not listed: wl02=%q wl12=%q", list("wl02"), list("wl12"))
	}
	if strings.Contains(list("wl12"), strings.ToUpper(own12)) {
		t.Error("a BSS lists itself")
	}
	if list("wl03") != "" {
		t.Error("a non-RRM SSID got a list")
	}
	if r.NeighborChanges != 2 {
		t.Errorf("changes = %d, want 2", r.NeighborChanges)
	}

	// The results are read once the scan had time: the peer, on both bands.
	f.state["wl1 scanresults"] = scanPeer
	now = now.Add(10 * time.Second)
	tick()
	want := "bssid AE:A7:B9:3E:16:91 bssid_info 0x00005ebf reg 0x7c channel 0x95 phytype 0x0e"
	for _, v := range []string{"wl02", "wl12"} {
		if !strings.Contains(list(v), want) {
			t.Errorf("%s list lacks the peer %q:\n%s", v, want, list(v))
		}
		if strings.Contains(list(v), "11:22:33:44:55:66") {
			t.Errorf("%s lists a foreign SSID", v)
		}
	}
	if r := tick(); r.NeighborChanges != 0 || strings.Count(f.state["wl1 scans"], "x") != 1 {
		t.Errorf("steady tick changed %d entries / rescanned", r.NeighborChanges)
	}

	// A hostapd restart empties the lists: the next tick refills them.
	f.state["wl12 nbr"] = ""
	if r := tick(); r.NeighborChanges != 2 {
		t.Errorf("refill changed %d, want 2", r.NeighborChanges)
	}

	// Rescans every 30 min; a peer missing from them is kept for 90 min.
	f.state["wl1 scanresults"] = ""
	for i := 0; i < 3; i++ {
		now = now.Add(31 * time.Minute)
		tick()
		now = now.Add(10 * time.Second)
		tick()
		gone := !strings.Contains(list("wl12"), "AE:A7:B9:3E:16:91")
		if i < 2 && gone {
			t.Fatalf("peer dropped after %d missed scan(s)", i+1)
		}
		if i == 2 && !gone {
			t.Errorf("peer kept after 3 missed scans:\n%s", list("wl12"))
		}
	}
	if !strings.Contains(list("wl12"), strings.ToUpper(own02)) {
		t.Error("own other-band entry dropped with the peer")
	}
}

// Every neighbour report and BTM candidate list carries rf.OpClass's
// operating class: the 802.11k list's entries (entryFor) and the 802.11v
// requests' candidates (neighborInfo: SteerToBand, Roam), for every
// channel of both bands.
func TestOpClassIsRF(t *testing.T) {
	for _, band := range []string{rf.Band2G, rf.Band5G} {
		for ch := 1; ch <= 196; ch++ {
			want := rf.OpClass(band, ch)
			if _, got, _ := neighborInfo(band, ch); got != want {
				t.Errorf("neighborInfo(%s, %d) class %d, want %d", band, ch, got, want)
			}
			if rf.ChanBand(ch) != band {
				continue
			}
			if got := entryFor(nbrBSS{BSSID: "02:00:00:00:00:01", Channel: ch}, false).Reg; got != want {
				t.Errorf("entryFor channel %d class %d, want %d", ch, got, want)
			}
		}
	}
}
