// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/stasnoop"
)

// The downlink watchdog. Seen on the Garage 2026-11-20 (the pump, a Tuya
// plug FC:3C:D7:31:00:CD on ra1, and already ~2 a day under the stock Jio
// firmware): the MT7603 holds a station as dozing (stainfo PSM 1) and
// queues its unicast frames, and the station never fetches them. Its own
// frames keep arriving (its broadcasts every 5 s, the AP's RxPackets
// growing) and broadcasts still reach it at the DTIM, but nothing addressed
// to it does, until it gives up and re-associates by itself ~300 s later.
// The driver's TxPackets is no witness (it kept growing through the
// stall), so the agent tests delivery end to end: every stuckProbeEvery
// each station of an untagged 2.4 GHz BSS (the radio whose station counters
// are read) is sent a unicast ARP request for its
// own address from the unit's bridge (the unit's MAC and IPv4 there: a
// station answers that, verified on the pump; from the BSS netdev itself,
// or from 0.0.0.0, it got no answer), and its reply to that address is seen
// on its BSS (arpTable.replies: the station's other ARP does not count). A probe unanswered by the next reading counts as a
// miss and is sent again. A station that answered a probe in this
// association, then misses stuckMisses in a row over at least stuckAfter
// while the driver reads it dozing and (where the driver counts) still
// sending, is sent DisConnectSta: it re-associates in a few seconds instead
// of minutes. Back-off as the minimum RSSI kick (kickBackoff ..
// kickBackoffMax). A station that never answered (no address learnt yet,
// a stack that ignores ARP) is never kicked.
const (
	stuckProbeEvery = 30 * time.Second
	stuckProbeWait  = 2 * time.Second // a reply after this misses the reading
	stuckMisses     = 3
	stuckAfter      = 12 * time.Second
)

// downProber learns the stations' addresses on their BSS netdevs and
// sends the probes (stuckps_linux.go).
type downProber interface {
	// SetVifs sets the BSS netdevs to learn on (empty: close everything)
	SetVifs([]string)
	// Stations sets each netdev's associated stations (lower-case MACs)
	Stations(map[string][]string)
	Neighbor(mac string) (net.IP, bool)
	// Replied is when the station last answered an ARP request from self
	// at ip (zero: never)
	Replied(mac string, self net.HardwareAddr, ip net.IP) time.Time
	// Self is the unit's MAC and IPv4 address on bridge
	Self(bridge string) (net.HardwareAddr, net.IP, bool)
}

type stuckSta struct {
	conn     int64     // Station.Connected at the last reading: lower is a new association
	probed   time.Time // the probe waiting for its reply (zero: none)
	next     time.Time // no probe before
	answered bool      // answered a probe in this association
	misses   int       // probes in a row unanswered
	first    time.Time // the first of them
	rx0      int64     // RxPackets then
	until    time.Time // no kick before
	backoff  time.Duration
}

// KickStuck runs the downlink watchdog on a reading and returns the MACs
// (lower case) it disconnected. Like KickWeak it never waits: while the
// applier changes the radios or a restart settles it does nothing, and
// the probe in flight then is dropped (not a miss).
func (a *Applier) KickStuck(ctx context.Context, s *apstate.Snapshot) []string {
	if s == nil || a.o.DryRun || !a.mu.TryLock() {
		return nil
	}
	defer a.mu.Unlock()
	if a.live == nil || a.uplinkDown {
		return nil
	}
	if a.down == nil {
		a.down = newDownProber(a.o.Logf)
	}
	if a.stuck == nil {
		a.stuck = map[string]*stuckSta{}
	}
	now := s.Time
	if a.settling() {
		for _, p := range a.stuck {
			p.probed = time.Time{}
		}
		return nil
	}
	// the untagged BSSes that are up, of the radios whose station
	// counters are read (the MT7603's: "still sending" needs RxPackets)
	vifs := map[string]bool{}
	for _, rd := range a.o.Layout {
		rp := a.live[rd.Band]
		if counts, _, _ := driverReads(rd); !rp.On || !counts {
			continue
		}
		for i, b := range rp.BSS {
			if v := a.ifaceOf(rd, rp, i); b.VLAN == 0 && a.isUp(v) {
				vifs[v] = true
			}
		}
	}
	var names []string
	for v := range vifs {
		names = append(names, v)
	}
	a.down.SetVifs(names)
	assoc := map[string][]string{}
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			if !vifs[v.Iface] {
				continue
			}
			for _, st := range v.Stations {
				if mac := strings.ToLower(st.MAC); mac != "" {
					assoc[v.Iface] = append(assoc[v.Iface], mac)
				}
			}
		}
	}
	a.down.Stations(assoc)
	self, selfIP, haveSelf := a.down.Self(a.o.Bridge)
	var kicked []string
	seen := map[string]bool{}
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			if !vifs[v.Iface] {
				continue
			}
			for _, st := range v.Stations {
				mac := strings.ToLower(st.MAC)
				if mac == "" {
					continue
				}
				seen[mac] = true
				p := a.stuck[mac]
				if p == nil || st.Connected < p.conn {
					// a new association proves itself again (back-off kept)
					q := &stuckSta{}
					if p != nil {
						q.until, q.backoff = p.until, p.backoff
					}
					p = q
					a.stuck[mac] = p
				}
				p.conn = st.Connected
				if !p.probed.IsZero() && now.Sub(p.probed) >= stuckProbeWait {
					if haveSelf && a.down.Replied(mac, self, selfIP).After(p.probed) {
						p.answered, p.misses = true, 0
						p.next = now.Add(stuckProbeEvery)
					} else if p.answered {
						if p.misses == 0 {
							p.first, p.rx0 = p.probed, st.RxPackets
						}
						p.misses++
						p.next = now
					} else {
						p.next = now.Add(stuckProbeEvery) // not proven: no hurry
					}
					p.probed = time.Time{}
				}
				if p.answered && p.misses >= stuckMisses && now.Sub(p.first) >= stuckAfter &&
					st.PowerSave && st.RxPackets > p.rx0 && !now.Before(p.until) {
					if err := a.run(ctx, "iwpriv", v.Iface, "set", "DisConnectSta="+strings.ToUpper(mac)); err != nil {
						a.o.Logf("mtkwifi: downlink watchdog: disconnecting %s from %s: %v", mac, v.Iface, err)
					} else {
						a.o.Logf("mtkwifi: downlink watchdog: %s on %s dozing, %d ARP probes unanswered over %s while it kept sending: disconnected",
							mac, v.Iface, p.misses, now.Sub(p.first).Round(time.Second))
						switch {
						case p.backoff == 0 || now.After(p.until.Add(kickBackoffMax)):
							p.backoff = kickBackoff
						default:
							p.backoff = min(2*p.backoff, kickBackoffMax)
						}
						p.until = now.Add(p.backoff)
						p.answered, p.misses, p.next = false, 0, now.Add(stuckProbeEvery)
						kicked = append(kicked, mac)
						continue
					}
				}
				if !p.probed.IsZero() || now.Before(p.next) || !haveSelf {
					continue
				}
				ip, ok := a.down.Neighbor(mac)
				if !ok {
					continue
				}
				hw, err := net.ParseMAC(mac)
				if err != nil {
					continue
				}
				sentAt := a.o.wall() // a reply is only one after the probe left
				if err := a.o.sendFrame(a.o.Bridge, stasnoop.ARPFrame(hw, self, 1, selfIP, hw, ip)); err != nil {
					a.o.Logf("mtkwifi: downlink watchdog: probe to %s: %v", mac, err)
					p.next = now.Add(stuckProbeEvery)
					continue
				}
				p.probed = sentAt
			}
		}
	}
	for mac, p := range a.stuck {
		if !seen[mac] && now.After(p.until.Add(kickBackoffMax)) {
			delete(a.stuck, mac)
		}
	}
	return kicked
}

// stopStuck closes the watchdog's sockets (hand-back; a.mu held).
func (a *Applier) stopStuck() {
	if a.down != nil {
		a.down.SetVifs(nil)
	}
	a.stuck = nil
}
