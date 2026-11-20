// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dtechterminal/udeco/internal/rf"
)

// 802.11k neighbor lists.
//
// With wl rrm 0x33 (SSID.RRM) the driver answers a station's Neighbor
// Report Request from the BSS's own list (wl rrm_nbr_list), and nothing
// fills that list: TP-Link's nrd did, and the agent stops it. Seen on all
// three X20s on 2026-11-19: every list was empty, and a scan alone does not
// fill it (rrm_nbr_scan 1 notwithstanding). A station asking which APs are
// around was told none, so it scanned every channel before a roam.
//
// Tick now keeps each RRM BSS's list: the other APs' BSSes of the same SSID
// (from an active scan of each radio every nbrScanEvery, and again when the
// layout changes; one scan on .241's busy 2.4 GHz radio cost no ping and no
// station) plus this unit's own BSS of the SSID on the other band. A BSS is
// kept until it has been missing from the scans for nbrKeep, so one missed
// beacon does not take a far AP off the list. The scan is started by one
// Tick and read by a later one: a.mu is never held while it runs. Lists
// are changed by difference (rrm_nbr_add_nbr / rrm_nbr_del_nbr), which
// leaves associated stations alone; a hostapd restart empties them and the
// next Tick refills them.

const (
	nbrScanEvery = 30 * time.Minute
	nbrScanWait  = 8 * time.Second // results are read at the first Tick after this
	nbrKeep      = 3 * nbrScanEvery
	nbrMax       = 16 // entries per BSS
)

// nbrBSS is a BSS a neighbor list may name.
type nbrBSS struct {
	BSSID   string // upper case, as wl prints it
	SSID    string
	Channel int // primary channel
	HE      bool
	FT      bool // advertises an FT AKM (same SSID: same mobility domain)
	Seen    time.Time
}

// nbrState is the scan bookkeeping (a.mu held).
type nbrState struct {
	scanAt   time.Time // a scan is running since; zero = none
	lastScan time.Time
	key      string            // nbrKey of the layout scanned for
	seen     map[string]nbrBSS // by BSSID
}

// nbrEntry is one rrm_nbr_add_nbr's arguments.
type nbrEntry struct {
	BSSID   string
	Info    uint32
	Reg     int
	Channel int
	Phy     int
}

func (e nbrEntry) args() []string {
	return []string{e.BSSID, fmt.Sprintf("0x%x", e.Info), itoa(e.Reg), itoa(e.Channel), itoa(e.Phy)}
}

// entryFor fills a neighbor element for b (802.11-2020 9.4.2.36).
func entryFor(b nbrBSS, selfFT bool) nbrEntry {
	// Reachable (0-1), same security (2), QoS (5), RRM (7), immediate BA (9), HT (11).
	info := uint32(0x3 | 0x4 | 0x20 | 0x80 | 0x200 | 0x800)
	phy := 7 // HT
	if b.Channel > 14 {
		info |= 0x10 | 0x1000 // spectrum management, VHT
		phy = 9               // VHT
	}
	if b.FT && selfFT {
		info |= 0x8 | 0x400 // same key scope (FT), same mobility domain
	}
	if b.HE {
		info |= 0x4000
		phy = 14 // HE
	}
	return nbrEntry{BSSID: strings.ToUpper(b.BSSID), Info: info, Reg: rf.OpClass(rf.ChanBand(b.Channel), b.Channel), Channel: b.Channel, Phy: phy}
}

// nbrRadios returns the radios that serve an RRM SSID.
func nbrRadios(l *layout) []*radioLayout {
	var out []*radioLayout
	for _, rl := range l.Radios {
		if !rl.Radio.Enabled {
			continue
		}
		for _, u := range rl.Used {
			if u.SSID.RRM {
				out = append(out, rl)
				break
			}
		}
	}
	return out
}

// nbrKey changes when a scan should be redone: radios, channels, SSIDs.
func nbrKey(l *layout) string {
	var b strings.Builder
	for _, rl := range l.Radios {
		fmt.Fprintf(&b, "%s:%v:%d:%d;", rl.Primary, rl.Radio.Enabled, rl.Radio.Channel, rl.Radio.Width)
		for _, u := range rl.Used {
			fmt.Fprintf(&b, "%s=%s,", u.Vif, u.SSID.SSID)
		}
	}
	return b.String()
}

var (
	reScanSSID  = regexp.MustCompile(`^SSID: "(.*)"$`)
	reScanChan  = regexp.MustCompile(`Channel: (\d+)`)
	reScanBSSID = regexp.MustCompile(`^BSSID: ([0-9A-Fa-f:]{17})`)
	reNbrLine   = regexp.MustCompile(`bssid ([0-9A-Fa-f:]{17}) bssid_info 0x([0-9a-fA-F]+) reg 0x([0-9a-fA-F]+) channel 0x([0-9a-fA-F]+) phytype 0x([0-9a-fA-F]+)`)
)

// parseScan reads wl scanresults: one block per BSS, starting at SSID:.
func parseScan(out string, now time.Time) []nbrBSS {
	var res []nbrBSS
	var cur *nbrBSS
	flush := func() {
		if cur != nil && cur.BSSID != "" && cur.Channel > 0 {
			res = append(res, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if m := reScanSSID.FindStringSubmatch(t); m != nil {
			flush()
			cur = &nbrBSS{SSID: m[1], Seen: now}
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.HasPrefix(t, "Mode:"):
			if m := reScanChan.FindStringSubmatch(t); m != nil {
				cur.Channel, _ = strconv.Atoi(m[1])
			}
		case reScanBSSID.MatchString(t):
			cur.BSSID = strings.ToUpper(reScanBSSID.FindStringSubmatch(t)[1])
		case strings.HasPrefix(t, "AKM Suites"):
			cur.FT = strings.Contains(t, "FT-")
		case strings.HasPrefix(t, "HE Capable"):
			cur.HE = true
		}
	}
	flush()
	return res
}

// parseNbrList reads wl rrm_nbr_list.
func parseNbrList(out string) map[string]nbrEntry {
	m := map[string]nbrEntry{}
	for _, line := range strings.Split(out, "\n") {
		f := reNbrLine.FindStringSubmatch(line)
		if f == nil {
			continue
		}
		hex := func(s string) int { v, _ := strconv.ParseUint(s, 16, 32); return int(v) }
		e := nbrEntry{BSSID: strings.ToUpper(f[1]), Info: uint32(hex(f[2])), Reg: hex(f[3]), Channel: hex(f[4]), Phy: hex(f[5])}
		m[e.BSSID] = e
	}
	return m
}

// syncNeighbors keeps the 802.11k neighbor lists of l's RRM BSSes (Tick,
// a.mu held). It returns the number of entries added or removed.
func (a *Applier) syncNeighbors(ctx context.Context, l *layout, now time.Time) (int, []string) {
	radios := nbrRadios(l)
	if len(radios) == 0 {
		return 0, nil
	}
	var problems []string
	s := &a.nbr
	if s.seen == nil {
		s.seen = map[string]nbrBSS{}
	}
	key := nbrKey(l)
	switch {
	case !s.scanAt.IsZero() && now.Sub(s.scanAt) >= nbrScanWait:
		for _, rl := range radios {
			out, err := a.o.Run.Run(ctx, "wl", "-i", rl.Primary, "scanresults")
			if err != nil {
				problems = append(problems, fmt.Sprintf("802.11k: scan results on %s: %v", rl.Primary, err))
				continue
			}
			for _, b := range parseScan(string(out), now) {
				s.seen[b.BSSID] = b
			}
		}
		s.scanAt, s.lastScan = time.Time{}, now
	case s.scanAt.IsZero() && (s.lastScan.IsZero() || now.Sub(s.lastScan) >= nbrScanEvery || key != s.key):
		s.key, s.scanAt = key, now
		if !a.o.DryRun {
			for _, rl := range radios {
				if err := a.run(ctx, "wl", "-i", rl.Primary, "scan", "-t", "active"); err != nil {
					problems = append(problems, fmt.Sprintf("802.11k: scan on %s: %v", rl.Primary, err))
				}
			}
		}
	}
	for b, e := range s.seen {
		if now.Sub(e.Seen) > nbrKeep {
			delete(s.seen, b)
		}
	}

	// This unit's BSSes: never a neighbor from a scan, listed across bands.
	type ownBSS struct {
		nbrBSS
		band string
	}
	var own []ownBSS
	ownMAC := map[string]bool{}
	for _, rl := range l.Radios {
		ch := 0
		if out, err := a.o.Run.Run(ctx, "wl", "-i", rl.Primary, "chanspec"); err == nil {
			if f := strings.FieldsFunc(string(out), func(r rune) bool { return r < '0' || r > '9' }); len(f) > 0 {
				ch, _ = strconv.Atoi(f[0])
			}
		}
		for _, u := range rl.Used {
			mac, err := a.bssid(ctx, u.Vif)
			if err != nil {
				continue
			}
			ownMAC[strings.ToUpper(mac)] = true
			if rl.Radio.Enabled && ch > 0 {
				own = append(own, ownBSS{nbrBSS{BSSID: strings.ToUpper(mac), SSID: u.SSID.SSID, Channel: ch, HE: true, FT: u.SSID.FT}, rl.Band})
			}
		}
	}

	changes := 0
	for _, rl := range radios {
		for _, u := range rl.Used {
			if !u.SSID.RRM {
				continue
			}
			want := map[string]nbrEntry{}
			var order []string
			add := func(b nbrBSS) {
				if _, dup := want[b.BSSID]; dup || len(order) >= nbrMax {
					return
				}
				e := entryFor(b, u.SSID.FT)
				if e.Reg == 0 {
					return // a channel no operating class has
				}
				want[b.BSSID] = e
				order = append(order, b.BSSID)
			}
			for _, o := range own {
				if o.SSID == u.SSID.SSID && o.band != rl.Band {
					add(o.nbrBSS)
				}
			}
			var scanned []nbrBSS
			for _, b := range s.seen {
				if b.SSID == u.SSID.SSID && !ownMAC[b.BSSID] {
					scanned = append(scanned, b)
				}
			}
			slices.SortFunc(scanned, func(x, y nbrBSS) int { return strings.Compare(x.BSSID, y.BSSID) })
			for _, b := range scanned {
				add(b)
			}
			out, err := a.o.Run.Run(ctx, "wl", "-i", u.Vif, "rrm_nbr_list")
			if err != nil {
				problems = append(problems, fmt.Sprintf("802.11k: list on %s: %v", u.Vif, err))
				continue
			}
			have := parseNbrList(string(out))
			var steps []Step
			for b, h := range have {
				if w, ok := want[b]; !ok || w != h {
					steps = append(steps, onVif(u.Vif, cmdStep("802.11k: drop neighbor "+b+" from "+u.Vif, "wl", "-i", u.Vif, "rrm_nbr_del_nbr", b)))
				}
			}
			for _, b := range order {
				if h, ok := have[b]; !ok || h != want[b] {
					steps = append(steps, onVif(u.Vif, cmdStep("802.11k: add neighbor "+b+" to "+u.Vif,
						append([]string{"wl", "-i", u.Vif, "rrm_nbr_add_nbr"}, want[b].args()...)...)))
				}
			}
			if len(steps) == 0 {
				continue
			}
			slices.SortStableFunc(steps, func(x, y Step) int { // drops first
				return b2i(strings.Contains(x.Desc, " add ")) - b2i(strings.Contains(y.Desc, " add "))
			})
			if a.o.DryRun {
				a.logPlan("dry-run 802.11k neighbors", Plan{Steps: steps})
				continue
			}
			for _, st := range steps {
				if err := a.do(ctx, st); err != nil {
					problems = append(problems, fmt.Sprintf("802.11k: %s: %v", st.Desc, err))
					continue
				}
				changes++
			}
			a.o.Logf("bcmwifi: 802.11k: %s (%s) lists %d neighbor(s)", u.Vif, u.SSID.SSID, len(want))
		}
	}
	return changes, problems
}
