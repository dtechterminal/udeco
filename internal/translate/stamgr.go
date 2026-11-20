// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/rf"
)

// planStamgr: the UniFi's per-radio station manager (docs/internals.md),
// sent with the site's advanced features on:
//
//	stamgr.<n>.radio=ng|na|6e
//	stamgr.<n>.minrssi.status=true|false  stamgr.<n>.minrssi.rssi=<dBm>
//	stamgr.<n>.loadbalance.status=true|false  stamgr.<n>.loadbalance.maxsta=<n>
//
// Minimum RSSI -> the radio's rssi_reject_assoc_rssi (hostapd refuses weaker
// clients; the daemon also drops connected ones, cmd/uow). Load balancing ->
// maxassoc on the radio's UniFi-managed interfaces (unifi_* and any
// interface carrying a UniFi SSID).
func planStamgr(cfg Cfg, cur UCI, r *Result) []Op {
	radios := apRadios(cur)
	minRSSI := map[string]string{} // radio section -> dBm
	maxSta := map[string]string{}
	for _, e := range LegacyStamgr(cfg) {
		if e.Radio == "" {
			continue
		}
		sec := radios[rf.Legacy(e.Radio)]
		if sec == "" {
			r.Notes = append(r.Notes, fmt.Sprintf("stamgr.%d: no %s radio here", e.N, e.Radio))
			continue
		}
		if e.MinRSSIOn {
			minRSSI[sec] = strconv.Itoa(e.MinRSSI)
		}
		if e.MaxSta > 0 {
			maxSta[sec] = strconv.Itoa(e.MaxSta)
		}
	}
	// interfaces the UniFi manages: named unifi_*, or carrying one of its
	// SSIDs (a WLAN adopted onto an existing section, like ap0/ap1 here)
	ssids := map[string]bool{}
	for k, v := range cfg {
		if p := strings.Split(k, "."); len(p) == 3 && p[0] == "wireless" && p[2] == "ssid" && v != "" {
			ssids[v] = true
		}
	}
	var ops []Op
	set := func(key, want string) {
		old, has := cur[key]
		switch {
		case want != "" && old != want:
			ops = append(ops, Op{Key: key, Value: want, Old: old})
		case want == "" && has:
			ops = append(ops, Op{Del: true, Key: key, Old: old})
		}
	}
	var secs []string
	for _, s := range radios {
		secs = append(secs, s)
	}
	sort.Strings(secs)
	for _, sec := range secs {
		set("wireless."+sec+".rssi_reject_assoc_rssi", minRSSI[sec])
		var ifs []string
		for k, v := range cur {
			s := strings.TrimPrefix(k, "wireless.")
			if v == "wifi-iface" && (strings.HasPrefix(s, "unifi_") || ssids[cur[k+".ssid"]]) && cur[k+".device"] == sec && cur[k+".mode"] == "ap" {
				ifs = append(ifs, k)
			}
		}
		sort.Strings(ifs)
		for _, k := range ifs {
			set(k+".maxassoc", maxSta[sec])
		}
	}
	return ops
}

// StamgrEntry is one stamgr.N section as LegacyStamgr reads it.
type StamgrEntry struct {
	N     int    // the section: stamgr.N
	Radio string // stamgr.N.radio as sent ("ng", "na", "6e"); "" = not sent
	// MinRSSI is the minimum RSSI in dBm, valid with MinRSSIOn (a sent
	// value of 95 above the noise floor is 0 dBm, and on).
	MinRSSI   int
	MinRSSIOn bool
	MaxSta    int // the load balancer's client limit; 0 = none
}

// legacyStamgrMax is the highest stamgr.N LegacyStamgr reads.
const legacyStamgrMax = 8

// LegacyStamgr reads the station manager sections the way the OpenWrt path
// always has (planStamgr here, and cmd/uow's minimum RSSI kick): stamgr.1
// to stamgr.8 only, a setting is on only when its status is "true", and
// neither stamgr.status nor stamgr.N.status is looked at. It returns the
// sections that say anything (a radio, a minimum RSSI or a client limit),
// by number; what a section with no radio means is the caller's.
//
// IntentFromCfg (intentStamgr) reads the same keys with another rule: every
// section sent, "enabled" as well as "true", and nothing of a disabled
// section. Which rule is right is not decided here; TestStamgrReaders
// lists the inputs they differ on.
func LegacyStamgr(cfg Cfg) []StamgrEntry {
	var out []StamgrEntry
	for i := 1; i <= legacyStamgrMax; i++ {
		p := fmt.Sprintf("stamgr.%d.", i)
		e := StamgrEntry{N: i, Radio: cfg[p+"radio"]}
		if cfg[p+"minrssi.status"] == "true" {
			e.MinRSSI, e.MinRSSIOn = stamgrMinRSSI(cfg[p+"minrssi.rssi"])
		}
		if cfg[p+"loadbalance.status"] == "true" {
			e.MaxSta = stamgrMaxSta(cfg[p+"loadbalance.maxsta"])
		}
		if e.Radio != "" || e.MinRSSIOn || e.MaxSta > 0 {
			out = append(out, e)
		}
	}
	return out
}

// stamgrMinRSSI reads stamgr.N.minrssi.rssi: dBm when negative, RSSI above
// the noise floor (rf.NoiseFloorDBm) when positive. ok is false for 0 and
// for anything that is not a number.
func stamgrMinRSSI(v string) (dbm int, ok bool) {
	n, err := strconv.Atoi(v)
	if err != nil || n == 0 {
		return 0, false
	}
	if n > 0 {
		n += rf.NoiseFloorDBm
	}
	return n, true
}

// stamgrMaxSta reads stamgr.N.loadbalance.maxsta; 0 = no usable limit.
func stamgrMaxSta(v string) int {
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return n
	}
	return 0
}

// planOutdoor: radio.outdoor (Indoor/Outdoor in the UniFi). OpenWrt keeps
// the kernel's channel rules per country only; what changes is the
// environment byte of the Country IE clients see (country3 'O' = 0x4f,
// with the Country IE on). Indoor = OpenWrt's default (both unset).
func planOutdoor(cfg Cfg, cur UCI, r *Result) []Op {
	if cfg["radio.outdoor"] == "" {
		return nil
	}
	out := cfg["radio.outdoor"] == "enabled"
	var secs []string
	for k, v := range cur {
		if v == "wifi-device" {
			secs = append(secs, k)
		}
	}
	sort.Strings(secs)
	var ops []Op
	for _, k := range secs {
		for opt, want := range map[string]string{"country3": "0x4f", "ieee80211d": "1"} {
			key := k + "." + opt
			old, has := cur[key]
			switch {
			case out && old != want:
				ops = append(ops, Op{Key: key, Value: want, Old: old})
			case !out && has && old == want && cur[k+".country3"] == "0x4f": // only undo outdoor mode
				ops = append(ops, Op{Del: true, Key: key, Old: old})
			}
		}
	}
	if out && len(ops) > 0 {
		r.Notes = append(r.Notes, "outdoor mode: Country IE environment 'O'; channel limits stay the country's (OpenWrt has no outdoor channel table)")
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].Key < ops[j].Key })
	return ops
}
