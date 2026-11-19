// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// vapInfo is the slowly-changing identity of one candidate VAP.
type vapInfo struct {
	name       string
	up         bool // `wl bss` = up
	dwds       bool // `wl dwds` = 1: TP-Link's mesh backhaul, never user-facing
	ssid       string
	encryption string
}

// vapCache holds the probed VAPs of one radio.
type vapCache struct {
	key  string // the bridged candidate set the probe was for
	at   time.Time
	vaps []vapInfo
}

// vifName matches a Broadcom virtual interface: wl01 is vif 1 of radio wl0.
var vifName = regexp.MustCompile(`^(wl[0-9])[0-9]+$`)

// Collect reads the unit once: system from files, then per radio `wl
// chanspec`, `chanim_stats us`, `noise`, `txpwr_target_max`, and per
// user-facing VAP `sta_info all`. VAP identities are re-read every 60 s, when
// the bridge membership changes, or after a failed client read. The cached
// hardware facts (Caps) are re-read when the set of radios under
// /sys/class/net changes.
//
// An error from chanspec or sta_info fails the collection (the snapshot would
// be wrong); a failed noise, power or channel-use read leaves that value at
// zero (or the survey unchanged) so a radio that is down still reports.
func (c *Collector) Collect(ctx context.Context) (*apstate.Snapshot, error) {
	devs, err := c.netDevs()
	if err != nil {
		return nil, fmt.Errorf("wl: %w", err)
	}
	st, err := c.static(ctx)
	if err != nil {
		return nil, err
	}
	if !st.sameRadios(devs) {
		// a radio appeared or went away since the hardware facts were
		// read: read them again rather than report a stale set for ever
		// (or fail every collection on a radio that no longer exists)
		c.dropCaps(st)
		if st, err = c.static(ctx); err != nil {
			return nil, err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	s := &apstate.Snapshot{Time: c.now(), ARP: map[string]string{}, UplinkName: c.opt.Uplink}
	if err := c.readSystem(s); err != nil {
		return nil, fmt.Errorf("wl: system: %w", err)
	}
	for _, rs := range st.radios {
		r, err := c.collectRadio(ctx, rs, devs, s.Time)
		if err != nil {
			return nil, err
		}
		s.Radios = append(s.Radios, r)
	}
	sort.SliceStable(s.Radios, func(i, j int) bool { return s.Radios[i].Band > s.Radios[j].Band }) // ng before na
	return s, nil
}

func (c *Collector) collectRadio(ctx context.Context, rs radioStatic, devs []string, now time.Time) (apstate.Radio, error) {
	r := apstate.Radio{
		Iface: rs.name, Phy: rs.name, Mode: "Master", Band: rs.band,
		NSS: rs.caps.NSS, HWName: rs.hwName, VHT: rs.caps.VHT, HE: rs.caps.HE,
		TxMin: rs.caps.TxMinDBm, TxMax: rs.caps.TxMaxDBm,
	}
	// chanspec, noise, power and channel use: while a spectrum band runs on
	// this radio these are the values read at band start (`wl chanspec`
	// shows the scan channel during a call, spectrum-design §8.7)
	cur := c.readCurrent(ctx, rs.name)
	if cur.chanspecErr != nil {
		return r, cur.chanspecErr
	}
	cs, ok := parseChanspecHex(string(cur.chanspec))
	if !ok {
		return r, fmt.Errorf("wl -i %s chanspec: cannot parse %q", rs.name, firstLine(string(cur.chanspec)))
	}
	r.Band, r.Channel, r.Width = cs.Band, cs.Control, cs.Width
	if v, ok := rs.txMax[cs.Raw]; ok {
		r.TxMax = int(math.Floor(v))
	}
	if n, ok := parseInt(cur.noise); ok {
		r.Noise = int(n)
	}
	if v, ok := parseTxpwrTargetMax(cur.txpwr); ok {
		r.TxPower = int(math.Round(v))
	}
	sv := c.survey[rs.name]
	if sv == nil {
		sv = &surveyState{}
		c.survey[rs.name] = sv
	}
	r.Survey = sv.survey()
	if cur.haveUs {
		r.Survey = sv.update(cur.us, cur.usAt)
	}

	vaps, err := c.userVAPs(ctx, rs.name, devs, now)
	if err != nil {
		return r, err
	}
	for _, v := range vaps {
		out, err := c.wl(ctx, v.name, "sta_info", "all")
		if err != nil {
			delete(c.vaps, rs.name) // the VAP may have gone down: probe again next time
			return r, err
		}
		vap := r
		vap.Iface, vap.SSID, vap.Encryption, vap.Survey, vap.VAPs = v.name, v.ssid, v.encryption, apstate.Survey{}, nil
		vap.BSSID = strings.ToLower(c.trimmed(devPath(v.name, "address")))
		vap.Stats = c.netStats(v.name)
		vap.Stations = parseStaInfoAll(out)
		for i := range vap.Stations {
			st := &vap.Stations[i]
			if r.Noise != 0 {
				st.Noise = r.Noise
			}
			if r.Band != "na" {
				st.VHT = false // Broadcom's 2.4 GHz VHT rates are not 802.11ac
			}
		}
		r.VAPs = append(r.VAPs, vap)
	}
	return r, nil
}

// userVAPs returns the user-facing VAPs of a radio: bridged (a brport
// exists), `bss` up and not a dwds (mesh backhaul) interface. The bridged
// set is read from /sys every time; the wl probes are cached (vapRefresh).
func (c *Collector) userVAPs(ctx context.Context, radio string, devs []string, now time.Time) ([]vapInfo, error) {
	var cands []string
	for _, d := range devs {
		if m := vifName.FindStringSubmatch(d); m != nil && m[1] == radio && c.exists(devPath(d, "brport")) {
			cands = append(cands, d)
		}
	}
	key := strings.Join(cands, " ")
	vc := c.vaps[radio]
	if vc == nil || vc.key != key || now.Sub(vc.at) >= vapRefresh || now.Before(vc.at) {
		vc = &vapCache{key: key, at: now}
		for _, d := range cands {
			v, err := c.probeVAP(ctx, d)
			if err != nil {
				return nil, err
			}
			vc.vaps = append(vc.vaps, v)
		}
		c.vaps[radio] = vc
	}
	var out []vapInfo
	for _, v := range vc.vaps {
		if v.up && !v.dwds && !backhaulVif(v.name) {
			out = append(out, v)
		}
	}
	return out, nil
}

// backhaulVif reports wlN1, which never carries a client SSID on the Deco:
// TP-Link's mesh backhaul (dwds, hidden) in observe mode, the agent
// hostapd's hidden placeholder in takeover (agent-design §2). It is left
// out even when its dwds cannot be read, so its counters are never
// reported under a user VAP's name.
func backhaulVif(dev string) bool {
	m := vifName.FindStringSubmatch(dev)
	return m != nil && dev == m[1]+"1"
}

// probeVAP reads bss, dwds, ssid and wpa_auth of one interface.
func (c *Collector) probeVAP(ctx context.Context, dev string) (vapInfo, error) {
	v := vapInfo{name: dev}
	out, err := c.wl(ctx, dev, "bss")
	if err != nil {
		return v, err
	}
	v.up = strings.TrimSpace(string(out)) == "up"
	if !v.up {
		return v, nil
	}
	// A driver without the dwds iovar has no dwds interfaces.
	if out, err := c.wl(ctx, dev, "dwds"); err == nil {
		n, _ := parseInt(out)
		v.dwds = n != 0
	}
	if v.dwds {
		return v, nil
	}
	if out, err = c.wl(ctx, dev, "ssid"); err != nil {
		return v, err
	}
	v.ssid = parseSSID(out)
	if out, err := c.wl(ctx, dev, "wpa_auth"); err == nil {
		v.encryption = parseWPAAuth(out)
	}
	return v, nil
}
