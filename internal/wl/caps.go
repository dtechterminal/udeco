// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"context"
	"fmt"
	"math"
	"regexp"

	"github.com/antoniocosta/unifi-openwrt/internal/rf"
)

// Caps are the static hardware facts of the unit, as the driver reports
// them for the current country.
type Caps struct {
	Country string              // ISO code from `wl country` ("US")
	Bands   map[string]BandCaps // "ng", "na"
	MaxBSS  int                 // BSS configs per radio, including the primary (8)
}

// BandCaps describes one radio.
type BandCaps struct {
	Channels map[int][]int // width MHz -> allowed primary channels, from `wl chanspecs`
	// TxMinDBm has no driver source; it is a fixed floor (MinTxDBm).
	// TxMaxDBm is the highest per-chanspec limit of `wl chanspec_txpwr_max`.
	TxMinDBm, TxMaxDBm int
	NSS                int // popcount of `wl hw_txchain`
	HT, VHT, HE        bool
	DFS                bool // a DFS channel (52-144) is allowed in this country
	// MaxListedWidth is the widest width `wl chanspecs` could list when the
	// caps were read: the driver lists only widths its bw_cap allows, so
	// with the radio at 40 MHz (bw_cap 0x3) no 80 MHz chanspec is listed
	// even where 80 MHz is allowed (.205, 2026-11-19). Wider widths are
	// unknown, not forbidden. 0 = not known (every width was listable).
	MaxListedWidth int
}

// MinTxDBm is the lowest TX power we offer, and the floor bcmwifi sets
// (its txpower.go). `wl` has no getter for a minimum; this matches the
// UniFi U6-Lite profile (models catalog, 5 dBm).
const MinTxDBm = 5

// bwCapBits is `wl bw_cap`'s bitmap: one bit per channel width.
var bwCapBits = []struct{ bit, mhz int }{{1, 20}, {2, 40}, {4, 80}, {8, 160}}

// BWCap is the `wl bw_cap` bitmap that allows every width up to width MHz
// (20 MHz always): 1, 3, 7, 15.
func BWCap(width int) int {
	v := bwCapBits[0].bit
	for _, w := range bwCapBits[1:] {
		if width >= w.mhz {
			v |= w.bit
		}
	}
	return v
}

// BWCapMaxWidth is the widest width in MHz a `wl bw_cap` bitmap allows (0:
// none of the known widths).
func BWCapMaxWidth(v int) int {
	mhz := 0
	for _, w := range bwCapBits {
		if v&w.bit != 0 {
			mhz = w.mhz
		}
	}
	return mhz
}

// radioStatic is what is read once per radio and reused by Collect.
type radioStatic struct {
	name   string // wl0, wl1
	band   string // ng, na
	hwName string
	caps   BandCaps
	txMax  map[uint16]float64 // chanspec -> dBm (chanspec_txpwr_max)
	specs  []chanspec         // `wl chanspecs` of this band (spectrum blocks)
	maxBSS int
}

type capsState struct {
	caps   Caps
	radios []radioStatic // sorted by name
}

var radioName = regexp.MustCompile(`^wl[0-9]$`)

// Caps returns the static hardware facts. They are read once (about 17 `wl`
// getters) and cached until Invalidate.
func (c *Collector) Caps(ctx context.Context) (Caps, error) {
	st, err := c.static(ctx)
	if err != nil {
		return Caps{}, err
	}
	return st.caps, nil
}

func (c *Collector) static(ctx context.Context) (*capsState, error) {
	c.capsMu.Lock()
	defer c.capsMu.Unlock()
	if c.caps != nil {
		return c.caps, nil
	}
	devs, err := c.netDevs()
	if err != nil {
		return nil, fmt.Errorf("wl: %w", err)
	}
	st := &capsState{caps: Caps{Bands: map[string]BandCaps{}}}
	for _, d := range devs {
		if !radioName.MatchString(d) {
			continue
		}
		r, err := c.readRadioStatic(ctx, d)
		if err != nil {
			return nil, err
		}
		if _, dup := st.caps.Bands[r.band]; dup {
			return nil, fmt.Errorf("wl: two radios on band %s", r.band)
		}
		st.radios = append(st.radios, r)
		st.caps.Bands[r.band] = r.caps
		st.caps.MaxBSS = max(st.caps.MaxBSS, r.maxBSS)
		if st.caps.Country == "" {
			out, err := c.wl(ctx, d, "country")
			if err != nil {
				return nil, err
			}
			st.caps.Country = parseCountry(out)
		}
	}
	if len(st.radios) == 0 {
		return nil, errNoRadios
	}
	c.caps = st
	return st, nil
}

// sameRadios reports whether the radios in devs (a /sys/class/net listing)
// are exactly the ones st was read for.
func (st *capsState) sameRadios(devs []string) bool {
	i := 0
	for _, d := range devs {
		if !radioName.MatchString(d) {
			continue
		}
		if i >= len(st.radios) || st.radios[i].name != d {
			return false
		}
		i++
	}
	return i == len(st.radios)
}

// dropCaps forgets st if it is still the cached state (a concurrent
// Invalidate or refresh may already have replaced it).
func (c *Collector) dropCaps(st *capsState) {
	c.capsMu.Lock()
	if c.caps == st {
		c.caps = nil
	}
	c.capsMu.Unlock()
}

func (c *Collector) readRadioStatic(ctx context.Context, dev string) (radioStatic, error) {
	r := radioStatic{name: dev}
	get := func(args ...string) ([]byte, error) { return c.wl(ctx, dev, args...) }

	out, err := get("band")
	if err != nil {
		return r, err
	}
	switch firstField(out) { // "a" or "b"
	case "a":
		r.band = "na"
	case "b":
		r.band = "ng"
	default:
		out, err := get("chanspec")
		if err != nil {
			return r, err
		}
		cs, ok := parseChanspecHex(string(out))
		if !ok {
			return r, fmt.Errorf("wl -i %s: band unknown", dev)
		}
		r.band = cs.Band
	}

	out, err = get("cap")
	if err != nil {
		return r, err
	}
	capSet := parseCap(out)
	r.maxBSS = maxBSS(capSet)

	out, err = get("hw_txchain")
	if err != nil {
		return r, err
	}
	chains, _ := parseInt(out)
	r.caps.NSS = max(1, popcount(chains))

	if out, err = get("nmode"); err != nil {
		return r, err
	}
	n, _ := parseInt(out)
	r.caps.HT = n == 1
	if out, err = get("vhtmode"); err != nil {
		return r, err
	}
	// Broadcom also offers VHT rates on 2.4 GHz; only 5 GHz counts as 11ac.
	n, _ = parseInt(out)
	r.caps.VHT = r.band == "na" && n == 1
	r.caps.HE = capSet["11ax"]

	if out, err := get("bw_cap", rf.Legacy(r.band)); err == nil {
		if v, ok := parseInt(out); ok && v > 0 {
			r.caps.MaxListedWidth = BWCapMaxWidth(int(v))
		}
	}
	if out, err = get("chanspecs"); err != nil {
		return r, err
	}
	var list []chanspec
	for _, cs := range parseChanspecs(out) {
		if cs.Band == r.band {
			list = append(list, cs)
		}
	}
	r.caps.Channels = channelsByWidth(list)
	r.specs = list
	for _, cs := range list {
		if rf.IsDFS(cs.Band, cs.Control) {
			r.caps.DFS = true
		}
	}

	if out, err = get("chanspec_txpwr_max"); err != nil {
		return r, err
	}
	r.txMax = parseChanspecTxpwrMax(out)
	r.caps.TxMinDBm = MinTxDBm
	best := math.Inf(-1)
	for _, v := range r.txMax {
		best = max(best, v)
	}
	if !math.IsInf(best, -1) {
		r.caps.TxMaxDBm = int(math.Floor(best))
	}

	if out, err = get("revinfo"); err == nil {
		r.hwName = parseRevinfo(out)
	}
	return r, nil
}
