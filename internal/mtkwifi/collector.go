// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"errors"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

// CollectorOptions configures a Collector.
type CollectorOptions struct {
	Root   string
	Run    Runner
	Bridge string     // bdg2
	Layout []RadioDef // nil = JCOW414
	Model  string     // reported hardware model
	// FreshScan lets Scan (the controller's `cmd scan`, never a periodic
	// job) start a driver site survey (`iwpriv <radio> set SiteSurvey=1`),
	// which takes the radio off its channel for seconds. Off (the default),
	// Scan is unsupported, ScanSupported is false and the agent does not
	// claim RF_SCAN; HomeScan still reports the driver's cached survey.
	// Not to be turned on before the live impact test (clients' ping stall).
	FreshScan bool
	// CacheTTL: how long the driver readings (station table and counters
	// from the kernel log, busy time, iwconfig) are reused (0 = 5 s), so a
	// 1 s live view does not run iwpriv and fill the small kernel log every
	// second. The sysfs counters are read on every Collect.
	CacheTTL time.Duration
	// klog reads the kernel log (test hook; nil = klogctl).
	klog func() ([]byte, error)
	// now and sleep are test hooks.
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// Collector reads the unit for the inform.
type Collector struct {
	o   CollectorOptions
	sys *wl.Collector
	// mu: the driver readings go through the shared kernel log, and the
	// caches below
	mu     sync.Mutex
	cache  map[string]*radioReading // by the radio's first BSS (ra0, rai0)
	survey map[string]*surveyAcc    // by band
	// counts: the last station counters per radio (kept over Invalidate)
	counts map[string]map[string]staCount
	// countsAt: when counts were read, per radio (the own airtime
	// estimate's interval, staAirtime)
	countsAt map[string]time.Time
	// mib: the last `show mibinfo` ask and busy time per radio (by its
	// first BSS), asked at most every mibInterval
	mib map[string]*mibReading
	// scanSem: one site survey (Scan) or survey read (HomeScan) at a time;
	// WithoutScan waits for it
	scanSem  chan struct{}
	scanning atomic.Bool
	seen     map[string]*surveySeen // by band: the cached survey's first sighting
	// gate: the Wi-Fi applier's radio restarts (FollowRestarts,
	// restartgate.go); nil = none (observe mode)
	gate atomic.Pointer[RestartGate]
}

// ErrUnsupported: scans and spectrum runs are not implemented on this driver.
var ErrUnsupported = errors.New("mtkwifi: not supported on this unit")

// Ports on the JCOW414 are the switch port devices in the bridge.
var portRE = regexp.MustCompile(`^eth[0-9]+\.[0-9]+\.1$`)

type runnerAdapter struct{ r Runner }

func (x runnerAdapter) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return x.r.Run(ctx, name, args...)
}

// defaultCacheTTL: the driver readings' lifetime (CacheTTL).
const defaultCacheTTL = 5 * time.Second

// NewCollector returns a Collector.
func NewCollector(o CollectorOptions) *Collector {
	if o.Root == "" {
		o.Root = "/"
	}
	if o.Bridge == "" {
		o.Bridge = "bdg2"
	}
	if o.Layout == nil {
		o.Layout = JCOW414
	}
	if o.klog == nil {
		o.klog = readKlog
	}
	if o.CacheTTL <= 0 {
		o.CacheTTL = defaultCacheTTL
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.sleep == nil {
		o.sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	return &Collector{o: o, sys: wl.New(wl.Options{Root: o.Root, Run: runnerAdapter{o.Run}, Bridge: o.Bridge, Ports: portRE}),
		cache: map[string]*radioReading{}, survey: map[string]*surveyAcc{}, seen: map[string]*surveySeen{},
		counts: map[string]map[string]staCount{}, countsAt: map[string]time.Time{},
		mib:     map[string]*mibReading{},
		scanSem: make(chan struct{}, 1)}
}

func (c *Collector) path(p string) string { return c.o.Root + p }

func (c *Collector) read(p string) string {
	b, _ := os.ReadFile(c.path(p))
	return strings.TrimSpace(string(b))
}

func (c *Collector) isUp(dev string) bool {
	v, err := strconv.ParseInt(c.read("/sys/class/net/"+dev+"/flags"), 0, 64)
	return err == nil && v&1 == 1
}

var chanRE = regexp.MustCompile(`Channel[=:](\d+)`)

// Collect reads the system and both radios.
func (c *Collector) Collect(ctx context.Context) (*apstate.Snapshot, error) {
	now := c.o.now()
	s := &apstate.Snapshot{Time: now}
	if err := c.sys.ReadSystem(s); err != nil {
		return nil, err
	}
	s.Model = c.o.Model
	s.Release = c.read("/flash/firmwareVersionInfo")
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rd := range c.o.Layout {
		main := rd.Ifaces[0]
		r := apstate.Radio{Iface: main, Phy: main, Mode: "Master", Band: rd.Band,
			NSS: 2, HWName: rd.HWName, VHT: rd.Band == "na", TxMin: 5, TxMax: rd.MaxTxDBm, Noise: -95}
		dat, _ := os.ReadFile(c.path(rd.Dat))
		r.Width = 20
		if v, _ := getKey(dat, "HT_BW"); v == "1" {
			r.Width = 40
			if v, _ := getKey(dat, "VHT_BW"); rd.Band == "na" && v == "1" {
				r.Width = 80
			}
		}
		pct := 100
		if v, ok := getKey(dat, "TxPower"); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				pct = n
			}
		}
		r.TxPower = dbmOf(pct, rd.MaxTxDBm)
		if !c.isUp(main) {
			// kept, not dropped: a radio coming back from a restart is
			// not read until the settle time is over (restartgate.go)
			if rr := c.cache[main]; rr != nil {
				// its busy time is not carried over the gap: the reading
				// stands through the settle time, but without it (the
				// radio may come back on another channel)
				rr.stale, rr.busy = true, nil
			}
			if m := c.mib[main]; m != nil {
				// never asked while down; its last reading is not
				// carried over the gap, but the interval still holds,
				// and the next ask has no previous one (mibReading.gap)
				m.busy, m.gap = nil, true
			}
			r.Survey, _ = c.integrate(rd.Band, nil, now)
			r.NoSurvey = true
			s.Radios = append(s.Radios, r)
			continue
		}
		var up []string
		for _, ifc := range rd.Ifaces {
			if c.isUp(ifc) {
				up = append(up, ifc)
			}
		}
		rr := c.reading(ctx, rd, up, now)
		r.Channel = rr.channel
		for i, ifc := range rd.Ifaces {
			if !slices.Contains(up, ifc) {
				continue
			}
			v := apstate.Radio{Iface: ifc, Phy: main, Mode: "Master", Band: rd.Band, Channel: r.Channel,
				Width: r.Width, TxPower: r.TxPower, BSSID: strings.ToLower(c.read("/sys/class/net/" + ifc + "/address")),
				Stats: c.netStats(ifc), SSID: rr.essid[ifc]}
			for _, st := range rr.stas {
				if st.bss == i {
					v.Stations = append(v.Stations, st.Station)
				}
			}
			r.VAPs = append(r.VAPs, v)
		}
		if len(r.VAPs) > 0 {
			r.SSID, r.BSSID = r.VAPs[0].SSID, r.VAPs[0].BSSID
		}
		var ok bool
		r.Survey, ok = c.integrate(rd.Band, withStaAir(rr.busy, rr.staTx, rr.staRx), now)
		r.NoSurvey = !ok
		s.Radios = append(s.Radios, r)
	}
	return s, nil
}

// radioReading is one radio's driver reading, reused for CacheTTL.
type radioReading struct {
	at      time.Time
	up      []string          // the BSSes up when it was read
	channel int               // iwconfig of the first BSS
	essid   map[string]string // iwconfig per BSS
	stas    []sta
	busy    *busySample // nil: the driver gives no busy time for this radio
	// staTx, staRx: the AP's own transmit and receive airtime estimated
	// from the stations' byte counters and rates (staAirtime), µs per
	// second; 0 = none
	staTx, staRx int64
	stale        bool // Invalidate, or the radio went down: read again when the driver may be read
}

// restartKeep: how old a reading may be to stand in for one the radio
// restart's gate skips; an older one (a radio that was off for long) gives
// an empty reading instead.
const restartKeep = 5 * time.Minute

// FollowRestarts makes the driver reads keep away from the applier's radio
// restarts (restartgate.go): while g says no, Collect gives the last
// reading and HomeScan the last survey, without asking the driver, and
// Scan refuses.
func (c *Collector) FollowRestarts(g RestartGate) { c.gate.Store(&g) }

// driverRead: may the driver be read now (see RestartGate); never blocks.
func (c *Collector) driverRead() (func(), bool) {
	g := c.gate.Load()
	if g == nil {
		return func() {}, true
	}
	return (*g).DriverRead()
}

// ErrRadioRestart: a radio restart is under way or just ended (Scan).
var ErrRadioRestart = errors.New("mtkwifi: a radio was just restarted: the driver is not read for a while")

// driverReads says which kernel-log readings a radio's driver answers at
// the vendor's debug level (read on the unit, 2026-11-19): the MT7603
// (2.4 GHz, mt7603eap.ko) prints `show stacountinfo` (per-station packets
// and bytes) but has no `bgndscaninfo`; the MT7663 (5 GHz, in the kernel)
// prints `show bgndscaninfo` (one-second busy and own airtime) and nothing
// for `show stacountinfo`. Neither prints per-station retries or failures
// (`stacountinfo` has none, `show wtbl` holds only the rate-adaptation
// counters the driver clears as it reads them). The MT7603 prints no busy
// or airtime lines at all (the "One sec ..." lines are the MT7663's
// bgndscaninfo); its busy time is the Prim CCA Time MIB counter of `show
// mibinfo`, which the read clears (2026-11-20): asked as mib, at most every
// mibInterval (mibBusy).
func driverReads(rd RadioDef) (counts, busy, mib bool) {
	return rd.Band == "ng", rd.Band == "na", rd.Band == "ng"
}

// reading returns the radio's cached driver reading, read again when it is
// older than CacheTTL, when the set of BSSes up changed, or after
// Invalidate. During a site survey (Scan) the old reading stands: iwconfig
// may show the scan channel then. While the applier restarts a radio, and
// for its settle time after, the old reading stands too (restartgate.go);
// without one the reading is empty and not kept. c.mu is held.
func (c *Collector) reading(ctx context.Context, rd RadioDef, up []string, now time.Time) *radioReading {
	main := rd.Ifaces[0]
	old := c.cache[main]
	if old != nil && (c.scanning.Load() || (!old.stale && now.Sub(old.at) < c.o.CacheTTL && now.Sub(old.at) >= 0 && slices.Equal(old.up, up))) {
		return old
	}
	done, ok := c.driverRead()
	if !ok {
		if m := c.mib[main]; m != nil {
			// a radio restart (down, perhaps unseen between two
			// Collects) may have reset the MIB counters: the next ask
			// has no previous one
			m.gap = true
		}
		if old != nil && now.Sub(old.at) < restartKeep {
			return old
		}
		return &radioReading{at: now, up: up, essid: map[string]string{}}
	}
	defer done()
	rr := &radioReading{at: now, up: up, essid: map[string]string{}}
	if out, err := c.o.Run.Run(ctx, "iwconfig", main); err == nil {
		if m := chanRE.FindSubmatch(out); m != nil {
			rr.channel, _ = strconv.Atoi(string(m[1]))
		}
	}
	for _, ifc := range up {
		if out, err := c.o.Run.Run(ctx, "iwconfig", ifc); err == nil {
			if m := essidRE.FindSubmatch(out); m != nil {
				rr.essid[ifc] = string(m[1])
			}
		}
	}
	counts, busy, mib := driverReads(rd)
	c.klogRead(ctx, main, rr, counts, busy, mib, now)
	c.cache[main] = rr
	return rr
}

// klogRead asks the driver for the radio's station table (iwpriv
// get_mac_table writes nothing to stdout), its station counters and its
// busy time, each of which it prints to the kernel log, and parses what
// each request added there. One log read after each request is the next
// one's "before". wantMib (MT7603) asks `show mibinfo` last, after the
// station-table reads, so its 60-odd lines never land between a
// station-table request and its log read; within mibInterval of the last
// ask the radio keeps that one's reading. The caller holds the restart
// gate (reading).
func (c *Collector) klogRead(ctx context.Context, main string, rr *radioReading, wantCounts, wantBusy, wantMib bool, now time.Time) {
	if wantMib {
		// within mibInterval of the last ask the driver is not asked again
		// (whatever that one gave stands, nothing included)
		if m := c.mib[main]; m != nil && now.Sub(m.asked) >= 0 && now.Sub(m.asked) < mibInterval {
			rr.busy, wantMib = m.busy, false
		}
	}
	beforeB, err := c.o.klog()
	if err != nil {
		return
	}
	before := string(beforeB)
	// ask returns what the request added to the log
	ask := func(what string) (added string, ok bool) {
		if _, err := c.o.Run.Run(ctx, "iwpriv", main, "show", what); err != nil {
			return "", false
		}
		after, err := c.o.klog()
		if err != nil {
			return "", false
		}
		added = newLog(before, string(after))
		before = string(after)
		return added, true
	}
	// "show stainfo" prints the full table at any driver debug level;
	// get_mac_table prints it only at the vendor's (after a radio restart
	// it prints a short table without signal or rate). 2026-11-19.
	log, ok := ask("stainfo")
	if !ok {
		return
	}
	rr.stas = parseMacTable(log)
	if wantCounts && len(rr.stas) > 0 {
		var counts map[string]staCount
		if log, ok := ask("stacountinfo"); ok {
			counts = parseStaCount(log)
		}
		// A station's counters going down count as a new association
		// (apstate.Counters), so one missed reading would count all of
		// its traffic again: a station missing from this one keeps its
		// last counts.
		last := c.counts[main]
		next := map[string]staCount{}
		for i := range rr.stas {
			mac := rr.stas[i].MAC
			n, ok := counts[mac]
			if !ok {
				n, ok = last[mac]
			}
			if !ok {
				continue
			}
			next[mac] = n
			st := &rr.stas[i].Station
			st.TxPackets, st.RxPackets, st.TxBytes, st.RxBytes = n.txPkts, n.rxPkts, n.txBytes, n.rxBytes
		}
		if at := c.countsAt[main]; !at.IsZero() && now.After(at) {
			rr.staTx, rr.staRx = staAirtime(rr.stas, last, next, now.Sub(at))
		}
		c.counts[main] = next
		c.countsAt[main] = now
	}
	if wantBusy {
		if log, ok := ask("bgndscaninfo"); ok {
			if b, ok := parseBgndScanInfo(log); ok {
				rr.busy = &b
			}
		}
	}
	if wantMib {
		m := c.mib[main]
		if m == nil {
			m = &mibReading{gap: true}
			c.mib[main] = m
		}
		// the read clears the counter: every ask, whatever it answered,
		// is the next one's start (and is not repeated before mibInterval)
		var since time.Duration // 0: no previous ask to measure from
		at := c.o.now()
		if !m.gap {
			since = at.Sub(m.at)
		}
		m.asked, m.at, m.gap, m.busy = now, at, false, nil
		if _, err := c.o.Run.Run(ctx, "iwpriv", main, "show", "mibinfo"); err != nil {
			// whether the driver read (and cleared) the counters is not
			// known: the next ask does not measure from this one
			m.gap = true
		} else if after, err := c.o.klog(); err == nil {
			added, anchored := newLogAnchored(before, string(after))
			m.busy = mibBusy(added, anchored, since)
		}
		rr.busy = m.busy
	}
}

func dbmOf(pct, maxDBm int) int {
	d := maxDBm
	for p := 100; p/2 >= pct && d > 3; p /= 2 {
		d -= 3
	}
	return d
}

var statNames = []string{"rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"}

func (c *Collector) netStats(dev string) map[string]int64 {
	m := map[string]int64{}
	for _, k := range statNames {
		v, _ := strconv.ParseInt(c.read("/sys/class/net/"+dev+"/statistics/"+k), 10, 64)
		m[k] = v
	}
	return m
}

// newLog is what after holds beyond before (the kernel log is a ring: the
// end of before is found in after). Only a table printed for this request
// is parsed, never an older one of the other radio.
func newLog(before, after string) string {
	s, _ := newLogAnchored(before, after)
	return s
}

// newLogAnchored is newLog, and whether before's end was found in after.
// Not found (before was empty, or the ring wrapped past all of it), it is
// all of after: then whatever is in it may be older than the request.
func newLogAnchored(before, after string) (string, bool) {
	tail := before
	if len(tail) > 256 {
		tail = tail[len(tail)-256:]
	}
	if tail == "" {
		return after, false
	}
	if i := strings.LastIndex(after, tail); i >= 0 {
		return after[i+len(tail):], true
	}
	return after, false // the ring wrapped past all of before
}

// Caps describes the radios for the agent's capability words.
func (c *Collector) Caps(context.Context) (wl.Caps, error) {
	cp := wl.Caps{Country: "IN", MaxBSS: 4, Bands: map[string]wl.BandCaps{}}
	for _, rd := range c.o.Layout {
		b := wl.BandCaps{TxMinDBm: 5, TxMaxDBm: rd.MaxTxDBm, NSS: 2, HT: true, Channels: map[int][]int{}}
		if rd.Band == "ng" {
			b.Channels[20], b.Channels[40] = chans24, chans24
		} else {
			b.VHT = true
			b.Channels[20] = chans5
			b.Channels[40] = chans5[:8]
			b.Channels[80] = chans5[:8]
		}
		cp.Bands[rd.Band] = b
	}
	return cp, nil
}

// ScanSupported says whether Scan runs: only with FreshScan (the agent
// claims RF_SCAN on it).
func (c *Collector) ScanSupported() bool { return c.o.FreshScan }

// Spectrum: the MT76x3 drivers have no spectrum runner here.
func (c *Collector) Spectrum(context.Context, string) (*wl.SpectrumRunner, error) {
	return nil, ErrUnsupported
}

// WithoutScan runs fn while no site survey runs.
func (c *Collector) WithoutScan(ctx context.Context, fn func(context.Context) error) error {
	if err := c.lockScan(ctx); err != nil {
		return err
	}
	defer c.unlockScan()
	return fn(ctx)
}

// Invalidate marks the cached driver readings stale (after an apply:
// SSIDs, channel and the BSSes up may have changed): they are read again
// at the next Collect the radio restarts' gate lets through, and stand
// until then.
func (c *Collector) Invalidate() {
	c.mu.Lock()
	for _, rr := range c.cache {
		rr.stale = true
	}
	c.mu.Unlock()
}

func (c *Collector) lockScan(ctx context.Context) error {
	select {
	case c.scanSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Collector) unlockScan() { <-c.scanSem }

// ----------------------------------------------------------- station table

type sta struct {
	apstate.Station
	bss int
}

var (
	macLine = regexp.MustCompile(`^(?:MWDSCap\s+)?([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(.*)$`)
	rssiTok = regexp.MustCompile(`^-?\d+/-?\d+(?:/-?\d+)*$`)
	connRE  = regexp.MustCompile(`,\s*(\d+),\s*\d+%`)
	// tableHead is the table's column header (the newest one is parsed).
	tableHead = regexp.MustCompile(`(?m)^\S*\s*MAC\s+MODE\s+AID\s+BSS\b`)
)

// parseMacTable parses the newest station table of the kernel log:
//
//	MAC                MODE AID  BSS PSM WMM MIMOPS RSSI0/1/2 PhMd  BW  MCS   SGI   STBC  Idle   Rate   QosMap
//	MWDSCap C0:F8:53:17:23:A7  200011    0   0   1   3      -70/-83/0  HTMIX 20M 7     1   1    300    72     0         , 2243253, 100%
//	NO                                                              MaxCap:HTMIX     20M   7     1   1    -    72
//
// Columns are found from the RSSI field (MODE and AID print as one token):
// BSS is 4 before it; PhMd, BW, MCS follow it, Rate is 7 after it (Mbit/s);
// the trailing ", <seconds>, <n>%" is the association time.
func parseMacTable(log string) []sta {
	i := -1
	if m := tableHead.FindAllStringIndex(log, -1); len(m) > 0 {
		i = m[len(m)-1][0]
	}
	if i < 0 {
		return nil
	}
	var out []sta
	seen := map[string]bool{}
	for _, l := range strings.Split(log[i:], "\n") {
		l = strings.TrimSpace(stripPrintkPrefix(l))
		m := macLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		mac := strings.ToLower(m[1])
		if seen[mac] {
			continue
		}
		rest := m[2]
		conn := int64(0)
		if c := connRE.FindStringSubmatch(rest); c != nil {
			conn, _ = strconv.ParseInt(c[1], 10, 64)
			rest = rest[:strings.Index(rest, c[0])]
		}
		tok := strings.Fields(rest)
		k := -1
		for j, t := range tok {
			if rssiTok.MatchString(t) {
				k = j
				break
			}
		}
		if k < 4 || k+7 >= len(tok) {
			continue
		}
		st := sta{Station: apstate.Station{MAC: mac, Authorized: true, Connected: conn, Noise: -95}}
		st.bss, _ = strconv.Atoi(tok[k-4])
		best := 0
		for _, r := range strings.Split(tok[k], "/") {
			v, _ := strconv.Atoi(r)
			if v != 0 && (best == 0 || v > best) {
				best = v
			}
		}
		st.Signal, st.SignalAvg = best, best
		phy := strings.ToUpper(tok[k+1])
		st.HT = strings.Contains(phy, "HT")
		st.VHT = strings.Contains(phy, "VHT")
		st.HE = strings.Contains(phy, "HE")
		st.MHz, _ = strconv.Atoi(strings.TrimSuffix(strings.ToUpper(tok[k+2]), "M"))
		if mcs, err := strconv.Atoi(tok[k+3]); err == nil && st.HT && !st.VHT {
			st.NSS = 1 + mcs/8
		}
		if rate, err := strconv.Atoi(tok[k+7]); err == nil {
			st.TxRate, st.RxRate = rate*1000, rate*1000
		}
		seen[mac] = true
		out = append(out, st)
	}
	return out
}

// stripPrintkPrefix drops a "<6>" level or "[  12.345]" time prefix.
func stripPrintkPrefix(l string) string {
	if strings.HasPrefix(l, "<") {
		if j := strings.Index(l, ">"); j > 0 && j < 4 {
			l = l[j+1:]
		}
	}
	if strings.HasPrefix(l, "[") {
		if j := strings.Index(l, "]"); j > 0 {
			l = l[j+1:]
		}
	}
	return l
}

// ------------------------------------------------------- station counters

// staCount is one row of `show stacountinfo`.
type staCount struct{ txPkts, rxPkts, txBytes, rxBytes int64 }

var (
	countHead = regexp.MustCompile(`(?m)^\S*\s*MAC\s+AID\s+TxPackets\s+RxPackets\s+TxBytes\s+RxBytes`)
	countLine = regexp.MustCompile(`^([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+\d+\s+(-?\d+)\s+(-?\d+)\s+(-?\d+)\s+(-?\d+)`)
)

// parseStaCount parses the newest `show stacountinfo` table of the kernel
// log (MT7603, 2026-11-19), keyed by lower-case MAC:
//
//	MAC                AID TxPackets   RxPackets   TxBytes     RxBytes     TP(Tx)      TP(Rx)
//	FC:3C:D7:31:00:CD  1   386         413         23892       88619       23892886190Mbps       0Mbps
//
// The counts run from the station's association (they grow between reads).
// TxPackets/TxBytes are the AP's transmit to the station. The driver prints
// them with %ld on a 32-bit CPU, so a count past 2^31 prints negative and is
// taken modulo 2^32. The TP columns run into each other and are not read.
func parseStaCount(log string) map[string]staCount {
	m := countHead.FindAllStringIndex(log, -1)
	if len(m) == 0 {
		return nil
	}
	out := map[string]staCount{}
	for _, l := range strings.Split(log[m[len(m)-1][1]:], "\n") {
		f := countLine.FindStringSubmatch(strings.TrimSpace(stripPrintkPrefix(l)))
		if f == nil {
			continue
		}
		var v [4]int64
		for i := range v {
			v[i], _ = strconv.ParseInt(f[2+i], 10, 64)
			if v[i] < 0 {
				v[i] += 1 << 32
			}
		}
		out[strings.ToLower(f[1])] = staCount{txPkts: v[0], rxPkts: v[1], txBytes: v[2], rxBytes: v[3]}
	}
	return out
}

// ------------------------------------------------------------- busy time

// busySample is a channel reading, µs per second: busy time and the AP's
// own transmit and receive airtime. The MT7663 gives its last second
// (parseBgndScanInfo), the MT7603 its busy time since its previous
// `show mibinfo` (mibBusy).
type busySample struct{ busy, tx, rx int64 }

var bgndRE = regexp.MustCompile(`(?m)One sec (channel busy time|My Tx Airtime|My Rx Airtime) = (\d+)`)

// parseBgndScanInfo reads the newest `show bgndscaninfo` block (MT7663,
// 2026-11-19):
//
//	===== Status / Statistic =====
//	 One sec channel busy time = 5996
//	 One sec primary channel busy time = 1322
//	 One sec My Tx Airtime = 4818
//	 One sec My Rx Airtime = 0
//
// Each is microseconds in the last second (the block's "Channel busy time
// Threshold = 600000" is 60 %). "channel busy" covers the whole width and
// the AP's own transmissions (busy - own tx stays >= the primary channel's
// busy time), so it is the total; the primary channel figure is not used.
func parseBgndScanInfo(log string) (busySample, bool) {
	i := strings.LastIndex(log, "Status / Statistic")
	if i < 0 {
		return busySample{}, false
	}
	var b busySample
	var have int
	for _, m := range bgndRE.FindAllStringSubmatch(log[i:], -1) {
		v, _ := strconv.ParseInt(m[2], 10, 64)
		v = min(max(v, 0), 1_000_000)
		switch m[1] {
		case "channel busy time":
			b.busy, have = v, have|1
		case "My Tx Airtime":
			b.tx, have = v, have|2
		case "My Rx Airtime":
			b.rx, have = v, have|4
		}
	}
	if have != 7 {
		return busySample{}, false
	}
	b.busy = max(b.busy, b.tx+b.rx)
	return b, true
}

// staAirtime estimates the AP's own airtime from what each station sent
// and received in dt (its byte counters, last and next) at its rate, µs
// per second: tx the bytes sent to it at st.TxRate, rx the bytes it sent
// at st.RxRate (the station table's one rate). The MT7603 gives no own
// airtime at all (its `show mibinfo` has only raw MIB counters,
// 2026-11-20), so cu_self_tx and cu_self_rx are estimated the way the
// counters allow. Beacons, management frames, preambles, acks, retries
// and contention are not counted, so it runs low.
func staAirtime(stas []sta, last, next map[string]staCount, dt time.Duration) (tx, rx int64) {
	if dt <= 0 {
		return 0, 0
	}
	var txSec, rxSec float64
	for _, st := range stas {
		p, ok := last[st.MAC]
		n, ok2 := next[st.MAC]
		if !ok || !ok2 {
			continue // new
		}
		// a counter that went down (re-associated) or did not move adds
		// nothing
		if st.TxRate > 0 && n.txBytes > p.txBytes {
			txSec += float64(n.txBytes-p.txBytes) * 8 / (float64(st.TxRate) * 1000)
		}
		if st.RxRate > 0 && n.rxBytes > p.rxBytes {
			rxSec += float64(n.rxBytes-p.rxBytes) * 8 / (float64(st.RxRate) * 1000)
		}
	}
	per := func(sec float64) int64 { return min(int64(sec/dt.Seconds()*1e6), 1_000_000) }
	return per(txSec), per(rxSec)
}

// withStaAir fills a busy reading's own transmit and receive airtime from
// the station-counter estimate (staAirtime) where the driver gives 0, so
// that the driver's figures stand (the MT7663's own tx; it has no
// per-station counters, so it gets nothing new). The estimated parts are
// scaled down together, in proportion, to fit in what the busy time
// leaves after the driver's own figures.
func withStaAir(b *busySample, tx, rx int64) *busySample {
	if b == nil {
		return nil
	}
	if b.tx != 0 || tx < 0 {
		tx = 0
	}
	if b.rx != 0 || rx < 0 {
		rx = 0
	}
	if tx == 0 && rx == 0 {
		return b
	}
	if room := max(b.busy-b.tx-b.rx, 0); tx+rx > room {
		sum := tx + rx
		tx, rx = tx*room/sum, rx*room/sum
	}
	e := *b
	e.tx += tx
	e.rx += rx
	return &e
}

// --------------------------------------------- busy time (MT7603 mibinfo)

// mibInterval: `show mibinfo` (60-odd kernel-log lines a call) is asked at
// most this often per radio, Invalidate or not (a new channel's busy time
// shows within it); between, the last reading stands. The read clears the
// MIB counters (checked on the unit, 2026-11-20: Prim CCA Time read
// 263203, 541770, 1243292 and 253764 µs at 1.07, 3.12, 6.06 and 1.07 s
// apart, 17-25 % each time), so a manual `iwpriv ra0 show mibinfo` on the
// unit steals one interval: the agent's next reading holds only the time
// since that run, over the whole interval, and reads low once.
const mibInterval = 10 * time.Second

// mibMaxGap: a longer time since the previous ask gives no reading. The
// counter is 24 bits of µs (16.8 s): past a minute it saturates at 28 %
// busy, and the reading would stand for a long time it averages over.
const mibMaxGap = time.Minute

// mibSaturated: Prim CCA Time at or past this has run out of bits
// (0xffffff was read on the unit).
const mibSaturated = 0xffffff

// mibReading is a radio's last `show mibinfo` ask.
type mibReading struct {
	asked time.Time   // the Collect that asked (mibInterval)
	at    time.Time   // when the request was made (the next reading's interval)
	busy  *busySample // nil: no busy time (see mibBusy, or the radio went down since)
	// gap: the radio was down, behind the restart gate, or off its
	// channel for a site survey (Scan) since at (or there was no ask
	// yet): the next ask has no previous one to measure from
	gap bool
}

var primCCA = regexp.MustCompile(`Prim CCA Time=0x([0-9A-Fa-f]+)`)

// parseMibInfo reads the last Prim CCA Time of `iwpriv ra0 show mibinfo`
// (MT7603, 2026-11-20; stdout is only "ra0       show:mibinfo", the rest
// goes to the kernel log, tab-indented):
//
//	MIB Status Control=0x7fffffff
//	MIB Per-BSS Status Control=0x3f3f3f3f
//	===Phy/Timing Related Counters===
//		ChannelIdleCnt=0xffff
//		CCA_NAV_Tx_Time=0x11fd
//		Rx_MDRDY_CNT=0x1fda
//		Prim CCA Time=0x45b5af
//		Sec CCA Time=0x0
//		Prim ED Time=0x0
//	===Tx Related Counters(Generic)===
//	...
//
// followed by the AMPDU, Rx and per-BSS counters, none of which are read.
// Prim CCA Time is the µs the primary channel was busy since the previous
// read (which cleared it), 24 bits. ChannelIdleCnt and CCA_NAV_Tx_Time
// are 16 bits and saturate or wrap within a second: not used. There is no
// own-airtime counter (staAirtime).
func parseMibInfo(log string) (int64, bool) {
	m := primCCA.FindAllStringSubmatch(log, -1)
	if len(m) == 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(m[len(m)-1][1], 16, 32)
	if err != nil {
		return 0, false
	}
	return int64(v), true
}

// mibBusy is the busy time one `show mibinfo` ask gives: added and
// anchored are newLogAnchored(before, after) around the request, since
// the time since the previous ask (0: none). The busy time is Prim CCA
// Time over since, µs per second (at most 1e6); no own airtime (0, filled
// by withStaAir). No reading (nil): no previous ask, since over mibMaxGap,
// not anchored (added is then the whole log, whose last block may be an
// older call's or someone else's), no block, or a saturated counter.
func mibBusy(added string, anchored bool, since time.Duration) *busySample {
	us := since.Microseconds()
	if !anchored || us <= 0 || since > mibMaxGap {
		return nil
	}
	v, ok := parseMibInfo(added)
	if !ok || v >= mibSaturated {
		return nil
	}
	return &busySample{busy: min(v*1_000_000/us, 1_000_000)}
}

// surveyAcc turns the driver's busy readings (rates) into the cumulative
// survey counters the inform takes deltas of (Radio.Survey, ms): each
// Collect adds the time since the previous one at the newest reading's
// rates. The counters never go back (a drop would read as 0 % in the next
// inform): time without a reading is not added.
type surveyAcc struct {
	last                 time.Time // zero: no reading at the last Collect
	active, busy, tx, rx float64   // ms
	// measured: an interval was added since the last Collect without a
	// reading (until then the radio reports no channel use)
	measured bool
}

// surveyGap: a longer pause between Collects is not integrated (the
// reading would stand for minutes it never saw).
const surveyGap = 5 * time.Minute

// integrate updates the band's counters with the reading b (nil: none:
// the radio is down or its driver gave no busy time) and returns them, and
// whether the radio reports channel use (Radio.NoSurvey): only once a
// reading has measured an interval since the last Collect without one, so
// a missing reading, or the first one after it, is left out of the inform,
// never sent as 0 %. c.mu is held.
func (c *Collector) integrate(band string, b *busySample, now time.Time) (apstate.Survey, bool) {
	a := c.survey[band]
	if a == nil {
		a = &surveyAcc{}
		c.survey[band] = a
	}
	dt := now.Sub(a.last)
	switch {
	case b == nil:
		a.last, a.measured = time.Time{}, false
	case !a.last.IsZero() && dt > 0 && dt < surveyGap:
		ms := float64(dt) / float64(time.Millisecond)
		a.active += ms
		a.busy += ms * float64(b.busy) / 1e6
		a.tx += ms * float64(b.tx) / 1e6
		a.rx += ms * float64(b.rx) / 1e6
		a.last, a.measured = now, true
	case !a.last.IsZero() && dt == 0:
		// the same instant again: nothing to add
	default:
		// the first reading, or after a long pause: from here on
		a.last, a.measured = now, false
	}
	return apstate.Survey{Active: int64(a.active), Busy: int64(a.busy), Tx: int64(a.tx), Rx: int64(a.rx)}, a.measured
}
