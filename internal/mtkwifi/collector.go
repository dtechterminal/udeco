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
	// scanSem: one site survey (Scan) or survey read (HomeScan) at a time;
	// WithoutScan waits for it
	scanSem  chan struct{}
	scanning atomic.Bool
	seen     map[string]*surveySeen // by band: the cached survey's first sighting
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
		counts:  map[string]map[string]staCount{},
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
			delete(c.cache, main)
			delete(c.survey, rd.Band)
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
		r.Survey = c.integrate(rd.Band, rr.busy, now)
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
}

// driverReads says which kernel-log readings a radio's driver answers at
// the vendor's debug level (read on the unit, 2026-11-19): the MT7603
// (2.4 GHz, mt7603eap.ko) prints `show stacountinfo` (per-station packets
// and bytes) but has no `bgndscaninfo`; the MT7663 (5 GHz, in the kernel)
// prints `show bgndscaninfo` (one-second busy and own airtime) and nothing
// for `show stacountinfo`. Neither prints per-station retries or failures
// (`stacountinfo` has none, `show wtbl` holds only the rate-adaptation
// counters the driver clears as it reads them).
func driverReads(rd RadioDef) (counts, busy bool) {
	return rd.Band == "ng", rd.Band == "na"
}

// reading returns the radio's cached driver reading, read again when it is
// older than CacheTTL, when the set of BSSes up changed, or after
// Invalidate. During a site survey (Scan) the old reading stands: iwconfig
// may show the scan channel then. c.mu is held.
func (c *Collector) reading(ctx context.Context, rd RadioDef, up []string, now time.Time) *radioReading {
	main := rd.Ifaces[0]
	old := c.cache[main]
	if old != nil && (c.scanning.Load() || (now.Sub(old.at) < c.o.CacheTTL && now.Sub(old.at) >= 0 && slices.Equal(old.up, up))) {
		return old
	}
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
	counts, busy := driverReads(rd)
	c.klogRead(ctx, main, rr, counts, busy)
	c.cache[main] = rr
	return rr
}

// klogRead asks the driver for the radio's station table (iwpriv
// get_mac_table writes nothing to stdout), its station counters and its
// busy time, each of which it prints to the kernel log, and parses what
// each request added there. One log read after each request is the next
// one's "before".
func (c *Collector) klogRead(ctx context.Context, main string, rr *radioReading, wantCounts, wantBusy bool) {
	before, err := c.o.klog()
	if err != nil {
		return
	}
	ask := func(what string) (string, bool) {
		if _, err := c.o.Run.Run(ctx, "iwpriv", main, "show", what); err != nil {
			return "", false
		}
		after, err := c.o.klog()
		if err != nil {
			return "", false
		}
		added := newLog(string(before), string(after))
		before = after
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
		c.counts[main] = next
	}
	if wantBusy {
		if log, ok := ask("bgndscaninfo"); ok {
			if b, ok := parseBgndScanInfo(log); ok {
				rr.busy = &b
			}
		}
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
	tail := before
	if len(tail) > 256 {
		tail = tail[len(tail)-256:]
	}
	if tail == "" {
		return after
	}
	if i := strings.LastIndex(after, tail); i >= 0 {
		return after[i+len(tail):]
	}
	return after // the ring wrapped past all of before
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

// Invalidate drops the cached driver readings (after an apply: SSIDs,
// channel and the BSSes up may have changed).
func (c *Collector) Invalidate() {
	c.mu.Lock()
	clear(c.cache)
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

// busySample is the driver's last one-second channel reading, in µs.
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

// surveyAcc turns the driver's one-second readings into the cumulative
// survey counters the inform takes deltas of (Radio.Survey, ms): each
// Collect adds the time since the previous one at the newest reading's
// rates.
type surveyAcc struct {
	last                 time.Time
	active, busy, tx, rx float64 // ms
}

// surveyGap: a longer pause between Collects is not integrated (the
// reading would stand for minutes it never saw).
const surveyGap = 5 * time.Minute

// integrate updates the band's counters with the reading b (nil: none,
// the radio reports no channel use) and returns them. c.mu is held.
func (c *Collector) integrate(band string, b *busySample, now time.Time) apstate.Survey {
	if b == nil {
		delete(c.survey, band)
		return apstate.Survey{}
	}
	a := c.survey[band]
	if a == nil {
		a = &surveyAcc{}
		c.survey[band] = a
	}
	if dt := now.Sub(a.last); !a.last.IsZero() && dt > 0 && dt < surveyGap {
		ms := float64(dt) / float64(time.Millisecond)
		a.active += ms
		a.busy += ms * float64(b.busy) / 1e6
		a.tx += ms * float64(b.tx) / 1e6
		a.rx += ms * float64(b.rx) / 1e6
	}
	a.last = now
	return apstate.Survey{Active: int64(a.active), Busy: int64(a.busy), Tx: int64(a.tx), Rx: int64(a.rx)}
}
