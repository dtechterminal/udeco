// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
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
	// klog reads the kernel log (test hook; nil = klogctl).
	klog func() ([]byte, error)
}

// Collector reads the unit for the inform.
type Collector struct {
	o   CollectorOptions
	sys *wl.Collector
	mu  sync.Mutex // the station table is read through the shared kernel log
}

// ErrUnsupported: scans and spectrum runs are not implemented on this driver.
var ErrUnsupported = errors.New("mtkwifi: not supported on this unit")

// Ports on the JCOW414 are the switch port devices in the bridge.
var portRE = regexp.MustCompile(`^eth[0-9]+\.[0-9]+\.1$`)

type runnerAdapter struct{ r Runner }

func (x runnerAdapter) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return x.r.Run(ctx, name, args...)
}

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
	return &Collector{o: o, sys: wl.New(wl.Options{Root: o.Root, Run: runnerAdapter{o.Run}, Bridge: o.Bridge, Ports: portRE})}
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
	s := &apstate.Snapshot{Time: time.Now()}
	if err := c.sys.ReadSystem(s); err != nil {
		return nil, err
	}
	s.Model = c.o.Model
	s.Release = c.read("/flash/firmwareVersionInfo")
	for _, rd := range c.o.Layout {
		r := apstate.Radio{Iface: rd.Ifaces[0], Phy: rd.Ifaces[0], Mode: "Master", Band: rd.Band,
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
		if !c.isUp(rd.Ifaces[0]) {
			s.Radios = append(s.Radios, r)
			continue
		}
		if out, err := c.o.Run.Run(ctx, "iwconfig", rd.Ifaces[0]); err == nil {
			if m := chanRE.FindSubmatch(out); m != nil {
				r.Channel, _ = strconv.Atoi(string(m[1]))
			}
		}
		stas := c.stations(ctx, rd.Ifaces[0])
		for i, ifc := range rd.Ifaces {
			if !c.isUp(ifc) {
				continue
			}
			v := apstate.Radio{Iface: ifc, Phy: rd.Ifaces[0], Mode: "Master", Band: rd.Band, Channel: r.Channel,
				Width: r.Width, TxPower: r.TxPower, BSSID: strings.ToLower(c.read("/sys/class/net/" + ifc + "/address")),
				Stats: c.netStats(ifc)}
			if out, err := c.o.Run.Run(ctx, "iwconfig", ifc); err == nil {
				if m := essidRE.FindSubmatch(out); m != nil {
					v.SSID = string(m[1])
				}
			}
			for _, st := range stas {
				if st.bss == i {
					v.Stations = append(v.Stations, st.Station)
				}
			}
			r.VAPs = append(r.VAPs, v)
		}
		if len(r.VAPs) > 0 {
			r.SSID, r.BSSID = r.VAPs[0].SSID, r.VAPs[0].BSSID
		}
		s.Radios = append(s.Radios, r)
	}
	return s, nil
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

// stations asks the driver for the radio's station table, which it prints
// to the kernel log (iwpriv get_mac_table writes nothing to stdout), and
// parses the newest table there.
func (c *Collector) stations(ctx context.Context, main string) []sta {
	c.mu.Lock()
	defer c.mu.Unlock()
	before, err := c.o.klog()
	if err != nil {
		return nil
	}
	// "show stainfo" prints the full table at any driver debug level;
	// get_mac_table prints it only at the vendor's (after a radio restart
	// it prints a short table without signal or rate). 2026-11-19.
	if _, err := c.o.Run.Run(ctx, "iwpriv", main, "show", "stainfo"); err != nil {
		return nil
	}
	after, err := c.o.klog()
	if err != nil {
		return nil
	}
	return parseMacTable(newLog(string(before), string(after)))
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

func (c *Collector) Scan(context.Context, string) (*apstate.ScanResult, error) {
	return nil, ErrUnsupported
}

func (c *Collector) HomeScan(context.Context, string) (*apstate.ScanResult, error) {
	return nil, ErrUnsupported
}

func (c *Collector) Spectrum(context.Context, string) (*wl.SpectrumRunner, error) {
	return nil, ErrUnsupported
}

func (c *Collector) WithoutScan(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func (c *Collector) Invalidate() {}

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
