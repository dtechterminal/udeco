// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// readSystem fills the system fields of s from /proc, /sys and /tmp under
// Root. /proc/uptime, /proc/loadavg, /proc/stat and /proc/meminfo are
// required; everything else is best effort.
func (c *Collector) readSystem(s *apstate.Snapshot) error {
	up, err := c.readFile("/proc/uptime")
	if err != nil {
		return err
	}
	// whole seconds; as before, an empty file leaves s.Uptime alone and a
	// first field that is no number gives 0 (cmd/udeco-ap's readUptime,
	// the other caller of ParseUptime, reports both)
	if sec, err := apstate.ParseUptime(up); !errors.Is(err, apstate.ErrNoUptime) {
		s.Uptime = int64(sec)
	}
	load, err := c.readFile("/proc/loadavg")
	if err != nil {
		return err
	}
	for i, f := range strings.Fields(load) {
		if i == 3 {
			break
		}
		s.Load[i], _ = strconv.ParseFloat(f, 64)
	}
	st, err := c.readFile("/proc/stat")
	if err != nil {
		return err
	}
	s.CPUTotal, s.CPUIdle = parseProcStat(st)
	mi, err := c.readFile("/proc/meminfo")
	if err != nil {
		return err
	}
	mem := parseMeminfo(mi)
	s.MemTotal, s.MemFree, s.MemBuf, s.MemCache = mem["MemTotal"], mem["MemFree"], mem["Buffers"], mem["Cached"]

	if h, err := c.readFile("/proc/sys/kernel/hostname"); err == nil {
		s.Hostname = strings.TrimSpace(h)
	}
	s.Model, s.Release = c.productInfo()
	if a, err := c.readFile("/sys/class/net/" + c.opt.Bridge + "/address"); err == nil {
		s.MAC = strings.ToLower(strings.TrimSpace(a))
	}
	if addrs, err := c.ifAddrs(c.opt.Bridge); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				s.IP, s.Netmask = n.IP.String(), net.IP(n.Mask).String()
				break
			}
		}
	}
	if r, err := c.readFile("/proc/net/route"); err == nil {
		s.Gateway = parseRoute(r)
	}
	if a, err := c.readFile("/proc/net/arp"); err == nil {
		s.ARP = parseARP(a)
	}
	if b, err := os.ReadFile(c.path("/sys/class/net/" + c.opt.Bridge + "/brforward")); err == nil {
		s.FDB = parseBrforward(b)
	}
	s.Ports = c.readPorts()
	s.LLDP = nil // no lldpd on the Deco
	return nil
}

// ReadSystem fills the system fields of s (uptime, load, memory, the
// bridge's MAC/address/FDB, the gateway, ARP and the wired ports); the
// MediaTek collector shares it.
func (c *Collector) ReadSystem(s *apstate.Snapshot) error { return c.readSystem(s) }

func (c *Collector) readFile(p string) (string, error) {
	b, err := os.ReadFile(c.path(p))
	return string(b), err
}

// parseProcStat sums the first line of /proc/stat, the "cpu" line: total
// jiffies and idle+iowait (apstate.ParseCPULine).
func parseProcStat(s string) (total, idle int64) {
	line, _, _ := strings.Cut(s, "\n")
	return apstate.ParseCPULine(line)
}

// parseMeminfo reads /proc/meminfo into bytes per key.
func parseMeminfo(s string) map[string]int64 {
	m := map[string]int64{}
	for line := range strings.Lines(s) {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			n *= 1024
		}
		m[k] = n
	}
	return m
}

// parseRoute returns the default gateway from /proc/net/route (the row with
// Destination 00000000 and the RTF_GATEWAY flag; Gateway is little-endian
// hex).
func parseRoute(s string) string {
	for line := range strings.Lines(s) {
		f := strings.Fields(line)
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		g, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || g == 0 {
			continue
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(g))
		return net.IP(b[:]).String()
	}
	return ""
}

// parseARP reads /proc/net/arp into mac -> ip (complete entries only:
// internal/openwrt's Parse keeps an incomplete one that has a MAC, so the
// two readers stay two, apstate/proc.go).
func parseARP(s string) map[string]string {
	m := map[string]string{}
	for i, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 4 || f[3] == "00:00:00:00:00:00" || f[2] == "0x0" {
			continue
		}
		m[strings.ToLower(f[3])] = f[0]
	}
	return m
}

// fdbRecordSize is sizeof(struct __fdb_entry) (apstate.ParseBrforward).
const fdbRecordSize = 16

// parseBrforward decodes the binary /sys/class/net/<br>/brforward.
func parseBrforward(b []byte) []apstate.FDBEntry { return apstate.ParseBrforward(b) }

var ethName = regexp.MustCompile(`^eth[0-9]+$`)

// readPorts reads the wired ports (eth0, eth1, ...) from /sys/class/net.
// The Deco's switch (bcmsw) and packet accelerator (archer) are not ports,
// and its eth devices have no /device link, so they are listed by name.
func (c *Collector) readPorts() []apstate.Port {
	names, _ := c.netDevs()
	var ports []apstate.Port
	for _, n := range names {
		if !c.opt.Ports.MatchString(n) {
			continue
		}
		dir := "/sys/class/net/" + n
		p := apstate.Port{Name: n}
		p.MAC = strings.ToLower(c.trimmed(dir + "/address"))
		p.Up = c.trimmed(dir+"/operstate") == "up"
		if p.Up {
			// speed reads -1 or fails with EINVAL while there is no link
			if v, err := strconv.Atoi(c.trimmed(dir + "/speed")); err == nil && v > 0 {
				p.Speed = v
			}
			p.FullDuplex = c.trimmed(dir+"/duplex") == "full"
		}
		stats := c.netStats(n)
		p.RxBytes, p.TxBytes = stats["rx_bytes"], stats["tx_bytes"]
		p.RxPkts, p.TxPkts = stats["rx_packets"], stats["tx_packets"]
		if c.exists("/sys/class/net/" + c.opt.Bridge + "/brif/" + n) {
			if v, err := strconv.ParseInt(c.trimmed(dir+"/brport/port_no"), 0, 32); err == nil {
				p.BridgePort = int(v)
			}
		}
		ports = append(ports, p)
	}
	return ports
}

// netStats reads the interface counters a vap_table row carries
// (apstate.VAPNetdevFields, the /sys/class/net/<dev>/statistics files of
// those names; missing files read as 0).
func (c *Collector) netStats(dev string) map[string]int64 {
	m := make(map[string]int64, len(apstate.VAPNetdevFields))
	for _, k := range apstate.VAPNetdevFields {
		v, _ := strconv.ParseUint(c.trimmed("/sys/class/net/"+dev+"/statistics/"+k), 10, 64)
		m[k] = int64(v)
	}
	return m
}

// netDevs lists /sys/class/net, sorted.
func (c *Collector) netDevs() ([]string, error) {
	ents, err := os.ReadDir(c.path("/sys/class/net"))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (c *Collector) trimmed(p string) string {
	s, _ := c.readFile(p)
	return strings.TrimSpace(s)
}

func (c *Collector) exists(p string) bool {
	_, err := os.Stat(c.path(p))
	return err == nil
}

// productInfo returns the product model ("Deco X20 v2") and firmware
// version ("1.3.0 Build 20250912 Rel. 56370") from TP-Link's getfirm files.
// Only the product_name, product_ver and soft_ver keys are read: the
// product-info file also holds device private keys, which never leave here.
func (c *Collector) productInfo() (model, release string) {
	if s, err := c.readFile("/tmp/getfirm-product-info"); err == nil {
		kv := tpKeyvals(s, "product_name", "product_ver")
		if name := kv["product_name"]; name != "" {
			model = "Deco " + name
			if major, _, _ := strings.Cut(kv["product_ver"], "."); major != "" {
				model += " v" + major
			}
		}
	}
	if s, err := c.readFile("/tmp/getfirm-soft-version"); err == nil {
		release = tpKeyvals(s, "soft_ver")["soft_ver"]
	}
	return model, release
}

// tpKeyvals reads only the wanted keys of a TP-Link "key:value" file.
func tpKeyvals(s string, want ...string) map[string]string {
	m := map[string]string{}
	for line := range strings.Lines(s) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		for _, w := range want {
			if k == w {
				m[k] = strings.TrimSpace(v)
			}
		}
	}
	return m
}

// NormMAC returns the 6-byte MAC address s in lower case with colons
// (net.ParseMAC's spellings; no space around it). It is the one MAC
// normaliser of the Wi-Fi side: internal/bcmwifi's normMAC and
// internal/mtkwifi trim their input and call it. internal/ftpeer.NormMAC
// (unicast and non-zero only), internal/deco.NormMAC (TP-Link's
// spellings) and cmd/udeco-ap's colon-only normMAC take other sets on
// purpose.
func NormMAC(s string) (string, error) {
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("bad MAC %q", s)
	}
	return hw.String(), nil
}

// devPath is the /sys/class/net path of a device.
func devPath(dev string, parts ...string) string {
	return path.Join(append([]string{"/sys/class/net", dev}, parts...)...)
}
