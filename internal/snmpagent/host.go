// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// The unit's interfaces, load and memory, read from /proc and /sys (file
// reads only, nothing is executed), for IF-MIB and UCD-SNMP-MIB.

// netIf is one interface of /proc/net/dev.
type netIf struct {
	Index       int
	Name        string
	Type        int // IANAifType
	MTU         int
	SpeedMbps   int64 // 0 = unknown
	MAC         []byte
	AdminUp     bool
	Oper        int // IF-MIB ifOperStatus
	Promisc     bool
	Connector   bool // a physical port
	RxBytes     uint64
	RxPkts      uint64
	RxErrs      uint64
	RxDrop      uint64
	RxMulticast uint64
	TxBytes     uint64
	TxPkts      uint64
	TxErrs      uint64
	TxDrop      uint64
}

const (
	iffUp      = 0x1
	iffRunning = 0x40
	iffPromisc = 0x100
)

// IANAifType values used here.
const (
	ifTypeOther     = 1
	ifTypeEthernet  = 6
	ifTypeLoopback  = 24
	ifTypeIEEE80211 = 71
	ifTypeTunnel    = 131
	ifTypeL2VLAN    = 135
	ifTypeBridge    = 209
)

// host reads the unit below root. Interface counters are widened to 64 bits
// (the kernel's may be 32-bit on this ARMv7 unit): sample is called often
// enough (every counterSample) that a 32-bit counter wraps at most once
// between two readings.
type host struct {
	root string

	mu   sync.Mutex
	wide map[string]*wideCounters // by name + "/" + ifindex
}

type wideCounters struct {
	last, base [9]uint64
}

func newHost(root string) *host {
	if root == "" {
		root = "/"
	}
	return &host{root: root, wide: map[string]*wideCounters{}}
}

func (h *host) path(p string) string { return filepath.Join(h.root, p) }

func (h *host) readString(p string) string {
	b, err := os.ReadFile(h.path(p))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (h *host) readInt(p string) (int64, bool) {
	n, err := strconv.ParseInt(h.readString(p), 0, 64)
	return n, err == nil
}

// interfaces reads /proc/net/dev and each interface's /sys/class/net entry,
// in ifIndex order.
func (h *host) interfaces() []netIf {
	b, err := os.ReadFile(h.path("/proc/net/dev"))
	if err != nil {
		return nil
	}
	var out []netIf
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if name == "" || len(f) < 16 || strings.ContainsAny(name, "/ ") {
			continue
		}
		var c [16]uint64
		for i := range c {
			c[i], _ = strconv.ParseUint(f[i], 10, 64)
		}
		sys := "/sys/class/net/" + name
		idx, ok := h.readInt(sys + "/ifindex")
		if !ok || idx <= 0 || idx > 1<<31-1 {
			continue
		}
		it := netIf{Index: int(idx), Name: name,
			RxBytes: c[0], RxPkts: c[1], RxErrs: c[2], RxDrop: c[3], RxMulticast: c[7],
			TxBytes: c[8], TxPkts: c[9], TxErrs: c[10], TxDrop: c[11]}
		if m, ok := h.readInt(sys + "/mtu"); ok {
			it.MTU = int(m)
		}
		if s, ok := h.readInt(sys + "/speed"); ok && s > 0 {
			it.SpeedMbps = s
		}
		if hw, err := net.ParseMAC(h.readString(sys + "/address")); err == nil && len(hw) == 6 {
			it.MAC = hw
		}
		flags, _ := h.readInt(sys + "/flags")
		it.AdminUp = flags&iffUp != 0
		it.Promisc = flags&iffPromisc != 0
		it.Oper = operStatus(h.readString(sys+"/operstate"), flags)
		_, err := os.Stat(h.path(sys + "/device"))
		it.Connector = err == nil
		it.Type = h.ifType(name, sys)
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	h.widen(out)
	return out
}

// sample reads the counters so 32-bit wraps are seen (counterSample).
func (h *host) sample() { h.interfaces() }

// widen turns each counter into a 64-bit one: a value lower than the last
// one, where both fit in 32 bits, is a 32-bit wrap. A counter that ever
// exceeds 32 bits is the kernel's own 64-bit one and is left alone.
func (h *host) widen(ifs []netIf) {
	h.mu.Lock()
	defer h.mu.Unlock()
	seen := map[string]bool{}
	for i := range ifs {
		it := &ifs[i]
		key := it.Name + "/" + strconv.Itoa(it.Index)
		seen[key] = true
		w := h.wide[key]
		ptrs := [9]*uint64{&it.RxBytes, &it.RxPkts, &it.RxErrs, &it.RxDrop, &it.RxMulticast, &it.TxBytes, &it.TxPkts, &it.TxErrs, &it.TxDrop}
		if w == nil {
			w = &wideCounters{}
			for k, p := range ptrs {
				w.last[k] = *p
			}
			h.wide[key] = w
			continue
		}
		for k, p := range ptrs {
			v := *p
			if v < w.last[k] && w.last[k] <= 0xffffffff {
				w.base[k] += 1 << 32
			}
			w.last[k] = v
			*p = v + w.base[k]
		}
	}
	for k := range h.wide {
		if !seen[k] {
			delete(h.wide, k)
		}
	}
}

func operStatus(state string, flags int64) int {
	switch state {
	case "up":
		return 1
	case "down":
		return 2
	case "testing":
		return 3
	case "dormant":
		return 5
	case "notpresent":
		return 6
	case "lowerlayerdown":
		return 7
	}
	// "unknown" (many drivers, the Broadcom vifs, bridges): the flags decide,
	// as net-snmp does
	if flags&iffUp != 0 && flags&iffRunning != 0 {
		return 1
	}
	return 2
}

func (h *host) ifType(name, sys string) int {
	t, _ := h.readInt(sys + "/type")
	switch {
	case t == 772:
		return ifTypeLoopback
	case t == 778 || t == 776 || t == 768 || strings.HasPrefix(name, "gre") || strings.HasPrefix(name, "ip6tnl") || strings.HasPrefix(name, "sit"):
		return ifTypeTunnel
	case t != 1:
		return ifTypeOther
	}
	if _, err := os.Stat(h.path(sys + "/bridge")); err == nil {
		return ifTypeBridge
	}
	if _, err := os.Stat(h.path(sys + "/wireless")); err == nil || strings.HasPrefix(name, "wl") {
		return ifTypeIEEE80211
	}
	if strings.Contains(name, ".") {
		return ifTypeL2VLAN
	}
	return ifTypeEthernet
}

// load is /proc/loadavg's three averages.
func (h *host) load() ([3]float64, bool) {
	var l [3]float64
	f := strings.Fields(h.readString("/proc/loadavg"))
	if len(f) < 3 {
		return l, false
	}
	for i := range l {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			return l, false
		}
		l[i] = v
	}
	return l, true
}

// meminfo is /proc/meminfo in kB.
func (h *host) meminfo() map[string]int64 {
	m := map[string]int64{}
	for _, line := range strings.Split(h.readString("/proc/meminfo"), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		if n, err := strconv.ParseInt(f[0], 10, 64); err == nil {
			m[k] = n
		}
	}
	return m
}
