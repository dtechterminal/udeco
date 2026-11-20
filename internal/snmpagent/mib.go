// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// The objects served, all read-only:
//
//   - SNMPv2-MIB system (1.3.6.1.2.1.1) and snmp (1.3.6.1.2.1.11) groups;
//   - IF-MIB ifNumber, ifTable and ifXTable for every /proc/net/dev interface;
//   - SNMP-FRAMEWORK-MIB snmpEngine and SNMP-USER-BASED-SM-MIB usmStats;
//   - UCD-SNMP-MIB laTable and memory (a UAP's snmpd has "load 8.0 8.0 8.0");
//   - UBNT-UniFi-MIB (1.3.6.1.4.1.41112.1.6): unifiRadioTable,
//     unifiVapTable, unifiIfTable and unifiApSystem, from the inform fields
//     (the MIB LibreNMS and others poll UniFi APs with).
//
// sysObjectID is net-snmp's Linux one (a UAP runs net-snmp) and sysDescr
// starts with the display model, so NMS detection of a UniFi AP (sysObjectID
// .1.3.6.1.4.1.8072.3.2.10 with sysDescr /^U6/) holds.

var (
	oidSystem       = mustOID("1.3.6.1.2.1.1")
	oidIfNumber     = mustOID("1.3.6.1.2.1.2.1.0")
	oidIfEntry      = mustOID("1.3.6.1.2.1.2.2.1")
	oidIfXEntry     = mustOID("1.3.6.1.2.1.31.1.1.1")
	oidSNMP         = mustOID("1.3.6.1.2.1.11")
	oidEngine       = mustOID("1.3.6.1.6.3.10.2.1")
	oidUsmStats     = mustOID("1.3.6.1.6.3.15.1.1")
	oidLaEntry      = mustOID("1.3.6.1.4.1.2021.10.1")
	oidMemory       = mustOID("1.3.6.1.4.1.2021.4")
	oidUniFi        = mustOID("1.3.6.1.4.1.41112.1.6")
	oidNetSNMPLinux = mustOID("1.3.6.1.4.1.8072.3.2.10")
	zeroDotZero     = OID{0, 0}
)

// usmStats* counters (SNMP-USER-BASED-SM-MIB), the varbinds of USM reports.
const (
	usmUnsupportedSecLevels = 1
	usmNotInTimeWindows     = 2
	usmUnknownUserNames     = 3
	usmUnknownEngineIDs     = 4
	usmWrongDigests         = 5
	usmDecryptionErrors     = 6
)

// sysServices: what a UAP's ubntconf writes (sysservices 79).
const sysServices = 79

// loadLimit is laConfig (the UAP's "load 8.0 8.0 8.0").
const loadLimit = 8.0

type entry struct {
	oid OID
	v   Value
}

// tree is a sorted, immutable set of objects.
type tree []entry

type builder struct{ e []entry }

func (b *builder) add(o OID, v Value) { b.e = append(b.e, entry{o, v}) }

func (b *builder) tree() tree {
	t := tree(b.e)
	sort.Slice(t, func(i, j int) bool { return t[i].oid.Compare(t[j].oid) < 0 })
	out := t[:0]
	for i, e := range t {
		if i > 0 && e.oid.Compare(out[len(out)-1].oid) == 0 {
			continue
		}
		out = append(out, e)
	}
	return out
}

// get is the object o exactly.
func (t tree) get(o OID) (Value, bool) {
	i := sort.Search(len(t), func(i int) bool { return t[i].oid.Compare(o) >= 0 })
	if i < len(t) && t[i].oid.Compare(o) == 0 {
		return t[i].v, true
	}
	return Value{}, false
}

// next is the first object after o (skip64: not a Counter64, for SNMPv1).
func (t tree) next(o OID, skip64 bool) (entry, bool) {
	i := sort.Search(len(t), func(i int) bool { return t[i].oid.Compare(o) > 0 })
	for ; i < len(t); i++ {
		if skip64 && t[i].v.Tag == tagCounter64 {
			continue
		}
		return t[i], true
	}
	return entry{}, false
}

// hasPrefix reports whether any object lies below o (GET's noSuchObject
// versus noSuchInstance).
func (t tree) hasPrefix(o OID) bool {
	i := sort.Search(len(t), func(i int) bool { return t[i].oid.Compare(o) >= 0 })
	return i < len(t) && t[i].oid.HasPrefix(o)
}

// mibInput is everything one tree is built from.
type mibInput struct {
	cfg      *Config
	view     *View
	ifs      []netIf
	load     [3]float64
	loadOK   bool
	mem      map[string]int64
	upTicks  uint64 // sysUpTime, centiseconds
	engineID []byte
	boots    int64
	etime    int64
	stats    statsSnapshot
}

// DefaultDescr stands in for a display model nobody set: sysDescr here,
// and the agent's own fallbacks (cmd/udeco-ap: the SNMP view's model and
// the syslog host name). It is the display name of the model a Deco is
// reported as (the catalogue's entry for models.DecoAgentModel; this
// package does not import models, the agent's test compares the two).
const DefaultDescr = "U6-Lite"

func buildTree(in mibInput) tree {
	var b builder
	v := in.view
	if v == nil {
		v = &View{}
	}
	// system
	descr := strings.TrimSpace(v.Model + " " + v.Version)
	if descr == "" {
		descr = DefaultDescr
	}
	sys := func(n uint32, val Value) { b.add(oidSystem.Append(n, 0), val) }
	sys(1, OctetString(display(descr)))
	sys(2, ObjectID(oidNetSNMPLinux))
	sys(3, TimeTicks(in.upTicks))
	var contact, location string
	if in.cfg != nil {
		contact, location = in.cfg.Contact, in.cfg.Location
	}
	sys(4, OctetString(contact))
	sys(5, OctetString(display(v.Hostname)))
	sys(6, OctetString(location))
	sys(7, Integer(sysServices))

	// interfaces
	b.add(oidIfNumber, Integer(int64(len(in.ifs))))
	for _, it := range in.ifs {
		idx := uint32(it.Index)
		col := func(c uint32, val Value) { b.add(oidIfEntry.Append(c, idx), val) }
		xcol := func(c uint32, val Value) { b.add(oidIfXEntry.Append(c, idx), val) }
		speed := it.SpeedMbps * 1_000_000
		col(1, Integer(int64(it.Index)))
		col(2, OctetString(it.Name))
		col(3, Integer(int64(it.Type)))
		col(4, Integer(int64(it.MTU)))
		col(5, Gauge32(speed))
		col(6, Octets(it.MAC))
		col(7, Integer(map[bool]int64{true: 1, false: 2}[it.AdminUp]))
		col(8, Integer(int64(it.Oper)))
		col(9, TimeTicks(0))
		inUcast := it.RxPkts - min(it.RxPkts, it.RxMulticast)
		col(10, Counter32(it.RxBytes))
		col(11, Counter32(inUcast))
		col(12, Counter32(it.RxMulticast))
		col(13, Counter32(it.RxDrop))
		col(14, Counter32(it.RxErrs))
		col(15, Counter32(0))
		col(16, Counter32(it.TxBytes))
		col(17, Counter32(it.TxPkts))
		col(18, Counter32(0))
		col(19, Counter32(it.TxDrop))
		col(20, Counter32(it.TxErrs))
		col(21, Gauge32(0))
		col(22, ObjectID(zeroDotZero))
		xcol(1, OctetString(it.Name))
		xcol(2, Counter32(it.RxMulticast))
		xcol(3, Counter32(0))
		xcol(4, Counter32(0))
		xcol(5, Counter32(0))
		xcol(6, Counter64(it.RxBytes))
		xcol(7, Counter64(inUcast))
		xcol(8, Counter64(it.RxMulticast))
		xcol(9, Counter64(0))
		xcol(10, Counter64(it.TxBytes))
		xcol(11, Counter64(it.TxPkts))
		xcol(12, Counter64(0))
		xcol(13, Counter64(0))
		xcol(14, Integer(2)) // ifLinkUpDownTrapEnable: disabled (no traps)
		xcol(15, Gauge32(it.SpeedMbps))
		xcol(16, Truth(it.Promisc))
		xcol(17, Truth(it.Connector))
		xcol(18, OctetString(""))
		xcol(19, TimeTicks(0))
	}

	// snmp group
	s := in.stats
	snmp := func(n uint32, val Value) { b.add(oidSNMP.Append(n, 0), val) }
	snmp(1, Counter32(s.inPkts))
	snmp(2, Counter32(s.outPkts))
	snmp(3, Counter32(s.badVersions))
	snmp(4, Counter32(s.badCommunity))
	snmp(5, Counter32(0)) // snmpInBadCommunityUses
	snmp(6, Counter32(s.parseErrs))
	snmp(30, Integer(2)) // snmpEnableAuthenTraps: disabled
	snmp(31, Counter32(s.silentDrops))
	snmp(32, Counter32(0)) // snmpProxyDrops

	// snmpEngine, usmStats
	if len(in.engineID) > 0 {
		b.add(oidEngine.Append(1, 0), Octets(in.engineID))
		b.add(oidEngine.Append(2, 0), Integer(in.boots))
		b.add(oidEngine.Append(3, 0), Integer(in.etime))
		b.add(oidEngine.Append(4, 0), Integer(maxMsgSize))
	}
	for i, c := range s.usm {
		b.add(oidUsmStats.Append(uint32(i+1), 0), Counter32(c))
	}

	// UCD laTable, memory
	if in.loadOK {
		names := [3]string{"Load-1", "Load-5", "Load-15"}
		for i, l := range in.load {
			idx := uint32(i + 1)
			la := func(c uint32, val Value) { b.add(oidLaEntry.Append(c, idx), val) }
			la(1, Integer(int64(idx)))
			la(2, OctetString(names[i]))
			la(3, OctetString(fmt.Sprintf("%.2f", l)))
			la(4, OctetString(fmt.Sprintf("%.2f", loadLimit)))
			la(5, Integer(int64(l*100+0.5)))
			over := l > loadLimit
			la(100, Integer(map[bool]int64{true: 1, false: 0}[over]))
			msg := ""
			if over {
				msg = fmt.Sprintf("%d min Load Average too high (= %.2f)", [3]int{1, 5, 15}[i], l)
			}
			la(101, OctetString(msg))
		}
	}
	if m := in.mem; m["MemTotal"] > 0 {
		mem := func(n uint32, val Value) { b.add(oidMemory.Append(n, 0), val) }
		clamp := func(x int64) Value { return Integer(max(0, min(x, 1<<31-1))) }
		avail := m["MemFree"]
		if a, ok := m["MemAvailable"]; ok {
			avail = a
		}
		mem(1, Integer(0))
		mem(2, OctetString("swap"))
		mem(3, clamp(m["SwapTotal"]))
		mem(4, clamp(m["SwapFree"]))
		mem(5, clamp(m["MemTotal"]))
		mem(6, clamp(avail))
		mem(11, clamp(avail+m["SwapFree"]))
		mem(12, clamp(16000))
		mem(13, clamp(m["Shmem"]))
		mem(14, clamp(m["Buffers"]))
		mem(15, clamp(m["Cached"]))
		mem(100, Integer(0))
		mem(101, OctetString(""))
	}

	// UBNT-UniFi-MIB
	radio := oidUniFi.Append(1, 1, 1) // unifiRadioEntry
	for i, r := range v.Radios {
		idx := uint32(i + 1)
		col := func(c uint32, val Value) { b.add(radio.Append(c, idx), val) }
		col(1, Integer(int64(idx)))
		col(2, OctetString(r.Name))
		col(3, OctetString(r.Band))
		col(4, Counter32(uint64(max(0, r.RxPackets))))
		col(5, Counter32(uint64(max(0, r.TxPackets))))
		col(6, Integer(r.CuTotal))
		col(7, Integer(r.CuSelfRx))
		col(8, Integer(r.CuSelfTx))
		col(9, Integer(r.CuInterf))
	}
	vap := oidUniFi.Append(1, 2, 1) // unifiVapEntry
	for i, r := range v.VAPs {
		idx := uint32(i + 1)
		col := func(c uint32, val Value) { b.add(vap.Append(c, idx), val) }
		c32 := func(x int64) Value { return Counter32(uint64(max(0, x))) }
		usage := "user"
		if r.Guest {
			usage = "guest"
		}
		col(1, Integer(int64(idx)))
		col(2, Octets(r.BSSID))
		col(3, Integer(r.CCQ))
		col(4, Integer(r.Channel))
		col(5, Integer(r.ExtChannel))
		col(6, OctetString(r.ESSID))
		col(7, OctetString(r.Name))
		col(8, Integer(r.NumSta))
		col(9, OctetString(r.Radio))
		col(10, c32(r.RxBytes))
		col(11, c32(0))
		col(12, c32(r.RxDropped))
		col(13, c32(r.RxErrors))
		col(14, c32(0))
		col(15, c32(r.RxPackets))
		col(16, c32(r.TxBytes))
		col(17, c32(r.TxDropped))
		col(18, c32(r.TxErrors))
		col(19, c32(r.TxPackets))
		col(20, c32(r.TxRetries))
		col(21, Integer(r.TxPower))
		col(22, Truth(r.Up))
		col(23, OctetString(usage))
	}
	port := oidUniFi.Append(2, 1, 1) // unifiIfEntry
	for i, r := range v.Ports {
		idx := uint32(i + 1)
		col := func(c uint32, val Value) { b.add(port.Append(c, idx), val) }
		c32 := func(x int64) Value { return Counter32(uint64(max(0, x))) }
		col(1, Integer(int64(idx)))
		col(2, Truth(r.FullDuplex))
		col(3, IPAddress(ip4(r.IP)))
		col(4, Octets(r.MAC))
		col(5, OctetString(r.Name))
		col(6, c32(r.RxBytes))
		col(7, c32(r.RxDropped))
		col(8, c32(r.RxErrors))
		col(9, c32(r.RxMulticast))
		col(10, c32(r.RxPackets))
		col(11, Integer(r.Speed))
		col(12, c32(r.TxBytes))
		col(13, c32(r.TxDropped))
		col(14, c32(r.TxErrors))
		col(15, c32(r.TxPackets))
		col(16, Truth(r.Up))
	}
	apSys := oidUniFi.Append(3) // unifiApSystem
	b.add(apSys.Append(1, 0), IPAddress(ip4(v.IP)))
	b.add(apSys.Append(2, 0), Truth(false))
	b.add(apSys.Append(3, 0), OctetString(display(v.Model)))
	b.add(apSys.Append(4, 0), OctetString(v.Uplink))
	b.add(apSys.Append(5, 0), Counter32(uint64(max(0, v.Uptime))))
	b.add(apSys.Append(6, 0), OctetString(display(v.Version)))
	return b.tree()
}

func ip4(s string) []byte {
	if ip := net.ParseIP(s).To4(); ip != nil {
		return ip
	}
	return nil
}
