// SPDX-License-Identifier: GPL-2.0-or-later

// Package lldp is a minimal IEEE 802.1AB LLDP agent for the on-device Deco
// agent (cmd/udeco-ap): it decodes the LLDPDUs heard on the unit's Ethernet
// ports (the UniFi gateway sends them every 30 s, TTL 120) and builds the
// AP's own LLDPDU, sent every 30 s on the uplink the way a real U6-Lite does,
// so the gateway lists the AP as its neighbour on that port
// (docs/deco/topology-and-tplink-scrub.md).
//
// Frames go through a Conn (an AF_PACKET socket for ethertype 0x88cc on
// Linux, a fake in tests); Encode and Decode are pure.
package lldp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

// EtherType of LLDP frames.
const EtherType = 0x88cc

// MulticastMAC is the nearest-bridge group address LLDPDUs are sent to.
var MulticastMAC = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}

// TLV types (802.1AB-2016 table 8-1).
const (
	tlvEnd        = 0
	tlvChassisID  = 1
	tlvPortID     = 2
	tlvTTL        = 3
	tlvPortDescr  = 4
	tlvSysName    = 5
	tlvSysDescr   = 6
	tlvSysCaps    = 7
	tlvMgmtAddr   = 8
	maxTLVLength  = 511
	minFrameBytes = 60 // Ethernet minimum without FCS
)

// Chassis ID subtypes (table 8-2).
const (
	ChassisComponent = 1
	ChassisIfAlias   = 2
	ChassisPort      = 3
	ChassisMAC       = 4
	ChassisNetAddr   = 5
	ChassisIfName    = 6
	ChassisLocal     = 7
)

// Port ID subtypes (table 8-3).
const (
	PortIfAlias   = 1
	PortComponent = 2
	PortMAC       = 3
	PortNetAddr   = 4
	PortIfName    = 5
	PortCircuitID = 6
	PortLocal     = 7
)

// System capability bits (table 8-4).
const (
	CapOther    = 0x0001
	CapRepeater = 0x0002
	CapBridge   = 0x0004
	CapWLANAP   = 0x0008
	CapRouter   = 0x0010
	CapPhone    = 0x0020
	CapDOCSIS   = 0x0040
	CapStation  = 0x0080
)

// Info is what the AP announces about itself.
type Info struct {
	ChassisMAC net.HardwareAddr // chassis ID, subtype MAC (the AP's MAC)
	PortID     string           // port ID, subtype interface name ("eth0")
	PortDescr  string           // "" = PortID
	TTL        uint16           // seconds (120)
	SysName    string           // hostname
	SysDescr   string
	Caps       uint16 // system capabilities (also sent as enabled)
	MgmtIPv4   net.IP // management address; nil = none
	IfIndex    uint32 // interface number in the management address TLV
}

// Encode builds the Ethernet frame (destination MulticastMAC, source src,
// ethertype 0x88cc) carrying info's LLDPDU, padded to the Ethernet minimum.
func Encode(src net.HardwareAddr, info Info) ([]byte, error) {
	if len(src) != 6 || len(info.ChassisMAC) != 6 {
		return nil, errors.New("lldp: source and chassis must be 6-byte MACs")
	}
	if info.PortID == "" {
		return nil, errors.New("lldp: empty port ID")
	}
	b := make([]byte, 0, 256)
	b = append(b, MulticastMAC...)
	b = append(b, src...)
	b = binary.BigEndian.AppendUint16(b, EtherType)
	var err error
	tlv := func(typ int, v []byte) {
		if err != nil {
			return
		}
		if len(v) > maxTLVLength {
			err = fmt.Errorf("lldp: TLV %d too long (%d bytes)", typ, len(v))
			return
		}
		b = binary.BigEndian.AppendUint16(b, uint16(typ)<<9|uint16(len(v)))
		b = append(b, v...)
	}
	tlv(tlvChassisID, append([]byte{ChassisMAC}, info.ChassisMAC...))
	tlv(tlvPortID, append([]byte{PortIfName}, info.PortID...))
	tlv(tlvTTL, binary.BigEndian.AppendUint16(nil, info.TTL))
	descr := info.PortDescr
	if descr == "" {
		descr = info.PortID
	}
	tlv(tlvPortDescr, []byte(descr))
	if info.SysName != "" {
		tlv(tlvSysName, []byte(info.SysName))
	}
	if info.SysDescr != "" {
		tlv(tlvSysDescr, []byte(info.SysDescr))
	}
	if info.Caps != 0 {
		c := binary.BigEndian.AppendUint16(nil, info.Caps)
		tlv(tlvSysCaps, binary.BigEndian.AppendUint16(c, info.Caps))
	}
	if ip := info.MgmtIPv4.To4(); ip != nil {
		v := []byte{5, 1} // address string length (subtype + 4), IANA family IPv4
		v = append(v, ip...)
		v = append(v, 2) // interface numbering: ifIndex
		v = binary.BigEndian.AppendUint32(v, info.IfIndex)
		v = append(v, 0) // no OID
		tlv(tlvMgmtAddr, v)
	}
	tlv(tlvEnd, nil)
	if err != nil {
		return nil, err
	}
	for len(b) < minFrameBytes {
		b = append(b, 0)
	}
	return b, nil
}

// Neighbor is one decoded LLDPDU.
type Neighbor struct {
	SrcMAC           string // Ethernet source of the frame
	ChassisID        string // a MAC as aa:bb:..., else the text (or hex when not printable)
	ChassisIDSubtype int
	PortID           string
	PortIDSubtype    int
	PortDescr        string
	TTL              int // seconds; 0 = the neighbour is leaving (shutdown LLDPDU)
	SysName          string
	SysDescr         string
	Caps, CapsOn     uint16
	MgmtIPs          []string
}

// ChassisSubtypeName is the name lldpd (and the UniFi inform's
// lldp_table.chassis_id_subtype, e.g. "local") gives a chassis ID subtype.
func ChassisSubtypeName(st int) string {
	switch st {
	case ChassisComponent:
		return "chassis"
	case ChassisIfAlias:
		return "ifalias"
	case ChassisPort:
		return "port"
	case ChassisMAC:
		return "mac"
	case ChassisNetAddr:
		return "ip"
	case ChassisIfName:
		return "ifname"
	case ChassisLocal:
		return "local"
	}
	return "unknown"
}

// Decode reads an Ethernet frame holding an LLDPDU (an 802.1Q tag before
// the ethertype is skipped).
func Decode(frame []byte) (Neighbor, error) {
	var n Neighbor
	if len(frame) < 14 {
		return n, errors.New("lldp: short frame")
	}
	n.SrcMAC = net.HardwareAddr(frame[6:12]).String()
	et, p := binary.BigEndian.Uint16(frame[12:14]), frame[14:]
	if et == 0x8100 && len(p) >= 4 {
		et, p = binary.BigEndian.Uint16(p[2:4]), p[4:]
	}
	if et != EtherType {
		return n, fmt.Errorf("lldp: ethertype %#04x", et)
	}
	seen := map[int]bool{}
	for len(p) >= 2 {
		h := binary.BigEndian.Uint16(p)
		typ, l := int(h>>9), int(h&0x1ff)
		p = p[2:]
		if l > len(p) {
			return n, fmt.Errorf("lldp: TLV %d overruns the frame", typ)
		}
		v := p[:l]
		p = p[l:]
		switch typ {
		case tlvEnd:
			p = nil
		case tlvChassisID:
			if l < 2 {
				return n, errors.New("lldp: bad chassis ID")
			}
			n.ChassisIDSubtype = int(v[0])
			n.ChassisID = idString(v[0] == ChassisMAC, v[0] == ChassisNetAddr, v[1:])
		case tlvPortID:
			if l < 2 {
				return n, errors.New("lldp: bad port ID")
			}
			n.PortIDSubtype = int(v[0])
			n.PortID = idString(v[0] == PortMAC, v[0] == PortNetAddr, v[1:])
		case tlvTTL:
			if l < 2 {
				return n, errors.New("lldp: bad TTL")
			}
			n.TTL = int(binary.BigEndian.Uint16(v))
		case tlvPortDescr:
			n.PortDescr = text(v)
		case tlvSysName:
			n.SysName = text(v)
		case tlvSysDescr:
			n.SysDescr = text(v)
		case tlvSysCaps:
			if l >= 4 {
				n.Caps, n.CapsOn = binary.BigEndian.Uint16(v), binary.BigEndian.Uint16(v[2:])
			}
		case tlvMgmtAddr:
			if ip := mgmtAddr(v); ip != "" {
				n.MgmtIPs = append(n.MgmtIPs, ip)
			}
		}
		seen[typ] = true
	}
	if !seen[tlvChassisID] || !seen[tlvPortID] || !seen[tlvTTL] {
		return n, errors.New("lldp: chassis ID, port ID or TTL missing")
	}
	return n, nil
}

// idString renders a chassis or port ID value.
func idString(isMAC, isAddr bool, v []byte) string {
	switch {
	case isMAC && len(v) == 6:
		return net.HardwareAddr(v).String()
	case isAddr && len(v) == 5 && v[0] == 1:
		return net.IP(v[1:]).String()
	case isAddr && len(v) == 17 && v[0] == 2:
		return net.IP(v[1:]).String()
	}
	if utf8.Valid(v) && printable(string(v)) {
		return string(v)
	}
	return fmt.Sprintf("%x", v)
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return s != ""
}

// text is a TLV string, trimmed of NULs and with control characters dropped.
func text(v []byte) string {
	s := strings.TrimRight(string(v), "\x00")
	if !utf8.ValidString(s) {
		return fmt.Sprintf("%x", v)
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// mgmtAddr reads the address of a management address TLV (IPv4 and IPv6).
func mgmtAddr(v []byte) string {
	if len(v) < 2 {
		return ""
	}
	l := int(v[0])
	if l < 2 || 1+l > len(v) {
		return ""
	}
	fam, a := v[1], v[2:1+l]
	switch {
	case fam == 1 && len(a) == 4, fam == 2 && len(a) == 16:
		return net.IP(a).String()
	}
	return ""
}
