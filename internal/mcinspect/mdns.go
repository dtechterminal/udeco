// SPDX-License-Identifier: GPL-2.0-or-later

package mcinspect

import (
	"encoding/binary"
	"strings"
)

// MDNS is what accounting needs from one mDNS message: the record types of
// its questions and records (mdns_rr) and the DNS-SD service names it asks
// about or announces (services).
type MDNS struct {
	RR       []string // one entry per question/record of a known type
	Services []string // distinct names whose first label starts with '_' (lower case)
}

// rrNames are the record types counted in mdns_rr (the U6 Pro reports A,
// AAAA, ANY, PTR, SRV and TXT; the rest are the other types mDNS uses).
var rrNames = map[uint16]string{
	1: "A", 5: "CNAME", 12: "PTR", 13: "HINFO", 16: "TXT", 28: "AAAA", 33: "SRV", 47: "NSEC", 255: "ANY",
}

// maxRecords bounds the work one message can cause.
const maxRecords = 64

// ParseMDNS parses a DNS message (the UDP payload). It returns nil for
// anything that is not a well-formed message; a message cut short keeps
// what was read before the cut.
func ParseMDNS(b []byte) *MDNS {
	if len(b) < 12 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	rr := int(binary.BigEndian.Uint16(b[6:8])) + int(binary.BigEndian.Uint16(b[8:10])) + int(binary.BigEndian.Uint16(b[10:12]))
	m := &MDNS{}
	seen := map[string]bool{}
	add := func(name string, typ uint16) {
		if n, ok := rrNames[typ]; ok {
			m.RR = append(m.RR, n)
		}
		if strings.HasPrefix(name, "_") && !seen[name] && len(m.Services) < maxRecords {
			seen[name] = true
			m.Services = append(m.Services, name)
		}
	}
	off := 12
	for i := 0; i < qd && i < maxRecords; i++ {
		name, n, ok := readName(b, off)
		if !ok || n+4 > len(b) {
			return m
		}
		add(name, binary.BigEndian.Uint16(b[n:n+2]))
		off = n + 4
	}
	for i := 0; i < rr && i < maxRecords; i++ {
		name, n, ok := readName(b, off)
		if !ok || n+10 > len(b) {
			return m
		}
		typ := binary.BigEndian.Uint16(b[n : n+2])
		rdlen := int(binary.BigEndian.Uint16(b[n+8 : n+10]))
		off = n + 10 + rdlen
		if off > len(b) {
			return m // the record is cut: not counted
		}
		if typ != 41 { // OPT is a pseudo-record
			add(name, typ)
		}
	}
	return m
}

// readName reads a (possibly compressed) domain name at off and returns it
// in lower case without the trailing dot, and the offset after it. It is
// not internal/mdnsbr's readName: that one refuses a forward pointer and a
// name over 255 octets, which this one takes.
func readName(b []byte, off int) (string, int, bool) {
	var labels []string
	end, jumps := -1, 0
	for {
		if off >= len(b) {
			return "", 0, false
		}
		l := int(b[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.ToLower(strings.Join(labels, ".")), end, true
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) || jumps > 16 {
				return "", 0, false
			}
			if end < 0 {
				end = off + 2
			}
			off = (l&0x3f)<<8 | int(b[off+1])
			jumps++
		case l&0xc0 != 0:
			return "", 0, false
		default:
			if off+1+l > len(b) || len(labels) > 127 {
				return "", 0, false
			}
			labels = append(labels, string(b[off+1:off+1+l]))
			off += 1 + l
		}
	}
}
