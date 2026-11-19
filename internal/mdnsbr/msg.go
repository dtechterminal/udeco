// SPDX-License-Identifier: GPL-2.0-or-later

package mdnsbr

import (
	"encoding/binary"
	"errors"
	"strings"
)

// DNS message parsing, filtering and re-encoding for the service filter.
//
// A message is parsed whole (names decompressed, with a pointer-loop guard).
// When the filter keeps everything, the original bytes are forwarded; when
// it removes something, the message is rebuilt without name compression
// from the parsed parts. Records whose RDATA may hold compressed names the
// parser does not decode (NS, SOA, MX, ...) cannot be moved safely and are
// left out of a rebuilt message.

const (
	typeA     = 1
	typeCNAME = 5
	typePTR   = 12
	typeAAAA  = 28
	typeSRV   = 33
	typeDNAME = 39
	typeNSEC  = 47

	classQU    = 0x8000 // question: unicast response wanted (RFC 6762 §5.4)
	maxRecords = 256    // per message, all sections
	maxJumps   = 64     // compression pointers followed per name
)

// compressible are the types whose RDATA may hold compressed names (RFC
// 3597 §4, RFC 6762 §18.14) beyond the ones decoded here.
var compressible = map[uint16]bool{2: true, 3: true, 4: true, 6: true, 7: true, 8: true, 9: true, 14: true, 15: true,
	17: true, 18: true, 21: true, 24: true, 26: true, 30: true, 35: true, 36: true, 38: true}

var errMsg = errors.New("mdnsbr: malformed DNS message")

type name []string // labels, as sent (case kept)

func (n name) key() string {
	var b strings.Builder
	for i, l := range n {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strings.ReplaceAll(strings.ToLower(l), ".", `\.`))
	}
	return b.String()
}

// service is the name's service-scoped part: false for a host name (no
// label starts with '_').
func (n name) scoped() bool {
	for _, l := range n {
		if strings.HasPrefix(l, "_") {
			return true
		}
	}
	return false
}

type question struct {
	n          name
	typ, class uint16
	classOff   int // offset of the class field in the original message
}

type record struct {
	n          name
	typ, class uint16
	ttl        uint32
	rdata      []byte // original RDATA
	target     name   // PTR/CNAME/DNAME target, SRV target, NSEC next name
	srvHead    []byte // SRV priority, weight, port
	nsecBitmap []byte
	movable    bool // can be re-encoded
}

type message struct {
	id, flags  uint16
	qs         []question
	an, ns, ar []record
}

func (m *message) response() bool { return m.flags&0x8000 != 0 }

// readName decodes the name at off; it returns the offset after it in the
// original stream.
func readName(b []byte, off int) (name, int, error) {
	var n name
	end := -1
	total := 0
	for jumps := 0; ; {
		if off >= len(b) {
			return nil, 0, errMsg
		}
		l := int(b[off])
		switch l & 0xc0 {
		case 0x00:
			if l == 0 {
				if end < 0 {
					end = off + 1
				}
				return n, end, nil
			}
			if off+1+l > len(b) {
				return nil, 0, errMsg
			}
			total += l + 1
			if total > 255 || len(n) >= 127 {
				return nil, 0, errMsg
			}
			n = append(n, string(b[off+1:off+1+l]))
			off += 1 + l
		case 0xc0:
			if off+1 >= len(b) {
				return nil, 0, errMsg
			}
			if jumps++; jumps > maxJumps {
				return nil, 0, errMsg
			}
			if end < 0 {
				end = off + 2
			}
			p := int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			if p >= off { // only backwards: no loops
				return nil, 0, errMsg
			}
			off = p
		default:
			return nil, 0, errMsg
		}
	}
}

func parseMessage(b []byte) (*message, error) {
	if len(b) < 12 {
		return nil, errMsg
	}
	m := &message{id: binary.BigEndian.Uint16(b), flags: binary.BigEndian.Uint16(b[2:])}
	qd, an, ns, ar := int(binary.BigEndian.Uint16(b[4:])), int(binary.BigEndian.Uint16(b[6:])),
		int(binary.BigEndian.Uint16(b[8:])), int(binary.BigEndian.Uint16(b[10:]))
	if qd+an+ns+ar > maxRecords {
		return nil, errMsg
	}
	off := 12
	for range qd {
		n, o, err := readName(b, off)
		if err != nil || o+4 > len(b) {
			return nil, errMsg
		}
		m.qs = append(m.qs, question{n: n, typ: binary.BigEndian.Uint16(b[o:]), class: binary.BigEndian.Uint16(b[o+2:]), classOff: o + 2})
		off = o + 4
	}
	for s, cnt := range []int{an, ns, ar} {
		for range cnt {
			r, o, err := readRecord(b, off)
			if err != nil {
				return nil, err
			}
			off = o
			switch s {
			case 0:
				m.an = append(m.an, r)
			case 1:
				m.ns = append(m.ns, r)
			default:
				m.ar = append(m.ar, r)
			}
		}
	}
	return m, nil
}

func readRecord(b []byte, off int) (record, int, error) {
	n, o, err := readName(b, off)
	if err != nil || o+10 > len(b) {
		return record{}, 0, errMsg
	}
	r := record{n: n, typ: binary.BigEndian.Uint16(b[o:]), class: binary.BigEndian.Uint16(b[o+2:]),
		ttl: binary.BigEndian.Uint32(b[o+4:])}
	rdl := int(binary.BigEndian.Uint16(b[o+8:]))
	rs := o + 10
	if rs+rdl > len(b) {
		return record{}, 0, errMsg
	}
	r.rdata = b[rs : rs+rdl]
	r.movable = true
	switch r.typ {
	case typePTR, typeCNAME, typeDNAME:
		t, e, err := readName(b, rs)
		if err != nil || e != rs+rdl {
			return record{}, 0, errMsg
		}
		r.target = t
	case typeSRV:
		if rdl < 7 {
			return record{}, 0, errMsg
		}
		t, e, err := readName(b, rs+6)
		if err != nil || e != rs+rdl {
			return record{}, 0, errMsg
		}
		r.srvHead, r.target = b[rs:rs+6], t
	case typeNSEC:
		t, e, err := readName(b, rs)
		if err != nil || e > rs+rdl {
			return record{}, 0, errMsg
		}
		r.target, r.nsecBitmap = t, b[e:rs+rdl]
	default:
		r.movable = !compressible[r.typ]
	}
	return r, rs + rdl, nil
}

// encoder builds a message without compression.
type encoder struct{ b []byte }

func (e *encoder) u16(v uint16) { e.b = binary.BigEndian.AppendUint16(e.b, v) }
func (e *encoder) name(n name) {
	for _, l := range n {
		e.b = append(e.b, byte(len(l)))
		e.b = append(e.b, l...)
	}
	e.b = append(e.b, 0)
}

func (e *encoder) record(r record) {
	e.name(r.n)
	e.u16(r.typ)
	e.u16(r.class)
	e.b = binary.BigEndian.AppendUint32(e.b, r.ttl)
	at := len(e.b)
	e.u16(0)
	switch {
	case r.typ == typeSRV:
		e.b = append(e.b, r.srvHead...)
		e.name(r.target)
	case r.typ == typeNSEC:
		e.name(r.target)
		e.b = append(e.b, r.nsecBitmap...)
	case r.target != nil:
		e.name(r.target)
	default:
		e.b = append(e.b, r.rdata...)
	}
	binary.BigEndian.PutUint16(e.b[at:], uint16(len(e.b)-at-2))
}

func (m *message) encode() []byte {
	e := &encoder{b: make([]byte, 0, 512)}
	e.u16(m.id)
	e.u16(m.flags)
	e.u16(uint16(len(m.qs)))
	e.u16(uint16(len(m.an)))
	e.u16(uint16(len(m.ns)))
	e.u16(uint16(len(m.ar)))
	for _, q := range m.qs {
		e.name(q.n)
		e.u16(q.typ)
		e.u16(q.class)
	}
	for _, sec := range [][]record{m.an, m.ns, m.ar} {
		for _, r := range sec {
			e.record(r)
		}
	}
	return e.b
}

// Policy is a filter's decision on service types.
type Policy struct {
	Allow    bool            // the default
	Services map[string]bool // exceptions (normalised: NormService)
}

// NewPolicy builds a Policy from a Filter.
func NewPolicy(f Filter) *Policy {
	p := &Policy{Allow: f.Allow, Services: map[string]bool{}}
	for _, s := range f.Services {
		p.Services[s] = true
	}
	return p
}

// All reports a policy that lets every message through unchanged.
func (p *Policy) All() bool { return p.Allow && len(p.Services) == 0 }

// service reports whether the service-scoped name n is allowed: the name
// matches a listed type when the type is the name or a suffix of it on a
// label boundary (instance and subtype names: "TV._airplay._tcp.local",
// "_printer._sub._http._tcp.local").
func (p *Policy) service(n name) bool {
	if len(p.Services) == 0 {
		return p.Allow
	}
	ls := make([]string, 0, len(n))
	for _, l := range n {
		ls = append(ls, strings.ToLower(l))
	}
	if len(ls) > 0 && ls[len(ls)-1] == "local" {
		ls = ls[:len(ls)-1]
	}
	for i := range ls {
		if !strings.HasPrefix(ls[i], "_") {
			continue
		}
		if p.Services[strings.Join(ls[i:], ".")] {
			return !p.Allow
		}
	}
	return p.Allow
}

// ServiceAllowed is service for a dotted name (tests, the agent's notes).
func (p *Policy) ServiceAllowed(s string) bool {
	return p.service(name(strings.Split(strings.TrimSuffix(s, "."), ".")))
}

// hostSet answers whether a host name (no service labels) may be shown: a
// host that offers a service the policy allows.
type hostSet interface {
	allowedHost(n name, p *Policy) bool
}

// enumName is the DNS-SD service type enumeration name (RFC 6763 §9).
var enumName = name{"_services", "_dns-sd", "_udp", "local"}

func isEnum(n name) bool { return n.key() == enumName.key() }

// filterMessage applies p to the DNS message b. It returns the bytes to
// forward and false when nothing is left. With clearQU, questions asking for
// a unicast response ask for a multicast one instead (the answer must cross
// the bridge, which only carries multicast). b is never modified.
func filterMessage(b []byte, p *Policy, hosts hostSet, clearQU bool) ([]byte, bool) {
	m, err := parseMessage(b)
	if err != nil {
		return nil, false
	}
	if p.All() {
		if !clearQU {
			return b, len(m.qs)+len(m.an) > 0
		}
		out := append([]byte(nil), b...)
		for _, q := range m.qs {
			if q.class&classQU != 0 {
				binary.BigEndian.PutUint16(out[q.classOff:], q.class&^classQU)
			}
		}
		return out, len(m.qs)+len(m.an) > 0
	}
	// hosts the kept SRV records of this message point at
	srvHosts := map[string]bool{}
	for _, sec := range [][]record{m.an, m.ns, m.ar} {
		for _, r := range sec {
			if r.typ == typeSRV && r.n.scoped() && p.service(r.n) {
				srvHosts[r.target.key()] = true
			}
		}
	}
	nameOK := func(n name) bool {
		if n.scoped() {
			return p.service(n)
		}
		if p.Allow {
			return true
		}
		return srvHosts[n.key()] || (hosts != nil && hosts.allowedHost(n, p))
	}
	keepRec := func(r record) bool {
		if !nameOK(r.n) {
			return false
		}
		if r.typ == typePTR && (isEnum(r.n) || r.n.scoped()) && r.target.scoped() && !p.service(r.target) {
			return false
		}
		return true
	}
	out := &message{id: m.id, flags: m.flags}
	changed := false
	for _, q := range m.qs {
		if !nameOK(q.n) {
			changed = true
			continue
		}
		if clearQU && q.class&classQU != 0 {
			q.class &^= classQU
			changed = true
		}
		out.qs = append(out.qs, q)
	}
	sec := func(in []record) []record {
		var keep []record
		for _, r := range in {
			if !keepRec(r) {
				changed = true
				continue
			}
			keep = append(keep, r)
		}
		return keep
	}
	out.an, out.ns, out.ar = sec(m.an), sec(m.ns), sec(m.ar)
	if len(out.qs)+len(out.an) == 0 {
		return nil, false
	}
	if !changed {
		return b, true
	}
	out.dropUnmovable()
	if len(out.qs)+len(out.an) == 0 {
		return nil, false
	}
	return out.encode(), true
}

// dropUnmovable leaves out the records that cannot be moved without their
// compression targets.
func (m *message) dropUnmovable() {
	drop := func(in []record) []record {
		var keep []record
		for _, r := range in {
			if r.movable {
				keep = append(keep, r)
			}
		}
		return keep
	}
	m.an, m.ns, m.ar = drop(m.an), drop(m.ns), drop(m.ar)
}
