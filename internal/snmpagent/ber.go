// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// BER tags SNMP uses (single-byte tags only; RFC 1157, RFC 3416).
const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagNull        = 0x05
	tagOID         = 0x06
	tagSequence    = 0x30

	tagIPAddress = 0x40
	tagCounter32 = 0x41
	tagGauge32   = 0x42
	tagTimeTicks = 0x43
	tagOpaque    = 0x44
	tagCounter64 = 0x46

	tagNoSuchObject   = 0x80
	tagNoSuchInstance = 0x81
	tagEndOfMibView   = 0x82

	pduGet      = 0xa0
	pduGetNext  = 0xa1
	pduResponse = 0xa2
	pduSet      = 0xa3
	pduTrapV1   = 0xa4
	pduGetBulk  = 0xa5
	pduInform   = 0xa6
	pduTrapV2   = 0xa7
	pduReport   = 0xa8
)

// Limits on what a request may hold. A request is a few hundred bytes; these
// only stop a crafted packet from costing memory or time.
const (
	maxOIDArcs = 128
	maxVarBind = 128
)

var errBER = errors.New("malformed BER")

// readTLV splits the first BER element off b: its tag, its value and what
// follows it. Only definite lengths of up to 4 bytes are accepted.
func readTLV(b []byte) (tag byte, val, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errBER
	}
	tag = b[0]
	if tag&0x1f == 0x1f { // multi-byte tag: never used by SNMP
		return 0, nil, nil, errBER
	}
	n := int(b[1])
	p := 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 || len(b) < 2+k {
			return 0, nil, nil, errBER
		}
		n = 0
		for _, c := range b[2 : 2+k] {
			n = n<<8 | int(c)
		}
		if n < 0 {
			return 0, nil, nil, errBER
		}
		p += k
	}
	if n > len(b)-p {
		return 0, nil, nil, errBER
	}
	return tag, b[p : p+n], b[p+n:], nil
}

// expect reads one element and checks its tag.
func expect(b []byte, tag byte) (val, rest []byte, err error) {
	t, v, r, err := readTLV(b)
	if err != nil {
		return nil, nil, err
	}
	if t != tag {
		return nil, nil, fmt.Errorf("%w: tag 0x%02x, want 0x%02x", errBER, t, tag)
	}
	return v, r, nil
}

// parseInt decodes a two's-complement INTEGER of up to 8 bytes.
func parseInt(v []byte) (int64, error) {
	if len(v) == 0 || len(v) > 8 {
		return 0, errBER
	}
	x := int64(int8(v[0]))
	for _, c := range v[1:] {
		x = x<<8 | int64(c)
	}
	return x, nil
}

// parseUint decodes an unsigned application value (Counter32/64, Gauge32,
// TimeTicks): up to 9 bytes with a leading zero.
func parseUint(v []byte) (uint64, error) {
	if len(v) == 0 || len(v) > 9 || len(v) == 9 && v[0] != 0 {
		return 0, errBER
	}
	var x uint64
	for _, c := range v {
		x = x<<8 | uint64(c)
	}
	return x, nil
}

func readInt(b []byte) (int64, []byte, error) {
	v, rest, err := expect(b, tagInteger)
	if err != nil {
		return 0, nil, err
	}
	x, err := parseInt(v)
	return x, rest, err
}

// appendLen appends a BER definite length.
func appendLen(dst []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(dst, byte(n))
	case n <= 0xff:
		return append(dst, 0x81, byte(n))
	case n <= 0xffff:
		return append(dst, 0x82, byte(n>>8), byte(n))
	case n <= 0xffffff:
		return append(dst, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(dst, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func tlv(tag byte, val []byte) []byte {
	out := make([]byte, 0, len(val)+6)
	out = append(out, tag)
	out = appendLen(out, len(val))
	return append(out, val...)
}

// seq is a SEQUENCE (or a PDU with tag) of the encoded parts.
func seq(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n+6)
	out = append(out, tag)
	out = appendLen(out, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func encInt(x int64) []byte {
	var b [8]byte
	n := 8
	for i := 7; i >= 0; i-- {
		b[i] = byte(x)
		x >>= 8
	}
	i := 0
	for i < n-1 && (b[i] == 0 && b[i+1]&0x80 == 0 || b[i] == 0xff && b[i+1]&0x80 != 0) {
		i++
	}
	return tlv(tagInteger, b[i:])
}

func encUint(tag byte, x uint64) []byte {
	var b [9]byte
	for i := 8; i >= 1; i-- {
		b[i] = byte(x)
		x >>= 8
	}
	i := 0
	for i < 8 && b[i] == 0 && b[i+1]&0x80 == 0 {
		i++
	}
	return tlv(tag, b[i:])
}

func encOctets(b []byte) []byte { return tlv(tagOctetString, b) }

// OID is an object identifier.
type OID []uint32

// ParseOID reads a dotted OID ("1.3.6.1.2.1.1.1.0", a leading dot allowed).
func ParseOID(s string) (OID, error) {
	s = strings.TrimPrefix(s, ".")
	if s == "" {
		return nil, errors.New("empty OID")
	}
	parts := strings.Split(s, ".")
	if len(parts) > maxOIDArcs {
		return nil, errors.New("OID too long")
	}
	o := make(OID, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bad OID %q", s)
		}
		o[i] = uint32(n)
	}
	return o, nil
}

// mustOID is ParseOID for constants.
func mustOID(s string) OID {
	o, err := ParseOID(s)
	if err != nil {
		panic(err)
	}
	return o
}

func (o OID) String() string {
	var b strings.Builder
	for i, n := range o {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(n), 10))
	}
	return b.String()
}

// Compare orders OIDs lexicographically, as SNMP walks them.
func (o OID) Compare(p OID) int {
	for i := 0; i < len(o) && i < len(p); i++ {
		if o[i] != p[i] {
			if o[i] < p[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(o) < len(p):
		return -1
	case len(o) > len(p):
		return 1
	}
	return 0
}

// HasPrefix reports whether p is a prefix of o.
func (o OID) HasPrefix(p OID) bool {
	if len(p) > len(o) {
		return false
	}
	for i := range p {
		if o[i] != p[i] {
			return false
		}
	}
	return true
}

// Append returns o followed by the arcs (a new slice).
func (o OID) Append(arcs ...uint32) OID {
	out := make(OID, 0, len(o)+len(arcs))
	return append(append(out, o...), arcs...)
}

func parseOIDValue(v []byte) (OID, error) {
	if len(v) == 0 {
		return nil, errBER
	}
	o := make(OID, 0, 16)
	var x uint64
	first := true
	for i, c := range v {
		if x == 0 && c == 0x80 { // non-minimal encoding
			return nil, errBER
		}
		x = x<<7 | uint64(c&0x7f)
		if x > 0xffffffff {
			return nil, errBER
		}
		if c&0x80 != 0 {
			if i == len(v)-1 {
				return nil, errBER
			}
			continue
		}
		if first {
			switch {
			case x < 40:
				o = append(o, 0, uint32(x))
			case x < 80:
				o = append(o, 1, uint32(x-40))
			default:
				o = append(o, 2, uint32(x-80))
			}
			first = false
		} else {
			o = append(o, uint32(x))
		}
		if len(o) > maxOIDArcs {
			return nil, errBER
		}
		x = 0
	}
	return o, nil
}

func appendBase128(dst []byte, x uint64) []byte {
	var tmp [10]byte
	i := len(tmp) - 1
	tmp[i] = byte(x & 0x7f)
	for x >>= 7; x > 0; x >>= 7 {
		i--
		tmp[i] = byte(x&0x7f) | 0x80
	}
	return append(dst, tmp[i:]...)
}

func encOID(o OID) []byte {
	var v []byte
	switch {
	case len(o) == 0:
		v = []byte{0}
	case len(o) == 1:
		v = appendBase128(nil, uint64(o[0])*40)
	default:
		v = appendBase128(nil, uint64(o[0])*40+uint64(o[1]))
		for _, n := range o[2:] {
			v = appendBase128(v, uint64(n))
		}
	}
	return tlv(tagOID, v)
}

// Value is one SNMP value. Tag picks the field that holds it.
type Value struct {
	Tag   byte
	Int   int64  // INTEGER
	Uint  uint64 // Counter32, Gauge32, TimeTicks, Counter64
	Bytes []byte // OCTET STRING, IpAddress, Opaque
	OID   OID    // OBJECT IDENTIFIER
}

// Value constructors.
func Integer(x int64) Value      { return Value{Tag: tagInteger, Int: x} }
func OctetString(s string) Value { return Value{Tag: tagOctetString, Bytes: []byte(s)} }
func Octets(b []byte) Value      { return Value{Tag: tagOctetString, Bytes: b} }
func ObjectID(o OID) Value       { return Value{Tag: tagOID, OID: o} }
func Counter32(x uint64) Value   { return Value{Tag: tagCounter32, Uint: x & 0xffffffff} }
func Counter64(x uint64) Value   { return Value{Tag: tagCounter64, Uint: x} }
func TimeTicks(x uint64) Value   { return Value{Tag: tagTimeTicks, Uint: x & 0xffffffff} }

// Gauge32 clamps to the type's range (a gauge latches at its maximum).
func Gauge32(x int64) Value {
	if x < 0 {
		x = 0
	}
	return Value{Tag: tagGauge32, Uint: uint64(min(x, 0xffffffff))}
}

// IPAddress is an IPv4 address (4 bytes; anything else is 0.0.0.0).
func IPAddress(ip4 []byte) Value {
	b := make([]byte, 4)
	if len(ip4) == 4 {
		copy(b, ip4)
	}
	return Value{Tag: tagIPAddress, Bytes: b}
}

// Truth is an SNMPv2-TC TruthValue (true(1), false(2)).
func Truth(b bool) Value {
	if b {
		return Integer(1)
	}
	return Integer(2)
}

var nullValue = Value{Tag: tagNull}

func (v Value) encode() []byte {
	switch v.Tag {
	case tagInteger:
		return encInt(v.Int)
	case tagOctetString, tagIPAddress, tagOpaque:
		return tlv(v.Tag, v.Bytes)
	case tagOID:
		return encOID(v.OID)
	case tagCounter32, tagGauge32, tagTimeTicks, tagCounter64:
		return encUint(v.Tag, v.Uint)
	}
	return []byte{v.Tag, 0} // NULL and the v2 exceptions
}

func parseValue(tag byte, v []byte) (Value, error) {
	switch tag {
	case tagInteger:
		x, err := parseInt(v)
		return Value{Tag: tag, Int: x}, err
	case tagOctetString, tagIPAddress, tagOpaque:
		return Value{Tag: tag, Bytes: v}, nil
	case tagOID:
		o, err := parseOIDValue(v)
		return Value{Tag: tag, OID: o}, err
	case tagCounter32, tagGauge32, tagTimeTicks, tagCounter64:
		x, err := parseUint(v)
		return Value{Tag: tag, Uint: x}, err
	case tagNull, tagNoSuchObject, tagNoSuchInstance, tagEndOfMibView:
		if len(v) != 0 {
			return Value{}, errBER
		}
		return Value{Tag: tag}, nil
	}
	return Value{}, fmt.Errorf("%w: value tag 0x%02x", errBER, tag)
}

// VarBind is one name/value pair.
type VarBind struct {
	Name  OID
	Value Value
}

func (vb VarBind) encode() []byte { return seq(tagSequence, encOID(vb.Name), vb.Value.encode()) }

// PDU is a request or response PDU (GetBulk keeps non-repeaters and
// max-repetitions in ErrorStatus and ErrorIndex, as on the wire).
type PDU struct {
	Type        byte
	RequestID   int32
	ErrorStatus int64
	ErrorIndex  int64
	VarBinds    []VarBind
}

func parsePDU(b []byte) (PDU, error) {
	t, v, rest, err := readTLV(b)
	if err != nil {
		return PDU{}, err
	}
	if len(rest) != 0 { // nothing follows a PDU in its message or ScopedPDU
		return PDU{}, errBER
	}
	if t < pduGet || t > pduReport {
		return PDU{}, fmt.Errorf("%w: PDU tag 0x%02x", errBER, t)
	}
	p := PDU{Type: t}
	id, v, err := readInt(v)
	if err != nil {
		return PDU{}, err
	}
	if id < -1<<31 || id > 1<<31-1 {
		return PDU{}, errBER
	}
	p.RequestID = int32(id)
	if p.ErrorStatus, v, err = readInt(v); err != nil {
		return PDU{}, err
	}
	if p.ErrorIndex, v, err = readInt(v); err != nil {
		return PDU{}, err
	}
	list, v, err := expect(v, tagSequence)
	if err != nil || len(v) != 0 {
		return PDU{}, errBER
	}
	for len(list) > 0 {
		if len(p.VarBinds) == maxVarBind {
			return PDU{}, fmt.Errorf("%w: more than %d varbinds", errBER, maxVarBind)
		}
		var vb []byte
		if vb, list, err = expect(list, tagSequence); err != nil {
			return PDU{}, err
		}
		name, r, err := expect(vb, tagOID)
		if err != nil {
			return PDU{}, err
		}
		o, err := parseOIDValue(name)
		if err != nil {
			return PDU{}, err
		}
		vt, vv, r, err := readTLV(r)
		if err != nil || len(r) != 0 {
			return PDU{}, errBER
		}
		val, err := parseValue(vt, vv)
		if err != nil {
			return PDU{}, err
		}
		p.VarBinds = append(p.VarBinds, VarBind{Name: o, Value: val})
	}
	return p, nil
}

func (p PDU) encode() []byte {
	vbs := make([][]byte, len(p.VarBinds))
	for i, vb := range p.VarBinds {
		vbs[i] = vb.encode()
	}
	return seq(p.Type, encInt(int64(p.RequestID)), encInt(p.ErrorStatus), encInt(p.ErrorIndex), seq(tagSequence, vbs...))
}
