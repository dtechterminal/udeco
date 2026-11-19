// SPDX-License-Identifier: GPL-2.0-or-later

package mdnsbr

import (
	"encoding/binary"
	"errors"
)

// Conn is a port's socket.
type Conn interface {
	// Recv reads one frame into b. n is the frame's real length (it may
	// exceed len(b)); outgoing tells a frame the port sent. ErrTimeout
	// means nothing arrived within the poll interval.
	Recv(b []byte) (n int, outgoing bool, err error)
	// Send transmits an untagged frame on the port (tagged with the port's
	// VID for a virtual port).
	Send(frame []byte) error
	Close() error
}

// Opener opens a port's socket (Open on Linux; tests use fakes).
type Opener func(p Port) (Conn, error)

// ErrTimeout is Conn.Recv's poll timeout.
var ErrTimeout = errors.New("mdnsbr: timeout")

// tag inserts an 802.1Q header with vid after the MAC addresses.
func tag(f []byte, vid int) []byte {
	out := make([]byte, 0, len(f)+4)
	out = append(out, f[:12]...)
	out = binary.BigEndian.AppendUint16(out, 0x8100)
	out = binary.BigEndian.AppendUint16(out, uint16(vid&0x0fff))
	return append(out, f[12:]...)
}

// Classic BPF for a port: unfragmented UDP 5353 to 224.0.0.251 or
// ff02::fb (no IP options, no IPv6 extension headers), untagged on a plain
// port, tagged with VID on a virtual one. The tag is read from the packet's
// metadata (SKF_AD_VLAN_TAG_PRESENT, SKF_AD_VLAN_TAG): the kernel moves it
// there before the taps run.
type insn struct {
	code   uint16
	jt, jf string // labels ("" = next)
	k      uint32
	label  string
}

const (
	skfAdOff            = 0xfffff000 // SKF_AD_OFF (-0x1000)
	skfAdVlanTag        = 44
	skfAdVlanTagPresent = 48
	snapLen             = 2048
)

func filterProgram(vid int) []insn {
	var p []insn
	add := func(i insn) { p = append(p, i) }
	add(insn{code: 0x20, k: skfAdOff + skfAdVlanTagPresent}) // ld vlan_tag_present
	if vid == 0 {
		add(insn{code: 0x15, k: 0, jf: "drop"}) // jeq #0
	} else {
		add(insn{code: 0x15, k: 0, jt: "drop"})           // tagged only
		add(insn{code: 0x20, k: skfAdOff + skfAdVlanTag}) // ld vlan_tag
		add(insn{code: 0x54, k: 0x0fff})                  // and #0xfff
		add(insn{code: 0x15, k: uint32(vid), jf: "drop"})
	}
	add(insn{code: 0x28, k: 12})                     // ldh [12]
	add(insn{code: 0x15, k: etherIP6, jt: "v6"})     // IPv6
	add(insn{code: 0x15, k: etherIP4, jf: "drop"})   // IPv4
	add(insn{code: 0x30, k: 14})                     // ldb [14]
	add(insn{code: 0x15, k: 0x45, jf: "drop"})       // version 4, no options
	add(insn{code: 0x30, k: 23})                     // ldb [23]
	add(insn{code: 0x15, k: 17, jf: "drop"})         // UDP
	add(insn{code: 0x28, k: 20})                     // ldh [20]
	add(insn{code: 0x45, k: 0x3fff, jt: "drop"})     // MF or an offset: a fragment
	add(insn{code: 0x20, k: 30})                     // ld [30]
	add(insn{code: 0x15, k: 0xe00000fb, jf: "drop"}) // 224.0.0.251
	add(insn{code: 0x28, k: 36})                     // ldh [36]: UDP dport
	add(insn{code: 0x15, k: mdnsPort, jt: "keep", jf: "drop"})
	add(insn{label: "v6", code: 0x30, k: 20}) // ldb [20]: next header
	add(insn{code: 0x15, k: 17, jf: "drop"})  // UDP
	add(insn{code: 0x20, k: 38})              // ld [38]
	add(insn{code: 0x15, k: 0xff020000, jf: "drop"})
	add(insn{code: 0x20, k: 42})
	add(insn{code: 0x15, k: 0, jf: "drop"})
	add(insn{code: 0x20, k: 46})
	add(insn{code: 0x15, k: 0, jf: "drop"})
	add(insn{code: 0x20, k: 50})
	add(insn{code: 0x15, k: 0xfb, jf: "drop"}) // ff02::fb
	add(insn{code: 0x28, k: 56})               // ldh [56]: UDP dport
	add(insn{code: 0x15, k: mdnsPort, jf: "drop"})
	add(insn{label: "keep", code: 0x06, k: snapLen})
	add(insn{label: "drop", code: 0x06, k: 0})
	return p
}

// assemble resolves the labels: (code, jt, jf, k) per instruction.
func assemble(p []insn) ([][4]uint32, error) {
	at := map[string]int{}
	for i, x := range p {
		if x.label != "" {
			at[x.label] = i
		}
	}
	rel := func(i int, l string) (uint32, error) {
		if l == "" {
			return 0, nil
		}
		t, ok := at[l]
		if !ok || t <= i || t-i-1 > 255 {
			return 0, errors.New("mdnsbr: bad BPF jump to " + l)
		}
		return uint32(t - i - 1), nil
	}
	out := make([][4]uint32, len(p))
	for i, x := range p {
		jt, err := rel(i, x.jt)
		if err != nil {
			return nil, err
		}
		jf, err := rel(i, x.jf)
		if err != nil {
			return nil, err
		}
		out[i] = [4]uint32{uint32(x.code), jt, jf, x.k}
	}
	return out, nil
}

// runBPF interprets the subset of classic BPF filterProgram uses, for tests:
// frame is untagged, vlan the metadata tag (-1 = none).
func runBPF(prog [][4]uint32, frame []byte, vlan int) uint32 {
	var a uint32
	ld := func(k uint32, size int) (uint32, bool) {
		switch k {
		case skfAdOff + skfAdVlanTagPresent:
			if vlan >= 0 {
				return 1, true
			}
			return 0, true
		case skfAdOff + skfAdVlanTag:
			if vlan >= 0 {
				return uint32(vlan), true
			}
			return 0, true
		}
		if int(k)+size > len(frame) {
			return 0, false
		}
		switch size {
		case 1:
			return uint32(frame[k]), true
		case 2:
			return uint32(binary.BigEndian.Uint16(frame[k:])), true
		}
		return binary.BigEndian.Uint32(frame[k:]), true
	}
	for pc := 0; pc < len(prog); pc++ {
		code, jt, jf, k := prog[pc][0], prog[pc][1], prog[pc][2], prog[pc][3]
		var ok bool
		switch code {
		case 0x20:
			a, ok = ld(k, 4)
		case 0x28:
			a, ok = ld(k, 2)
		case 0x30:
			a, ok = ld(k, 1)
		case 0x54:
			a, ok = a&k, true
		case 0x15:
			ok = true
			if a == k {
				pc += int(jt)
			} else {
				pc += int(jf)
			}
		case 0x45:
			ok = true
			if a&k != 0 {
				pc += int(jt)
			} else {
				pc += int(jf)
			}
		case 0x06:
			return k
		}
		if !ok {
			return 0
		}
	}
	return 0
}
