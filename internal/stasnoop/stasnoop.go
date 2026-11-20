// SPDX-License-Identifier: GPL-2.0-or-later

// Package stasnoop watches the few frames that tell how a Wi-Fi client's
// connection came up: ARP, DHCP and DNS over IPv4, on a VAP, in both
// directions. The agent's connection-timing events (cmd/udeco-ap
// staconn.go) read them: when the station got its address, whether the
// gateway answered its ARP, whether its DNS queries were answered.
//
// A Source is an AF_PACKET socket bound to one VAP (raw_linux.go) whose
// kernel filter passes only those frames, so the rest of the traffic never
// reaches the agent. Run parses each frame into an Obs and adds it to a
// Ring, which keeps the newest Max and never blocks: a burst is cut, not
// queued. The taps never send; the one frame the package sends is a
// gratuitous ARP on a station's behalf (GARP, SendFrame), on request.
package stasnoop

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

// Kind is what a frame is.
type Kind int

const (
	ARPRequest Kind = iota + 1
	ARPReply
	DHCPDiscover
	DHCPOffer
	DHCPRequest
	DHCPAck
	DHCPNak
	DNSQuery
	DNSResponse
)

// Obs is one frame seen on a VAP.
type Obs struct {
	Vif          string
	At           time.Time
	Out          bool   // the VAP sent it (to a client); else a client sent it
	Kind         Kind   //
	Src, Dst     string // Ethernet addresses, lower case
	SrcIP, DstIP string // IPv4 (ARP: sender and target protocol addresses)
	Client       string // DHCP: the client hardware address
	YourIP       string // DHCP: yiaddr
	ID           uint32 // DHCP xid, DNS id
}

// Station is the client a frame is about: the DHCP client, else the
// sender of a frame a client sent, else the receiver of a unicast frame
// the VAP sent ("" for a group-addressed one).
func (o Obs) Station() string {
	switch {
	case o.Client != "":
		return o.Client
	case !o.Out:
		return o.Src
	}
	if hw, err := net.ParseMAC(o.Dst); err == nil && len(hw) == 6 && hw[0]&1 == 0 {
		return o.Dst
	}
	return ""
}

// Parse reads one Ethernet frame (out: the VAP sent it).
func Parse(b []byte, out bool) (Obs, bool) {
	if len(b) < 14 {
		return Obs{}, false
	}
	o := Obs{Out: out, Dst: net.HardwareAddr(b[0:6]).String(), Src: net.HardwareAddr(b[6:12]).String()}
	p := b[14:]
	switch binary.BigEndian.Uint16(b[12:]) {
	case 0x0806:
		if len(p) < 28 || binary.BigEndian.Uint16(p[0:]) != 1 || binary.BigEndian.Uint16(p[2:]) != 0x0800 || p[4] != 6 || p[5] != 4 {
			return Obs{}, false
		}
		switch binary.BigEndian.Uint16(p[6:]) {
		case 1:
			o.Kind = ARPRequest
		case 2:
			o.Kind = ARPReply
		default:
			return Obs{}, false
		}
		o.SrcIP, o.DstIP = net.IP(p[14:18]).String(), net.IP(p[24:28]).String()
		return o, true
	case 0x0800:
		if len(p) < 20 || p[0]>>4 != 4 || p[9] != 17 {
			return Obs{}, false
		}
		if binary.BigEndian.Uint16(p[6:])&0x3fff != 0 {
			return Obs{}, false // a fragment: never whole
		}
		ihl := int(p[0]&0xf) * 4
		if ihl < 20 || len(p) < ihl+8 {
			return Obs{}, false
		}
		o.SrcIP, o.DstIP = net.IP(p[12:16]).String(), net.IP(p[16:20]).String()
		u := p[ihl:]
		sport, dport := binary.BigEndian.Uint16(u[0:]), binary.BigEndian.Uint16(u[2:])
		d := u[8:]
		switch {
		case sport == 53 || dport == 53:
			return parseDNS(o, d, sport == 53)
		case (sport == 67 || sport == 68) && (dport == 67 || dport == 68):
			return parseDHCP(o, d)
		}
	}
	return Obs{}, false
}

func parseDNS(o Obs, d []byte, fromServer bool) (Obs, bool) {
	if len(d) < 12 {
		return Obs{}, false
	}
	qr := d[2]&0x80 != 0
	if qr != fromServer {
		return Obs{}, false
	}
	o.ID = uint32(binary.BigEndian.Uint16(d))
	o.Kind = DNSQuery
	if qr {
		o.Kind = DNSResponse
	}
	return o, true
}

func parseDHCP(o Obs, d []byte) (Obs, bool) {
	if len(d) < 240 || d[1] != 1 || d[2] != 6 || binary.BigEndian.Uint32(d[236:]) != 0x63825363 {
		return Obs{}, false
	}
	o.ID = binary.BigEndian.Uint32(d[4:])
	o.YourIP = net.IP(d[16:20]).String()
	o.Client = net.HardwareAddr(d[28:34]).String()
	var mt byte
	for opts := d[240:]; len(opts) > 0; {
		c := opts[0]
		if c == 255 {
			break
		}
		if c == 0 {
			opts = opts[1:]
			continue
		}
		if len(opts) < 2 || len(opts) < 2+int(opts[1]) {
			break
		}
		if c == 53 && opts[1] == 1 {
			mt = opts[2]
		}
		opts = opts[2+int(opts[1]):]
	}
	switch mt {
	case 1:
		o.Kind = DHCPDiscover
	case 2:
		o.Kind = DHCPOffer
	case 3:
		o.Kind = DHCPRequest
	case 5:
		o.Kind = DHCPAck
	case 6:
		o.Kind = DHCPNak
	default:
		return Obs{}, false
	}
	if d[0] == 1 {
		o.YourIP = "" // a client's request carries no yiaddr
		if o.Kind != DHCPDiscover && o.Kind != DHCPRequest {
			return Obs{}, false
		}
	}
	return o, true
}

// Insn is one classic BPF instruction (struct sock_filter).
type Insn struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

// snap is how much of a frame is kept: a DHCP packet with its options.
const snap = 1024

// filter passes ARP and unfragmented (or first-fragment) IPv4 UDP from or
// to port 53, 67 or 68; anything else stays in the kernel.
var filter = []Insn{
	{Code: 0x28, K: 12},               // 0: ldh [12]
	{Code: 0x15, Jt: 14, K: 0x0806},   // 1: ARP -> accept
	{Code: 0x15, Jf: 14, K: 0x0800},   // 2: IPv4, else drop
	{Code: 0x30, K: 23},               // 3: ldb [23] protocol
	{Code: 0x15, Jf: 12, K: 17},       // 4: UDP, else drop
	{Code: 0x28, K: 20},               // 5: ldh [20] flags/offset
	{Code: 0x45, Jt: 10, K: 0x1fff},   // 6: a later fragment -> drop
	{Code: 0xb1, K: 14},               // 7: x = IP header length
	{Code: 0x48, K: 14},               // 8: ldh [x+14] source port
	{Code: 0x15, Jt: 6, K: 53},        // 9
	{Code: 0x15, Jt: 5, K: 67},        // 10
	{Code: 0x15, Jt: 4, K: 68},        // 11
	{Code: 0x48, K: 16},               // 12: ldh [x+16] destination port
	{Code: 0x15, Jt: 2, K: 53},        // 13
	{Code: 0x15, Jt: 1, K: 67},        // 14
	{Code: 0x15, Jt: 0, Jf: 1, K: 68}, // 15
	{Code: 0x06, K: snap},             // 16: accept
	{Code: 0x06, K: 0},                // 17: drop
}

// Ring keeps the newest Max observations for the agent's loop.
type Ring struct {
	mu      sync.Mutex
	max     int
	obs     []Obs
	dropped int
}

// NewRing returns a Ring that keeps at most max observations.
func NewRing(max int) *Ring { return &Ring{max: max} }

// Add keeps o, dropping the oldest when full. It never blocks for long.
func (r *Ring) Add(o Obs) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.obs) >= r.max {
		r.obs = r.obs[1:]
		r.dropped++
	}
	r.obs = append(r.obs, o)
}

// Take returns what was added since the last call, oldest first, and how
// many were dropped meanwhile.
func (r *Ring) Take() ([]Obs, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, d := r.obs, r.dropped
	r.obs, r.dropped = nil, 0
	return o, d
}

// Source delivers a VAP's filtered frames.
type Source interface {
	// Recv reads one frame into b; outgoing: the VAP sent it. ErrTimeout:
	// nothing within the poll interval.
	Recv(b []byte) (n int, outgoing bool, err error)
	Close() error
}

// ErrTimeout is Source.Recv's poll timeout.
var ErrTimeout = errors.New("stasnoop: timeout")

// Opener opens a Source on a VAP (Open on Linux; tests use fakes).
type Opener func(ifname string) (Source, error)

// Run reads src into r as VAP vif until ctx ends or src fails, then closes
// src. It returns the error that stopped it (nil when ctx ended).
func Run(ctx context.Context, r *Ring, vif string, src Source, now func() time.Time) error {
	defer src.Close()
	b := make([]byte, snap)
	for ctx.Err() == nil {
		n, out, err := src.Recv(b)
		if errors.Is(err, ErrTimeout) {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if o, ok := Parse(b[:min(n, len(b))], out); ok {
			o.Vif, o.At = vif, now()
			r.Add(o)
		}
	}
	return nil
}
