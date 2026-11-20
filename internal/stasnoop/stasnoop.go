// SPDX-License-Identifier: GPL-2.0-or-later

// Package stasnoop watches the few frames that tell how a Wi-Fi client's
// connection came up: ARP, DHCP and DNS over IPv4, DNS over IPv6, and the
// handshake of DNS over TLS, on a VAP, in both directions. The agent's connection-timing events (cmd/udeco-ap
// staconn.go) read them: when the station got its address, whether the
// gateway answered its ARP, whether its DNS queries were answered.
//
// Encrypted DNS cannot be read: DNS over TLS (TCP 853) shows only as the
// station's SYN and the server's SYN-ACK (DoTSyn, DoTSynAck), and DNS
// over HTTPS (TCP or QUIC 443) not at all; no timing comes from either.
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
	DoTSyn    // a station opens a TCP connection to port 853 (DNS over TLS)
	DoTSynAck // and the server accepts it
)

// Obs is one frame seen on a VAP.
type Obs struct {
	Vif          string
	At           time.Time
	Out          bool   // the VAP sent it (to a client); else a client sent it
	Kind         Kind   //
	Src, Dst     string // Ethernet addresses, lower case
	SrcIP, DstIP string // IPv4, or IPv6 with V6 (ARP: sender and target protocol addresses)
	V6           bool   // an IPv6 packet
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
		if len(p) < 20 || p[0]>>4 != 4 || p[9] != 17 && p[9] != 6 {
			return Obs{}, false
		}
		if binary.BigEndian.Uint16(p[6:])&0x3fff != 0 {
			return Obs{}, false // a fragment: never whole
		}
		ihl := int(p[0]&0xf) * 4
		if ihl < 20 || len(p) < ihl {
			return Obs{}, false
		}
		o.SrcIP, o.DstIP = net.IP(p[12:16]).String(), net.IP(p[16:20]).String()
		return parseL4(o, p[9], p[ihl:])
	case 0x86dd:
		if len(p) < 40 || p[0]>>4 != 6 {
			return Obs{}, false
		}
		o.V6 = true
		o.SrcIP, o.DstIP = net.IP(p[8:24]).String(), net.IP(p[24:40]).String()
		nh, l := p[6], p[40:]
		// hop-by-hop (0), routing (43) and destination options (60) are
		// skipped; a fragment header (44), or anything else, ends it
		for i := 0; nh == 0 || nh == 43 || nh == 60; i++ {
			if i == 8 || len(l) < 8 || len(l) < (int(l[1])+1)*8 {
				return Obs{}, false
			}
			nh, l = l[0], l[(int(l[1])+1)*8:]
		}
		return parseL4(o, nh, l)
	}
	return Obs{}, false
}

// parseL4 reads the UDP or TCP header l (protocol proto) of o's packet.
func parseL4(o Obs, proto byte, l []byte) (Obs, bool) {
	switch proto {
	case 17:
		if len(l) < 8 {
			return Obs{}, false
		}
		sport, dport := binary.BigEndian.Uint16(l[0:]), binary.BigEndian.Uint16(l[2:])
		d := l[8:]
		switch {
		case sport == 53 || dport == 53:
			return parseDNS(o, d, sport == 53)
		case !o.V6 && (sport == 67 || sport == 68) && (dport == 67 || dport == 68):
			return parseDHCP(o, d)
		}
	case 6:
		if len(l) < 20 {
			return Obs{}, false
		}
		sport, dport := binary.BigEndian.Uint16(l[0:]), binary.BigEndian.Uint16(l[2:])
		switch fl := l[13] & 0x12; {
		case fl == 0x02 && dport == 853:
			o.Kind = DoTSyn
			return o, true
		case fl == 0x12 && sport == 853:
			o.Kind = DoTSynAck
			return o, true
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

// filter passes ARP; unfragmented (or first-fragment) IPv4 UDP from or to
// port 53, 67 or 68; IPv6 UDP from or to port 53; IPv6 whose first header
// is hop-by-hop, routing or destination options (rare; Parse walks them to
// the UDP header); and TCP SYNs from or to port 853 (DNS over TLS) over
// either family. IPv6 fragments and anything else stay in the kernel. The
// IPv4 UDP part (0-15) decides as it did before IPv6 was added.
var filter = []Insn{
	{Code: 0x28, K: 12},                 // 0: ldh [12]
	{Code: 0x15, Jt: 44, K: 0x0806},     // 1: ARP -> accept
	{Code: 0x15, Jf: 23, K: 0x0800},     // 2: IPv4, else 26 (IPv6)
	{Code: 0x30, K: 23},                 // 3: ldb [23] protocol
	{Code: 0x15, Jf: 11, K: 17},         // 4: UDP, else 16 (TCP)
	{Code: 0x28, K: 20},                 // 5: ldh [20] flags/offset
	{Code: 0x45, Jt: 40, K: 0x1fff},     // 6: a later fragment -> drop
	{Code: 0xb1, K: 14},                 // 7: x = IP header length
	{Code: 0x48, K: 14},                 // 8: ldh [x+14] source port
	{Code: 0x15, Jt: 36, K: 53},         // 9
	{Code: 0x15, Jt: 35, K: 67},         // 10
	{Code: 0x15, Jt: 34, K: 68},         // 11
	{Code: 0x48, K: 16},                 // 12: ldh [x+16] destination port
	{Code: 0x15, Jt: 32, K: 53},         // 13
	{Code: 0x15, Jt: 31, K: 67},         // 14
	{Code: 0x15, Jt: 30, Jf: 31, K: 68}, // 15
	// IPv4 TCP
	{Code: 0x15, Jf: 30, K: 6},           // 16: TCP, else drop
	{Code: 0x28, K: 20},                  // 17: ldh [20] flags/offset
	{Code: 0x45, Jt: 28, K: 0x1fff},      // 18: a later fragment -> drop
	{Code: 0xb1, K: 14},                  // 19: x = IP header length
	{Code: 0x50, K: 27},                  // 20: ldb [x+27] TCP flags
	{Code: 0x45, Jf: 25, K: 0x02},        // 21: SYN, else drop
	{Code: 0x48, K: 14},                  // 22: ldh [x+14] source port
	{Code: 0x15, Jt: 22, K: 853},         // 23
	{Code: 0x48, K: 16},                  // 24: ldh [x+16] destination port
	{Code: 0x15, Jt: 20, Jf: 21, K: 853}, // 25
	// IPv6
	{Code: 0x15, Jf: 20, K: 0x86dd},     // 26: IPv6, else drop
	{Code: 0x30, K: 14},                 // 27: ldb [14]
	{Code: 0x54, K: 0xf0},               // 28: version
	{Code: 0x15, Jf: 17, K: 0x60},       // 29: 6, else drop
	{Code: 0x30, K: 20},                 // 30: ldb [20] next header
	{Code: 0x15, Jf: 4, K: 17},          // 31: UDP, else 36
	{Code: 0x28, K: 54},                 // 32: ldh [54] source port
	{Code: 0x15, Jt: 12, K: 53},         // 33
	{Code: 0x28, K: 56},                 // 34: ldh [56] destination port
	{Code: 0x15, Jt: 10, Jf: 11, K: 53}, // 35
	{Code: 0x15, Jf: 6, K: 6},           // 36: TCP, else 43
	{Code: 0x30, K: 67},                 // 37: ldb [67] TCP flags
	{Code: 0x45, Jf: 8, K: 0x02},        // 38: SYN, else drop
	{Code: 0x28, K: 54},                 // 39: ldh [54] source port
	{Code: 0x15, Jt: 5, K: 853},         // 40
	{Code: 0x28, K: 56},                 // 41: ldh [56] destination port
	{Code: 0x15, Jt: 3, Jf: 4, K: 853},  // 42
	{Code: 0x15, Jt: 2, K: 0},           // 43: hop-by-hop -> accept
	{Code: 0x15, Jt: 1, K: 43},          // 44: routing -> accept
	{Code: 0x15, Jt: 0, Jf: 1, K: 60},   // 45: destination options -> accept
	{Code: 0x06, K: snap},               // 46: accept
	{Code: 0x06, K: 0},                  // 47: drop
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
