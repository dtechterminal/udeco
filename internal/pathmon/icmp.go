// SPDX-License-Identifier: GPL-2.0-or-later

package pathmon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

// ErrTimeout: no echo reply came within the probe's timeout.
var ErrTimeout = errors.New("no echo reply")

// ICMP is the Prober the agent uses: an ICMP echo over a raw IPv4 socket
// ("ip4:icmp"), which needs root (the agent runs as root on the Deco; the
// unit's ping_group_range is "1 0", so unprivileged ICMP sockets are off).
// Each probe opens its own socket, so probes to several targets run side
// by side; replies are matched on identifier, sequence, a random token in
// the payload and the source address.
type ICMP struct {
	// Listen opens the socket; nil = net.ListenPacket("ip4:icmp", "0.0.0.0").
	Listen func() (net.PacketConn, error)
	seq    atomic.Uint32
}

const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8
	tokenLen        = 8
)

// Probe implements Prober.
func (p *ICMP) Probe(ctx context.Context, dst net.IP, size int, timeout time.Duration) (time.Duration, error) {
	dst = dst.To4()
	if dst == nil {
		return 0, errors.New("not an IPv4 address")
	}
	listen := p.Listen
	if listen == nil {
		listen = func() (net.PacketConn, error) { return net.ListenPacket("ip4:icmp", "0.0.0.0") }
	}
	c, err := listen()
	if err != nil {
		return 0, err
	}
	defer c.Close()
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	seq := uint16(p.seq.Add(1))
	payload := make([]byte, max(size, tokenLen))
	if _, err := rand.Read(payload[:tokenLen]); err != nil {
		return 0, err
	}
	for i := tokenLen; i < len(payload); i++ {
		payload[i] = byte(i)
	}
	pkt := echoPacket(icmpEchoRequest, id, seq, payload)
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	t0 := time.Now()
	if _, err := c.WriteTo(pkt, &net.IPAddr{IP: dst}); err != nil {
		return 0, err
	}
	buf := make([]byte, 65536)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return 0, ErrTimeout
			}
			return 0, err
		}
		rtt := time.Since(t0)
		if src, ok := from.(*net.IPAddr); !ok || !src.IP.Equal(dst) {
			continue
		}
		if isReply(buf[:n], id, seq, payload[:tokenLen]) {
			return rtt, nil
		}
	}
}

// echoPacket builds an ICMP echo message (RFC 792) with its checksum.
func echoPacket(typ byte, id, seq uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], seq)
	copy(b[8:], payload)
	binary.BigEndian.PutUint16(b[2:], checksum(b))
	return b
}

// isReply tells whether msg (an ICMP message without IP header, as a raw
// "ip4:icmp" socket returns it) is the echo reply to id/seq carrying token.
// A message that starts with an IPv4 header (some kernels keep it) is
// accepted too.
func isReply(msg []byte, id, seq uint16, token []byte) bool {
	if len(msg) >= 20 && msg[0]>>4 == 4 {
		if hl := int(msg[0]&0x0f) * 4; hl >= 20 && len(msg) >= hl+8 && msg[9] == 1 {
			msg = msg[hl:]
		}
	}
	if len(msg) < 8+len(token) || msg[0] != icmpEchoReply || msg[1] != 0 {
		return false
	}
	return binary.BigEndian.Uint16(msg[4:]) == id && binary.BigEndian.Uint16(msg[6:]) == seq &&
		bytes.Equal(msg[8:8+len(token)], token)
}

// checksum is the Internet checksum (RFC 1071).
func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}
