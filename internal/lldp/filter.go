// SPDX-License-Identifier: GPL-2.0-or-later

package lldp

// The receive socket is bound with ETH_P_ALL, not ETH_P_LLDP. On a port
// enslaved to a bridge, protocol-specific packet handlers only run after the
// bridge rx_handler, and the bridge consumes the link-local 01:80:c2:00:00:0e
// group, so an ETH_P_LLDP socket never sees a neighbour's LLDPDU. ETH_P_ALL
// taps run before the rx_handler; a classic BPF filter then keeps the socket
// to LLDP frames only.

// ethPAll is htons(ETH_P_ALL), the protocol for the receive bind.
const ethPAll = 0x0003>>8 | (0x0003&0xff)<<8

// Classic BPF opcodes used by lldpFilter.
const (
	bpfLdHAbs = 0x28 // BPF_LD | BPF_H | BPF_ABS
	bpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfRetK   = 0x06 // BPF_RET | BPF_K
)

// bpfInsn mirrors struct sock_filter.
type bpfInsn struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

// lldpFilter accepts ethertype 0x88cc, untagged or behind one 802.1Q tag,
// and drops everything else.
var lldpFilter = []bpfInsn{
	{bpfLdHAbs, 0, 0, 12},      // 0: A = ethertype
	{bpfJeqK, 3, 0, EtherType}, // 1: LLDP -> accept
	{bpfJeqK, 0, 3, 0x8100},    // 2: not 802.1Q -> drop
	{bpfLdHAbs, 0, 0, 16},      // 3: A = inner ethertype
	{bpfJeqK, 0, 1, EtherType}, // 4: not LLDP -> drop
	{bpfRetK, 0, 0, 0x40000},   // 5: accept the whole frame
	{bpfRetK, 0, 0, 0},         // 6: drop
}

// packetOutgoing is PACKET_OUTGOING: a frame this host sent, looped back
// to ETH_P_ALL sockets.
const packetOutgoing = 4

// keepPkttype reports whether a received frame should be decoded; our own
// announcements come back as PACKET_OUTGOING and are skipped.
func keepPkttype(t uint8) bool { return t != packetOutgoing }
