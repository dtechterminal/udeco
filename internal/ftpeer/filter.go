// SPDX-License-Identifier: GPL-2.0-or-later

package ftpeer

// The socket is bound on the bridge device with ETH_P_ALL and a classic
// BPF filter keeps it to EtherType 0x88b5, as internal/lldp does: the
// filter is attached before the bind, so no other frame is ever queued.
// ETH_P_ALL also delivers this host's own frames (PACKET_OUTGOING), which
// are skipped.

// ethPAll is htons(ETH_P_ALL).
const ethPAll = 0x0003>>8 | (0x0003&0xff)<<8

// ethPAnnounce is htons(EtherType) for the send address.
const ethPAnnounce = EtherType>>8 | (EtherType&0xff)<<8

// Classic BPF opcodes.
const (
	bpfLdHAbs = 0x28 // BPF_LD | BPF_H | BPF_ABS
	bpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfRetK   = 0x06 // BPF_RET | BPF_K
)

type bpfInsn struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

// announceFilter accepts untagged EtherType 0x88b5 (up to maxFrame bytes)
// and drops everything else. On the bridge device frames arrive untagged.
var announceFilter = []bpfInsn{
	{bpfLdHAbs, 0, 0, 12},      // A = EtherType
	{bpfJeqK, 0, 1, EtherType}, // ours -> accept, else drop
	{bpfRetK, 0, 0, maxFrame},  // accept
	{bpfRetK, 0, 0, 0},         // drop
}

// maxFrame is the longest frame worth reading.
const maxFrame = ethHdrLen + maxPayload

// packetOutgoing is PACKET_OUTGOING.
const packetOutgoing = 4

// keepPkttype: our own frames come back as PACKET_OUTGOING.
func keepPkttype(t uint8) bool { return t != packetOutgoing }
