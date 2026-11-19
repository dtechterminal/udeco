// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux

package lldp

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxConstants(t *testing.T) {
	if want := unix.ETH_P_ALL>>8 | (unix.ETH_P_ALL&0xff)<<8; ethPAll != want {
		t.Errorf("ethPAll = %#x, want %#x", ethPAll, want)
	}
	if packetOutgoing != unix.PACKET_OUTGOING {
		t.Errorf("packetOutgoing = %d, want %d", packetOutgoing, unix.PACKET_OUTGOING)
	}
	for _, c := range []struct{ got, want uint16 }{
		{bpfLdHAbs, unix.BPF_LD | unix.BPF_H | unix.BPF_ABS},
		{bpfJeqK, unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K},
		{bpfRetK, unix.BPF_RET | unix.BPF_K},
	} {
		if c.got != c.want {
			t.Errorf("opcode %#x, want %#x", c.got, c.want)
		}
	}
}
