// SPDX-License-Identifier: GPL-2.0-or-later

package lldp

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"reflect"
	"strings"
	"testing"
)

// capturedUCG is a real LLDPDU from a UniFi gateway, captured on a Deco port.
func capturedUCG(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/ucg.hex")
	if err != nil {
		t.Fatal(err)
	}
	f, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// runBPF is a minimal classic BPF interpreter for the opcodes lldpFilter
// uses. Like the kernel, an out-of-bounds load drops the packet.
func runBPF(t *testing.T, prog []bpfInsn, pkt []byte) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case bpfLdHAbs:
			if int(in.K)+2 > len(pkt) {
				return 0
			}
			a = uint32(binary.BigEndian.Uint16(pkt[in.K:]))
		case bpfJeqK:
			if a == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfRetK:
			return in.K
		default:
			t.Fatalf("pc %d: unsupported opcode %#x", pc, in.Code)
		}
	}
	t.Fatal("program fell off the end")
	return 0
}

func TestDecodeUCGCapture(t *testing.T) {
	n, err := Decode(capturedUCG(t))
	if err != nil {
		t.Fatal(err)
	}
	if n.ChassisIDSubtype != ChassisLocal || n.ChassisID != "1c:6a:1b:c5:04:c1" {
		t.Errorf("chassis %d %q", n.ChassisIDSubtype, n.ChassisID)
	}
	if n.PortIDSubtype != PortMAC || n.PortID != "1c:6a:1b:c5:04:c4" {
		t.Errorf("port %d %q", n.PortIDSubtype, n.PortID)
	}
	if n.SrcMAC != "1c:6a:1b:c5:04:c4" || n.PortDescr != "eth3" || n.TTL != 120 || n.SysName != "Example-Network" {
		t.Errorf("src %q descr %q ttl %d name %q", n.SrcMAC, n.PortDescr, n.TTL, n.SysName)
	}
	if !strings.HasPrefix(n.SysDescr, "Debian GNU/Linux 13") {
		t.Errorf("sysdescr %q", n.SysDescr)
	}
	if len(n.MgmtIPs) == 0 || n.MgmtIPs[0] != "192.168.0.1" {
		t.Errorf("mgmt %v", n.MgmtIPs)
	}
}

func TestLLDPFilter(t *testing.T) {
	ucg := capturedUCG(t)
	tagged := append(append(append([]byte{}, ucg[:12]...), 0x81, 0x00, 0x00, 0x01), ucg[12:]...)
	if _, err := Decode(tagged); err != nil {
		t.Fatalf("tagged copy does not decode: %v", err)
	}
	ipv4 := append(append([]byte{}, ucg[:12]...), 0x08, 0x00, 0x45, 0x00)
	taggedIPv4 := append(append([]byte{}, ucg[:12]...), 0x81, 0x00, 0x00, 0x01, 0x08, 0x00)
	own, err := Encode(apMAC, apInfo())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		pkt    []byte
		accept bool
	}{
		{"gateway LLDPDU", ucg, true},
		{"802.1Q-tagged LLDPDU", tagged, true},
		{"our encoded LLDPDU", own, true},
		{"IPv4", ipv4, false},
		{"802.1Q-tagged IPv4", taggedIPv4, false},
		{"tag with no inner ethertype", tagged[:16], false},
		{"runt", ucg[:10], false},
	} {
		got := runBPF(t, lldpFilter, c.pkt)
		if (got != 0) != c.accept {
			t.Errorf("%s: filter returned %#x, want accept=%v", c.name, got, c.accept)
		}
		if c.accept && got < uint32(len(c.pkt)) {
			t.Errorf("%s: snap %d truncates a %d-byte frame", c.name, got, len(c.pkt))
		}
	}
}

func TestReceiveSocketConstants(t *testing.T) {
	// htons(ETH_P_ALL); the old bind used htons(0x88cc), which a bridge
	// port never delivers to.
	if ethPAll != 0x0300 {
		t.Errorf("ethPAll = %#x, want 0x0300", ethPAll)
	}
	if keepPkttype(packetOutgoing) {
		t.Error("PACKET_OUTGOING frames (our own announcements) must be skipped")
	}
	for _, pt := range []uint8{0, 1, 2, 3} { // host, broadcast, multicast, otherhost
		if !keepPkttype(pt) {
			t.Errorf("pkttype %d dropped", pt)
		}
	}
	if !reflect.DeepEqual(lldpFilter[len(lldpFilter)-1], bpfInsn{bpfRetK, 0, 0, 0}) {
		t.Error("filter must end by dropping")
	}
}
