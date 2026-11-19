// SPDX-License-Identifier: GPL-2.0-or-later

package radsec

import (
	"bytes"
	"testing"
)

func TestParseRejects(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		make([]byte, 19),
		{1, 1, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},       // Length below the header
		{1, 1, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},       // Length past the data
		{1, 1, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1}, // attribute length 1
	} {
		if _, err := parse(b, maxUDP); err == nil {
			t.Errorf("accepted %x", b)
		}
	}
	// trailing bytes past Length are cut (RFC 2865 §3)
	p := build(4, 1, make([]byte, 16), attr{40, []byte{0, 0, 0, 1}})
	q, err := parse(append(append([]byte(nil), p...), 9, 9, 9), maxUDP)
	if err != nil || !bytes.Equal(q, p) {
		t.Fatalf("padding: %v", err)
	}
	// two Message-Authenticators, or a short one
	two := build(1, 1, make([]byte, 16), attr{80, make([]byte, 16)}, attr{80, make([]byte, 16)})
	short := build(1, 1, make([]byte, 16), attr{80, make([]byte, 8)})
	for _, b := range [][]byte{two, short} {
		if _, err := maOffset(b); err == nil {
			t.Errorf("Message-Authenticator accepted in %x", b)
		}
	}
}

func TestRehideTunnelPassword(t *testing.T) {
	ra, salt := randBytes(16), []byte{0x81, 0x23}
	oldS, newS := []byte("old-secret"), []byte("new-secret")
	plain := append([]byte{6}, []byte("vlan42")...)
	ct := hide(plain, append(append([]byte(nil), ra...), salt...), oldS)
	val := append(append([]byte{1}, salt...), ct...) // tag, salt, cipher
	p := build(codeAccessAccept, 1, ra, attr{attrTunnelPassword, val})
	if err := rehideAttrs(p, ra, ra, oldS, newS); err != nil {
		t.Fatal(err)
	}
	got := findAttr(p, attrTunnelPassword)
	if got[0] != 1 || !bytes.Equal(got[1:3], salt) {
		t.Fatal("tag or salt changed")
	}
	if out := unhide(got[3:], append(append([]byte(nil), ra...), salt...), newS); !bytes.Equal(out[:len(plain)], plain) {
		t.Fatalf("re-encrypted to %x", out)
	}
	// a hidden attribute that cannot be re-encrypted is an error
	bad := build(codeAccessAccept, 1, ra, attr{attrUserPassword, make([]byte, 7)})
	if err := rehideAttrs(bad, ra, ra, oldS, newS); err == nil {
		t.Fatal("bad User-Password accepted")
	}
}
