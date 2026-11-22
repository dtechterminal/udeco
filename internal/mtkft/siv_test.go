// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// RFC 4493 examples 1 and 2 (also checked with pyca/cryptography's CMAC).
func TestCMAC(t *testing.T) {
	c, err := newCMAC(unhex(t, "2b7e151628aed2a6abf7158809cf4f3c"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.sum(nil); hex.EncodeToString(got[:]) != "bb1d6929e95937287fa37d129b756746" {
		t.Errorf("CMAC(empty) %x", got)
	}
	if got := c.sum(unhex(t, "6bc1bee22e409f96e93d7e117393172a")); hex.EncodeToString(got[:]) != "070a16b46b4d4144f79bdd9dd04a287c" {
		t.Errorf("CMAC(16) %x", got)
	}
}

const sivKey = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

// RFC 5297 A.1, and hostapd's three associated data (source, auth TLVs,
// subtype) with and without plaintext, the latter two from
// pyca/cryptography's AESSIV.
func TestAESSIV(t *testing.T) {
	key := unhex(t, sivKey)
	src, auth := unhex(t, "a842a1000001"), make([]byte, 20)
	for i := range auth {
		auth[i] = byte(i)
	}
	p40 := make([]byte, 40)
	for i := range p40 {
		p40[i] = byte(i)
	}
	for _, c := range []struct {
		name string
		p    []byte
		ad   [][]byte
		want string
	}{
		{"A.1", unhex(t, "112233445566778899aabbccddee"), [][]byte{unhex(t, "101112131415161718191a1b1c1d1e1f2021222324252627")},
			"85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c"},
		{"3 AD", p40, [][]byte{src, auth, {3}},
			"9bca14280eac007456c74d047785b24b53f98492de3f38cc26eca0fde9088d72796823fcb8e405a8faee7040694a60a779ac8969ee209b38"},
		{"3 AD empty", nil, [][]byte{src, auth, {5}}, "49237d1de764695952dbaf0989e68b71"},
	} {
		got, err := sivSeal(key, c.p, c.ad...)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("%s: %x", c.name, got)
		}
		p, err := sivOpen(key, got, c.ad...)
		if err != nil || !bytes.Equal(p, c.p) {
			t.Errorf("%s: open %x %v", c.name, p, err)
		}
		bad := append([]byte(nil), got...)
		bad[len(bad)-1] ^= 1
		if _, err := sivOpen(key, bad, c.ad...); err == nil {
			t.Errorf("%s: tampered ciphertext opened", c.name)
		}
		if _, err := sivOpen(key, got, append(c.ad[:len(c.ad):len(c.ad)], []byte{9})...); err == nil {
			t.Errorf("%s: other associated data opened", c.name)
		}
	}
	if _, err := sivSeal(key[:16], nil); err == nil {
		t.Error("16-byte SIV key accepted")
	}
	if _, err := sivOpen(key, make([]byte, 15)); err == nil {
		t.Error("15-byte SIV input opened")
	}
}
