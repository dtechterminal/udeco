// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// AES-CMAC (RFC 4493) and AES-SIV (RFC 5297), what hostapd 2.9 seals its
// RRB-OUI frames with (src/crypto/aes-siv.c: aes_siv_encrypt with a 32-byte
// key is AES-CMAC-SIV-128: the first half keys S2V, the second CTR).

var errSIV = errors.New("mtkft: AES-SIV authentication failed")

// cmac is AES-CMAC under one AES-128 block cipher.
type cmac struct {
	b      cipher.Block
	k1, k2 [16]byte
}

func newCMAC(key []byte) (*cmac, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c := &cmac{b: b}
	var l [16]byte
	b.Encrypt(l[:], l[:])
	c.k1 = dbl(l)
	c.k2 = dbl(c.k1)
	return c, nil
}

// dbl is multiplication by x in GF(2^128) (RFC 5297 "dbl").
func dbl(in [16]byte) (out [16]byte) {
	carry := in[0] >> 7
	for i := 0; i < 15; i++ {
		out[i] = in[i]<<1 | in[i+1]>>7
	}
	out[15] = in[15] << 1
	out[15] ^= 0x87 & -carry
	return out
}

func (c *cmac) sum(msg []byte) [16]byte {
	var x [16]byte
	n := len(msg)
	full := n > 0 && n%16 == 0
	blocks := (n + 15) / 16
	if blocks == 0 {
		blocks = 1
	}
	for i := 0; i < blocks-1; i++ {
		subtle.XORBytes(x[:], x[:], msg[i*16:i*16+16])
		c.b.Encrypt(x[:], x[:])
	}
	var last [16]byte
	rest := msg[(blocks-1)*16:]
	if full {
		subtle.XORBytes(last[:], rest, c.k1[:])
	} else {
		copy(last[:], rest)
		last[len(rest)] = 0x80
		subtle.XORBytes(last[:], last[:], c.k2[:])
	}
	subtle.XORBytes(x[:], x[:], last[:])
	c.b.Encrypt(x[:], x[:])
	return x
}

// s2v is RFC 5297 S2V over ad... and the plaintext p.
func (c *cmac) s2v(ad [][]byte, p []byte) [16]byte {
	var zero [16]byte
	d := c.sum(zero[:])
	for _, a := range ad {
		m := c.sum(a)
		d = dbl(d)
		subtle.XORBytes(d[:], d[:], m[:])
	}
	if len(p) >= 16 {
		t := append([]byte(nil), p...)
		subtle.XORBytes(t[len(t)-16:], t[len(t)-16:], d[:])
		return c.sum(t)
	}
	d = dbl(d)
	var t [16]byte
	copy(t[:], p)
	t[len(p)] = 0x80
	subtle.XORBytes(t[:], t[:], d[:])
	return c.sum(t[:])
}

// sivCTR runs AES-CTR under key from the synthetic IV v (bits 31 and 63
// cleared, RFC 5297 2.6).
func sivCTR(key []byte, v [16]byte, dst, src []byte) error {
	b, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	v[8] &= 0x7f
	v[12] &= 0x7f
	cipher.NewCTR(b, v[:]).XORKeyStream(dst, src)
	return nil
}

// sivSeal returns V || C for plaintext p under the 32-byte key with the
// associated data ad, in hostapd's order.
func sivSeal(key []byte, p []byte, ad ...[]byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("mtkft: AES-SIV key must be 32 bytes")
	}
	c, err := newCMAC(key[:16])
	if err != nil {
		return nil, err
	}
	v := c.s2v(ad, p)
	out := make([]byte, 16+len(p))
	copy(out, v[:])
	if err := sivCTR(key[16:], v, out[16:], p); err != nil {
		return nil, err
	}
	return out, nil
}

// sivOpen authenticates and decrypts V || C.
func sivOpen(key []byte, vc []byte, ad ...[]byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("mtkft: AES-SIV key must be 32 bytes")
	}
	if len(vc) < 16 {
		return nil, errSIV
	}
	var v [16]byte
	copy(v[:], vc[:16])
	p := make([]byte, len(vc)-16)
	if err := sivCTR(key[16:], v, p, vc[16:]); err != nil {
		return nil, err
	}
	c, err := newCMAC(key[:16])
	if err != nil {
		return nil, err
	}
	t := c.s2v(ad, p)
	if subtle.ConstantTimeCompare(t[:], v[:]) != 1 {
		clear(p)
		return nil, errSIV
	}
	return p, nil
}
