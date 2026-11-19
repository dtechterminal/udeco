// SPDX-License-Identifier: GPL-2.0-or-later

// Package radsec is a local RADIUS-over-UDP to RADIUS/TLS (RadSec, RFC 6614)
// proxy. The Deco's hostapd 2.9 has a UDP-only RADIUS client (its TLS
// backend is tls_none), so for a controller RADIUS server marked tls=enabled
// the agent points hostapd at 127.0.0.1:<port> with a local shared secret,
// and this package carries every request over one mutually authenticated
// TLS connection to the real server, re-signed with the server's secret:
//
//   - requests from hostapd are checked with the local secret
//     (Message-Authenticator on Access-Request, the Request Authenticator on
//     Accounting-Request) and dropped when they do not verify;
//   - the Identifier is remapped (several BSSes share one TLS connection);
//     Message-Authenticator and authenticators are recomputed with the
//     server's secret, and User-Password/Tunnel-Password re-encrypted;
//   - responses are checked with the server's secret (Response
//     Authenticator, and a Message-Authenticator is required on every
//     Access-Accept/Reject/Challenge), MS-MPPE keys and Tunnel-Password are
//     re-encrypted for the local secret, and the response goes back to the
//     hostapd socket that asked.
//
// The TLS side trusts only the controller's CA bundle, presents the
// controller's client certificate, requires TLS 1.2 or later and checks the
// server certificate against the server's IP address (an IP SAN). Nothing
// is sent in clear to the server, ever: no TLS, no RADIUS.
// docs/deco/features/radsec.md.
package radsec

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
)

// RADIUS codes and attributes the proxy handles.
const (
	codeAccessRequest      = 1
	codeAccessAccept       = 2
	codeAccessReject       = 3
	codeAccountingRequest  = 4
	codeAccountingResponse = 5
	codeAccessChallenge    = 11

	attrUserPassword         = 2
	attrVendorSpecific       = 26
	attrTunnelPassword       = 69
	attrMessageAuthenticator = 80

	vendorMicrosoft = 311
	msMPPESendKey   = 16
	msMPPERecvKey   = 17

	hdrLen = 20
	// maxUDP is the RADIUS UDP maximum (RFC 2865 §3); hostapd never sends
	// more, and a response larger than this is not passed back to it.
	maxUDP = 4096
	// maxTLS is the largest packet read from the TLS stream (RFC 7930).
	maxTLS = 65535
)

var errPacket = errors.New("malformed RADIUS packet")

// parse checks b as one RADIUS packet: a header, a Length that fits b
// (trailing bytes are cut, RFC 2865 §3) and well-formed attributes. The
// result aliases b.
func parse(b []byte, max int) ([]byte, error) {
	if len(b) < hdrLen {
		return nil, errPacket
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n < hdrLen || n > len(b) || n > max {
		return nil, errPacket
	}
	p := b[:n]
	for off := hdrLen; off < n; {
		if off+2 > n {
			return nil, errPacket
		}
		l := int(p[off+1])
		if l < 2 || off+l > n {
			return nil, errPacket
		}
		off += l
	}
	return p, nil
}

// eachAttr calls fn with the offset of each attribute's value, its type and
// value; p must have passed parse.
func eachAttr(p []byte, fn func(off int, typ byte, val []byte)) {
	for off := hdrLen; off+2 <= len(p); {
		l := int(p[off+1])
		fn(off+2, p[off], p[off+2:off+l])
		off += l
	}
}

// maOffset is the offset of the Message-Authenticator value, or -1 when
// there is none. More than one, or one that is not 16 bytes, is an error.
func maOffset(p []byte) (int, error) {
	at, n := -1, 0
	var err error
	eachAttr(p, func(off int, typ byte, val []byte) {
		if typ != attrMessageAuthenticator {
			return
		}
		n++
		if len(val) != 16 {
			err = errPacket
		}
		at = off
	})
	if err != nil || n > 1 {
		return -1, errPacket
	}
	return at, nil
}

// msgAuth is the Message-Authenticator of p (RFC 3579 §3.2): HMAC-MD5 over
// the packet with the authenticator field set to auth and the
// Message-Authenticator value zeroed.
func msgAuth(p []byte, maOff int, auth []byte, secret []byte) []byte {
	q := append([]byte(nil), p...)
	copy(q[4:20], auth)
	clear(q[maOff : maOff+16])
	m := hmac.New(md5.New, secret)
	m.Write(q)
	return m.Sum(nil)
}

// pktAuth is MD5(Code+Identifier+Length+auth+Attributes+secret): the
// Response Authenticator (auth = the request's) or, with 16 zero bytes, the
// Accounting-Request Request Authenticator (RFC 2866 §3).
func pktAuth(p []byte, auth []byte, secret []byte) []byte {
	h := md5.New()
	h.Write(p[:4])
	h.Write(auth)
	h.Write(p[hdrLen:])
	h.Write(secret)
	return h.Sum(nil)
}

var zero16 = make([]byte, 16)

// checkRequest verifies a request from hostapd with secret. An
// Access-Request must carry a valid Message-Authenticator (hostapd always
// adds one); an Accounting-Request must have a valid Request
// Authenticator (and a valid Message-Authenticator if it has one). Other
// codes are refused.
func checkRequest(p []byte, secret []byte) error {
	ma, err := maOffset(p)
	if err != nil {
		return err
	}
	switch p[0] {
	case codeAccessRequest:
		if ma < 0 {
			return errors.New("Access-Request without Message-Authenticator")
		}
		if !hmac.Equal(msgAuth(p, ma, p[4:20], secret), p[ma:ma+16]) {
			return errors.New("bad Message-Authenticator")
		}
	case codeAccountingRequest:
		if ma >= 0 && !hmac.Equal(msgAuth(p, ma, zero16, secret), p[ma:ma+16]) {
			return errors.New("bad Message-Authenticator")
		}
		if !hmac.Equal(pktAuth(p, zero16, secret), p[4:20]) {
			return errors.New("bad Request Authenticator")
		}
	default:
		return fmt.Errorf("code %d is not proxied", p[0])
	}
	return nil
}

// signRequest finishes a request for secret in place: the
// Message-Authenticator (if present) and, for Accounting-Request, the
// Request Authenticator. Access-Request keeps its random authenticator.
func signRequest(p []byte, secret []byte) {
	ma, _ := maOffset(p)
	switch p[0] {
	case codeAccessRequest:
		if ma >= 0 {
			copy(p[ma:], msgAuth(p, ma, p[4:20], secret))
		}
	case codeAccountingRequest:
		copy(p[4:20], zero16)
		if ma >= 0 {
			copy(p[ma:], msgAuth(p, ma, zero16, secret))
		}
		copy(p[4:20], pktAuth(p, zero16, secret))
	}
}

// responseCode reports whether c answers request code req.
func responseCode(req, c byte) bool {
	switch req {
	case codeAccessRequest:
		return c == codeAccessAccept || c == codeAccessReject || c == codeAccessChallenge
	case codeAccountingRequest:
		return c == codeAccountingResponse
	}
	return false
}

// checkResponse verifies a response to a request whose authenticator was
// reqAuth, with secret: the Response Authenticator, and the
// Message-Authenticator, which every Access-* response must carry (RFC 3579
// §3.2; hostapd requires it too, and it is the BlastRADIUS defence).
func checkResponse(p []byte, reqCode byte, reqAuth []byte, secret []byte) error {
	if !responseCode(reqCode, p[0]) {
		return fmt.Errorf("code %d does not answer code %d", p[0], reqCode)
	}
	ma, err := maOffset(p)
	if err != nil {
		return err
	}
	if !hmac.Equal(pktAuth(p, reqAuth, secret), p[4:20]) {
		return errors.New("bad Response Authenticator")
	}
	if ma < 0 {
		if reqCode == codeAccessRequest {
			return errors.New("response without Message-Authenticator")
		}
		return nil
	}
	if !hmac.Equal(msgAuth(p, ma, reqAuth, secret), p[ma:ma+16]) {
		return errors.New("bad Message-Authenticator")
	}
	return nil
}

// signResponse finishes a response to a request with authenticator reqAuth
// for secret in place: the Message-Authenticator (if present), then the
// Response Authenticator.
func signResponse(p []byte, reqAuth []byte, secret []byte) {
	if ma, _ := maOffset(p); ma >= 0 {
		copy(p[ma:], msgAuth(p, ma, reqAuth, secret))
	}
	copy(p[4:20], pktAuth(p, reqAuth, secret))
}

// --- hidden attributes ---

// rehidePassword re-encrypts a User-Password value (RFC 2865 §5.2) in
// place: decrypted with oldSecret and request authenticator oldRA,
// encrypted with newSecret and newRA.
func rehidePassword(v []byte, oldRA, newRA, oldSecret, newSecret []byte) error {
	if len(v) < 16 || len(v) > 128 || len(v)%16 != 0 {
		return errors.New("bad User-Password length")
	}
	rehide(v, oldRA, newRA, oldSecret, newSecret)
	return nil
}

// rehideSalted re-encrypts a salt-encrypted value in place (RFC 2868 §3.5
// Tunnel-Password, RFC 2548 §2.4.2 MS-MPPE-Send/Recv-Key): v is salt(2)
// followed by the cipher text; the salt and lengths are kept.
func rehideSalted(v []byte, oldRA, newRA, oldSecret, newSecret []byte) error {
	if len(v) < 2+16 || (len(v)-2)%16 != 0 {
		return errors.New("bad salt-encrypted value")
	}
	salt := v[:2:2]
	rehide(v[2:], append(append([]byte(nil), oldRA...), salt...), append(append([]byte(nil), newRA...), salt...),
		oldSecret, newSecret)
	return nil
}

// rehide runs the RFC 2865 §5.2 chain over c: b1 = MD5(S + iv),
// bi = MD5(S + c(i-1)), with the cipher text under each secret.
func rehide(c, oldIV, newIV, oldSecret, newSecret []byte) {
	prevOld, prevNew := oldIV, newIV
	for i := 0; i < len(c); i += 16 {
		bo := md5Sum(oldSecret, prevOld)
		bn := md5Sum(newSecret, prevNew)
		blk := c[i : i+16]
		oldC := append([]byte(nil), blk...)
		for j := range blk {
			blk[j] ^= bo[j] ^ bn[j]
		}
		prevOld, prevNew = oldC, append([]byte(nil), blk...)
	}
}

func md5Sum(a, b []byte) []byte {
	h := md5.New()
	h.Write(a)
	h.Write(b)
	return h.Sum(nil)
}

// rehideAttrs re-encrypts every hidden attribute of p that the proxy knows
// (User-Password, Tunnel-Password, MS-MPPE-Send-Key, MS-MPPE-Recv-Key) from
// (oldSecret, oldRA) to (newSecret, newRA), where RA is the request
// authenticator each side used. A hidden attribute it cannot re-encrypt is
// an error: it would reach the other side as garbage keys.
func rehideAttrs(p, oldRA, newRA, oldSecret, newSecret []byte) error {
	var err error
	set := func(e error) {
		if err == nil && e != nil {
			err = e
		}
	}
	eachAttr(p, func(_ int, typ byte, val []byte) {
		switch typ {
		case attrUserPassword:
			set(rehidePassword(val, oldRA, newRA, oldSecret, newSecret))
		case attrTunnelPassword:
			if len(val) < 1 {
				set(errPacket)
				return
			}
			set(rehideSalted(val[1:], oldRA, newRA, oldSecret, newSecret)) // tag, then salt
		case attrVendorSpecific:
			if len(val) < 4 || binary.BigEndian.Uint32(val[:4]) != vendorMicrosoft {
				return
			}
			for off := 4; off < len(val); {
				if off+2 > len(val) || val[off+1] < 2 || off+int(val[off+1]) > len(val) {
					set(errPacket)
					return
				}
				t, l := val[off], int(val[off+1])
				if t == msMPPESendKey || t == msMPPERecvKey {
					set(rehideSalted(val[off+2:off+l], oldRA, newRA, oldSecret, newSecret))
				}
				off += l
			}
		}
	})
	return err
}
