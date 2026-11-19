// SPDX-License-Identifier: GPL-2.0-or-later

package radsec

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// --- an independent RADIUS encoder for the tests (not the package's) ---

type attr struct {
	t byte
	v []byte
}

func build(code, id byte, auth []byte, attrs ...attr) []byte {
	b := []byte{code, id, 0, 0}
	b = append(b, auth...)
	for _, a := range attrs {
		b = append(b, a.t, byte(len(a.v)+2))
		b = append(b, a.v...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// tMA computes and writes the Message-Authenticator (attribute 80, which
// must be present, zeroed) with the authenticator field as authForMA.
func tMA(p, authForMA, secret []byte) {
	q := append([]byte(nil), p...)
	copy(q[4:20], authForMA)
	off := -1
	for i := 20; i < len(q); i += int(q[i+1]) {
		if q[i] == 80 {
			off = i + 2
		}
	}
	for i := off; i < off+16; i++ {
		q[i] = 0
	}
	m := hmac.New(md5.New, secret)
	m.Write(q)
	copy(p[off:], m.Sum(nil))
}

func tMD5(parts ...[]byte) []byte {
	h := md5.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// tAcctAuth writes an Accounting-Request's Request Authenticator.
func tAcctAuth(p, secret []byte) {
	copy(p[4:20], make([]byte, 16))
	copy(p[4:20], tMD5(p[:4], make([]byte, 16), p[20:], secret))
}

// tRespAuth writes a Response Authenticator.
func tRespAuth(p, reqAuth, secret []byte) {
	copy(p[4:20], tMD5(p[:4], reqAuth, p[20:], secret))
}

func tRespAuthOK(p, reqAuth, secret []byte) bool {
	return bytes.Equal(p[4:20], tMD5(p[:4], reqAuth, p[20:], secret))
}

func tMAOK(p, authForMA, secret []byte) bool {
	q := append([]byte(nil), p...)
	got := []byte(nil)
	for i := 20; i < len(q); i += int(q[i+1]) {
		if q[i] == 80 {
			got = append([]byte(nil), q[i+2:i+18]...)
		}
	}
	if got == nil {
		return false
	}
	want := append([]byte(nil), p...)
	tMA(want, authForMA, secret)
	for i := 20; i < len(want); i += int(want[i+1]) {
		if want[i] == 80 {
			return bytes.Equal(want[i+2:i+18], got)
		}
	}
	return false
}

// hide encrypts plain (padded to 16) the RFC 2865 §5.2 way from iv.
func hide(plain, iv, secret []byte) []byte {
	p := append([]byte(nil), plain...)
	for len(p)%16 != 0 || len(p) == 0 {
		p = append(p, 0)
	}
	out := make([]byte, len(p))
	prev := iv
	for i := 0; i < len(p); i += 16 {
		b := tMD5(secret, prev)
		for j := 0; j < 16; j++ {
			out[i+j] = p[i+j] ^ b[j]
		}
		prev = out[i : i+16]
	}
	return out
}

func unhide(c, iv, secret []byte) []byte {
	out := make([]byte, len(c))
	prev := iv
	for i := 0; i < len(c); i += 16 {
		b := tMD5(secret, prev)
		for j := 0; j < 16; j++ {
			out[i+j] = c[i+j] ^ b[j]
		}
		prev = c[i : i+16]
	}
	return out
}

// mppe builds an MS-MPPE key VSA value (vendor 311) with key hidden for
// (ra, secret) under salt.
func mppe(typ byte, key, ra, salt, secret []byte) []byte {
	plain := append([]byte{byte(len(key))}, key...)
	ct := hide(plain, append(append([]byte(nil), ra...), salt...), secret)
	sub := append([]byte{typ, byte(2 + 2 + len(ct))}, salt...)
	sub = append(sub, ct...)
	return append([]byte{0, 0, 1, 55}, sub...) // 311
}

// mppeKey recovers the key from an MS-MPPE VSA value.
func mppeKey(v, ra, secret []byte) []byte {
	salt, ct := v[6:8], v[8:]
	p := unhide(ct, append(append([]byte(nil), ra...), salt...), secret)
	return p[1 : 1+int(p[0])]
}

func findAttr(p []byte, t byte) []byte {
	for i := 20; i+2 <= len(p); i += int(p[i+1]) {
		if p[i] == t {
			return p[i+2 : i+int(p[i+1])]
		}
	}
	return nil
}

func findVSA(p []byte, sub byte) []byte {
	for i := 20; i+2 <= len(p); i += int(p[i+1]) {
		v := p[i+2 : i+int(p[i+1])]
		if p[i] == 26 && len(v) > 6 && binary.BigEndian.Uint32(v[:4]) == 311 && v[4] == sub {
			return v
		}
	}
	return nil
}

// --- certificates ---

type pki struct {
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	caPEM   []byte
	srv     tls.Certificate
	cliPEM  []byte
	cliKey  []byte
	cliPool *x509.CertPool
}

var serial int64 = 1

func mkCert(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, pub, signer any) *x509.Certificate {
	t.Helper()
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// newPKI: a CA, a server certificate for serverIPs and a client
// certificate, all P-256.
func newPKI(t *testing.T, serverIPs ...string) *pki {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := mkCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "test radsec CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, &caKey.PublicKey, caKey)
	p := &pki{caCert: ca, caKey: caKey, caPEM: pemOf("CERTIFICATE", ca.Raw)}
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var ips []net.IP
	for _, s := range serverIPs {
		ips = append(ips, net.ParseIP(s))
	}
	sc := mkCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "radius.example"}, IPAddresses: ips,
		DNSNames: []string{"radius.example"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature}, ca, &sk.PublicKey, caKey)
	p.srv = tls.Certificate{Certificate: [][]byte{sc.Raw}, PrivateKey: sk}
	ck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cc := mkCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "deco-ap"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature},
		ca, &ck.PublicKey, caKey)
	p.cliPEM = pemOf("CERTIFICATE", cc.Raw)
	kd, _ := x509.MarshalPKCS8PrivateKey(ck)
	p.cliKey = pemOf("PRIVATE KEY", kd)
	p.cliPool = x509.NewCertPool()
	p.cliPool.AddCert(ca)
	return p
}

func (p *pki) material() Material {
	return Material{CA: p.caPEM, Cert: p.cliPEM, Key: p.cliKey}
}
