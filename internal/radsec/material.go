// SPDX-License-Identifier: GPL-2.0-or-later

package radsec

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"net"
	"strings"
)

// Material is the TLS identity for one RadSec server, as the controller
// sends it (system_cfg certs.<i>.key, aaa.N.radius.*.M.private_key_passwd):
// each blob is PEM text, base64 of PEM text (what the controller writes:
// its CA bundle is base64 of the joined PEM files) or base64/raw DER. Key
// and KeyPassword are secrets.
type Material struct {
	CA, Cert, Key []byte
	KeyPassword   string
}

// String never prints the key or its password.
func (m Material) String() string {
	return fmt.Sprintf("ca=%dB cert=%dB key=<%dB> passwd=%t", len(m.CA), len(m.Cert), len(m.Key), m.KeyPassword != "")
}

// GoString is String.
func (m Material) GoString() string { return "radsec.Material{" + m.String() + "}" }

// maxIterations bounds PBKDF2 work for an encrypted key (OpenSSL's default
// is 2048; recent tools use up to a few hundred thousand).
const maxIterations = 1 << 21

// decodeBlob returns PEM text, or DER bytes with der=true.
func decodeBlob(b []byte) (out []byte, der bool, err error) {
	t := bytes.TrimSpace(b)
	if len(t) == 0 {
		return nil, false, errors.New("empty")
	}
	if bytes.Contains(t, []byte("-----BEGIN ")) {
		return t, false, nil
	}
	s := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, string(t))
	d, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if d, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err != nil {
			return nil, false, errors.New("neither PEM nor base64")
		}
	}
	if bytes.Contains(d, []byte("-----BEGIN ")) {
		return bytes.TrimSpace(d), false, nil
	}
	if len(d) > 0 && d[0] == 0x30 {
		return d, true, nil
	}
	return nil, false, errors.New("base64 holds neither PEM nor DER")
}

// parseCerts reads one or more certificates.
func parseCerts(b []byte) ([]*x509.Certificate, error) {
	data, der, err := decodeBlob(b)
	if err != nil {
		return nil, err
	}
	if der {
		return x509.ParseCertificates(data)
	}
	var out []*x509.Certificate
	for rest := data; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" && blk.Type != "TRUSTED CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate")
	}
	return out, nil
}

// parseKey reads a private key: PKCS#8 (also encrypted, PBES2), PKCS#1 RSA
// or SEC1 EC, PEM (legacy "Proc-Type: 4,ENCRYPTED" too) or DER.
func parseKey(b []byte, pass string) (crypto.Signer, error) {
	data, der, err := decodeBlob(b)
	if err != nil {
		return nil, err
	}
	if der {
		if k, err := parseDERKey(data); err == nil {
			return k, nil
		}
		if pass == "" {
			return nil, errors.New("unreadable DER key")
		}
		plain, err := decryptPKCS8(data, pass)
		if err != nil {
			return nil, err
		}
		return parseDERKey(plain)
	}
	for rest := data; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return nil, errors.New("no private key")
		}
		switch blk.Type {
		case "ENCRYPTED PRIVATE KEY":
			if pass == "" {
				return nil, errors.New("encrypted private key without a password")
			}
			plain, err := decryptPKCS8(blk.Bytes, pass)
			if err != nil {
				return nil, err
			}
			return parseDERKey(plain)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			body := blk.Bytes
			//nolint:staticcheck // legacy RFC 1423 PEM encryption is what old tools write
			if x509.IsEncryptedPEMBlock(blk) {
				if pass == "" {
					return nil, errors.New("encrypted private key without a password")
				}
				//nolint:staticcheck // see above
				if body, err = x509.DecryptPEMBlock(blk, []byte(pass)); err != nil {
					return nil, errors.New("private key: wrong password or damaged key")
				}
			}
			return parseDERKey(body)
		}
	}
}

func parseDERKey(d []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(d); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("unsupported private key type")
	}
	if k, err := x509.ParsePKCS1PrivateKey(d); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(d); err == nil {
		return k, nil
	}
	return nil, errors.New("private key: not PKCS#8, PKCS#1 or SEC1 (or a wrong password)")
}

// PKCS#5 v2 (RFC 8018) object identifiers.
var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

type encryptedPKInfo struct {
	Algo pkix.AlgorithmIdentifier
	Data []byte
}

type pbes2Params struct {
	KDF pkix.AlgorithmIdentifier
	Enc pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

// decryptPKCS8 decrypts a PBES2 EncryptedPrivateKeyInfo (PBKDF2 with
// HMAC-SHA1/256/384/512; AES-CBC or 3DES-CBC), what OpenSSL writes for
// `-aes256` / `pkcs8 -topk8`.
func decryptPKCS8(der []byte, pass string) ([]byte, error) {
	var info encryptedPKInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil || len(rest) != 0 {
		return nil, errors.New("encrypted key: not PKCS#8")
	}
	if !info.Algo.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("encrypted key: scheme %v is not supported (PBES2 only)", info.Algo.Algorithm)
	}
	var p pbes2Params
	if _, err := asn1.Unmarshal(info.Algo.Parameters.FullBytes, &p); err != nil {
		return nil, errors.New("encrypted key: bad PBES2 parameters")
	}
	if !p.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, errors.New("encrypted key: key derivation is not PBKDF2")
	}
	var kp pbkdf2Params
	if _, err := asn1.Unmarshal(p.KDF.Parameters.FullBytes, &kp); err != nil {
		return nil, errors.New("encrypted key: bad PBKDF2 parameters")
	}
	if kp.Iterations < 1 || kp.Iterations > maxIterations {
		return nil, fmt.Errorf("encrypted key: %d PBKDF2 iterations (1..%d)", kp.Iterations, maxIterations)
	}
	var h func() hash.Hash
	switch prf := kp.PRF.Algorithm; {
	case len(prf) == 0 || prf.Equal(oidHMACSHA1):
		h = sha1.New
	case prf.Equal(oidHMACSHA256):
		h = sha256.New
	case prf.Equal(oidHMACSHA384):
		h = sha512.New384
	case prf.Equal(oidHMACSHA512):
		h = sha512.New
	default:
		return nil, errors.New("encrypted key: PBKDF2 PRF is not supported")
	}
	var keyLen int
	var newCipher func([]byte) (cipher.Block, error)
	switch e := p.Enc.Algorithm; {
	case e.Equal(oidAES128CBC):
		keyLen, newCipher = 16, aes.NewCipher
	case e.Equal(oidAES192CBC):
		keyLen, newCipher = 24, aes.NewCipher
	case e.Equal(oidAES256CBC):
		keyLen, newCipher = 32, aes.NewCipher
	case e.Equal(oidDESEDE3CBC):
		keyLen, newCipher = 24, des.NewTripleDESCipher
	default:
		return nil, errors.New("encrypted key: cipher is not supported (AES-CBC or 3DES-CBC)")
	}
	if kp.KeyLength != 0 && kp.KeyLength != keyLen {
		return nil, errors.New("encrypted key: key length does not match the cipher")
	}
	var iv []byte
	if _, err := asn1.Unmarshal(p.Enc.Parameters.FullBytes, &iv); err != nil {
		return nil, errors.New("encrypted key: bad IV")
	}
	key, err := pbkdf2.Key(h, pass, kp.Salt, kp.Iterations, keyLen)
	if err != nil {
		return nil, errors.New("encrypted key: key derivation failed")
	}
	blk, err := newCipher(key)
	if err != nil || len(iv) != blk.BlockSize() || len(info.Data) == 0 || len(info.Data)%blk.BlockSize() != 0 {
		return nil, errors.New("encrypted key: bad cipher parameters")
	}
	out := make([]byte, len(info.Data))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, info.Data)
	// PKCS#7 padding; a wrong password nearly always fails here
	n := int(out[len(out)-1])
	if n == 0 || n > blk.BlockSize() || n > len(out) {
		return nil, errors.New("private key: wrong password or damaged key")
	}
	for _, c := range out[len(out)-n:] {
		if int(c) != n {
			return nil, errors.New("private key: wrong password or damaged key")
		}
	}
	return out[:len(out)-n], nil
}

// samePublic reports whether the key belongs to the certificate.
func samePublic(k crypto.Signer, c *x509.Certificate) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	switch k.Public().(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		if e, ok := k.Public().(eq); ok {
			return e.Equal(c.PublicKey)
		}
	}
	return false
}

// tlsConfig builds the client TLS configuration for a RadSec server at ip:
// only the CA bundle is trusted (no system roots, never skipped), the
// server certificate must name ip (an IP SAN; Go ignores the CN), TLS 1.2
// or later, and the client certificate is presented.
func (m Material) tlsConfig(ip net.IP) (*tls.Config, error) {
	if ip == nil {
		return nil, errors.New("server address is not an IP address")
	}
	cas, err := parseCerts(m.CA)
	if err != nil {
		return nil, fmt.Errorf("CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	for _, c := range cas {
		pool.AddCert(c)
	}
	chain, err := parseCerts(m.Cert)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	key, err := parseKey(m.Key, m.KeyPassword)
	if err != nil {
		return nil, fmt.Errorf("client private key: %w", err)
	}
	// the leaf is the certificate that belongs to the key, wherever it sits
	leaf := -1
	for i, c := range chain {
		if samePublic(key, c) {
			leaf = i
			break
		}
	}
	if leaf < 0 {
		return nil, errors.New("client private key does not match the client certificate")
	}
	ders := [][]byte{chain[leaf].Raw}
	for i, c := range chain {
		if i != leaf {
			ders = append(ders, c.Raw)
		}
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      pool,
		ServerName:   ip.String(), // an IP: verified against the IP SANs, no SNI sent
		Certificates: []tls.Certificate{{Certificate: ders, PrivateKey: key, Leaf: chain[leaf]}},
		// RFC 6614 §2.3: no renegotiation needed; the default refuses it.
	}, nil
}
