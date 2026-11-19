// SPDX-License-Identifier: GPL-2.0-or-later

package radsec

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are test-only keys made with OpenSSL 3.5:
//
//	genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec-plain.pem
//	pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:fixture-only
//	pkcs8 -topk8 -v2 des3 -passout pass:fixture-only
//	genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-plain.pem
//	pkcs8 -topk8 -v2 aes-128-cbc -passout pass:fixture-only
//	rsa -traditional -aes256 -passout pass:fixture-only
func fixture(t *testing.T, name string) []byte {
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseKeyOpenSSLFormats(t *testing.T) {
	ec, err := parseKey(fixture(t, "ec-plain.pem"), "")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := parseKey(fixture(t, "rsa-plain.pem"), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		file string
		want any
	}{
		{"ec-pbes2-aes256.pem", ec}, {"ec-pbes2-des3.pem", ec},
		{"rsa-pbes2-aes128.pem", rs}, {"rsa-legacy-aes256.pem", rs},
	} {
		t.Run(c.file, func(t *testing.T) {
			b := fixture(t, c.file)
			k, err := parseKey(b, "fixture-only")
			if err != nil {
				t.Fatal(err)
			}
			switch w := c.want.(type) {
			case *ecdsa.PrivateKey:
				if !w.Equal(k) {
					t.Fatal("different EC key")
				}
			case *rsa.PrivateKey:
				if !w.Equal(k) {
					t.Fatal("different RSA key")
				}
			}
			if _, err := parseKey(b, "wrong-password"); err == nil {
				t.Fatal("wrong password accepted")
			}
			if _, err := parseKey(b, ""); err == nil || !strings.Contains(err.Error(), "password") {
				t.Fatalf("no password: %v", err)
			}
			// the controller's encoding: base64 of the PEM file
			if _, err := parseKey([]byte(base64.StdEncoding.EncodeToString(b)), "fixture-only"); err != nil {
				t.Fatalf("base64: %v", err)
			}
		})
	}
}

func TestControllerCABundleEncoding(t *testing.T) {
	// the controller joins every CA file (chomped) with "\n" and base64s the
	// result (ubntconf config generator: x_ca_crt)
	a, b := newPKI(t, "127.0.0.1"), newPKI(t, "127.0.0.1")
	joined := strings.TrimRight(string(a.caPEM), "\n") + "\n" + strings.TrimRight(string(b.caPEM), "\n")
	blob := []byte(base64.StdEncoding.EncodeToString([]byte(joined)))
	cs, err := parseCerts(blob)
	if err != nil || len(cs) != 2 {
		t.Fatalf("%d certs, %v", len(cs), err)
	}
	// DER, base64'd
	cs, err = parseCerts([]byte(base64.StdEncoding.EncodeToString(a.caCert.Raw)))
	if err != nil || len(cs) != 1 {
		t.Fatalf("DER: %v", err)
	}
	if _, err := parseCerts([]byte("not a certificate !!")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestTLSConfigFailsClosed(t *testing.T) {
	k := newPKI(t, "127.0.0.1")
	other := newPKI(t, "127.0.0.1")
	cfg, err := k.material().tlsConfig(net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify || cfg.RootCAs == nil || cfg.ServerName != "10.0.0.5" || cfg.MinVersion < 0x0303 {
		t.Fatalf("weak config: %+v", cfg)
	}
	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Leaf == nil {
		t.Fatal("no client certificate")
	}
	// the key must belong to the certificate
	m := k.material()
	m.Key = other.cliKey
	if _, err := m.tlsConfig(net.ParseIP("10.0.0.5")); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key: %v", err)
	}
	// the client chain may list the CA first: the leaf is the key's
	m = k.material()
	m.Cert = append(append([]byte(nil), k.caPEM...), k.cliPEM...)
	cfg, err = m.tlsConfig(net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if leaf.Subject.CommonName != "deco-ap" || len(cfg.Certificates[0].Certificate) != 2 {
		t.Fatal("leaf not first")
	}
	if _, err := k.material().tlsConfig(nil); err == nil {
		t.Fatal("no IP accepted")
	}
}
