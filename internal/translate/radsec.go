// SPDX-License-Identifier: GPL-2.0-or-later

package translate

// RADIUS over TLS (RadSec, RFC 6614). With fw2_caps 0x80000
// (supportsRadSec) Network 11.1.50 writes, for a RADIUS profile with TLS on
// (com.ubnt.service.config.XHjguBsIf and the certificate section generator
// com.ubnt.service.config.ubntconf.aoUDgXMlCqEvTSIrOtq):
//
//	certs.status=enabled
//	certs.<i>.status=enabled
//	certs.<i>.comment=<outfile>
//	certs.<i>.outfile=ca-<i>.pem | client-<i>.crt | client-<i>.key
//	certs.<i>.key=<base64>      CA: base64 of every CA file of the profile,
//	                            each chomped, joined with "\n"; client
//	                            certificate and key as stored (base64)
//	aaa.N.radius.{auth,acct}.M.{ip,port,secret}
//	aaa.N.radius.{auth,acct}.M.tls=enabled
//	aaa.N.radius.{auth,acct}.M.{ca_cert,client_cert,private_key}=<outfile>
//	aaa.N.radius.{auth,acct}.M.private_key_passwd=<password>   (if set)
//
// The certs section comes before the aaa sections, and one profile's files
// are written once even when several WLANs use it. A UAP's ubntbox decodes
// each file to /etc/certs/<outfile> and writes auth_server_type=TLS plus
// auth_server_{ca_cert,client_cert,private_key}=/etc/certs/<file> for its
// patched hostapd; it refuses a TLS server without the CA and client
// certificate ("Radius auth over tls requires ca/client certificates").

import (
	"fmt"
	"net"
)

// RadSecPort is RADIUS/TLS's port (RFC 6614 §2.1): a TLS server without a
// port gets it.
const RadSecPort = 2083

// RadSecTLS is a RADIUS server's TLS identity as the controller sent it:
// the certs.<i>.key values (base64 text; decoded by internal/radsec) and
// the private key password. Key and KeyPassword are secrets.
type RadSecTLS struct {
	CA, Cert, Key             string
	KeyPassword               string
	CAFile, CertFile, KeyFile string // the controller's outfile names
}

// String never prints the key or the password.
func (t *RadSecTLS) String() string {
	if t == nil {
		return "<nil>"
	}
	return fmt.Sprintf("tls(ca=%s cert=%s key=%s passwd=%t)", t.CAFile, t.CertFile, t.KeyFile, t.KeyPassword != "")
}

// GoString is String.
func (t *RadSecTLS) GoString() string { return t.String() }

// radsecTLS reads the TLS identity of the server whose keys start with p
// ("aaa.N.radius.<kind>.M."); nil when it is not marked tls.
func radsecTLS(cfg Cfg, p string) *RadSecTLS {
	if !isOn(cfg[p+"tls"]) {
		return nil
	}
	t := &RadSecTLS{CAFile: cfg[p+"ca_cert"], CertFile: cfg[p+"client_cert"], KeyFile: cfg[p+"private_key"],
		KeyPassword: cfg[p+"private_key_passwd"]}
	t.CA, t.Cert, t.Key = certFile(cfg, t.CAFile), certFile(cfg, t.CertFile), certFile(cfg, t.KeyFile)
	return t
}

// certFile is the content of the certs.<i> entry written to outfile name.
func certFile(cfg Cfg, name string) string {
	if name == "" || !isOn(cfg["certs.status"]) {
		return ""
	}
	for _, i := range indices(cfg, "certs") {
		p := "certs." + i + "."
		if cfg[p+"outfile"] == name && isOn(cfg[p+"status"]) {
			return cfg[p+"key"]
		}
	}
	return ""
}

// radsecCheck is "" or why a WLAN with RadSec servers (aaa prefix a) must
// stay off: like a UAP, a TLS server needs the CA, the client certificate
// and the key; the proxy also needs an IP address (the server certificate
// is checked against it, and the egress firewall opens it by address).
func radsecCheck(cfg Cfg, a string) string {
	for _, kind := range []string{"auth", "acct"} {
		for _, m := range indices(cfg, a+"radius."+kind) {
			p := a + "radius." + kind + "." + m + "."
			if cfg[p+"status"] == "disabled" || cfg[p+"ip"] == "" {
				continue
			}
			t := radsecTLS(cfg, p)
			if t == nil {
				continue
			}
			switch {
			case t.CA == "":
				return fmt.Sprintf("RADIUS over TLS (RadSec) %s server %s: no CA certificate (certs.*)", kind, m)
			case t.Cert == "" || t.Key == "":
				return fmt.Sprintf("RADIUS over TLS (RadSec) %s server %s: no client certificate and key (certs.*)", kind, m)
			case net.ParseIP(cfg[p+"ip"]) == nil:
				return fmt.Sprintf("RADIUS over TLS (RadSec) %s server %s: the server must be an IP address", kind, m)
			}
		}
	}
	return ""
}
