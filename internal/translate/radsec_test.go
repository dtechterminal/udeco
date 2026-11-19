// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"fmt"
	"strings"
	"testing"
)

// radsecCfg is what Network 11.1.50 writes for a WPA-Enterprise WLAN on a
// RADIUS profile with TLS (certs section first, then the aaa keys).
func radsecCfg(extra ...string) string {
	return wlan(append([]string{
		"certs.status=enabled",
		"certs.1.status=enabled", "certs.1.comment=ca-1.pem", "certs.1.outfile=ca-1.pem", "certs.1.key=Q0EtQkxPQg==",
		"certs.2.status=enabled", "certs.2.comment=client-2.crt", "certs.2.outfile=client-2.crt", "certs.2.key=Q0VSVC1CTE9C",
		"certs.3.status=enabled", "certs.3.comment=client-3.key", "certs.3.outfile=client-3.key", "certs.3.key=S0VZLUJMT0I=",
		"aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-EAP",
		"aaa.1.radius.auth.1.ip=10.0.0.5", "aaa.1.radius.auth.1.port=2083", "aaa.1.radius.auth.1.secret=radsec",
		"aaa.1.radius.auth.1.tls=enabled", "aaa.1.radius.auth.1.ca_cert=ca-1.pem",
		"aaa.1.radius.auth.1.client_cert=client-2.crt", "aaa.1.radius.auth.1.private_key=client-3.key",
		"aaa.1.radius.auth.1.private_key_passwd=tls-key-pass",
		"aaa.1.radius.acct.1.ip=10.0.0.5", "aaa.1.radius.acct.1.secret=radsec",
		"aaa.1.radius.acct.1.tls=enabled", "aaa.1.radius.acct.1.ca_cert=ca-1.pem",
		"aaa.1.radius.acct.1.client_cert=client-2.crt", "aaa.1.radius.acct.1.private_key=client-3.key",
	}, extra...)...)
}

func TestIntentRadSec(t *testing.T) {
	in, notes := IntentFromCfg(radsecCfg())
	if len(in.WLANs) != 1 {
		t.Fatalf("wlans %v notes %v", in.WLANs, notes)
	}
	w := in.WLANs[0]
	if !w.Enabled || w.Security != "wpa2-enterprise" || w.Radius == nil || len(w.Radius.Auth) != 1 || len(w.Radius.Acct) != 1 {
		t.Fatalf("wlan %+v notes %v", w, notes)
	}
	a, c := w.Radius.Auth[0], w.Radius.Acct[0]
	if a.TLS == nil || a.Host != "10.0.0.5" || a.Port != 2083 || a.Secret != "radsec" {
		t.Fatalf("auth %v", a)
	}
	want := RadSecTLS{CA: "Q0EtQkxPQg==", Cert: "Q0VSVC1CTE9C", Key: "S0VZLUJMT0I=", KeyPassword: "tls-key-pass",
		CAFile: "ca-1.pem", CertFile: "client-2.crt", KeyFile: "client-3.key"}
	if *a.TLS != want {
		t.Fatalf("auth tls %#v", a.TLS)
	}
	// no port sent: RadSec's own
	if c.TLS == nil || c.Port != RadSecPort || c.TLS.KeyPassword != "" {
		t.Fatalf("acct %v", c)
	}
	for _, n := range notes {
		if strings.Contains(n, "RadSec") || strings.Contains(n, "certs") || strings.Contains(n, "tls") {
			t.Errorf("note %q", n)
		}
	}
	// printing never shows the key, the password or the secret
	out := fmt.Sprintf("%v %+v %#v %v %#v", in, a, a, a.TLS, *w.Radius)
	for _, bad := range []string{"S0VZLUJMT0I=", "tls-key-pass", "secret=radsec"} {
		if strings.Contains(out, bad) {
			t.Fatalf("%q leaks %q", out, bad)
		}
	}
}

func TestIntentRadSecIncomplete(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		note string
	}{
		{"no certs section", wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-EAP", "aaa.1.radius.auth.1.ip=10.0.0.5",
			"aaa.1.radius.auth.1.secret=s", "aaa.1.radius.auth.1.tls=enabled", "aaa.1.radius.auth.1.ca_cert=ca-1.pem"), "no CA certificate"},
		{"certs off", strings.Replace(radsecCfg(), "certs.status=enabled", "certs.status=disabled", 1), "no CA certificate"},
		{"no key", strings.Replace(radsecCfg(), "certs.3.status=enabled", "certs.3.status=disabled", 1), "no client certificate and key"},
		{"fqdn", strings.ReplaceAll(radsecCfg(), "=10.0.0.5", "=radius.example.com"), "must be an IP address"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, notes := IntentFromCfg(c.cfg)
			for _, w := range in.WLANs {
				if w.Enabled {
					t.Fatalf("WLAN served: %+v", w)
				}
			}
			if !strings.Contains(strings.Join(notes, "\n"), c.note) {
				t.Fatalf("notes %v", notes)
			}
		})
	}
}

func TestMaskCfgPrivateKeyPassword(t *testing.T) {
	m := MaskCfg(ParseCfg(radsecCfg()))
	for k, v := range m {
		if strings.Contains(v, "tls-key-pass") || strings.Contains(v, "S0VZLUJMT0I=") {
			t.Fatalf("%s=%s not masked", k, v)
		}
	}
}
