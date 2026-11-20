// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/radsec"
	"github.com/dtechterminal/udeco/internal/translate"
)

// radsecSystemCfg: a WPA-Enterprise WLAN whose auth and acct servers are
// RadSec (what Network 11.1.50 sends with fw2_caps 0x80000), plus a WPA2
// WLAN that has nothing to do with it.
const radsecSystemCfg = `radio.1.phyname=wifi0
radio.1.ieee_mode=11nght20
radio.2.phyname=wifi1
radio.2.ieee_mode=11acvht80
certs.status=enabled
certs.1.status=enabled
certs.1.outfile=ca-1.pem
certs.1.key=Q0E=
certs.2.status=enabled
certs.2.outfile=client-2.crt
certs.2.key=Q0VSVA==
certs.3.status=enabled
certs.3.outfile=client-3.key
certs.3.key=S0VZLW1hdGVyaWFs
wireless.1.ssid=corp
wireless.1.id=w1
wireless.1.parent=wifi1
wireless.1.devname=ath1
aaa.1.wpa=2
aaa.1.wpa.key.1.mgmt=WPA-EAP
aaa.1.radius.auth.1.ip=203.0.113.7
aaa.1.radius.auth.1.port=2083
aaa.1.radius.auth.1.secret=radsec-secret
aaa.1.radius.auth.1.tls=enabled
aaa.1.radius.auth.1.ca_cert=ca-1.pem
aaa.1.radius.auth.1.client_cert=client-2.crt
aaa.1.radius.auth.1.private_key=client-3.key
aaa.1.radius.acct.1.ip=203.0.113.7
aaa.1.radius.acct.1.port=2083
aaa.1.radius.acct.1.secret=radsec-secret
aaa.1.radius.acct.1.tls=enabled
aaa.1.radius.acct.1.ca_cert=ca-1.pem
aaa.1.radius.acct.1.client_cert=client-2.crt
aaa.1.radius.acct.1.private_key=client-3.key
wireless.2.ssid=home
wireless.2.id=w2
wireless.2.parent=wifi1
wireless.2.devname=ath2
aaa.2.wpa=2
aaa.2.wpa.key.1.mgmt=WPA-PSK
aaa.2.wpa.psk=good-pass-1
`

type fakeRouter struct {
	got    []radsec.Server
	fail   error
	closed bool
	sets   int
}

func (f *fakeRouter) Set(ss []radsec.Server) (map[string]radsec.Endpoint, map[string]error) {
	f.sets++
	f.got = ss
	eps, errs := map[string]radsec.Endpoint{}, map[string]error{}
	for i, s := range ss {
		if f.fail != nil {
			errs[s.Key()] = f.fail
			continue
		}
		eps[s.Key()] = radsec.Endpoint{IP: "127.0.0.1", Port: 18200 + i, Secret: "local-secret-0123456789abcdef01"}
	}
	return eps, errs
}

func (f *fakeRouter) Remotes() []string {
	if f.closed || len(f.got) == 0 || f.fail != nil {
		return nil
	}
	return []string{"203.0.113.7:2083"}
}

func (f *fakeRouter) Close() { f.closed = true }

func radsecPlan(t *testing.T) (bcmwifi.Desired, translate.Intent) {
	t.Helper()
	in, _ := translate.IntentFromCfg(radsecSystemCfg)
	if len(in.WLANs) != 2 || !in.WLANs[0].Enabled || !hasRadSec(in.WLANs[0].Radius) {
		t.Fatalf("intent %v", in.WLANs)
	}
	d, notes := desiredFrom(in)
	// never plain UDP to the RadSec server: held off until routed
	if d.SSIDs[0].Enabled || !d.SSIDs[1].Enabled {
		t.Fatalf("desiredFrom: %v", d.SSIDs)
	}
	if !strings.Contains(strings.Join(notes, "\n"), radsecHeldNote) {
		t.Fatalf("notes %q", notes)
	}
	return d, in
}

func TestRadSecRoute(t *testing.T) {
	d, in := radsecPlan(t)
	r := &fakeRouter{}
	out, notes := radsecRoute(d, in, r)
	if len(r.got) != 2 || r.got[0].Host != "203.0.113.7" || r.got[0].Port != 2083 || string(r.got[0].TLS.Key) != "S0VZLW1hdGVyaWFs" {
		t.Fatalf("proxy given %v", r.got)
	}
	s := out.SSIDs[0]
	if !s.Enabled || s.Radius == nil {
		t.Fatalf("not turned back on: %v (%q)", s, notes)
	}
	for _, x := range append(s.Radius.Auth, s.Radius.Acct...) {
		if x.IP != "127.0.0.1" || x.Port < 18200 || x.Secret != "local-secret-0123456789abcdef01" {
			t.Fatalf("server not routed through the proxy: %v", x)
		}
	}
	// the input Desired is not changed under the caller
	if d.SSIDs[0].Enabled || d.SSIDs[0].Radius.Auth[0].IP != "203.0.113.7" {
		t.Fatal("radsecRoute changed its input")
	}
	all := strings.Join(notes, "\n") + fmt.Sprintf("%v %+v %#v", out.SSIDs, out.SSIDs, r.got)
	for _, bad := range []string{"radsec-secret", "S0VZLW1hdGVyaWFs", "local-secret-0123456789abcdef01"} {
		if strings.Contains(all, bad) {
			t.Fatalf("printed %q: %s", bad, all)
		}
	}
}

func TestRadSecRouteFailsClosed(t *testing.T) {
	d, in := radsecPlan(t)
	// the proxy refuses the server (bad certificate, say)
	out, notes := radsecRoute(d, in, &fakeRouter{fail: errors.New("CA certificate: no certificate")})
	if out.SSIDs[0].Enabled {
		t.Fatal("WLAN served without its RadSec server")
	}
	if !out.SSIDs[1].Enabled {
		t.Fatal("the unrelated WLAN went off")
	}
	if n := strings.Join(notes, "\n"); !strings.Contains(n, "CA certificate") || !strings.Contains(n, "kept off") {
		t.Fatalf("notes %q", notes)
	}
	// no proxy (observe mode)
	out, notes = radsecRoute(d, in, nil)
	if out.SSIDs[0].Enabled || len(notes) != 1 {
		t.Fatalf("observe: %v %q", out.SSIDs[0], notes)
	}
	// a plan that does not line up with the intent
	short := d
	short.SSIDs = d.SSIDs[1:]
	out, _ = radsecRoute(short, in, &fakeRouter{})
	for _, s := range out.SSIDs {
		if s.ID == "w1" && s.Enabled {
			t.Fatal("served from a mismatched plan")
		}
	}
	// a controller WLAN that is off stays off
	in.WLANs[0].Enabled = false
	out, _ = radsecRoute(d, in, &fakeRouter{})
	if out.SSIDs[0].Enabled {
		t.Fatal("a disabled WLAN was turned on")
	}
}

type allowSys struct {
	sysManager
	allow  [][]string
	egress int
}

func (s *allowSys) SetEgressAllowTCP(d []string) bool {
	s.allow = append(s.allow, d)
	return true
}

func (s *allowSys) Egress(context.Context, bool) error {
	s.egress++
	return nil
}

func TestRadSecProvisionLifecycle(t *testing.T) {
	d, in := radsecPlan(t)
	sys := &allowSys{}
	r := &fakeRouter{}
	var logs []string
	a := &agent{cfg: &Config{Egress: true}, sys: sys,
		o: options{logf: func(f string, x ...any) { logs = append(logs, fmt.Sprintf(f, x...)) }}}
	a.rs.newProxy = func() radsecRouter { return r }
	out := a.radsecProvision(context.Background(), d, in)
	if !out.SSIDs[0].Enabled || a.rs.p == nil {
		t.Fatalf("not routed: %v %q", out.SSIDs[0], logs)
	}
	if len(sys.allow) != 1 || sys.allow[0][0] != "203.0.113.7:2083" || sys.egress != 1 {
		t.Fatalf("egress hole %v (egress %d)", sys.allow, sys.egress)
	}
	// the same plan again: the firewall is not touched
	a.radsecProvision(context.Background(), d, in)
	if len(sys.allow) != 1 || sys.egress != 1 {
		t.Fatalf("egress re-applied: %v %d", sys.allow, sys.egress)
	}
	// a drop to observe: proxy closed, hole forgotten, egress NOT re-installed
	a.radsecStop()
	if !r.closed || a.rs.p != nil || len(sys.allow) != 2 || sys.allow[1] != nil || sys.egress != 1 {
		t.Fatalf("stop: closed %t allow %v egress %d", r.closed, sys.allow, sys.egress)
	}
	// a plan without RadSec starts no proxy
	plain, _ := translate.IntentFromCfg(strings.Split(radsecSystemCfg, "wireless.1.ssid")[0])
	dp, _ := desiredFrom(plain)
	a2 := &agent{cfg: &Config{}, sys: sys, o: options{logf: func(string, ...any) {}}}
	a2.rs.newProxy = func() radsecRouter { t.Fatal("proxy started without RadSec"); return nil }
	a2.radsecProvision(context.Background(), dp, plain)
}
