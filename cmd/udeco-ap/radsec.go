// SPDX-License-Identifier: GPL-2.0-or-later

package main

// RadSec (fw2_caps 0x80000, supportsRadSec): the controller marks a RADIUS
// server tls=enabled and sends the CA bundle, client certificate and key
// inline (certs.<i>.key). A UAP's patched hostapd speaks RADIUS/TLS itself
// (auth_server_type=TLS); the Deco's hostapd 2.9 is UDP only, so the agent
// runs internal/radsec, a local UDP-to-RadSec proxy, and points hostapd at
// 127.0.0.1:<port> with a local shared secret. Takeover only: in observe
// mode there is no proxy and a RadSec WLAN stays off (desiredFrom).
// docs/deco/features/radsec.md.

import (
	"context"
	"fmt"
	"slices"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/radsec"
	"github.com/dtechterminal/udeco/internal/translate"
)

// radsecRouter is what the agent uses of *radsec.Proxy.
type radsecRouter interface {
	Set(servers []radsec.Server) (map[string]radsec.Endpoint, map[string]error)
	Remotes() []string
	Close()
}

var _ radsecRouter = (*radsec.Proxy)(nil)

// egressAllower is decosys's extra egress hole for RadSec servers off the
// LAN (decosys.Manager.SetEgressAllowTCP); optional on the sysManager.
type egressAllower interface {
	SetEgressAllowTCP(dsts []string) bool
}

// radsecState is the worker goroutine's proxy.
type radsecState struct {
	p       radsecRouter
	remotes []string // last handed to the egress firewall
	// newProxy builds the proxy (tests); nil = radsec.New.
	newProxy func() radsecRouter
}

// radsecHeldNote is desiredFrom's note for a WLAN it turned off because
// it has a RadSec server; radsecRoute turns it back on.
const radsecHeldNote = "RADIUS over TLS (RadSec): served only through the agent's RadSec proxy (takeover mode)"

// hasRadSec reports whether r names a server marked tls=enabled.
func hasRadSec(r *translate.Radius) bool {
	if r == nil {
		return false
	}
	return slices.ContainsFunc(append(append([]translate.RadiusServer{}, r.Auth...), r.Acct...),
		func(s translate.RadiusServer) bool { return s.TLS != nil })
}

func radsecServer(x translate.RadiusServer) radsec.Server {
	return radsec.Server{Host: x.Host, Port: x.Port, Secret: x.Secret, TLS: radsec.Material{
		CA: []byte(x.TLS.CA), Cert: []byte(x.TLS.Cert), Key: []byte(x.TLS.Key), KeyPassword: x.TLS.KeyPassword}}
}

// radsecRoute points every RadSec server of d (built by desiredFrom from
// in: one SSID per WLAN, in order, servers in order) at the proxy, and
// turns each WLAN that desiredFrom held off for it back on as the
// controller asked, when every one of its RadSec servers got a local
// endpoint. A WLAN whose RadSec server cannot be served stays off: it is
// never served without its RADIUS servers, nor with any of them in clear.
// r nil (observe mode) keeps them all off. It returns notes (no secrets).
func radsecRoute(d bcmwifi.Desired, in translate.Intent, r radsecRouter) (bcmwifi.Desired, []string) {
	var servers []radsec.Server
	for _, w := range in.WLANs {
		if w.Radius == nil {
			continue
		}
		for _, x := range append(append([]translate.RadiusServer{}, w.Radius.Auth...), w.Radius.Acct...) {
			if x.TLS != nil {
				servers = append(servers, radsecServer(x))
			}
		}
	}
	if r == nil {
		if len(servers) > 0 {
			return d, []string{"RadSec WLANs stay off: no RadSec proxy (observe mode)"}
		}
		return d, nil
	}
	eps, errs := r.Set(servers)
	if len(d.SSIDs) != len(in.WLANs) {
		return d, []string{"RadSec WLANs stay off: the Wi-Fi plan does not match the controller's WLAN list"}
	}
	var notes []string
	ssids := slices.Clone(d.SSIDs)
	for i, w := range in.WLANs {
		if !hasRadSec(w.Radius) {
			continue
		}
		s := ssids[i]
		if s.ID != w.ID || s.Radius == nil || len(s.Radius.Auth) != len(w.Radius.Auth) || len(s.Radius.Acct) != len(w.Radius.Acct) {
			notes = append(notes, fmt.Sprintf("wlan %s: RadSec: the Wi-Fi plan does not match the controller's servers: kept off", w.ID))
			continue
		}
		rad := *s.Radius
		rad.Auth, rad.Acct = slices.Clone(rad.Auth), slices.Clone(rad.Acct)
		ok := true
		route := func(kind string, xs []translate.RadiusServer, out []bcmwifi.RadiusServer) {
			for j, x := range xs {
				if x.TLS == nil {
					continue
				}
				k := radsecServer(x).Key()
				ep, has := eps[k]
				if !has {
					ok = false
					notes = append(notes, fmt.Sprintf("wlan %s: RadSec %s server %d (%s:%d): %v", w.ID, kind, j+1, x.Host, x.Port, errs[k]))
					continue
				}
				out[j] = bcmwifi.RadiusServer{IP: ep.IP, Port: ep.Port, Secret: ep.Secret}
			}
		}
		route("auth", w.Radius.Auth, rad.Auth)
		route("acct", w.Radius.Acct, rad.Acct)
		if !ok {
			notes = append(notes, fmt.Sprintf("wlan %s: kept off (a RadSec server cannot be served)", w.ID))
			continue
		}
		s.Radius = &rad
		s.Enabled = w.Enabled
		ssids[i] = s
		notes = append(notes, fmt.Sprintf("wlan %s: RADIUS over TLS through the local RadSec proxy", w.ID))
	}
	d.SSIDs = ssids
	return d, notes
}

// radsecProvision is provision's RadSec step (worker goroutine): it starts
// the proxy when the plan has a RadSec server, routes d through it and
// keeps the egress hole for off-LAN servers in step.
func (a *agent) radsecProvision(ctx context.Context, d bcmwifi.Desired, in translate.Intent) bcmwifi.Desired {
	rs := &a.rs
	need := false
	for _, w := range in.WLANs {
		need = need || hasRadSec(w.Radius)
	}
	if rs.p == nil && need {
		if rs.newProxy != nil {
			rs.p = rs.newProxy()
		} else {
			rs.p = radsec.New(context.Background(), radsec.Options{Logf: a.logf})
		}
	}
	if rs.p == nil {
		return d
	}
	d, notes := radsecRoute(d, in, rs.p)
	for _, n := range notes {
		a.logf("wifi: %s", n)
	}
	a.radsecEgress(ctx, rs.p.Remotes())
	return d
}

// radsecEgress lets the agent's own TCP to the RadSec servers through the
// egress firewall (decosys allows only the LAN otherwise).
func (a *agent) radsecEgress(ctx context.Context, remotes []string) {
	rs := &a.rs
	if slices.Equal(remotes, rs.remotes) {
		return
	}
	e, ok := a.sys.(egressAllower)
	if !ok {
		return
	}
	rs.remotes = remotes
	if e.SetEgressAllowTCP(remotes) && a.cfg.Egress {
		if err := a.sys.Egress(ctx, true); err != nil {
			a.logf("decosys: egress (RadSec servers): %v", err)
		}
	}
}

// radsecStop closes the proxy (drop to observe: TP-Link's hostapd has no
// use for it) and forgets the egress hole.
func (a *agent) radsecStop() {
	rs := &a.rs
	if rs.p == nil {
		return
	}
	rs.p.Close()
	rs.p = nil
	// only forgotten: the drop to observe removes the egress chain itself
	// (decosys.Restore), and it must not be put back here
	if e, ok := a.sys.(egressAllower); ok {
		e.SetEgressAllowTCP(nil)
	}
	rs.remotes = nil
}
