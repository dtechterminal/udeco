// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/ftpeer"
)

// FT-SAE (802.11r for WPA3 clients) between the units running the agent.
//
// hostapd 2.9 needs every other unit's key holders listed explicitly
// (bcmwifi ftsae.go). Each agent announces its FT-SAE BSSes on their
// bridges and learns the others' (internal/ftpeer, authenticated with a
// key derived from the WLAN's iapp_key); the Wi-Fi worker hands the peers
// to bcmwifi, which writes them into the confs at the next start and adds
// the new ones to the running hostapds live (no restart, no client drop).
//
// Runs only in takeover with apply, the wpa3 config key and ft_sae (default
// on with wpa3), and a Wi-Fi backend that serves FT-SAE; then the agent
// claims radio_caps2 WPA3 fast roaming (models.RadioCap2WPA3FT) and the
// controller sends wpa3.ft.status and the WLAN's iapp_key.

// ftSAEServer is a Wi-Fi backend that builds FT-SAE with explicit peers:
// *bcmwifi.Applier (ftsae.go, ftpeers.go).
type ftSAEServer interface {
	ServesFTSAE() bool
	FTLocals(ctx context.Context, d bcmwifi.Desired) ([]ftpeer.Local, error)
	SetFTPeers(peers []ftpeer.Peer)
	SyncFTPeers(ctx context.Context, d bcmwifi.Desired) (bcmwifi.FTSync, error)
}

var _ ftSAEServer = (*bcmwifi.Applier)(nil)

// ftPeerState is the running peer discovery.
type ftPeerState struct {
	svc      *ftpeer.Service
	problems string // the last sync's problems, logged when they change
}

// startFTPeers starts the peer discovery when FT-SAE is served.
func (a *agent) startFTPeers(ctx context.Context) {
	if !a.takeover.Load() || !a.cfg.Apply || !a.cfg.ftSAE() {
		return
	}
	if ft, ok := a.wifi.(ftSAEServer); !ok || !ft.ServesFTSAE() {
		return
	}
	a.ftp = &ftPeerState{}
	a.ftp.svc = ftpeer.New(ftpeer.Options{Unit: a.x.Dev.MAC, Open: a.o.ftOpen, Logf: a.logf, OnAir: a.ftOnAir,
		OnChange: func([]ftpeer.Peer) { a.submit("ft-sae peers", a.ftSync) }})
	a.bg.Add(1)
	go func() { defer a.bg.Done(); a.ftp.svc.Run(ctx) }()
	a.logf("ft-sae: announcing this unit's FT-SAE key holders and learning the other units' (EtherType %#04x on the SSIDs' bridges)", ftpeer.EtherType)
}

// ftKick queues a sync after an apply (worker).
func (a *agent) ftKick() {
	if a.ftp != nil {
		a.submit("ft-sae sync", a.ftSync)
	}
}

// ftSync announces the applied Wi-Fi's FT-SAE key holders and brings the
// running hostapds up to the known peers (worker goroutine).
func (a *agent) ftSync(ctx context.Context) {
	if a.ftp == nil {
		return
	}
	ft, ok := a.wifi.(ftSAEServer)
	w := &a.worker
	if !ok || w.applied == nil || !a.takeover.Load() {
		a.ftp.svc.SetLocals(nil)
		return
	}
	d := *w.applied
	locals, err := ft.FTLocals(ctx, d)
	if err != nil {
		a.logf("ft-sae: this unit's key holders: %v", err)
	}
	a.ftp.svc.SetLocals(locals)
	ft.SetFTPeers(a.ftp.svc.Peers())
	r, err := ft.SyncFTPeers(ctx, d)
	if err != nil {
		a.logf("ft-sae: sync: %v", err)
		return
	}
	a.count("ft-sae-peer-added", len(r.Added))
	if p := strings.Join(r.Problems, "; "); p != a.ftp.problems {
		a.ftp.problems = p
		if p != "" {
			a.logf("ft-sae: peers not added live: %s", p)
		}
	}
}

// ftDrop stops announcing (Wi-Fi went back to TP-Link).
func (a *agent) ftDrop() {
	if a.ftp != nil {
		a.ftp.svc.SetLocals(nil)
	}
}

// ftOnAir is the discovery's cross-check with the last neighbour scans.
func (a *agent) ftOnAir(bssid string) (seen, known bool) {
	if a.scans == nil {
		return false, false
	}
	a.scans.mu.Lock()
	defer a.scans.mu.Unlock()
	for _, r := range a.scans.results {
		known = known || len(r.BSS) > 0
		for _, b := range r.BSS {
			if strings.EqualFold(b.BSSID, bssid) {
				return true, true
			}
		}
	}
	return false, known
}
