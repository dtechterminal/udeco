// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/ftpeer"
)

// FT-SAE peers: the other units' key holders each FT-SAE BSS lists
// (ftsae.go explains why they must be explicit on hostapd 2.9).
//
// The agent learns them with internal/ftpeer and hands them over with
// SetFTPeers. A Plan writes the peers known at that moment into the conf;
// the r0kh/r1kh lines are left out of the comparison that decides a
// hostapd restart (sameConf), so a new peer never restarts a radio.
// SyncFTPeers adds the peers the running hostapd lacks over its control
// socket: SET r0kh/SET r1kh go through hostapd 2.9's config parser
// (hostapd_ctrl_iface_set -> hostapd_set_iface -> add_r0kh/add_r1kh), which
// prepends to the BSS's r0kh_list/r1kh_list; wpa_auth reads those lists
// through a pointer to the same heads (wpa_auth_glue.c: wconf->r0kh_list =
// &conf->r0kh_list), so the entry is live at once, without a restart or a
// client drop. The command carries the key: it goes over the socket
// (Options.Ctrl), never on a command line, in a Step or in a log.
//
// Removal: hostapd 2.9 has no command that removes a configured entry (it
// drops only the temporary ones a wildcard creates). A peer that went away
// therefore stays in the running hostapd until its next restart, when the
// conf is written with the peers known then. That is harmless: the entry
// is used only for a station whose R0KH-ID is that peer's (a PULL to an
// absent BSSID times out, the station does a full SAE; while the peer's
// hostapd still runs, e.g. its agent crashed, the entry keeps working),
// and pmk_r1_push sends one small encrypted frame to it per SAE
// association. Entries are never duplicated (the live set is tracked per
// hostapd process, in RunDir across agent restarts) and at most
// maxFTRuntime are added per BSS between restarts. A key change is not
// patched live (with two entries for one peer hostapd uses the older one):
// the drv-wlN.json key id differs, so the next Plan restarts the radio.

// maxFTPeers bounds the peers one BSS lists in its conf, maxFTRuntime the
// entries (r0kh + r1kh) added to one running BSS between restarts.
const (
	maxFTPeers   = 32
	maxFTRuntime = 64
)

// SetFTPeers replaces the other units' key holders (from ftpeer). Plans
// write them into the confs; SyncFTPeers adds them to running hostapds.
func (a *Applier) SetFTPeers(peers []ftpeer.Peer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ftPeers = append([]ftpeer.Peer(nil), peers...)
}

// ownBSSIDs are this unit's BSSIDs known so far: never a peer.
func (a *Applier) ownBSSIDs() map[string]bool {
	own := map[string]bool{}
	for _, m := range a.macs {
		own[m] = true
	}
	return own
}

// peersFor returns the peers an FT-SAE BSS of s on band, bridged to
// bridge, lists: same WLAN key (by key id), same mobility domain, heard on
// the same bridge (the L2 path its RRB takes), not one of this unit's
// BSSes; valid, one per BSSID, sorted, at most maxFTPeers. a.mu is held.
func (a *Applier) peersFor(s SSID, band, bridge string) []ftpeer.Peer {
	if !s.FT || !s.FTSAE || !validFTKey(s.FTKey) || len(a.ftPeers) == 0 {
		return nil
	}
	id, md, own := ftpeer.KeyID(s.FTKey), ssidMDID(s, band), a.ownBSSIDs()
	seen := map[string]bool{}
	var out []ftpeer.Peer
	for _, p := range a.ftPeers {
		p.BSSID, p.R1KHID = ftpeer.NormMAC(p.BSSID), ftpeer.NormMAC(p.R1KHID)
		if p.KeyID != id || p.MDID != md || p.Bridge != bridge || own[p.BSSID] || seen[p.BSSID] || p.Holder.Valid() != nil {
			continue
		}
		seen[p.BSSID] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BSSID < out[j].BSSID })
	if len(out) > maxFTPeers {
		out = out[:maxFTPeers]
	}
	return out
}

// FTLocals returns this unit's FT-SAE key holders under d, to announce
// (the Key field is secret: ftpeer never logs or sends it). Empty in
// DryRun: no BSS of the agent is on the air then.
func (a *Applier) FTLocals(ctx context.Context, d Desired) ([]ftpeer.Local, error) {
	if a.o.DryRun || !a.ServesFTSAE() {
		return nil, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []ftpeer.Local
	for _, rl := range a.layout(d).Radios {
		for _, u := range rl.Used {
			s := u.SSID
			if !s.FT || !s.FTSAE || !validFTKey(s.FTKey) {
				continue
			}
			mac, err := a.bssid(ctx, u.Vif)
			if err != nil {
				return out, err
			}
			out = append(out, ftpeer.Local{Holder: ftpeer.Holder{Band: rl.Band, BSSID: mac,
				R0KHID: strings.ReplaceAll(mac, ":", ""), R1KHID: mac, MDID: ssidMDID(s, rl.Band)},
				Bridge: u.Bridge, Key: strings.ToLower(s.FTKey)})
		}
	}
	return out, nil
}

// FTSync is what SyncFTPeers did. No line holds a key.
type FTSync struct {
	Added    []string // "wl12: r0kh aa:bb:.. <id>" per entry added (or, in DryRun, that would be)
	Problems []string // entries not added and why
}

// ftLiveState is what the agent added to one radio's running hostapd:
// RunDir/ftpeers-wlN.json (0600; MACs and key holder ids, no key).
type ftLiveState struct {
	PID   int                 `json:"pid"`
	Added map[string][]string `json:"added"` // vif -> "r0kh <addr> <id>" / "r1kh <addr> <id>"
}

func ftLivePath(runDir, primary string) string { return path.Join(runDir, "ftpeers-"+primary+".json") }

// SyncFTPeers adds to each running agent hostapd the FT-SAE peers (from
// SetFTPeers) its BSSes of d lack, over the control socket. A BSS is
// skipped while its running hostapd does not match d (another conf, key or
// mobility domain): the next Apply restarts it with the peers in its conf.
func (a *Applier) SyncFTPeers(ctx context.Context, d Desired) (FTSync, error) {
	var r FTSync
	if !a.ServesFTSAE() {
		return r, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ftLive == nil {
		a.ftLive = map[string]*ftLiveState{}
	}
	for _, rl := range a.layout(d).Radios {
		var want []vifAssign
		for _, u := range rl.Used {
			if u.SSID.FT && u.SSID.FTSAE && validFTKey(u.SSID.FTKey) {
				want = append(want, u)
			}
		}
		if len(want) == 0 {
			continue
		}
		p := rl.Primary
		conf, err := a.readFile(ConfPath(a.o.RunDir, p))
		if err != nil {
			continue // not ours (yet)
		}
		pid, ok := a.findProc("hostapd", ConfPath(a.o.RunDir, p))
		if !ok {
			continue
		}
		st := a.ftLiveFor(p, pid)
		secs := confSections(conf)
		drv := a.liveDriver(p)
		dirty := false
		for _, u := range want {
			sec, ok := secs[u.Vif]
			if !ok || sec.kv["bridge"] != u.Bridge || sec.kv["mobility_domain"] != fmt.Sprintf("%04x", ssidMDID(u.SSID, rl.Band)) ||
				drv[u.Vif].FTKeyID != ftpeer.KeyID(u.SSID.FTKey) {
				r.Problems = append(r.Problems, u.Vif+": running hostapd is not this layout's (an apply is due): peers wait for it")
				continue
			}
			have := map[string]bool{}
			for _, e := range sec.ft {
				have[e] = true
			}
			for _, e := range st.Added[u.Vif] {
				have[e] = true
			}
			key := strings.ToLower(u.SSID.FTKey)
			for _, pr := range a.peersFor(u.SSID, rl.Band, u.Bridge) {
				for _, e := range []struct{ kind, id string }{{"r1kh", pr.R1KHID}, {"r0kh", pr.R0KHID}} {
					ent := e.kind + " " + pr.BSSID + " " + e.id
					if have[ent] {
						continue
					}
					if len(st.Added[u.Vif]) >= maxFTRuntime {
						r.Problems = append(r.Problems, fmt.Sprintf("%s: %d entries added since hostapd started: %s waits for its next restart", u.Vif, maxFTRuntime, ent))
						continue
					}
					if a.o.DryRun {
						r.Added = append(r.Added, u.Vif+": "+ent+" (dry run)")
						continue
					}
					reply, err := a.ctrl(ctx, u.Vif, "SET "+ent+" "+key)
					if err != nil || strings.TrimSpace(reply) != "OK" {
						why := strings.TrimSpace(reply)
						if err != nil {
							why = err.Error()
						}
						r.Problems = append(r.Problems, fmt.Sprintf("%s: SET %s: %s", u.Vif, ent, why))
						continue
					}
					have[ent] = true
					st.Added[u.Vif] = append(st.Added[u.Vif], ent)
					r.Added = append(r.Added, u.Vif+": "+ent)
					dirty = true
				}
			}
		}
		if dirty {
			if b, err := json.Marshal(st); err == nil {
				if err := writeFileAtomic(a.fsPath(ftLivePath(a.o.RunDir, p)), b, 0o600); err != nil {
					r.Problems = append(r.Problems, fmt.Sprintf("%s: save %s: %v", p, ftLivePath(a.o.RunDir, p), err))
				}
			}
		}
	}
	for _, s := range r.Added {
		a.o.Logf("bcmwifi: FT-SAE peer added live: %s", s)
	}
	return r, nil
}

// ftLiveFor returns the live-additions record of primary's hostapd pid:
// from memory, else from RunDir (an agent restart), else empty (a new
// hostapd). a.mu is held.
func (a *Applier) ftLiveFor(primary string, pid int) *ftLiveState {
	if st := a.ftLive[primary]; st != nil && st.PID == pid {
		return st
	}
	st := &ftLiveState{PID: pid, Added: map[string][]string{}}
	if b, err := a.readFile(ftLivePath(a.o.RunDir, primary)); err == nil {
		var saved ftLiveState
		if json.Unmarshal(b, &saved) == nil && saved.PID == pid && saved.Added != nil {
			st = &saved
		}
	}
	a.ftLive[primary] = st
	return st
}

// liveDriver reads drv-wlN.json (what the running hostapd's BSSes were
// set up with), by vif.
func (a *Applier) liveDriver(primary string) map[string]vifDriver {
	out := map[string]vifDriver{}
	b, err := a.readFile(drvPath(a.o.RunDir, primary))
	if err != nil {
		return out
	}
	var ds []vifDriver
	if json.Unmarshal(b, &ds) != nil {
		return out
	}
	for _, d := range ds {
		out[d.Vif] = d
	}
	return out
}

// confSection is one bss= section of an agent conf: its keys (first value)
// and its FT peer entries without the key ("r0kh <addr> <id>").
type confSection struct {
	kv map[string]string
	ft []string
}

func confSections(conf []byte) map[string]confSection {
	out := map[string]confSection{}
	cur := ""
	for _, line := range strings.Split(string(conf), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k == "bss" {
			cur = v
			out[cur] = confSection{kv: map[string]string{}}
			continue
		}
		sec, ok := out[cur]
		if cur == "" || !ok {
			continue
		}
		if k == "r0kh" || k == "r1kh" {
			if f := strings.Fields(v); len(f) == 3 {
				sec.ft = append(sec.ft, k+" "+strings.ToLower(f[0])+" "+f[1])
				out[cur] = sec
			}
			continue
		}
		if _, dup := sec.kv[k]; !dup {
			sec.kv[k] = v
		}
	}
	return out
}

// stripFTPeers drops the r0kh=/r1kh= lines: the peer entries, the only
// lines that change when a peer comes or goes.
func stripFTPeers(conf []byte) []byte {
	var b bytes.Buffer
	for _, line := range bytes.SplitAfter(conf, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("r0kh=")) || bytes.HasPrefix(line, []byte("r1kh=")) {
			continue
		}
		b.Write(line)
	}
	return b.Bytes()
}

// sameConf reports whether the hostapd conf at p equals conf but for the
// FT-SAE peer lines (added live by SyncFTPeers, never by a restart). A
// key change still differs: the key id is in drv-wlN.json.
func (a *Applier) sameConf(p string, conf []byte) bool {
	b, err := a.readFile(p)
	return err == nil && bytes.Equal(stripFTPeers(b), stripFTPeers(conf))
}

// ctrl sends cmd to vif's hostapd control socket (Options.Ctrl, else the
// unix socket). Errors never include cmd (it may carry a key).
func (a *Applier) ctrl(ctx context.Context, vif, cmd string) (string, error) {
	if a.o.Ctrl != nil {
		return a.o.Ctrl(ctx, vif, cmd)
	}
	return unixCtrl(ctx, a.fsPath(path.Join(CtrlDir, vif)), a.fsPath(a.o.RunDir), cmd)
}

var ctrlSeq atomic.Uint64

// unixCtrl is hostapd's control protocol (wpa_ctrl): one datagram to the
// BSS's socket from a bound local socket, one reply. Errors name the
// socket, never the command.
func unixCtrl(ctx context.Context, sock, localDir, cmd string) (string, error) {
	local := filepath.Join(localDir, fmt.Sprintf("ctrl-%d-%d", os.Getpid(), ctrlSeq.Add(1)))
	_ = os.Remove(local)
	c, err := net.DialUnix("unixgram", &net.UnixAddr{Name: local, Net: "unixgram"}, &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		return "", fmt.Errorf("control socket %s: %w", sock, errors.Unwrap(err))
	}
	defer os.Remove(local)
	defer c.Close()
	dl := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	_ = c.SetDeadline(dl)
	if _, err := c.Write([]byte(cmd)); err != nil {
		return "", fmt.Errorf("control socket %s: send failed", sock)
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return "", fmt.Errorf("control socket %s: no reply", sock)
		}
		if n > 0 && buf[0] == '<' {
			continue // an unsolicited event (only to attached monitors)
		}
		return string(buf[:n]), nil
	}
}

// ftLiveEntries is for tests and status: the live additions per vif.
func (a *Applier) ftLiveEntries(primary string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.ftLive[primary]
	if st == nil {
		return nil
	}
	var out []string
	for v, es := range st.Added {
		for _, e := range es {
			out = append(out, v+" "+e)
		}
	}
	sort.Strings(out)
	return out
}
