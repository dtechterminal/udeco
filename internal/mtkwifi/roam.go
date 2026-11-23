// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/ftpeer"
	"github.com/dtechterminal/udeco/internal/mtkft"
)

// Roaming with the Decos (docs/deco/features/garage-ft.md, "Agent side"):
// the runtime half of 802.11r. ftplan.go writes the profile keys; this
// moves the keys between the Garage's key holders and the Decos'.
//
// FT-SAE (the controller's WPA3 fast roaming, iapp_key, ft_sae): the
// Garage's FT-SAE BSSes are announced over internal/ftpeer (FTLocals), so
// the Decos list them in their r0kh/r1kh lines, and the Decos' holders are
// learned (SetFTPeers). Between them hostapd 2.9's RRB-OUI (EtherType
// 0x88b7, internal/mtkft rrb.go) runs on each SSID's bridge:
//
//   - an initial FT-SAE association on the Garage: 5 GHz, the driver's
//     FT_ASSOCIATION (KDP 0x50 on raiN) -> KEY_REQ per same-domain Deco
//     R1KH -> KEY_RSP_AUTO -> PUSH to that Deco (pmk_r1_push); 2.4 GHz,
//     the UDFT event R0_CREATED -> R1_GET per Deco R1KH -> PUSH;
//   - a Deco's PUSH (after an SAE there) -> installed: 5 GHz KEY_RSP
//     (OID 0x040a), 2.4 GHz R1_SET (0x8960), before the station roams;
//   - a Deco's SEQ_REQ (its first frame from this unit) -> SEQ_RESP;
//   - a Deco's PULL -> 5 GHz KEY_REQ, 2.4 GHz R1_GET -> RESP;
//   - 2.4 GHz R1_MISS (a station whose key was not pushed) -> PULL to its
//     R0KH -> RESP -> R1_SET (the driver holds the station ~400 ms).
//
// Frames are taken only for a BSS's own BSSID from a current peer of its
// WLAN key and mobility domain at that peer's address, sealed under the
// key (AES-SIV), within a per-source rate, and with a fresh sequence per
// (BSS, peer, role) (mtkft.RxSeq). No key is ever logged.
//
// The MT7663's R1KH table has 64 entries for the radio, never aged and
// emptied only by a radio stop (mtkft.R1KHTableSize): the runtime counts
// its own installs and the driver's own entries (one per FT initial
// association) since the radio's start and stops installing at
// r1khBudget. Installed SAs are kept (until they expire) and installed
// again after a radio restart, most recent first.
//
// Driver ioctls wait for the restart gate (restartgate.go): an install
// that comes inside a settle time is retried after it.

const (
	r1khBudget     = mtkft.R1KHTableSize - 8 // 5 GHz installs since the radio's start, at most
	r1kh2GBudget   = 240                     // the MT7603's R1 table holds 256
	r1khKnownFree  = 24                      // 5 GHz: a station never seen here gets a pushed SA only while this many are free
	keyReqTimeout  = 2 * time.Second
	pullTimeout    = 3 * time.Second
	staMemory      = 24 * time.Hour
	saDefaultLife  = 43200 // s: hostapd r0_key_lifetime (12 h)
	reassocTU      = 20    // PeerPairMsg4Action's reassociation deadline (FT_KDP_KeyResponseToUs callers)
	maxSAs         = 256
	rrbRate        = 20 // frames per second per source
	rrbBurst       = 40
	installRetries = 30 // s an install waits for a settle time to end
)

// roamIO is the runtime's view of the unit (roam_linux.go; tests fake it).
type roamIO interface {
	// OID sends a private OID ioctl and returns the reply's length
	// (iw_point.length after the call).
	OID(ifname string, flags uint16, buf []byte) (int, error)
	// Set is `iwpriv <ifname> set <arg>`.
	Set(ifname, arg string) error
	// Open taps dev for frames of etherType (ETH_P_ALL and a BPF; a
	// receive times out after about 1 s with errRoamTimeout).
	Open(dev string, etherType uint16) (frameConn, error)
}

type frameConn interface {
	Recv(b []byte) (int, error)
	Send(frame []byte) error
	Close() error
}

var errRoamTimeout = errors.New("mtkwifi: receive timeout")

// roamBSS is one served BSS as the runtime sees it.
type roamBSS struct {
	Band, Ifname, Bridge, SSID string
	BSSID                      mtkft.MAC
	FT, FTSAE                  bool
	MDID                       uint16
	R0KHID                     []byte
	RRM, BTM                   bool
	keyID                      string   // ftpeer.KeyID of the WLAN key (FT-SAE)
	rawKey                     string   // the iapp_key (FTLocals only; secret)
	key                        [32]byte // mtkft.RRBKey(rawKey) (secret)
	psk                        [32]byte // the WPA2 PSK (FT-PSK pre-install, 5 GHz; secret)
	hasPSK                     bool
}

func (b roamBSS) String() string { return b.Ifname + " " + b.BSSID.String() }

// role: which key holder of the pair this unit's BSS is.
type role byte

const (
	asR0KH role = iota // pushes, responses (the station joined here)
	asR1KH             // pulls (the station roams here)
)

type pairKey struct {
	bss, peer mtkft.MAC
	r         role
}

type keyReq struct {
	at   time.Time
	bss  mtkft.MAC
	peer ftpeer.Peer
	sta  mtkft.MAC
	pull *mtkft.Pull // answering a Deco's pull (else: a push after an initial association)
	join bool        // sent on a 4-way completion event, not the driver's FT_ASSOCIATION
}

// assocMark: a 5 GHz station's last initial association the runtime asked
// the driver's keys for, and whether its R1KH entry was counted.
type assocMark struct {
	at      time.Time
	counted bool
}

// joinWait: a pending 4-way completion is sent KEY_REQs this long after it
// (PeerPairMsg4Action inserts the R1KH entry after securing the port).
const joinWait = time.Second

// assocDedup: an FT_ASSOCIATION signal and the 4-way completion event of
// the same join ask once.
const assocDedup = 10 * time.Second

type pullReq struct {
	at        time.Time
	bss       mtkft.MAC
	peer      ftpeer.Peer
	sta       mtkft.MAC
	r0kh      []byte
	pmkR0Name [16]byte
}

// sa is one PMK-R1 SA a Deco pushed or answered, kept to install again
// after a radio restart.
type sa struct {
	bss     mtkft.MAC
	band    string
	exp     time.Time
	last    time.Time // the station's last sighting or the SA's arrival (priority)
	el      mtkft.KeyElement
	gen     int  // the radio generation it is installed in (-1: none)
	pending bool // waiting for the restart gate
	since   time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

// roam is the runtime (its own lock; never takes the Applier's).
type roam struct {
	a    *Applier
	mu   sync.Mutex
	io   roamIO
	logf func(string, ...any)
	now  func() time.Time
	// gate: may the runtime send a driver ioctl now (restartgate.go)
	gate func() (func(), bool)

	bss   []roamBSS
	peers []ftpeer.Peer
	gen   map[string]int // radio restarts per band
	used  map[string]int // 5 GHz/2.4 GHz R1KH entries since the radio's start
	full  map[string]bool
	stas  map[mtkft.MAC]time.Time
	assoc map[keyJoin]assocMark
	joins map[keyJoin]time.Time

	tx      map[pairKey]*mtkft.TxSeq
	rx      map[pairKey]*mtkft.RxSeq
	keyReqs map[uint32]keyReq
	tag     uint32
	pulls   map[[mtkft.NonceLen]byte]pullReq
	sas     map[[16]byte]*sa
	udftSeq map[string]uint32
	rate    map[mtkft.MAC]*bucket
	stats   map[string]uint64
	psks    map[string][32]byte
	logged  map[string]bool

	conns map[string]frameConn // "kdp raiN", "rrb bdg2"
	start time.Time

	// status: the last status line logged and when (logStatus)
	status   string
	statusAt time.Time
}

type keyJoin struct{ sta, bss mtkft.MAC }

func newRoam(a *Applier) *roam {
	r := &roam{a: a, io: a.o.roamIO, logf: a.o.Logf, now: time.Now, gate: a.DriverRead,
		gen: map[string]int{}, used: map[string]int{}, full: map[string]bool{}, stas: map[mtkft.MAC]time.Time{},
		assoc: map[keyJoin]assocMark{}, joins: map[keyJoin]time.Time{},
		tx: map[pairKey]*mtkft.TxSeq{}, rx: map[pairKey]*mtkft.RxSeq{}, keyReqs: map[uint32]keyReq{},
		pulls: map[[mtkft.NonceLen]byte]pullReq{}, sas: map[[16]byte]*sa{}, udftSeq: map[string]uint32{},
		rate: map[mtkft.MAC]*bucket{}, stats: map[string]uint64{}, psks: map[string][32]byte{}, logged: map[string]bool{},
		conns: map[string]frameConn{}, start: time.Now()}
	return r
}

// count bumps a statistic (r.mu held).
func (r *roam) count(k string) { r.stats[k]++ }

// once logs a line the first time its key comes (r.mu held).
func (r *roam) once(key, f string, args ...any) {
	if !r.logged[key] {
		r.logged[key] = true
		r.logf(f, args...)
	}
}

// secs is the RRB TS clock: monotonic seconds since the runtime began.
func (r *roam) secs() uint32 { return uint32(r.now().Sub(r.start) / time.Second) }

// ----------------------------------------------------------- configuration

// roamSync hands the applied plans to the runtime (a.mu held).
func (a *Applier) roamSync() {
	if a.roam != nil {
		a.roam.setConfig(a.roamConfig())
	}
}

// roamConfig is the served BSSes the runtime works for (a.mu held): none
// unless the agent serves 802.11r (ft) and owns the radios.
func (a *Applier) roamConfig() []roamBSS {
	if !a.o.FT || a.o.DryRun || a.live == nil {
		return nil
	}
	ssids := map[string]bcmwifi.SSID{}
	for _, s := range a.desired.SSIDs {
		ssids[s.ID] = s
	}
	var out []roamBSS
	for _, rd := range a.o.Layout {
		rp := a.live[rd.Band]
		if !rp.On || !rd.FT {
			continue
		}
		for i, b := range rp.BSS {
			ifc := a.ifaceOf(rd, rp, i)
			mac, err := a.netdevMAC(ifc)
			if err != nil {
				continue
			}
			rb := roamBSS{Band: rd.Band, Ifname: ifc, Bridge: a.o.Bridge, SSID: b.SSID, BSSID: mac, FT: b.FT,
				FTSAE: b.FTSAE, MDID: b.MDID, RRM: b.RRM, BTM: b.BTM}
			if b.VLAN > 0 {
				rb.Bridge = vlanBridge(b.VLAN)
			}
			rb.R0KHID = []byte(mac.Hex()) // the MT7603's FT_DefaultR0khId
			if rd.Band == "na" {
				rb.R0KHID = []byte(b.R0KHID)
			}
			if rd.Band == "na" && b.FT && b.Auth != "WPA3PSK" {
				rb.psk, rb.hasPSK = a.roam.pskOf(ssids[b.ID].ForBand(rd.Band).Passphrase, b.SSID)
			}
			if rb.FTSAE {
				k := strings.ToLower(ssids[b.ID].ForBand(rd.Band).FTKey)
				key, err := mtkft.RRBKey(k)
				if err != nil || !bcmwifi.ValidFTKey(k) || len(rb.R0KHID) == 0 {
					rb.FTSAE = false
				} else {
					rb.keyID, rb.rawKey, rb.key = ftpeer.KeyID(k), k, key
				}
			}
			out = append(out, rb)
		}
	}
	return out
}

// pskOf is the PSK of (passphrase, ssid), cached: PBKDF2's 4096 rounds
// are not redone on every tick.
func (r *roam) pskOf(pass, ssid string) ([32]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := ssid + "\x00" + pass
	if v, ok := r.psks[k]; ok {
		return v, true
	}
	v, err := mtkft.PSK(pass, []byte(ssid))
	if err != nil {
		return v, false
	}
	if len(r.psks) > 16 {
		clear(r.psks)
	}
	r.psks[k] = v
	return v, true
}

// setConfig replaces the served BSSes.
func (r *roam) setConfig(bss []roamBSS) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bss = bss
}

// radioRestarted: band's radio went down (its R1KH table is empty now).
func (r *roam) radioRestarted(band string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gen[band]++
	r.used[band] = 0
	r.full[band] = false
}

// setPeers replaces the Decos' key holders.
func (r *roam) setPeers(p []ftpeer.Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers = append([]ftpeer.Peer(nil), p...)
}

func (r *roam) bssByMAC(m mtkft.MAC) (roamBSS, bool) {
	for _, b := range r.bss {
		if b.BSSID == m {
			return b, true
		}
	}
	return roamBSS{}, false
}

func (r *roam) bssByIfname(ifc string) (roamBSS, bool) {
	for _, b := range r.bss {
		if b.Ifname == ifc {
			return b, true
		}
	}
	return roamBSS{}, false
}

// peersOf are b's FT-SAE peers: same WLAN key and mobility domain, heard on
// b's bridge, not this unit's, valid (bcmwifi peersFor's rule).
func (r *roam) peersOf(b roamBSS) []ftpeer.Peer {
	if !b.FTSAE {
		return nil
	}
	var out []ftpeer.Peer
	seen := map[string]bool{}
	for _, p := range r.peers {
		bs := ftpeer.NormMAC(p.BSSID)
		if p.KeyID != b.keyID || p.MDID != b.MDID || p.Bridge != b.Bridge || seen[bs] || p.Holder.Valid() != nil {
			continue
		}
		if m, err := mtkft.ParseMAC(bs); err != nil || r.ownMAC(m) {
			continue
		}
		seen[bs] = true
		out = append(out, p)
	}
	slices.SortFunc(out, func(x, y ftpeer.Peer) int { return strings.Compare(x.BSSID, y.BSSID) })
	return out
}

func (r *roam) ownMAC(m mtkft.MAC) bool {
	_, ok := r.bssByMAC(m)
	return ok
}

func peerMACs(p ftpeer.Peer) (bssid, r1kh mtkft.MAC, err error) {
	if bssid, err = mtkft.ParseMAC(ftpeer.NormMAC(p.BSSID)); err != nil {
		return
	}
	r1kh, err = mtkft.ParseMAC(ftpeer.NormMAC(p.R1KHID))
	return
}

// FTLocals implements the agent's ftSAEServer: the Garage's FT-SAE key
// holders, to announce (d is applied already: the live plans are used).
func (a *Applier) FTLocals(ctx context.Context, d bcmwifi.Desired) ([]ftpeer.Local, error) {
	if !a.ServesFTSAE() || a.o.DryRun {
		return nil, nil
	}
	a.mu.Lock()
	bss := a.roamConfig()
	a.mu.Unlock()
	var out []ftpeer.Local
	for _, b := range bss {
		if !b.FTSAE {
			continue
		}
		m := b.BSSID.String()
		out = append(out, ftpeer.Local{Holder: ftpeer.Holder{Band: b.Band, BSSID: m, R0KHID: string(b.R0KHID), R1KHID: m,
			MDID: b.MDID}, Bridge: b.Bridge, Key: b.rawKey})
	}
	return out, nil
}

// SetFTPeers implements ftSAEServer: the Decos' key holders.
func (a *Applier) SetFTPeers(peers []ftpeer.Peer) { a.roam.setPeers(peers) }

// SyncFTPeers implements ftSAEServer. The runtime uses the peers as they
// come (no driver list to patch): it reports the 5 GHz table budget.
func (a *Applier) SyncFTPeers(ctx context.Context, d bcmwifi.Desired) (bcmwifi.FTSync, error) {
	var s bcmwifi.FTSync
	r := a.roam
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, band := range []string{"ng", "na"} {
		if r.full[band] {
			s.Problems = append(s.Problems, fmt.Sprintf("%s: the driver's R1KH table budget is used up until the radio's next restart: further roams to this unit do a full association", band))
		}
	}
	return s, nil
}

// ServesFTSAE implements ftSAEServer: FT-SAE is built on some radio
// (ft, wpa3, ft_sae, a driver with FT and SAE).
func (a *Applier) ServesFTSAE() bool {
	if !a.o.FT || !a.o.WPA3 || !a.o.FTSAE {
		return false
	}
	return slices.ContainsFunc(a.o.Layout, func(rd RadioDef) bool { return rd.FT && rd.SAE && rd.FTSAE })
}

// ServesRoaming: the agent runs the roaming runtime (ft): 802.11v
// requests and the neighbour lists. The agent claims band steering and
// the Roaming Assistant only then.
func (a *Applier) ServesRoaming() bool {
	return a.o.FT && slices.ContainsFunc(a.o.Layout, func(rd RadioDef) bool { return rd.FT })
}

// ftLayout applies the ft and ft_sae keys to o's layout.
func ftLayout(o Options) []RadioDef {
	l := append([]RadioDef(nil), o.Layout...)
	for i := range l {
		switch {
		case !o.FT && l[i].FT:
			l[i].FT, l[i].NoFTWhy = false, "off in the agent's config (ft)"
		case !l[i].FT && l[i].NoFTWhy == "":
			l[i].NoFTWhy = fmt.Sprintf("the %s driver has no 802.11r (2.4 GHz: the rebuilt mt7603roam module is not loaded)", l[i].HWName)
		}
		l[i].FTSAE = o.WPA3 && o.FTSAE
	}
	return l
}

// ----------------------------------------------------------- driver access

// drv runs f with the restart gate open; false: the gate is closed.
func (r *roam) drv(f func() error) (bool, error) {
	done, ok := r.gate()
	if !ok {
		return false, nil
	}
	defer done()
	return true, f()
}

func (r *roam) oid(ifc string, req mtkft.Request) error {
	_, err := r.io.OID(ifc, req.Flags, req.Buf)
	return err
}

// ----------------------------------------------------------- frames

// ethFrame is dst | src | type | payload.
func ethFrame(dst, src mtkft.MAC, typ uint16, payload []byte) []byte {
	b := make([]byte, 14, 14+len(payload))
	copy(b, dst[:])
	copy(b[6:], src[:])
	binary.BigEndian.PutUint16(b[12:], typ)
	return append(b, payload...)
}

// sendRRB sends payload from b to dst on b's bridge (r.mu held).
func (r *roam) sendRRB(b roamBSS, dst mtkft.MAC, payload []byte, what string) {
	c := r.conns["rrb "+b.Bridge]
	if c == nil {
		r.count("rrb-no-socket")
		return
	}
	if err := c.Send(ethFrame(dst, b.BSSID, mtkft.EtherTypeOUI, payload)); err != nil {
		r.once("send "+b.Bridge, "mtkwifi: roaming: sending the %s on %s: %v", what, b.Bridge, err)
		r.count("rrb-send-error")
		return
	}
	r.count("rrb-sent-" + what)
}

func (r *roam) txSeq(k pairKey) mtkft.Seq {
	t := r.tx[k]
	if t == nil {
		t = &mtkft.TxSeq{}
		r.tx[k] = t
	}
	return t.Next(r.secs())
}

func (r *roam) rxOK(k pairKey, s mtkft.Seq) bool {
	x := r.rx[k]
	if x == nil {
		x = &mtkft.RxSeq{}
		r.rx[k] = x
	}
	return x.Accept(s)
}

func (r *roam) allow(src mtkft.MAC, now time.Time) bool {
	b := r.rate[src]
	if b == nil {
		if len(r.rate) > 256 {
			clear(r.rate)
		}
		b = &bucket{tokens: rrbBurst, at: now}
		r.rate[src] = b
	}
	b.tokens = min(rrbBurst, b.tokens+now.Sub(b.at).Seconds()*rrbRate)
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// onRRB takes one frame of a bridge's RRB tap.
func (r *roam) onRRB(bridge string, frame []byte) {
	if len(frame) < 14 || binary.BigEndian.Uint16(frame[12:]) != mtkft.EtherTypeOUI {
		return
	}
	var dst, src mtkft.MAC
	copy(dst[:], frame[0:6])
	copy(src[:], frame[6:12])
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.bssByMAC(dst)
	if !ok || !b.FTSAE || b.Bridge != bridge || r.ownMAC(src) {
		return // another AP's, or this unit's own
	}
	now := r.now()
	if !r.allow(src, now) {
		r.count("rrb-rate-limited")
		return
	}
	f, sealed, err := mtkft.Split(frame[14:])
	if err != nil {
		r.count("rrb-malformed")
		return
	}
	r0, r1, ok := f.R0KHIDOf()
	if !ok {
		r.count("rrb-malformed")
		return
	}
	var ro role
	var peer ftpeer.Peer
	found := false
	switch {
	case r1 == b.BSSID && !bytes.Equal(r0, b.R0KHID):
		ro = asR1KH
		for _, p := range r.peersOf(b) {
			if bs, _, err := peerMACs(p); err == nil && bs == src && p.R0KHID == string(r0) {
				peer, found = p, true
			}
		}
	case bytes.Equal(r0, b.R0KHID) && r1 != b.BSSID:
		ro = asR0KH
		for _, p := range r.peersOf(b) {
			if bs, pr1, err := peerMACs(p); err == nil && bs == src && pr1 == r1 {
				peer, found = p, true
			}
		}
	}
	if !found {
		r.count("rrb-unknown-peer")
		return
	}
	if err := f.Open(b.key, src, sealed); err != nil {
		r.count("rrb-auth-failed")
		return
	}
	pk := pairKey{b.BSSID, src, ro}
	switch {
	case f.Subtype == mtkft.SubSeqReq:
		q, err := mtkft.ParseSeqReq(f)
		if err != nil {
			r.count("rrb-malformed")
			return
		}
		out, err := mtkft.SealSeqResp(b.key, b.BSSID, q, r.txSeq(pk))
		if err == nil {
			r.sendRRB(b, src, out, "seq-resp")
		}
	case f.Subtype == mtkft.SubPush && ro == asR1KH:
		p, err := mtkft.ParsePush(f)
		if err != nil || p.R1KHID != b.BSSID {
			r.count("rrb-malformed")
			return
		}
		if !r.rxOK(pk, p.Seq) {
			r.count("rrb-replayed")
			return
		}
		r.count("rrb-push-received")
		r.keep(b, src, p.R0KHID, p.S1KHID, p.PMKR0Name, p.PMKR1Name, p.PMKR1, p.Pairwise, p.ExpiresIn, now)
	case f.Subtype == mtkft.SubResp && ro == asR1KH:
		resp, err := mtkft.ParseResp(f)
		if err != nil {
			r.count("rrb-malformed")
			return
		}
		pr, ok := r.pulls[resp.Nonce]
		if !ok || pr.bss != b.BSSID || pr.sta != resp.S1KHID {
			r.count("rrb-unasked-response")
			return
		}
		delete(r.pulls, resp.Nonce)
		if !r.rxOK(pk, resp.Seq) {
			r.count("rrb-replayed")
			return
		}
		if !resp.Found || mtkft.PMKR1Name(pr.pmkR0Name, b.BSSID, pr.sta) != resp.PMKR1Name {
			r.count("pull-not-found")
			return
		}
		r.count("pull-answered")
		r.keep(b, src, pr.r0kh, pr.sta, pr.pmkR0Name, resp.PMKR1Name, resp.PMKR1, resp.Pairwise, resp.ExpiresIn, now)
	case f.Subtype == mtkft.SubPull && ro == asR0KH:
		p, err := mtkft.ParsePull(f)
		if err != nil {
			r.count("rrb-malformed")
			return
		}
		if !r.rxOK(pk, p.Seq) {
			r.count("rrb-replayed")
			return
		}
		r.count("rrb-pull-received")
		r.answerPull(b, peer, p)
	default:
		r.count("rrb-ignored")
	}
}

// ----------------------------------------------------------- keys from the Decos

// keep records an SA a Deco sent and installs it (r.mu held).
func (r *roam) keep(b roamBSS, r0kh mtkft.MAC, r0khID []byte, sta mtkft.MAC, r0name, r1name [16]byte, pmk [32]byte,
	pairwise, expires uint16, now time.Time) {
	if mtkft.PMKR1Name(r0name, b.BSSID, sta) != r1name {
		r.count("sa-bad-name")
		return
	}
	cipher, err := mtkft.CipherFromHostapd(pairwise)
	if err != nil {
		r.count("sa-bad-cipher")
		return
	}
	life := uint32(expires)
	if life == 0 {
		life = saDefaultLife
	}
	s := &sa{bss: b.BSSID, band: b.Band, exp: now.Add(time.Duration(life) * time.Second), last: now, gen: -1, since: now,
		el: mtkft.KeyElement{STA: sta, R0KHID: append([]byte(nil), r0khID...), PMKR0Name: r0name, R1KHID: b.BSSID,
			S1KHID: sta, PMKR1Name: r1name, PMKR1: pmk, R0KHMAC: r0kh, Pairwise: cipher, AKM: mtkft.AKMFTSAE,
			KeyLifeTime: life, ReassocDeadline: reassocTU}}
	if t, ok := r.stas[sta]; ok && t.After(now.Add(-staMemory)) {
		s.last = t
	}
	if len(r.sas) >= maxSAs {
		r.dropOldestSA()
	}
	r.sas[r1name] = s
	r.install(b, s)
}

// ftPSKFor installs sta's FT-PSK PMK-R1s on 5 GHz BSS b for each Deco
// R0KH-ID in b's mobility domain (r.mu held): the MT7663 does not derive
// FT-PSK keys itself (FT_AuthReqRsnValidation), a Deco never pushes them
// (ft_psk_generate_local), so the agent computes what hostapd's
// wpa_ft_psk_pmk_r1 would (mtkft.FTPSKR1). The Decos' 5 GHz holders come
// from the FT peers (announced for FT-SAE WLANs); a WPA2-only WLAN has none
// and gets nothing (noted in garage-ft.md). SAs already kept are refreshed.
func (r *roam) ftPSKFor(b roamBSS, sta mtkft.MAC) {
	if b.Band != "na" || !b.FT || !b.hasPSK {
		return
	}
	now := r.now()
	for _, p := range r.peers {
		// same domain; with a WLAN key, the same WLAN's holders only
		if p.Holder.Band != "na" || p.Holder.MDID != b.MDID || len(p.Holder.R0KHID) == 0 || (b.keyID != "" && p.KeyID != b.keyID) {
			continue
		}
		r0mac, _, err := peerMACs(p)
		if err != nil || r0mac == b.BSSID {
			continue
		}
		r0, r1, err := mtkft.FTPSKR1(b.psk, []byte(b.SSID), mtkft.MDID(b.MDID), []byte(p.Holder.R0KHID), sta, b.BSSID)
		clear(r0.Key[:])
		if err != nil {
			continue
		}
		if s, ok := r.sas[r1.Name]; ok {
			s.exp, s.last = now.Add(saDefaultLife*time.Second), now
			clear(r1.Key[:])
			r.install(b, s)
			continue
		}
		s := &sa{bss: b.BSSID, band: b.Band, exp: now.Add(saDefaultLife * time.Second), last: now, gen: -1, since: now,
			el: mtkft.KeyElement{STA: sta, R0KHID: []byte(p.Holder.R0KHID), PMKR0Name: r0.Name, R1KHID: b.BSSID,
				S1KHID: sta, PMKR1Name: r1.Name, PMKR1: r1.Key, R0KHMAC: r0mac, Pairwise: mtkft.CipherCCMP,
				AKM: mtkft.AKMFTPSK, KeyLifeTime: saDefaultLife, ReassocDeadline: reassocTU}}
		if len(r.sas) >= maxSAs {
			r.dropOldestSA()
		}
		r.sas[r1.Name] = s
		r.count("ftpsk-derived")
		r.install(b, s)
	}
}

func (r *roam) dropOldestSA() {
	var oldest [16]byte
	var t time.Time
	first := true
	for k, s := range r.sas {
		if first || s.since.Before(t) {
			oldest, t, first = k, s.since, false
		}
	}
	if !first {
		clear(r.sas[oldest].el.PMKR1[:])
		delete(r.sas, oldest)
	}
}

// budgetOK: band's driver table has room for s (r.mu held). On 5 GHz a
// station never seen on this unit takes an entry only while plenty are
// free (the Decos push every SAE join; most of those stations never come).
func (r *roam) budgetOK(band string, s *sa, now time.Time) bool {
	limit := r1kh2GBudget
	if band == "na" {
		limit = r1khBudget
		if t, ok := r.stas[s.el.STA]; !ok || t.Before(now.Add(-staMemory)) {
			limit = r1khBudget - r1khKnownFree
		}
	}
	if r.used[band] < limit {
		return true
	}
	if !r.full[band] {
		r.full[band] = true
		r.logf("mtkwifi: roaming: %s: %d PMK-R1 SAs in the driver since the radio started: no more until its next restart (stations then do a full association)", band, r.used[band])
	}
	return false
}

// install puts s into the driver (r.mu held): KEY_RSP on the MT7663, R1_SET
// on the MT7603. Inside a settle time it waits (retry).
func (r *roam) install(b roamBSS, s *sa) {
	now := r.now()
	if s.gen == r.gen[b.Band] || now.After(s.exp) {
		return
	}
	if !r.budgetOK(b.Band, s, now) {
		r.count("sa-over-budget")
		return
	}
	ran, err := r.drv(func() error {
		if b.Band == "na" {
			req, err := mtkft.KeyResponse(s.el)
			if err != nil {
				return err
			}
			return r.oid(b.Ifname, req)
		}
		rec, err := (mtkft.UDFTR1{NameGiven: true, STA: s.el.STA, R1KHID: b.BSSID, R0KHID: s.el.R0KHID,
			PMKR0Name: s.el.PMKR0Name, PMKR1Name: s.el.PMKR1Name, PMKR1: s.el.PMKR1, AKM: mtkft.AKMFTSAE,
			Pairwise: s.el.Pairwise, Lifetime: uint32(s.exp.Sub(now) / time.Second)}).MarshalBinary()
		if err != nil {
			return err
		}
		defer clear(rec)
		_, err = r.io.OID(b.Ifname, mtkft.OIDUDFTR1Set|mtkft.OIDSet, rec)
		return err
	})
	if !ran {
		s.pending = true
		r.count("sa-waiting-settle")
		return
	}
	s.pending = false
	if err != nil {
		r.once("install "+b.Ifname+err.Error(), "mtkwifi: roaming: installing a PMK-R1 on %s: %v", b.Ifname, err)
		r.count("sa-install-error")
		return
	}
	s.gen = r.gen[b.Band]
	r.used[b.Band]++
	r.count("sa-installed-" + b.Band)
}

// ----------------------------------------------------------- keys to the Decos

func (r *roam) newTag() uint32 {
	for {
		r.tag++
		if r.tag == 0 {
			continue
		}
		if _, busy := r.keyReqs[r.tag]; !busy {
			return r.tag
		}
	}
}

// ftAssoc: sta completed an FT initial association on b (r.mu held).
func (r *roam) ftAssoc(b roamBSS, sta mtkft.MAC, join bool) {
	now := r.now()
	k := keyJoin{sta, b.BSSID}
	if m, ok := r.assoc[k]; ok && now.Sub(m.at) < assocDedup {
		if !join && !m.counted {
			r.used["na"]++ // the driver's own R1KH entry
			m.counted = true
			r.assoc[k] = m
		}
		return
	}
	r.stas[sta] = now
	// the driver's own R1KH entry: counted on its FT_ASSOCIATION signal,
	// or on the first KEY_RSP_AUTO for a 4-way completion (the driver
	// answers only with an entry)
	r.assoc[k] = assocMark{at: now, counted: !join}
	if !join {
		r.used["na"]++
	}
	for _, p := range r.peersOf(b) {
		_, r1kh, err := peerMACs(p)
		if err != nil {
			continue
		}
		tag := r.newTag()
		req, err := mtkft.KeyRequest(tag, sta, r1kh)
		if err != nil {
			continue
		}
		ran, err := r.drv(func() error { return r.oid(b.Ifname, req) })
		if !ran || err != nil {
			r.count("keyreq-failed")
			continue
		}
		r.keyReqs[tag] = keyReq{at: now, bss: b.BSSID, peer: p, sta: sta, join: join}
	}
}

// pushTo sends a PMK-R1 to peer (r.mu held).
func (r *roam) pushTo(b roamBSS, peer ftpeer.Peer, sta mtkft.MAC, r0name, r1name [16]byte, pmk [32]byte, cipher mtkft.Suite, life uint32) {
	bs, r1kh, err := peerMACs(peer)
	if err != nil {
		return
	}
	pw, err := mtkft.HostapdCipher(cipher)
	if err != nil {
		r.count("push-bad-cipher")
		return
	}
	switch {
	case life == 0:
		life = saDefaultLife
	case life > 0xffff:
		life = 0xffff
	}
	p := mtkft.Push{Seq: r.txSeq(pairKey{b.BSSID, bs, asR0KH}), R0KHID: b.R0KHID, R1KHID: r1kh, S1KHID: sta,
		PMKR0Name: r0name, PMKR1: pmk, PMKR1Name: r1name, Pairwise: pw, ExpiresIn: uint16(life)}
	out, err := mtkft.SealPush(b.key, b.BSSID, p)
	clear(p.PMKR1[:])
	if err != nil {
		return
	}
	r.sendRRB(b, bs, out, "push")
}

// respond answers pull p of peer from b (r.mu held); el nil: not found.
func (r *roam) respond(b roamBSS, peer ftpeer.Peer, p mtkft.Pull, r1name [16]byte, pmk [32]byte, cipher mtkft.Suite, life uint32, found bool) {
	bs, _, err := peerMACs(peer)
	if err != nil {
		return
	}
	resp := mtkft.Resp{Nonce: p.Nonce, Seq: r.txSeq(pairKey{b.BSSID, bs, asR0KH}), R0KHID: p.R0KHID, R1KHID: p.R1KHID,
		S1KHID: p.S1KHID}
	if found {
		pw, err := mtkft.HostapdCipher(cipher)
		if err == nil {
			resp.Found, resp.PMKR1, resp.PMKR1Name, resp.Pairwise = true, pmk, r1name, pw
			resp.ExpiresIn = uint16(min(life, 0xffff))
		}
	}
	out, err := mtkft.SealResp(b.key, b.BSSID, resp)
	clear(resp.PMKR1[:])
	if err != nil {
		return
	}
	r.sendRRB(b, bs, out, "resp")
}

// answerPull derives the PMK-R1 a Deco pulls (r.mu held): 5 GHz with a
// KEY_REQ (the answer comes as a KDP KEY_RSP_AUTO), 2.4 GHz with R1_GET.
func (r *roam) answerPull(b roamBSS, peer ftpeer.Peer, p mtkft.Pull) {
	if b.Band == "na" {
		tag := r.newTag()
		req, err := mtkft.KeyRequest(tag, p.S1KHID, p.R1KHID)
		if err == nil {
			if ran, err := r.drv(func() error { return r.oid(b.Ifname, req) }); ran && err == nil {
				pc := p
				r.keyReqs[tag] = keyReq{at: r.now(), bss: b.BSSID, peer: peer, sta: p.S1KHID, pull: &pc}
				return
			}
		}
		r.respond(b, peer, p, [16]byte{}, [32]byte{}, mtkft.Suite{}, 0, false)
		return
	}
	buf := mtkft.UDFTR1Request(p.S1KHID, p.R1KHID, p.PMKR0Name)
	var rec mtkft.UDFTR1
	ran, err := r.drv(func() error {
		if _, err := r.io.OID(b.Ifname, mtkft.OIDUDFTR1Get, buf); err != nil {
			return err
		}
		return rec.UnmarshalBinary(buf)
	})
	clear(buf)
	found := ran && err == nil && rec.PMKR0Name == p.PMKR0Name && rec.R1KHID == p.R1KHID
	r.respond(b, peer, p, rec.PMKR1Name, rec.PMKR1, suiteOr(rec.Pairwise, mtkft.CipherCCMP), rec.Lifetime, found)
	clear(rec.PMKR1[:])
}

func suiteOr(s, def mtkft.Suite) mtkft.Suite {
	if s == (mtkft.Suite{}) {
		return def
	}
	return s
}

// onKDP takes one frame of a 5 GHz netdev's KDP tap.
func (r *roam) onKDP(ifc string, frame []byte) {
	sig, err := mtkft.ParseSignal(frame)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.bssByMAC(sig.BSSID)
	if !ok || b.Band != "na" || !b.FT {
		return
	}
	r.count(fmt.Sprintf("kdp-%#02x", sig.Sig))
	switch sig.Sig {
	case mtkft.SigFTAssoc:
		ev, err := sig.ParseAssoc()
		if err != nil {
			return
		}
		r.ftAssoc(b, ev.STA, false)
	case mtkft.SigKeyRspAuto:
		kr, ok := r.keyReqs[sig.PeerIP]
		if !ok || kr.bss != b.BSSID {
			return
		}
		delete(r.keyReqs, sig.PeerIP)
		if k := (keyJoin{kr.sta, kr.bss}); kr.join && !r.assoc[k].counted {
			if m, ok := r.assoc[k]; ok {
				r.used["na"]++
				m.counted = true
				r.assoc[k] = m
			}
		}
		var e mtkft.KeyElement
		if err := e.UnmarshalBinary(sig.Body); err != nil {
			r.count("kdp-malformed")
			return
		}
		defer clear(e.PMKR1[:])
		if e.S1KHID == (mtkft.MAC{}) {
			e.S1KHID = kr.sta
		}
		_, r1kh, _ := peerMACs(kr.peer)
		if e.R1KHID != r1kh || mtkft.PMKR1Name(e.PMKR0Name, e.R1KHID, e.S1KHID) != e.PMKR1Name {
			r.count("kdp-key-mismatch")
			if kr.pull != nil {
				r.respond(b, kr.peer, *kr.pull, [16]byte{}, [32]byte{}, mtkft.Suite{}, 0, false)
			}
			return
		}
		if len(e.R0KHID) > 0 && !bytes.Equal(e.R0KHID, b.R0KHID) {
			r.once("r0kh "+b.Ifname, "mtkwifi: roaming: %s: the driver's R0KH-ID %q is not the profile's %q (its length bug): FT-SAE roams to the Decos may fail", b.Ifname, e.R0KHID, b.R0KHID)
		}
		if kr.pull != nil {
			found := e.PMKR0Name == kr.pull.PMKR0Name
			r.respond(b, kr.peer, *kr.pull, e.PMKR1Name, e.PMKR1, e.Pairwise, e.KeyLifeTime, found)
			return
		}
		if e.AKM != mtkft.AKMFTSAE {
			// FT-PSK: the Decos derive it themselves. The answer proves
			// an FT-PSK station: pre-install its keys for a roam back
			// from each Deco (a station without FT gets no answer, an
			// SAE one none of these)
			r.count("kdp-not-ftsae")
			if e.AKM == mtkft.AKMFTPSK && kr.pull == nil {
				r.ftPSKFor(b, kr.sta)
			}
			return
		}
		r.pushTo(b, kr.peer, e.S1KHID, e.PMKR0Name, e.PMKR1Name, e.PMKR1, e.Pairwise, e.KeyLifeTime)
	case mtkft.SigKeyReqAuto:
		var e mtkft.KeyElement
		if e.UnmarshalBinary(sig.Body) == nil && e.STA != (mtkft.MAC{}) {
			r.stas[e.STA] = r.now()
			// refused with 53 already; the station's retry (or its next
			// roam) finds the FT-PSK SAs
			if e.AKM != mtkft.AKMFTSAE {
				r.ftPSKFor(b, e.STA)
			}
		}
		r.count("r1kh-miss-na")
	}
}

// FTJoined takes a station's 4-way completion (drvevents.go DrvAuthorized,
// DrvKeyDone). On the unit no FT_ASSOCIATION signal came on an initial
// FT-PSK association (2026-11-23), so the runtime does not rely on it: a
// 5 GHz FT-SAE BSS's new station is sent the KEY_REQs joinWait later, once,
// whichever comes first. The events' netdev is not always the station's
// (WAPP and the system log report on any rai*), so without a BSSID every
// 5 GHz FT-SAE BSS asks: the driver answers on the station's own BSS
// (FT_KDP_KeyRequestToUs takes the BSS from its MAC entry) and onKDP drops
// the answers to the others. A station without an FT key hierarchy gets no
// answer (FT_QueryKeyInfoForKDP finds no R1KH entry): its requests time out.
func (a *Applier) FTJoined(ifname, mac, bssid string) {
	if a.roam == nil {
		return
	}
	sta, err := mtkft.ParseMAC(mac)
	if err != nil {
		return
	}
	r := a.roam
	r.mu.Lock()
	defer r.mu.Unlock()
	want, err := mtkft.ParseMAC(bssid)
	given := err == nil && want != (mtkft.MAC{})
	if b, ok := r.bssByMAC(want); given && ok && b.Band == "na" && b.FT {
		r.stas[sta] = r.now()
	}
	for _, b := range r.bss {
		k := keyJoin{sta, b.BSSID}
		if m, ok := r.assoc[k]; ok && r.now().Sub(m.at) < assocDedup {
			continue
		}
		if b.Band == "na" && b.FT && b.FTSAE && (!given || b.BSSID == want) {
			r.joins[k] = r.now()
		}
	}
}

// ----------------------------------------------------------- 2.4 GHz events

// FTEvent takes the drivers' roaming IWEVCUSTOM events (drvevents.go):
// the MT7603's UDFT records (flags 0x0961), the MT7663's neighbour report
// requests and BTM responses (rrm.go).
func (a *Applier) FTEvent(ifname string, flags uint16, data []byte) {
	if a.roam == nil {
		return
	}
	switch flags {
	case mtkft.OIDUDFTEvents:
		a.roam.onUDFTNotify(ifname, data)
	default:
		a.roam.onRRMEvent(ifname, flags, data)
	}
}

// onUDFTNotify: an MT7603 key event was queued; the ring is drained with
// EVENT_GET (the IWEVCUSTOM can be lost; the ring keeps 32).
func (r *roam) onUDFTNotify(ifc string, _ []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.bssByIfname(ifc)
	if !ok || b.Band != "ng" || !b.FT {
		return
	}
	r.drainUDFT(b.Ifname)
}

// drainUDFT reads the MT7603's queued events (r.mu held).
func (r *roam) drainUDFT(ifc string) {
	buf := make([]byte, mtkft.UDFTRing*mtkft.UDFTEventLen)
	var n int
	ran, err := r.drv(func() error {
		var err error
		n, err = r.io.OID(ifc, mtkft.OIDUDFTEvents, buf)
		return err
	})
	if !ran || err != nil || n <= 0 || n > len(buf) {
		return
	}
	evs, err := mtkft.ParseUDFTEvents(buf[:n])
	if err != nil {
		r.count("udft-malformed")
	}
	for _, e := range evs {
		if last, ok := r.udftSeq["ng"]; ok && e.Seq != last+1 && e.Seq > last {
			r.count("udft-lost")
		}
		r.udftSeq["ng"] = e.Seq
		b, ok := r.bssByMAC(e.BSSID)
		if !ok || b.Band != "ng" {
			continue
		}
		switch e.Type {
		case mtkft.UDFTR0Created:
			r.stas[e.STA] = r.now()
			if e.AKM != mtkft.AKMFTSAE {
				continue
			}
			r.pushFrom2G(b, e)
		case mtkft.UDFTR1Miss:
			r.pull2G(b, e)
		}
	}
}

// pushFrom2G pushes the SA of an initial FT-SAE association on 2.4 GHz to
// each Deco R1KH (R1_GET derives each) (r.mu held).
func (r *roam) pushFrom2G(b roamBSS, e mtkft.UDFTEvent) {
	for _, p := range r.peersOf(b) {
		_, r1kh, err := peerMACs(p)
		if err != nil {
			continue
		}
		buf := mtkft.UDFTR1Request(e.STA, r1kh, e.PMKR0Name)
		var rec mtkft.UDFTR1
		ran, err := r.drv(func() error {
			if _, err := r.io.OID(b.Ifname, mtkft.OIDUDFTR1Get, buf); err != nil {
				return err
			}
			return rec.UnmarshalBinary(buf)
		})
		clear(buf)
		if !ran || err != nil || rec.R1KHID != r1kh {
			r.count("r1get-failed")
			continue
		}
		r.pushTo(b, p, e.STA, rec.PMKR0Name, rec.PMKR1Name, rec.PMKR1, suiteOr(rec.Pairwise, mtkft.CipherCCMP), rec.Lifetime)
		clear(rec.PMKR1[:])
	}
}

// pull2G asks the station's R0KH for the PMK-R1 the MT7603 missed (r.mu held).
func (r *roam) pull2G(b roamBSS, e mtkft.UDFTEvent) {
	for _, p := range r.peersOf(b) {
		bs, _, err := peerMACs(p)
		if err != nil || p.R0KHID != string(e.R0KHID) {
			continue
		}
		var nonce [mtkft.NonceLen]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return
		}
		pl := mtkft.Pull{Nonce: nonce, Seq: r.txSeq(pairKey{b.BSSID, bs, asR1KH}), R0KHID: e.R0KHID, R1KHID: b.BSSID,
			PMKR0Name: e.PMKR0Name, S1KHID: e.STA}
		out, err := mtkft.SealPull(b.key, b.BSSID, pl)
		if err != nil {
			return
		}
		r.pulls[nonce] = pullReq{at: r.now(), bss: b.BSSID, peer: p, sta: e.STA, r0kh: append([]byte(nil), e.R0KHID...), pmkR0Name: e.PMKR0Name}
		r.sendRRB(b, bs, out, "pull")
		return
	}
	r.count("r1kh-miss-unknown-r0kh")
}

// ----------------------------------------------------------- the loop

// tick expires requests and installs what waits (r.mu not held).
func (r *roam) tick() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for t, kr := range r.keyReqs {
		if now.Sub(kr.at) > keyReqTimeout {
			delete(r.keyReqs, t)
			if kr.pull != nil {
				if b, ok := r.bssByMAC(kr.bss); ok {
					r.respond(b, kr.peer, *kr.pull, [16]byte{}, [32]byte{}, mtkft.Suite{}, 0, false)
				}
			}
			r.count("keyreq-timeout")
		}
	}
	var joins []keyJoin
	for j, at := range r.joins {
		if now.Sub(at) >= joinWait {
			joins = append(joins, j)
			delete(r.joins, j)
		}
	}
	for _, j := range joins {
		if b, ok := r.bssByMAC(j.bss); ok && b.FTSAE {
			r.ftAssoc(b, j.sta, true)
		}
	}
	for m, t := range r.assoc {
		if now.Sub(t.at) > staMemory {
			delete(r.assoc, m)
		}
	}
	for n, p := range r.pulls {
		if now.Sub(p.at) > pullTimeout {
			delete(r.pulls, n)
			r.count("pull-timeout")
		}
	}
	for m, t := range r.stas {
		if now.Sub(t) > staMemory {
			delete(r.stas, m)
		}
	}
	// SAs: expired ones go; the others are installed where missing (a
	// radio restart, a settle time), most recent first
	var todo []*sa
	for k, s := range r.sas {
		if now.After(s.exp) {
			clear(s.el.PMKR1[:])
			delete(r.sas, k)
			continue
		}
		if s.pending && now.Sub(s.since) > installRetries*time.Second && s.gen < 0 {
			s.pending = false // too late for the roam it was for: kept for a restart
		}
		if s.gen != r.gen[s.band] {
			todo = append(todo, s)
		}
	}
	slices.SortFunc(todo, func(x, y *sa) int { return y.last.Compare(x.last) })
	for _, s := range todo {
		if b, ok := r.bssByMAC(s.bss); ok && (b.FTSAE || (s.el.AKM == mtkft.AKMFTPSK && b.hasPSK)) {
			r.install(b, s)
		}
	}
}

// handBack: Wi-Fi goes back to the vendor (a.mu held, the gate held).
func (r *roam) handBack() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bss = nil
	for k, s := range r.sas {
		clear(s.el.PMKR1[:])
		delete(r.sas, k)
	}
	clear(r.keyReqs)
	clear(r.pulls)
	clear(r.joins)
}

// roamHandBack is restoreBaseline's part (a.mu held).
func (a *Applier) roamHandBack(ctx context.Context) {
	if a.roam != nil {
		a.roam.handBack()
	}
}

// RunRoaming runs the runtime's taps until ctx ends (the agent's
// goroutine, platform jio-mtk): a KDP tap on each 5 GHz FT netdev and an
// RRB tap on each FT-SAE bridge, opened and closed as the plans change.
func (a *Applier) RunRoaming(ctx context.Context) {
	r := a.roam
	if r == nil || a.o.DryRun {
		return
	}
	if r.io == nil {
		io, err := openRoamIO()
		if err != nil {
			a.o.Logf("mtkwifi: roaming: %v", err)
			return
		}
		r.io = io
	}
	var wg sync.WaitGroup
	defer func() {
		r.mu.Lock()
		for k, c := range r.conns {
			_ = c.Close()
			delete(r.conns, k)
		}
		r.mu.Unlock()
		wg.Wait()
	}()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		r.reconcile(ctx, &wg)
		r.tick()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// reconcile opens the taps the configuration needs and closes the others.
func (r *roam) reconcile(ctx context.Context, wg *sync.WaitGroup) {
	r.mu.Lock()
	want := map[string]bool{}
	for _, b := range r.bss {
		if b.Band == "na" && b.FT {
			want["kdp "+b.Ifname] = true
		}
		if b.FTSAE {
			want["rrb "+b.Bridge] = true
		}
	}
	for k, c := range r.conns {
		if !want[k] {
			_ = c.Close()
			delete(r.conns, k)
		}
	}
	var open []string
	for k := range want {
		if r.conns[k] == nil {
			open = append(open, k)
		}
	}
	r.mu.Unlock()
	for _, k := range open {
		kind, dev, _ := strings.Cut(k, " ")
		typ := uint16(mtkft.EtherTypeOUI)
		if kind == "kdp" {
			typ = mtkft.EtherTypeKDP
		}
		c, err := r.io.Open(dev, typ)
		if err != nil {
			r.mu.Lock()
			r.once("open "+k+err.Error(), "mtkwifi: roaming: opening the %s tap on %s: %v", kind, dev, err)
			r.mu.Unlock()
			continue
		}
		r.mu.Lock()
		r.conns[k] = c
		r.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			for ctx.Err() == nil {
				n, err := c.Recv(buf)
				if errors.Is(err, errRoamTimeout) {
					continue
				}
				if err != nil {
					return // closed
				}
				if kind == "kdp" {
					r.onKDP(dev, buf[:n])
				} else {
					r.onRRB(dev, buf[:n])
				}
			}
		}()
	}
}

// statusEvery is the shortest gap between two roaming status lines.
const statusEvery = time.Minute

// logStatus logs the runtime's BSSes, peer count and counters when they
// changed since the last line, at most once a statusEvery (the agent's
// tick calls it), so the on-unit roaming test can follow the key exchange.
func (r *roam) logStatus() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bss) == 0 {
		return
	}
	var bs []string
	for _, b := range r.bss {
		f := "-"
		switch {
		case b.FTSAE:
			f = "ft+sae"
		case b.FT:
			f = "ft"
		}
		bs = append(bs, fmt.Sprintf("%s/%s/%s", b.Ifname, b.Band, f))
	}
	var ks []string
	for k, v := range r.stats {
		ks = append(ks, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(ks)
	line := fmt.Sprintf("bss [%s] peers %d r1kh %v counters [%s]", strings.Join(bs, " "), len(r.peers), r.used, strings.Join(ks, " "))
	if line == r.status || (!r.statusAt.IsZero() && r.now().Sub(r.statusAt) < statusEvery) {
		return
	}
	r.status, r.statusAt = line, r.now()
	r.logf("mtkwifi: roaming: %s", line)
}

// RoamStats are the runtime's counters (for the agent's log).
func (a *Applier) RoamStats() map[string]uint64 {
	r := a.roam
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]uint64{}
	for k, v := range r.stats {
		out[k] = v
	}
	return out
}
