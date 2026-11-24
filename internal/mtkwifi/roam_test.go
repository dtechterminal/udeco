// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"bytes"
	"encoding/binary"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/ftpeer"
	"github.com/dtechterminal/udeco/internal/mtkft"
)

// The roaming runtime against a fake driver and a fake Deco: the Deco's
// side is built from internal/mtkft's codecs, which are byte-exact against
// hostapd 2.9's layouts (mtkft rrb_test.go, rrbpull_test.go).

const testIAPPKey = "101112131415161718191a1b1c1d1e1f"

var (
	garageNA = mtkft.MAC{0x56, 0xf2, 0x83, 0x1d, 0xc0, 0x1e}
	garageNG = mtkft.MAC{0x54, 0xf2, 0x83, 0x1d, 0xc0, 0x1e}
	decoNA   = mtkft.MAC{0xa8, 0x42, 0xa1, 0, 0, 0x10}
	decoNG   = mtkft.MAC{0xa8, 0x42, 0xa1, 0, 0, 0x11}
	testSTA  = mtkft.MAC{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
)

type oidCall struct {
	ifname string
	flags  uint16
	buf    []byte
}

// fakeRoamIO is the drivers: it records every OID and set; reply fills an
// OID's answer (R1_GET, EVENT_GET).
type fakeRoamIO struct {
	mu    sync.Mutex
	oids  []oidCall
	sets  []string
	reply func(ifname string, flags uint16, buf []byte) (int, error)
}

func (f *fakeRoamIO) OID(ifname string, flags uint16, buf []byte) (int, error) {
	f.mu.Lock()
	f.oids = append(f.oids, oidCall{ifname, flags, append([]byte(nil), buf...)})
	r := f.reply
	f.mu.Unlock()
	if r != nil {
		return r(ifname, flags, buf)
	}
	return len(buf), nil
}

func (f *fakeRoamIO) Set(ifname, arg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets = append(f.sets, ifname+" "+arg)
	return nil
}

func (f *fakeRoamIO) Open(dev string, typ uint16) (frameConn, error) { return &fakeConn{}, nil }

func (f *fakeRoamIO) calls(flags uint16) []oidCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []oidCall
	for _, c := range f.oids {
		if c.flags == flags {
			out = append(out, c)
		}
	}
	return out
}

type fakeConn struct {
	mu   sync.Mutex
	sent [][]byte
}

func (c *fakeConn) Recv([]byte) (int, error) { return 0, errRoamTimeout }
func (c *fakeConn) Send(b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, append([]byte(nil), b...))
	return nil
}
func (c *fakeConn) Close() error { return nil }

func (c *fakeConn) take() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.sent
	c.sent = nil
	return s
}

type roamRig struct {
	t    *testing.T
	a    *Applier
	r    *roam
	io   *fakeRoamIO
	conn *fakeConn
	key  [32]byte
	na   roamBSS
	ng   roamBSS
	now  time.Time
}

func newRoamRig(t *testing.T) *roamRig {
	t.Helper()
	io := &fakeRoamIO{}
	a := New(Options{Root: t.TempDir(), FT: true, FTSAE: true, WPA3: true, roamIO: io, Logf: t.Logf})
	key, err := mtkft.RRBKey(testIAPPKey)
	if err != nil {
		t.Fatal(err)
	}
	rg := &roamRig{t: t, a: a, r: a.roam, io: io, conn: &fakeConn{}, key: key, now: time.Unix(1_800_000_000, 0)}
	rg.r.now = func() time.Time { return rg.now }
	rg.na = roamBSS{Band: "na", Ifname: "rai0", Bridge: "bdg2", SSID: "home", BSSID: garageNA, FT: true, FTSAE: true,
		MDID: 0xd530, R0KHID: []byte(mtkft.R0KHID(garageNA)), keyID: ftpeer.KeyID(testIAPPKey), rawKey: testIAPPKey, key: key}
	rg.ng = roamBSS{Band: "ng", Ifname: "ra0", Bridge: "bdg2", SSID: "home", BSSID: garageNG, FT: true, FTSAE: true,
		MDID: 0x1234, R0KHID: []byte(garageNG.Hex()), keyID: ftpeer.KeyID(testIAPPKey), rawKey: testIAPPKey, key: key}
	rg.r.setConfig([]roamBSS{rg.na, rg.ng})
	rg.r.setPeers([]ftpeer.Peer{
		{Holder: ftpeer.Holder{Band: "na", BSSID: decoNA.String(), R0KHID: decoNA.Hex(), R1KHID: decoNA.String(), MDID: 0xd530},
			KeyID: ftpeer.KeyID(testIAPPKey), Unit: "a8:42:a1:00:00:00", Bridge: "bdg2"},
		{Holder: ftpeer.Holder{Band: "ng", BSSID: decoNG.String(), R0KHID: decoNG.Hex(), R1KHID: decoNG.String(), MDID: 0x1234},
			KeyID: ftpeer.KeyID(testIAPPKey), Unit: "a8:42:a1:00:00:00", Bridge: "bdg2"},
		// another WLAN's key: never used
		{Holder: ftpeer.Holder{Band: "na", BSSID: "a8:42:a1:00:00:20", R0KHID: "a842a1000020", R1KHID: "a8:42:a1:00:00:20", MDID: 0xd530},
			KeyID: "0011223344556677", Unit: "a8:42:a1:00:00:01", Bridge: "bdg2"},
	})
	rg.r.conns["rrb bdg2"] = rg.conn
	return rg
}

// kdp builds a KDP signal frame as FT_KDP_EventInform puts it up the stack.
func kdp(bssid mtkft.MAC, sig byte, peerIP uint32, body []byte) []byte {
	f := make([]byte, 14+0x1c+8)
	copy(f, bssid[:])
	copy(f[6:], []byte{0, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(f[12:], mtkft.EtherTypeKDP)
	p := f[14:]
	p[0x12] = sig
	binary.LittleEndian.PutUint32(p[0x1c:], uint32(len(body)))
	binary.LittleEndian.PutUint32(p[0x20:], peerIP)
	return append(f, body...)
}

func assocBody(sta mtkft.MAC) []byte { return append([]byte{1, 0}, sta[:]...) }

// a station's FT-SAE key hierarchy at R0KH r0khID for R1KH r1kh.
func hierarchy(t *testing.T, r0khID []byte, r1kh mtkft.MAC) (mtkft.PMKR0, mtkft.PMKR1) {
	t.Helper()
	pmk := bytes.Repeat([]byte{0x5a}, 32) // the SAE PMK
	r0, err := mtkft.DerivePMKR0(pmk, []byte("home"), 0xd530, r0khID, testSTA)
	if err != nil {
		t.Fatal(err)
	}
	return r0, mtkft.DerivePMKR1(r0, r1kh, testSTA)
}

// openAt is the Deco's hostapd opening a frame the Garage sent it.
func (rg *roamRig) openAt(frame []byte, dst mtkft.MAC) mtkft.Frame {
	rg.t.Helper()
	if !bytes.Equal(frame[0:6], dst[:]) || binary.BigEndian.Uint16(frame[12:]) != mtkft.EtherTypeOUI {
		rg.t.Fatalf("frame header %x", frame[:14])
	}
	var src mtkft.MAC
	copy(src[:], frame[6:12])
	f, sealed, err := mtkft.Split(frame[14:])
	if err != nil {
		rg.t.Fatal(err)
	}
	if err := f.Open(rg.key, src, sealed); err != nil {
		rg.t.Fatalf("the Deco cannot open the Garage's frame: %v", err)
	}
	return f
}

// TestRoamFTSAEGarageToDeco: an initial FT-SAE association on the
// Garage's 5 GHz ends in a PUSH to the Deco's same-domain R1KH that
// hostapd takes, and the Deco's SEQ_REQ is answered.
func TestRoamFTSAEGarageToDeco(t *testing.T) {
	rg := newRoamRig(t)
	rg.r.onKDP("rai0", kdp(garageNA, mtkft.SigFTAssoc, 0, assocBody(testSTA)))
	reqs := rg.io.calls(mtkft.OIDKeyReq | mtkft.OIDSet)
	if len(reqs) != 1 || reqs[0].ifname != "rai0" {
		t.Fatalf("KEY_REQs %+v (one per same-key, same-domain Deco R1KH)", reqs)
	}
	tag := binary.LittleEndian.Uint32(reqs[0].buf)
	var asked mtkft.KeyElement
	if err := asked.UnmarshalBinary(reqs[0].buf[12:]); err != nil || asked.STA != testSTA || asked.R1KHID != decoNA {
		t.Fatalf("KEY_REQ element %+v %v", asked, err)
	}
	// the driver answers with KEY_RSP_AUTO, the PeerIP echoed
	r0, r1 := hierarchy(t, rg.na.R0KHID, decoNA)
	// as the MT7663 answers on the unit (2026-11-23): S1KH-ID zero; its
	// lifetime the PMKCachePeriod (90 days, pmkCacheMinutes), which the
	// push caps at hostapd's r0_key_lifetime
	el := mtkft.KeyElement{STA: testSTA, R0KHID: rg.na.R0KHID, PMKR0Name: r0.Name, R1KHID: decoNA,
		PMKR1Name: r1.Name, PMKR1: r1.Key, Pairwise: mtkft.CipherCCMP, AKM: mtkft.AKMFTSAE, KeyLifeTime: 129600 * 60}
	body, _ := el.MarshalBinary()
	rg.r.onKDP("rai0", kdp(garageNA, mtkft.SigKeyRspAuto, tag+1, body)) // a tag never asked: ignored
	if s := rg.conn.take(); len(s) != 0 {
		t.Fatalf("pushed on an unknown tag: %d", len(s))
	}
	rg.r.onKDP("rai0", kdp(garageNA, mtkft.SigKeyRspAuto, tag, body))
	sent := rg.conn.take()
	if len(sent) != 1 {
		t.Fatalf("%d frames, want one PUSH", len(sent))
	}
	f := rg.openAt(sent[0], decoNA)
	p, err := mtkft.ParsePush(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.R0KHID, rg.na.R0KHID) || p.R1KHID != decoNA || p.S1KHID != testSTA || p.PMKR1 != r1.Key ||
		p.PMKR1Name != r1.Name || p.PMKR0Name != r0.Name || p.Pairwise != 0x10 || p.ExpiresIn != 43200 {
		t.Fatalf("push %+v", p)
	}
	if !bytes.Equal(sent[0][6:12], garageNA[:]) {
		t.Fatalf("push from %x, want the BSSID (the Deco's r0kh line address)", sent[0][6:12])
	}
	// hostapd defers the first push and asks for the sequence
	var nonce [16]byte
	copy(nonce[:], bytes.Repeat([]byte{0xa0}, 16))
	q, err := mtkft.Seal(rg.key, decoNA, mtkft.SubSeqReq,
		[]mtkft.TLV{{Type: mtkft.TLVNonce, Data: nonce[:]}, {Type: mtkft.TLVR0KHID, Data: rg.na.R0KHID}, {Type: mtkft.TLVR1KHID, Data: decoNA[:]}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rg.r.onRRB("bdg2", ethFrame(garageNA, decoNA, mtkft.EtherTypeOUI, q))
	sent = rg.conn.take()
	if len(sent) != 1 {
		t.Fatalf("%d frames, want the SEQ_RESP", len(sent))
	}
	f = rg.openAt(sent[0], decoNA)
	if f.Subtype != mtkft.SubSeqResp {
		t.Fatalf("subtype %d", f.Subtype)
	}
	var gotNonce, seq []byte
	for _, v := range f.Auth {
		switch v.Type {
		case mtkft.TLVNonce:
			gotNonce = v.Data
		case mtkft.TLVSeq:
			seq = v.Data
		}
	}
	// the response's sequence follows the push's in the same domain, so
	// hostapd's reset accepts the deferred push
	if !bytes.Equal(gotNonce, nonce[:]) || len(seq) != 12 || binary.LittleEndian.Uint32(seq) != p.Seq.Dom ||
		binary.LittleEndian.Uint32(seq[4:]) != p.Seq.Seq+1 {
		t.Fatalf("seq resp nonce %x seq %x (push %+v)", gotNonce, seq, p.Seq)
	}
	// an FT-PSK initial association: the Decos derive it themselves
	rg.now = rg.now.Add(assocDedup)
	rg.r.onKDP("rai0", kdp(garageNA, mtkft.SigFTAssoc, 0, assocBody(testSTA)))
	tag = binary.LittleEndian.Uint32(rg.io.calls(mtkft.OIDKeyReq | mtkft.OIDSet)[1].buf)
	el.AKM = mtkft.AKMFTPSK
	body, _ = el.MarshalBinary()
	rg.r.onKDP("rai0", kdp(garageNA, mtkft.SigKeyRspAuto, tag, body))
	if s := rg.conn.take(); len(s) != 0 {
		t.Fatalf("FT-PSK pushed")
	}
}

// TestRoamJoinTrigger: without the driver's FT_ASSOCIATION (none came on
// the unit), a 4-way completion on an FT-SAE BSS sends the KEY_REQs a
// second later, once; the signal and the event of one join ask once; the
// R1KH entry is counted only when the driver answers.
func TestRoamJoinTrigger(t *testing.T) {
	rg := newRoamRig(t)
	reqs := func() int { return len(rg.io.calls(mtkft.OIDKeyReq | mtkft.OIDSet)) }
	rg.a.FTJoined("rai0", testSTA.String(), "")
	rg.a.FTJoined("ra0", testSTA.String(), garageNG.String()) // 2.4 GHz: the UDFT events do it
	rg.r.tick()
	if reqs() != 0 {
		t.Fatal("asked before joinWait")
	}
	rg.now = rg.now.Add(joinWait)
	rg.r.tick()
	if reqs() != 1 || rg.r.used["na"] != 0 {
		t.Fatalf("KEY_REQs %d used %d", reqs(), rg.r.used["na"])
	}
	// the driver's signal for the same join: no second request, counted once
	rg.r.onKDP("rai0", kdp(garageNA, mtkft.SigFTAssoc, 0, assocBody(testSTA)))
	rg.a.FTJoined("rai0", testSTA.String(), "")
	rg.now = rg.now.Add(joinWait)
	rg.r.tick()
	if reqs() != 1 || rg.r.used["na"] != 1 {
		t.Fatalf("KEY_REQs %d used %d", reqs(), rg.r.used["na"])
	}
	// a station without FT keys: no answer, nothing counted
	other := mtkft.MAC{0x02, 9, 9, 9, 9, 9}
	rg.a.FTJoined("rai1", other.String(), garageNA.String()) // reported on another netdev
	rg.now = rg.now.Add(joinWait)
	rg.r.tick()
	rg.now = rg.now.Add(keyReqTimeout + time.Second)
	rg.r.tick()
	if reqs() != 2 || rg.r.used["na"] != 1 || len(rg.r.keyReqs) != 0 {
		t.Fatalf("KEY_REQs %d used %d pending %d", reqs(), rg.r.used["na"], len(rg.r.keyReqs))
	}
	// an FT-PSK-only BSS: nothing to push, nothing asked
	rg.r.bss[0].FTSAE = false
	rg.a.FTJoined("rai0", mtkft.MAC{0x02, 8, 8, 8, 8, 8}.String(), "")
	rg.now = rg.now.Add(joinWait)
	rg.r.tick()
	if reqs() != 2 {
		t.Fatal("asked on an FT-PSK BSS")
	}
}

// decoPush is a Deco's hostapd pushing sta's PMK-R1 for the Garage BSS.
func (rg *roamRig) decoPush(from mtkft.MAC, to roamBSS, seq uint32) ([]byte, mtkft.PMKR1) {
	r0, r1 := hierarchy(rg.t, []byte(from.Hex()), to.BSSID)
	p := mtkft.Push{Seq: mtkft.Seq{Dom: 0x1001, Seq: seq, TS: 5}, R0KHID: []byte(from.Hex()), R1KHID: to.BSSID,
		S1KHID: testSTA, PMKR0Name: r0.Name, PMKR1: r1.Key, PMKR1Name: r1.Name, Pairwise: 0x10, ExpiresIn: 3600}
	out, err := mtkft.SealPush(rg.key, from, p)
	if err != nil {
		rg.t.Fatal(err)
	}
	return ethFrame(to.BSSID, from, mtkft.EtherTypeOUI, out), r1
}

// TestRoamFTSAEDecoToGarage: a Deco's PUSH is installed in the MT7663's
// R1KH table with KEY_RSP before the station roams; replays, other keys and
// strangers are not; a radio restart reinstalls it.
func TestRoamFTSAEDecoToGarage(t *testing.T) {
	rg := newRoamRig(t)
	frame, r1 := rg.decoPush(decoNA, rg.na, 7)
	rg.r.onRRB("bdg2", frame)
	ins := rg.io.calls(mtkft.OIDKeyRsp | mtkft.OIDSet)
	if len(ins) != 1 || ins[0].ifname != "rai0" {
		t.Fatalf("KEY_RSPs %+v", ins)
	}
	var e mtkft.KeyElement
	if err := e.UnmarshalBinary(ins[0].buf[12:]); err != nil {
		t.Fatal(err)
	}
	if e.R1KHID != garageNA || e.STA != testSTA || e.S1KHID != testSTA || e.PMKR1 != r1.Key || e.PMKR1Name != r1.Name ||
		e.AKM != mtkft.AKMFTSAE || e.Pairwise != mtkft.CipherCCMP || e.R0KHMAC != decoNA || string(e.R0KHID) != decoNA.Hex() ||
		e.KeyLifeTime != mtkft.DriverKeyLife || e.ReassocDeadline != reassocTU {
		t.Fatalf("installed %+v", e)
	}
	// the request the driver checks: PMKR1Name = f(PMKR0Name, its BSSID, STA)
	if mtkft.PMKR1Name(e.PMKR0Name, garageNA, testSTA) != e.PMKR1Name {
		t.Fatal("PMKR1Name the driver would not find")
	}
	if binary.LittleEndian.Uint32(ins[0].buf) == 0 {
		t.Fatal("KEY_RSP PeerIP 0")
	}
	// replayed: not installed again
	rg.r.onRRB("bdg2", frame)
	// sealed under another key
	other, _ := mtkft.RRBKey("202122232425262728292a2b2c2d2e2f")
	rg.key, other = other, rg.key
	bad, _ := rg.decoPush(decoNA, rg.na, 8)
	rg.key = other
	rg.r.onRRB("bdg2", bad)
	// from an address that is not the peer's
	stranger, _ := rg.decoPush(mtkft.MAC{0xa8, 0x42, 0xa1, 0, 0, 0x99}, rg.na, 9)
	rg.r.onRRB("bdg2", stranger)
	// for another AP
	elsewhere, _ := rg.decoPush(decoNA, roamBSS{BSSID: mtkft.MAC{2, 0, 0, 0, 0, 9}}, 10)
	rg.r.onRRB("bdg2", elsewhere)
	if n := len(rg.io.calls(mtkft.OIDKeyRsp | mtkft.OIDSet)); n != 1 {
		t.Fatalf("%d installs, want the first push only", n)
	}
	st := rg.a.RoamStats()
	if st["rrb-replayed"] != 1 || st["rrb-auth-failed"] != 1 || st["rrb-unknown-peer"] != 1 {
		t.Fatalf("stats %v", st)
	}
	// a radio restart empties the table: the SA goes in again
	rg.r.radioRestarted("na")
	rg.r.tick()
	if n := len(rg.io.calls(mtkft.OIDKeyRsp | mtkft.OIDSet)); n != 2 {
		t.Fatalf("%d installs after a restart, want 2", n)
	}
	rg.r.tick()
	if n := len(rg.io.calls(mtkft.OIDKeyRsp | mtkft.OIDSet)); n != 2 {
		t.Fatalf("installed twice in one radio start")
	}
	// expired: gone
	rg.now = rg.now.Add(2 * time.Hour)
	rg.r.radioRestarted("na")
	rg.r.tick()
	if n := len(rg.io.calls(mtkft.OIDKeyRsp | mtkft.OIDSet)); n != 2 || len(rg.r.sas) != 0 {
		t.Fatalf("expired SA installed (%d) or kept (%d)", n, len(rg.r.sas))
	}
}

// TestRoamSettleWait: an install inside a radio restart's settle time
// waits for it to end.
func TestRoamSettleWait(t *testing.T) {
	rg := newRoamRig(t)
	rg.a.quietFor(time.Hour)
	frame, _ := rg.decoPush(decoNA, rg.na, 1)
	rg.r.onRRB("bdg2", frame)
	if n := len(rg.io.calls(mtkft.OIDKeyRsp | mtkft.OIDSet)); n != 0 {
		t.Fatalf("installed inside a settle time")
	}
	rg.a.quietUntil.Store(0)
	rg.r.tick()
	if n := len(rg.io.calls(mtkft.OIDKeyRsp | mtkft.OIDSet)); n != 1 {
		t.Fatalf("%d installs after the settle time, want 1", n)
	}
}

// TestRoamBudget: the MT7663's 64-entry table is never overfilled; a
// station seen on this unit keeps the last entries.
func TestRoamBudget(t *testing.T) {
	rg := newRoamRig(t)
	rg.r.used["na"] = r1khBudget - r1khKnownFree
	frame, _ := rg.decoPush(decoNA, rg.na, 1)
	rg.r.onRRB("bdg2", frame)
	if n := len(rg.io.calls(mtkft.OIDKeyRsp | mtkft.OIDSet)); n != 0 {
		t.Fatalf("a stranger took one of the last entries")
	}
	rg.r.stas[testSTA] = rg.now
	rg.r.tick()
	if n := len(rg.io.calls(mtkft.OIDKeyRsp | mtkft.OIDSet)); n != 1 {
		t.Fatalf("a station seen here was not installed")
	}
	rg.r.used["na"] = r1khBudget
	rg.r.radioRestarted("ng") // another radio: nothing changes
	rg.r.gen["na"]++          // as if restarted, budget kept full
	rg.r.tick()
	if n := len(rg.io.calls(mtkft.OIDKeyRsp | mtkft.OIDSet)); n != 1 || !rg.r.full["na"] {
		t.Fatalf("installed beyond the budget")
	}
	s, _ := rg.a.SyncFTPeers(t.Context(), rg.a.desired)
	if len(s.Problems) != 1 || !strings.Contains(s.Problems[0], "na: the driver's R1KH table budget is used up") {
		t.Fatalf("problems %q", s.Problems)
	}
}

// TestRoamPullFromDeco: a Deco's PULL is answered from the MT7663 (KEY_REQ
// -> KEY_RSP_AUTO -> RESP) and from the MT7603 (R1_GET -> RESP); an
// unanswered one gets a "not found" RESP.
func TestRoamPullFromDeco(t *testing.T) {
	rg := newRoamRig(t)
	r0, r1 := hierarchy(t, rg.na.R0KHID, decoNA)
	var nonce [16]byte
	nonce[0] = 9
	pull := mtkft.Pull{Nonce: nonce, Seq: mtkft.Seq{Dom: 3, Seq: 1, TS: 1}, R0KHID: rg.na.R0KHID, R1KHID: decoNA,
		PMKR0Name: r0.Name, S1KHID: testSTA}
	out, _ := mtkft.SealPull(rg.key, decoNA, pull)
	rg.r.onRRB("bdg2", ethFrame(garageNA, decoNA, mtkft.EtherTypeOUI, out))
	reqs := rg.io.calls(mtkft.OIDKeyReq | mtkft.OIDSet)
	if len(reqs) != 1 {
		t.Fatalf("KEY_REQs %d", len(reqs))
	}
	el := mtkft.KeyElement{STA: testSTA, R0KHID: rg.na.R0KHID, PMKR0Name: r0.Name, R1KHID: decoNA, S1KHID: testSTA,
		PMKR1Name: r1.Name, PMKR1: r1.Key, Pairwise: mtkft.CipherCCMP, AKM: mtkft.AKMFTSAE, KeyLifeTime: 600}
	body, _ := el.MarshalBinary()
	rg.r.onKDP("rai0", kdp(garageNA, mtkft.SigKeyRspAuto, binary.LittleEndian.Uint32(reqs[0].buf), body))
	sent := rg.conn.take()
	if len(sent) != 1 {
		t.Fatalf("%d frames", len(sent))
	}
	resp, err := mtkft.ParseResp(rg.openAt(sent[0], decoNA))
	if err != nil || !resp.Found || resp.Nonce != nonce || resp.PMKR1 != r1.Key || resp.PMKR1Name != r1.Name || resp.S1KHID != testSTA {
		t.Fatalf("resp %+v %v", resp, err)
	}
	// no answer from the driver (the station left): "not found" after the timeout
	pull.Seq.Seq, pull.Nonce[0] = 2, 10
	out, _ = mtkft.SealPull(rg.key, decoNA, pull)
	rg.r.onRRB("bdg2", ethFrame(garageNA, decoNA, mtkft.EtherTypeOUI, out))
	rg.now = rg.now.Add(3 * time.Second)
	rg.r.tick()
	sent = rg.conn.take()
	if len(sent) != 1 {
		t.Fatalf("%d frames after the timeout", len(sent))
	}
	if resp, err := mtkft.ParseResp(rg.openAt(sent[0], decoNA)); err != nil || resp.Found || resp.Nonce[0] != 10 {
		t.Fatalf("timeout resp %+v %v", resp, err)
	}
	// 2.4 GHz: R1_GET
	r0g, r1g := hierarchy(t, rg.ng.R0KHID, decoNG)
	rg.io.reply = func(ifname string, flags uint16, buf []byte) (int, error) {
		if flags == mtkft.OIDUDFTR1Get {
			rec := mtkft.UDFTR1{NameGiven: true, STA: testSTA, R1KHID: decoNG, R0KHID: rg.ng.R0KHID, PMKR0Name: r0g.Name,
				PMKR1Name: r1g.Name, PMKR1: r1g.Key, Pairwise: mtkft.CipherCCMP, Lifetime: 500}
			b, _ := rec.MarshalBinary()
			copy(buf, b)
		}
		return len(buf), nil
	}
	pg := mtkft.Pull{Nonce: nonce, Seq: mtkft.Seq{Dom: 4, Seq: 1, TS: 1}, R0KHID: rg.ng.R0KHID, R1KHID: decoNG, PMKR0Name: r0g.Name, S1KHID: testSTA}
	out, _ = mtkft.SealPull(rg.key, decoNG, pg)
	rg.r.onRRB("bdg2", ethFrame(garageNG, decoNG, mtkft.EtherTypeOUI, out))
	sent = rg.conn.take()
	if len(sent) != 1 {
		t.Fatalf("%d frames (2.4 GHz)", len(sent))
	}
	if resp, err := mtkft.ParseResp(rg.openAt(sent[0], decoNG)); err != nil || !resp.Found || resp.PMKR1 != r1g.Key {
		t.Fatalf("2.4 GHz resp %+v %v", resp, err)
	}
	if g := rg.io.calls(mtkft.OIDUDFTR1Get); len(g) != 1 || g[0].ifname != "ra0" || g[0].buf[10] != decoNG[0] {
		t.Fatalf("R1_GET %+v", g)
	}
}

func udftEvent(typ byte, seq uint32, sta, bssid mtkft.MAC, r0kh []byte, r0name, r1name [16]byte) []byte {
	b := make([]byte, mtkft.UDFTEventLen)
	b[0], b[1], b[2] = 1, typ, byte(len(r0kh))
	copy(b[4:], sta[:])
	copy(b[10:], bssid[:])
	copy(b[16:], r0kh)
	copy(b[64:], r0name[:])
	copy(b[80:], r1name[:])
	copy(b[96:], mtkft.AKMFTSAE[:])
	binary.LittleEndian.PutUint32(b[100:], seq)
	return b
}

// TestRoam2GPushAndPull: the MT7603's R0_CREATED becomes a PUSH (R1_GET
// per Deco R1KH); its R1_MISS a PULL to the station's R0KH, whose RESP is
// installed with R1_SET.
func TestRoam2GPushAndPull(t *testing.T) {
	rg := newRoamRig(t)
	r0, r1 := hierarchy(t, rg.ng.R0KHID, decoNG)
	var queue []byte
	rg.io.reply = func(ifname string, flags uint16, buf []byte) (int, error) {
		switch flags {
		case mtkft.OIDUDFTEvents:
			n := copy(buf, queue)
			queue = nil
			return n, nil
		case mtkft.OIDUDFTR1Get:
			rec := mtkft.UDFTR1{NameGiven: true, STA: testSTA, R1KHID: decoNG, R0KHID: rg.ng.R0KHID, PMKR0Name: r0.Name,
				PMKR1Name: r1.Name, PMKR1: r1.Key, Pairwise: mtkft.CipherCCMP, Lifetime: 500}
			b, _ := rec.MarshalBinary()
			copy(buf, b)
		}
		return len(buf), nil
	}
	queue = udftEvent(mtkft.UDFTR0Created, 1, testSTA, garageNG, rg.ng.R0KHID, r0.Name, [16]byte{})
	rg.a.FTEvent("ra0", mtkft.OIDUDFTEvents, queue)
	sent := rg.conn.take()
	if len(sent) != 1 {
		t.Fatalf("%d frames, want a PUSH", len(sent))
	}
	p, err := mtkft.ParsePush(rg.openAt(sent[0], decoNG))
	if err != nil || p.PMKR1 != r1.Key || p.R1KHID != decoNG || !bytes.Equal(p.R0KHID, rg.ng.R0KHID) {
		t.Fatalf("push %+v %v", p, err)
	}
	// a station that SAE'd at the Deco roams here and its key was not pushed
	dr0, dr1 := hierarchy(t, []byte(decoNG.Hex()), garageNG)
	queue = udftEvent(mtkft.UDFTR1Miss, 2, testSTA, garageNG, []byte(decoNG.Hex()), dr0.Name, dr1.Name)
	rg.a.FTEvent("ra0", mtkft.OIDUDFTEvents, queue)
	sent = rg.conn.take()
	if len(sent) != 1 {
		t.Fatalf("%d frames, want a PULL", len(sent))
	}
	pl, err := mtkft.ParsePull(rg.openAt(sent[0], decoNG))
	if err != nil || pl.R1KHID != garageNG || pl.S1KHID != testSTA || pl.PMKR0Name != dr0.Name || string(pl.R0KHID) != decoNG.Hex() {
		t.Fatalf("pull %+v %v", pl, err)
	}
	// the Deco answers (after its SEQ_REQ, which the first test covers)
	resp := mtkft.Resp{Nonce: pl.Nonce, Seq: mtkft.Seq{Dom: 5, Seq: 1, TS: 1}, R0KHID: pl.R0KHID, R1KHID: garageNG,
		S1KHID: testSTA, Found: true, PMKR1: dr1.Key, PMKR1Name: dr1.Name, Pairwise: 0x10, ExpiresIn: 100}
	out, _ := mtkft.SealResp(rg.key, decoNG, resp)
	rg.r.onRRB("bdg2", ethFrame(garageNG, decoNG, mtkft.EtherTypeOUI, out))
	sets := rg.io.calls(mtkft.OIDUDFTR1Set | mtkft.OIDSet)
	if len(sets) != 1 || sets[0].ifname != "ra0" {
		t.Fatalf("R1_SETs %+v", sets)
	}
	var rec mtkft.UDFTR1
	if err := rec.UnmarshalBinary(sets[0].buf); err != nil || rec.R1KHID != garageNG || rec.PMKR1 != dr1.Key ||
		rec.PMKR1Name != dr1.Name || !rec.NameGiven || rec.AKM != mtkft.AKMFTSAE || string(rec.R0KHID) != decoNG.Hex() {
		t.Fatalf("R1_SET %+v %v", rec, err)
	}
	// the same response again: no pull waits for it
	rg.r.onRRB("bdg2", ethFrame(garageNG, decoNG, mtkft.EtherTypeOUI, out))
	if n := len(rg.io.calls(mtkft.OIDUDFTR1Set | mtkft.OIDSet)); n != 1 {
		t.Fatalf("an unasked response installed")
	}
}

// TestRoamHandBack: nothing is kept or answered after the hand-back.
func TestRoamHandBack(t *testing.T) {
	rg := newRoamRig(t)
	frame, _ := rg.decoPush(decoNA, rg.na, 1)
	rg.r.onRRB("bdg2", frame)
	rg.r.handBack()
	if len(rg.r.sas) != 0 || len(rg.r.bss) != 0 {
		t.Fatal("state kept")
	}
	frame, _ = rg.decoPush(decoNA, rg.na, 2)
	rg.r.onRRB("bdg2", frame)
	if n := len(rg.io.calls(mtkft.OIDKeyRsp | mtkft.OIDSet)); n != 1 {
		t.Fatalf("installed after the hand-back")
	}
}

// TestFTLocals: the Garage announces its FT-SAE holders with the R0KH-ID
// its driver puts in the FTIE; ftpeer accepts them.
func TestFTLocals(t *testing.T) {
	rg := newRoamRig(t)
	if !rg.a.ServesFTSAE() {
		t.Fatal("FT-SAE not served")
	}
	n := New(Options{Root: t.TempDir(), FTSAE: true, WPA3: true})
	if n.ServesFTSAE() || n.ServesRoaming() {
		t.Fatal("served without ft")
	}
}

// TestEventsJoined: both 4-way completion sources reach the roaming
// trigger, with the BSSID when the event has one; other steps do not.
func TestEventsJoined(t *testing.T) {
	var got []string
	m := NewEvents(EventsOptions{Joined: func(ifc, mac, bssid string) { got = append(got, ifc+" "+mac+" "+bssid) }})
	sta := "a6:7b:63:9f:25:40"
	m.handle(DrvEvent{Kind: DrvAssoc, Ifname: "rai0", MAC: sta})
	m.handle(DrvEvent{Kind: DrvKeyDone, Ifname: "rai0", MAC: sta})
	m.handle(DrvEvent{Kind: DrvAuthorized, Ifname: "rai1", MAC: sta, BSSID: "b4:a7:c6:a9:f4:f5"})
	if strings.Join(got, "|") != "rai0 "+sta+" |rai1 "+sta+" b4:a7:c6:a9:f4:f5" {
		t.Fatalf("%q", got)
	}
}

// TestRoamFTPSKPreinstall: a station that joined the Garage's 5 GHz with
// FT-PSK (the driver's KEY_RSP_AUTO for the join says so), and one refused
// with KEY_REQ_AUTO, get the FT-PSK PMK-R1 the driver needs for a roam
// from each same-WLAN Deco: hostapd's wpa_ft_psk_pmk_r1 with the Deco's
// R0KH-ID, installed with KEY_RSP as AKM 00-0F-AC-04. An SAE station gets
// none.
func TestRoamFTPSKPreinstall(t *testing.T) {
	rg := newRoamRig(t)
	psk, err := mtkft.PSK("secret-home", []byte("home"))
	if err != nil {
		t.Fatal(err)
	}
	rg.r.bss[0].psk, rg.r.bss[0].hasPSK = psk, true
	installs := func() []mtkft.KeyElement {
		var out []mtkft.KeyElement
		for _, c := range rg.io.calls(mtkft.OIDKeyRsp | mtkft.OIDSet) {
			var e mtkft.KeyElement
			if err := e.UnmarshalBinary(c.buf[12:]); err != nil {
				t.Fatal(err)
			}
			out = append(out, e)
		}
		return out
	}
	// the join: KEY_REQ a second later, answered as FT-PSK (as on the unit)
	answer := func(sta mtkft.MAC, akm mtkft.Suite) {
		rg.a.FTJoined("rai1", sta.String(), "")
		rg.now = rg.now.Add(joinWait)
		rg.r.tick()
		reqs := rg.io.calls(mtkft.OIDKeyReq | mtkft.OIDSet)
		tag := binary.LittleEndian.Uint32(reqs[len(reqs)-1].buf)
		el := mtkft.KeyElement{STA: sta, R0KHID: rg.na.R0KHID, R1KHID: decoNA, AKM: akm, Pairwise: mtkft.CipherCCMP}
		r0, r1 := hierarchy(t, rg.na.R0KHID, decoNA)
		el.PMKR0Name, el.PMKR1 = r0.Name, r1.Key
		el.PMKR1Name = mtkft.PMKR1Name(r0.Name, decoNA, sta)
		body, _ := el.MarshalBinary()
		rg.r.onKDP("rai0", kdp(garageNA, mtkft.SigKeyRspAuto, tag, body))
	}
	answer(mtkft.MAC{0x02, 5, 5, 5, 5, 5}, mtkft.AKMFTSAE)
	if n := len(installs()); n != 0 {
		t.Fatalf("%d FT-PSK installs for an SAE station", n)
	}
	rg.conn.take()
	answer(testSTA, mtkft.AKMFTPSK)
	ins := installs()
	if len(ins) != 1 { // the one same-WLAN Deco R0KH in the domain (not the other key's)
		t.Fatalf("%d installs", len(ins))
	}
	if s := rg.conn.take(); len(s) != 0 {
		t.Fatal("FT-PSK pushed")
	}
	e := ins[0]
	r0, r1, _ := mtkft.FTPSKR1(psk, []byte("home"), 0xd530, []byte(decoNA.Hex()), testSTA, garageNA)
	if e.AKM != mtkft.AKMFTPSK || e.PMKR1 != r1.Key || e.PMKR1Name != r1.Name || e.PMKR0Name != r0.Name ||
		string(e.R0KHID) != decoNA.Hex() || e.R0KHMAC != decoNA || e.R1KHID != garageNA || e.Pairwise != mtkft.CipherCCMP {
		t.Fatalf("installed %+v", e)
	}
	// the same station again: kept SAs refreshed, not installed twice
	n := len(ins)
	rg.now = rg.now.Add(assocDedup)
	answer(testSTA, mtkft.AKMFTPSK)
	if len(installs()) != n {
		t.Fatal("installed twice")
	}
	// a radio restart: reinstalled
	rg.r.radioRestarted("na")
	rg.r.tick()
	if len(installs()) != 2*n {
		t.Fatalf("%d installs after a restart", len(installs()))
	}
	// KEY_REQ_AUTO for a new station: FT-PSK installed; an FT-SAE miss is not
	other := mtkft.MAC{0x02, 7, 7, 7, 7, 7}
	miss := mtkft.KeyElement{STA: other, R1KHID: garageNA}
	body, _ := miss.MarshalBinary()
	rg.r.onKDP("rai0", kdp(garageNA, mtkft.SigKeyReqAuto, 0, body))
	if len(installs()) != 3*n {
		t.Fatalf("%d installs after KEY_REQ_AUTO", len(installs()))
	}
	miss.STA, miss.AKM = mtkft.MAC{0x02, 6, 6, 6, 6, 6}, mtkft.AKMFTSAE
	body, _ = miss.MarshalBinary()
	rg.r.onKDP("rai0", kdp(garageNA, mtkft.SigKeyReqAuto, 0, body))
	if len(installs()) != 3*n {
		t.Fatal("FT-PSK installed for an FT-SAE miss")
	}
}
