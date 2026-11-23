// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/mtkft"
)

// btmRun answers iwconfig with a channel per radio and fails BtmReq for
// the station noBTM (the module's EINVAL).
type btmRun struct {
	log   []string
	noBTM string
}

func (b *btmRun) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	b.log = append(b.log, cmd)
	switch {
	case name == "iwconfig" && strings.HasPrefix(args[0], "rai"):
		return []byte(`rai0  ESSID:"home"  Channel=149`), nil
	case name == "iwconfig":
		return []byte(`ra0  ESSID:"home"  Channel=6`), nil
	case b.noBTM != "" && strings.Contains(cmd, "BtmReq="+b.noBTM):
		return []byte("Interface doesn't accept private ioctl...\nset (8BE2): Invalid argument"), errors.New("exit status 255")
	}
	return nil, nil
}

func btmRig(t *testing.T) (*roamRig, *btmRun) {
	rg := newRoamRig(t)
	run := &btmRun{}
	rg.a.o.Run = run
	rg.a.live = map[string]RadioPlan{"na": {On: true}, "ng": {On: true}}
	rg.r.bss[0].BTM, rg.r.bss[1].BTM = true, true
	return rg, run
}

// TestSteerToBand: a steer to this unit's other band is one BTM request
// with that BSS as the candidate: the MT7663's OID (no disassociation
// imminent), the MT7603 module's BtmReq; EINVAL is ErrNoBTM.
func TestSteerToBand(t *testing.T) {
	rg, run := btmRig(t)
	ctx := context.Background()
	if err := rg.a.SteerToBand(ctx, "rai0", testSTA.String(), garageNG.String()); err != nil {
		t.Fatal(err)
	}
	reqs := rg.io.calls(mtkft.OIDWNMBTMReq | mtkft.OIDSet)
	if len(reqs) != 1 || reqs[0].ifname != "rai0" {
		t.Fatalf("BTM OIDs %+v", reqs)
	}
	b := reqs[0].buf
	if !bytesEq(b[4:10], testSTA[:]) || int(binary.LittleEndian.Uint32(b[10:])) != len(b)-14 {
		t.Fatalf("btm_req_data %x", b)
	}
	body := b[14:]
	// mode: preferred list + abridged, never disassociation imminent; timer 0
	if body[0] != mtkft.BTMPrefListIncluded|mtkft.BTMAbridged || binary.LittleEndian.Uint16(body[1:]) != 0 {
		t.Fatalf("mode %x", body[:4])
	}
	nr := body[4:]
	if nr[0] != 52 || !bytesEq(nr[2:8], garageNG[:]) || nr[12] != 81 || nr[13] != 6 || nr[14] != 7 {
		t.Fatalf("candidate %x", nr)
	}
	if info := binary.LittleEndian.Uint32(nr[8:]); info&mtkft.BSSIDMobilityDom == 0 {
		t.Fatalf("info %x", info)
	}
	// 2.4 GHz to 5 GHz: the module's BtmReq, one candidate
	if err := rg.a.SteerToBand(ctx, "ra0", testSTA.String(), garageNA.String()); err != nil {
		t.Fatal(err)
	}
	if j := strings.Join(run.log, "\n"); !strings.Contains(j, "iwpriv ra0 set BtmReq="+testSTA.String()+","+garageNA.String()+",149") {
		t.Fatalf("log %q", run.log)
	}
	run.noBTM = testSTA.String()
	if err := rg.a.SteerToBand(ctx, "ra0", testSTA.String(), garageNA.String()); !errors.Is(err, bcmwifi.ErrNoBTM) {
		t.Fatalf("EINVAL: %v", err)
	}
	// not one of ours, the same BSS, 802.11v off
	if err := rg.a.SteerToBand(ctx, "rai0", testSTA.String(), decoNA.String()); err == nil {
		t.Fatal("steered to a Deco")
	}
	if err := rg.a.SteerToBand(ctx, "rai0", testSTA.String(), garageNA.String()); err == nil {
		t.Fatal("steered to its own BSS")
	}
	rg.r.bss[0].BTM = false
	if err := rg.a.SteerToBand(ctx, "rai0", testSTA.String(), garageNG.String()); !errors.Is(err, errBTMOff) {
		t.Fatalf("BTM off: %v", err)
	}
}

// TestRoamAssistGarage: the candidates are the Decos (never this unit's
// BSSes), ranked; the 5 GHz request carries no disassociation timer, the
// 2.4 GHz one the first candidate and the timer.
func TestRoamAssistGarage(t *testing.T) {
	rg, run := btmRig(t)
	ctx := context.Background()
	req := bcmwifi.RoamRequest{Vif: "rai0", MAC: testSTA.String(), DisassocTBTT: 30, Candidates: []bcmwifi.Neighbor{
		{BSSID: garageNG.String(), Band: "ng", Channel: 6}, // this unit: skipped
		{BSSID: decoNA.String(), Band: "na", Channel: 44},
		{BSSID: "a8:42:a1:00:00:30", Band: "na", Channel: 149},
	}}
	if err := rg.a.RoamAssist(ctx, req); err != nil {
		t.Fatal(err)
	}
	reqs := rg.io.calls(mtkft.OIDWNMBTMReq | mtkft.OIDSet)
	if len(reqs) != 1 {
		t.Fatalf("%d requests", len(reqs))
	}
	body := reqs[0].buf[14:]
	if body[0]&mtkft.BTMDisassocImminent != 0 || binary.LittleEndian.Uint16(body[1:]) != 0 {
		t.Fatalf("5 GHz request with a disassociation timer: %x", body[:4])
	}
	nr := body[4:]
	// two candidates of 18 octets (with the preference subelement), the
	// same-domain Deco first with the mobility-domain bit, op class 115
	if len(nr) != 36 || !bytesEq(nr[2:8], decoNA[:]) || nr[12] != 115 || nr[13] != 44 || nr[17] != 255 || nr[35] != 254 {
		t.Fatalf("candidates %x", nr)
	}
	if binary.LittleEndian.Uint32(nr[8:])&mtkft.BSSIDMobilityDom == 0 || binary.LittleEndian.Uint32(nr[26:])&mtkft.BSSIDMobilityDom != 0 {
		t.Fatalf("mobility-domain bits %x %x", nr[8:12], nr[26:30])
	}
	req.Vif = "ra0"
	if err := rg.a.RoamAssist(ctx, req); err != nil {
		t.Fatal(err)
	}
	if j := strings.Join(run.log, "\n"); !strings.Contains(j, "iwpriv ra0 set BtmReq="+testSTA.String()+","+decoNA.String()+",44,30") {
		t.Fatalf("log %q", run.log)
	}
	req.Candidates = req.Candidates[:1]
	if err := rg.a.RoamAssist(ctx, req); !errors.Is(err, bcmwifi.ErrNoCandidate) {
		t.Fatalf("own BSS only: %v", err)
	}
	// without ft: nothing is served
	n := New(Options{Root: t.TempDir()})
	if err := n.RoamAssist(ctx, req); err == nil {
		t.Fatal("served without ft")
	}
}

// TestRRMEventsCounted: BTM responses reach RoamStats.
func TestRRMEventsCounted(t *testing.T) {
	rg := newRoamRig(t)
	ev := make([]byte, 4+6+4+8)
	copy(ev[4:], testSTA[:])
	binary.LittleEndian.PutUint32(ev[10:], 8)
	ev[14] = 0 // accept
	copy(ev[16:], decoNA[:])
	rg.a.FTEvent("rai0", mtkft.EvBTMRsp, ev)
	if st := rg.a.RoamStats(); st["btm-accept"] != 1 {
		t.Fatalf("stats %v", st)
	}
}

func bytesEq(a, b []byte) bool { return string(a) == string(b) }
