// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// staInfoRun answers `wl -i <vif> sta_info <mac>` from the given outputs
// (real `wl sta_info` captures from .205) and passes everything else to
// the fake device.
type staInfoRun struct {
	*fakeDev
	out map[string]string // MAC as passed -> output
}

func (r staInfoRun) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "wl" && len(args) == 4 && args[2] == "sta_info" {
		r.fakeDev.mu.Lock()
		r.fakeDev.calls = append(r.fakeDev.calls, append([]string{name}, args...))
		r.fakeDev.mu.Unlock()
		if o, ok := r.out[args[3]]; ok {
			return []byte(o), nil
		}
		return []byte("wl: STA not found\n"), errors.New("exit status 1")
	}
	return r.fakeDev.Run(ctx, name, args...)
}

func wlFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "wl", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const (
	staBTMOK = "02:00:00:00:00:b1" // advertises BSS transition (wnm 0x21)
	staNoBTM = "02:00:00:00:00:b2" // does not (wnm 0x0)
)

func TestRoamAssist(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	a.o.Run = staInfoRun{f, map[string]string{
		staBTMOK: wlFixture(t, "wl_-i_wl12_sta_info_88571DBBBB86.txt"),
		staNoBTM: wlFixture(t, "wl_-i_wl02_sta_info_8CBFEA1DBA74.txt"),
	}}
	cand := []Neighbor{{BSSID: "02:00:00:00:77:01", Band: "ng", Channel: 6}}
	if err := a.RoamAssist(ctx, RoamRequest{Vif: "wl12", MAC: staBTMOK, Candidates: cand, DisassocTBTT: 100}); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("before takeover: %v", err)
	}
	applyOK(t, a, twoSSIDs())
	ng, err := a.bssid(ctx, "wl02") // the same SSID's 2.4 GHz BSS
	if err != nil {
		t.Fatal(err)
	}
	own, _ := a.bssid(ctx, "wl12")
	f.reset()
	req := RoamRequest{Vif: "wl12", MAC: strings.ToUpper(staBTMOK), DisassocTBTT: 100, Candidates: []Neighbor{
		{BSSID: own, Band: "na", Channel: 44},                  // the station's own BSS: left out
		{BSSID: strings.ToUpper(ng), Band: "ng", Channel: 6},   // this AP's 2.4 GHz BSS: left out (live bug 2026-11-19)
		{BSSID: laa(ng), Band: "ng", Channel: 6},               // the same with another first octet: left out
		{BSSID: "02:00:00:00:77:02", Band: "na", Channel: 149}, // a sibling AP heard by a scan
		{BSSID: "junk", Band: "na", Channel: 36},               // bad: left out
		{BSSID: "02:00:00:00:77:03", Band: "6e", Channel: 37},  // no such radio here: left out
	}}
	if err := a.RoamAssist(ctx, req); err != nil {
		t.Fatal(err)
	}
	// channel 149: operating class 124 (rf.OpClass, Table E-4)
	want := "hostapd_cli -p /var/run/udeco-hostapd -i wl12 bss_tm_req " + staBTMOK +
		" disassoc_imminent=1 disassoc_timer=100 pref=1 abridged=1" +
		" neighbor=02:00:00:00:77:02,6319,124,149,9"
	if !f.called(want) {
		t.Errorf("missing %q in %v", want, f.mutating())
	}

	// No disassociation timer: no Disassociation Imminent either.
	f.reset()
	req.DisassocTBTT = 0
	if err := a.RoamAssist(ctx, req); err != nil {
		t.Fatal(err)
	}
	if f.called("disassoc") {
		t.Errorf("timer 0 sent a disassociation: %v", f.mutating())
	}

	// Guards: never a bare kick.
	f.reset()
	for _, c := range []struct {
		name string
		r    RoamRequest
		want error
	}{
		{"station without BTM", RoamRequest{Vif: "wl02", MAC: staNoBTM, Candidates: cand, DisassocTBTT: 100}, ErrNoBTM},
		{"no candidate", RoamRequest{Vif: "wl12", MAC: staBTMOK, DisassocTBTT: 100}, ErrNoCandidate},
		{"only its own BSS", RoamRequest{Vif: "wl12", MAC: staBTMOK, Candidates: []Neighbor{{BSSID: own, Band: "na", Channel: 44}}}, ErrNoCandidate},
		{"only this AP's BSSes", RoamRequest{Vif: "wl12", MAC: staBTMOK, Candidates: []Neighbor{
			{BSSID: own, Band: "na", Channel: 44}, {BSSID: ng, Band: "ng", Channel: 6}}}, ErrNoCandidate},
	} {
		if err := a.RoamAssist(ctx, c.r); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	for _, c := range []RoamRequest{
		{Vif: "wl02", MAC: "02:00:00:00:00:b3", Candidates: cand},                         // not associated: sta_info fails
		{Vif: "wl05", MAC: staBTMOK, Candidates: cand},                                    // not served
		{Vif: "wl12", MAC: "x", Candidates: cand},                                         // bad MAC
		{Vif: "wl12", MAC: staBTMOK, Candidates: cand, DisassocTBTT: maxDisassocTBTT + 1}, // timer out of range
	} {
		if err := a.RoamAssist(ctx, c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	if f.called("bss_tm_req") {
		t.Errorf("a refused request reached hostapd: %v", f.mutating())
	}

	// A served BSS whose BSSID cannot be read might be the candidate:
	// no request at all rather than one that may name this AP.
	f.write(CtrlDir+"/wl17", "") // its socket, no netdev, no BSSID on record
	f.reset()
	if err := a.RoamAssist(ctx, RoamRequest{Vif: "wl12", MAC: staBTMOK, Candidates: []Neighbor{
		{BSSID: "02:00:00:00:77:02", Band: "na", Channel: 149}}, DisassocTBTT: 100}); err == nil {
		t.Errorf("sent with a served BSS's BSSID unknown")
	}
	if f.called("bss_tm_req") {
		t.Errorf("a request reached hostapd with a served BSS's BSSID unknown: %v", f.mutating())
	}
}

func TestStaBTM(t *testing.T) {
	for name, want := range map[string]bool{
		"wl_-i_wl12_sta_info_88571DBBBB86.txt": true,  // 0x21
		"wl_-i_wl12_sta_info_A67B639F2540.txt": true,  // 0x1
		"wl_-i_wl12_sta_info_D2F7E5586F89.txt": true,  // 0x101
		"wl_-i_wl02_sta_info_8CBFEA1DBA74.txt": false, // 0x0
		"wl_-i_wl02_sta_info_F4CFA21E7264.txt": false, // 0x0
	} {
		if got := staBTM(wlFixture(t, name)); got != want {
			t.Errorf("%s: %t", name, got)
		}
	}
	for _, s := range []string{"", "wnm", "wnm\n", "wnm\nzz:", "flags 0x1"} {
		if staBTM(s) {
			t.Errorf("%q: BTM", s)
		}
	}
}

// laa is a BSSID with another first octet (the X20 derives its BSSIDs as
// such variants of one address).
func laa(b string) string {
	if b[:2] == "a2" {
		return "b2" + b[2:]
	}
	return "a2" + b[2:]
}
