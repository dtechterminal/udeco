// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"testing"
	"time"
)

// The MT7663's system log events (IWEVCUSTOM on rai0, the event flag as
// flags, "STA(<mac>) <text>" as data, as mt_wifi's RtmpDrvSendWirelessEvent
// formats it) are the join steps; other flags and texts without a station
// are not.
func TestParseSysLogEvents(t *testing.T) {
	sta := "a6:7b:63:9f:25:40"
	for flags, want := range map[uint16]DrvKind{0x200: DrvAssoc, 0x207: DrvMICDiff, 0x20B: DrvHSTimeout, 0x20D: DrvKeyDone, 0x20E: DrvKeyDone} {
		text := map[uint16]string{0x200: "had associated successfully", 0x207: "occurred MIC different in Key Handshaking",
			0x20B: "Pairwise Key Handshaking timeout", 0x20D: "set key done in WPA/WPAPSK", 0x20E: "set key done in WPA2/WPA2PSK"}[flags]
		evs := parseRTNL(rtnlFrame("rai0", 12, flags, []byte("STA(A6:7B:63:9F:25:40) "+text+"\x00")))
		if len(evs) != 1 || evs[0].Kind != want || evs[0].MAC != sta || evs[0].Ifname != "rai0" {
			t.Errorf("flags %#x: %+v", flags, evs)
		}
	}
	for _, f := range []struct {
		flags uint16
		data  string
	}{{0x201, "STA(a6:7b:63:9f:25:40) had disassociated"}, {0x200, "BSS(ra0) had associated successfully"},
		{0x20E, "STA(a6:7b:63:9f:25) set key done"}, {0x211, "scan completed"}} {
		if evs := parseRTNL(rtnlFrame("rai0", 12, f.flags, []byte(f.data))); len(evs) != 0 {
			t.Errorf("%#x %q: %+v", f.flags, f.data, evs)
		}
	}
}

// Steps: every join step is passed as it arrives, an authorization once
// when the WAPP event and the system log both report it, an ECNT failure
// the system log reported already not again (and the reverse), a source's
// own repeats (retried handshake messages) each; leaves are no steps.
func TestEventsSteps(t *testing.T) {
	ck := &evClock{t: time.Unix(1_800_000_000, 0)}
	var got []DrvEvent
	m := NewEvents(EventsOptions{Now: ck.now, Steps: func(e DrvEvent) { got = append(got, e) }})
	sta := "a6:7b:63:9f:25:40"
	m.handle(DrvEvent{Kind: DrvInsert, Ifname: "rai1", MAC: sta})
	ck.t = ck.t.Add(10 * time.Millisecond)
	m.handle(DrvEvent{Kind: DrvAssoc, Ifname: "rai0", MAC: sta})
	ck.t = ck.t.Add(10 * time.Millisecond)
	m.handle(DrvEvent{Kind: DrvMICDiff, Ifname: "rai0", MAC: sta})
	m.handle(DrvEvent{Kind: DrvFailure, Ifname: "rai1", MAC: sta, Reason: 14}) // the same mismatch from ECNT
	ck.t = ck.t.Add(time.Second)
	m.handle(DrvEvent{Kind: DrvMICDiff, Ifname: "rai0", MAC: sta}) // a retried message 2
	m.handle(DrvEvent{Kind: DrvFailure, Ifname: "rai1", MAC: sta, Reason: 3})
	ck.t = ck.t.Add(100 * time.Millisecond)
	m.handle(DrvEvent{Kind: DrvKeyDone, Ifname: "rai0", MAC: sta})
	m.handle(DrvEvent{Kind: DrvAuthorized, Ifname: "rai1", MAC: sta}) // WAPP's report of the same
	m.handle(DrvEvent{Kind: DrvDelete, Ifname: "rai1", MAC: sta})
	var kinds []DrvKind
	for _, e := range got {
		kinds = append(kinds, e.Kind)
		if e.At.IsZero() {
			t.Errorf("step %+v without a time", e)
		}
	}
	want := []DrvKind{DrvInsert, DrvAssoc, DrvMICDiff, DrvMICDiff, DrvKeyDone}
	if len(kinds) != len(want) {
		t.Fatalf("steps %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Errorf("steps %v, want %v", kinds, want)
		}
	}
	// an ECNT timeout first: the system log's report of it is the same step
	got = nil
	ck.t = ck.t.Add(time.Minute)
	m.handle(DrvEvent{Kind: DrvFailure, Ifname: "rai1", MAC: sta, Reason: 15})
	m.handle(DrvEvent{Kind: DrvHSTimeout, Ifname: "rai0", MAC: sta})
	if len(got) != 1 || got[0].Kind != DrvFailure {
		t.Errorf("timeout steps %+v", got)
	}
	// after dedupWindow a new authorization passes again
	got = nil
	ck.t = ck.t.Add(dedupWindow)
	m.handle(DrvEvent{Kind: DrvAuthorized, Ifname: "rai1", MAC: sta})
	if len(got) != 1 {
		t.Errorf("a later authorization: %+v", got)
	}
}
