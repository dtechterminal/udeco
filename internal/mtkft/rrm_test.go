// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// rrm_command_t {u8 id, u32 len LE (unaligned), body}; rrm_MsgHandle
// checks len == 1 for command 1.
func TestRRMCommands(t *testing.T) {
	for _, c := range []struct {
		r    Request
		want []byte
	}{
		{RRMEnable(true), []byte{1, 1, 0, 0, 0, 1}},
		{NRByDaemon(true), []byte{8, 1, 0, 0, 0, 1}},
		{NRByDaemon(false), []byte{8, 1, 0, 0, 0, 0}},
	} {
		if c.r.Flags != OIDRRMCommand|OIDSet || !bytes.Equal(c.r.Buf, c.want) {
			t.Errorf("%#x % x, want % x", c.r.Flags, c.r.Buf, c.want)
		}
	}
}

// nr_rsp_data_t {u32 ifindex, u8 dialog_token, peer[6], u32 nr_rsp_len,
// nr_rsp}: rrm_send_nr_rsp_ie needs command_len == nr_rsp_len + 0xf.
func TestNRResponse(t *testing.T) {
	peer := mustMAC(t, "02:11:22:33:44:55")
	ies := NeighborReport{
		BSSID: mustMAC(t, "a8:42:a1:00:00:03"), Info: BSSIDReachable | BSSIDSecurity | BSSIDKeyScope | BSSIDMobilityDom,
		OpClass: 125, Channel: 149, PHYType: 9,
	}.Append(nil)
	if len(ies) != 15 || ies[0] != 52 || ies[1] != 13 {
		t.Fatalf("element % x", ies)
	}
	if binary.LittleEndian.Uint32(ies[8:]) != 0x40f {
		t.Errorf("BSSID info % x", ies[8:12])
	}
	r, err := NRResponse(7, peer, ies)
	if err != nil {
		t.Fatal(err)
	}
	b := r.Buf
	if b[0] != 6 || binary.LittleEndian.Uint32(b[1:]) != uint32(len(b)-5) {
		t.Fatalf("header % x", b[:5])
	}
	body := b[5:]
	if body[4] != 7 || !bytes.Equal(body[5:11], peer[:]) || binary.LittleEndian.Uint32(body[0xb:]) != uint32(len(ies)) ||
		!bytes.Equal(body[0xf:], ies) || len(body) != len(ies)+0xf {
		t.Errorf("body % x", body)
	}
	if _, err := NRResponse(1, peer, make([]byte, 1001)); err == nil {
		t.Error("1001-octet report accepted (driver limit 1000)")
	}
}

// btm_req_data {u32 ifindex, peer[6], u32 btm_req_len, btm_req}; the body
// starts with the request mode (SendBTMReq reads the mode at btm_req[0] and
// the disassociation timer at btm_req[1..2]).
func TestBTMReq(t *testing.T) {
	peer := mustMAC(t, "02:11:22:33:44:55")
	cand := NeighborReport{BSSID: mustMAC(t, "a8:42:a1:00:00:03"), Info: BSSIDReachable, OpClass: 125, Channel: 149, PHYType: 9, Preference: 255}
	r, err := BTMReq(peer, BTMRequest{Mode: BTMAbridged | BTMDisassocImminent, DisassocTimer: 300, Validity: 100, Candidates: []NeighborReport{cand}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Flags != OIDWNMBTMReq|OIDSet {
		t.Errorf("flags %#x", r.Flags)
	}
	b := r.Buf
	if !bytes.Equal(b[4:10], peer[:]) || int(binary.LittleEndian.Uint32(b[10:])) != len(b)-14 {
		t.Fatalf("header % x", b[:14])
	}
	body := b[14:]
	if body[0] != BTMPrefListIncluded|BTMAbridged|BTMDisassocImminent || binary.LittleEndian.Uint16(body[1:]) != 300 || body[3] != 100 {
		t.Errorf("fixed fields % x", body[:4])
	}
	if c := body[4:]; c[0] != 52 || c[1] != 16 || !bytes.Equal(c[15:], []byte{3, 1, 255}) {
		t.Errorf("candidate % x", c)
	}
	// ESS disassociation imminent carries the URL length (and URL)
	r, _ = BTMReq(peer, BTMRequest{Mode: BTMESSDisassocImminent})
	if body := r.Buf[14:]; len(body) != 5 || body[4] != 0 {
		t.Errorf("ESS body % x", body)
	}
	if _, err := BTMReq(peer, BTMRequest{Mode: BTMBSSTerminationIncl}); err == nil {
		t.Error("BSS termination accepted without its duration")
	}
	if _, err := BTMReq(peer, BTMRequest{SessionURL: "http://x"}); err == nil {
		t.Error("URL without ESS disassociation imminent accepted")
	}
}

// Event layouts: wext_send_nr_req_event (rrm_event_t + nr_req_data from the
// dialog token), SendBTMConfirmEvent / SendBTMQueryEvent ({u32 ifindex,
// peer, u32 len at 10, data at 14}).
func TestParseEvent(t *testing.T) {
	sta := mustMAC(t, "02:11:22:33:44:55")
	req := []byte{9, 0, 4, 'h', 'o', 'm', 'e'} // token 9, SSID element
	nr := []byte{2}
	nr = binary.LittleEndian.AppendUint32(nr, uint32(len(req)+0xe))
	nr = binary.LittleEndian.AppendUint32(nr, 12)
	nr = append(nr, sta[:]...)
	nr = binary.LittleEndian.AppendUint32(nr, uint32(len(req)))
	nr = append(nr, req...)
	v, err := ParseEvent(EvRRM, nr)
	if err != nil {
		t.Fatal(err)
	}
	if e := v.(*NeighborRequest); e.STA != sta || e.Token != 9 || e.IfIndex != 12 || !bytes.Equal(e.Body, req[1:]) {
		t.Errorf("%+v", e)
	}

	btm := func(flags uint16, body []byte) *BTMEvent {
		t.Helper()
		b := binary.LittleEndian.AppendUint32(nil, 12)
		b = append(b, sta[:]...)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(body)))
		v, err := ParseEvent(flags, append(b, body...))
		if err != nil {
			t.Fatal(err)
		}
		return v.(*BTMEvent)
	}
	target := mustMAC(t, "a8:42:a1:00:00:03")
	if e := btm(EvBTMRsp, append([]byte{0, 0}, append(target[:], 0xee)...)); e.Status != 0 || !e.HaveTarget || e.Target != target || e.Timeout {
		t.Errorf("accept %+v", e)
	}
	if e := btm(EvBTMRsp, []byte{6, 0, 0xee}); e.Status != 6 || e.HaveTarget {
		t.Errorf("reject %+v", e)
	}
	if e := btm(EvBTMRsp, []byte{0x5a}); !e.Timeout {
		t.Errorf("timeout %+v", e)
	}
	if e := btm(EvBTMQuery, []byte{3, 16}); e.Flags != EvBTMQuery || !bytes.Equal(e.Body, []byte{3, 16}) {
		t.Errorf("query %+v", e)
	}
	for _, c := range []struct {
		f uint16
		b []byte
	}{{EvRRM, nr[:0x13]}, {EvRRM, append([]byte{1}, nr[1:]...)}, {EvBTMRsp, make([]byte, 13)}, {0x93b, nr}} {
		if _, err := ParseEvent(c.f, c.b); err == nil {
			t.Errorf("ParseEvent(%#x, % x) accepted", c.f, c.b)
		}
	}
}
