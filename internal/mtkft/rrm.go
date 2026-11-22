// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// 802.11k neighbour reports and 802.11v BSS transition management on the
// MT7663, the driver's daemon interface (CONFIG_11KV_API_SUPPORT; padavan
// mt7615 oid.h and embedded/common/rrm.c, checked against the Garage
// kernel's rrm_MsgHandle 0x80508ca8, rrm_send_nr_rsp_ie 0x80508a00,
// RTMPAPSetInformation 0x803143e0, Send_BTM_Req 0x80313c30, SendBTMReq
// 0x8050f954, PeerWNMAction 0x80512df8). The driver applies each to the
// BSS of the interface the ioctl is sent on (pObj->ioctl_if); the ifindex
// fields are not read.
//
// Not in this kernel: the iwpriv commands of CONFIG_DOT11V_WNM
// ("WNMCertEnable", "SendBTMReq" are absent from the set table) and
// OID_802_11_WNM_COMMAND (0x094A) has no case in RTMPAPSetInformation.

// OIDs (sent with OIDSet).
const (
	OIDWNMBTMReq  = 0x0928 // struct btm_req_data
	OIDRRMCommand = 0x094C // rrm_command_t
)

// Wireless events (RtmpOSWrielessEventSend type 1 = IWEVCUSTOM 0x8c02 on
// rtnetlink, iw_point.flags = the value below).
const (
	EvBTMQuery = 0x0929 // a station's BTM query
	EvBTMRsp   = 0x093a // a station's BTM response, or the 15 s timeout
	EvRRM      = 0x094D // rrm_event_t: a neighbour report request
)

// IWCustomMax is IW_CUSTOM_MAX: wireless_send_event drops an IWEVCUSTOM
// longer than this, so a BTM response with a long candidate list (more
// than 242 octets after the status) or a neighbour request longer than 237
// octets never reaches the agent.
const IWCustomMax = 256

// rrm_cmd_subid.
const (
	rrmCmdEnable      = 0x01
	rrmCmdSendNR      = 0x06 // nr_rsp_data_t
	rrmCmdNRByDaemon  = 0x08
	rrmEvtNeighborReq = 0x02
	maxNRRspLen       = 1000 // rrm_send_nr_rsp_ie: FrameLen > 1000 is refused
)

func rrmCommand(id byte, body []byte) Request {
	b := make([]byte, 5, 5+len(body))
	b[0] = id
	binary.LittleEndian.PutUint32(b[1:], uint32(len(body)))
	return Request{Flags: OIDRRMCommand | OIDSet, Buf: append(b, body...)}
}

func b2u8(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// RRMEnable turns 802.11k on or off for the BSS (Set_Dot11kRRM_Enable;
// the profile's RRMEnable= is the normal way, this is for tests).
func RRMEnable(on bool) Request { return rrmCommand(rrmCmdEnable, []byte{b2u8(on)}) }

// NRByDaemon makes the driver hand neighbour report requests to the agent
// (EvRRM) instead of answering them from its scan table
// (rrm_set_handle_nr_req_flag: one flag for the whole radio). The driver
// then waits for NRResponse; a request the agent does not answer gets no
// response (the station times out). Hand-back must send NRByDaemon(false).
func NRByDaemon(on bool) Request { return rrmCommand(rrmCmdNRByDaemon, []byte{b2u8(on)}) }

// NRResponse answers a neighbour report request with the elements ies
// (Neighbor Report elements, NeighborReport.Append). token is the
// request's dialog token: the driver drops a response whose non-zero token
// matches no pending request (send_nr_resp_toair), and sends one only to an
// associated station that advertised RRM, once its 4-way handshake is
// done. The driver adds the action header (category 5, action 5, token).
func NRResponse(token byte, peer MAC, ies []byte) (Request, error) {
	if len(ies) > maxNRRspLen {
		return Request{}, fmt.Errorf("mtkft: neighbour report of %d octets (driver limit %d)", len(ies), maxNRRspLen)
	}
	b := make([]byte, 0xf, 0xf+len(ies))
	b[4] = token
	copy(b[5:], peer[:])
	binary.LittleEndian.PutUint32(b[0xb:], uint32(len(ies)))
	return rrmCommand(rrmCmdSendNR, append(b, ies...)), nil
}

// BSSID Information bits (IEEE 802.11-2016 9.4.2.37).
const (
	BSSIDReachable     = 0x3 // AP reachability: reachable
	BSSIDSecurity      = 1 << 2
	BSSIDKeyScope      = 1 << 3
	BSSIDSpectrumMgmt  = 1 << 4
	BSSIDQoS           = 1 << 5
	BSSIDAPSD          = 1 << 6
	BSSIDRadioMeas     = 1 << 7
	BSSIDDelayedBA     = 1 << 8
	BSSIDImmediateBA   = 1 << 9
	BSSIDMobilityDom   = 1 << 10 // same MDID as this AP: FT possible
	BSSIDHighThroughpt = 1 << 11
	BSSIDVHT           = 1 << 12
)

// NeighborReport is one Neighbor Report element (ID 52).
type NeighborReport struct {
	BSSID   MAC
	Info    uint32 // BSSID Information
	OpClass byte
	Channel byte
	PHYType byte // 7 HT, 9 VHT
	// Preference, when non-zero, adds the BSS Transition Candidate
	// Preference subelement (3) a BTM request's candidate list needs.
	Preference byte
}

// Append adds n's element to b.
func (n NeighborReport) Append(b []byte) []byte {
	l := 13
	if n.Preference != 0 {
		l += 3
	}
	b = append(b, 52, byte(l))
	b = append(b, n.BSSID[:]...)
	b = binary.LittleEndian.AppendUint32(b, n.Info)
	b = append(b, n.OpClass, n.Channel, n.PHYType)
	if n.Preference != 0 {
		b = append(b, 3, 1, n.Preference)
	}
	return b
}

// BTM Request Mode bits.
const (
	BTMPrefListIncluded     = 1 << 0
	BTMAbridged             = 1 << 1
	BTMDisassocImminent     = 1 << 2
	BTMBSSTerminationIncl   = 1 << 3
	BTMESSDisassocImminent  = 1 << 4
	btmTerminationUnhandled = BTMBSSTerminationIncl
)

// BTMRequest is the body of a BSS Transition Management Request after the
// dialog token (the driver writes category 10, action 7 and its own
// dialog token, SendBTMReq).
type BTMRequest struct {
	Mode byte
	// DisassocTimer is in TBTTs. With Mode bits 2-4 SendBTMReq also arms a
	// per-station countdown of DisassocTimer x beacon interval / 1000
	// (presumably the disconnect; not checked on the unit).
	DisassocTimer uint16
	Validity      byte   // TBTTs
	SessionURL    string // only with BTMESSDisassocImminent
	Candidates    []NeighborReport
}

// MarshalBinary is the body. BSS termination (Mode bit 3) is refused:
// it needs a duration subelement this package does not build.
func (r BTMRequest) MarshalBinary() ([]byte, error) {
	if r.Mode&btmTerminationUnhandled != 0 {
		return nil, errors.New("mtkft: BTM BSS termination is not supported")
	}
	if r.SessionURL != "" && r.Mode&BTMESSDisassocImminent == 0 {
		return nil, errors.New("mtkft: a BTM session URL needs ESS disassociation imminent")
	}
	if len(r.SessionURL) > 255 {
		return nil, errors.New("mtkft: BTM session URL too long")
	}
	mode := r.Mode
	if len(r.Candidates) > 0 {
		mode |= BTMPrefListIncluded
	}
	b := []byte{mode}
	b = binary.LittleEndian.AppendUint16(b, r.DisassocTimer)
	b = append(b, r.Validity)
	if mode&BTMESSDisassocImminent != 0 {
		b = append(b, byte(len(r.SessionURL)))
		b = append(b, r.SessionURL...)
	}
	for _, c := range r.Candidates {
		b = c.Append(b)
	}
	return b, nil
}

// BTMReq sends a BTM request to peer (struct btm_req_data {u32 ifindex,
// peer[6], u32 btm_req_len, btm_req}). The driver sends it at once to an
// associated station whose 4-way handshake is done (or on an open BSS),
// else keeps it for after the handshake; it then waits 15 s for the
// response (EvBTMRsp).
func BTMReq(peer MAC, r BTMRequest) (Request, error) {
	body, err := r.MarshalBinary()
	if err != nil {
		return Request{}, err
	}
	b := make([]byte, 14, 14+len(body))
	copy(b[4:], peer[:])
	binary.LittleEndian.PutUint32(b[10:], uint32(len(body)))
	return Request{Flags: OIDWNMBTMReq | OIDSet, Buf: append(b, body...)}, nil
}

// NeighborRequest is an EvRRM neighbour report request.
type NeighborRequest struct {
	IfIndex uint32
	STA     MAC
	Token   byte   // the dialog token NRResponse must echo
	Body    []byte // the request's elements after the token (SSID, LCI/civic requests)
}

// BTMEvent is an EvBTMQuery or EvBTMRsp.
type BTMEvent struct {
	Flags   uint16
	IfIndex uint32
	STA     MAC
	// Timeout: an EvBTMRsp from ReceiveBTMRspTimeout (no response in
	// 15 s; its one-octet body is not a status).
	Timeout bool
	// For a response: the status (0 accept), the BSS termination delay and,
	// for an accept, the target BSSID.
	Status     byte
	TermDelay  byte
	Target     MAC
	HaveTarget bool
	// Body is the frame from the status (a response; the driver's length
	// counts one octet past the frame) or from the dialog token (a query).
	Body []byte
}

// ParseEvent reads the data of an IWEVCUSTOM with iw_point flags flags:
// a *NeighborRequest, a *BTMEvent, or an error for others.
func ParseEvent(flags uint16, data []byte) (any, error) {
	switch flags {
	case EvRRM:
		// rrm_event_t {u8 id, u32 len} + nr_req_data {u32 ifindex,
		// peer[6], u32 nr_req_len, nr_req (from the dialog token)}
		if len(data) < 0x13+1 || data[0] != rrmEvtNeighborReq {
			return nil, errors.New("mtkft: not a neighbour report request event")
		}
		n := binary.LittleEndian.Uint32(data[0xf:])
		if int(n) > len(data)-0x13 || n == 0 {
			return nil, fmt.Errorf("mtkft: neighbour request length %d", n)
		}
		e := &NeighborRequest{IfIndex: binary.LittleEndian.Uint32(data[5:])}
		copy(e.STA[:], data[9:15])
		req := data[0x13 : 0x13+n]
		e.Token = req[0]
		e.Body = append([]byte(nil), req[1:]...)
		return e, nil
	case EvBTMQuery, EvBTMRsp:
		// {u32 ifindex, peer[6], u32 len, body}
		if len(data) < 14 {
			return nil, errors.New("mtkft: short BTM event")
		}
		n := binary.LittleEndian.Uint32(data[10:])
		if int(n) > len(data)-14 {
			return nil, fmt.Errorf("mtkft: BTM event length %d", n)
		}
		e := &BTMEvent{Flags: flags, IfIndex: binary.LittleEndian.Uint32(data), Body: append([]byte(nil), data[14:14+n]...)}
		copy(e.STA[:], data[4:10])
		if flags == EvBTMRsp {
			switch {
			case n == 1:
				e.Timeout = true
			case n >= 2:
				e.Status, e.TermDelay = e.Body[0], e.Body[1]
				if e.Status == 0 && n >= 8 {
					copy(e.Target[:], e.Body[2:8])
					e.HaveTarget = true
				}
			}
		}
		return e, nil
	}
	return nil, fmt.Errorf("mtkft: event flags %#x not handled", flags)
}
