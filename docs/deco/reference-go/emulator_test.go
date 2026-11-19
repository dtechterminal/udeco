package deco

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeDeco is an in-process emulator of the device side of TMP v1 + business V2.
// Everything about its behaviour is INFERRED; it exists to exercise the client paths.
type fakeDeco struct {
	t           *testing.T
	conn        net.Conn
	directAck   bool // answer the final PUSH with PULL_ACK (true) or PUSH_ACK (false)
	handler     func(opcode uint16, req []byte) []byte
	badEmptyCRC bool
	reqs        map[uint16][]byte // tid -> assembled request
	resps       map[uint16][]byte // tid -> response
	heartbeats  int
}

func (d *fakeDeco) serve() {
	d.reqs, d.resps = map[uint16][]byte{}, map[uint16][]byte{}
	for {
		fr, err := ReadFrame(d.conn)
		if err != nil {
			return
		}
		switch fr.Type {
		case TMPTypeHeartbeat:
			d.heartbeats++
			_, _ = d.conn.Write(ShortFrame(TMPTypeHeartbeat))
			continue
		case TMPTypeBye:
			return
		case TMPTypeData:
		default:
			continue
		}
		h, body, err := DecodeV2(fr.Payload)
		if err != nil {
			d.t.Errorf("device: bad V2: %v", err)
			return
		}
		var reply []byte
		switch h.Operation {
		case OpPush:
			d.reqs[h.TransID] = append(d.reqs[h.TransID], body...)
			last := h.Start/V2ChunkSize == h.Total/V2ChunkSize // last of len/8156+1 pushes (a.java:78-86)
			if last && h.Total != 0 && crc32.ChecksumIEEE(d.reqs[h.TransID]) != h.CRC32 {
				d.t.Errorf("device: request crc mismatch")
			}
			if !last {
				reply = EncodeV2(V2Header{Type: 1, Version: 2, Opcode: h.Opcode, Operation: OpPushAck, TransID: h.TransID}, nil)
				break
			}
			d.resps[h.TransID] = d.handler(h.Opcode, d.reqs[h.TransID])
			if d.directAck {
				reply = d.chunk(h, 0)
			} else {
				reply = EncodeV2(V2Header{Type: 1, Version: 2, Opcode: h.Opcode, Operation: OpPushAck, TransID: h.TransID}, nil)
			}
		case OpPull:
			reply = d.chunk(h, h.Start)
		}
		_, _ = d.conn.Write(responseFrame(fr.Serial, reply))
	}
}

func (d *fakeDeco) chunk(h V2Header, start uint32) []byte {
	resp := d.resps[h.TransID]
	crc := crc32.ChecksumIEEE(resp)
	if len(resp) == 0 {
		crc = 0
		if d.badEmptyCRC {
			crc = 0xdeadbeef
		}
	}
	end := min(int(start)+V2ChunkSize, len(resp))
	var body []byte
	if int(start) < len(resp) {
		body = resp[start:end]
	}
	return EncodeV2(V2Header{Type: 1, Version: 2, Opcode: h.Opcode, Operation: OpPullAck, TransID: h.TransID,
		CRC32: crc, Total: uint32(len(resp)), Start: start}, body)
}

func responseFrame(serial uint32, payload []byte) []byte { return EncodeDataFrame(serial, payload) }

func newPair(t *testing.T, direct bool, h func(uint16, []byte) []byte) (*Session, *FrameConn, *fakeDeco) {
	a, b := net.Pipe()
	d := &fakeDeco{t: t, conn: b, directAck: direct, handler: h}
	go d.serve()
	fc := NewFrameConn(a, 50*time.Millisecond)
	return &Session{RT: fc}, fc, d
}

func jsonHandler(token string, big int) func(uint16, []byte) []byte {
	return func(op uint16, req []byte) []byte {
		switch op {
		case OpcodeTokenAlloc:
			return []byte(token)
		case OpcodeTokenFree, OpcodeTokenVerify:
			return nil
		case OpNegotiation:
			var p TMPParams
			_ = json.Unmarshal(req, &p)
			m := p.Params.(map[string]any)
			if m["role"] != UserRoleOwner {
				return []byte(`{"error_code":-1,"msg":"role"}`)
			}
			return []byte(`{"error_code":0,"result":{"operation_mode":"AP","component_list":[{"id":"wireless","ver_code":1}]}}`)
		case OpGetDeviceList:
			name := strings.Repeat("x", big)
			return []byte(`{"error_code":"0","result":{"device_list":[{"device_id":"8e6a","mac":"B0-A7-B9-3E-16-94","role":"master","inet_status":"online","hw_id":"` + name + `"}]}}`)
		case OpSetWireless:
			return nil // empty payload -> TMPResult(0)
		}
		return []byte(`{"error_code":-40210,"msg":"unsupported"}`)
	}
}

func TestEndToEndBothAckStyles(t *testing.T) {
	for _, direct := range []bool{true, false} {
		for _, big := range []int{0, 9000, 3*V2ChunkSize - 40} {
			s, fc, _ := newPair(t, direct, jsonHandler("tok123", big))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			body, _ := EncodeRequest(NegotiationParams{Role: UserRoleOwner, Username: AccountDigest("a@b.c")}, time.Now())
			resp, err := s.Call(ctx, OpNegotiation, body)
			if err != nil {
				t.Fatalf("direct=%v negotiate: %v", direct, err)
			}
			var nr NegotiationResult
			if err := DecodeResult(OpNegotiation, resp, &nr); err != nil || !nr.OperationMode.Is(OpModeAP) || !nr.HasComponent("wireless") {
				t.Fatalf("negotiate decode: %v %+v", err, nr)
			}
			body, _ = EncodeRequest(nil, time.Now())
			if !bytes.HasPrefix(body, []byte(`{"config_version":`)) || bytes.Contains(body, []byte("params")) {
				t.Fatalf("null params must be omitted: %s", body)
			}
			resp, err = s.Call(ctx, OpGetDeviceList, body)
			if err != nil {
				t.Fatalf("direct=%v big=%d device list: %v", direct, big, err)
			}
			var dl DeviceListResult
			if err := DecodeResult(OpGetDeviceList, resp, &dl); err != nil || len(dl.DeviceList) != 1 || !dl.DeviceList[0].IsMaster() {
				t.Fatalf("device list decode: %v %+v", err, dl)
			}
			// large request (multi-push) with empty response
			huge := WirelessHost{SSID: ptr(B64(strings.Repeat("s", 2*V2ChunkSize)))}
			body, _ = EncodeRequest(BuildHostSet(&WirelessInfo{Band2G4: &WirelessBand{}}, huge), time.Now())
			if _, err := s.Call(ctx, OpSetWireless, body); err != nil {
				t.Fatalf("multi-push set: %v", err)
			}
			resp, err = s.Call(ctx, 0x7777, mustReq(nil))
			if err != nil {
				t.Fatal(err)
			}
			var ae *AppError
			if err := DecodeResult(0x7777, resp, nil); !errors.As(err, &ae) || ae.ErrorCode != -40210 {
				t.Fatalf("want AppError -40210, got %v", err)
			}
			_ = s.Close(ctx)
			_ = fc.Close()
			cancel()
		}
	}
}

func TestEmptyResponseCRC(t *testing.T) {
	// single PUSH, total=0, crc!=0 -> app rejects with -3200 (a.java:108-110,134-141)
	s, fc, d := newPair(t, true, jsonHandler("t", 0))
	defer fc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.Call(ctx, 0, nil); err != nil {
		t.Fatal(err)
	}
	d.badEmptyCRC = true
	_, err := s.Call(ctx, OpSetWireless, mustReq(map[string]any{"a": 1}))
	var be *BizError
	if !errors.As(err, &be) || be.Code != -3200 {
		t.Fatalf("want -3200, got %v", err)
	}
	// multi-push, total=0, crc!=0 -> app accepts (e() -> d(null), a.java:163,135-136)
	big := map[string]string{"x": strings.Repeat("y", V2ChunkSize+10)}
	if _, err := s.Call(ctx, OpSetWireless, mustReq(big)); err != nil {
		t.Fatalf("multi-push empty reply: %v", err)
	}
}

func TestEmptyTokenIsValid(t *testing.T) {
	allocs := 0
	h := jsonHandler("", 0)
	s, fc, _ := newPair(t, false, func(op uint16, req []byte) []byte {
		if op == OpcodeTokenAlloc {
			allocs++
		}
		return h(op, req)
	})
	defer fc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		if _, err := s.Call(ctx, OpGetDeviceList, mustReq(nil)); err != nil {
			t.Fatal(err)
		}
	}
	if allocs != 1 {
		t.Fatalf("allocs=%d, want 1 (o.java:384-390)", allocs)
	}
}

func TestFrameCRCAndHeartbeat(t *testing.T) {
	f := EncodeDataFrame(7, []byte("abc"))
	if binary.BigEndian.Uint16(f[4:]) != 3 || binary.BigEndian.Uint32(f[8:]) != 7 {
		t.Fatal("header")
	}
	if fr, err := ReadFrame(bytes.NewReader(f)); err != nil || string(fr.Payload) != "abc" {
		t.Fatal(err)
	}
	f[17] ^= 1
	if _, err := ReadFrame(bytes.NewReader(f)); err == nil {
		t.Fatal("expected -2004")
	}
	_, fc, _ := newPair(t, true, jsonHandler("t", 0))
	defer fc.Close()
	time.Sleep(200 * time.Millisecond)
	if fc.LastHeartbeatEcho().IsZero() {
		t.Fatal("no heartbeat echo seen")
	}
}

func TestNegotiateTolerance(t *testing.T) {
	if !negotiateTolerated(&AppError{ErrorCode: -1}) || !negotiateTolerated(&BizError{Code: -3220}) {
		t.Fatal("should tolerate")
	}
	if negotiateTolerated(&BizError{Code: -3222}) || negotiateTolerated(errors.New("io")) {
		t.Fatal("should not tolerate")
	}
}

func TestTDPAndUsername(t *testing.T) {
	d := DecoInfo{NeedAccountDigest: true, Owner: "098f6bcd4621d373cade4e832627b4f6"} // md5("test")
	if !d.OwnerMatches("test") || d.SSHUsername("test") != "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" {
		t.Fatal("owner/username")
	}
	pkt := EncodeTDP(TDPVersion2, TDPOpDiscover, TDPFlagUnicast, 0, 0x1234, []byte(`{"error_code":0}`))
	if h, body, err := DecodeTDP(pkt); err != nil || h.Serial != 0x1234 || string(body) != `{"error_code":0}` {
		t.Fatal(err)
	}
}

func mustReq(p any) []byte { b, _ := EncodeRequest(p, time.Now()); return b }
func ptr[T any](v T) *T    { return &v }
