// SPDX-License-Identifier: GPL-2.0-or-later

package deco

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ============================================================================
// AppBusiness V2 layer (com/tplink/tmp/business/v2/o.java, u.java, transaction/a.java)
// Deco uses V2 with no negotiation: mesh/context/c.java:1508-1512 -> v2/t.b() -> new o()
// (v2/t.java:17-19); TMP v1 from c.java:1604-1608.
// ============================================================================

const (
	BizType      = 0x01 // wk/a.java:11; o.java:460-461
	BizVersionV2 = 0x02 // o.java:192-194; u.java:79

	V2HeaderLen = 20   // u.java:89-101 (2-byte prefix + 18, u.java:16)
	V2ChunkSize = 8156 // transaction/a.java:16 (INFERRED: 8156+20+16 = 8192 per frame)

	// MaxPayload is a LOCAL cap (not in the app): Java allocates new byte[total]
	// with a signed int (transaction/a.java:109).
	MaxPayload = 16 << 20
)

// V2 operation byte at offset 4 (u.java:119-131). 1 exists (u.java:19) but is never sent.
const (
	OpPush    = 2 // sent by a.java:194-198
	OpPushAck = 3
	OpPull    = 4 // sent by a.java:188-192
	OpPullAck = 5
)

// Reserved business opcodes carrying the session token (o.java:24-31).
const (
	OpcodeTokenAlloc  uint16 = 1 // o.java:234-241, null payload
	OpcodeTokenVerify uint16 = 2 // o.java:318-335, payload = token bytes
	OpcodeTokenFree   uint16 = 3 // o.java:254-266, payload = token bytes
)

var statusToCode = map[byte]int{ // o.java:286-316
	2: -3212, 3: -3213, 4: -3214, 5: -3215, 6: -3216, 7: -3217,
	8: -3218, 9: -3219, 10: -3220, 11: -3221, 12: -3222,
}

// AppBusinessLayerException.java:19-24; AppBusinessV2LayerException.java:62-81.
var bizErrNames = map[int]string{
	-3000: "ERR_INVALID_BUSINESS_TYPE", -3001: "ERR_INVALID_BUSINESS_VER",
	-3002: "ERR_INVALID_BUSINESS_CONFIG_INFO_LACKED",
	-3200: "ERR_TRANSACTION_ALL_PAYLOAD_CHECKSUM", -3201: "ERR_TRANSACTION_DATA_PUSH_ENQUEUE",
	-3202: "ERR_TRANSACTION_DATA_PULL_ENQUEUE", -3203: "ERR_INVALID_TOTAL_PAYLOAD_LENGTH",
	-3204: "ERR_APP_V2_CONFIG_INFO_LACKED", -3211: "ERR_APP_V2_UNKNOWN",
	-3212: "ERR_APP_V2_BUSINESS_TYPE", -3213: "ERR_APP_V2_BUSINESS_VERSION",
	-3214: "ERR_APP_V2_OPERATION", -3215: "ERR_APP_V2_FLAGS", -3216: "ERR_APP_V2_TRANS_ID",
	-3217: "ERR_APP_V2_TRANS_CRC32", -3218: "ERR_APP_V2_TRANS_TOTAL_BYTES",
	-3219: "ERR_APP_V2_TRANS_START_BYTE", -3220: "ERR_APP_V2_TOKEN_EXPIRED",
	-3221: "ERR_APP_V2_TOKEN_ALLOC", -3222: "ERR_APP_V2_BUSINESS_FAILED",
}

// BizError carries the app's business-layer error code.
type BizError struct {
	Code   int  // e.g. -3220
	Status byte // raw device status byte, 0 if detected locally
}

func (e *BizError) Error() string {
	return fmt.Sprintf("tmp business: %s (%d, status=%d)", bizErrNames[e.Code], e.Code, e.Status)
}

// Retryable mirrors AppBusinessV2LayerException.d() (AppBusinessV2LayerException.java:101-103):
// client/f.java:161-171 re-runs the whole request once.
func (e *BizError) Retryable() bool { return e.Code == -3220 || e.Code == -3221 }

// resetsLayer: g.t() calls p() on a bad type or version (business/g.java:107-115).
func (e *BizError) resetsLayer() bool { return e.Code == -3000 || e.Code == -3001 }

// ProtocolError: Go-only, for replies the Java state machine would wait on forever
// (transaction/a.java:223-248 with o.java:115-118). Not an app error code.
type ProtocolError struct{ Msg string }

func (e *ProtocolError) Error() string { return "tmp business (local): " + e.Msg }

func statusError(st byte) error {
	if st == 0 {
		return nil
	}
	if c, ok := statusToCode[st]; ok {
		return &BizError{Code: c, Status: st}
	}
	return &BizError{Code: -3211, Status: st} // 1 and unlisted (o.java:313-314)
}

// V2Header: 20 bytes, big-endian (util/b.java:12-26).
type V2Header struct {
	Type      byte   // 0: 0x01
	Version   byte   // 1: 0x02
	Opcode    uint16 // 2-3
	Operation byte   // 4: OpPush..OpPullAck
	Status    byte   // 5: 0 in requests
	TransID   uint16 // 6-7
	CRC32     uint32 // 8-11: CRC32/IEEE of the whole logical payload; 0 if empty and in PULL
	Total     uint32 // 12-15: payload length; 0 in PULL
	Start     uint32 // 16-19: offset of this chunk
}

func EncodeV2(h V2Header, body []byte) []byte {
	b := make([]byte, V2HeaderLen+len(body))
	b[0], b[1] = h.Type, h.Version
	binary.BigEndian.PutUint16(b[2:], h.Opcode)
	b[4], b[5] = h.Operation, h.Status
	binary.BigEndian.PutUint16(b[6:], h.TransID)
	binary.BigEndian.PutUint32(b[8:], h.CRC32)
	binary.BigEndian.PutUint32(b[12:], h.Total)
	binary.BigEndian.PutUint32(b[16:], h.Start)
	copy(b[V2HeaderLen:], body)
	return b
}

// DecodeV2 applies g.t() (business/g.java:99-116) then o.l() (o.java:414-432).
// The reply opcode and transaction id are NOT checked, as in the app.
// A body is nil when the packet is exactly 20 bytes (o.java:424-430).
func DecodeV2(b []byte) (V2Header, []byte, error) {
	var h V2Header
	switch {
	case len(b) < 2:
		return h, nil, &BizError{Code: -3002}
	case b[0] != BizType:
		return h, nil, &BizError{Code: -3000}
	case b[1] != BizVersionV2:
		return h, nil, &BizError{Code: -3001}
	case len(b) < V2HeaderLen:
		return h, nil, &BizError{Code: -3204}
	}
	h = V2Header{Type: b[0], Version: b[1], Opcode: binary.BigEndian.Uint16(b[2:]),
		Operation: b[4], Status: b[5], TransID: binary.BigEndian.Uint16(b[6:]),
		CRC32: binary.BigEndian.Uint32(b[8:]), Total: binary.BigEndian.Uint32(b[12:]),
		Start: binary.BigEndian.Uint32(b[16:])}
	if err := statusError(h.Status); err != nil {
		return h, nil, err
	}
	var body []byte
	if len(b) > V2HeaderLen {
		body = b[V2HeaderLen:]
	}
	return h, body, nil
}

// PushPackets mirrors transaction/a.java:70-96: an empty payload is one PUSH with
// crc=0,total=0,start=0; otherwise len/8156+1 PUSHes with the same crc and total,
// including a trailing 0-byte PUSH at start=len when len is a multiple of 8156 (a.java:84).
func PushPackets(opcode, tid uint16, payload []byte) [][]byte {
	if len(payload) == 0 {
		return [][]byte{EncodeV2(V2Header{Type: BizType, Version: BizVersionV2, Opcode: opcode,
			Operation: OpPush, TransID: tid}, nil)}
	}
	crc := crc32.ChecksumIEEE(payload)
	n := len(payload)/V2ChunkSize + 1
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		start := i * V2ChunkSize
		end := min(start+V2ChunkSize, len(payload))
		out = append(out, EncodeV2(V2Header{Type: BizType, Version: BizVersionV2, Opcode: opcode,
			Operation: OpPush, TransID: tid, CRC32: crc, Total: uint32(len(payload)),
			Start: uint32(start)}, payload[start:end]))
	}
	return out
}

// PullPacket mirrors transaction/a.java:188-192 (crc=0, total=0, no body).
func PullPacket(opcode, tid uint16, start uint32) []byte {
	return EncodeV2(V2Header{Type: BizType, Version: BizVersionV2, Opcode: opcode,
		Operation: OpPull, TransID: tid, Start: start}, nil)
}

// RoundTripper carries one business packet as the payload of one TMP DATA frame
// and returns the payload of the reply frame with the same serial. *FrameConn
// implements it.
type RoundTripper interface {
	RoundTrip(ctx context.Context, pkt []byte) ([]byte, error)
}

func startBuf(h V2Header, body []byte) ([]byte, error) {
	if h.Total > MaxPayload {
		return nil, &ProtocolError{Msg: fmt.Sprintf("total %d exceeds local cap", h.Total)}
	}
	return append(make([]byte, 0, h.Total), body...), nil
}

// Transact runs one V2 transaction with window=1 (the app pipelines up to 20
// packets, o.java:59,82-110; sequential sending is a subset, INFERRED safe).
//
// Mirrors transaction/a.java:98-253:
//   - a reply to a PUSH that is not PULL_ACK means "keep pushing"; after the last
//     PUSH the client sends PULL start=0 (a.java:223-234);
//   - the first PULL_ACK gives crc and total; further PULLs go to start=k*8156 for
//     k=1..total/8156, which includes one surplus PULL at start==total when total is
//     a multiple of 8156 (a.java:143-156);
//   - reassembly checks overflow and PULL/PULL_ACK start equality (-3203,
//     a.java:113-118), pads short data with zeros and CRCs byte[total] (-3200,
//     a.java:108-110,134-141);
//   - single-chunk replies must have len==total (-3203, a.java:157-161);
//   - the one case without a CRC check: total==0 after a MULTI-push request,
//     where e() calls d(null) (a.java:157-165,135-136). With a single PUSH, k()
//     routes total==0 to c(), which checks CRC32("")==0 (a.java:177-186,108-110).
func Transact(ctx context.Context, rt RoundTripper, opcode, tid uint16, payload []byte) ([]byte, error) {
	return transactTrace(ctx, rt, opcode, tid, payload, nil)
}

// transactTrace is Transact with a business-packet tracer (nil: off): one
// line per packet sent and received (operation, opcode, tid, status, start,
// total, chunk length) and the CRC verdict. Bodies are never traced.
func transactTrace(ctx context.Context, rt RoundTripper, opcode, tid uint16, payload []byte, trace func(string, ...any)) ([]byte, error) {
	if trace != nil {
		rt = traceRT{rt: rt, f: trace}
	}
	out, err := transact(ctx, rt, opcode, tid, payload)
	if trace != nil {
		var be *BizError
		switch {
		case err == nil:
			trace("trace: biz 0x%04x tid=%d done: %d byte(s), crc ok", opcode, tid, len(out))
		case errors.As(err, &be) && be.Code == -3200:
			trace("trace: biz 0x%04x tid=%d crc MISMATCH", opcode, tid)
		default:
			trace("trace: biz 0x%04x tid=%d failed: %v", opcode, tid, err)
		}
	}
	return out, err
}

func transact(ctx context.Context, rt RoundTripper, opcode, tid uint16, payload []byte) ([]byte, error) {
	var first *V2Header
	var buf []byte
	pushes := PushPackets(opcode, tid, payload)
	for i, p := range pushes {
		resp, err := rt.RoundTrip(ctx, p)
		if err != nil {
			return nil, err
		}
		h, body, err := DecodeV2(resp)
		if err != nil {
			return nil, err
		}
		if h.Operation == OpPullAck {
			if i != len(pushes)-1 {
				return nil, &ProtocolError{Msg: "DATA_PULL_ACK before final DATA_PUSH"}
			}
			hh := h
			first = &hh
			if buf, err = startBuf(h, body); err != nil {
				return nil, err
			}
		}
	}
	if first == nil {
		resp, err := rt.RoundTrip(ctx, PullPacket(opcode, tid, 0))
		if err != nil {
			return nil, err
		}
		h, body, err := DecodeV2(resp)
		if err != nil {
			return nil, err
		}
		if h.Operation != OpPullAck {
			return nil, &ProtocolError{Msg: fmt.Sprintf("operation %d in reply to DATA_PULL", h.Operation)}
		}
		if h.Start != 0 { // a.java:115
			return nil, &BizError{Code: -3203}
		}
		first = &h
		if buf, err = startBuf(h, body); err != nil {
			return nil, err
		}
	}
	got := uint32(len(buf))
	if n := first.Total / V2ChunkSize; n != 0 {
		for k := uint32(1); k <= n; k++ {
			start := k * V2ChunkSize
			resp, err := rt.RoundTrip(ctx, PullPacket(opcode, tid, start))
			if err != nil {
				return nil, err
			}
			h, body, err := DecodeV2(resp)
			if err != nil {
				return nil, err
			}
			if h.Operation != OpPullAck {
				return nil, &ProtocolError{Msg: fmt.Sprintf("operation %d in reply to DATA_PULL", h.Operation)}
			}
			if h.Start != start || uint64(got)+uint64(len(body)) > uint64(first.Total) {
				return nil, &BizError{Code: -3203}
			}
			buf = append(buf, body...)
			got += uint32(len(body))
		}
	} else if got != first.Total {
		return nil, &BizError{Code: -3203}
	}
	if first.Total == 0 && len(pushes) > 1 {
		return []byte{}, nil // e() -> d(null): no CRC check (a.java:163,135-136)
	}
	full := make([]byte, first.Total)
	copy(full, buf)
	if crc32.ChecksumIEEE(full) != first.CRC32 {
		return nil, &BizError{Code: -3200}
	}
	return full, nil
}

// v2OpName names the V2 operation byte (u.java:119-131).
func v2OpName(op byte) string {
	switch op {
	case OpPush:
		return "PUSH"
	case OpPushAck:
		return "PUSH_ACK"
	case OpPull:
		return "PULL"
	case OpPullAck:
		return "PULL_ACK"
	}
	return fmt.Sprintf("op%d", op)
}

// v2Desc describes a V2 packet's header and body length, never its bytes.
func v2Desc(p []byte) string {
	if len(p) < V2HeaderLen {
		return fmt.Sprintf("short packet (%d bytes)", len(p))
	}
	return fmt.Sprintf("%s opcode=0x%04x tid=%d status=%d start=%d total=%d chunk=%d", v2OpName(p[4]),
		binary.BigEndian.Uint16(p[2:]), binary.BigEndian.Uint16(p[6:]), p[5],
		binary.BigEndian.Uint32(p[16:]), binary.BigEndian.Uint32(p[12:]), len(p)-V2HeaderLen)
}

type traceRT struct {
	rt RoundTripper
	f  func(string, ...any)
}

func (t traceRT) RoundTrip(ctx context.Context, pkt []byte) ([]byte, error) {
	t.f("trace: biz tx %s", v2Desc(pkt))
	resp, err := t.rt.RoundTrip(ctx, pkt)
	if err != nil {
		t.f("trace: biz rx none: %v", err)
	} else {
		t.f("trace: biz rx %s", v2Desc(resp))
	}
	return resp, err
}

// Session mirrors AppBusinessV2Layer (v2/o.java): transaction ids and the token.
// Safe for concurrent use; requests are serialised (window=1).
type Session struct {
	RT RoundTripper
	// ResetTransport is called where the app resets the TMP layer
	// (g.p() -> client/g.reset() -> h0.W(null); client/g.java:44-47, h0.java:460-484):
	// after a failed alloc (o.java:222-225,342-346), a verify failure other than
	// -3220 (o.java:349-351), and a bad business type/version (g.java:107-115).
	// It runs with the session lock held and must not call Session methods.
	ResetTransport func()
	// Trace, if set, receives one line per business packet (see transactTrace).
	Trace func(string, ...any)

	mu       sync.Mutex // o.java:356 Semaphore(1) + window
	nextTID  uint32     // o.java:161-166
	token    []byte     // o.java f68321j; an empty token is valid (o.java:384-390)
	haveTok  bool
	verified bool // o.java f68320i
}

// tid: AtomicInteger(0).getAndIncrement(); at 65535 a CAS resets to 0 and the call
// returns (short)-1 (o.java:161-166). Not reset by p() (o.java:169-174).
func (s *Session) tid() uint16 {
	if s.nextTID == 65535 {
		s.nextTID = 0
		return 0xFFFF
	}
	t := uint16(s.nextTID)
	s.nextTID++
	return t
}

func (s *Session) resetTransport() {
	s.verified = false // o.java:452-455
	if s.ResetTransport != nil {
		s.ResetTransport()
	}
}

func (s *Session) transact(ctx context.Context, opcode uint16, payload []byte) ([]byte, error) {
	out, err := transactTrace(ctx, s.RT, opcode, s.tid(), payload, s.Trace)
	var be *BizError
	if errors.As(err, &be) && be.resetsLayer() {
		s.resetTransport()
	}
	return out, err
}

// ensureToken mirrors N()/M()/P() (o.java:196-208,234-241,268-284,318-396).
func (s *Session) ensureToken(ctx context.Context) error {
	if s.haveTok && s.verified {
		return nil // o.java:197-199
	}
	if s.haveTok {
		_, err := s.transact(ctx, OpcodeTokenVerify, s.token)
		if err == nil {
			s.verified = true // o.java:380: any result, even empty
			return nil
		}
		s.verified = false
		var be *BizError
		if !errors.As(err, &be) || be.Code != -3220 {
			s.token, s.haveTok = nil, false // o.java:349-351
			s.resetTransport()
			return err
		}
	}
	tok, err := s.transact(ctx, OpcodeTokenAlloc, nil)
	if err != nil {
		s.token, s.haveTok, s.verified = nil, false, false // o.java:392-395
		s.resetTransport()                                 // o.java:342-346
		return err
	}
	s.token, s.haveTok, s.verified = tok, true, true // o.java:384-391: alloc implies verified
	return nil
}

// Reset is the o.p() equivalent: call after the TMP/SSH stream is replaced. The
// token is kept and re-verified with opcode 2 before the next request (o.java:449-458).
func (s *Session) Reset() {
	s.mu.Lock()
	s.verified = false
	s.mu.Unlock()
}

// Call runs the token step then one transaction (o.java:434-447). Opcode 0 with a
// nil payload performs only the token step (o.java:436).
func (s *Session) Call(ctx context.Context, opcode uint16, payload []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out, err := s.callOnce(ctx, opcode, payload)
	var be *BizError
	if errors.As(err, &be) && be.Retryable() && ctx.Err() == nil {
		// The app re-runs the whole n() once on -3220/-3221 WITH the same token
		// (client/f.java:132-136,161-171; o.java:441-446). DEVIATION (INFERRED
		// recovery): drop the token so the retry re-allocates.
		s.token, s.haveTok, s.verified = nil, false, false
		return s.callOnce(ctx, opcode, payload)
	}
	return out, err
}

func (s *Session) callOnce(ctx context.Context, opcode uint16, payload []byte) ([]byte, error) {
	if err := s.ensureToken(ctx); err != nil {
		return nil, err
	}
	if opcode == 0 && payload == nil {
		return nil, nil
	}
	return s.transact(ctx, opcode, payload)
}

// Close frees the token with opcode 3 if one is held (o.java:210-220,254-266,398-406).
func (s *Session) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, have := s.token, s.haveTok
	s.token, s.haveTok, s.verified = nil, false, false
	if !have {
		return nil
	}
	_, err := transactTrace(ctx, s.RT, OpcodeTokenFree, s.tid(), tok, s.Trace)
	return err
}

// ============================================================================
// JSON envelope (com/tplink/apps/network/tmp/bean/AppRequest.java:48-111,
// TMPParams.java:17-22, TMPResult.java:17-24; Gson config k0.java:21-29)
// ============================================================================

// TMPParams is the request body. config_version is always present
// (AppRequest.java:56); params is omitted when nil (Gson serializeNulls off).
type TMPParams struct {
	ConfigVersion int64 `json:"config_version"`
	Params        any   `json:"params,omitempty"`
}

// CompatInt mirrors IntegerCompatTypeAdapter, which applies to primitive int fields
// only (k0.java:24-28; TypeAdapters.java:1118-1127): numbers and numeric strings are
// accepted, anything else becomes Integer.MAX_VALUE, null keeps the default.
type CompatInt int

func (c *CompatInt) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		return nil
	}
	s = strings.Trim(s, `"`)
	if v, err := strconv.ParseInt(s, 10, 32); err == nil {
		*c = CompatInt(v)
		return nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f == math.Trunc(f) &&
		f >= math.MinInt32 && f <= math.MaxInt32 {
		*c = CompatInt(int32(f))
		return nil
	}
	*c = math.MaxInt32
	return nil
}

// TMPResult is the reply body; an empty payload means TMPResult(0) (AppRequest.java:110).
type TMPResult struct {
	ErrorCode CompatInt       `json:"error_code"`
	Msg       string          `json:"msg,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
}

// AppError mirrors TMPException(opCode, errorCode, msg, raw) (i0.java:651-667).
type AppError struct {
	Opcode    uint16
	ErrorCode int
	Msg, Raw  string
}

func (e *AppError) Error() string {
	return fmt.Sprintf("tmp opcode 0x%04x: error_code=%d msg=%q", e.Opcode, e.ErrorCode, e.Msg)
}

// NoData: repositories treat 1010 as an empty result (repo/d.java:136-139; TMPException.java:34,54).
func (e *AppError) NoData() bool { return e.ErrorCode == 1010 }

// EncodeRequest marshals TMPParams without HTML escaping (Gson disableHtmlEscaping,
// gson/d.java:187-189).
func EncodeRequest(params any, now time.Time) ([]byte, error) {
	p := TMPParams{ConfigVersion: now.UnixMilli()}
	if !isNil(params) {
		p.Params = params
	}
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(sb.String(), "\n")), nil
}

// DecodeResult parses TMPResult and unmarshals result into out (may be nil).
func DecodeResult(opcode uint16, resp []byte, out any) error {
	if len(resp) == 0 {
		return nil
	}
	var r TMPResult
	if err := json.Unmarshal(resp, &r); err != nil {
		return fmt.Errorf("decode reply for 0x%04x: %w", opcode, err)
	}
	if r.ErrorCode != 0 {
		return &AppError{Opcode: opcode, ErrorCode: int(r.ErrorCode), Msg: r.Msg, Raw: string(resp)}
	}
	if out != nil && len(r.Result) > 0 && string(r.Result) != "null" {
		err := json.Unmarshal(r.Result, out)
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) {
			return &ResultTypeError{Opcode: opcode, Err: err}
		}
		return err
	}
	return nil
}

// ResultTypeError: a field of an otherwise well-formed result has a JSON type
// the Go schema does not take. json.Unmarshal still filled every other field,
// so out holds a partial decode. The session itself is healthy.
type ResultTypeError struct {
	Opcode uint16
	Err    error // the *json.UnmarshalTypeError
}

func (e *ResultTypeError) Error() string {
	return fmt.Sprintf("decode result of 0x%04x: %v", e.Opcode, e.Err)
}

func (e *ResultTypeError) Unwrap() error { return e.Err }

func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

// ============================================================================
// NEGOTIATE 0x4001 (mesh/repository/q1.java:387-397)
// ============================================================================

// EnumUserRole wire values from the dex @SerializedName annotations
// (scratchpad/dexcheck/sn6.txt:404-406). jadx hides them; "ROLE_OWNER" is WRONG.
const (
	UserRoleOwner = "owner"
	UserRoleUser  = "user"
)

// NegotiationParams (bo/negotiation/params/NegotiationParams.java:8-9).
type NegotiationParams struct {
	Role     string `json:"role"`               // owner iff network.W() (q1.java:388)
	Username string `json:"username,omitempty"` // AccountDigest(cloudUserName) (q1.java:389-391)
}

// NegotiationResult (bo/negotiation/result/NegotiationResult.java:22-61, subset).
type NegotiationResult struct {
	ComponentList []struct {
		ID        string     `json:"id"`        // @SerializedName(value="id", alternate={"component"})
		Component string     `json:"component"` // NegotiationComponentBean.java:13-20
		VerCode   FlexInt    `json:"ver_code"`
		Lock      FlexString `json:"lock,omitempty"`
	} `json:"component_list"`
	OperationMode     Enum            `json:"operation_mode"` // "Router" (default, :48-49) | "AP" | ... (sn6.txt:393-403)
	WorkingStatus     Enum            `json:"working_status"` // default "well" (:51-52)
	EasyMeshRole      Enum            `json:"easymesh_role"`
	DeviceColor       FlexString      `json:"device_color"` // Java Strings: Gson also takes numbers
	FrontModem        FlexString      `json:"front_modem"`
	TopologyLimit     *FlexBool       `json:"topology_limit"` // Java Boolean: Gson also takes "true"
	AlertOpModeSwitch *FlexBool       `json:"alert_operation_mode_switch"`
	GroupData         json.RawMessage `json:"group_data"`
	HardwareInfo      json.RawMessage `json:"hardware_info"`
	Region            json.RawMessage `json:"region"`
	ExtraISP          json.RawMessage `json:"extra_isp"`
	EcoModeStatus     json.RawMessage `json:"eco_mode_status"`
	EcoModeAdvanced   FlexString      `json:"eco_mode_advanced_status"`
}

// HasComponent reports whether the negotiation lists a component id.
func (n *NegotiationResult) HasComponent(id string) bool {
	for _, c := range n.ComponentList {
		if c.ID == id || c.Component == id {
			return true
		}
	}
	return false
}

// AccountDigest = wf.d.d(): lowercase hex SHA-256 of String.getBytes()
// (wf/d.java:38-64; UTF-8 on Android, INFERRED).
func AccountDigest(cloudUserName string) string {
	s := sha256.Sum256([]byte(cloudUserName))
	return hex.EncodeToString(s[:])
}

// negotiateTolerated: the app swallows a TMPException (any error_code) and any
// AppBusinessV2LayerException except -3222 (q1.java:721-725,326-332,428-430).
func negotiateTolerated(err error) bool {
	var ae *AppError
	var be *BizError
	switch {
	case errors.As(err, &ae):
		return true
	case errors.As(err, &be):
		return be.Code <= -3200 && be.Code >= -3221
	}
	return false
}

// ============================================================================
// Client: one TMP session to one Deco (the master), with lazy reconnect
// ============================================================================

// Config describes how to reach one Deco. Build it from a TDP DecoInfo.
type Config struct {
	Host          string
	Port          int    // TDP tmp_port[0]; 20001 on the X20s (LIVE)
	SSHUser       string // DecoInfo.SSHUsername(CloudUserName)
	CloudUserName string // exact stored TP-Link ID string (md5 must equal TDP owner)
	CloudPassword Secret // never printed: Secret formats as [redacted]
	Owner         bool   // NEGOTIATE role owner; required for local access (TDPMeshDevice.java:123-129)
	TPS           bool   // DecoInfo.TPSBanner(); false on the X20s
	HostKey       ssh.HostKeyCallback
	// Heartbeat: 0 => DefaultHeartbeat; negative disables (t.java:180-182).
	Heartbeat time.Duration
	// RequestTimeout bounds one Call. The app uses timeout+15 s = 45 s around the whole
	// request (apps/network/tmp/i0.java:581) and no per-frame timeout. 0 => 45 s.
	// Opcodes the app gives a longer budget get at least that (AppRequestTimeout).
	RequestTimeout time.Duration
	// OpTimeouts overrides the budget of single opcodes (tests, live diagnosis).
	OpTimeouts map[uint16]time.Duration
	// Trace, if set, receives one line per TMP frame, per business packet and
	// per request (opcode, elapsed). Payloads, tokens and credentials are never
	// traced.
	Trace func(format string, args ...any)
	// SkipNegotiate omits NEGOTIATE (INFERRED optional; the app always sends it).
	SkipNegotiate bool
	// NoRedial makes a Call on a dead transport fail with a *TransportLostError
	// instead of redialling. Every redial costs one SSH password attempt, so an
	// owner that rate-limits logins (Mesh) sets this and reconnects itself.
	NoRedial bool
}

// Secret is a string that never formats or marshals its value. Use
// string(s) only where the plaintext is needed (ssh.Password).
type Secret string

func (Secret) String() string               { return "[redacted]" }
func (Secret) GoString() string             { return "[redacted]" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// TransportLostError is returned by Call with Config.NoRedial when the TMP
// stream is gone. Cause is why it died (a *ByeError, an I/O error, or nil).
type TransportLostError struct{ Cause error }

func (e *TransportLostError) Error() string {
	if e.Cause == nil {
		return "tmp: transport lost"
	}
	return "tmp: transport lost: " + e.Cause.Error()
}
func (e *TransportLostError) Unwrap() error { return e.Cause }

// Client owns the SSH connection, the TMP FrameConn and the business Session.
type Client struct {
	cfg  Config
	sess *Session

	mu    sync.Mutex
	sshc  *ssh.Client
	fc    *FrameConn
	cause error // why the last transport was dropped

	Negotiation    *NegotiationResult
	NegotiationErr error // a NEGOTIATE error the app would tolerate
}

// Connect dials, allocates a token and sends NEGOTIATE (bring-up order of
// q1.f0()/l0(), q1.java:387-397,717-737; token alloc precedes it via o.N()).
func Connect(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Port == 0 {
		cfg.Port = 20001
	}
	if cfg.Heartbeat == 0 {
		cfg.Heartbeat = DefaultHeartbeat
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 45 * time.Second
	}
	c := &Client{cfg: cfg}
	c.sess = &Session{RT: c, ResetTransport: c.dropTransport, Trace: cfg.Trace}
	if err := c.redial(ctx); err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
	defer cancel()
	if _, err := c.sess.Call(cctx, 0, nil); err != nil { // token alloc (o.java:436)
		c.Close()
		return nil, fmt.Errorf("token alloc: %w", err)
	}
	if cfg.SkipNegotiate {
		return c, nil
	}
	role := UserRoleUser
	if cfg.Owner {
		role = UserRoleOwner
	}
	np := NegotiationParams{Role: role}
	if cfg.CloudUserName != "" {
		np.Username = AccountDigest(cfg.CloudUserName)
	}
	var nr NegotiationResult
	if err := c.Call(ctx, OpNegotiation, np, &nr); err != nil {
		var te *ResultTypeError
		if errors.As(err, &te) {
			// A field the app's Gson would read leniently: keep what
			// decoded (json.Unmarshal fills every other field) and go on,
			// as the app does after a NEGOTIATE problem.
			c.Negotiation, c.NegotiationErr = &nr, err
			return c, nil
		}
		if !negotiateTolerated(err) {
			c.Close()
			return nil, fmt.Errorf("negotiate: %w", err)
		}
		c.NegotiationErr = err
		return c, nil
	}
	c.Negotiation = &nr
	return c, nil
}

func (c *Client) redial(ctx context.Context) error {
	dctx, cancel := context.WithTimeout(ctx, ConnectTimeout)
	defer cancel()
	sshc, ch, err := DialTMP(dctx, c.cfg.Host, c.cfg.Port,
		DecoSSHConfig(c.cfg.SSHUser, string(c.cfg.CloudPassword), c.cfg.HostKey, c.cfg.TPS))
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.sshc, c.fc, c.cause = sshc, NewFrameConnTrace(ch, c.cfg.Heartbeat, c.cfg.Trace), nil
	c.mu.Unlock()
	return nil
}

// dropTransport is Session.ResetTransport: close the stream; the next Call redials.
func (c *Client) dropTransport() {
	c.mu.Lock()
	fc, sshc := c.fc, c.sshc
	c.fc, c.sshc = nil, nil
	if fc != nil && c.cause == nil {
		c.cause = fc.Err() // nil while alive: a deliberate reset
		if c.cause == nil {
			c.cause = errors.New("tmp: layer reset")
		}
	}
	c.mu.Unlock()
	if fc != nil {
		_ = fc.Close()
	}
	if sshc != nil {
		_ = sshc.Close()
	}
}

// RoundTrip implements RoundTripper for the Session.
func (c *Client) RoundTrip(ctx context.Context, pkt []byte) ([]byte, error) {
	c.mu.Lock()
	fc := c.fc
	c.mu.Unlock()
	if fc == nil {
		return nil, errors.New("tmp: no transport")
	}
	return fc.RoundTrip(ctx, pkt)
}

// ensureTransport redials a dead stream and marks the token unverified, as the
// TMP error callback does (client/g.java:31-37 -> business/g.java:161-164 -> o.p()).
// Each redial costs one SSH password attempt: callers must rate-limit.
func (c *Client) ensureTransport(ctx context.Context) error {
	c.mu.Lock()
	fc := c.fc
	c.mu.Unlock()
	if fc != nil && fc.Alive() {
		return nil
	}
	c.dropTransport()
	if c.cfg.NoRedial {
		return &TransportLostError{Cause: c.Err()}
	}
	if err := c.redial(ctx); err != nil {
		return err
	}
	c.sess.Reset()
	return nil
}

// Err is nil while the TMP stream is alive; otherwise it is why the stream
// died (a *ByeError for a device BYE).
func (c *Client) Err() error {
	c.mu.Lock()
	fc, cause := c.fc, c.cause
	c.mu.Unlock()
	if fc != nil {
		return fc.Err()
	}
	if cause == nil {
		cause = errors.New("tmp: no transport")
	}
	return cause
}

// Alive reports whether the TMP stream can carry requests.
func (c *Client) Alive() bool { return c.Err() == nil }

// LastHeartbeatEcho is when the device last echoed a heartbeat (zero if never).
func (c *Client) LastHeartbeatEcho() time.Time {
	c.mu.Lock()
	fc := c.fc
	c.mu.Unlock()
	if fc == nil {
		return time.Time{}
	}
	return fc.LastHeartbeatEcho()
}

// Call sends one Deco JSON command. Get and Set are identical on the wire
// (repo/j.java:137-155 -> repo/d.java:279-297 -> i0.G0).
func (c *Client) Call(ctx context.Context, opcode uint16, params, out any) error {
	if err := ctx.Err(); err != nil {
		return err // the caller gave up: send nothing
	}
	budget := c.timeoutFor(opcode)
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	t0 := time.Now()
	if c.cfg.Trace != nil {
		c.cfg.Trace("trace: req 0x%04x start (budget %s)", opcode, budget)
	}
	err := c.call(ctx, opcode, params, out)
	if c.cfg.Trace != nil {
		res := "ok"
		if err != nil {
			res = "error: " + err.Error()
		}
		c.cfg.Trace("trace: req 0x%04x done in %s: %s", opcode, time.Since(t0).Round(time.Millisecond), res)
	}
	return err
}

func (c *Client) call(ctx context.Context, opcode uint16, params, out any) error {
	if err := c.ensureTransport(ctx); err != nil {
		return err
	}
	body, err := EncodeRequest(params, time.Now())
	if err != nil {
		return err
	}
	resp, err := c.sess.Call(ctx, opcode, body)
	if err != nil {
		return err
	}
	return DecodeResult(opcode, resp, out)
}

// timeoutFor is the whole-request budget for opcode: an OpTimeouts entry,
// else RequestTimeout, raised to the app's own budget for the opcodes the
// app waits longer for (0x4012: 75 s).
func (c *Client) timeoutFor(opcode uint16) time.Duration {
	if d, ok := c.cfg.OpTimeouts[opcode]; ok && d > 0 {
		return d
	}
	if _, long := appTimeouts[opcode]; long {
		return max(c.cfg.RequestTimeout, AppRequestTimeout(opcode))
	}
	return c.cfg.RequestTimeout
}

// CallRaw sends a pre-encoded JSON body and returns the raw response bytes.
func (c *Client) CallRaw(ctx context.Context, opcode uint16, body []byte) ([]byte, error) {
	if err := c.ensureTransport(ctx); err != nil {
		return nil, err
	}
	return c.sess.Call(ctx, opcode, body)
}

// Get is Call for read opcodes.
func (c *Client) Get(ctx context.Context, opcode uint16, params, out any) error {
	return c.Call(ctx, opcode, params, out)
}

// Set is Call for write opcodes; the result is kept raw (shape unverified).
func (c *Client) Set(ctx context.Context, opcode uint16, params any) (json.RawMessage, error) {
	var raw json.RawMessage
	err := c.Call(ctx, opcode, params, &raw)
	return raw, err
}

// Close: free token (opcode 3), then BYE, then close the transport
// (o.java:398-406; business/g.java:118-121; client/g.java:40-42; h0.java:422-431).
func (c *Client) Close() error {
	c.mu.Lock()
	fc := c.fc
	c.mu.Unlock()
	if fc != nil && fc.Alive() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = c.sess.Close(ctx)
		cancel()
	}
	c.dropTransport()
	return nil
}
