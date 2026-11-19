// SPDX-License-Identifier: GPL-2.0-or-later

// Package deco is an off-device client for the TP-Link Deco management protocol
// as spoken by the Deco Android app v3.10.666. It covers TDP discovery
// (discovery.go), SSH login and the TMP v1 frame layer (this file), the
// AppBusiness V2 layer and the JSON envelope (business.go), and the JSON beans
// (schemas.go).
//
// Paths in comments are relative to deco-jadx/out/sources/ unless prefixed.
// INFERRED marks behaviour that was not read directly from code.
//
// Stack:
//
//	SSH (dropbear, TCP tmp_port[0]=20001)
//	  -> direct-tcpip channel to 127.0.0.1:20002
//	  -> TMP v1 frames (4-byte short frames, 16-byte data header, serial, CRC32)
//	  -> AppBusiness V2 packets (20-byte header, token, transactions, 8156-byte chunks)
//	  -> UTF-8 JSON {"config_version":ms,"params":P} / {"error_code":n,"msg":s,"result":R}
package deco

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// ============================================================================
// SSH transport (com/tplink/apps/network/manager/repo/t.java:174-193 G();
// com/tplink/ssh2/k0.java; com/jcraft/jsch/*)
// ============================================================================

const (
	// TMP endpoint inside the Deco. The app calls setPortForwardingL(0,"127.0.0.1",20002)
	// (com/tplink/ssh2/k0.java:60-63; lk/g.java:42); on the wire that is one SSH
	// direct-tcpip channel to 127.0.0.1:20002 (ChannelDirectTCPIP.java:12-15,57-70).
	TMPForwardHost = "127.0.0.1"
	TMPForwardPort = 20002

	// JSch 0.1.54 default ident (com/jcraft/jsch/Session.java:88; JSch.java:13).
	JSchClientVersion = "SSH-2.0-JSCH-0.1.54"
	// TDP banner_type==1 devices: setClientVersion("TPS"+"-2.0-JSCH-"+VERSION) replaces
	// the whole ident line (com/tplink/ssh2/k0.java:136-139; Session.java:1616-1618).
	// Not used by the X20s (no banner_type in TDP, LIVE).
	TPSClientVersion = "TPS-2.0-JSCH-0.1.54"

	// Overall transport-connect timeout: t.java:191 m(ctx.o()) = 30000 ms
	// (manager/context/a.java:417-419; tmp/transport/k.java:180-182).
	ConnectTimeout = 30 * time.Second

	// Heartbeat interval: t.java:180-182 n(3000), or -1 (off) for factory-default devices.
	DefaultHeartbeat = 3 * time.Second
)

// DecoSSHConfig returns an x/crypto/ssh config matching what the X20 dropbear
// offered on 2026-11-18 (LIVE: kex ecdh-sha2-nistp{256,384,521},
// diffie-hellman-group14-sha256; hostkey ecdsa-sha2-nistp521, ssh-rsa; ciphers
// aes128-ctr, aes256-ctr; MACs hmac-sha2-256, hmac-sha2-512; auth publickey,password).
//
// sshUser must come from DecoInfo.SSHUsername(cloudUserName). For the X20s
// (need_account_digest=true, no tpap) that is lowercase hex SHA-1 of the TP-Link ID
// string (com/tplink/libtpnetwork/mesh/global/y.java:374-382; dj/a.java:211-221,242-254),
// NOT the e-mail. cloudPassword is TCAccountBean.password in plaintext
// (t.java:509-514; com/tplink/ssh2/m0.java:13-25).
func DecoSSHConfig(sshUser, cloudPassword string, hostKeyCB ssh.HostKeyCallback, tps bool) *ssh.ClientConfig {
	ver := JSchClientVersion
	if tps {
		// x/crypto/ssh only accepts a server banner starting "SSH-"; a TPS device
		// would need a custom transport (TPSSession.java:47-378).
		ver = TPSClientVersion
	}
	if hostKeyCB == nil {
		// The app accepts any key: StrictHostKeyChecking=ask (JSch.java:86) with
		// promptYesNo()=true (com/tplink/ssh2/m0.java:42-45). Prefer PinnedHostKey.
		hostKeyCB = ssh.InsecureIgnoreHostKey()
	}
	return &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges: []string{"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha256"},
			Ciphers: []string{"aes128-ctr", "aes256-ctr"},
			MACs:    []string{"hmac-sha2-256", "hmac-sha2-512"},
		},
		User: sshUser,
		// Exactly one password attempt (wrapper choice). The app re-sends the same
		// password up to MaxAuthTries=2 (com/tplink/ssh2/k0.java:128;
		// TPUserAuthPasswordMethods.java:107,207-211) unless the USERAUTH_FAILURE list
		// carries lockout tokens (TPUserAuthPasswordMethods.java:16-17,35-52,204-206).
		Auth:              []ssh.AuthMethod{ssh.Password(cloudPassword)},
		HostKeyCallback:   hostKeyCB,
		HostKeyAlgorithms: []string{ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA},
		ClientVersion:     ver,
		Timeout:           ConnectTimeout,
	}
}

// DialTMP opens SSH to host:port and returns the SSH client plus the direct-tcpip
// channel to 127.0.0.1:20002, i.e. the raw TMP byte stream.
func DialTMP(ctx context.Context, host string, port int, cfg *ssh.ClientConfig) (*ssh.Client, net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := net.Dialer{Timeout: cfg.Timeout}
	tcp, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	if tc, ok := tcp.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true) // TPSSession.java:94
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = tcp.SetDeadline(dl)
	}
	c, chans, reqs, err := ssh.NewClientConn(tcp, addr, cfg)
	if err != nil {
		tcp.Close()
		err = fmt.Errorf("deco ssh %s: %w", addr, err)
		if isAuthFailure(err) {
			return nil, nil, &AuthError{Err: err}
		}
		return nil, nil, err
	}
	_ = tcp.SetDeadline(time.Time{})
	client := ssh.NewClient(c, chans, reqs)
	// JSch sends originator 127.0.0.1:<local port> (ChannelDirectTCPIP.java:57-68).
	ch, err := client.DialTCP("tcp",
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		&net.TCPAddr{IP: net.ParseIP(TMPForwardHost), Port: TMPForwardPort})
	if err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("deco direct-tcpip 127.0.0.1:20002: %w", err)
	}
	return client, ch, nil
}

// PinnedHostKey accepts only the given SHA256 fingerprints. LIVE ecdsa-sha2-nistp521 keys:
//
//	192.168.0.205 SHA256:iL5AgxP1yb8O/JT6zcvdcrO4c/r8GZrSUknS4BdeH+A
//	192.168.0.232 SHA256:jIkTACXVqZ/UUL8MwuIiZINvYyt+7cbH9VLg2NfZNSo
//	192.168.0.241 SHA256:wcQkT6FKAB+PxFEAkHQhV3++pQsPCk9bNpU+4EfN4b4
func PinnedHostKey(fingerprints ...string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		for _, want := range fingerprints {
			if fp == want {
				return nil
			}
		}
		return &HostKeyError{Got: fp}
	}
}

// HostKeyError: the device presented a host key that is not pinned. The
// password is never sent in this case (the host key is checked before auth).
type HostKeyError struct{ Got string }

func (e *HostKeyError) Error() string { return "deco host key mismatch: " + e.Got }

// AuthError: the device rejected the SSH login. TP-Link IDs lock out after
// repeated failures (USERAUTH_FAILURE tokens lockedMinute/remainAttempts,
// TPUserAuthPasswordMethods.java:16-17,35-52), so callers must not retry.
// The wrapped error never contains the password.
type AuthError struct{ Err error }

func (e *AuthError) Error() string { return "deco login rejected: " + e.Err.Error() }
func (e *AuthError) Unwrap() error { return e.Err }

// isAuthFailure matches x/crypto/ssh's client-side "no auth method left"
// error (client_auth.go), which it does not export as a type.
func isAuthFailure(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unable to authenticate")
}

// ============================================================================
// TMP v1 frame layer (com/tplink/tmp/tmp/h0.java, com/tplink/tmp/v1/b.java, xk/*)
// ============================================================================

const (
	tmpVer    = 0x01 // v1/b.java:46-48 super((byte)1,(byte)1)
	tmpSubVer = 0x01

	TMPTypeAssocReq    = 1 // xk/a.java; never sent by v1 (v1/b.java:80-83)
	TMPTypeAssocAccept = 2
	TMPTypeAssocRefuse = 3
	TMPTypeHeartbeat   = 4
	TMPTypeData        = 5
	TMPTypeBye         = 6

	tmpDataHdrLen = 16
	tmpCRCPreset  = 0x5A6B7C8D // 1516993677, xk/b.java:13; h0.java:391-402
	tmpMaxPayload = 0xFFFF     // u16 length field (xk/b.java:51-70)
)

// TMPLayerError is a non-zero errcode byte [7] in a data reply (h0.java:333-363;
// TMPLayerException.java:26-57).
type TMPLayerError struct{ Code byte }

func (e *TMPLayerError) Error() string {
	n := map[byte]string{2: "CONFIG_VERSION(-2012)", 3: "CONFIG_PAYLOAD_LEN(-2013)",
		4: "CONFIG_SN(-2014)", 5: "CONFIG_CHECKSUM(-2015)"}[e.Code]
	if n == "" {
		n = "CONFIG_FAILED(-2011)"
	}
	return "tmp: device rejected frame: " + n
}

// ByeError: device sent type 6; reason is byte [3] (v1/b.java:50-78,102-107;
// TMPLayerV1Exception.java:46-56). Any received BYE tears the layer down.
type ByeError struct{ Reason byte }

func (e *ByeError) Error() string {
	n := map[byte]string{0: "NO_REASON", 2: "HEART_BEAT_TIME_OUT", 3: "CLIENT_LIMIT",
		4: "SYSTEM_REBOOT", 5: "WIRELESS_DOWN", 6: "SYSTEM_UPGRADE", 7: "USER_COUNT_EXCEED",
		8: "AUTH_CHANGED", 16: "KICK_OUT", 17: "COMPONENT_CHANGED"}[e.Reason]
	if n == "" {
		n = "UNKNOWN_REASON"
	}
	return fmt.Sprintf("tmp: device sent BYE reason %d (%s)", e.Reason, n)
}

// EncodeDataFrame builds a type-5 frame: [1,1,5,0][len u16][flags 0][errcode 0]
// [serial u32][crc u32] || payload, CRC32/IEEE over the whole frame with the CRC
// field preset to 0x5A6B7C8D (h0.java:391-402,449-454; xk/b.java:51-70).
func EncodeDataFrame(serial uint32, payload []byte) []byte {
	f := make([]byte, tmpDataHdrLen+len(payload))
	f[0], f[1], f[2], f[3] = tmpVer, tmpSubVer, TMPTypeData, 0
	binary.BigEndian.PutUint16(f[4:], uint16(len(payload)))
	binary.BigEndian.PutUint32(f[8:], serial)
	binary.BigEndian.PutUint32(f[12:], tmpCRCPreset)
	copy(f[16:], payload)
	binary.BigEndian.PutUint32(f[12:], crc32.ChecksumIEEE(f))
	return f
}

// ShortFrame: v1 sends heartbeat and bye as 4 bytes with no serial (v1/b.java:85-100).
func ShortFrame(typ byte) []byte { return []byte{tmpVer, tmpSubVer, typ, 0} }

// Frame is one received TMP frame.
type Frame struct {
	Type, Reserved, Flags, ErrCode byte
	Serial                         uint32
	Payload                        []byte
}

// ReadFrame reads one frame (h0.java:185-207,433-446; v1/b.java:85-91): types 1-4
// and 6 are 4 bytes, type 5 is 16+len; other types are -2003; CRC mismatch -2004
// (h0.java:350-356,614-626).
func ReadFrame(r io.Reader) (*Frame, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	if h[0] != tmpVer {
		return nil, fmt.Errorf("tmp: bad main version %d (-2001)", h[0])
	}
	if h[1] != tmpSubVer {
		return nil, fmt.Errorf("tmp: bad sub version %d (-2002)", h[1])
	}
	fr := &Frame{Type: h[2], Reserved: h[3]}
	switch fr.Type {
	case TMPTypeAssocReq, TMPTypeAssocAccept, TMPTypeAssocRefuse, TMPTypeHeartbeat, TMPTypeBye:
		return fr, nil
	case TMPTypeData:
	default:
		return nil, fmt.Errorf("tmp: bad control code %d (-2003)", fr.Type)
	}
	var rest [12]byte
	if _, err := io.ReadFull(r, rest[:]); err != nil {
		return nil, err
	}
	plen := int(binary.BigEndian.Uint16(rest[0:]))
	fr.Flags, fr.ErrCode = rest[2], rest[3]
	fr.Serial = binary.BigEndian.Uint32(rest[4:])
	got := binary.BigEndian.Uint32(rest[8:])
	fr.Payload = make([]byte, plen)
	if _, err := io.ReadFull(r, fr.Payload); err != nil {
		return nil, err
	}
	whole := make([]byte, 0, tmpDataHdrLen+plen)
	whole = append(append(append(whole, h[:]...), rest[:]...), fr.Payload...)
	binary.BigEndian.PutUint32(whole[12:], tmpCRCPreset)
	if crc32.ChecksumIEEE(whole) != got {
		return nil, errors.New("tmp: bad checksum (-2004)")
	}
	return fr, nil
}

// FrameConn is the TMP v1 layer over one byte stream. It implements RoundTripper
// (business.go): one business packet per DATA frame, reply matched by serial only
// (h0.java:144-156,172-182). Safe for concurrent use; the business Session uses
// window=1 anyway.
type FrameConn struct {
	rw        io.ReadWriteCloser
	rd        io.Reader // rw, counting bytes into rx
	heartbeat time.Duration
	trace     func(format string, args ...any) // nil: off
	start     time.Time

	rx         atomic.Int64 // bytes read from the stream
	frameStart atomic.Int64 // rx when the frame being read began
	unmatched  atomic.Int64 // DATA frames with no waiter (late, duplicate or unknown serial)

	wmu     sync.Mutex
	mu      sync.Mutex
	serial  uint32 // per-layer AtomicInteger(1) (h0.java:37,158-160)
	wait    map[uint32]chan *Frame
	inflt   int
	dead    error
	lastHB  time.Time // last type-4 echo received (INFERRED that the device echoes; h0.java:111-123)
	idle    chan struct{}
	done    chan struct{}
	closeMu sync.Once
}

// NewFrameConn starts the read loop and the idle-edge heartbeat. heartbeat<=0
// disables heartbeats (t.java:180-182; h0.java:137). v1 sends no association
// frames: the layer is CONNECTED as soon as the stream exists (v1/b.java:80-83;
// h0.java:261-267,380-389).
func NewFrameConn(rw io.ReadWriteCloser, heartbeat time.Duration) *FrameConn {
	return NewFrameConnTrace(rw, heartbeat, nil)
}

// NewFrameConnTrace is NewFrameConn with a frame tracer: one line per frame
// sent or received (type, serial, length, flags, errcode). Payload bytes are
// never traced.
func NewFrameConnTrace(rw io.ReadWriteCloser, heartbeat time.Duration, trace func(string, ...any)) *FrameConn {
	c := &FrameConn{rw: rw, heartbeat: heartbeat, trace: trace, start: time.Now(), serial: 1,
		wait: map[uint32]chan *Frame{}, idle: make(chan struct{}, 1), done: make(chan struct{})}
	c.rd = countReader{r: rw, n: &c.rx}
	go c.readLoop()
	go c.heartbeatLoop()
	c.signalIdle() // h0.java:245-259: interval(0, ms) starts while idle
	return c
}

// RoundTrip sends one DATA frame and waits for the reply with the same serial.
// Mesh sets no per-frame timeout (mesh/context/c.java:848-851 M()=0;
// h0.java:319-321); the ctx deadline is the caller's whole-request deadline.
func (c *FrameConn) RoundTrip(ctx context.Context, payload []byte) ([]byte, error) {
	if len(payload) > tmpMaxPayload {
		return nil, fmt.Errorf("tmp: payload %d exceeds u16 length", len(payload))
	}
	if err := ctx.Err(); err != nil {
		// Never hand the device a request nobody will wait for: it would
		// still run it, ahead of whatever comes next on this stream.
		return nil, fmt.Errorf("tmp: not sent: %w", err)
	}
	c.mu.Lock()
	if c.dead != nil {
		err := c.dead
		c.mu.Unlock()
		return nil, err
	}
	s := c.serial
	c.serial++
	ch := make(chan *Frame, 1)
	c.wait[s] = ch
	c.inflt++
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.wait, s)
		c.inflt--
		idle := c.inflt == 0
		c.mu.Unlock()
		if idle { // h0.java:134-142: heartbeat (re)starts when the last request finishes
			c.signalIdle()
		}
	}()
	if err := c.write(EncodeDataFrame(s, payload)); err != nil {
		c.fail(err)
		return nil, err
	}
	c.tracef("tx DATA serial=%d len=%d", s, len(payload))
	sent := time.Now()
	select {
	case fr := <-ch:
		if fr.ErrCode != 0 { // h0.java:350-362
			return nil, &TMPLayerError{Code: fr.ErrCode}
		}
		return fr.Payload, nil
	case <-ctx.Done():
		if c.trace != nil {
			c.tracef("serial=%d no reply after %s: %s", s, time.Since(sent).Round(time.Millisecond), c.readerState())
		}
		return nil, fmt.Errorf("tmp: waiting for serial %d: %w", s, ctx.Err())
	case <-c.done:
		return nil, c.Err()
	}
}

// Err returns the reason the layer died, or nil while alive.
func (c *FrameConn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead == nil {
		select {
		case <-c.done:
			return io.ErrClosedPipe
		default:
		}
	}
	return c.dead
}

// Alive reports whether the layer can still carry requests.
func (c *FrameConn) Alive() bool { return c.Err() == nil }

// LastHeartbeatEcho is the time of the last type-4 frame received (zero if none).
func (c *FrameConn) LastHeartbeatEcho() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastHB
}

func (c *FrameConn) signalIdle() {
	select {
	case c.idle <- struct{}{}:
	default:
	}
}

func (c *FrameConn) write(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.rw.Write(b)
	return err
}

func (c *FrameConn) fail(err error) {
	if err == nil {
		err = io.ErrClosedPipe
	}
	c.mu.Lock()
	if c.dead == nil {
		c.dead = err
	}
	c.mu.Unlock()
	c.closeMu.Do(func() { close(c.done); _ = c.rw.Close() })
}

// readLoop hands each DATA frame to the waiter with its serial. Like the
// app, which publishes every frame to a PublishSubject that each request
// filters by serial (h0.java:144-156,172-182,219-225,552-577), it never
// blocks: a frame nobody waits for (a late reply, an unknown serial, a
// duplicate) is dropped, and counted.
func (c *FrameConn) readLoop() {
	for {
		c.frameStart.Store(c.rx.Load())
		fr, err := ReadFrame(c.rd)
		if err != nil {
			c.tracef("rx error after %d bytes: %v", c.rx.Load(), err)
			c.fail(err)
			return
		}
		switch fr.Type {
		case TMPTypeData:
			// The first frame for a serial claims its waiter: a copy that
			// follows finds none and is counted, even when the waiter has
			// already taken the first one from its buffer but RoundTrip has
			// not yet removed it (that copy used to land in the emptied
			// buffer, uncounted).
			c.mu.Lock()
			ch := c.wait[fr.Serial]
			delete(c.wait, fr.Serial)
			c.mu.Unlock()
			delivered := false
			if ch != nil {
				select {
				case ch <- fr:
					delivered = true
				default: // cannot happen: only the reader sends, once per waiter
				}
			}
			if !delivered {
				c.unmatched.Add(1)
			}
			if c.trace != nil {
				note := ""
				if !delivered { // late, a duplicate, or an unknown serial
					note = " NO-WAITER(dropped)"
				}
				c.tracef("rx DATA serial=%d len=%d flags=%d errcode=%d%s%s",
					fr.Serial, len(fr.Payload), fr.Flags, fr.ErrCode, v2Brief(fr.Payload), note)
			}
		case TMPTypeHeartbeat:
			c.tracef("rx HEARTBEAT")
			c.mu.Lock()
			c.lastHB = time.Now()
			c.mu.Unlock()
		case TMPTypeBye: // h0.java:203-205; v1/b.java:102-107
			c.tracef("rx BYE reason=%d", fr.Reserved)
			c.fail(&ByeError{Reason: fr.Reserved})
			return
		default:
			c.tracef("rx type=%d (ignored)", fr.Type)
		}
	}
}

// heartbeatLoop mirrors h0.java:134-142,163-170,245-259: interval(0, ms) armed on
// the idle edge (first beat immediately), cancelled while a request is in flight.
// The app waits for a type-4 echo with no timeout (h0.java:111-123,319-321); this
// loop does not wait, it only records echoes in lastHB.
func (c *FrameConn) heartbeatLoop() {
	if c.heartbeat <= 0 {
		return
	}
	for {
		select {
		case <-c.done:
			return
		case <-c.idle:
		}
		t := time.NewTicker(c.heartbeat)
		for beat := true; ; beat = false {
			if !beat {
				select {
				case <-c.done:
					t.Stop()
					return
				case <-t.C:
				}
			}
			c.mu.Lock()
			idle := c.inflt == 0
			c.mu.Unlock()
			if !idle {
				break
			}
			if err := c.write(ShortFrame(TMPTypeHeartbeat)); err != nil {
				t.Stop()
				c.fail(err)
				return
			}
			c.tracef("tx HEARTBEAT")
		}
		t.Stop()
	}
}

// Close sends BYE [1,1,6,0] if alive (fire-and-forget, h0.java:422-431,505-512)
// and closes the stream.
func (c *FrameConn) Close() error {
	if c.Alive() {
		_ = c.write(ShortFrame(TMPTypeBye))
		c.tracef("tx BYE (rx %d bytes, %d unmatched frame(s))", c.rx.Load(), c.unmatched.Load())
	}
	c.fail(io.ErrClosedPipe)
	return nil
}

// Unmatched is how many DATA frames arrived with no waiter for their serial
// (late replies, unknown serials, duplicates) and were dropped.
func (c *FrameConn) Unmatched() int64 { return c.unmatched.Load() }

func (c *FrameConn) tracef(format string, args ...any) {
	if c.trace == nil {
		return
	}
	el := time.Since(c.start).Seconds()
	c.trace("trace: tmp +%.3fs "+format, append([]any{el}, args...)...)
}

// readerState says where the read loop is: idle at a frame boundary, or
// partway through a frame (the device sent fewer bytes than it announced).
func (c *FrameConn) readerState() string {
	rx, fs := c.rx.Load(), c.frameStart.Load()
	if rx == fs {
		return fmt.Sprintf("reader idle at a frame boundary, rx %d bytes, %d unmatched frame(s)", rx, c.unmatched.Load())
	}
	return fmt.Sprintf("reader MID-FRAME: %d byte(s) of the current frame read, rx %d bytes, %d unmatched frame(s)",
		rx-fs, rx, c.unmatched.Load())
}

// v2Brief summarises the AppBusiness V2 header of a DATA payload for the
// frame trace (header fields only, never the body).
func v2Brief(p []byte) string {
	if len(p) < V2HeaderLen {
		return ""
	}
	return fmt.Sprintf(" [v2 %s opcode=0x%04x tid=%d status=%d total=%d start=%d]", v2OpName(p[4]),
		binary.BigEndian.Uint16(p[2:]), binary.BigEndian.Uint16(p[6:]), p[5],
		binary.BigEndian.Uint32(p[12:]), binary.BigEndian.Uint32(p[16:]))
}

type countReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}
