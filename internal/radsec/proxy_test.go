// SPDX-License-Identifier: GPL-2.0-or-later

package radsec

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const serverSecret = "server-shared-secret-for-tests"

// tServer is a RadSec server: TLS with client certificates required, the
// answer built by reply (nil = drop it).
type tServer struct {
	t     *testing.T
	ln    net.Listener
	reply func(c net.Conn, req []byte) []byte
	conns atomic.Int32
	mu    sync.Mutex
	reqs  [][]byte
	close bool // close each connection after its first answer
}

func newServer(t *testing.T, p *pki, reply func(net.Conn, []byte) []byte) *tServer {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{p.srv}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: p.cliPool, MinVersion: tls.VersionTLS12}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &tServer{t: t, ln: ln, reply: reply}
	go s.accept()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *tServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *tServer) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.conns.Add(1)
		go func() {
			defer c.Close()
			for {
				hdr := make([]byte, 4)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				b := make([]byte, binary.BigEndian.Uint16(hdr[2:]))
				copy(b, hdr)
				if _, err := io.ReadFull(c, b[4:]); err != nil {
					return
				}
				s.mu.Lock()
				s.reqs = append(s.reqs, b)
				s.mu.Unlock()
				if out := s.reply(c, b); out != nil {
					c.Write(out)
					if s.close {
						return
					}
				}
			}
		}()
	}
}

func (s *tServer) requests() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.reqs...)
}

// accept answers an Access-Request with Access-Accept carrying MS-MPPE keys
// and a Message-Authenticator, and an Accounting-Request with a response.
var recvKey = bytes.Repeat([]byte{0xa5}, 32)
var sendKey = bytes.Repeat([]byte{0x5a}, 32)

func acceptAll(_ net.Conn, req []byte) []byte {
	sec := []byte(serverSecret)
	ra := req[4:20]
	switch req[0] {
	case codeAccessRequest:
		out := build(codeAccessAccept, req[1], ra,
			attr{26, mppe(msMPPERecvKey, recvKey, ra, []byte{0x80, 0x01}, sec)},
			attr{26, mppe(msMPPESendKey, sendKey, ra, []byte{0x80, 0x02}, sec)},
			attr{80, make([]byte, 16)})
		tMA(out, ra, sec)
		tRespAuth(out, ra, sec)
		return out
	case codeAccountingRequest:
		out := build(codeAccountingResponse, req[1], ra)
		tRespAuth(out, ra, sec)
		return out
	}
	return nil
}

type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuf) logf(f string, a ...any) {
	l.mu.Lock()
	fmt.Fprintf(&l.b, f+"\n", a...)
	l.mu.Unlock()
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func testProxy(t *testing.T, mod func(*Options)) (*Proxy, *logBuf) {
	t.Helper()
	lb := &logBuf{}
	o := Options{Logf: lb.logf, BasePort: 20000 + int(time.Now().UnixNano()%20000), PortSpan: 50,
		Stall: 600 * time.Millisecond, Expire: 3 * time.Second, Idle: time.Minute,
		BackoffMin: 200 * time.Millisecond, BackoffMax: time.Second, ConnectTimeout: 3 * time.Second}
	if mod != nil {
		mod(&o)
	}
	p := New(context.Background(), o)
	t.Cleanup(p.Close)
	return p, lb
}

func endpointFor(t *testing.T, p *Proxy, s Server) Endpoint {
	t.Helper()
	eps, errs := p.Set([]Server{s})
	if err := errs[s.Key()]; err != nil {
		t.Fatalf("Set: %v", err)
	}
	ep, ok := eps[s.Key()]
	if !ok || ep.IP != "127.0.0.1" || ep.Port == 0 || len(ep.Secret) != 32 {
		t.Fatalf("endpoint %v", ep)
	}
	return ep
}

// hostapd is a UDP RADIUS client like hostapd's.
type hostapd struct {
	t  *testing.T
	c  *net.UDPConn
	ep Endpoint
}

func newHostapd(t *testing.T, ep Endpoint) *hostapd {
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(ep.IP), Port: ep.Port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &hostapd{t: t, c: c, ep: ep}
}

func (h *hostapd) send(p []byte) { h.c.Write(p) }

func (h *hostapd) recv(wait time.Duration) []byte {
	h.c.SetReadDeadline(time.Now().Add(wait))
	b := make([]byte, 5000)
	n, err := h.c.Read(b)
	if err != nil {
		return nil
	}
	return b[:n]
}

func (h *hostapd) accessRequest(id byte, password string) ([]byte, []byte) {
	ra := randBytes(16)
	ls := []byte(h.ep.Secret)
	p := build(codeAccessRequest, id, ra,
		attr{1, []byte("user@example")},
		attr{2, hide([]byte(password), ra, ls)},
		attr{79, []byte{2, 1, 0, 9, 1, 'u', 's', 'e', 'r'}}, // EAP-Response/Identity
		attr{80, make([]byte, 16)})
	tMA(p, ra, ls)
	return p, ra
}

func TestAccessRoundTrip(t *testing.T) {
	k := newPKI(t, "127.0.0.1")
	srv := newServer(t, k, acceptAll)
	p, lb := testProxy(t, nil)
	s := Server{Host: "127.0.0.1", Port: srv.port(), Secret: serverSecret, TLS: k.material()}
	ep := endpointFor(t, p, s)
	if ep.Secret == serverSecret || strings.Contains(ep.String(), ep.Secret) {
		t.Fatal("hostapd's secret must differ from the server's and never print")
	}
	h := newHostapd(t, ep)
	req, ra := h.accessRequest(77, "pap-password")
	h.send(req)
	resp := h.recv(3 * time.Second)
	if resp == nil {
		t.Fatalf("no answer; log:\n%s", lb)
	}
	ls := []byte(ep.Secret)
	if resp[0] != codeAccessAccept || resp[1] != 77 {
		t.Fatalf("answer code %d id %d", resp[0], resp[1])
	}
	if !tRespAuthOK(resp, ra, ls) || !tMAOK(resp, ra, ls) {
		t.Fatal("answer not signed for hostapd's secret")
	}
	if got := mppeKey(findVSA(resp, msMPPERecvKey), ra, ls); !bytes.Equal(got, recvKey) {
		t.Fatalf("MS-MPPE-Recv-Key re-encrypted wrongly: %x", got)
	}
	if got := mppeKey(findVSA(resp, msMPPESendKey), ra, ls); !bytes.Equal(got, sendKey) {
		t.Fatalf("MS-MPPE-Send-Key re-encrypted wrongly: %x", got)
	}
	// what the server saw: signed for its own secret, password readable
	got := srv.requests()
	if len(got) != 1 {
		t.Fatalf("server saw %d requests", len(got))
	}
	sec := []byte(serverSecret)
	if !tMAOK(got[0], got[0][4:20], sec) {
		t.Fatal("request not signed for the server's secret")
	}
	if pw := bytes.TrimRight(unhide(findAttr(got[0], 2), got[0][4:20], sec), "\x00"); string(pw) != "pap-password" {
		t.Fatalf("User-Password re-encrypted wrongly: %q", pw)
	}
	if !strings.Contains(lb.String(), "connected (TLS 1.3") {
		t.Fatalf("log: %s", lb)
	}
}

func TestAccountingRoundTrip(t *testing.T) {
	k := newPKI(t, "127.0.0.1")
	srv := newServer(t, k, acceptAll)
	p, _ := testProxy(t, nil)
	ep := endpointFor(t, p, Server{Host: "127.0.0.1", Port: srv.port(), Secret: serverSecret, TLS: k.material()})
	h := newHostapd(t, ep)
	ls := []byte(ep.Secret)
	req := build(codeAccountingRequest, 9, make([]byte, 16), attr{40, []byte{0, 0, 0, 1}}, attr{44, []byte("sess-1")})
	tAcctAuth(req, ls)
	h.send(req)
	resp := h.recv(3 * time.Second)
	if resp == nil || resp[0] != codeAccountingResponse || resp[1] != 9 || !tRespAuthOK(resp, req[4:20], ls) {
		t.Fatalf("accounting answer %x", resp)
	}
	got := srv.requests()[0]
	want := append([]byte(nil), got...)
	tAcctAuth(want, []byte(serverSecret))
	if !bytes.Equal(want[4:20], got[4:20]) {
		t.Fatal("Accounting-Request not signed for the server's secret")
	}
}

func TestBadLocalRequestsDropped(t *testing.T) {
	k := newPKI(t, "127.0.0.1")
	srv := newServer(t, k, acceptAll)
	p, lb := testProxy(t, nil)
	ep := endpointFor(t, p, Server{Host: "127.0.0.1", Port: srv.port(), Secret: serverSecret, TLS: k.material()})
	h := newHostapd(t, ep)
	// signed with the wrong secret
	ra := randBytes(16)
	bad := build(codeAccessRequest, 1, ra, attr{1, []byte("u")}, attr{80, make([]byte, 16)})
	tMA(bad, ra, []byte("not-the-local-secret"))
	h.send(bad)
	// no Message-Authenticator at all
	h.send(build(codeAccessRequest, 2, randBytes(16), attr{1, []byte("u")}))
	// accounting with a bad authenticator
	acct := build(codeAccountingRequest, 3, randBytes(16), attr{40, []byte{0, 0, 0, 1}})
	h.send(acct)
	// a code the proxy does not carry
	h.send(build(codeAccessAccept, 4, randBytes(16)))
	// truncated
	h.send([]byte{1, 5, 0, 30, 1, 2})
	if r := h.recv(700 * time.Millisecond); r != nil {
		t.Fatalf("answer to a bad request: %x", r)
	}
	if n := len(srv.requests()); n != 0 {
		t.Fatalf("server saw %d bad requests", n)
	}
	if !strings.Contains(lb.String(), "refused") {
		t.Fatalf("log: %s", lb)
	}
}

func TestUnsignedOrForgedAnswersDropped(t *testing.T) {
	k := newPKI(t, "127.0.0.1")
	mode := atomic.Int32{}
	srv := newServer(t, k, func(c net.Conn, req []byte) []byte {
		sec := []byte(serverSecret)
		switch mode.Load() {
		case 0: // no Message-Authenticator (BlastRADIUS shape)
			out := build(codeAccessAccept, req[1], req[4:20])
			tRespAuth(out, req[4:20], sec)
			return out
		case 1: // signed with another secret
			out := build(codeAccessAccept, req[1], req[4:20], attr{80, make([]byte, 16)})
			tMA(out, req[4:20], []byte("other"))
			tRespAuth(out, req[4:20], []byte("other"))
			return out
		default: // an Accounting-Response to an Access-Request
			out := build(codeAccountingResponse, req[1], req[4:20])
			tRespAuth(out, req[4:20], sec)
			return out
		}
	})
	p, lb := testProxy(t, nil)
	ep := endpointFor(t, p, Server{Host: "127.0.0.1", Port: srv.port(), Secret: serverSecret, TLS: k.material()})
	h := newHostapd(t, ep)
	for m := int32(0); m < 3; m++ {
		mode.Store(m)
		req, _ := h.accessRequest(byte(10+m), "x")
		h.send(req)
		if r := h.recv(700 * time.Millisecond); r != nil {
			t.Fatalf("mode %d: a bad answer reached hostapd", m)
		}
	}
	if !strings.Contains(lb.String(), "failed verification") {
		t.Fatalf("log: %s", lb)
	}
}

func TestServerCertificateChecks(t *testing.T) {
	cases := []struct {
		name string
		srv  func(t *testing.T) (*pki, *pki) // the server's PKI, the PKI given to the proxy
		want string
	}{
		{"IP not in the certificate", func(t *testing.T) (*pki, *pki) {
			k := newPKI(t, "10.9.9.9") // DNS name and another IP only
			return k, k
		}, "certificate"},
		{"untrusted CA", func(t *testing.T) (*pki, *pki) {
			return newPKI(t, "127.0.0.1"), newPKI(t, "127.0.0.1")
		}, "certificate"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sk, ck := c.srv(t)
			srv := newServer(t, sk, acceptAll)
			p, lb := testProxy(t, nil)
			ep := endpointFor(t, p, Server{Host: "127.0.0.1", Port: srv.port(), Secret: serverSecret, TLS: ck.material()})
			h := newHostapd(t, ep)
			req, _ := h.accessRequest(1, "x")
			h.send(req)
			if r := h.recv(time.Second); r != nil {
				t.Fatal("answer through an unverified server")
			}
			if len(srv.requests()) != 0 {
				t.Fatal("request sent to an unverified server")
			}
			if l := lb.String(); !strings.Contains(l, "connect failed") || !strings.Contains(l, c.want) {
				t.Fatalf("log: %s", l)
			}
		})
	}
}

func TestReconnectAfterServerClose(t *testing.T) {
	k := newPKI(t, "127.0.0.1")
	srv := newServer(t, k, acceptAll)
	srv.close = true
	p, lb := testProxy(t, nil)
	ep := endpointFor(t, p, Server{Host: "127.0.0.1", Port: srv.port(), Secret: serverSecret, TLS: k.material()})
	h := newHostapd(t, ep)
	for i := byte(1); i <= 3; i++ {
		req, _ := h.accessRequest(i, "x")
		var r []byte
		for try := 0; try < 3 && r == nil; try++ { // hostapd retransmits
			h.send(req)
			r = h.recv(time.Second)
		}
		if r == nil || r[1] != i {
			t.Fatalf("request %d: no answer; log:\n%s", i, lb)
		}
	}
	if n := srv.conns.Load(); n < 3 {
		t.Fatalf("%d connections, want a reconnect per request", n)
	}
	if !strings.Contains(lb.String(), "connection lost") {
		t.Fatalf("log: %s", lb)
	}
}

func TestStalledServerReconnects(t *testing.T) {
	k := newPKI(t, "127.0.0.1")
	var first atomic.Bool
	srv := newServer(t, k, func(c net.Conn, req []byte) []byte {
		if first.CompareAndSwap(false, true) {
			return nil // the first connection's first request is swallowed
		}
		return acceptAll(c, req)
	})
	p, lb := testProxy(t, nil)
	ep := endpointFor(t, p, Server{Host: "127.0.0.1", Port: srv.port(), Secret: serverSecret, TLS: k.material()})
	h := newHostapd(t, ep)
	req, _ := h.accessRequest(5, "x")
	var r []byte
	for try := 0; try < 6 && r == nil; try++ {
		h.send(req) // hostapd's retransmissions
		r = h.recv(500 * time.Millisecond)
	}
	if r == nil || r[1] != 5 {
		t.Fatalf("no answer after the stall; log:\n%s", lb)
	}
	if srv.conns.Load() < 2 || !strings.Contains(lb.String(), "no answer for") {
		t.Fatalf("conns %d, log:\n%s", srv.conns.Load(), lb)
	}
}

func TestRetransmissionNotResent(t *testing.T) {
	k := newPKI(t, "127.0.0.1")
	release := make(chan struct{})
	srv := newServer(t, k, func(c net.Conn, req []byte) []byte {
		<-release
		return acceptAll(c, req)
	})
	p, _ := testProxy(t, func(o *Options) { o.Stall = 5 * time.Second })
	ep := endpointFor(t, p, Server{Host: "127.0.0.1", Port: srv.port(), Secret: serverSecret, TLS: k.material()})
	h := newHostapd(t, ep)
	req, _ := h.accessRequest(8, "x")
	h.send(req)
	time.Sleep(200 * time.Millisecond)
	h.send(req)
	h.send(req)
	time.Sleep(200 * time.Millisecond)
	close(release)
	if r := h.recv(2 * time.Second); r == nil {
		t.Fatal("no answer")
	}
	if n := len(srv.requests()); n != 1 {
		t.Fatalf("server saw %d copies of one request", n)
	}
}

func TestBSSesShareOneConnection(t *testing.T) {
	k := newPKI(t, "127.0.0.1")
	srv := newServer(t, k, acceptAll)
	p, _ := testProxy(t, nil)
	s := Server{Host: "127.0.0.1", Port: srv.port(), Secret: serverSecret, TLS: k.material()}
	ep := endpointFor(t, p, s)
	a, b := newHostapd(t, ep), newHostapd(t, ep)
	ra, _ := a.accessRequest(42, "a")
	rb, _ := b.accessRequest(42, "b") // the same Identifier from another BSS
	a.send(ra)
	b.send(rb)
	x, y := a.recv(3*time.Second), b.recv(3*time.Second)
	if x == nil || y == nil || x[1] != 42 || y[1] != 42 {
		t.Fatal("both BSSes must get their own answer")
	}
	reqs := srv.requests()
	if len(reqs) != 2 || reqs[0][1] == reqs[1][1] {
		t.Fatal("the shared connection needs distinct Identifiers")
	}
	if srv.conns.Load() != 1 {
		t.Fatalf("%d connections for one server", srv.conns.Load())
	}
	// a WLAN with the same server again: the same endpoint
	if ep2 := endpointFor(t, p, s); ep2 != ep {
		t.Fatal("same server, different endpoint")
	}
}

func TestSetLifecycle(t *testing.T) {
	k := newPKI(t, "127.0.0.1")
	p, _ := testProxy(t, nil)
	s1 := Server{Host: "127.0.0.1", Port: 2083, Secret: "one", TLS: k.material()}
	s2 := Server{Host: "127.0.0.1", Port: 2084, Secret: "two", TLS: k.material()}
	e1 := endpointFor(t, p, s1)
	endpointFor(t, p, s2) // s1 kept one more round (rollback)
	if got := p.Remotes(); len(got) != 2 {
		t.Fatalf("remotes %v", got)
	}
	endpointFor(t, p, s2) // now s1 goes
	if got := p.Remotes(); len(got) != 1 || got[0] != "127.0.0.1:2084" {
		t.Fatalf("remotes %v", got)
	}
	// the port is free again; a new proxy picks the same one for s1
	q, _ := testProxy(t, func(o *Options) { o.BasePort, o.PortSpan = p.o.BasePort, p.o.PortSpan })
	if e := endpointFor(t, q, s1); e != e1 {
		t.Fatalf("restarted proxy: %v, was %v", e, e1)
	}
	// refusals
	bad := []Server{
		{Host: "radius.example", Port: 2083, Secret: "x", TLS: k.material()},
		{Host: "127.0.0.1", Port: 0, Secret: "x", TLS: k.material()},
		{Host: "127.0.0.1", Port: 2083, Secret: "", TLS: k.material()},
		{Host: "127.0.0.1", Port: 2083, Secret: "x\n", TLS: k.material()},
		{Host: "127.0.0.1", Port: 2083, Secret: "x", TLS: Material{Cert: k.cliPEM, Key: k.cliKey}},
		{Host: "127.0.0.1", Port: 2083, Secret: "x", TLS: Material{CA: k.caPEM, Key: k.cliKey}},
		{Host: "127.0.0.1", Port: 2083, Secret: "x", TLS: Material{CA: k.caPEM, Cert: k.cliPEM}},
	}
	eps, errs := q.Set(bad)
	if len(eps) != 0 || len(errs) != len(bad) {
		t.Fatalf("bad servers served: %v %v", eps, errs)
	}
	q.Close()
	if _, errs := q.Set([]Server{s1}); errs[s1.Key()] == nil {
		t.Fatal("closed proxy served")
	}
}

func TestDialFailureBacksOff(t *testing.T) {
	k := newPKI(t, "127.0.0.1")
	var dials atomic.Int32
	p, lb := testProxy(t, func(o *Options) {
		o.BackoffMin, o.BackoffMax = time.Hour, time.Hour
		o.Dial = func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, fmt.Errorf("connection refused")
		}
	})
	ep := endpointFor(t, p, Server{Host: "127.0.0.1", Port: 2083, Secret: serverSecret, TLS: k.material()})
	h := newHostapd(t, ep)
	for i := byte(0); i < 5; i++ {
		req, _ := h.accessRequest(i, "x")
		h.send(req)
		if h.recv(100*time.Millisecond) != nil {
			t.Fatal("answer without a server")
		}
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("%d dials inside the backoff", n)
	}
	if !strings.Contains(lb.String(), "connect failed: connection refused") {
		t.Fatalf("log: %s", lb)
	}
}

func TestStringsHideSecrets(t *testing.T) {
	k := newPKI(t, "127.0.0.1")
	m := k.material()
	m.KeyPassword = "key-pass-123"
	s := Server{Host: "10.0.0.5", Port: 2083, Secret: "very-secret-value", TLS: m}
	for _, out := range []string{s.String(), fmt.Sprintf("%v %+v %#v", s, s, s), m.String(), fmt.Sprintf("%#v", m)} {
		for _, bad := range []string{"very-secret-value", "key-pass-123", "PRIVATE", string(k.cliKey[30:60])} {
			if strings.Contains(out, bad) {
				t.Fatalf("%q leaks %q", out, bad)
			}
		}
	}
	if !strings.Contains(s.String(), "10.0.0.5:2083") {
		t.Fatal(s.String())
	}
	_ = strconv.Itoa
}

func TestServerInitiatedPacketsDropped(t *testing.T) {
	k := newPKI(t, "127.0.0.1")
	srv := newServer(t, k, func(c net.Conn, req []byte) []byte {
		// a Disconnect-Request using the pending request's Identifier first
		dm := build(40, req[1], make([]byte, 16), attr{1, []byte("u")})
		c.Write(dm)
		return acceptAll(c, req)
	})
	p, lb := testProxy(t, nil)
	ep := endpointFor(t, p, Server{Host: "127.0.0.1", Port: srv.port(), Secret: serverSecret, TLS: k.material()})
	h := newHostapd(t, ep)
	req, _ := h.accessRequest(3, "x")
	h.send(req)
	r := h.recv(3 * time.Second)
	if r == nil || r[0] != codeAccessAccept {
		t.Fatalf("answer %x; log:\n%s", r, lb)
	}
	if !strings.Contains(lb.String(), "code 40") {
		t.Fatalf("log: %s", lb)
	}
}
