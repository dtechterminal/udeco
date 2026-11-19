// SPDX-License-Identifier: GPL-2.0-or-later

package radsec

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server is one controller RADIUS server marked tls=enabled. Secret is the
// RADIUS shared secret used inside the TLS connection (RFC 6614 §2.3: the
// controller's, as a UAP's hostapd uses it). Host must be an IP address.
type Server struct {
	Host   string
	Port   int
	Secret string
	TLS    Material
}

// String never prints the secret or the key material.
func (s Server) String() string {
	return fmt.Sprintf("%s secret=<%d chars> %v", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)), len(s.Secret), s.TLS)
}

// GoString is String.
func (s Server) GoString() string { return "radsec.Server{" + s.String() + "}" }

// Key identifies a server with its secret and TLS identity (a hash: it
// reveals none of them). Servers with the same Key share one local
// endpoint and one TLS connection.
func (s Server) Key() string {
	h := sha256.New()
	for _, b := range [][]byte{[]byte(s.Host), []byte(strconv.Itoa(s.Port)), []byte(s.Secret),
		s.TLS.CA, s.TLS.Cert, s.TLS.Key, []byte(s.TLS.KeyPassword)} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Endpoint is what hostapd is given for a server: auth_server_addr/port and
// auth_server_shared_secret (and acct_*). Secret is a secret.
type Endpoint struct {
	IP     string
	Port   int
	Secret string
}

// String masks the secret.
func (e Endpoint) String() string {
	return fmt.Sprintf("%s secret=<%d chars>", net.JoinHostPort(e.IP, strconv.Itoa(e.Port)), len(e.Secret))
}

// GoString is String.
func (e Endpoint) GoString() string { return "radsec.Endpoint{" + e.String() + "}" }

// Options configure a Proxy; zero values take the defaults.
type Options struct {
	// ListenIP is the local address hostapd sends to (127.0.0.1).
	ListenIP string
	// BasePort, PortSpan: local UDP ports are BasePort..BasePort+PortSpan-1
	// (18120..18519), chosen by a hash of the server's Key so a restarted
	// agent gets the same port (and hostapd's conf stays the same).
	BasePort, PortSpan int
	// Dial opens the TCP connection to the server (tests); nil = a
	// net.Dialer with TCP keepalives.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Logf func(string, ...any)
	Now  func() time.Time
	// Stall: a request has waited this long and the server has sent
	// nothing since it was written: the connection is taken as dead and
	// closed (default 10 s; hostapd retransmits after 3 s and fails over to
	// its next server after a few).
	Stall time.Duration
	// Expire: an unanswered request is forgotten (its Identifier freed)
	// after this long (default 30 s).
	Expire time.Duration
	// Idle: a connection with nothing outstanding is closed after this
	// long; the next request reconnects (default 5 min).
	Idle time.Duration
	// BackoffMin/Max: after a failed connect, requests are dropped
	// (hostapd fails over or times out) until the next attempt, which
	// waits 1 s, 2 s, ... up to BackoffMax (60 s).
	BackoffMin, BackoffMax time.Duration
	// ConnectTimeout bounds the TCP connect plus the TLS handshake (10 s).
	ConnectTimeout time.Duration
}

func (o *Options) defaults() {
	if o.ListenIP == "" {
		o.ListenIP = "127.0.0.1"
	}
	if o.BasePort == 0 {
		o.BasePort = 18120
	}
	if o.PortSpan == 0 {
		o.PortSpan = 400
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	d := func(v *time.Duration, def time.Duration) {
		if *v <= 0 {
			*v = def
		}
	}
	d(&o.Stall, 10*time.Second)
	d(&o.Expire, 30*time.Second)
	d(&o.Idle, 5*time.Minute)
	d(&o.BackoffMin, time.Second)
	d(&o.BackoffMax, time.Minute)
	d(&o.ConnectTimeout, 10*time.Second)
	if o.Dial == nil {
		dl := &net.Dialer{KeepAlive: 30 * time.Second}
		o.Dial = dl.DialContext
	}
}

// Proxy runs one local UDP endpoint and one TLS connection per server.
type Proxy struct {
	o      Options
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	routes map[string]*route
	prev   map[string]bool // the keys the previous Set asked for
	closed bool
}

// New starts an empty proxy; it closes everything when ctx ends.
func New(ctx context.Context, o Options) *Proxy {
	o.defaults()
	ctx, cancel := context.WithCancel(ctx)
	p := &Proxy{o: o, ctx: ctx, cancel: cancel, routes: map[string]*route{}}
	go func() {
		<-ctx.Done()
		p.Close()
	}()
	return p
}

// Set makes the proxy serve servers. Routes the previous Set asked for are
// kept one more round, so a rollback to the last-good Wi-Fi still finds its
// endpoints; older ones are closed. It returns the local endpoint of every
// server it serves and the reason for each it cannot (by Key): hostapd must
// not be pointed anywhere for those.
func (p *Proxy) Set(servers []Server) (map[string]Endpoint, map[string]error) {
	eps, errs := map[string]Endpoint{}, map[string]error{}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		for _, s := range servers {
			errs[s.Key()] = errors.New("RadSec proxy is closed")
		}
		return eps, errs
	}
	want := map[string]bool{}
	for _, s := range servers {
		k := s.Key()
		if want[k] || errs[k] != nil {
			continue
		}
		r := p.routes[k]
		if r == nil {
			var err error
			if r, err = p.start(k, s); err != nil {
				errs[k] = err
				continue
			}
			p.routes[k] = r
			p.o.Logf("radsec: serving %s on %s", r.remote, r.local.String())
		}
		want[k] = true
		eps[k] = r.local
	}
	for k, r := range p.routes {
		if !want[k] && !p.prev[k] {
			r.close()
			delete(p.routes, k)
			p.o.Logf("radsec: stopped %s on %s", r.remote, r.local.String())
		}
	}
	p.prev = want
	return eps, errs
}

// Remotes lists the servers in use ("ip:port", sorted): what the egress
// firewall must let through.
func (p *Proxy) Remotes() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	seen := map[string]bool{}
	for _, r := range p.routes {
		if !seen[r.remote] {
			seen[r.remote] = true
			out = append(out, r.remote)
		}
	}
	sort.Strings(out)
	return out
}

// Close stops every endpoint and connection; Set refuses afterwards.
func (p *Proxy) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	rs := p.routes
	p.routes = map[string]*route{}
	p.mu.Unlock()
	p.cancel()
	for _, r := range rs {
		r.close()
	}
}

// route is one server: a local UDP socket and its upstream connection.
type route struct {
	p           *Proxy
	remote      string // ip:port
	local       Endpoint
	secret      []byte // the server's shared secret
	localSecret []byte // hostapd's
	pc          *net.UDPConn
	up          *upstream
	once        sync.Once

	lmu    sync.Mutex
	logged map[string]time.Time // rate-limited problem logs
}

// localSecretFor derives hostapd's shared secret for a route: a keyed hash
// of the server's secret, so it is stable across agent restarts (hostapd's
// conf does not change) and the server's secret never appears in it.
func localSecretFor(key, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("udeco-radsec-local\x00" + key))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

func (p *Proxy) start(key string, s Server) (*route, error) {
	ip := net.ParseIP(s.Host)
	if ip == nil {
		return nil, fmt.Errorf("server %q is not an IP address", s.Host)
	}
	if s.Port < 1 || s.Port > 65535 {
		return nil, fmt.Errorf("server %s: bad port %d", s.Host, s.Port)
	}
	if s.Secret == "" || strings.ContainsFunc(s.Secret, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return nil, fmt.Errorf("server %s: empty or unprintable shared secret", s.Host)
	}
	cfg, err := s.TLS.tlsConfig(ip)
	if err != nil {
		return nil, fmt.Errorf("server %s: %w", s.Host, err)
	}
	h := fnv.New32a()
	h.Write([]byte(key))
	first := int(h.Sum32() % uint32(p.o.PortSpan))
	var pc *net.UDPConn
	for i := 0; i < p.o.PortSpan && pc == nil; i++ {
		port := p.o.BasePort + (first+i)%p.o.PortSpan
		pc, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(p.o.ListenIP), Port: port})
	}
	if pc == nil {
		return nil, fmt.Errorf("no free local port in %d..%d: %v", p.o.BasePort, p.o.BasePort+p.o.PortSpan-1, err)
	}
	ls := localSecretFor(key, s.Secret)
	r := &route{p: p, remote: net.JoinHostPort(ip.String(), strconv.Itoa(s.Port)),
		local:  Endpoint{IP: p.o.ListenIP, Port: pc.LocalAddr().(*net.UDPAddr).Port, Secret: ls},
		secret: []byte(s.Secret), localSecret: []byte(ls), pc: pc, logged: map[string]time.Time{}}
	r.up = &upstream{r: r, cfg: cfg, pend: map[byte]*pend{}, dup: map[dupKey]byte{}}
	go r.serve()
	return r, nil
}

func (r *route) close() {
	r.once.Do(func() {
		r.pc.Close()
		r.up.close()
	})
}

// problem logs a recurring problem at most once a minute per kind.
func (r *route) problem(kind, f string, args ...any) {
	now := r.p.o.Now()
	r.lmu.Lock()
	last, ok := r.logged[kind]
	if ok && now.Sub(last) < time.Minute {
		r.lmu.Unlock()
		return
	}
	r.logged[kind] = now
	r.lmu.Unlock()
	r.p.o.Logf("radsec: %s: "+f, append([]any{r.remote}, args...)...)
}

// serve reads hostapd's requests until the socket is closed.
func (r *route) serve() {
	buf := make([]byte, maxUDP+1)
	for {
		n, src, err := r.pc.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if !src.IP.IsLoopback() {
			continue // bound to loopback; belt and braces
		}
		if n > maxUDP {
			r.problem("big", "request from hostapd over %d bytes: dropped", maxUDP)
			continue
		}
		p, err := parse(buf[:n], maxUDP)
		if err == nil {
			err = checkRequest(p, r.localSecret)
		}
		if err != nil {
			r.problem("local", "request from %s refused: %v", src, err)
			continue
		}
		r.up.send(src, append([]byte(nil), p...))
	}
}

// --- the TLS side ---

type dupKey struct {
	src  string
	id   byte
	auth [16]byte
}

// pend is one request waiting for its answer, by upstream Identifier.
type pend struct {
	key      dupKey
	src      *net.UDPAddr
	code     byte
	origID   byte
	origAuth []byte // hostapd's authenticator
	upAuth   []byte // the authenticator sent to the server
	pkt      []byte // the upstream packet, until written
	created  time.Time
	sent     time.Time // zero until written
}

type upstream struct {
	r   *route
	cfg *tls.Config

	mu       sync.Mutex
	conn     net.Conn // nil when not connected
	dialing  bool
	closed   bool
	pend     map[byte]*pend
	dup      map[dupKey]byte
	queue    []byte // Identifiers waiting for the connection, in order
	next     byte
	lastRecv time.Time
	lastUse  time.Time
	retryAt  time.Time
	backoff  time.Duration
	state    string // "up", or why it is down: logged on change

	wmu sync.Mutex
}

func (u *upstream) close() {
	u.mu.Lock()
	u.closed = true
	c := u.conn
	u.conn = nil
	u.dropLocked()
	u.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

func (u *upstream) dropLocked() {
	clear(u.pend)
	clear(u.dup)
	u.queue = nil
}

func (u *upstream) setState(s string) {
	if s == u.state {
		return
	}
	u.state = s
	u.r.p.o.Logf("radsec: %s: %s", u.r.remote, s)
}

// expireLocked forgets requests that were never answered.
func (u *upstream) expireLocked(now time.Time) {
	for id, pd := range u.pend {
		if now.Sub(pd.created) >= u.r.p.o.Expire {
			delete(u.pend, id)
			delete(u.dup, pd.key)
		}
	}
}

// stalledLocked reports whether a written request has waited Stall with
// nothing at all from the server since.
func (u *upstream) stalledLocked(now time.Time) bool {
	for _, pd := range u.pend {
		if !pd.sent.IsZero() && now.Sub(pd.sent) >= u.r.p.o.Stall && !u.lastRecv.After(pd.sent) {
			return true
		}
	}
	return false
}

// send forwards one verified request from hostapd (src).
func (u *upstream) send(src *net.UDPAddr, p []byte) {
	o := &u.r.p.o
	now := o.Now()
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return
	}
	u.expireLocked(now)
	k := dupKey{src: src.String(), id: p[1]}
	copy(k.auth[:], p[4:20])
	if _, ok := u.dup[k]; ok {
		// hostapd's retransmission: TLS is reliable, so it is not sent
		// again (RFC 6614 §2.5); a server silent since then is dead
		if c := u.conn; c != nil && u.stalledLocked(now) {
			u.mu.Unlock()
			u.fail(c, fmt.Errorf("no answer for %s", o.Stall))
			return
		}
		u.mu.Unlock()
		return
	}
	if u.conn == nil && !u.dialing && now.Before(u.retryAt) {
		u.mu.Unlock()
		return // down: dropped, hostapd fails over or times out
	}
	id, ok := u.allocLocked()
	if !ok {
		u.mu.Unlock()
		u.r.problem("ids", "256 requests outstanding: request dropped")
		return
	}
	q := p
	origID, origAuth := q[1], append([]byte(nil), q[4:20]...)
	q[1] = id
	if err := rehideAttrs(q, origAuth, origAuth, u.r.localSecret, u.r.secret); err != nil {
		u.mu.Unlock()
		u.r.problem("hide", "request: %v: dropped", err)
		return
	}
	signRequest(q, u.r.secret)
	pd := &pend{key: k, src: src, code: q[0], origID: origID, origAuth: origAuth,
		upAuth: append([]byte(nil), q[4:20]...), created: now}
	u.pend[id], u.dup[k] = pd, id
	u.lastUse = now
	if u.conn == nil {
		pd.pkt = q
		u.queue = append(u.queue, id)
		if !u.dialing {
			u.dialing = true
			go u.dial()
		}
		u.mu.Unlock()
		return
	}
	c := u.conn
	pd.sent = now
	u.mu.Unlock()
	u.write(c, q)
}

func (u *upstream) allocLocked() (byte, bool) {
	for range 256 {
		id := u.next
		u.next++
		if _, busy := u.pend[id]; !busy {
			return id, true
		}
	}
	return 0, false
}

func (u *upstream) dial() {
	o := &u.r.p.o
	ctx, cancel := context.WithTimeout(u.r.p.ctx, o.ConnectTimeout)
	var c net.Conn
	raw, err := o.Dial(ctx, "tcp", u.r.remote)
	if err == nil {
		tc := tls.Client(raw, u.cfg)
		if err = tc.HandshakeContext(ctx); err != nil {
			raw.Close()
		} else {
			c = tc
		}
	}
	cancel()
	now := o.Now()
	u.mu.Lock()
	u.dialing = false
	if u.closed {
		u.mu.Unlock()
		if c != nil {
			c.Close()
		}
		return
	}
	if err != nil {
		if u.backoff == 0 {
			u.backoff = o.BackoffMin
		} else if u.backoff *= 2; u.backoff > o.BackoffMax {
			u.backoff = o.BackoffMax
		}
		u.retryAt = now.Add(u.backoff)
		u.dropLocked()
		u.setState(fmt.Sprintf("connect failed: %v (requests dropped; next attempt in %s at the earliest)", err, u.backoff))
		u.mu.Unlock()
		return
	}
	cs := c.(*tls.Conn).ConnectionState()
	u.conn, u.backoff, u.lastRecv, u.lastUse = c, 0, now, now
	var out [][]byte
	for _, id := range u.queue {
		if pd := u.pend[id]; pd != nil && pd.pkt != nil {
			out = append(out, pd.pkt)
			pd.pkt, pd.sent = nil, now
		}
	}
	u.queue = nil
	u.setState("connected (" + tls.VersionName(cs.Version) + ", " + tls.CipherSuiteName(cs.CipherSuite) + ")")
	u.mu.Unlock()
	go u.read(c)
	for _, q := range out {
		u.write(c, q)
	}
}

func (u *upstream) write(c net.Conn, q []byte) {
	u.wmu.Lock()
	c.SetWriteDeadline(u.r.p.o.Now().Add(5 * time.Second))
	_, err := c.Write(q)
	u.wmu.Unlock()
	if err != nil {
		u.fail(c, err)
	}
}

// fail closes c if it is still the live connection; what waited on it is
// dropped (hostapd retransmits, and a retransmission goes out on the next
// connection, which the next request opens at once).
func (u *upstream) fail(c net.Conn, err error) {
	u.mu.Lock()
	if u.conn != c {
		u.mu.Unlock()
		return
	}
	u.conn = nil
	u.retryAt = time.Time{}
	u.dropLocked()
	u.setState(fmt.Sprintf("connection lost: %v", err))
	u.mu.Unlock()
	c.Close()
}

// read takes the server's packets off c until it fails or idles out.
func (u *upstream) read(c net.Conn) {
	o := &u.r.p.o
	br := bufio.NewReaderSize(c, 4096)
	tick := min(o.Stall/2, o.Idle/2)
	for {
		hdr := make([]byte, 4)
		c.SetReadDeadline(time.Now().Add(tick))
		n, err := io.ReadFull(br, hdr)
		if err != nil {
			var ne net.Error
			if n == 0 && errors.As(err, &ne) && ne.Timeout() {
				if !u.check(c) {
					return
				}
				continue
			}
			u.fail(c, err)
			return
		}
		l := int(binary.BigEndian.Uint16(hdr[2:4]))
		if l < hdrLen || l > maxTLS {
			u.fail(c, fmt.Errorf("server sent a packet of length %d", l))
			return
		}
		buf := make([]byte, l)
		copy(buf, hdr)
		c.SetReadDeadline(time.Now().Add(o.Stall))
		if _, err := io.ReadFull(br, buf[4:]); err != nil {
			u.fail(c, err)
			return
		}
		p, err := parse(buf, maxTLS)
		if err != nil {
			u.fail(c, errors.New("server sent a malformed packet"))
			return
		}
		u.handle(p)
	}
}

// check runs between reads: it closes a stalled or idle connection and
// reports whether c is still live.
func (u *upstream) check(c net.Conn) bool {
	o := &u.r.p.o
	now := o.Now()
	u.mu.Lock()
	if u.conn != c {
		u.mu.Unlock()
		return false
	}
	u.expireLocked(now)
	if u.stalledLocked(now) {
		u.mu.Unlock()
		u.fail(c, fmt.Errorf("no answer for %s", o.Stall))
		return false
	}
	if len(u.pend) == 0 && now.Sub(u.lastUse) >= o.Idle && now.Sub(u.lastRecv) >= o.Idle {
		u.conn = nil
		u.retryAt = time.Time{}
		u.setState("idle: connection closed (the next request reconnects)")
		u.mu.Unlock()
		c.Close()
		return false
	}
	u.mu.Unlock()
	return true
}

// handle passes one server packet back to the hostapd socket that asked.
func (u *upstream) handle(p []byte) {
	r := u.r
	switch p[0] {
	case codeAccessAccept, codeAccessReject, codeAccessChallenge, codeAccountingResponse:
	default:
		// server-initiated (Disconnect/CoA-Request, RFC 5176) or a request:
		// hostapd 2.9 takes neither over this path
		u.mu.Lock()
		u.lastRecv = r.p.o.Now()
		u.mu.Unlock()
		r.problem("code", "server sent code %d, which the proxy does not carry: dropped", p[0])
		return
	}
	u.mu.Lock()
	u.lastRecv = r.p.o.Now()
	pd := u.pend[p[1]]
	if pd == nil || pd.sent.IsZero() {
		u.mu.Unlock()
		r.problem("unknown", "answer with Identifier %d matches no request (late or duplicate): dropped", p[1])
		return
	}
	delete(u.pend, p[1])
	delete(u.dup, pd.key)
	u.mu.Unlock()
	if err := checkResponse(p, pd.code, pd.upAuth, r.secret); err != nil {
		r.problem("verify", "answer failed verification with the server's secret: %v: dropped", err)
		return
	}
	if len(p) > maxUDP {
		r.problem("big", "answer of %d bytes is over the UDP maximum: dropped", len(p))
		return
	}
	if err := rehideAttrs(p, pd.upAuth, pd.origAuth, r.secret, r.localSecret); err != nil {
		r.problem("hide", "answer: %v: dropped", err)
		return
	}
	p[1] = pd.origID
	signResponse(p, pd.origAuth, r.localSecret)
	if _, err := r.pc.WriteToUDP(p, pd.src); err != nil && !errors.Is(err, net.ErrClosed) {
		r.problem("reply", "answer to hostapd: %v", err)
	}
}
