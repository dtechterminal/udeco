// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Limits.
const (
	// maxMsgSize is the largest message received or sent
	// (snmpEngineMaxMessageSize); larger requests are dropped and a reply
	// that would be larger becomes tooBig (GetBulk is cut short instead).
	maxMsgSize = 8192
	// minMsgSize is the smallest msgMaxSize a v3 request may name (RFC 3412).
	minMsgSize = 484
	// maxRepetitions caps GetBulk's max-repetitions.
	maxRepetitions = 64
	// treeTTL: how long one reading of the unit answers requests (a walk
	// is thousands of GetNext requests).
	treeTTL = 2 * time.Second
	// counterSample: interface counters are read this often while the
	// agent runs, so a 32-bit kernel counter's wrap is never missed.
	counterSample = 10 * time.Second
	// rate limit: requests per second and burst, over all sources
	rateLimit = 100
	rateBurst = 200
	// timeWindow is USM's 150 s (RFC 3414 3.2.7).
	timeWindow = 150
)

// Options configure a Server.
type Options struct {
	Addr     string // UDP listen address; "" = 0.0.0.0:161 (IPv4 only)
	Root     string // filesystem root for /proc and /sys; "" = "/"
	EngineID []byte // snmpEngineID (EngineIDFromMAC); required for v3
	Boots    int64  // snmpEngineBoots (NextEngineBoots); required for v3
	Logf     func(string, ...any)
	Now      func() time.Time
}

// Server is the SNMP agent. Its settings change while it runs: SetConfig,
// SetView and SetAllow may be called from any goroutine.
type Server struct {
	o     Options
	host  *host
	start time.Time

	mu      sync.Mutex
	cfg     *Config
	user    *userKeys // cfg's v3 user, keys localised to EngineID
	view    *View
	allow   func(netip.Addr) bool
	gen     uint64 // bumped by every Set*
	cache   tree
	cacheAt time.Time
	cacheG  uint64

	salt   atomic.Uint64
	tokens float64
	last   time.Time
	rate   float64 // requests per second (rateLimit; tests raise it)
	burst  float64

	stats struct {
		inPkts, outPkts, badVersions, badCommunity, parseErrs, silentDrops atomic.Uint64
		usm                                                                [6]atomic.Uint64
	}
}

type statsSnapshot struct {
	inPkts, outPkts, badVersions, badCommunity, parseErrs, silentDrops uint64
	usm                                                                [6]uint64
}

// New returns a Server; it answers nothing until SetConfig and Run.
func New(o Options) *Server {
	if o.Addr == "" {
		o.Addr = "0.0.0.0:161"
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	s := &Server{o: o, host: newHost(o.Root), start: o.Now(), tokens: rateBurst, rate: rateLimit, burst: rateBurst}
	s.last = s.start
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		s.salt.Store(binary.BigEndian.Uint64(b[:]))
	}
	return s
}

// EngineIDFromMAC is an RFC 3411 snmpEngineID: Ubiquiti's enterprise number
// (41112) with the MAC address format.
func EngineIDFromMAC(mac net.HardwareAddr) []byte {
	if len(mac) != 6 {
		return nil
	}
	return append([]byte{0x80, 0x00, 0xa0, 0x98, 0x03}, mac...)
}

// NextEngineBoots reads, increments and saves snmpEngineBoots (RFC 3414: it
// must grow every time the engine restarts, or old messages could be
// replayed within the time window). The file is created 0600. An error
// means v3 must not be served.
func NextEngineBoots(path string) (int64, error) {
	var n int64
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		n, err = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("snmp engine boots file %s unreadable", path)
		}
	case !errors.Is(err, os.ErrNotExist):
		return 0, err
	}
	if n < 1<<31-1 {
		n++
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(n, 10)+"\n"), 0o600); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	if n >= 1<<31-1 {
		return 0, errors.New("snmp engine boots at its maximum: v3 needs a new engine ID")
	}
	return n, nil
}

// SetConfig applies the settings (nil: answer nothing). Without an engine
// ID and boots v3 stays off. An unchanged v3 user keeps its derived keys.
func (s *Server) SetConfig(c *Config) {
	var u *userKeys
	if c != nil && c.V3 {
		s.mu.Lock()
		old, oldU := s.cfg, s.user
		s.mu.Unlock()
		switch {
		case len(s.o.EngineID) == 0 || s.o.Boots < 1:
			s.o.Logf("snmp: v3 off: no engine ID or engine boots")
			cc := *c
			cc.V3, cc.User, cc.Password = false, "", ""
			c = &cc
		case old != nil && old.V3 && old.User == c.User && old.Password == c.Password:
			u = oldU
		default:
			u = newUserKeys(c.User, c.Password, s.o.EngineID)
		}
	}
	s.mu.Lock()
	s.cfg, s.user = c, u
	s.gen++
	s.mu.Unlock()
}

// SetView hands the server the latest inform state (nil keeps none).
func (s *Server) SetView(v *View) {
	s.mu.Lock()
	s.view = v
	s.gen++
	s.mu.Unlock()
}

// SetAllow sets which sources are answered (nil: loopback only). Requests
// from anyone else are dropped unread.
func (s *Server) SetAllow(f func(netip.Addr) bool) {
	s.mu.Lock()
	s.allow = f
	s.mu.Unlock()
}

// Run serves on Options.Addr until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp4", s.o.Addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, pc)
}

// Serve answers requests on pc until ctx ends; it closes pc.
func (s *Server) Serve(ctx context.Context, pc net.PacketConn) error {
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	defer stop()
	defer pc.Close()
	go func() {
		t := time.NewTicker(counterSample)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.host.sample()
			}
		}
	}()
	buf := make([]byte, maxMsgSize+1)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok || n > maxMsgSize {
			continue
		}
		addr, _ := netip.AddrFromSlice(ua.IP)
		if out := s.Handle(buf[:n], addr.Unmap()); out != nil {
			pc.WriteTo(out, from)
		}
	}
}

func (s *Server) allowed(a netip.Addr) bool {
	if a.IsLoopback() {
		return true
	}
	s.mu.Lock()
	f := s.allow
	s.mu.Unlock()
	return f != nil && f(a)
}

func (s *Server) rateOK() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.o.Now()
	s.tokens = min(s.burst, s.tokens+max(0, now.Sub(s.last).Seconds())*s.rate)
	s.last = now
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

// engineTimes are snmpEngineBoots and snmpEngineTime now.
func (s *Server) engineTimes() (int64, int64) {
	t := int64(s.o.Now().Sub(s.start) / time.Second)
	return s.o.Boots, max(0, min(t, 1<<31-1))
}

func (s *Server) snapshotStats() statsSnapshot {
	st := statsSnapshot{inPkts: s.stats.inPkts.Load(), outPkts: s.stats.outPkts.Load(),
		badVersions: s.stats.badVersions.Load(), badCommunity: s.stats.badCommunity.Load(),
		parseErrs: s.stats.parseErrs.Load(), silentDrops: s.stats.silentDrops.Load()}
	for i := range st.usm {
		st.usm[i] = s.stats.usm[i].Load()
	}
	return st
}

// tree is the current object set (rebuilt at most every treeTTL or after a
// settings change).
func (s *Server) tree() tree {
	now := s.o.Now()
	s.mu.Lock()
	if s.cache != nil && s.cacheG == s.gen && now.Sub(s.cacheAt) < treeTTL && !now.Before(s.cacheAt) {
		t := s.cache
		s.mu.Unlock()
		return t
	}
	cfg, view, gen := s.cfg, s.view, s.gen
	s.mu.Unlock()

	in := mibInput{cfg: cfg, view: view, ifs: s.host.interfaces(), mem: s.host.meminfo(),
		upTicks: uint64(max(0, now.Sub(s.start)/(10*time.Millisecond))), stats: s.snapshotStats()}
	in.load, in.loadOK = s.host.load()
	if len(s.o.EngineID) > 0 {
		in.engineID = s.o.EngineID
		in.boots, in.etime = s.engineTimes()
	}
	t := buildTree(in)
	s.mu.Lock()
	s.cache, s.cacheAt, s.cacheG = t, now, gen
	s.mu.Unlock()
	return t
}

// Handle answers one request datagram from src; nil means no reply.
func (s *Server) Handle(pkt []byte, src netip.Addr) []byte {
	if !s.allowed(src) || len(pkt) > maxMsgSize || !s.rateOK() {
		return nil
	}
	s.stats.inPkts.Add(1)
	// an exact-capacity copy: v3 finds its digest's offset from the slices
	p := make([]byte, len(pkt))
	copy(p, pkt)
	body, rest, err := expect(p, tagSequence)
	if err != nil || len(rest) != 0 {
		s.stats.parseErrs.Add(1)
		return nil
	}
	ver, body, err := readInt(body)
	if err != nil {
		s.stats.parseErrs.Add(1)
		return nil
	}
	var out []byte
	switch ver {
	case 0, 1:
		out = s.community(ver, body)
	case 3:
		out = s.v3(p, body)
	default:
		s.stats.badVersions.Add(1)
	}
	if out != nil {
		s.stats.outPkts.Add(1)
	}
	return out
}

// community is SNMPv1 (ver 0) and SNMPv2c (ver 1).
func (s *Server) community(ver int64, body []byte) []byte {
	comm, body, err := expect(body, tagOctetString)
	if err != nil {
		s.stats.parseErrs.Add(1)
		return nil
	}
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	if cfg == nil || !cfg.V1V2c || subtle.ConstantTimeCompare(comm, []byte(cfg.Community)) != 1 {
		s.stats.badCommunity.Add(1)
		return nil
	}
	pdu, err := parsePDU(body)
	if err != nil || ver == 0 && pdu.Type == pduGetBulk {
		s.stats.parseErrs.Add(1)
		return nil
	}
	room := maxMsgSize - 32 - len(comm)
	resp, ok := s.process(pdu, ver == 0, room)
	if !ok {
		s.stats.silentDrops.Add(1)
		return nil
	}
	return seq(tagSequence, encInt(ver), encOctets(comm), resp.encode())
}

// Error statuses (RFC 3416; v1 uses the first five).
const (
	errTooBig     = 1
	errNoSuchName = 2
	errNoAccess   = 6
)

// process answers a Get, GetNext, GetBulk or Set; ok is false for PDUs an
// agent does not answer. room is the space the PDU may take.
func (s *Server) process(req PDU, v1 bool, room int) (PDU, bool) {
	resp := PDU{Type: pduResponse, RequestID: req.RequestID}
	fail := func(status, index int64) PDU {
		resp.ErrorStatus, resp.ErrorIndex = status, index
		resp.VarBinds = req.VarBinds
		return resp
	}
	switch req.Type {
	case pduGet, pduGetNext, pduGetBulk:
	case pduSet: // read-only
		if v1 {
			return fail(errNoSuchName, 1), true
		}
		return fail(errNoAccess, 1), true
	default:
		return PDU{}, false
	}
	t := s.tree()
	size := 0
	add := func(vb VarBind) bool {
		n := len(vb.encode())
		if size+n > room-40 {
			return false
		}
		size += n
		resp.VarBinds = append(resp.VarBinds, vb)
		return true
	}
	tooBig := func() PDU {
		resp.ErrorStatus, resp.ErrorIndex = errTooBig, 0
		resp.VarBinds = nil
		if v1 {
			resp.VarBinds = req.VarBinds
		}
		return resp
	}
	next := func(o OID) (VarBind, bool) {
		if e, ok := t.next(o, v1); ok {
			return VarBind{Name: e.oid, Value: e.v}, true
		}
		return VarBind{Name: o, Value: Value{Tag: tagEndOfMibView}}, false
	}
	switch req.Type {
	case pduGet:
		for i, vb := range req.VarBinds {
			v, ok := t.get(vb.Name)
			if ok && v1 && v.Tag == tagCounter64 {
				ok = false
			}
			if !ok {
				if v1 {
					return fail(errNoSuchName, int64(i+1)), true
				}
				v = Value{Tag: tagNoSuchInstance}
				if !t.hasPrefix(vb.Name[:max(0, len(vb.Name)-1)]) {
					v = Value{Tag: tagNoSuchObject}
				}
			}
			if !add(VarBind{Name: vb.Name, Value: v}) {
				return tooBig(), true
			}
		}
	case pduGetNext:
		for i, vb := range req.VarBinds {
			nv, ok := next(vb.Name)
			if !ok && v1 {
				return fail(errNoSuchName, int64(i+1)), true
			}
			if !add(nv) {
				return tooBig(), true
			}
		}
	case pduGetBulk:
		nonRep := int(max(0, min(req.ErrorStatus, int64(len(req.VarBinds)))))
		maxRep := int(max(0, min(req.ErrorIndex, maxRepetitions)))
		for _, vb := range req.VarBinds[:nonRep] {
			nv, _ := next(vb.Name)
			if !add(nv) {
				return tooBig(), true
			}
		}
		cur := make([]OID, 0, len(req.VarBinds)-nonRep)
		for _, vb := range req.VarBinds[nonRep:] {
			cur = append(cur, vb.Name)
		}
	bulk:
		for r := 0; r < maxRep && len(cur) > 0; r++ {
			end := true
			for j, o := range cur {
				nv, ok := next(o)
				if !add(nv) {
					if len(resp.VarBinds) == 0 {
						return tooBig(), true
					}
					break bulk // the reply holds as many as fit
				}
				cur[j] = nv.Name
				end = end && !ok
			}
			if end {
				break
			}
		}
	}
	return resp, true
}

// msgFlags bits (RFC 3412).
const (
	flagAuth       = 0x1
	flagPriv       = 0x2
	flagReportable = 0x4
)

// secParams are a v3 message's USM parameters.
type secParams struct {
	engineID    []byte
	boots, time int64
	user        []byte
	auth, priv  []byte // slices of the message
}

func parseSecParams(b []byte) (secParams, error) {
	var sp secParams
	body, rest, err := expect(b, tagSequence)
	if err != nil || len(rest) != 0 {
		return sp, errBER
	}
	if sp.engineID, body, err = expect(body, tagOctetString); err != nil {
		return sp, err
	}
	if sp.boots, body, err = readInt(body); err != nil {
		return sp, err
	}
	if sp.time, body, err = readInt(body); err != nil {
		return sp, err
	}
	if sp.user, body, err = expect(body, tagOctetString); err != nil {
		return sp, err
	}
	if sp.auth, body, err = expect(body, tagOctetString); err != nil {
		return sp, err
	}
	if sp.priv, body, err = expect(body, tagOctetString); err != nil || len(body) != 0 {
		return sp, errBER
	}
	if len(sp.engineID) > 32 || len(sp.user) > 32 || sp.boots < 0 || sp.time < 0 {
		return sp, errBER
	}
	return sp, nil
}

// parseScoped reads a ScopedPDU; trailing bytes (DES padding) are allowed
// only when padded is true.
func parseScoped(b []byte, padded bool) (ctxEngine, ctxName []byte, pdu PDU, err error) {
	body, rest, err := expect(b, tagSequence)
	if err != nil || len(rest) != 0 && (!padded || len(rest) >= 8) {
		return nil, nil, PDU{}, errBER
	}
	if ctxEngine, body, err = expect(body, tagOctetString); err != nil {
		return nil, nil, PDU{}, err
	}
	if ctxName, body, err = expect(body, tagOctetString); err != nil {
		return nil, nil, PDU{}, err
	}
	pdu, err = parsePDU(body)
	return ctxEngine, ctxName, pdu, err
}

// v3 is SNMPv3 with USM (RFC 3412, RFC 3414). msg is the whole datagram
// (exact capacity), body what follows msgVersion.
func (s *Server) v3(msg, body []byte) []byte {
	s.mu.Lock()
	cfg, user := s.cfg, s.user
	s.mu.Unlock()
	if cfg == nil || !cfg.V3 || user == nil {
		s.stats.silentDrops.Add(1)
		return nil
	}
	glob, body, err := expect(body, tagSequence)
	if err != nil {
		s.stats.parseErrs.Add(1)
		return nil
	}
	msgID, g, err1 := readInt(glob)
	maxSize, g, err2 := readInt(g)
	flagB, g, err3 := expect(g, tagOctetString)
	model, g, err4 := readInt(g)
	if err := errors.Join(err1, err2, err3, err4); err != nil || len(g) != 0 || len(flagB) != 1 ||
		msgID < 0 || msgID > 1<<31-1 || maxSize < minMsgSize || maxSize > 1<<31-1 {
		s.stats.parseErrs.Add(1)
		return nil
	}
	flags := flagB[0]
	if model != 3 || flags&flagPriv != 0 && flags&flagAuth == 0 {
		s.stats.silentDrops.Add(1)
		return nil
	}
	rawSP, body, err := expect(body, tagOctetString)
	if err != nil {
		s.stats.parseErrs.Add(1)
		return nil
	}
	sp, err := parseSecParams(rawSP)
	if err != nil {
		s.stats.parseErrs.Add(1)
		return nil
	}
	dataTag, data, rest, err := readTLV(body)
	if err != nil || len(rest) != 0 {
		s.stats.parseErrs.Add(1)
		return nil
	}
	reportable := flags&flagReportable != 0
	// the request-id of a plaintext request, for its reports
	var reqID int32
	if flags&flagPriv == 0 {
		if dataTag != tagSequence {
			s.stats.parseErrs.Add(1)
			return nil
		}
		if _, _, pdu, err := parseScoped(body, false); err == nil {
			reqID = pdu.RequestID
		}
	} else if dataTag != tagOctetString {
		s.stats.parseErrs.Add(1)
		return nil
	}
	report := func(stat int, authed bool, ap authProto) []byte {
		n := s.stats.usm[stat-1].Add(1)
		if !reportable {
			return nil
		}
		pdu := PDU{Type: pduReport, RequestID: reqID,
			VarBinds: []VarBind{{Name: oidUsmStats.Append(uint32(stat), 0), Value: Counter32(n)}}}
		var keys *userKeys
		if authed {
			keys = user
		}
		out, err := s.buildV3(msgID, sp.user, keys, ap, -1, pdu)
		if err != nil {
			return nil
		}
		return out
	}

	// RFC 3414 3.2, in order: engine, user, level, digest, time, privacy
	if !bytes.Equal(sp.engineID, s.o.EngineID) {
		return report(usmUnknownEngineIDs, false, 0)
	}
	if subtle.ConstantTimeCompare(sp.user, []byte(user.name)) != 1 {
		return report(usmUnknownUserNames, false, 0)
	}
	if flags&(flagAuth|flagPriv) != flagAuth|flagPriv { // rouser <name> authpriv
		return report(usmUnsupportedSecLevels, false, 0)
	}
	zeroed := make([]byte, len(msg))
	copy(zeroed, msg)
	off := cap(msg) - cap(sp.auth)
	if off < 0 || off+len(sp.auth) > len(msg) {
		s.stats.parseErrs.Add(1)
		return nil
	}
	clear(zeroed[off : off+len(sp.auth)])
	ap, ok := user.verify(zeroed, sp.auth)
	if !ok {
		return report(usmWrongDigests, false, 0)
	}
	boots, etime := s.engineTimes()
	if boots >= 1<<31-1 || sp.boots != boots || sp.time < etime-timeWindow || sp.time > etime+timeWindow {
		return report(usmNotInTimeWindows, true, ap)
	}
	var (
		pp     privProto
		ctxEng []byte
		pdu    PDU
		done   bool
	)
	for _, try := range []privProto{privDES, privAES128} {
		if try == privDES && len(data)%8 != 0 {
			continue
		}
		pt, err := decrypt(try, user.privKey(ap), uint32(sp.boots), uint32(sp.time), sp.priv, data)
		if err != nil {
			continue
		}
		ce, cn, p, err := parseScoped(pt, try == privDES)
		if err != nil || len(cn) != 0 {
			continue
		}
		pp, ctxEng, pdu, done = try, ce, p, true
		break
	}
	if !done {
		return report(usmDecryptionErrors, false, 0)
	}
	if len(ctxEng) != 0 && !bytes.Equal(ctxEng, s.o.EngineID) {
		s.stats.silentDrops.Add(1)
		return nil
	}
	room := int(min(maxSize, maxMsgSize)) - 96 - len(user.name) - len(s.o.EngineID)*2 - ap.digestLen() - 16
	resp, ok := s.process(pdu, false, room)
	if !ok {
		s.stats.silentDrops.Add(1)
		return nil
	}
	out, err := s.buildV3(msgID, sp.user, user, ap, pp, resp)
	if err != nil {
		return nil
	}
	return out
}

// buildV3 encodes a v3 response or report: noAuthNoPriv when keys is nil,
// authNoPriv when pp < 0, else authPriv.
func (s *Server) buildV3(msgID int64, userName []byte, keys *userKeys, ap authProto, pp privProto, pdu PDU) ([]byte, error) {
	boots, etime := s.engineTimes()
	scoped := seq(tagSequence, encOctets(s.o.EngineID), encOctets(nil), pdu.encode())
	var flags byte
	var authP, privP, data []byte
	data = scoped
	if keys != nil {
		flags |= flagAuth
		authP = make([]byte, ap.digestLen())
		if pp >= 0 {
			flags |= flagPriv
			c := s.salt.Add(1)
			privP = make([]byte, 8)
			if pp == privDES {
				binary.BigEndian.PutUint32(privP, uint32(boots))
				binary.BigEndian.PutUint32(privP[4:], uint32(c))
			} else {
				binary.BigEndian.PutUint64(privP, c)
			}
			ct, err := encrypt(pp, keys.privKey(ap), uint32(boots), uint32(etime), privP, scoped)
			if err != nil {
				return nil, err
			}
			data = encOctets(ct)
		}
	}
	privEnc := encOctets(privP)
	spSeq := seq(tagSequence, encOctets(s.o.EngineID), encInt(boots), encInt(etime), encOctets(userName), encOctets(authP), privEnc)
	glob := seq(tagSequence, encInt(msgID), encInt(maxMsgSize), encOctets([]byte{flags}), encInt(3))
	msg := seq(tagSequence, encInt(3), glob, encOctets(spSeq), data)
	if keys != nil {
		spStart := len(msg) - len(data) - len(spSeq)
		off := spStart + len(spSeq) - len(privEnc) - len(authP)
		copy(msg[off:], keys.mac(ap, msg))
	}
	return msg, nil
}

// LANAllow is a SetAllow filter: addresses inside the prefix.
func LANAllow(p netip.Prefix) func(netip.Addr) bool {
	p = p.Masked()
	return func(a netip.Addr) bool { return p.IsValid() && p.Contains(a.Unmap()) }
}

// PrefixFromIPMask is the LAN prefix of an IPv4 address and dotted netmask
// (the reading's IP and Netmask); invalid input gives an invalid prefix.
func PrefixFromIPMask(ip, mask string) netip.Prefix {
	a, err := netip.ParseAddr(ip)
	m := net.ParseIP(mask).To4()
	if err != nil || !a.Is4() || m == nil {
		return netip.Prefix{}
	}
	ones, bits := net.IPMask(m).Size()
	if bits != 32 || ones < 8 { // a non-contiguous or too-wide mask
		return netip.Prefix{}
	}
	return netip.PrefixFrom(a, ones).Masked()
}

// BootsFile is where NextEngineBoots keeps the count in a state directory.
func BootsFile(dir string) string { return filepath.Join(dir, "snmp-engine-boots") }
