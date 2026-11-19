// SPDX-License-Identifier: GPL-2.0-or-later

package ftpeer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Conn is one bridge's announcement socket. Recv returns ErrTimeout when
// nothing arrived within its poll interval, and an error once closed.
type Conn interface {
	Recv(b []byte) (int, error)
	Send(frame []byte) error
	Close() error
}

// Opener opens bridge's socket.
type Opener func(bridge string) (Conn, error)

// ErrTimeout is Conn.Recv's "nothing yet".
var ErrTimeout = errors.New("ftpeer: receive timeout")

// Options configures a Service.
type Options struct {
	// Unit is this unit's MAC (br-lan's): sent as the frames' source and
	// unit, and frames carrying it are ignored.
	Unit net.HardwareAddr
	// Open opens a bridge's socket; nil = OpenRaw (AF_PACKET, Linux).
	Open Opener
	// Interval between announcements (default DefaultInterval).
	Interval time.Duration
	// TTL: a peer not re-announced for this long is dropped (default 3.5
	// intervals: two lost frames in a row are tolerated).
	TTL time.Duration
	// MinGap spaces the announcements a change or a new unit triggers
	// (default 2 s).
	MinGap time.Duration
	Now    func() time.Time
	Logf   func(format string, args ...any)
	// OnChange receives the peer set whenever it changed (a peer came,
	// changed or went). Called from Run's goroutine, never with the
	// Service's lock held.
	OnChange func(peers []Peer)
	// OnAir, when set, is the optional cross-check with the neighbour
	// scans: seen reports that bssid was in the last scan, known that a
	// scan result exists at all. A new peer the scans have not seen is
	// logged; it is not refused (its unit may be out of radio range of
	// this one and still on the same LAN).
	OnAir func(bssid string) (seen, known bool)
}

// Service announces this unit's FT-SAE key holders and learns the others'.
type Service struct {
	o     Options
	unit  string
	epoch uint64

	mu       sync.Mutex
	t        *Table
	locals   []Local
	keys     map[string]map[string]string // bridge -> key id -> key, of locals (derived once, not per frame)
	gone     map[string]map[string]string // bridge -> key id -> key: withdrawals to send once
	conns    map[string]Conn
	seq      uint64
	known    map[string]bool // units with an accepted announcement
	want     map[string]bool // bridges owed an announcement soon
	lastSend map[string]time.Time
	openErr  map[string]string
	dirty    bool
	logged   map[Verdict]uint64 // stats at the last drop summary

	kick    chan struct{}
	changed chan struct{}
	wg      sync.WaitGroup
}

// New returns a Service; Run starts it.
func New(o Options) *Service {
	if o.Interval <= 0 {
		o.Interval = DefaultInterval
	}
	if o.TTL <= 0 {
		o.TTL = o.Interval*3 + o.Interval/2
	}
	if o.MinGap <= 0 {
		o.MinGap = 2 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Open == nil {
		o.Open = OpenRaw
	}
	unit := ""
	if len(o.Unit) == 6 {
		unit = NormMAC(o.Unit.String())
	}
	return &Service{o: o, unit: unit, epoch: uint64(o.Now().UnixNano()),
		t: NewTable(unit, o.TTL), gone: map[string]map[string]string{}, conns: map[string]Conn{},
		known: map[string]bool{}, want: map[string]bool{}, lastSend: map[string]time.Time{}, openErr: map[string]string{},
		logged: map[Verdict]uint64{}, kick: make(chan struct{}, 1), changed: make(chan struct{}, 1)}
}

func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// keysOn returns the WLAN keys of the locals on bridge, by key id.
func keysOn(locals []Local, bridge string) map[string]string {
	out := map[string]string{}
	for _, l := range locals {
		if l.Bridge == bridge && l.Key != "" {
			out[KeyID(l.Key)] = l.Key
		}
	}
	return out
}

func fingerprint(ls []Local) string {
	var s []string
	for _, l := range ls {
		s = append(s, l.String()+" "+KeyID(l.Key))
	}
	sort.Strings(s)
	return strings.Join(s, "\n")
}

// SetLocals replaces this unit's FT-SAE BSSes (nil: none, e.g. Wi-Fi went
// back to TP-Link). A change is announced at once; a WLAN no longer served
// on a bridge is withdrawn there with one empty announcement, and the
// peers learnt for it are dropped.
func (s *Service) SetLocals(ls []Local) {
	var valid []Local
	for _, l := range ls {
		l.BSSID, l.R1KHID = NormMAC(l.BSSID), NormMAC(l.R1KHID)
		if l.Bridge == "" || l.Key == "" || l.Holder.Valid() != nil {
			s.o.Logf("ft-peers: local holder %s not announced (invalid)", l)
			continue
		}
		valid = append(valid, l)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if fingerprint(valid) == fingerprint(s.locals) {
		return
	}
	oldBridges := map[string]map[string]string{}
	for _, l := range s.locals {
		if oldBridges[l.Bridge] == nil {
			oldBridges[l.Bridge] = keysOn(s.locals, l.Bridge)
		}
	}
	s.locals = valid
	s.keys = map[string]map[string]string{}
	for _, l := range valid {
		if s.keys[l.Bridge] == nil {
			s.keys[l.Bridge] = keysOn(valid, l.Bridge)
		}
	}
	for br, old := range oldBridges {
		now := keysOn(valid, br)
		for id, k := range old {
			if _, ok := now[id]; !ok {
				if s.gone[br] == nil {
					s.gone[br] = map[string]string{}
				}
				s.gone[br][id] = k
			}
		}
		if s.t.Forget(br, func(id string) bool { _, ok := now[id]; return ok }) {
			s.dirty = true
			signal(s.changed)
		}
	}
	for _, l := range valid {
		s.want[l.Bridge] = true
	}
	for br := range s.gone {
		s.want[br] = true
	}
	s.o.Logf("ft-peers: announcing %d key holder(s) on %v", len(valid), bridgesOf(valid))
	signal(s.kick)
}

func bridgesOf(ls []Local) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range ls {
		if !seen[l.Bridge] {
			seen[l.Bridge] = true
			out = append(out, l.Bridge)
		}
	}
	sort.Strings(out)
	return out
}

// Peers returns the peers known now.
func (s *Service) Peers() []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.t.Peers()
}

// Stats returns the per-verdict frame counts.
func (s *Service) Stats() map[Verdict]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.t.Stats()
}

// receive handles one frame heard on bridge.
func (s *Service) receive(bridge string, frame []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// s.keys, not keysOn: a frame costs no key derivation before the rate
	// limits (Table.Receive verifies only frames that passed them).
	v, changed, unit := s.t.Receive(bridge, frame, s.keys[bridge], s.o.Now())
	if v != Accepted {
		return
	}
	if !s.known[unit] {
		s.known[unit] = true
		s.o.Logf("ft-peers: unit %s heard on %s", unit, bridge)
		// It may not know us yet: answer soon rather than at the next
		// interval, so two agents converge within seconds.
		s.want[bridge] = true
		signal(s.kick)
	}
	if changed {
		s.dirty = true
		signal(s.changed)
	}
}

// Run announces and listens until ctx ends; the sockets are closed then.
func (s *Service) Run(ctx context.Context) {
	tick := time.NewTicker(s.o.Interval)
	defer tick.Stop()
	defer s.closeAll()
	var reported map[string]bool
	s.step(ctx, true)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.step(ctx, true)
		case <-s.kick:
			s.step(ctx, false)
		case <-s.changed:
		}
		reported = s.notify(reported)
	}
}

// step opens and closes sockets as the locals need, expires peers (on the
// interval) and sends the announcements due.
func (s *Service) step(ctx context.Context, interval bool) {
	s.reconcile(ctx)
	s.mu.Lock()
	now := s.o.Now()
	if interval {
		if s.t.Expire(now) {
			s.dirty = true
		}
		// A unit whose peers expired is new again when it comes back.
		s.known = map[string]bool{}
		for _, p := range s.t.Peers() {
			s.known[p.Unit] = true
		}
		for _, l := range s.locals {
			s.want[l.Bridge] = true
		}
		s.logDrops()
	}
	type out struct {
		c      Conn
		bridge string
		frames [][]byte
	}
	var sends []out
	var later bool
	for br := range s.want {
		c := s.conns[br]
		if c == nil {
			continue // not open (yet): the next step retries
		}
		if !interval && now.Sub(s.lastSend[br]) < s.o.MinGap {
			later = true
			continue
		}
		delete(s.want, br)
		s.lastSend[br] = now
		sends = append(sends, out{c, br, s.framesFor(br)})
	}
	s.mu.Unlock()
	if later {
		time.AfterFunc(s.o.MinGap, func() { signal(s.kick) })
	}
	for _, o := range sends {
		for _, f := range o.frames {
			if err := o.c.Send(f); err != nil && ctx.Err() == nil {
				s.o.Logf("ft-peers: send on %s: %v", o.bridge, err)
				break
			}
		}
	}
}

// framesFor builds bridge's announcements: one per WLAN key served there,
// one empty one per key withdrawn there (sent once). s.mu is held.
func (s *Service) framesFor(br string) [][]byte {
	byKey := map[string][]Holder{}
	keys := map[string]string{}
	for _, l := range s.locals {
		if l.Bridge != br {
			continue
		}
		id := KeyID(l.Key)
		keys[id] = l.Key
		byKey[id] = append(byKey[id], l.Holder)
	}
	for id, k := range s.gone[br] {
		if _, ok := keys[id]; !ok {
			keys[id] = k
			byKey[id] = nil
		}
	}
	delete(s.gone, br)
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var frames [][]byte
	for _, id := range ids {
		hs := byKey[id]
		if len(hs) > MaxHolders {
			s.o.Logf("ft-peers: %d holders for one WLAN on %s, announcing %d", len(hs), br, MaxHolders)
			hs = hs[:MaxHolders]
		}
		sortHolders(hs)
		s.seq++
		p, err := Encode(Announcement{Unit: s.unit, Epoch: s.epoch, Seq: s.seq, KeyID: id, Holders: hs}, keys[id])
		if err != nil {
			s.o.Logf("ft-peers: announcement on %s not built: %v", br, err)
			continue
		}
		frames = append(frames, Frame(s.o.Unit, p))
	}
	return frames
}

// reconcile opens a socket per bridge the locals use (or that owes a
// withdrawal) and closes the others.
func (s *Service) reconcile(ctx context.Context) {
	s.mu.Lock()
	need := map[string]bool{}
	for _, l := range s.locals {
		need[l.Bridge] = true
	}
	for br := range s.gone {
		need[br] = true
	}
	var open []string
	for br := range need {
		if s.conns[br] == nil {
			open = append(open, br)
		}
	}
	var closeC []Conn
	for br, c := range s.conns {
		if !need[br] {
			closeC = append(closeC, c)
			delete(s.conns, br)
			delete(s.lastSend, br)
		}
	}
	s.mu.Unlock()
	for _, c := range closeC {
		_ = c.Close()
	}
	sort.Strings(open)
	for _, br := range open {
		if ctx.Err() != nil || s.unit == "" {
			return
		}
		c, err := s.o.Open(br)
		s.mu.Lock()
		if err != nil {
			if msg := err.Error(); s.openErr[br] != msg {
				s.openErr[br] = msg
				s.o.Logf("ft-peers: %s: %v (retried every %s)", br, err, s.o.Interval)
			}
			s.mu.Unlock()
			continue
		}
		delete(s.openErr, br)
		s.conns[br] = c
		s.want[br] = true
		s.mu.Unlock()
		s.wg.Add(1)
		go func(br string, c Conn) {
			defer s.wg.Done()
			s.recvLoop(ctx, br, c)
		}(br, c)
	}
}

func (s *Service) recvLoop(ctx context.Context, br string, c Conn) {
	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		n, err := c.Recv(buf)
		if errors.Is(err, ErrTimeout) {
			continue
		}
		if err != nil {
			return // closed (reconcile, shutdown)
		}
		s.receive(br, buf[:n])
	}
}

func (s *Service) closeAll() {
	s.mu.Lock()
	for br, c := range s.conns {
		_ = c.Close()
		delete(s.conns, br)
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// notify hands the peer set to OnChange when it changed, and logs peers
// that appeared or went (and, with OnAir, those the scans have not seen).
func (s *Service) notify(prev map[string]bool) map[string]bool {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return prev
	}
	s.dirty = false
	peers := s.t.Peers()
	s.mu.Unlock()
	cur := map[string]bool{}
	for _, p := range peers {
		id := p.Bridge + " " + p.BSSID + " " + p.KeyID
		cur[id] = true
		if prev[id] {
			continue
		}
		air := ""
		if s.o.OnAir != nil {
			if seen, known := s.o.OnAir(p.BSSID); known && !seen {
				air = " (not in the last neighbour scan)"
			}
		}
		s.o.Logf("ft-peers: peer %s %s r0kh-id %s mdid %04x of unit %s on %s%s", p.Band, p.BSSID, p.R0KHID, p.MDID, p.Unit, p.Bridge, air)
	}
	for id := range prev {
		if !cur[id] {
			f := strings.Fields(id)
			s.o.Logf("ft-peers: peer %s on %s gone (expired or withdrawn)", f[1], f[0])
		}
	}
	if s.o.OnChange != nil {
		s.o.OnChange(peers)
	}
	return cur
}

// logDrops logs, once per interval at most, the frames refused since the
// last summary (no key material: counts only). s.mu is held.
func (s *Service) logDrops() {
	st := s.t.Stats()
	var parts []string
	for _, v := range []Verdict{AuthFailed, Replayed, RateLimited, Malformed} {
		if d := st[v] - s.logged[v]; d > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", v, d))
		}
		s.logged[v] = st[v]
	}
	if len(parts) > 0 {
		s.o.Logf("ft-peers: ignored announcements: %s", strings.Join(parts, ", "))
	}
}
