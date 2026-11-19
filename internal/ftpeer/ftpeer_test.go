// SPDX-License-Identifier: GPL-2.0-or-later

package ftpeer

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fake per-WLAN keys (32 hex digits, as the controller's x_iapp_key).
const (
	keyA = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	keyB = "ffeeddccbbaa99887766554433221100"
)

var (
	unitA = net.HardwareAddr{0x02, 0xa0, 0, 0, 0, 1}
	unitB = net.HardwareAddr{0x02, 0xb0, 0, 0, 0, 1}
	t0    = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
)

func holder(bssid, band string, md uint16) Holder {
	return Holder{Band: band, BSSID: bssid, R0KHID: strings.ReplaceAll(bssid, ":", ""), R1KHID: bssid, MDID: md}
}

// frameOf builds unit's announcement of hs under key.
func frameOf(t *testing.T, unit net.HardwareAddr, epoch, seq uint64, key string, hs ...Holder) []byte {
	t.Helper()
	p, err := Encode(Announcement{Unit: unit.String(), Epoch: epoch, Seq: seq, KeyID: KeyID(key), Holders: hs}, key)
	if err != nil {
		t.Fatal(err)
	}
	return Frame(unit, p)
}

func keys(ks ...string) map[string]string {
	m := map[string]string{}
	for _, k := range ks {
		m[KeyID(k)] = k
	}
	return m
}

// The key id names the key without revealing it, is case-insensitive in
// the key, and differs per key; the wire format round-trips.
func TestWireRoundTrip(t *testing.T) {
	if KeyID(keyA) == KeyID(keyB) || KeyID(keyA) != KeyID(strings.ToUpper(keyA)) || len(KeyID(keyA)) != 16 {
		t.Fatalf("key ids %s %s", KeyID(keyA), KeyID(keyB))
	}
	if strings.Contains(keyA, KeyID(keyA)) {
		t.Fatal("key id is part of the key")
	}
	hs := []Holder{holder("be:a7:b9:3e:17:05", "na", 0xff24), holder("ba:a7:b9:3e:17:04", "ng", 0x9216)}
	hs[0].R0KHID = "nas-1.x_y:Z"
	f := frameOf(t, unitA, 7, 9, keyA, hs...)
	if bytes.Contains(f, []byte(keyA)) || strings.Contains(fmt.Sprintf("%x", f), keyA) {
		t.Fatal("key on the wire")
	}
	src, p, ok := unframe(f)
	if !ok || src != unitA.String() {
		t.Fatalf("unframe %v %s", ok, src)
	}
	a, err := Parse(p)
	if err != nil || !Verify(p, keyA) || Verify(p, keyB) {
		t.Fatalf("parse %v verify A %t B %t", err, Verify(p, keyA), Verify(p, keyB))
	}
	if a.Unit != unitA.String() || a.Epoch != 7 || a.Seq != 9 || a.KeyID != KeyID(keyA) || len(a.Holders) != 2 || a.Holders[0] != hs[0] || a.Holders[1] != hs[1] {
		t.Errorf("round trip %+v", a)
	}
	// Every truncation and every flipped byte is refused (parse or HMAC).
	for i := range p {
		if _, err := Parse(p[:i]); err == nil && Verify(p[:i], keyA) {
			t.Fatalf("truncated to %d accepted", i)
		}
		q := append([]byte(nil), p...)
		q[i] ^= 0x40
		if _, err := Parse(q); err == nil && Verify(q, keyA) {
			t.Fatalf("byte %d flipped accepted", i)
		}
	}
	// Holders a hostapd conf line could not carry are refused at both ends.
	for _, bad := range []Holder{
		{Band: "na", BSSID: "be:a7:b9:3e:17:05", R0KHID: "two words", R1KHID: "be:a7:b9:3e:17:05"},
		{Band: "na", BSSID: "be:a7:b9:3e:17:05", R0KHID: "", R1KHID: "be:a7:b9:3e:17:05"},
		{Band: "na", BSSID: "be:a7:b9:3e:17:05", R0KHID: strings.Repeat("a", 49), R1KHID: "be:a7:b9:3e:17:05"},
		{Band: "na", BSSID: "ff:ff:ff:ff:ff:ff", R0KHID: "x", R1KHID: "be:a7:b9:3e:17:05"},
		{Band: "na", BSSID: "00:00:00:00:00:00", R0KHID: "x", R1KHID: "be:a7:b9:3e:17:05"},
		{Band: "6g", BSSID: "be:a7:b9:3e:17:05", R0KHID: "x", R1KHID: "be:a7:b9:3e:17:05"},
		{Band: "na", BSSID: "be:a7:b9:3e:17:05", R0KHID: "x\nr0kh=evil", R1KHID: "be:a7:b9:3e:17:05"},
	} {
		if _, err := Encode(Announcement{Unit: unitA.String(), KeyID: KeyID(keyA), Holders: []Holder{bad}}, keyA); err == nil {
			t.Errorf("encoded %+v", bad)
		}
	}
}

// Receive: a valid frame from another unit is taken; own frames, frames
// under a key not served on that bridge, a wrong HMAC, a replay and a
// unit/source mismatch are ignored and leave the peers as they were.
func TestTableReceive(t *testing.T) {
	tb := NewTable(unitA.String(), time.Minute)
	ks := keys(keyA)
	hb := holder("02:b0:00:00:01:02", "na", 0xff24)
	f := frameOf(t, unitB, 100, 1, keyA, hb)
	if v, ch, u := tb.Receive("br-lan", f, ks, t0); v != Accepted || !ch || u != unitB.String() {
		t.Fatalf("valid frame: %v changed %t unit %s", v, ch, u)
	}
	peers := tb.Peers()
	if len(peers) != 1 || peers[0].Holder != hb || peers[0].Unit != unitB.String() || peers[0].KeyID != KeyID(keyA) || peers[0].Bridge != "br-lan" {
		t.Fatalf("peers %+v", peers)
	}
	cases := []struct {
		name string
		f    []byte
		br   string
		ks   map[string]string
		want Verdict
	}{
		{"own frame", frameOf(t, unitA, 100, 2, keyA, hb), "br-lan", ks, Own},
		{"own unit from another source", resource(frameOf(t, unitA, 100, 2, keyA, hb), unitB), "br-lan", ks, Own},
		{"own source, another unit", resource(frameOf(t, unitB, 100, 2, keyA, hb), unitA), "br-lan", ks, Own},
		{"same frame again (replay)", f, "br-lan", ks, Replayed},
		{"older sequence (replay)", frameOf(t, unitB, 100, 0, keyA, holder("02:b0:00:00:01:09", "na", 0xff24)), "br-lan", ks, Replayed},
		{"older epoch (replay)", frameOf(t, unitB, 99, 50, keyA, holder("02:b0:00:00:01:09", "na", 0xff24)), "br-lan", ks, Replayed},
		{"key not served on this bridge", frameOf(t, unitB, 100, 3, keyB, hb), "br-lan", ks, UnknownKey},
		{"key served on another bridge only", frameOf(t, unitB, 100, 4, keyA, hb), "br-v20", nil, UnknownKey},
		{"forged: another key's HMAC under this key id", forge(t, frameOf(t, unitB, 100, 5, keyB, holder("02:b0:00:00:01:09", "na", 0xff24)), KeyID(keyA)), "br-lan", ks, AuthFailed},
		{"tampered holder", tamper(t, frameOf(t, unitB, 100, 6, keyA, hb)), "br-lan", ks, AuthFailed},
		{"source is not the unit", resource(frameOf(t, unitB, 100, 7, keyA, hb), net.HardwareAddr{0x02, 0xcc, 0, 0, 0, 1}), "br-lan", ks, Malformed},
		{"not ours", append(append([]byte(nil), GroupMAC...), make([]byte, 60)...), "br-lan", ks, NotOurs},
	}
	for _, c := range cases {
		v, ch, _ := tb.Receive(c.br, c.f, c.ks, t0.Add(time.Second))
		if v != c.want || ch {
			t.Errorf("%s: %v changed %t, want %v unchanged", c.name, v, ch, c.want)
		}
	}
	if p := tb.Peers(); len(p) != 1 || p[0].BSSID != hb.BSSID {
		t.Errorf("peers changed by refused frames: %+v", p)
	}
	st := tb.Stats()
	if st[AuthFailed] != 2 || st[Replayed] != 3 || st[Own] != 3 {
		t.Errorf("stats %v", st)
	}
	// A newer frame with the same holders is taken, unchanged; a restarted
	// sender (newer epoch, sequence from 1) too.
	if v, ch, _ := tb.Receive("br-lan", frameOf(t, unitB, 100, 9, keyA, hb), ks, t0.Add(2*time.Second)); v != Accepted || ch {
		t.Errorf("refresh: %v %t", v, ch)
	}
	if v, ch, _ := tb.Receive("br-lan", frameOf(t, unitB, 200, 1, keyA, hb), ks, t0.Add(3*time.Second)); v != Accepted || ch {
		t.Errorf("restarted sender: %v %t", v, ch)
	}
}

// forge rewrites a frame's key id (its HMAC stays the other key's).
func forge(t *testing.T, f []byte, keyID string) []byte {
	t.Helper()
	g := append([]byte(nil), f...)
	kid, err := hex.DecodeString(keyID)
	if err != nil || len(kid) != 8 {
		t.Fatal(keyID)
	}
	copy(g[ethHdrLen+28:ethHdrLen+36], kid)
	return g
}

// tamper changes the first holder's BSSID (still a valid holder).
func tamper(t *testing.T, f []byte) []byte {
	t.Helper()
	g := append([]byte(nil), f...)
	g[ethHdrLen+headerLen+3+5] ^= 0x10
	return g
}

// resource replaces the Ethernet source.
func resource(f []byte, src net.HardwareAddr) []byte {
	g := append([]byte(nil), f...)
	copy(g[6:12], src)
	return g
}

// Peers expire when their announcements stop (and their replay state with
// them, so a unit that came back with its clock behind is accepted again);
// an empty announcement withdraws them at once.
func TestTableExpiryAndWithdrawal(t *testing.T) {
	tb := NewTable(unitA.String(), time.Minute)
	ks := keys(keyA)
	hb := holder("02:b0:00:00:01:02", "na", 0xff24)
	tb.Receive("br-lan", frameOf(t, unitB, 100, 1, keyA, hb), ks, t0)
	if tb.Expire(t0.Add(59*time.Second)) || len(tb.Peers()) != 1 {
		t.Fatal("expired early")
	}
	if !tb.Expire(t0.Add(61*time.Second)) || len(tb.Peers()) != 0 {
		t.Fatal("not expired")
	}
	// Back after a reboot with an older clock: accepted (state expired).
	if v, ch, _ := tb.Receive("br-lan", frameOf(t, unitB, 50, 1, keyA, hb), ks, t0.Add(2*time.Minute)); v != Accepted || !ch {
		t.Fatalf("returning unit: %v %t", v, ch)
	}
	if v, ch, _ := tb.Receive("br-lan", frameOf(t, unitB, 50, 2, keyA), ks, t0.Add(2*time.Minute)); v != Accepted || !ch || len(tb.Peers()) != 0 {
		t.Fatalf("withdrawal: %v %t %v", v, ch, tb.Peers())
	}
	// Forget: this unit stopped serving the key on that bridge.
	tb.Receive("br-lan", frameOf(t, unitB, 50, 3, keyA, hb), ks, t0.Add(3*time.Minute))
	if !tb.Forget("br-lan", func(string) bool { return false }) || len(tb.Peers()) != 0 {
		t.Error("forget")
	}
}

// Rate limits apply before any cryptography: a source flooding valid-
// looking frames is cut off after its burst, others still get through
// until the global limit, and the table stays bounded.
func TestTableRateLimits(t *testing.T) {
	tb := NewTable(unitA.String(), time.Minute)
	ks := keys(keyA)
	limited := 0
	for i := 0; i < 100; i++ {
		f := frameOf(t, unitB, 100, uint64(i+1), keyA, holder("02:b0:00:00:01:02", "na", 0xff24))
		if v, _, _ := tb.Receive("br-lan", f, ks, t0); v == RateLimited {
			limited++
		}
	}
	if limited != 100-int(srcBurst) {
		t.Errorf("one source: %d of 100 limited, want %d", limited, 100-int(srcBurst))
	}
	// A second later the source has 2 more tokens.
	ok := 0
	for i := 0; i < 5; i++ {
		f := frameOf(t, unitB, 100, uint64(200+i), keyA, holder("02:b0:00:00:01:02", "na", 0xff24))
		if v, _, _ := tb.Receive("br-lan", f, ks, t0.Add(time.Second)); v == Accepted {
			ok++
		}
	}
	if ok != int(srcRate) {
		t.Errorf("after 1 s: %d accepted, want %d", ok, int(srcRate))
	}
	// Many sources: the global bucket holds.
	tb = NewTable(unitA.String(), time.Minute)
	acc := 0
	for i := 0; i < 500; i++ {
		u := net.HardwareAddr{0x02, 0xc0, 0, 0, byte(i >> 8), byte(i)}
		if v, _, _ := tb.Receive("br-lan", frameOf(t, u, 1, 1, keyB), ks, t0); v != RateLimited {
			acc++
		}
	}
	if acc != int(globalBurst) || len(tb.src) > maxSources {
		t.Errorf("global: %d through (want %d), %d buckets", acc, int(globalBurst), len(tb.src))
	}
}

// bus is an in-memory L2 segment per bridge.
type bus struct {
	mu    sync.Mutex
	conns map[string][]*busConn
	wire  [][]byte
}

type busConn struct {
	b      *bus
	br     string
	in     chan []byte
	closed chan struct{}
	once   sync.Once
}

func (b *bus) open(br string) (Conn, error) {
	c := &busConn{b: b, br: br, in: make(chan []byte, 64), closed: make(chan struct{})}
	b.mu.Lock()
	b.conns[br] = append(b.conns[br], c)
	b.mu.Unlock()
	return c, nil
}

func (c *busConn) Recv(p []byte) (int, error) {
	select {
	case f := <-c.in:
		return copy(p, f), nil
	case <-c.closed:
		return 0, net.ErrClosed
	case <-time.After(20 * time.Millisecond):
		return 0, ErrTimeout
	}
}

func (c *busConn) Send(f []byte) error {
	c.b.mu.Lock()
	defer c.b.mu.Unlock()
	c.b.wire = append(c.b.wire, append([]byte(nil), f...))
	for _, o := range c.b.conns[c.br] {
		select {
		case <-o.closed:
			continue
		default:
		}
		if o != c {
			select {
			case o.in <- append([]byte(nil), f...):
			default:
			}
		}
	}
	return nil
}

func (c *busConn) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

type logs struct {
	mu sync.Mutex
	l  []string
}

func (l *logs) logf(f string, a ...any) {
	l.mu.Lock()
	l.l = append(l.l, fmt.Sprintf(f, a...))
	l.mu.Unlock()
}

func (l *logs) all() string { l.mu.Lock(); defer l.mu.Unlock(); return strings.Join(l.l, "\n") }

// Two services on one segment: each learns the other's holders within
// one triggered exchange (not an interval), OnChange fires; a WLAN the
// other side does not serve is not learnt; when one stops serving it is
// withdrawn at once; when one goes silent, its peers expire. Keys never
// reach a log or the wire.
func TestServiceDiscoveryAndExpiry(t *testing.T) {
	b := &bus{conns: map[string][]*busConn{}}
	lg := &logs{}
	var mu sync.Mutex
	changes := map[string]int{}
	mk := func(name string, unit net.HardwareAddr) *Service {
		return New(Options{Unit: unit, Open: b.open, Interval: time.Hour, TTL: 300 * time.Millisecond, MinGap: time.Millisecond,
			Logf: lg.logf, OnChange: func([]Peer) { mu.Lock(); changes[name]++; mu.Unlock() },
			OnAir: func(bssid string) (bool, bool) { return bssid != "02:b0:00:00:00:02", true }})
	}
	sa, sb := mk("A", unitA), mk("B", unitB)
	la := []Local{{Holder: holder("02:a0:00:00:01:02", "na", 0xff24), Bridge: "br-lan", Key: keyA},
		{Holder: holder("02:a0:00:00:00:02", "ng", 0x9216), Bridge: "br-lan", Key: keyA}}
	lb := []Local{{Holder: holder("02:b0:00:00:01:02", "na", 0xff24), Bridge: "br-lan", Key: keyA},
		{Holder: holder("02:b0:00:00:00:02", "ng", 0x9216), Bridge: "br-lan", Key: keyA},
		{Holder: holder("02:b0:00:00:01:03", "na", 0x1234), Bridge: "br-lan", Key: keyB}} // A does not serve keyB
	sa.SetLocals(la)
	sb.SetLocals(lb)
	ctxA, stopA := context.WithCancel(context.Background())
	ctxB, stopB := context.WithCancel(context.Background())
	defer stopA()
	defer stopB()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); sa.Run(ctxA) }()
	go func() { defer wg.Done(); sb.Run(ctxB) }()
	eventually(t, "A learns B's two holders", func() bool { return len(sa.Peers()) == 2 })
	eventually(t, "B learns A's two holders", func() bool { return len(sb.Peers()) == 2 })
	for _, p := range sa.Peers() {
		if p.Unit != unitB.String() || p.KeyID != KeyID(keyA) {
			t.Errorf("A learnt %+v", p)
		}
	}
	mu.Lock()
	if changes["A"] == 0 || changes["B"] == 0 {
		t.Errorf("OnChange not called: %v", changes)
	}
	mu.Unlock()
	if !strings.Contains(lg.all(), "not in the last neighbour scan") {
		t.Error("the scan cross-check did not report a holder it has not seen")
	}

	// B stops serving its 2.4 GHz BSS: withdrawn by the next announcement.
	sb.SetLocals([]Local{lb[0], lb[2]})
	eventually(t, "A drops B's withdrawn holder", func() bool { return len(sa.Peers()) == 1 })
	// B goes silent: A expires it at its next interval step.
	stopB()
	time.Sleep(400 * time.Millisecond)
	sa.mu.Lock()
	sa.want["br-lan"] = true
	sa.mu.Unlock()
	sa.step(ctxA, true)
	if p := sa.Peers(); len(p) != 0 {
		t.Errorf("B's peers did not expire: %+v", p)
	}
	stopA()
	wg.Wait()
	all := lg.all()
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, k := range []string{keyA, keyB} {
		if strings.Contains(all, k) {
			t.Fatal("key in a log line")
		}
		for _, f := range b.wire {
			if bytes.Contains(f, []byte(k)) || strings.Contains(fmt.Sprintf("%x", f), k) {
				t.Fatal("key on the wire")
			}
		}
	}
	if s := fmt.Sprintf("%v %+v %#v", la, la, la); strings.Contains(s, keyA) {
		t.Fatalf("Local prints its key: %s", s)
	}
}

// A service with another unit's frames but the wrong key learns nothing,
// and says so (counts only) in its summary.
func TestServiceIgnoresWrongKey(t *testing.T) {
	b := &bus{conns: map[string][]*busConn{}}
	lg := &logs{}
	sa := New(Options{Unit: unitA, Open: b.open, Interval: time.Hour, MinGap: time.Millisecond, Logf: lg.logf})
	sa.SetLocals([]Local{{Holder: holder("02:a0:00:00:01:02", "na", 0xff24), Bridge: "br-lan", Key: keyA}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); sa.Run(ctx) }()
	eventually(t, "A's socket", func() bool { b.mu.Lock(); defer b.mu.Unlock(); return len(b.conns["br-lan"]) == 1 })
	inj, _ := b.open("br-lan")
	inj.Send(forge(t, frameOf(t, unitB, 1, 1, keyB, holder("02:b0:00:00:01:02", "na", 0xff24)), KeyID(keyA)))
	inj.Send(frameOf(t, unitA, 1, 1, keyA, holder("02:a0:00:00:01:09", "na", 0xff24))) // "own"
	eventually(t, "the forged frame counted", func() bool { return sa.Stats()[AuthFailed] == 1 && sa.Stats()[Own] == 1 })
	if len(sa.Peers()) != 0 {
		t.Errorf("learnt %v", sa.Peers())
	}
	sa.mu.Lock()
	sa.logDrops()
	sa.mu.Unlock()
	if !strings.Contains(lg.all(), "auth failed 1") {
		t.Errorf("no summary: %s", lg.all())
	}
	cancel()
	<-done
}

// A flood of frames the rate limits refuse, or that are not announcements
// at all, costs no cryptography: the receiver's key ids are derived when
// its locals change, not per frame.
func TestServiceNoCryptoBeforeRateLimit(t *testing.T) {
	s := New(Options{Unit: unitA, Open: (&bus{conns: map[string][]*busConn{}}).open, Now: func() time.Time { return t0 }})
	s.SetLocals([]Local{
		{Holder: holder("02:a0:00:00:01:02", "na", 0xff24), Bridge: "br-lan", Key: keyA},
		{Holder: holder("02:a0:00:00:01:03", "ng", 0x9216), Bridge: "br-lan", Key: keyB},
	})
	junk := Frame(unitB, append([]byte("UDFT"), make([]byte, 60)...)) // malformed
	other := Frame(unitB, []byte("not an announcement at all"))
	src := net.HardwareAddr{0x02, 0xd0, 0, 0, 0, 1}
	flood := frameOf(t, src, 1, 1, keyA, holder("02:d0:00:00:01:02", "na", 0xff24))
	before := derivations.Load()
	for i := 0; i < 200; i++ {
		s.receive("br-lan", junk)
		s.receive("br-lan", other)
		s.receive("br-lan", flood) // the same source: rate limited after its burst
	}
	if st := s.Stats(); st[RateLimited] == 0 {
		t.Fatalf("nothing rate limited: %v", st)
	}
	// Only the frames that passed the rate limits may cost a verification
	// (one derivation each).
	passed := s.Stats()[UnknownKey] + s.Stats()[AuthFailed] + s.Stats()[Accepted] + s.Stats()[Replayed]
	if d := derivations.Load() - before; d > passed {
		t.Errorf("%d key derivations for %d frames past the rate limits", d, passed)
	}
}
