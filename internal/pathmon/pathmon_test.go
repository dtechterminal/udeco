// SPDX-License-Identifier: GPL-2.0-or-later

package pathmon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// u6proPathmon is the pathmon section of the U6 Pro's system.cfg as the
// Network 11.1.50 controller wrote it (docs/reference/u6pro/config-apply/
// tmp_system.cfg.redacted).
var u6proPathmon = map[string]string{
	"pathmon.status": "enabled", "pathmon.interval": "5", "pathmon.timeout": "1000",
	"pathmon.ema_samples": "60", "pathmon.size": "56",
	"pathmon.target.1.type": "gateway", "pathmon.target.2.type": "uplink",
}

func TestFromCfgU6Pro(t *testing.T) {
	c, notes := FromCfg(u6proPathmon)
	want := &Config{Interval: 5 * time.Second, Timeout: time.Second, EMASamples: 60, Size: 56,
		Targets: []Target{{Type: TypeGateway}, {Type: TypeUplink}}}
	if !reflect.DeepEqual(c, want) || len(notes) != 0 {
		t.Fatalf("got %+v notes %q, want %+v", c, notes, want)
	}
}

func TestFromCfgOffAndBadTargets(t *testing.T) {
	if c, _ := FromCfg(map[string]string{"pathmon.status": "disabled", "pathmon.target.1.type": "gateway"}); c != nil {
		t.Errorf("disabled: %+v", c)
	}
	if c, _ := FromCfg(map[string]string{}); c != nil {
		t.Errorf("absent: %+v", c)
	}
	cfg := map[string]string{
		"pathmon.status":         "enabled",
		"pathmon.interval":       "0",
		"pathmon.timeout":        "9000",
		"pathmon.target.10.type": "host", "pathmon.target.10.addr": "1.1.1.1",
		"pathmon.target.2.type": "host", "pathmon.target.2.addr": "example.com",
		"pathmon.target.3.type": "host", "pathmon.target.3.addr": "2001:db8::1",
		"pathmon.target.4.type": "wan",
		"pathmon.target.1.type": "gateway",
		"pathmon.target.5.type": "gateway", // duplicate
	}
	c, notes := FromCfg(cfg)
	if c == nil {
		t.Fatal("nil config")
	}
	// index order (1 before 10), only usable targets, duplicates once
	if want := []Target{{Type: TypeGateway}, {Type: TypeHost, Addr: "1.1.1.1"}}; !reflect.DeepEqual(c.Targets, want) {
		t.Errorf("targets %+v, want %+v", c.Targets, want)
	}
	if c.Interval != DefaultInterval || c.Timeout != DefaultInterval {
		t.Errorf("interval %s timeout %s: want the default interval and the timeout held to it", c.Interval, c.Timeout)
	}
	all := strings.Join(notes, "\n")
	for _, w := range []string{"pathmon.interval=\"0\"", "target 2", "target 3", "unknown type \"wan\"", "held to the interval"} {
		if !strings.Contains(all, w) {
			t.Errorf("notes lack %q:\n%s", w, all)
		}
	}
	if c, notes := FromCfg(map[string]string{"pathmon.status": "enabled", "pathmon.target.1.type": "bogus"}); c != nil || len(notes) == 0 {
		t.Errorf("no usable target: %+v %q", c, notes)
	}
}

// fakeProber answers from a table: rtt per address, or a loss.
type fakeProber struct {
	mu    sync.Mutex
	rtt   map[string]time.Duration // missing = no reply
	calls []string
	size  int
	to    time.Duration
}

func (f *fakeProber) Probe(_ context.Context, dst net.IP, size int, timeout time.Duration) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, dst.String())
	f.size, f.to = size, timeout
	if d, ok := f.rtt[dst.String()]; ok {
		return d, nil
	}
	return 0, ErrTimeout
}

func (f *fakeProber) set(ip string, d time.Duration, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ok {
		f.rtt[ip] = d
	} else {
		delete(f.rtt, ip)
	}
}

func row(t *testing.T, rep map[string]any, typ string) map[string]any {
	t.Helper()
	for _, r := range rep["targets"].([]map[string]any) {
		if r["type"] == typ {
			return r
		}
	}
	t.Fatalf("no %s row in %v", typ, rep)
	return nil
}

func TestMonitorReportsLikeU6Pro(t *testing.T) {
	p := &fakeProber{rtt: map[string]time.Duration{"192.168.0.1": 400 * time.Microsecond}}
	clock := time.Unix(1795017033, 0)
	m := New(p, func() time.Time { return clock })
	if m.Report() != nil {
		t.Fatal("report while off")
	}
	c, _ := FromCfg(u6proPathmon)
	m.SetConfig(c)
	m.SetAddrs("192.168.0.1", "")
	ctx := context.Background()
	for _, us := range []int{400, 600, 500} {
		p.set("192.168.0.1", time.Duration(us)*time.Microsecond, true)
		m.Round(ctx)
	}
	if p.size != 56 || p.to != time.Second {
		t.Errorf("probe size %d timeout %s", p.size, p.to)
	}
	rep := m.Report()
	if rep["interval"] != int64(5) || rep["ema_samples"] != 60 {
		t.Errorf("header %v", rep)
	}
	gw := row(t, rep, "gateway")
	want := map[string]any{
		"type": "gateway", "family": "ipv4", "state": "reachable", "resolved": "192.168.0.1",
		"latency_us": int64(500), "latency_us_ema": int64(500), // mean of 400, 600, 500 (warm-up)
		"jitter_us": int64(100), "jitter_us_ema": int64(150), // mean of |600-400|, |500-600|
		"loss_pcm_ema": int64(0), "samples": int64(3), "last_update_ts": int64(1795017033),
	}
	if !reflect.DeepEqual(gw, want) {
		t.Errorf("gateway row\n got %v\nwant %v", gw, want)
	}
	// the uplink device is unknown (no LLDP neighbour): pending, never probed
	up := row(t, rep, "uplink")
	if up["state"] != "pending" || up["resolved"] != "" || up["samples"] != int64(0) {
		t.Errorf("uplink row %v", up)
	}
	for _, ip := range p.calls {
		if ip != "192.168.0.1" {
			t.Errorf("probed %s", ip)
		}
	}
	// the inform carries exactly the U6 Pro's keys per row
	b, _ := json.Marshal(rep)
	var back struct {
		Targets []map[string]any `json:"targets"`
	}
	json.Unmarshal(b, &back)
	u6, err := os.ReadFile("../../docs/reference/u6pro/mca-dump.json")
	if err != nil {
		t.Skip(err)
	}
	var dump struct {
		Pathmon struct {
			Targets []map[string]any `json:"targets"`
		} `json:"pathmon"`
	}
	if err := json.Unmarshal(u6, &dump); err != nil || len(dump.Pathmon.Targets) == 0 {
		t.Fatalf("u6 dump: %v", err)
	}
	for k := range dump.Pathmon.Targets[0] {
		if _, ok := back.Targets[0][k]; !ok {
			t.Errorf("row lacks the U6 Pro key %q", k)
		}
	}
	for k := range back.Targets[0] {
		if _, ok := dump.Pathmon.Targets[0][k]; !ok {
			t.Errorf("row has key %q the U6 Pro does not send", k)
		}
	}
}

func TestMonitorLossAndUnreachable(t *testing.T) {
	p := &fakeProber{rtt: map[string]time.Duration{"10.0.0.1": time.Millisecond}}
	m := New(p, nil)
	m.SetConfig(&Config{Interval: time.Second, Timeout: time.Second, EMASamples: 4, Size: 56, Targets: []Target{{Type: TypeGateway}}})
	m.SetAddrs("10.0.0.1", "")
	ctx := context.Background()
	m.Round(ctx)
	p.set("10.0.0.1", 0, false)
	m.Round(ctx)
	m.Round(ctx)
	r := row(t, m.Report(), "gateway")
	// two of three lost: still reachable (one lost echo is no outage)
	if r["state"] != "reachable" || r["loss_pcm_ema"] != int64(66667) || r["samples"] != int64(3) || r["latency_us"] != int64(1000) {
		t.Errorf("after 2 losses: %v", r)
	}
	m.Round(ctx)
	r = row(t, m.Report(), "gateway")
	if r["state"] != "unreachable" || r["loss_pcm_ema"] != int64(75000) {
		t.Errorf("after 3 losses: %v", r)
	}
	// past the window the average is exponential: weight 1/4
	p.set("10.0.0.1", time.Millisecond, true)
	m.Round(ctx)
	r = row(t, m.Report(), "gateway")
	if r["state"] != "reachable" || r["loss_pcm_ema"] != int64(56250) {
		t.Errorf("answered again: %v", r)
	}
}

func TestMonitorAddressChangeStartsAfresh(t *testing.T) {
	p := &fakeProber{rtt: map[string]time.Duration{"10.0.0.1": time.Millisecond, "10.0.0.2": 2 * time.Millisecond}}
	m := New(p, nil)
	c, _ := FromCfg(u6proPathmon)
	m.SetConfig(c)
	m.SetAddrs("10.0.0.1", "10.0.0.2")
	m.Round(context.Background())
	m.SetAddrs("10.0.0.1", "10.0.0.2") // unchanged: figures kept
	if r := row(t, m.Report(), "uplink"); r["samples"] != int64(1) || r["latency_us"] != int64(2000) {
		t.Errorf("uplink %v", r)
	}
	m.SetAddrs("10.0.0.1", "") // the uplink device is gone
	if r := row(t, m.Report(), "uplink"); r["samples"] != int64(0) || r["state"] != "pending" || r["resolved"] != "" {
		t.Errorf("uplink after loss of its address %v", r)
	}
	if r := row(t, m.Report(), "gateway"); r["samples"] != int64(1) {
		t.Errorf("gateway reset by an uplink change: %v", r)
	}
	// the same config again keeps the figures; a different one does not
	c2, _ := FromCfg(u6proPathmon)
	m.SetConfig(c2)
	if r := row(t, m.Report(), "gateway"); r["samples"] != int64(1) {
		t.Errorf("unchanged config reset the figures: %v", r)
	}
	c2.EMASamples = 30
	m.SetConfig(c2)
	if r := row(t, m.Report(), "gateway"); r["samples"] != int64(0) {
		t.Errorf("changed config kept the figures: %v", r)
	}
	m.SetConfig(nil)
	if m.Report() != nil {
		t.Error("report after off")
	}
}

func TestMonitorHostTarget(t *testing.T) {
	p := &fakeProber{rtt: map[string]time.Duration{"192.168.0.53": 3 * time.Millisecond}}
	m := New(p, nil)
	c, _ := FromCfg(map[string]string{"pathmon.status": "enabled",
		"pathmon.target.1.type": "host", "pathmon.target.1.addr": "192.168.0.53"})
	m.SetConfig(c)
	m.Round(context.Background())
	r := row(t, m.Report(), "host")
	if r["addr"] != "192.168.0.53" || r["resolved"] != "192.168.0.53" || r["state"] != "reachable" {
		t.Errorf("host row %v", r)
	}
}

// blockingProber waits for ctx: Run must stop promptly with it.
type blockingProber struct{ started chan struct{} }

func (b *blockingProber) Probe(ctx context.Context, _ net.IP, _ int, _ time.Duration) (time.Duration, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestRunStopsWithContextAndDropsCutProbes(t *testing.T) {
	b := &blockingProber{started: make(chan struct{}, 1)}
	m := New(b, nil)
	c, _ := FromCfg(u6proPathmon)
	m.SetConfig(c)
	m.SetAddrs("10.0.0.1", "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	<-b.started
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if r := row(t, m.Report(), "gateway"); r["samples"] != int64(0) {
		t.Errorf("a probe cut by shutdown counted: %v", r)
	}
}

func TestRunProbesEveryInterval(t *testing.T) {
	p := &fakeProber{rtt: map[string]time.Duration{"10.0.0.1": time.Millisecond}}
	m := New(p, nil)
	m.SetConfig(&Config{Interval: time.Second, Timeout: time.Second, EMASamples: 60, Size: 56, Targets: []Target{{Type: TypeGateway}}})
	m.SetAddrs("10.0.0.1", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r := row(t, m.Report(), "gateway"); r["samples"].(int64) >= 2 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("fewer than 2 probes in 5 s: %v", m.Report())
}

// --- ICMP ---

func TestChecksum(t *testing.T) {
	// RFC 1071 example bytes 00 01 f2 03 f4 f5 f6 f7: sum 0xddf2, checksum 0x220d
	if c := checksum([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}); c != 0x220d {
		t.Errorf("checksum %#04x", c)
	}
	pkt := echoPacket(icmpEchoRequest, 0x1234, 7, []byte("abcdefghi"))
	if checksum(pkt) != 0 {
		t.Errorf("packet does not verify: %x", pkt)
	}
}

// memConn is a PacketConn whose peer answers echo requests like a host
// would, after noise: a reply from another host, a reply with another id,
// one with another token, and the kernel's copy of our own request.
type memConn struct {
	mu       sync.Mutex
	in       chan pkt
	deadline time.Time
	answer   bool
	sent     []byte
}

type pkt struct {
	b    []byte
	from net.Addr
}

func (c *memConn) WriteTo(b []byte, to net.Addr) (int, error) {
	c.mu.Lock()
	c.sent = append([]byte{}, b...)
	c.mu.Unlock()
	dst := to.(*net.IPAddr).IP
	id := uint16(b[4])<<8 | uint16(b[5])
	seq := uint16(b[6])<<8 | uint16(b[7])
	payload := b[8:]
	other := append([]byte{}, payload...)
	other[0] ^= 0xff
	c.in <- pkt{echoPacket(icmpEchoReply, id, seq, payload), &net.IPAddr{IP: net.ParseIP("10.9.9.9")}}
	c.in <- pkt{echoPacket(icmpEchoReply, id+1, seq, payload), &net.IPAddr{IP: dst}}
	c.in <- pkt{echoPacket(icmpEchoReply, id, seq, other), &net.IPAddr{IP: dst}}
	c.in <- pkt{b, &net.IPAddr{IP: dst}} // our own request (type 8)
	if c.answer {
		c.in <- pkt{echoPacket(icmpEchoReply, id, seq, payload), &net.IPAddr{IP: dst}}
	}
	return len(b), nil
}

func (c *memConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	t := time.NewTimer(time.Until(d))
	defer t.Stop()
	select {
	case p := <-c.in:
		return copy(b, p.b), p.from, nil
	case <-t.C:
		return 0, nil, timeoutErr{}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func (c *memConn) Close() error        { return nil }
func (c *memConn) LocalAddr() net.Addr { return &net.IPAddr{} }
func (c *memConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}
func (c *memConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *memConn) SetWriteDeadline(t time.Time) error { return nil }

func TestICMPProbeMatchesOnlyItsReply(t *testing.T) {
	conn := &memConn{in: make(chan pkt, 8), answer: true}
	p := &ICMP{Listen: func() (net.PacketConn, error) { return conn, nil }}
	rtt, err := p.Probe(context.Background(), net.ParseIP("192.168.0.1"), 56, time.Second)
	if err != nil || rtt <= 0 {
		t.Fatalf("rtt %s err %v", rtt, err)
	}
	if len(conn.sent) != 8+56 || conn.sent[0] != icmpEchoRequest || checksum(conn.sent) != 0 {
		t.Errorf("request %x", conn.sent)
	}
	// only noise: the probe times out
	conn2 := &memConn{in: make(chan pkt, 8)}
	p2 := &ICMP{Listen: func() (net.PacketConn, error) { return conn2, nil }}
	if _, err := p2.Probe(context.Background(), net.ParseIP("192.168.0.1"), 56, 200*time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Errorf("noise only: err %v, want ErrTimeout", err)
	}
	if _, err := p2.Probe(context.Background(), net.ParseIP("2001:db8::1"), 56, time.Second); err == nil {
		t.Error("IPv6 probed")
	}
}

func TestIsReplyWithIPHeader(t *testing.T) {
	tok := []byte("12345678")
	msg := echoPacket(icmpEchoReply, 9, 10, append(tok, 1, 2, 3))
	ip := append([]byte{0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}, msg...)
	if !isReply(ip, 9, 10, tok) || !isReply(msg, 9, 10, tok) {
		t.Error("reply not recognised")
	}
	if isReply(msg, 9, 11, tok) || isReply(msg, 8, 10, tok) || isReply(msg[:10], 9, 10, tok) {
		t.Error("wrong reply accepted")
	}
}

// TestICMPLoopback sends a real echo to 127.0.0.1 when raw sockets are
// allowed (root); skipped otherwise.
func TestICMPLoopback(t *testing.T) {
	c, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		t.Skipf("no raw ICMP socket here: %v", err)
	}
	c.Close()
	rtt, err := (&ICMP{}).Probe(context.Background(), net.ParseIP("127.0.0.1"), 56, 2*time.Second)
	if err != nil || rtt <= 0 {
		t.Fatalf("loopback: %s %v", rtt, err)
	}
}
