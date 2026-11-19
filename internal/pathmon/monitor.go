// SPDX-License-Identifier: GPL-2.0-or-later

package pathmon

import (
	"context"
	"math"
	"net"
	"sync"
	"time"
)

// Prober sends one echo request to dst and waits up to timeout for its
// reply: the round-trip time, or an error (ErrTimeout when no reply came).
type Prober interface {
	Probe(ctx context.Context, dst net.IP, size int, timeout time.Duration) (time.Duration, error)
}

// Target states (the controller's enum com.ubnt.i.k.g.mMObEXELV).
const (
	StatePending     = "pending"     // no address yet, or not probed yet
	StateReachable   = "reachable"   // the last probes were answered
	StateUnreachable = "unreachable" // lostToUnreachable probes in a row went unanswered
)

// lostToUnreachable is how many unanswered probes in a row turn a target
// unreachable: one lost echo on a busy link is not an outage.
const lostToUnreachable = 3

// Monitor probes the configured targets every Interval and keeps their
// statistics. Safe for concurrent use: the agent's inform loop calls
// SetConfig, SetAddrs and Report; Run probes in its own goroutine.
type Monitor struct {
	prober Prober
	now    func() time.Time

	mu      sync.Mutex
	cfg     *Config
	addrs   map[string]string // TypeGateway/TypeUplink -> IPv4 ("" unknown)
	targets []*stats
	wake    chan struct{}
}

// stats is one target's running figures (microseconds, per-cent-mille).
type stats struct {
	Target
	resolved   string
	samples    int64
	latency    float64
	latencyEMA float64
	jitter     float64
	jitterEMA  float64
	lossEMA    float64
	answered   int64 // replies, for the averages' warm-up
	lastUpdate int64 // unix seconds of the last finished probe
	lost       int   // unanswered probes in a row
	state      string
}

// New returns a Monitor that is off until SetConfig. now is the wall clock
// (nil = time.Now).
func New(p Prober, now func() time.Time) *Monitor {
	if now == nil {
		now = time.Now
	}
	return &Monitor{prober: p, now: now, addrs: map[string]string{}, wake: make(chan struct{}, 1)}
}

// SetConfig turns monitoring on with c, or off with nil. An unchanged
// config keeps the figures; a changed one starts every target afresh.
func (m *Monitor) SetConfig(c *Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sameConfig(m.cfg, c) {
		return
	}
	m.cfg = c
	m.targets = nil
	if c != nil {
		for _, t := range c.Targets {
			s := &stats{Target: t, state: StatePending}
			s.resolved = m.resolve(t)
			m.targets = append(m.targets, s)
		}
	}
	m.kick()
}

// SetAddrs hands over the current gateway and uplink-device addresses
// (IPv4; "" = unknown). A target whose address changed starts afresh.
func (m *Monitor) SetAddrs(gateway, uplink string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addrs[TypeGateway], m.addrs[TypeUplink] = ipv4(gateway), ipv4(uplink)
	changed := false
	for i, s := range m.targets {
		if r := m.resolve(s.Target); r != s.resolved {
			m.targets[i] = &stats{Target: s.Target, resolved: r, state: StatePending}
			changed = true
		}
	}
	if changed {
		m.kick()
	}
}

func (m *Monitor) kick() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Monitor) resolve(t Target) string {
	if t.Type == TypeHost {
		return t.Addr
	}
	return m.addrs[t.Type]
}

func ipv4(s string) string {
	if ip := net.ParseIP(s).To4(); ip != nil && !ip.IsUnspecified() {
		return ip.String()
	}
	return ""
}

func sameConfig(a, b *Config) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Interval != b.Interval || a.Timeout != b.Timeout || a.EMASamples != b.EMASamples || a.Size != b.Size || len(a.Targets) != len(b.Targets) {
		return false
	}
	for i := range a.Targets {
		if a.Targets[i] != b.Targets[i] {
			return false
		}
	}
	return true
}

// Run probes until ctx ends: one round at once, then one every Interval.
// It idles while monitoring is off.
func (m *Monitor) Run(ctx context.Context) {
	for {
		m.Round(ctx)
		m.mu.Lock()
		wait := time.Duration(0)
		if m.cfg != nil {
			wait = m.cfg.Interval
		}
		m.mu.Unlock()
		var tc <-chan time.Time
		var t *time.Timer
		if wait > 0 {
			t = time.NewTimer(wait)
			tc = t.C
		}
		select {
		case <-ctx.Done():
		case <-m.wake:
		case <-tc:
		}
		if t != nil {
			t.Stop()
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// Round probes every target that has an address once, all at the same
// time, and folds the results in. A result for a target that was replaced
// meanwhile (config or address change) is dropped.
func (m *Monitor) Round(ctx context.Context) {
	m.mu.Lock()
	cfg := m.cfg
	var todo []*stats
	for _, s := range m.targets {
		if s.resolved != "" {
			todo = append(todo, s)
		}
	}
	m.mu.Unlock()
	if cfg == nil || len(todo) == 0 {
		return
	}
	type result struct {
		s   *stats
		rtt time.Duration
		err error
	}
	res := make([]result, len(todo))
	var wg sync.WaitGroup
	for i, s := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rtt, err := m.prober.Probe(ctx, net.ParseIP(s.resolved), cfg.Size, cfg.Timeout)
			res[i] = result{s, rtt, err}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return // cut short: not a loss
	}
	now := m.now().Unix()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg != cfg {
		return
	}
	for _, r := range res {
		live := false
		for _, s := range m.targets {
			live = live || s == r.s
		}
		if live {
			r.s.add(r.rtt, r.err == nil, cfg.EMASamples, now)
		}
	}
}

// add folds one probe in. The averages are exponential over n samples
// (weight 1/n); until n samples exist they are the plain mean, so the
// first figures are not dragged towards zero.
func (s *stats) add(rtt time.Duration, ok bool, n int, now int64) {
	s.samples++
	s.lastUpdate = now
	w := 1 / float64(min(s.samples, int64(n)))
	if !ok {
		s.lossEMA += w * (100000 - s.lossEMA)
		s.lost++
		if s.lost >= lostToUnreachable {
			s.state = StateUnreachable
		}
		return
	}
	s.lossEMA += w * (0 - s.lossEMA)
	s.lost = 0
	s.state = StateReachable
	us := float64(rtt.Microseconds())
	s.answered++
	wa := 1 / float64(min(s.answered, int64(n)))
	if s.answered > 1 {
		s.jitter = math.Abs(us - s.latency)
		// jitter needs two replies: its average starts with the second
		wj := 1 / float64(min(s.answered-1, int64(n)))
		s.jitterEMA += wj * (s.jitter - s.jitterEMA)
	}
	s.latency = us
	s.latencyEMA += wa * (us - s.latencyEMA)
}

// Report is the inform's "pathmon" object (nil while monitoring is off):
// the U6 Pro's shape, {interval (s), ema_samples, targets[]}, one IPv4 row
// per target with type, family, state, resolved, latency_us(_ema),
// jitter_us(_ema), loss_pcm_ema, samples, last_update_ts, and addr for a
// host target.
func (m *Monitor) Report() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg == nil {
		return nil
	}
	rows := make([]map[string]any, 0, len(m.targets))
	for _, s := range m.targets {
		r := map[string]any{
			"type": s.Type, "family": "ipv4", "state": s.state, "resolved": s.resolved,
			"latency_us": round(s.latency), "latency_us_ema": round(s.latencyEMA),
			"jitter_us": round(s.jitter), "jitter_us_ema": round(s.jitterEMA),
			"loss_pcm_ema": round(s.lossEMA), "samples": s.samples, "last_update_ts": s.lastUpdate,
		}
		if s.Type == TypeHost {
			r["addr"] = s.Addr
		}
		rows = append(rows, r)
	}
	return map[string]any{
		"interval":    int64(m.cfg.Interval / time.Second),
		"ema_samples": m.cfg.EMASamples,
		"targets":     rows,
	}
}

func round(f float64) int64 { return int64(math.Round(f)) }
