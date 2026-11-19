// SPDX-License-Identifier: GPL-2.0-or-later

package mdnsbr

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// env205 is .205 as read on 2026-11-19 (br-lan: eth0 eth1 wl02 wl12;
// br-v3: eth1.3 wl13), with the controller's VAP names: ra1/rai1 the home
// WLAN on br-lan, ra2 (wl13) the IoT WLAN on VLAN 3, rai2 (wl14) a guest
// SSID on br-lan.
func env205() Env {
	return Env{
		VAPs:    map[string]string{"ra1": "wl02", "rai1": "wl12", "ra2": "wl13", "rai2": "wl14"},
		Vifs:    map[string]bool{"wl02": true, "wl12": true, "wl13": true, "wl14": true},
		Guest:   map[string]bool{"wl14": true},
		Bridges: map[string][]string{"br-lan": {"eth0", "eth1", "wl01", "wl02", "wl12", "wl14"}, "br-v3": {"eth1.3", "wl13"}},
		Uplink:  "eth1",
		MACs:    [][6]byte{unitMAC},
	}
}

func plan205(t *testing.T, text string) Plan {
	t.Helper()
	c, notes := ParseConfig(translate.ParseCfg(text))
	if len(notes) > 0 {
		t.Fatalf("config notes: %v", notes)
	}
	p, _ := BuildPlan(c, env205())
	return p
}

func TestBuildPlan(t *testing.T) {
	p, notes := BuildPlan(func() Config { c, _ := ParseConfig(translate.ParseCfg(cfgText)); return c }(), env205())
	var keys []string
	for _, x := range p.Ports {
		keys = append(keys, fmt.Sprintf("%s/%d/%t", x.Key(), x.VLAN, x.Vif))
	}
	sort.Strings(keys)
	// VLAN 1 (home's own filter: every br-lan port but the guest vif and
	// TP-Link's backhaul vif), VLAN 3 (bridge here) and VLAN 30 (no bridge:
	// tagged frames on the uplink)
	want := []string{"eth0/1/false", "eth1.3/3/false", "eth1/1/false", "eth1@30/30/false", "wl02/1/true", "wl12/1/true", "wl13/3/true"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("ports = %v\nwant %v", keys, want)
	}
	if _, ok := p.Own["wl02"]; !ok || len(p.Own) != 3 {
		t.Errorf("own = %v (wl02, wl12 for VLAN 1 and wl13 for VLAN 3)", p.Own)
	}
	var routes []string
	for _, r := range p.Routes {
		routes = append(routes, fmt.Sprintf("%s<-%d", r.Vif, r.SrcVLAN))
	}
	if want := []string{"wl02<-3", "wl02<-30", "wl12<-3", "wl12<-30"}; !reflect.DeepEqual(routes, want) {
		t.Errorf("routes = %v", routes)
	}
	if len(notes) != 0 {
		t.Errorf("notes = %v", notes)
	}

	// a guest VAP, a VAP not served here, a filter with no proxy
	c := Config{Enabled: true, Filters: []Filter{
		{VLAN: 1, VAPs: []string{"rai2", "ra9"}, Services: []string{"_airplay._tcp"}},
		{VLAN: 7, VAPs: []string{"ra1"}, Allow: true},
	}}
	p, notes = BuildPlan(c, env205())
	if len(p.Ports) != 0 || len(notes) != 3 {
		t.Errorf("plan %+v notes %v", p, notes)
	}
	// AP mode: no virtual ports
	c, _ = ParseConfig(translate.ParseCfg(cfgText + "mdns_sd.ap_mode=enabled\n"))
	p, _ = BuildPlan(c, env205())
	for _, x := range p.Ports {
		if x.VID > 0 {
			t.Errorf("AP mode tapped %s", x.Key())
		}
	}
	// an allow-all own filter intercepts nothing
	p, _ = BuildPlan(Config{Enabled: true, Filters: []Filter{{VLAN: 1, Allow: true, VAPs: []string{"ra1"}}}}, env205())
	if len(p.Own) != 0 || len(p.Ports) != 0 {
		t.Errorf("allow-all plan = %+v", p)
	}
}

var (
	airplayQuery = dnsMsg(false, []tq{{name: "_airplay._tcp.local", typ: typePTR, qu: true}, {name: "_ssh._tcp.local", typ: typePTR}}, nil, nil)
	airplayResp  = dnsMsg(true, nil, []trr{
		{name: "_airplay._tcp.local", typ: typePTR, ttl: 4500, rdata: encName("TV._airplay._tcp.local")},
		{name: "_ssh._tcp.local", typ: typePTR, ttl: 4500, rdata: encName("box._ssh._tcp.local")},
	}, []trr{{name: "TV._airplay._tcp.local", typ: typeSRV, ttl: 120, rdata: srvData(7000, "tv.local")},
		{name: "tv.local", typ: typeA, ttl: 120, rdata: []byte{192, 168, 3, 20}}})
)

func outPorts(outs []Out) []string {
	var ps []string
	for _, o := range outs {
		ps = append(ps, o.Port)
	}
	sort.Strings(ps)
	return ps
}

func TestEngineRoutes(t *testing.T) {
	e := NewEngine(DefaultRates)
	e.SetPlan(plan205(t, cfgText))
	now := time.Unix(1000, 0)

	// a query from a home client goes to every VLAN 3 and VLAN 30 port,
	// AirPlay only, QU cleared, but not to the IoT vif wl13, whose own
	// (auto) filter does not list AirPlay; on VLAN 1 the intercepted wl12
	// gets it through home's own filter (AirPlay only, QU kept)
	outs := e.Handle("wl02", frame4(staMAC, "192.168.0.50", airplayQuery), now)
	if got, want := outPorts(outs), []string{"eth1.3", "eth1@30", "wl12"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("query to %v, want %v", got, want)
	}
	for _, o := range outs {
		m, _ := parseMessage(payloadOf(t, o.Frame))
		if len(m.qs) != 1 || m.qs[0].n.key() != "_airplay._tcp.local" {
			t.Errorf("%s got questions %+v", o.Port, m.qs)
		}
		if qu := m.qs[0].class&classQU != 0; qu != (o.Port == "wl12") {
			t.Errorf("%s: QU = %t", o.Port, qu)
		}
		if p, _ := parseFrame(o.Frame); p.src != staMAC || p.ipSrc.String() != "192.168.0.50" || p.ttl != 255 {
			t.Errorf("%s: addresses changed: %+v", o.Port, p)
		}
	}

	// the TV's answer on VLAN 3 (wired) reaches home's vifs (AirPlay only)
	// and, on VLAN 3, the IoT vif wl13 through its own (auto) filter, which
	// does not list AirPlay: nothing for it
	outs = e.Handle("eth1.3", frame4(tvMAC, "192.168.3.20", airplayResp), now)
	if got, want := outPorts(outs), []string{"wl02", "wl12"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("response to %v, want %v", got, want)
	}
	_, rrs := names(t, payloadOf(t, outs[0].Frame))
	if want := []string{"_airplay._tcp.local", "tv._airplay._tcp.local", "tv.local"}; !reflect.DeepEqual(rrs, want) {
		t.Errorf("response records %v", rrs)
	}

	// one way: a home client's answer does not go to VLAN 3, a wired
	// query on VLAN 3 does not come to home
	if outs := e.Handle("wl02", frame4(staMAC, "192.168.0.50", dnsMsg(true, nil, []trr{{name: "_airplay._tcp.local", typ: typePTR, ttl: 1, rdata: encName("Mac._airplay._tcp.local")}}, nil)), now); len(outs) != 1 || outs[0].Port != "wl12" {
		t.Errorf("home answer sent to %v (only home's other vif, own VLAN)", outPorts(outs))
	}
	if outs := e.Handle("eth1.3", frame4(tvMAC, "192.168.3.20", dnsMsg(false, []tq{{name: "_airplay._tcp.local", typ: typePTR}}, nil, nil)), now.Add(time.Second)); len(outs) != 0 {
		t.Errorf("VLAN 3 query sent to %v", outPorts(outs))
	}
	// VLAN 30 (tagged on the uplink) answers too, through filter 3
	outs = e.Handle("eth1@30", frame4(tvMAC, "192.168.30.9", airplayResp), now)
	if got := outPorts(outs); !reflect.DeepEqual(got, []string{"wl02", "wl12"}) {
		t.Errorf("VLAN 30 response to %v", got)
	}
	c := e.Counters()
	if c.In != 5 || c.Bad != 0 {
		t.Errorf("counters %+v", c)
	}
}

func TestEngineAPModeAndLoops(t *testing.T) {
	e := NewEngine(DefaultRates)
	e.SetPlan(plan205(t, cfgText+"mdns_sd.ap_mode=enabled\n"))
	now := time.Unix(1000, 0)
	// AP mode: wired answers are not bridged, wireless ones are; queries go
	// to vifs only
	if outs := e.Handle("eth1.3", frame4(tvMAC, "192.168.3.20", airplayResp), now); len(outs) != 0 {
		t.Errorf("AP mode bridged a wired answer to %v", outPorts(outs))
	}
	if outs := e.Handle("wl13", frame4(tvMAC, "192.168.3.20", airplayResp), now.Add(time.Second)); !reflect.DeepEqual(outPorts(outs), []string{"wl02", "wl12"}) {
		t.Errorf("AP mode: wireless answer to %v", outPorts(outs))
	}
	// (wl13 is VLAN 3's only vif, and its own filter has no AirPlay: the
	// query reaches no VLAN 3 port, wired ones being out in AP mode)
	if outs := e.Handle("wl02", frame4(staMAC, "192.168.0.50", airplayQuery), now); !reflect.DeepEqual(outPorts(outs), []string{"wl12"}) {
		t.Errorf("AP mode: query to %v", outPorts(outs))
	}

	e.SetPlan(plan205(t, cfgText))
	// the unit's own MAC: never forwarded
	if outs := e.Handle("eth1.3", frame4(unitMAC, "192.168.3.2", airplayResp), now); len(outs) != 0 {
		t.Errorf("own frame forwarded")
	}
	// a copy coming back (another bridge reflected it) within the window
	f := frame4(tvMAC, "192.168.3.20", airplayResp)
	t0 := now.Add(10 * time.Second)
	if len(e.Handle("eth1.3", f, t0)) == 0 {
		t.Fatal("first copy not forwarded")
	}
	if outs := e.Handle("eth1@30", f, t0.Add(100*time.Millisecond)); len(outs) != 0 {
		t.Errorf("duplicate forwarded to %v", outPorts(outs))
	}
	if len(e.Handle("eth1.3", f, t0.Add(DedupWindow+time.Millisecond))) == 0 {
		t.Errorf("a repeat after the window was dropped")
	}
	// unknown port, garbage
	if e.Handle("eth9", f, t0) != nil || e.Handle("eth1.3", []byte{1, 2, 3}, t0) != nil {
		t.Errorf("unknown port or garbage forwarded")
	}
}

func TestEngineRateLimits(t *testing.T) {
	e := NewEngine(Rates{PortPPS: 1, PortBurst: 3, MACPPS: 100, MACBurst: 100, OutPPS: 100, OutBurst: 100})
	e.SetPlan(plan205(t, cfgText))
	now := time.Unix(1000, 0)
	sent := 0
	for i := range 10 {
		q := dnsMsg(false, []tq{{name: fmt.Sprintf("x%d._airplay._tcp.local", i), typ: 16}}, nil, nil)
		if len(e.Handle("wl02", frame4(staMAC, "192.168.0.50", q), now)) > 0 {
			sent++
		}
	}
	if sent != 3 || e.Counters().Limited != 7 {
		t.Errorf("sent %d, counters %+v", sent, e.Counters())
	}
	// per source MAC
	e = NewEngine(Rates{PortPPS: 100, PortBurst: 100, MACPPS: 1, MACBurst: 2, OutPPS: 100, OutBurst: 100})
	e.SetPlan(plan205(t, cfgText))
	sent = 0
	for i := range 5 {
		q := dnsMsg(false, []tq{{name: fmt.Sprintf("y%d._airplay._tcp.local", i), typ: 16}}, nil, nil)
		if len(e.Handle("wl02", frame4(staMAC, "192.168.0.50", q), now)) > 0 {
			sent++
		}
	}
	if sent != 2 {
		t.Errorf("per-MAC: sent %d", sent)
	}
}

// --- ebtables ---

// fakeEb simulates the ebtables filter table (FORWARD and user chains).
type fakeEb struct {
	mu     sync.Mutex
	chains map[string][]string // FORWARD + user chains -> rules
	policy map[string]string
	calls  []string
	fail   string // a command prefix that fails
}

func newFakeEb() *fakeEb {
	return &fakeEb{chains: map[string][]string{"FORWARD": nil}, policy: map[string]string{"FORWARD": "ACCEPT"}}
}

func (f *fakeEb) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := name + " " + strings.Join(args, " ")
	if name != "ebtables" {
		f.calls = append(f.calls, cmd)
		return nil, nil
	}
	if args[0] != "-L" {
		f.calls = append(f.calls, cmd)
	}
	if f.fail != "" && strings.HasPrefix(cmd, f.fail) {
		return []byte("failed"), fmt.Errorf("exit status 255")
	}
	switch args[0] {
	case "-L":
		r, ok := f.chains[args[1]]
		if !ok {
			return []byte("Chain '" + args[1] + "' doesn't exist."), fmt.Errorf("exit status 255")
		}
		out := fmt.Sprintf("Bridge table: filter\n\nBridge chain: %s, entries: %d, policy: %s\n", args[1], len(r), f.policy[args[1]])
		for _, x := range r {
			out += x + " \n"
		}
		return []byte(out), nil
	case "-N":
		f.chains[args[1]] = nil
		f.policy[args[1]] = "ACCEPT"
		if len(args) == 4 && args[2] == "-P" {
			f.policy[args[1]] = args[3]
		}
	case "-P":
		f.policy[args[1]] = args[2]
	case "-F":
		f.chains[args[1]] = nil
	case "-X":
		for _, r := range f.chains["FORWARD"] {
			if strings.HasSuffix(r, "-j "+args[1]) {
				return nil, fmt.Errorf("chain in use")
			}
		}
		delete(f.chains, args[1])
	case "-A":
		f.chains[args[1]] = append(f.chains[args[1]], strings.Join(args[2:], " "))
	case "-I":
		f.chains[args[1]] = append([]string{strings.Join(args[3:], " ")}, f.chains[args[1]]...)
	case "-D":
		r := strings.Join(args[2:], " ")
		for i, x := range f.chains[args[1]] {
			if x == r {
				f.chains[args[1]] = append(f.chains[args[1]][:i:i], f.chains[args[1]][i+1:]...)
				return nil, nil
			}
		}
		return nil, fmt.Errorf("rule not found")
	}
	return nil, nil
}

func TestInterceptor(t *testing.T) {
	eb := newFakeEb()
	eb.chains["FORWARD"] = []string{"-o wl14 -j UDECO-GOUT"} // bcmwifi's guest jump stays
	x := &Interceptor{Run: eb}
	ctx := context.Background()
	if err := x.Set(ctx, []string{"wl02", "wl12"}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"-o wl12 -j UDECO-MDNS", "-o wl02 -j UDECO-MDNS", "-o wl14 -j UDECO-GOUT"}; !reflect.DeepEqual(eb.chains["FORWARD"], want) {
		t.Errorf("FORWARD = %v", eb.chains["FORWARD"])
	}
	if len(eb.chains[ChainName]) != 2 || eb.policy[ChainName] != "RETURN" {
		t.Errorf("chain = %v policy %s", eb.chains[ChainName], eb.policy[ChainName])
	}
	for _, r := range eb.chains[ChainName] {
		if !strings.Contains(r, "--ip") || !strings.HasSuffix(r, "--ip-dport 5353 -j DROP") && !strings.HasSuffix(r, "--ip6-dport 5353 -j DROP") {
			t.Errorf("rule %q", r)
		}
	}
	// idempotent
	eb.calls = nil
	if err := x.Set(ctx, []string{"wl12", "wl02"}); err != nil || len(eb.calls) != 0 {
		t.Errorf("second Set ran %v (%v)", eb.calls, err)
	}
	// a changed set: one jump out, flow cache flushed for it
	if err := x.Set(ctx, []string{"wl12"}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"-o wl12 -j UDECO-MDNS", "-o wl14 -j UDECO-GOUT"}; !reflect.DeepEqual(eb.chains["FORWARD"], want) {
		t.Errorf("FORWARD = %v", eb.chains["FORWARD"])
	}
	if eb.calls[len(eb.calls)-1] != "fc flush --if wl02" {
		t.Errorf("calls %v", eb.calls)
	}
	// a damaged chain is rebuilt
	eb.chains[ChainName] = eb.chains[ChainName][:1]
	if err := x.Set(ctx, []string{"wl12"}); err != nil || len(eb.chains[ChainName]) != 2 {
		t.Errorf("chain not repaired: %v %v", eb.chains[ChainName], err)
	}
	// clear: our jumps and chain go, the guest jump stays
	if err := Cleanup(ctx, eb); err != nil {
		t.Fatal(err)
	}
	if _, ok := eb.chains[ChainName]; ok || !reflect.DeepEqual(eb.chains["FORWARD"], []string{"-o wl14 -j UDECO-GOUT"}) {
		t.Errorf("after Cleanup: %v", eb.chains)
	}
	if err := x.Set(ctx, []string{"wl02;rm"}); err == nil {
		t.Errorf("bad interface name taken")
	}
	// dry run changes nothing
	if err := (&Interceptor{Run: eb, DryRun: true}).Set(ctx, []string{"wl02"}); err != nil || len(eb.chains["FORWARD"]) != 1 {
		t.Errorf("dry run changed FORWARD: %v", eb.chains["FORWARD"])
	}
}

// --- service ---

type fakeConn struct {
	key  string
	in   chan []byte
	mu   *sync.Mutex
	sent *map[string][][]byte
	once sync.Once
	done chan struct{}
}

func (c *fakeConn) Recv(b []byte) (int, bool, error) {
	select {
	case f := <-c.in:
		return copy(b, f), false, nil
	case <-c.done:
		return 0, false, fmt.Errorf("closed")
	case <-time.After(20 * time.Millisecond):
		return 0, false, ErrTimeout
	}
}

func (c *fakeConn) Send(f []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	(*c.sent)[c.key] = append((*c.sent)[c.key], append([]byte(nil), f...))
	return nil
}

func (c *fakeConn) Close() error { c.once.Do(func() { close(c.done) }); return nil }

type fakeNet struct {
	mu    sync.Mutex
	conns map[string]*fakeConn
	sent  map[string][][]byte
	down  map[string]bool
}

func (n *fakeNet) open(p Port) (Conn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down[p.Key()] {
		return nil, fmt.Errorf("no such device")
	}
	c := &fakeConn{key: p.Key(), in: make(chan []byte, 8), mu: &n.mu, sent: &n.sent, done: make(chan struct{})}
	n.conns[p.Key()] = c
	return c, nil
}

func (n *fakeNet) sentTo() map[string]int {
	n.mu.Lock()
	defer n.mu.Unlock()
	m := map[string]int{}
	for k, v := range n.sent {
		m[k] = len(v)
	}
	return m
}

func TestService(t *testing.T) {
	ctx := context.Background()
	net := &fakeNet{conns: map[string]*fakeConn{}, sent: map[string][][]byte{}, down: map[string]bool{"eth0": true}}
	eb := newFakeEb()
	var logs []string
	var lmu sync.Mutex
	s := NewService(ctx, Options{Open: net.open, Run: eb, Logf: func(f string, a ...any) {
		lmu.Lock()
		logs = append(logs, fmt.Sprintf(f, a...))
		lmu.Unlock()
	}})
	p := plan205(t, cfgText)
	if err := s.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	// eth0 (a VLAN 1 port) failed to open: VLAN 1 vifs are not intercepted
	// (they would miss eth0's mDNS); wl13 (VLAN 3) is
	if got := s.Intercepted(); !reflect.DeepEqual(got, []string{"wl13"}) {
		t.Errorf("intercepted %v", got)
	}
	net.mu.Lock()
	net.conns["wl02"].in <- frame4(staMAC, "192.168.0.50", airplayQuery)
	net.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(net.sentTo()) < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	if got, want := net.sentTo(), map[string]int{"eth1.3": 1, "eth1@30": 1}; !reflect.DeepEqual(got, want) {
		t.Errorf("sent %v, want %v (wl12 is not intercepted: the bridge serves it; wl13's own filter has no AirPlay)", got, want)
	}
	// eth0 back: VLAN 1 intercepted too (after the retry interval)
	net.mu.Lock()
	delete(net.down, "eth0")
	net.mu.Unlock()
	s.o.Now = func() time.Time { return time.Now().Add(time.Minute) }
	if err := s.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got := s.Intercepted(); !reflect.DeepEqual(got, []string{"wl02", "wl12", "wl13"}) {
		t.Errorf("intercepted %v", got)
	}
	if len(eb.chains["FORWARD"]) != 3 {
		t.Errorf("FORWARD %v", eb.chains["FORWARD"])
	}
	// Close: interception gone, readers stopped
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if len(eb.chains["FORWARD"]) != 0 {
		t.Errorf("FORWARD after Close: %v", eb.chains["FORWARD"])
	}
	// an empty plan clears interception without Close
	s2 := NewService(ctx, Options{Open: net.open, Run: eb})
	s2.Update(ctx, p)
	s2.Update(ctx, Plan{})
	if len(eb.chains["FORWARD"]) != 0 || len(s2.Intercepted()) != 0 {
		t.Errorf("empty plan left %v", eb.chains["FORWARD"])
	}
	s2.Close(ctx)
	// dry run: no sockets, no ebtables
	opened := len(net.conns)
	s3 := NewService(ctx, Options{Open: net.open, Run: eb, DryRun: true})
	s3.Update(ctx, p)
	if len(net.conns) != opened || len(eb.chains["FORWARD"]) != 0 {
		t.Errorf("dry run opened sockets or changed ebtables")
	}
	s3.Close(ctx)
}
