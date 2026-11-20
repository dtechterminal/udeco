// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/mdnsbr"
)

// ebSim is a minimal ebtables: FORWARD rules and user chains.
type ebSim struct {
	mu      sync.Mutex
	forward []string
	chains  map[string][]string
	writes  []string
	calls   int // every ebtables run, reads included
}

func (e *ebSim) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if name != "ebtables" {
		return nil, nil
	}
	e.calls++
	if e.chains == nil {
		e.chains = map[string][]string{}
	}
	if args[0] != "-L" {
		e.writes = append(e.writes, strings.Join(args, " "))
	}
	switch args[0] {
	case "-L":
		if args[1] == "FORWARD" {
			return []byte("Bridge chain: FORWARD, entries: 0, policy: ACCEPT\n" + strings.Join(e.forward, "\n")), nil
		}
		r, ok := e.chains[args[1]]
		if !ok {
			return nil, errors.New("no chain")
		}
		return []byte("Bridge chain: " + args[1] + ", entries: 2, policy: RETURN\n" + strings.Join(r, "\n")), nil
	case "-N", "-F":
		e.chains[args[1]] = nil
	case "-X":
		delete(e.chains, args[1])
	case "-A":
		e.chains[args[1]] = append(e.chains[args[1]], strings.Join(args[2:], " "))
	case "-I":
		e.forward = append([]string{strings.Join(args[3:], " ")}, e.forward...)
	case "-D":
		r := strings.Join(args[2:], " ")
		for i, x := range e.forward {
			if x == r {
				e.forward = append(e.forward[:i:i], e.forward[i+1:]...)
				break
			}
		}
	}
	return nil, nil
}

func (e *ebSim) state() ([]string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.chains[mdnsbr.ChainName]
	return append([]string(nil), e.forward...), ok
}

type nullConn struct{ closed chan struct{} }

func (c *nullConn) Recv([]byte) (int, bool, error) {
	<-c.closed
	return 0, false, errors.New("closed")
}
func (c *nullConn) Send([]byte) error { return nil }
func (c *nullConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

const mdnsCfg = "wireless.1.devname=wifi1ap1\nwireless.1.ssid=net\nwireless.1.parent=wifi1\nwireless.1.id=w1\nwireless.1.status=enabled\n" +
	"mdns_sd.status=enabled\nmdns_sd.filter.1.vlan=1\nmdns_sd.filter.1.policy=deny\nmdns_sd.filter.1.dst.1.devname=wifi1ap1\n" +
	"mdns_sd.filter.1.service.1.name=_airplay._tcp.local\n"

type mdnsRig struct {
	a      *agent
	eb     *ebSim
	mu     sync.Mutex
	opened []string
	snap   *apstate.Snapshot
	info   apstate.CfgInfo
}

func newMdnsRig(t *testing.T, takeover, apply bool) *mdnsRig {
	t.Helper()
	root := t.TempDir()
	for dir, ports := range map[string][]string{"br-lan": {"eth0", "eth1", "wl12"}, "br-v3": {"eth1.3"}} {
		for _, p := range ports {
			if err := os.MkdirAll(filepath.Join(root, "sys/class/net", dir, "brif", p), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i, n := range []string{"br-lan", "eth0", "eth1", "wl12", "eth1.3", "br-v3"} {
		d := filepath.Join(root, "sys/class/net", n)
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "address"), []byte(fmt.Sprintf("50:91:e3:00:00:%02x\n", i+1)), 0o644)
	}
	path := filepath.Join(root, "system_cfg.txt")
	if err := os.WriteFile(path, []byte(mdnsCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &mdnsRig{eb: &ebSim{}, snap: testSnapshot(), info: apstate.InfoFromCfg(mdnsCfg)}
	r.a = &agent{cfg: &Config{Takeover: takeover, Apply: apply, MdnsBridge: takeover && apply}, o: options{logf: t.Logf, root: root, run: r.eb},
		sysCfgPath: path, infoKey: "1/1", uplink: "eth1"}
	r.a.takeover.Store(takeover)
	r.a.mdns = &mdnsState{open: func(p mdnsbr.Port) (mdnsbr.Conn, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.opened = append(r.opened, p.Key())
		return &nullConn{closed: make(chan struct{})}, nil
	}}
	t.Cleanup(r.a.mdnsShutdown)
	return r
}

func (r *mdnsRig) ports() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := append([]string(nil), r.opened...)
	sort.Strings(p)
	return p
}

func TestMdnsBridgeTakeover(t *testing.T) {
	r := newMdnsRig(t, true, true)
	ctx := context.Background()
	r.a.mdnsReconcile(ctx, r.snap, r.info)
	// the VAP's own-VLAN filter restricts: every br-lan port tapped, wl12
	// intercepted
	if got, want := r.ports(), []string{"eth0", "eth1", "wl12"}; !reflect.DeepEqual(got, want) {
		t.Errorf("opened %v, want %v", got, want)
	}
	fw, chain := r.eb.state()
	if !chain || !reflect.DeepEqual(fw, []string{"-o wl12 -j UDECO-MDNS"}) {
		t.Errorf("ebtables FORWARD %v, chain %t", fw, chain)
	}
	// a second tick changes nothing
	n := len(r.eb.writes)
	r.a.mdnsReconcile(ctx, r.snap, r.info)
	if len(r.eb.writes) != n || len(r.ports()) != 3 {
		t.Errorf("second tick: writes %v, ports %v", r.eb.writes[n:], r.ports())
	}
	// a Wi-Fi apply in flight: left alone
	r.a.wifiBusy.Store(true)
	r.a.mdnsReconcile(ctx, r.snap, r.info)
	r.a.wifiBusy.Store(false)
	if _, err := os.Stat(r.a.mdnsMarker()); err != nil {
		t.Errorf("no marker while intercepting: %v", err)
	}
	// drop to observe: stopped, native mDNS back
	r.a.takeover.Store(false)
	r.a.mdnsReconcile(ctx, r.snap, r.info)
	if fw, chain := r.eb.state(); len(fw) != 0 || chain || r.a.mdns.svc != nil {
		t.Errorf("after drop to observe: FORWARD %v chain %t", fw, chain)
	}
	if _, err := os.Stat(r.a.mdnsMarker()); !os.IsNotExist(err) {
		t.Errorf("marker left after a clean stop: %v", err)
	}
}

func TestMdnsBridgeObserveAndNoApply(t *testing.T) {
	for _, c := range []struct {
		name            string
		takeover, apply bool
		key             bool // mdns_bridge
	}{{"observe", false, false, false}, {"takeover without apply", true, false, false},
		{"takeover and apply without mdns_bridge", true, true, false}} {
		r := newMdnsRig(t, c.takeover, c.apply)
		r.a.cfg.MdnsBridge = c.key
		// an earlier run's leftovers (its marker in the run dir) are
		// removed in either mode
		r.eb.forward = []string{"-o wl12 -j UDECO-MDNS"}
		r.eb.chains = map[string][]string{mdnsbr.ChainName: {"x", "y"}}
		if err := r.a.writeMdnsMarker(); err != nil {
			t.Fatal(err)
		}
		r.a.mdnsReconcile(context.Background(), r.snap, r.info)
		if fw, chain := r.eb.state(); len(fw) != 0 || chain {
			t.Errorf("%s: leftovers stay: %v %t", c.name, fw, chain)
		}
		if len(r.ports()) != 0 || r.a.mdns.svc != nil {
			t.Errorf("%s: bridge started (%v)", c.name, r.ports())
		}
		if _, err := os.Stat(r.a.mdnsMarker()); !os.IsNotExist(err) {
			t.Errorf("%s: marker left after the cleanup: %v", c.name, err)
		}
		// a unit with no marker (the bridge never ran since boot) sees no
		// ebtables command at all, not even a read
		r2 := newMdnsRig(t, c.takeover, c.apply)
		r2.a.cfg.MdnsBridge = c.key
		r2.a.mdnsReconcile(context.Background(), r2.snap, r2.info)
		if r2.eb.calls != 0 {
			t.Errorf("%s: %d ebtables runs (writes %v)", c.name, r2.eb.calls, r2.eb.writes)
		}
	}
}

func TestMdnsBridgeGuestAndShed(t *testing.T) {
	r := newMdnsRig(t, true, true)
	r.info.GuestVAP = map[string]bool{"wifi1ap1": true}
	r.a.mdnsReconcile(context.Background(), r.snap, r.info)
	if len(r.ports()) != 0 {
		t.Errorf("a guest VAP was bridged: %v", r.ports())
	}
	r = newMdnsRig(t, true, true)
	r.a.mdnsReconcile(context.Background(), r.snap, r.info)
	r.a.shed.Store(true)
	r.a.mdnsReconcile(context.Background(), r.snap, r.info)
	if fw, _ := r.eb.state(); len(fw) != 0 || r.a.mdns.svc != nil {
		t.Errorf("R4 shedding left the bridge running: %v", fw)
	}
}

func TestParseMAC(t *testing.T) {
	if m, ok := parseMAC("50:91:E3:00:00:01"); !ok || m != [6]byte{0x50, 0x91, 0xe3, 0, 0, 1} {
		t.Errorf("parseMAC = %x %t", m, ok)
	}
	for _, s := range []string{"00:00:00:00:00:00", "01:00:5e:00:00:fb", "50:91:e3:00:00", "zz:91:e3:00:00:01"} {
		if _, ok := parseMAC(s); ok {
			t.Errorf("parseMAC(%q) ok", s)
		}
	}
}
