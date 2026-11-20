// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/mcinspect"
)

// mcSource replays frames once, then times out until closed.
type mcSource struct {
	mu     sync.Mutex
	frames [][]byte
	out    []bool
	closed bool
}

func (s *mcSource) Recv(b []byte) (int, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, false, net.ErrClosed
	}
	if len(s.frames) == 0 {
		time.Sleep(time.Millisecond)
		return 0, false, mcinspect.ErrTimeout
	}
	f, o := s.frames[0], s.out[0]
	s.frames, s.out = s.frames[1:], s.out[1:]
	return copy(b, f), o, nil
}

func (s *mcSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *mcSource) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// mdnsFromSta is an IPv4 mDNS PTR query for _airplay._tcp.local sent by
// the test station.
func mdnsFromSta(t *testing.T) []byte {
	src, err := net.ParseMAC(staMAC)
	if err != nil {
		t.Fatal(err)
	}
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[4:], 1)
	for _, l := range strings.Split("_airplay._tcp.local", ".") {
		q = append(append(q, byte(len(l))), l...)
	}
	q = append(q, 0, 0, 12, 0, 1)
	u := append([]byte{0x14, 0xe9, 0x14, 0xe9, 0, byte(8 + len(q)), 0, 0}, q...)
	ip := []byte{0x45, 0, 0, byte(20 + len(u)), 0, 0, 0, 0, 255, 17, 0, 0, 192, 168, 0, 50, 224, 0, 0, 251}
	f := append([]byte{0x01, 0x00, 0x5e, 0, 0, 0xfb}, src...)
	return append(append(append(f, 0x08, 0x00), ip...), u...)
}

func arpBroadcast() []byte {
	f := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x60, 0x22, 0x32, 0, 0, 1, 0x08, 0x06}
	return append(f, make([]byte, 28)...)
}

const mcastCfg = "wireless.1.devname=wifi1ap1\nwireless.1.ssid=net\nwireless.1.parent=wifi1\nwireless.1.id=w1\n" +
	"wireless.1.status=enabled\nwireless.1.multicast.inspect=%s\n"

type mcastRig struct {
	a      *agent
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	opened []string
	srcs   []*mcSource
	fail   error
	snap   *apstate.Snapshot
	info   apstate.CfgInfo
}

func newMcastRig(t *testing.T, inspect string) *mcastRig {
	t.Helper()
	dir := t.TempDir()
	cfg := strings.Replace(mcastCfg, "%s", inspect, 1)
	path := filepath.Join(dir, "system_cfg.txt")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &mcastRig{snap: testSnapshot(), info: apstate.InfoFromCfg(cfg)}
	r.a = &agent{o: options{logf: t.Logf}, sysCfgPath: path, infoKey: "1/1"}
	r.a.takeover.Store(true)
	r.a.mcast = newMcastInspect(func(vif string) (mcinspect.Source, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.opened = append(r.opened, vif)
		if r.fail != nil {
			return nil, r.fail
		}
		s := &mcSource{frames: [][]byte{mdnsFromSta(t), arpBroadcast()}, out: []bool{false, true}}
		r.srcs = append(r.srcs, s)
		return s, nil
	})
	r.ctx, r.cancel = context.WithCancel(context.Background())
	t.Cleanup(func() { r.cancel(); r.a.bg.Wait() })
	return r
}

// inform builds the inform fields of the test snapshot and merges the
// multicast blocks in, as agent.fields does.
func (r *mcastRig) inform(now time.Time) map[string]any {
	f := r.snap.Fields(nil, r.info, nil)
	r.a.mcastMerge(r.ctx, f, r.snap, r.info, now)
	return f
}

func staRow(t *testing.T, f map[string]any) map[string]any {
	t.Helper()
	vaps, _ := f["vap_table"].([]map[string]any)
	if len(vaps) != 1 || vaps[0]["name"] != "wifi1ap1" {
		t.Fatalf("vap_table = %v", f["vap_table"])
	}
	stas, _ := vaps[0]["sta_table"].([]map[string]any)
	if len(stas) != 1 {
		t.Fatalf("sta_table = %v", vaps[0]["sta_table"])
	}
	return stas[0]
}

func TestMcastInspectReportsClientBlock(t *testing.T) {
	r := newMcastRig(t, "true")
	now := time.Now()
	r.inform(now) // starts the reader on the VAP wifi1ap1 maps to
	if r.opened == nil || r.opened[0] != "wl12" {
		t.Fatalf("opened %v, want wl12", r.opened)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		row := staRow(t, r.inform(now))
		if m, ok := row["multicast"].(map[string]any); ok {
			ty := m["types"].(map[string]any)
			if ty["mdns"].(map[string]any)["rx_pkts"] == int64(1) && ty["arp"].(map[string]any)["tx_pkts"] == int64(1) {
				svc := m["services"].([]map[string]any)
				if len(svc) != 1 || svc[0]["name"] != "_airplay._tcp.local" {
					t.Errorf("services = %v", svc)
				}
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no multicast block with the client's mDNS and the VAP's ARP: %v", row["multicast"])
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(r.opened) != 1 {
		t.Errorf("reader reopened: %v", r.opened)
	}

	// a drop to observe mode stops the reader and the block goes away
	r.a.takeover.Store(false)
	row := staRow(t, r.inform(now))
	if _, ok := row["multicast"]; ok {
		t.Errorf("observe mode still reports a multicast block")
	}
	waitClosed(t, r.srcs[0])
}

func waitClosed(t *testing.T, s *mcSource) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !s.isClosed() {
		if time.Now().After(deadline) {
			t.Fatal("reader not stopped")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMcastInspectOffByConfig(t *testing.T) {
	r := newMcastRig(t, "false")
	row := staRow(t, r.inform(time.Now()))
	if len(r.opened) != 0 {
		t.Errorf("multicast.inspect=false opened %v", r.opened)
	}
	if _, ok := row["multicast"]; ok {
		t.Errorf("multicast block without multicast.inspect")
	}
}

func TestMcastInspectShedStops(t *testing.T) {
	r := newMcastRig(t, "true")
	now := time.Now()
	r.inform(now)
	if len(r.srcs) != 1 {
		t.Fatalf("no reader started: %v", r.opened)
	}
	r.a.shed.Store(true) // R4: memory is short
	if _, ok := staRow(t, r.inform(now))["multicast"]; ok {
		t.Errorf("multicast block while shedding")
	}
	waitClosed(t, r.srcs[0])
}

func TestMcastInspectOpenFailureRetry(t *testing.T) {
	r := newMcastRig(t, "true")
	r.fail = errors.New("no such device")
	now := time.Now()
	r.inform(now)
	r.inform(now.Add(10 * time.Second))
	if len(r.opened) != 1 {
		t.Fatalf("opens within the retry interval: %v", r.opened)
	}
	if _, ok := staRow(t, r.inform(now.Add(20*time.Second)))["multicast"]; ok {
		t.Errorf("multicast block without a reader")
	}
	r.mu.Lock()
	r.fail = nil
	r.mu.Unlock()
	r.inform(now.Add(mcastRetry + time.Second))
	if len(r.opened) != 2 || len(r.srcs) != 1 {
		t.Errorf("not retried after %s: opened %v", mcastRetry, r.opened)
	}
}

// End to end: a takeover agent provisioned with multicast.inspect=true
// informs the client's multicast block (system_cfg in, sta_table out).
func TestMcastInspectInform(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover = true })
	var mu sync.Mutex
	var opened []string
	h.a.mcast = newMcastInspect(func(vif string) (mcinspect.Source, error) {
		mu.Lock()
		defer mu.Unlock()
		opened = append(opened, vif)
		return &mcSource{frames: [][]byte{mdnsFromSta(t), arpBroadcast()}, out: []bool{false, true}}, nil
	})
	h.ctl.queue(adoptReply, provisionReply(testCfg+"wireless.1.multicast.inspect=true\n"))
	h.start()
	eventually(t, "an inform with the client's multicast block", func() bool {
		m := h.ctl.last()
		vaps, _ := m["vap_table"].([]any)
		if len(vaps) != 1 {
			return false
		}
		stas, _ := vaps[0].(map[string]any)["sta_table"].([]any)
		if len(stas) != 1 {
			return false
		}
		mc, _ := stas[0].(map[string]any)["multicast"].(map[string]any)
		ty, _ := mc["types"].(map[string]any)
		md, _ := ty["mdns"].(map[string]any)
		return md != nil && num(md["rx_pkts"]) == 1
	})
	h.stop()
	mu.Lock()
	defer mu.Unlock()
	if len(opened) != 1 || opened[0] != "wl12" {
		t.Errorf("opened %v, want wl12 once", opened)
	}
}
