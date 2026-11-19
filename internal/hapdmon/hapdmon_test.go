// SPDX-License-Identifier: GPL-2.0-or-later

package hapdmon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHostapd is one BSS's control socket: it answers ATTACH, DETACH and
// PING like hostapd 2.9 and can send unsolicited events to its monitors.
type fakeHostapd struct {
	t       *testing.T
	path    string
	c       *net.UnixConn
	mu      sync.Mutex
	mons    map[string]*net.UnixAddr
	attachN int
	mute    bool // stop answering PING (a hung hostapd)
	done    chan struct{}
}

func newFakeHostapd(t *testing.T, path string) *fakeHostapd {
	t.Helper()
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Skip(err)
	}
	h := &fakeHostapd{t: t, path: path, c: c, mons: map[string]*net.UnixAddr{}, done: make(chan struct{})}
	go h.serve()
	return h
}

func (h *fakeHostapd) serve() {
	defer close(h.done)
	buf := make([]byte, 512)
	for {
		n, from, err := h.c.ReadFromUnix(buf)
		if err != nil {
			return
		}
		if from == nil {
			continue
		}
		cmd := string(buf[:n])
		h.mu.Lock()
		mute := h.mute
		switch cmd {
		case "ATTACH":
			h.mons[from.Name] = from
			h.attachN++
		case "DETACH":
			delete(h.mons, from.Name)
		}
		h.mu.Unlock()
		switch {
		case cmd == "ATTACH" || cmd == "DETACH":
			h.c.WriteToUnix([]byte("OK\n"), from)
		case cmd == "PING" && !mute:
			h.c.WriteToUnix([]byte("PONG\n"), from)
		}
	}
}

func (h *fakeHostapd) send(msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.mons {
		h.c.WriteToUnix([]byte(msg), m)
	}
}

func (h *fakeHostapd) monitors() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.mons)
}

func (h *fakeHostapd) attaches() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.attachN
}

// stop is hostapd exiting: the socket file goes away.
func (h *fakeHostapd) stop() {
	h.c.Close()
	<-h.done
	os.Remove(h.path)
}

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "hm")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	dl := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(dl) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func startMonitor(t *testing.T, o Options) (*Monitor, func()) {
	t.Helper()
	m := New(o)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); m.Run(ctx) }()
	return m, func() { cancel(); <-done }
}

// The monitor attaches to each wanted BSS socket and hands over the
// station events in the order hostapd sent them, a quick disconnect and
// reconnect of the same station included.
func TestMonitorEvents(t *testing.T) {
	ctrl, local := shortDir(t), shortDir(t)
	h12 := newFakeHostapd(t, filepath.Join(ctrl, "wl12"))
	defer h12.stop()
	h11 := newFakeHostapd(t, filepath.Join(ctrl, "wl11")) // placeholder: not wanted
	defer h11.stop()
	os.WriteFile(filepath.Join(ctrl, "wl13"), nil, 0o600)         // not a socket
	os.WriteFile(filepath.Join(local, "hapdmon-1-1"), nil, 0o600) // left by an agent that was killed
	m, stop := startMonitor(t, Options{Dir: ctrl, LocalDir: local, Scan: 10 * time.Millisecond, Ping: time.Second,
		Want: func(n string) bool { return n != "wl11" }})
	waitFor(t, "attach wl12", func() bool { return h12.monitors() == 1 && !m.Attached()["wl12"].IsZero() })
	if h11.monitors() != 0 {
		t.Errorf("attached to an unwanted BSS")
	}
	if _, ok := m.Attached()["wl13"]; ok {
		t.Errorf("attached to a plain file")
	}
	h12.send("<3>AP-STA-DISCONNECTED D2:F7:E5:58:6F:89")
	h12.send("<3>CTRL-EVENT-EAP-STARTED d2:f7:e5:58:6f:89")
	h12.send("<3>AP-STA-CONNECTED d2:f7:e5:58:6f:89 keyid=x")
	var evs []Event
	waitFor(t, "two events", func() bool {
		e, _ := m.Take()
		evs = append(evs, e...)
		return len(evs) >= 2
	})
	if len(evs) != 2 || evs[0].Kind != Disconnected || evs[1].Kind != Connected ||
		evs[0].MAC != "d2:f7:e5:58:6f:89" || evs[1].MAC != "d2:f7:e5:58:6f:89" || evs[0].Vif != "wl12" ||
		evs[0].At.IsZero() || evs[1].At.Before(evs[0].At) {
		t.Fatalf("events %+v", evs)
	}
	stop()
	if h12.monitors() != 0 {
		t.Errorf("not detached on stop")
	}
	if ents, _ := os.ReadDir(local); len(ents) != 0 {
		t.Errorf("local sockets left behind: %v", ents)
	}
}

// hostapd restarting (its socket replaced) and a BSS going away are
// followed: the monitor re-attaches to the new socket and forgets the old.
func TestMonitorRestart(t *testing.T) {
	ctrl, local := shortDir(t), shortDir(t)
	p := filepath.Join(ctrl, "wl02")
	h := newFakeHostapd(t, p)
	m, stop := startMonitor(t, Options{Dir: ctrl, LocalDir: local, Scan: 10 * time.Millisecond, Ping: 50 * time.Millisecond, Retry: 10 * time.Millisecond})
	defer stop()
	waitFor(t, "attach", func() bool { return h.monitors() == 1 })
	first := m.Attached()["wl02"]
	h.stop()
	waitFor(t, "detached after the socket went", func() bool { _, ok := m.Attached()["wl02"]; return !ok })
	h = newFakeHostapd(t, p)
	defer h.stop()
	waitFor(t, "re-attach", func() bool { return h.monitors() == 1 && m.Attached()["wl02"].After(first) })
	h.send("<3>AP-STA-CONNECTED a6:7b:00:00:00:01")
	waitFor(t, "event after restart", func() bool { e, _ := m.Take(); return len(e) == 1 && e[0].Kind == Connected })
	if ents, _ := os.ReadDir(local); len(ents) != 1 {
		t.Errorf("local sockets %v: want the one in use", ents)
	}
}

// A hostapd that stops answering PING is re-attached.
func TestMonitorPing(t *testing.T) {
	ctrl, local := shortDir(t), shortDir(t)
	h := newFakeHostapd(t, filepath.Join(ctrl, "wl12"))
	defer h.stop()
	m, stop := startMonitor(t, Options{Dir: ctrl, LocalDir: local, Scan: 10 * time.Millisecond, Ping: 20 * time.Millisecond, Retry: 10 * time.Millisecond})
	defer stop()
	waitFor(t, "attach", func() bool { return h.attaches() == 1 })
	time.Sleep(100 * time.Millisecond) // PONGs keep it attached
	if n := h.attaches(); n != 1 {
		t.Fatalf("re-attached %d times while hostapd answered", n)
	}
	h.mu.Lock()
	h.mute = true
	h.mu.Unlock()
	waitFor(t, "re-attach after no PONG", func() bool { return h.attaches() >= 2 })
	_ = m
}

// The queue is bounded: the oldest events go first and are counted.
func TestMonitorBound(t *testing.T) {
	m := New(Options{Max: 3})
	for i := 0; i < 5; i++ {
		m.push(Event{Vif: "wl12", MAC: "00:00:00:00:00:0" + string(rune('0'+i)), Kind: Connected})
	}
	evs, dropped := m.Take()
	if len(evs) != 3 || dropped != 2 || evs[0].MAC != "00:00:00:00:00:02" {
		t.Fatalf("events %v dropped %d", evs, dropped)
	}
	if evs, dropped := m.Take(); len(evs) != 0 || dropped != 0 {
		t.Fatalf("second take %v %d", evs, dropped)
	}
}

func TestParse(t *testing.T) {
	for in, want := range map[string]Event{
		"<3>AP-STA-CONNECTED D2:F7:E5:58:6F:89":                     {MAC: "d2:f7:e5:58:6f:89", Kind: Connected},
		"<3>AP-STA-CONNECTED 02:11:22:33:44:55 p2p_dev_addr=x":      {MAC: "02:11:22:33:44:55", Kind: Connected},
		"<3>AP-STA-DISCONNECTED 02:11:22:33:44:55\n":                {MAC: "02:11:22:33:44:55", Kind: Disconnected},
		"<2>AP-STA-DISCONNECTED 02:11:22:33:44:55":                  {MAC: "02:11:22:33:44:55", Kind: Disconnected},
		"<3>AP-STA-CONNECTED 02:11:22:33:44":                        {},
		"<3>AP-STA-POSSIBLE-PSK-MISMATCH 02:11:22:33:44:55":         {},
		"<3>CTRL-EVENT-EAP-STARTED 02:11:22:33:44:55":               {},
		"AP-STA-CONNECTED 02:11:22:33:44:55":                        {},
		"<3>AP-STA-CONNECTEDX 02:11:22:33:44:55":                    {},
		"<3>" + strings.Repeat("A", 40):                             {},
		"<3>AP-STA-DISCONNECTED 02:11:22:33:44:55 extra=1 more=two": {MAC: "02:11:22:33:44:55", Kind: Disconnected},
	} {
		got, ok := parse(in)
		if ok != (want.Kind != 0) || got.MAC != want.MAC || got.Kind != want.Kind {
			t.Errorf("parse(%q) = %+v %v, want %+v", in, got, ok, want)
		}
	}
}
