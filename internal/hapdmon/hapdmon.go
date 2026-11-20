// SPDX-License-Identifier: GPL-2.0-or-later

// Package hapdmon follows hostapd's station events on its control sockets.
//
// hostapd (2.9 on the Deco X20) has one control socket per BSS under its
// ctrl_interface directory, named by the BSS's interface (wl02, wl12). A
// client of that socket (wpa_ctrl: a unix datagram socket bound to a path
// of its own) that sends ATTACH gets every message at level MSG_INFO and
// above as an unsolicited datagram "<level>TEXT". The ones read here:
//
//	<3>AP-STA-CONNECTED <mac> [keyid=..]   the station is authorized (after the 4-way handshake)
//	<3>AP-STA-DISCONNECTED <mac>           it is not any more (disassociation, deauthentication, timeout)
//
// hostapd sends them from ap_sta_set_authorized on every change, so a
// station that disassociates and associates again within a second gives
// both, unlike two readings of the association list.
//
// The Monitor attaches to every socket in the directory that Want accepts,
// keeps each attachment alive with PING (re-attaching when hostapd stops
// answering, restarts with a new socket, or a BSS goes away or appears),
// removes its own socket files, and never blocks its caller: events wait in
// a bounded queue that Take empties.
package hapdmon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Kind is what happened to the station.
type Kind int

const (
	Connected    Kind = iota + 1 // AP-STA-CONNECTED
	Disconnected                 // AP-STA-DISCONNECTED
)

func (k Kind) String() string {
	switch k {
	case Connected:
		return "connected"
	case Disconnected:
		return "disconnected"
	}
	return "?"
}

// Event is one station event of one BSS.
type Event struct {
	Vif  string    // the BSS's interface (its socket's name)
	MAC  string    // the station, lower case
	Kind Kind      //
	At   time.Time // when the monitor received it
}

// Options configure a Monitor; zero durations take the defaults.
type Options struct {
	Dir      string            // hostapd's ctrl_interface directory
	LocalDir string            // where the monitor binds its own sockets (must exist)
	Want     func(string) bool // which BSS sockets to follow (nil: all)
	Scan     time.Duration     // how often Dir is listed (2 s)
	Ping     time.Duration     // keepalive: PING after this long without a message, re-attach after as long again without PONG (10 s)
	Retry    time.Duration     // first wait before attaching again after a failure, doubled up to a minute (2 s)
	Max      int               // events kept at most until Take (256); the oldest go first
	Logf     func(string, ...any)
	Now      func() time.Time
}

// Monitor follows the BSS sockets of one hostapd control directory.
type Monitor struct {
	o Options

	mu      sync.Mutex
	events  []Event
	dropped int
	since   map[string]time.Time // BSS -> attached since
	noted   map[string]string    // BSS -> last problem logged
}

const (
	maxRetry     = time.Minute
	replyTimeout = 3 * time.Second
)

var seq atomic.Uint64

// New returns a Monitor; Run starts it.
func New(o Options) *Monitor {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.Scan, 2*time.Second)
	def(&o.Ping, 10*time.Second)
	def(&o.Retry, 2*time.Second)
	if o.Max <= 0 {
		o.Max = 256
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Monitor{o: o, since: map[string]time.Time{}, noted: map[string]string{}}
}

// Take returns the events received since the last call, oldest first, and
// how many were dropped because the queue was full.
func (m *Monitor) Take() ([]Event, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	evs, d := m.events, m.dropped
	m.events, m.dropped = nil, 0
	return evs, d
}

// Attached returns the BSSes attached now and since when. A BSS attached
// continuously since t has reported every station event after t.
func (m *Monitor) Attached() map[string]time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]time.Time, len(m.since))
	for k, v := range m.since {
		out[k] = v
	}
	return out
}

func (m *Monitor) push(e Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) >= m.o.Max {
		m.events = m.events[1:]
		m.dropped++
	}
	m.events = append(m.events, e)
}

func (m *Monitor) setSince(name string, t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.IsZero() {
		delete(m.since, name)
	} else {
		m.since[name] = t
	}
}

// note logs a BSS's problem once until it changes or the BSS attaches.
func (m *Monitor) note(name, msg string) {
	m.mu.Lock()
	same := m.noted[name] == msg
	m.noted[name] = msg
	m.mu.Unlock()
	if !same && msg != "" {
		m.o.Logf("hostapd events %s: %s", name, msg)
	}
}

type watch struct {
	fi       os.FileInfo
	cancel   context.CancelFunc
	done     chan struct{}
	attached atomic.Bool
}

type backoff struct {
	fails int
	next  time.Time
}

// Run follows the sockets until ctx ends, then detaches from all of them.
func (m *Monitor) Run(ctx context.Context) {
	// sockets left by a monitor that was killed (one agent runs at a time)
	if old, err := filepath.Glob(filepath.Join(m.o.LocalDir, "hapdmon-*")); err == nil {
		for _, p := range old {
			_ = os.Remove(p)
		}
	}
	ws := map[string]*watch{}
	back := map[string]*backoff{}
	defer func() {
		for _, w := range ws {
			w.cancel()
			<-w.done
		}
	}()
	t := time.NewTicker(m.o.Scan)
	defer t.Stop()
	for {
		m.scan(ctx, ws, back)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// scan lists the directory and starts, stops or restarts the watches.
func (m *Monitor) scan(ctx context.Context, ws map[string]*watch, back map[string]*backoff) {
	now := time.Now()
	present := map[string]os.FileInfo{}
	if ents, err := os.ReadDir(m.o.Dir); err == nil {
		for _, e := range ents {
			n := e.Name()
			if m.o.Want != nil && !m.o.Want(n) {
				continue
			}
			fi, err := os.Stat(filepath.Join(m.o.Dir, n))
			if err == nil && fi.Mode()&os.ModeSocket != 0 {
				present[n] = fi
			}
		}
	}
	for n, w := range ws {
		select {
		case <-w.done: // it ended on its own: hostapd went quiet or refused
			delete(ws, n)
			b := back[n]
			if b == nil {
				b = &backoff{}
				back[n] = b
			}
			if w.attached.Load() {
				b.fails = 0
			}
			b.fails++
			b.next = now.Add(min(m.o.Retry<<min(b.fails-1, 10), maxRetry))
			continue
		default:
		}
		if fi, ok := present[n]; !ok || !os.SameFile(fi, w.fi) {
			// the BSS went away, or hostapd restarted with a new socket
			w.cancel()
			<-w.done
			delete(ws, n)
			delete(back, n)
		}
	}
	for n := range back {
		if _, ok := present[n]; !ok {
			delete(back, n)
		}
	}
	for n, fi := range present {
		if ws[n] != nil {
			continue
		}
		if b := back[n]; b != nil && now.Before(b.next) {
			continue
		}
		wctx, cancel := context.WithCancel(ctx)
		w := &watch{fi: fi, cancel: cancel, done: make(chan struct{})}
		ws[n] = w
		go m.watch(wctx, n, w)
	}
}

// watch attaches to one BSS socket and reads its events until ctx ends or
// the socket fails.
func (m *Monitor) watch(ctx context.Context, name string, w *watch) {
	defer close(w.done)
	sock := filepath.Join(m.o.Dir, name)
	local := filepath.Join(m.o.LocalDir, fmt.Sprintf("hapdmon-%d-%d", os.Getpid(), seq.Add(1)))
	_ = os.Remove(local)
	c, err := net.DialUnix("unixgram", &net.UnixAddr{Name: local, Net: "unixgram"}, &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		_ = os.Remove(local)
		m.note(name, "cannot reach the control socket: "+errText(err))
		return
	}
	defer os.Remove(local)
	defer c.Close()
	// Every read deadline goes through rd: once ctx has ended it is now,
	// whoever sets it, so ctx ending wakes a blocked read (the loop then
	// detaches) and no later deadline (a request's, the keepalive's)
	// undoes that wake-up.
	var dl sync.Mutex
	rd := func(t time.Time) {
		dl.Lock()
		defer dl.Unlock()
		if ctx.Err() != nil {
			t = time.Now()
		}
		_ = c.SetReadDeadline(t)
	}
	stop := context.AfterFunc(ctx, func() { rd(time.Now()) })
	defer stop()
	if err := request(c, rd, "ATTACH", "OK"); err != nil {
		if ctx.Err() == nil {
			m.note(name, "ATTACH: "+err.Error())
		}
		return
	}
	w.attached.Store(true)
	m.note(name, "")
	m.setSince(name, m.o.Now())
	defer m.setSince(name, time.Time{})
	buf := make([]byte, 4096)
	pinged := false
	for {
		rd(time.Now().Add(m.o.Ping))
		n, err := c.Read(buf)
		if ctx.Err() != nil {
			_ = c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			_, _ = c.Write([]byte("DETACH"))
			return
		}
		if err != nil {
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				m.note(name, "control socket closed: "+errText(err))
				return
			}
			if pinged {
				m.note(name, "no PONG: attaching again")
				return
			}
			_ = c.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := c.Write([]byte("PING")); err != nil {
				m.note(name, "PING: "+errText(err))
				return
			}
			pinged = true
			continue
		}
		msg := string(buf[:n])
		switch {
		case strings.HasPrefix(msg, "<"):
			pinged = false // hostapd is alive
			if e, ok := parse(msg); ok {
				e.Vif, e.At = name, m.o.Now()
				m.push(e)
			}
		case strings.HasPrefix(msg, "PONG"):
			pinged = false
		}
	}
}

// request sends cmd and waits for a reply starting with want, skipping
// unsolicited events; rd sets the read deadline (watch).
func request(c *net.UnixConn, rd func(time.Time), cmd, want string) error {
	dl := time.Now().Add(replyTimeout)
	_ = c.SetWriteDeadline(dl)
	rd(dl)
	if _, err := c.Write([]byte(cmd)); err != nil {
		return errors.New("send failed: " + errText(err))
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return errors.New("no reply")
		}
		r := string(buf[:n])
		if strings.HasPrefix(r, "<") {
			continue
		}
		if !strings.HasPrefix(r, want) {
			return fmt.Errorf("reply %q", strings.TrimSpace(r))
		}
		return nil
	}
}

// parse reads one unsolicited message.
func parse(msg string) (Event, bool) {
	msg = strings.TrimRight(msg, "\r\n\x00")
	i := strings.IndexByte(msg, '>')
	if !strings.HasPrefix(msg, "<") || i < 2 || i > 3 {
		return Event{}, false
	}
	f := strings.Fields(msg[i+1:])
	if len(f) < 2 {
		return Event{}, false
	}
	var k Kind
	switch f[0] {
	case "AP-STA-CONNECTED":
		k = Connected
	case "AP-STA-DISCONNECTED":
		k = Disconnected
	default:
		return Event{}, false
	}
	hw, err := net.ParseMAC(f[1])
	if err != nil || len(hw) != 6 {
		return Event{}, false
	}
	return Event{MAC: hw.String(), Kind: k}, true
}

// errText is an error without the socket paths net puts in it.
func errText(err error) string {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		err = oe.Err
	}
	var se *os.SyscallError
	if errors.As(err, &se) && se.Err != nil {
		err = se.Err
	}
	return err.Error()
}
