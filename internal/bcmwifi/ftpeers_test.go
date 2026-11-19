// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/ftpeer"
)

// ctrlRec is a fake hostapd control socket: it records the commands per
// vif and answers OK (or fail).
type ctrlRec struct {
	mu   sync.Mutex
	cmds []string // "vif cmd"
	fail bool
}

func (c *ctrlRec) ctrl(_ context.Context, vif, cmd string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cmds = append(c.cmds, vif+" "+cmd)
	if c.fail {
		return "FAIL\n", nil
	}
	return "OK\n", nil
}

func (c *ctrlRec) take() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.cmds
	c.cmds = nil
	return out
}

// logRec collects log lines.
type logRec struct {
	mu    sync.Mutex
	lines []string
}

func (l *logRec) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logRec) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// ftUnit is one simulated Deco running FT-SAE: a fake device, an Applier
// with SAE and FT-SAE on, a recording control socket.
type ftUnit struct {
	f    *fakeDev
	a    *Applier
	ctrl *ctrlRec
	log  *logRec
}

func newFTUnit(t *testing.T, macPrefix string) *ftUnit {
	u := &ftUnit{f: newFakeDev(t), ctrl: &ctrlRec{}, log: &logRec{}}
	u.a = New(Options{Root: u.f.root, Run: u.f, Logf: u.log.logf, VerifyTimeout: 4 * time.Second, WPA3: true, FTSAE: true, Ctrl: u.ctrl.ctrl})
	u.a.sleep = func(time.Duration) { u.f.tick() }
	if macPrefix != "" {
		// Another unit: its own BSSIDs (the fixtures are .205's), in the
		// driver and in TP-Link's confs.
		for _, p := range []string{"wl0", "wl1"} {
			conf, err := os.ReadFile(u.f.path("/tmp/" + p + ".1_hapd.conf"))
			if err != nil {
				t.Fatal(err)
			}
			for j := 1; j <= 6; j++ {
				v := fmt.Sprintf("%s%d", p, j)
				m := fmt.Sprintf("%s:0%c:%02x", macPrefix, p[2], j)
				u.f.state[v+" cur_etheraddr"] = m
				if out, ok := u.f.fixture(v, []string{"cur_etheraddr"}); ok {
					fl := strings.Fields(out)
					conf = []byte(strings.ReplaceAll(string(conf), "bssid="+strings.ToLower(fl[len(fl)-1]), "bssid="+m))
				}
			}
			u.f.write("/tmp/"+p+".1_hapd.conf", string(conf))
		}
	}
	return u
}

func ftDesired() Desired {
	s := ftTransition()
	s.Bands = []string{"ng", "na"}
	return Desired{Country: "IN", Radios: map[string]Radio{"ng": {Enabled: true, Channel: 6}, "na": {Enabled: true, Channel: 44, Width: 80}},
		SSIDs: []SSID{s}}
}

// planConf returns the hostapd conf a plan writes for radio.
func planConf(t *testing.T, p Plan, radio string) string {
	t.Helper()
	for _, st := range p.Steps {
		if st.Kind == StepWrite && st.Path == "/tmp/udeco/hapd-"+radio+".conf" {
			return string(st.Data)
		}
	}
	t.Fatalf("plan writes no conf for %s:\n%s", radio, p)
	return ""
}

// noKeyIn fails when the FT key is in s.
func noKeyIn(t *testing.T, what, s string) {
	t.Helper()
	if strings.Contains(strings.ToLower(s), testFTKey) {
		t.Errorf("FT key in %s", what)
	}
}

// A peer learnt while the radio runs is added to the running hostapd over
// its control socket (SET r1kh, SET r0kh with the key), with no restart:
// the next Plan is empty. Added once: a second sync, or a restarted agent
// (state in RunDir, keyed by the hostapd's pid), adds nothing again. The
// key never reaches a log, a plan, a note or the state file.
func TestFTSAEPeerAddedLive(t *testing.T) {
	ctx := context.Background()
	u := newFTUnit(t, "")
	d := ftDesired()
	applyOK(t, u.a, d)
	pidBefore, _ := u.a.findProc("hostapd", confPath(DefaultRunDir, "wl1"))

	peers := []ftpeer.Peer{ftPeer("02:11:22:33:44:50", "na", "Example Network", testFTKey, "br-lan"),
		ftPeer("02:11:22:33:44:24", "ng", "Example Network", testFTKey, "br-lan")}
	u.a.SetFTPeers(peers)
	if p, err := u.a.Plan(ctx, d); err != nil || !p.Empty() {
		t.Fatalf("a new peer must not restart hostapd: plan (%v):\n%s", err, p)
	}
	r, err := u.a.SyncFTPeers(ctx, d)
	if err != nil || len(r.Problems) > 0 {
		t.Fatalf("sync: %v %q", err, r.Problems)
	}
	got := u.ctrl.take()
	sort.Strings(got)
	want := []string{
		"wl02 SET r0kh 02:11:22:33:44:24 021122334424 " + testFTKey,
		"wl02 SET r1kh 02:11:22:33:44:24 02:11:22:33:44:24 " + testFTKey,
		"wl12 SET r0kh 02:11:22:33:44:50 021122334450 " + testFTKey,
		"wl12 SET r1kh 02:11:22:33:44:50 02:11:22:33:44:50 " + testFTKey,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("control commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(r.Added) != 4 {
		t.Errorf("added %q", r.Added)
	}
	noKeyIn(t, "the sync report", strings.Join(append(r.Added, r.Problems...), "\n"))
	if pid, _ := u.a.findProc("hostapd", confPath(DefaultRunDir, "wl1")); pid != pidBefore {
		t.Errorf("hostapd restarted (%d -> %d)", pidBefore, pid)
	}

	// Again: nothing to add.
	if r, _ := u.a.SyncFTPeers(ctx, d); len(r.Added) != 0 || len(u.ctrl.take()) != 0 {
		t.Errorf("re-added: %q", r.Added)
	}
	// An agent restart (new Applier, same running hostapd): the RunDir
	// record says what is live, nothing is added twice.
	st := u.f.path("/tmp/udeco/ftpeers-wl1.json")
	b, err := os.ReadFile(st)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(st); fi.Mode().Perm() != 0o600 {
		t.Errorf("state mode %o", fi.Mode().Perm())
	}
	noKeyIn(t, "the live-peer state file", string(b))
	a2 := New(Options{Root: u.f.root, Run: u.f, Logf: u.log.logf, WPA3: true, FTSAE: true, Ctrl: u.ctrl.ctrl})
	a2.SetFTPeers(peers)
	if r, _ := a2.SyncFTPeers(ctx, d); len(r.Added) != 0 || len(u.ctrl.take()) != 0 {
		t.Errorf("restarted agent re-added %q", r.Added)
	}

	// The peer expires: nothing is removed from the running hostapd (2.9
	// cannot) and nothing restarts.
	u.a.SetFTPeers(nil)
	if p, err := u.a.Plan(ctx, d); err != nil || !p.Empty() {
		t.Fatalf("an expired peer must not restart hostapd: plan (%v):\n%s", err, p)
	}
	if r, _ := u.a.SyncFTPeers(ctx, d); len(r.Added) != 0 || len(u.ctrl.take()) != 0 {
		t.Errorf("expiry sent commands: %q", r.Added)
	}

	// The controller rotates the WLAN key: the running entries carry the
	// old one (hostapd would keep using them), so the radio restarts with
	// the new key, its peers in the conf.
	u.a.SetFTPeers(peers)
	d2 := ftDesired()
	newKey := "00112233445566778899aabbccddeeff"
	d2.SSIDs[0].FTKey = newKey
	if r, _ := u.a.SyncFTPeers(ctx, d2); len(r.Added) != 0 || len(r.Problems) == 0 {
		t.Errorf("a key change was patched live: added %q problems %q", r.Added, r.Problems)
	}
	u.ctrl.take()
	// The other units re-announce under the new key.
	u.a.SetFTPeers([]ftpeer.Peer{ftPeer("02:11:22:33:44:50", "na", "Example Network", newKey, "br-lan")})
	p, err := u.a.Plan(ctx, d2)
	if err != nil || p.Empty() {
		t.Fatalf("key change: no restart (%v)", err)
	}
	if c := planConf(t, p, "wl1"); !strings.Contains(c, "\nr0kh=02:11:22:33:44:50 021122334450 "+newKey+"\n") {
		t.Errorf("restarted conf lacks the peer under the new key")
	}
	noKeyIn(t, "the logs", u.log.all())
	noKeyIn(t, "the plan text", p.String())
}

// A refused SET is reported (without the key) and retried by the next
// sync; a BSS whose running hostapd is not the layout's gets no command.
func TestFTSAEPeerSyncFailures(t *testing.T) {
	ctx := context.Background()
	u := newFTUnit(t, "")
	d := ftDesired()
	u.a.SetFTPeers([]ftpeer.Peer{ftPeer("02:11:22:33:44:50", "na", "Example Network", testFTKey, "br-lan")})
	// Nothing of ours runs yet (TP-Link's hostapd): no command.
	if r, _ := u.a.SyncFTPeers(ctx, d); len(r.Added) != 0 || len(u.ctrl.take()) != 0 {
		t.Fatalf("commands to a hostapd that is not ours: %q", r.Added)
	}
	applyOK(t, u.a, d) // the peer is in the conf from the start
	if r, _ := u.a.SyncFTPeers(ctx, d); len(r.Added) != 0 || len(u.ctrl.take()) != 0 {
		t.Fatalf("peer in the conf re-added live: %q", r.Added)
	}
	u.a.SetFTPeers([]ftpeer.Peer{ftPeer("02:11:22:33:44:50", "na", "Example Network", testFTKey, "br-lan"),
		ftPeer("02:11:22:33:44:51", "na", "Example Network", testFTKey, "br-lan")})
	u.ctrl.fail = true
	r, _ := u.a.SyncFTPeers(ctx, d)
	if len(r.Added) != 0 || len(r.Problems) != 2 || !strings.Contains(r.Problems[0], "FAIL") {
		t.Fatalf("refused SET: added %q problems %q", r.Added, r.Problems)
	}
	noKeyIn(t, "problems", strings.Join(r.Problems, "\n"))
	u.ctrl.take()
	u.ctrl.fail = false
	if r, _ := u.a.SyncFTPeers(ctx, d); len(r.Added) != 2 {
		t.Errorf("not retried: %q %q", r.Added, r.Problems)
	}
	// Bounded: at most maxFTRuntime entries per BSS between restarts.
	var many []ftpeer.Peer
	for i := 0; i < maxFTPeers; i++ {
		many = append(many, ftPeer(fmt.Sprintf("02:11:22:33:45:%02x", i), "na", "Example Network", testFTKey, "br-lan"))
	}
	u.a.SetFTPeers(many)
	u.a.SyncFTPeers(ctx, d)
	if n := len(u.a.ftLiveEntries("wl1")); n > maxFTRuntime {
		t.Errorf("%d live entries on wl1, cap %d", n, maxFTRuntime)
	}
}

// wpa3 off (or ft_sae off): peers change nothing. The confs are byte for
// byte those without peers, the mobility domain is the SSID-wide one FT-PSK
// always had, drv-wlN.json has no key id, nothing is announced and nothing
// is sent to hostapd.
func TestFTSAEOffPeersChangeNothing(t *testing.T) {
	ctx := context.Background()
	for _, o := range []struct{ wpa3, ftsae bool }{{false, true}, {true, false}, {false, false}} {
		t.Run(fmt.Sprintf("wpa3=%t,ftsae=%t", o.wpa3, o.ftsae), func(t *testing.T) {
			u := newFTUnit(t, "")
			u.a.o.WPA3, u.a.o.FTSAE = o.wpa3, o.ftsae
			d := ftDesired()
			p0, err := u.a.Plan(ctx, d)
			if err != nil {
				t.Fatal(err)
			}
			u.a.SetFTPeers([]ftpeer.Peer{ftPeer("02:11:22:33:44:50", "na", "Example Network", testFTKey, "br-lan"),
				ftPeer("02:11:22:33:44:24", "ng", "Example Network", testFTKey, "br-lan")})
			p1, err := u.a.Plan(ctx, d)
			if err != nil {
				t.Fatal(err)
			}
			for _, radio := range []string{"wl0", "wl1"} {
				c0, c1 := planConf(t, p0, radio), planConf(t, p1, radio)
				if c0 != c1 {
					t.Errorf("%s: peers changed the conf", radio)
				}
				sec := bssSection(t, c1)
				if strings.Contains(sec, "FT-SAE") || strings.Contains(sec, "kh=") || strings.Contains(sec, "pmk_r1_push") {
					t.Errorf("%s: FT-SAE lines:\n%s", radio, sec)
				}
				if confValue(sec, "mobility_domain") != fmt.Sprintf("%04x", mobilityDomain("Example Network")) {
					t.Errorf("%s: mobility domain %s, want the SSID-wide one", radio, confValue(sec, "mobility_domain"))
				}
				noKeyIn(t, radio+" conf", c1)
			}
			for _, st := range p1.Steps {
				if strings.Contains(string(st.Data), "ft_key_id") {
					t.Errorf("%s has a key id", st.Path)
				}
			}
			if ls, _ := u.a.FTLocals(ctx, d); len(ls) != 0 {
				t.Errorf("locals announced: %v", ls)
			}
			applyOK(t, u.a, d)
			if r, _ := u.a.SyncFTPeers(ctx, d); len(r.Added) != 0 || len(u.ctrl.take()) != 0 {
				t.Errorf("commands sent: %q", r.Added)
			}
		})
	}
}

// busNet is an in-memory L2 segment per bridge name: a frame sent by one
// Conn reaches every other Conn on the same bridge.
type busNet struct {
	mu    sync.Mutex
	conns map[string][]*busConn
}

type busConn struct {
	net    *busNet
	bridge string
	in     chan []byte
	closed chan struct{}
	once   sync.Once
}

func (b *busNet) opener() ftpeer.Opener {
	return func(bridge string) (ftpeer.Conn, error) {
		c := &busConn{net: b, bridge: bridge, in: make(chan []byte, 64), closed: make(chan struct{})}
		b.mu.Lock()
		b.conns[bridge] = append(b.conns[bridge], c)
		b.mu.Unlock()
		return c, nil
	}
}

func (c *busConn) Recv(p []byte) (int, error) {
	select {
	case f := <-c.in:
		return copy(p, f), nil
	case <-c.closed:
		return 0, net.ErrClosed
	case <-time.After(50 * time.Millisecond):
		return 0, ftpeer.ErrTimeout
	}
}

func (c *busConn) Send(f []byte) error {
	c.net.mu.Lock()
	defer c.net.mu.Unlock()
	for _, o := range c.net.conns[c.bridge] {
		if o != c {
			select {
			case o.in <- append([]byte(nil), f...):
			default:
			}
		}
	}
	return nil
}

func (c *busConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func eventuallyFT(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Two simulated units running the agent discover each other's FT-SAE key
// holders over an L2 segment and write matching entries: unit A lists unit
// B's BSS of the same band with B's nas_identifier as R0KH-ID and B's
// r1_key_holder as R1KH-ID under the WLAN key, and the other way round;
// neither lists its own radios, and the key never crosses the wire.
func TestFTSAETwoUnitsMatchingEntries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := ftDesired()
	units := map[string]*ftUnit{"A": newFTUnit(t, ""), "B": newFTUnit(t, "02:5b:00:00")}
	unitMAC := map[string]net.HardwareAddr{"A": {0x02, 0xa0, 0, 0, 0, 1}, "B": {0x02, 0xb0, 0, 0, 0, 1}}
	bus := &busNet{conns: map[string][]*busConn{}}
	var wire [][]byte
	var wireMu sync.Mutex
	svcs := map[string]*ftpeer.Service{}
	var wg sync.WaitGroup
	for name, u := range units {
		locals, err := u.a.FTLocals(ctx, d)
		if err != nil || len(locals) != 2 {
			t.Fatalf("%s locals %v: %v", name, locals, err)
		}
		open := bus.opener()
		svc := ftpeer.New(ftpeer.Options{Unit: unitMAC[name], Interval: 200 * time.Millisecond, MinGap: 10 * time.Millisecond,
			Logf: u.log.logf, Open: func(br string) (ftpeer.Conn, error) {
				c, err := open(br)
				return &tapConn{Conn: c, tap: func(f []byte) { wireMu.Lock(); wire = append(wire, f); wireMu.Unlock() }}, err
			}})
		svc.SetLocals(locals)
		svcs[name] = svc
		wg.Add(1)
		go func() { defer wg.Done(); svc.Run(ctx) }()
	}
	for name, svc := range svcs {
		eventuallyFT(t, name+" learns the other unit's two key holders", func() bool { return len(svc.Peers()) == 2 })
	}
	confs := map[string]map[string]string{} // unit -> radio -> bss section
	for name, u := range units {
		u.a.SetFTPeers(svcs[name].Peers())
		p, err := u.a.Plan(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		confs[name] = map[string]string{}
		for _, radio := range []string{"wl0", "wl1"} {
			confs[name][radio] = bssSection(t, planConf(t, p, radio))
		}
		noKeyIn(t, name+" logs", u.log.all())
	}
	for _, pair := range [][2]string{{"A", "B"}, {"B", "A"}} {
		me, peer := pair[0], pair[1]
		for _, radio := range []string{"wl0", "wl1"} {
			mine, theirs := confs[me][radio], confs[peer][radio]
			pb := confValue(theirs, "bssid")
			wantR0 := pb + " " + confValue(theirs, "nas_identifier") + " " + testFTKey
			r1 := confValue(theirs, "r1_key_holder")
			wantR1 := pb + " " + strings.Join(regexp.MustCompile(`..`).FindAllString(r1, -1), ":") + " " + testFTKey
			r0s := regexp.MustCompile(`(?m)^r0kh=(.*)$`).FindAllStringSubmatch(mine, -1)
			r1s := regexp.MustCompile(`(?m)^r1kh=(.*)$`).FindAllStringSubmatch(mine, -1)
			if len(r0s) != 1 || r0s[0][1] != wantR0 || len(r1s) != 1 || r1s[0][1] != wantR1 {
				t.Errorf("%s %s lists %v %v, want r0kh=%s r1kh=%s", me, radio, r0s, r1s, wantR0, wantR1)
			}
			if confValue(mine, "mobility_domain") != confValue(theirs, "mobility_domain") {
				t.Errorf("%s %s: mobility domain differs from %s's", me, radio, peer)
			}
			for _, other := range []string{"wl0", "wl1"} {
				if strings.Contains(mine, "kh="+confValue(confs[me][other], "bssid")+" ") {
					t.Errorf("%s %s lists its own %s", me, radio, other)
				}
			}
		}
	}
	cancel()
	wg.Wait()
	wireMu.Lock()
	defer wireMu.Unlock()
	if len(wire) == 0 {
		t.Fatal("nothing on the wire")
	}
	for _, f := range wire {
		if strings.Contains(strings.ToLower(string(f)), testFTKey) || strings.Contains(fmt.Sprintf("%x", f), testFTKey) {
			t.Fatal("the WLAN key went on the wire")
		}
	}
}

// tapConn records every frame sent.
type tapConn struct {
	ftpeer.Conn
	tap func([]byte)
}

func (c *tapConn) Send(f []byte) error { c.tap(append([]byte(nil), f...)); return c.Conn.Send(f) }

// The default control path: one datagram from a bound local socket, the
// reply read back; errors name the socket, never the command (it carries
// the key).
func TestUnixCtrl(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ftc")
	if err != nil {
		t.Skip(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "wl12")
	srv, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Skip(err)
	}
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 512)
		n, from, err := srv.ReadFromUnix(buf)
		if err != nil {
			return
		}
		got <- string(buf[:n])
		srv.WriteToUnix([]byte("<3>CTRL-EVENT-X"), from) // an event first: skipped
		srv.WriteToUnix([]byte("OK\n"), from)
	}()
	cmd := "SET r0kh 02:11:22:33:44:55 021122334455 " + testFTKey
	reply, err := unixCtrl(context.Background(), sock, dir, cmd)
	if err != nil || reply != "OK\n" || <-got != cmd {
		t.Fatalf("reply %q err %v", reply, err)
	}
	srv.Close()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "ctrl-") {
			t.Errorf("local socket %s left behind", e.Name())
		}
	}
	_, err = unixCtrl(context.Background(), sock, dir, cmd)
	if err == nil || strings.Contains(err.Error(), testFTKey) || strings.Contains(err.Error(), "SET") {
		t.Errorf("error %v: want one that does not echo the command", err)
	}
	var ne *net.OpError
	_ = errors.As(err, &ne)
}

// The live-peer state round-trips (keys never in it).
func TestFTLiveStateJSON(t *testing.T) {
	st := ftLiveState{PID: 7, Added: map[string][]string{"wl12": {"r0kh 02:11:22:33:44:55 021122334455"}}}
	b, _ := json.Marshal(st)
	var back ftLiveState
	if json.Unmarshal(b, &back) != nil || back.PID != 7 || back.Added["wl12"][0] != st.Added["wl12"][0] {
		t.Errorf("round trip %s", b)
	}
}
