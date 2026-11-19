// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux || darwin

package device

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// A refused login with a huge user name must not put the name into the
// log as is: the agent logs to a file on the unit's ramfs, and a LAN host
// could otherwise fill the RAM a few hundred KiB per try.
func TestSiteLogUserNameBounded(t *testing.T) {
	logs := captureLog(t)
	_, addr := startSite(t, "192.0.2.1", nil, nil)
	long := strings.Repeat("\x01A", 32<<10)
	if _, _, err := runSite(t, addr, long, "wrong", "true"); err == nil {
		t.Fatal("accepted")
	}
	waitFor(t, "the refusal logged", func() bool { return strings.Contains(logs.String(), "site login REFUSED") })
	for _, l := range strings.Split(logs.String(), "\n") {
		if len(l) > 300 {
			t.Fatalf("log line of %d bytes: %.120q...", len(l), l)
		}
	}
}

// A source in backoff that keeps connecting gets one refusal line a
// minute, not one a second (the remaining wait must not make each line a
// new "reason").
func TestSiteRefusalLogRateLimited(t *testing.T) {
	logs := captureLog(t)
	var mu sync.Mutex
	now := time.Date(2026, 11, 19, 4, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	_, addr := startSite(t, "192.0.2.1", nil, func(o *SiteOptions) {
		o.Limits = LoginLimits{Free: 1, Base: 5 * time.Minute, Max: 10 * time.Minute, GlobalFails: 50, Now: clock}
	})
	runSite(t, addr, "siteadmin", "wrong", "true")
	runSite(t, addr, "siteadmin", "wrong", "true") // past the free one: 5 min backoff
	for range 5 {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			c.Read(make([]byte, 1)) // closed by the server
			c.Close()
		}
		advance(3 * time.Second)
	}
	if n := strings.Count(logs.String(), "site login from 127.0.0.1 refused: too many failed logins"); n != 1 {
		t.Fatalf("%d refusal lines, want 1:\n%s", n, logs.String())
	}
}

// One host that connects and never logs in may not hold every site
// connection slot (it never fails a password, so the backoff never
// starts): at most a few unauthenticated connections per source.
func TestSitePreAuthPerSourceCap(t *testing.T) {
	captureLog(t)
	s, addr := startSite(t, "192.0.2.1", nil, func(o *SiteOptions) { o.MaxConns = 8 })
	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for range 8 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	time.Sleep(200 * time.Millisecond)
	s.site.mu.Lock()
	open := s.site.open
	s.site.mu.Unlock()
	if open > maxPreAuthPerSource {
		t.Fatalf("one idle source holds %d of 8 slots (cap %d)", open, maxPreAuthPerSource)
	}
	// once logged in a connection no longer counts against the cap
	for range maxPreAuthPerSource {
		held[0].Close()
		held = held[1:]
	}
	waitFor(t, "slots released", func() bool {
		s.site.mu.Lock()
		defer s.site.mu.Unlock()
		return s.site.open == 0
	})
	var clients []interface{ Close() error }
	t.Cleanup(func() {
		for _, c := range clients {
			c.Close()
		}
	})
	for i := range maxPreAuthPerSource + 1 {
		c, err := dialSite(addr, "siteadmin", sitePW)
		if err != nil {
			t.Fatalf("login %d: %v", i+1, err)
		}
		clients = append(clients, c)
	}
}

// The console's pty-req is always answered true, as the adoption responder
// always did, also on a site user's console connection.
func TestSiteConsolePtyReqReplyUnchanged(t *testing.T) {
	captureLog(t)
	auth := func(user string, pw []byte) bool { return user == "siteadmin" && VerifyCrypt(siteHash, string(pw)) }
	_, addr := startSite(t, "127.0.0.1", auth, nil)
	c, err := dialSite(addr, "siteadmin", sitePW)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	for i, payload := range [][]byte{{0, 0}, nil} {
		ok, err := sess.SendRequest("pty-req", true, payload)
		if err != nil || !ok {
			t.Errorf("pty-req %d: ok=%v err=%v", i, ok, err)
		}
	}
}

// cryptShape is what a crypt's cost depends on besides the password: the
// scheme, the rounds field and the salt length.
func cryptShape(h string) string {
	f := strings.Split(h, "$")
	if len(f) < 4 {
		return h
	}
	if strings.HasPrefix(f[2], "rounds=") {
		return f[1] + " " + f[2] + " " + string(rune('0'+len(f[3])))
	}
	return f[1] + " " + string(rune('0'+len(f[2])))
}

// An unknown user costs the same crypt as a known one: the same scheme,
// rounds and salt length (the live controller's $6$ salt is 8 characters;
// sha-crypt's time per round depends on the salt length, by up to 40 %
// at some password lengths, so a fixed dummy would tell names apart).
func TestSiteUnknownUserSameCryptCost(t *testing.T) {
	captureLog(t)
	var mu sync.Mutex
	var used []string
	prev := siteCrypt
	siteCrypt = func(h, pw string) bool { mu.Lock(); used = append(used, h); mu.Unlock(); return prev(h, pw) }
	t.Cleanup(func() { siteCrypt = prev })
	live := "$6$abcdefgh$" + strings.Repeat("Zx", 43)
	s := &SSHAdopt{Site: &SiteOptions{}}
	s.siteInit()
	s.SetSite(SiteSSH{On: true, Users: []SiteUser{{Name: "siteadmin", Hash: live}}, From: []*net.IPNet{loopback}})
	for _, name := range []string{"siteadmin", "nosuchuser", "root"} {
		mu.Lock()
		used = nil
		mu.Unlock()
		if _, ok := s.siteVerify(name, []byte("guess-guess-guess19")); ok {
			t.Fatalf("%s accepted", name)
		}
		mu.Lock()
		if len(used) != 1 || cryptShape(used[0]) != cryptShape(live) {
			t.Errorf("%s: crypts %d, shape %q, want one of shape %q", name, len(used), cryptShape(strings.Join(used, "")), cryptShape(live))
		}
		mu.Unlock()
	}
}
