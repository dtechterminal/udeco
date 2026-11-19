// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux || darwin

package device

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// siteHash is the SHA-crypt specification's example: "Hello world!".
const (
	siteHash = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
	sitePW   = "Hello world!"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// captureLog sends the standard logger to a buffer for the test.
func captureLog(t *testing.T) *lockedBuf {
	t.Helper()
	b := &lockedBuf{}
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	return b
}

var loopback = &net.IPNet{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)}

// startSite starts an SSHAdopt on loopback. console is AllowFrom: with
// "192.0.2.1" the test client (127.0.0.1) is a site source, with
// "127.0.0.1" it is the console.
func startSite(t *testing.T, console string, auth func(string, []byte) bool, mod func(*SiteOptions)) (*SSHAdopt, string) {
	t.Helper()
	o := &SiteOptions{Shell: "/bin/sh", Home: t.TempDir(), IdleTimeout: time.Minute, Limits: LoginLimits{Free: 100}}
	if mod != nil {
		mod(o)
	}
	s := &SSHAdopt{Listen: "127.0.0.1:0", AllowFrom: []string{console}, HostKey: filepath.Join(t.TempDir(), "k.pem"),
		Requests: make(chan AdoptRequest, 4), Auth: auth, Site: o}
	s.SetSite(SiteSSH{On: true, Users: []SiteUser{{Name: "siteadmin", Hash: siteHash}}, From: []*net.IPNet{loopback}})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, s.ln.Addr().String()
}

func dialSite(addr, user, pw string) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(pw)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
}

// runSite runs cmd and returns its output and exit status (-1: no status).
func runSite(t *testing.T, addr, user, pw, cmd string) (string, int, error) {
	t.Helper()
	c, err := dialSite(addr, user, pw)
	if err != nil {
		return "", -1, err
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		return "", -1, err
	}
	defer sess.Close()
	var out lockedBuf
	sess.Stdout, sess.Stderr = &out, &out
	err = sess.Run(cmd)
	var ee *ssh.ExitError
	switch {
	case err == nil:
		return out.String(), 0, nil
	case errors.As(err, &ee):
		return out.String(), ee.ExitStatus(), nil
	}
	return out.String(), -1, err
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A LAN host logs in with a site user's password and runs a command: its
// output, stderr, environment and exit status come back. A wrong password,
// an unknown user and root are refused; nothing secret is logged.
func TestSiteLoginGoodAndBadPassword(t *testing.T) {
	logs := captureLog(t)
	_, addr := startSite(t, "192.0.2.1", nil, nil)
	out, code, err := runSite(t, addr, "siteadmin", sitePW, `echo "u=$USER l=$LOGNAME h=$HOME s=$SHELL"; echo err >&2; exit 3`)
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 || !strings.Contains(out, "u=siteadmin l=siteadmin h=") || !strings.Contains(out, "s=/bin/sh") || !strings.Contains(out, "err") {
		t.Fatalf("code %d out %q", code, out)
	}
	for _, c := range []struct{ user, pw string }{{"siteadmin", "wrong"}, {"siteadmin", ""}, {"nobody", sitePW}, {"root", sitePW}} {
		if _, _, err := runSite(t, addr, c.user, c.pw, "true"); err == nil {
			t.Errorf("%s/%q accepted", c.user, c.pw)
		}
	}
	l := logs.String()
	if !strings.Contains(l, `site login user="siteadmin" from 127.0.0.1`) || !strings.Contains(l, `site login REFUSED user="root" from 127.0.0.1`) {
		t.Errorf("log:\n%s", l)
	}
	if strings.Contains(l, sitePW) || strings.Contains(l, siteHash) || strings.Contains(l, "saltstring") || strings.Contains(l, "echo") {
		t.Errorf("a password, hash or command was logged:\n%s", l)
	}
}

// root, system accounts, empty and locked hashes are never handed a
// password login, whatever SetSite is given.
func TestSiteNeverRootOrUnusableHash(t *testing.T) {
	captureLog(t)
	s, addr := startSite(t, "192.0.2.1", nil, nil)
	s.SetSite(SiteSSH{On: true, From: []*net.IPNet{loopback}, Users: []SiteUser{
		{Name: "root", Hash: siteHash}, {Name: "daemon", Hash: siteHash}, {Name: "empty", Hash: ""},
		{Name: "locked", Hash: "!" + siteHash}, {Name: "star", Hash: "*"}, {Name: "siteadmin", Hash: siteHash}}})
	if got := len(s.site.cfg.Users); got != 1 {
		t.Fatalf("%d users kept: %v", got, s.site.cfg.Users)
	}
	for _, u := range []string{"root", "daemon", "empty", "locked", "star"} {
		if _, _, err := runSite(t, addr, u, sitePW, "true"); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	if _, _, err := runSite(t, addr, "siteadmin", sitePW, "true"); err != nil {
		t.Errorf("siteadmin: %v", err)
	}
}

// openShell starts a long-running command and returns once it runs.
func openShell(t *testing.T, addr string) (*ssh.Client, *ssh.Session, chan error) {
	t.Helper()
	c, err := dialSite(addr, "siteadmin", sitePW)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	r, _ := sess.StdoutPipe()
	if err := sess.Start("echo ready; sleep 30"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(r, buf); err != nil || string(buf) != "ready\n" {
		t.Fatalf("%q %v", buf, err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	return c, sess, done
}

func ended(t *testing.T, done chan error, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: the open session was not ended", what)
	}
}

// A removed user (or one whose password changed) is cut off at once and
// cannot log in again.
func TestSiteRemovedUserEndsSessions(t *testing.T) {
	logs := captureLog(t)
	s, addr := startSite(t, "192.0.2.1", nil, nil)
	c, _, done := openShell(t, addr)
	defer c.Close()
	s.SetSite(SiteSSH{On: true, From: []*net.IPNet{loopback}, Users: []SiteUser{{Name: "other", Hash: siteHash}}})
	ended(t, done, "removed user")
	if _, _, err := runSite(t, addr, "siteadmin", sitePW, "true"); err == nil {
		t.Error("removed user logged in")
	}
	if !strings.Contains(logs.String(), `site session user="siteadmin" from 127.0.0.1 closed`) {
		t.Errorf("log:\n%s", logs.String())
	}
	// a changed password ends the session too
	s.SetSite(SiteSSH{On: true, From: []*net.IPNet{loopback}, Users: []SiteUser{{Name: "siteadmin", Hash: siteHash}}})
	c2, _, done2 := openShell(t, addr)
	defer c2.Close()
	s.SetSite(SiteSSH{On: true, From: []*net.IPNet{loopback}, Users: []SiteUser{{Name: "siteadmin", Hash: "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"}}})
	ended(t, done2, "password changed")
	// the new hash ($5$) works
	if _, _, err := runSite(t, addr, "siteadmin", sitePW, "true"); err != nil {
		t.Errorf("$5$ login: %v", err)
	}
	waitFor(t, "processes reaped", func() bool {
		s.site.mu.Lock()
		defer s.site.mu.Unlock()
		return s.site.sessions == 0
	})
}

// Device SSH switched off (sshd disabled or on lo): open sessions end, new
// connections from site sources get no SSH banner.
func TestSiteSettingOff(t *testing.T) {
	captureLog(t)
	s, addr := startSite(t, "192.0.2.1", nil, nil)
	c, _, done := openShell(t, addr)
	defer c.Close()
	s.SetSite(SiteSSH{On: false, From: []*net.IPNet{loopback}, Users: []SiteUser{{Name: "siteadmin", Hash: siteHash}}})
	ended(t, done, "logins off")
	nc, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	nc.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 64)
	n, _ := nc.Read(b)
	nc.Close()
	if n != 0 {
		t.Errorf("a site source got an SSH banner with logins off: %q", b[:n])
	}
	// a source outside From is refused the same way
	s.SetSite(SiteSSH{On: true, Users: []SiteUser{{Name: "siteadmin", Hash: siteHash}},
		From: []*net.IPNet{{IP: net.IPv4(192, 168, 0, 0).To4(), Mask: net.CIDRMask(24, 32)}}})
	if _, _, err := runSite(t, addr, "siteadmin", sitePW, "true"); err == nil {
		t.Error("a source outside From logged in")
	}
}

// Failed logins: after the free ones the source is refused, even with the
// right password, until the backoff has passed; a success clears it. The
// global limit refuses every source.
func TestSiteRateLimit(t *testing.T) {
	logs := captureLog(t)
	var mu sync.Mutex
	now := time.Date(2026, 11, 19, 4, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	_, addr := startSite(t, "192.0.2.1", nil, func(o *SiteOptions) {
		o.Limits = LoginLimits{Free: 2, Base: time.Minute, Max: 10 * time.Minute, GlobalFails: 50, Now: clock}
	})
	for range 3 {
		runSite(t, addr, "siteadmin", "wrong", "true") // MaxAuthTries 3: the client tries once per password
	}
	if _, _, err := runSite(t, addr, "siteadmin", sitePW, "true"); err == nil {
		t.Fatal("right password accepted during the backoff")
	}
	if !strings.Contains(logs.String(), "site login from 127.0.0.1 refused: too many failed logins") {
		t.Errorf("log:\n%s", logs.String())
	}
	advance(61 * time.Second)
	if _, _, err := runSite(t, addr, "siteadmin", sitePW, "true"); err != nil {
		t.Fatalf("after the backoff: %v", err)
	}
	// cleared by the success: two more failures are free again
	runSite(t, addr, "siteadmin", "wrong", "true")
	if _, _, err := runSite(t, addr, "siteadmin", sitePW, "true"); err != nil {
		t.Fatalf("one failure after a success: %v", err)
	}

	// the limiter alone: backoff doubles and is capped, global blocks all
	l := newLoginLimiter(LoginLimits{Free: 1, Base: time.Second, Max: 4 * time.Second, GlobalFails: 5, Now: clock})
	for i, want := range []time.Duration{0, time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second} {
		l.fail("10.0.0.1")
		_, wait, _ := l.allow("10.0.0.1")
		if wait != want {
			t.Errorf("failure %d: wait %v, want %v", i+1, wait, want)
		}
		if i == 3 {
			break // the fifth would trip the global limit
		}
	}
	l.fail("10.0.0.2")
	if ok, _, global := l.allow("10.0.0.3"); ok || !global {
		t.Errorf("global limit: ok=%v global=%v", ok, global)
	}
	advance(2 * time.Minute)
	if ok, _, _ := l.allow("10.0.0.3"); !ok {
		t.Error("global block did not expire")
	}
}

// A PTY session: TERM, a terminal on stdin, the window size and its
// change, a command typed into an interactive login shell, and its exit
// status.
func TestSitePTYSession(t *testing.T) {
	captureLog(t)
	_, addr := startSite(t, "192.0.2.1", nil, nil)
	c, err := dialSite(addr, "siteadmin", sitePW)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// exec of one command on a PTY
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm-256color", 40, 100, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	out, err := sess.CombinedOutput(`echo "term=$TERM"; [ -t 0 ] && echo tty-yes; stty size; exit 5`)
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 5 {
		t.Fatalf("exit: %v (%q)", err, out)
	}
	for _, want := range []string{"term=xterm-256color", "tty-yes", "40 100"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("missing %q in %q", want, out)
		}
	}

	// an interactive login shell: window-change, then a typed command
	sh, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sh.RequestPty("vt100", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		t.Fatal(err)
	}
	stdin, _ := sh.StdinPipe()
	var buf lockedBuf
	sh.Stdout = &buf
	if err := sh.Shell(); err != nil {
		t.Fatal(err)
	}
	if err := sh.WindowChange(50, 132); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	io.WriteString(stdin, "stty size; echo \"marker-$((6*7))\"; exit 7\n")
	err = sh.Wait()
	if !errors.As(err, &ee) || ee.ExitStatus() != 7 {
		t.Fatalf("shell exit: %v (%q)", err, buf.String())
	}
	if o := buf.String(); !strings.Contains(o, "marker-42") || !strings.Contains(o, "50 132") {
		t.Errorf("shell output %q", o)
	}
}

// A signal request reaches the command; an idle connection is closed.
// The idle timeout leaves room for the signal's round trip on a loaded
// machine (400 ms failed about 1 run in 20 under the full suite).
func TestSiteSignalAndIdle(t *testing.T) {
	logs := captureLog(t)
	_, addr := startSite(t, "192.0.2.1", nil, func(o *SiteOptions) { o.IdleTimeout = 1500 * time.Millisecond })
	c, err := dialSite(addr, "siteadmin", sitePW)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, _ := c.NewSession()
	r, _ := sess.StdoutPipe()
	if err := sess.Start("echo go; sleep 30"); err != nil {
		t.Fatal(err)
	}
	io.ReadFull(r, make([]byte, 3))
	sess.Signal(ssh.SIGTERM)
	err = sess.Wait()
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.Signal() != "TERM" {
		t.Errorf("after SIGTERM: %v", err)
	}
	// nothing more: the idle timeout closes the connection
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idle connection not closed")
	}
	if !strings.Contains(logs.String(), "closed: idle for 1.5s") {
		t.Errorf("log:\n%s", logs.String())
	}
}

// At most MaxSessions shells run at once.
func TestSiteMaxSessions(t *testing.T) {
	captureLog(t)
	_, addr := startSite(t, "192.0.2.1", nil, func(o *SiteOptions) { o.MaxSessions = 1 })
	c, _, done := openShell(t, addr)
	defer c.Close()
	if _, _, err := runSite(t, addr, "siteadmin", sitePW, "true"); err == nil {
		t.Error("a second session ran")
	}
	c.Close()
	ended(t, done, "client closed")
}

// The console's adoption is unchanged with site logins on: the factory
// login (Auth accepts it) still only reaches the adoption parser, and so
// do set-adopt/set-inform from a site user, which run nothing. A site
// user's other command from the console runs for real.
func TestSiteConsoleAdoptionUnchanged(t *testing.T) {
	logs := captureLog(t)
	auth := func(user string, pw []byte) bool {
		return user == "ubnt" || user == "siteadmin" && VerifyCrypt(siteHash, string(pw))
	}
	s, addr := startSite(t, "127.0.0.1", auth, nil)
	marker := filepath.Join(t.TempDir(), "ran")
	setAdopt := "/usr/bin/syswrapper.sh set-adopt http://192.168.1.1:8080/inform " + newKey + "; touch " + marker
	for _, user := range []string{"ubnt", "siteadmin"} {
		pw := sitePW
		if user == "ubnt" {
			pw = "ubnt"
		}
		out, code, err := runSite(t, addr, user, pw, setAdopt)
		if err != nil || code != 0 || out != "" {
			t.Fatalf("%s: set-adopt: %q %d %v", user, out, code, err)
		}
		select {
		case r := <-s.Requests:
			if r.Key != newKey {
				t.Fatalf("%+v", r)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: set-adopt not delivered", user)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("%s: the adoption command ran in a shell", user)
		}
	}
	// the factory login's other commands are ignored, as before
	if out, code, err := runSite(t, addr, "ubnt", "ubnt", "echo hi"); err != nil || code != 0 || out != "" {
		t.Errorf("factory login: %q %d %v", out, code, err)
	}
	// a refused console login stays refused
	if _, _, err := runSite(t, addr, "siteadmin", "wrong", "echo hi"); err == nil {
		t.Error("wrong password accepted from the console")
	}
	// a site user's command from the console host still goes to the
	// adoption parser: the controller sends a plain `reboot` over SSH,
	// which must never run (a RAM-only unit would come back as TP-Link)
	for _, cmd := range []string{"echo hi; exit 2", "reboot"} {
		if out, code, err := runSite(t, addr, "siteadmin", sitePW, cmd); err != nil || code != 0 || out != "" {
			t.Errorf("site user from the console, %q: %q %d %v", cmd, out, code, err)
		}
	}
	// site logins off: the console's adoption still works, nothing runs
	s.SetSite(SiteSSH{})
	if out, code, err := runSite(t, addr, "siteadmin", sitePW, "echo hi"); err != nil || code != 0 || out != "" {
		t.Errorf("site off, console: %q %d %v", out, code, err)
	}
	if strings.Contains(logs.String(), sitePW) || strings.Contains(logs.String(), siteHash) {
		t.Error("secret logged")
	}
}

// Without Site the listener is what it always was: non-console peers get
// no banner whatever SetSite says.
func TestSiteNilKeepsConsoleOnly(t *testing.T) {
	captureLog(t)
	s := &SSHAdopt{Listen: "127.0.0.1:0", AllowFrom: []string{"192.0.2.1"}, HostKey: filepath.Join(t.TempDir(), "k.pem"),
		Requests: make(chan AdoptRequest, 1)}
	s.SetSite(SiteSSH{On: true, Users: []SiteUser{{Name: "siteadmin", Hash: siteHash}}, From: []*net.IPNet{loopback}})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, err := runSite(t, s.ln.Addr().String(), "siteadmin", sitePW, "true"); err == nil {
		t.Error("a site login without Site")
	}
}
