// SPDX-License-Identifier: GPL-2.0-or-later

package device

// Site SSH logins on the ssh-adopt listener (docs/deco/agent-design.md
// "Site SSH logins"). A UniFi AP lets the site's device users (system_cfg
// users.N, "Device SSH Authentication") log in with a password and gives
// them a shell. On a Deco port 22 is the owner's dropbear and is never
// touched, so the agent serves those logins itself, on its SSH-adopt port.
//
// The agent decides who may log in and hands it over with SetSite: on or
// off (the controller's sshd switch, takeover only), the provisioned users
// with their crypt hashes, and the source networks allowed besides the
// console. Rules:
//
//   - the console (AllowFrom) is served exactly as before: the same
//     password decision (Auth), and set-adopt/set-inform (and anything
//     naming syswrapper.sh, mca-cli-op or mca-ctrl) still only reach the
//     adoption parser. Every console command does (the controller also
//     sends a plain `reboot`); a console login that is also a site user's
//     gets a real shell only for an interactive PTY shell request;
//   - any other source must be inside SiteSSH.From, with site logins on,
//     and is checked against the site users only: never root or a system
//     account, never an empty, locked or unknown-scheme hash, per-source
//     and global failed-login backoff, a cap on connections and on
//     sessions, an idle timeout;
//   - SetSite ends the open sessions of a user who is no longer allowed
//     (removed, password changed, logins switched off) at once;
//   - only user, source and result are logged: never a password, a hash or
//     a command line.
//
// The shell runs with the agent's own credentials (root on the unit): the
// site users are uid-0 accounts, as on a UniFi AP (cmd/udeco-ap/users.go).

import (
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// SiteUser is one site SSH login. Hash is a crypt(3) hash: a secret, which
// String leaves out.
type SiteUser struct {
	Name string
	Hash string
}

func (u SiteUser) String() string   { return u.Name }
func (u SiteUser) GoString() string { return "device.SiteUser{" + strconv.Quote(u.Name) + "}" }

// SiteSSH is who may log in as a site user now.
type SiteSSH struct {
	On    bool         // the controller's Device SSH switch is on (and the agent owns the unit)
	Users []SiteUser   // the provisioned site users
	From  []*net.IPNet // sources allowed besides the console (the LAN, or mgmt_sources)
	// Keys are the site's Device SSH keys: like a UniFi AP's dropbear, any
	// of them logs in as any site user (sources other than the console
	// only). NoPasswords refuses passwords (sshd.auth.passwd=disabled).
	Keys        []ssh.PublicKey
	NoPasswords bool
}

// keyCred is the credential recorded for a key login: "key:" and the
// key's SHA256 fingerprint (a password login records the user's hash).
func keyCred(k ssh.PublicKey) string { return "key:" + ssh.FingerprintSHA256(k) }

// credOK reports whether user may still log in with cred (a hash, or a
// keyCred) under s.
func (s SiteSSH) credOK(user, cred string) bool {
	u, ok := s.user(user)
	if !s.On || !ok {
		return false
	}
	if strings.HasPrefix(cred, "key:") {
		return slices.ContainsFunc(s.Keys, func(k ssh.PublicKey) bool { return keyCred(k) == cred })
	}
	return !s.NoPasswords && u.Hash == cred
}

func (s SiteSSH) user(name string) (SiteUser, bool) {
	for _, u := range s.Users {
		if u.Name == name {
			return u, true
		}
	}
	return SiteUser{}, false
}

func (s SiteSSH) from(ip net.IP) bool {
	return ip != nil && slices.ContainsFunc(s.From, func(n *net.IPNet) bool { return n.Contains(ip) })
}

// SiteOptions turns site logins on for an SSHAdopt (nil: the listener only
// ever serves the console's adoption). Zero values take the defaults in
// brackets.
type SiteOptions struct {
	Shell       string        // the login shell [/bin/ash]
	Home        string        // the working directory and HOME [/root]
	Path        string        // PATH [/usr/sbin:/usr/bin:/sbin:/bin]
	MaxConns    int           // concurrent connections from site sources, logged in or not [8]
	MaxSessions int           // concurrent site shells and commands [4]
	IdleTimeout time.Duration // a site connection with no traffic is closed [15m]
	AuthTimeout time.Duration // a site source must log in within [30s]
	Limits      LoginLimits
}

// system accounts never logged in by password, whatever the agent hands
// over (the agent already refuses them; this is the second line)
var siteSystemUsers = map[string]bool{"root": true, "nobody": true, "daemon": true, "ftp": true, "network": true,
	"dnsmasq": true, "ntp": true, "logd": true, "ubus": true, "admin": true, "ubnt": true, "sshd": true, "bin": true, "sys": true}

var siteUserName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$`)

// SiteLoginNamePattern is the pattern a site login's name must match, as
// text, and SiteSystemUsers the accounts never logged in. They are for the
// test (cmd/udeco-ap) that holds this second check to the agent's first one
// (translate.LoginNamePattern, translate.SystemUsers): the same pattern,
// and every account refused there refused here too.
func SiteLoginNamePattern() string { return siteUserName.String() }

// SiteSystemUsers is a copy of the refused accounts, sorted.
func SiteSystemUsers() []string {
	out := make([]string, 0, len(siteSystemUsers))
	for n := range siteSystemUsers {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// siteNameOK is a name a site login may have.
func siteNameOK(name string) bool { return siteUserName.MatchString(name) && !siteSystemUsers[name] }

// Permission extensions (in memory only) that mark a site login.
const (
	permSiteUser = "udeco-site-user"
	permSiteHash = "udeco-site-hash"
)

// dummyHash is checked when the user is unknown, so an unknown name costs
// as much as a known one (no user enumeration by timing).
const dummyHash = "$6$udecodummysalt$" + "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

var errSiteDenied = errors.New("access denied")

// siteCrypt is VerifyCrypt (a variable for the tests).
var siteCrypt = VerifyCrypt

// maxPreAuthPerSource caps a source's connections that have not logged in
// yet (dropbear's MAX_UNAUTH_PER_IP): a host that connects and never tries
// a password trips no backoff, and must not hold every connection slot.
const maxPreAuthPerSource = 3

type siteRuntime struct {
	mu       sync.Mutex
	cfg      SiteSSH
	conns    map[*siteConn]struct{}
	open     int            // connections from site sources
	preauth  map[string]int // of those, not logged in yet, per source
	sessions int            // running site shells and commands
	lim      *loginLimiter
	noted    map[string]time.Time // refusal log lines, per source and reason
}

// siteConn is one logged-in site connection (a site source, or the console
// with a site user's password).
type siteConn struct {
	user, hash string
	src        string
	console    bool
	nc         net.Conn
	last       atomic.Int64 // unix nanoseconds of the last traffic
	real       atomic.Bool  // a shell or command ran (console: the adoption deadline is lifted)
	revoked    atomic.Bool  // the user is no longer allowed (console: no new site sessions)
	closing    atomic.Bool
	watch      sync.Once
	mu         sync.Mutex
	procs      map[*siteProc]struct{}
}

func (c *siteConn) touch() { c.last.Store(time.Now().UnixNano()) }

// close ends the connection (once) and hangs up its processes.
func (c *siteConn) close(why string) {
	if c.closing.Swap(true) {
		return
	}
	log.Printf("ssh: site session user=%q from %s closed: %s", c.user, c.src, why)
	c.nc.Close()
	c.hangupAll()
}

func (c *siteConn) hangupAll() {
	c.mu.Lock()
	ps := make([]*siteProc, 0, len(c.procs))
	for p := range c.procs {
		ps = append(ps, p)
	}
	c.mu.Unlock()
	for _, p := range ps {
		p.hangup()
	}
}

// SetSite replaces who may log in as a site user. Users with an unusable
// name or hash are dropped (logged by name). Open site sessions of a user
// no longer allowed, or whose password changed, end at once; a console
// connection that ran no site session is not cut (it may be adopting), it
// only cannot start one any more. Safe for concurrent use, also before
// Start.
func (s *SSHAdopt) SetSite(c SiteSSH) {
	var users []SiteUser
	for _, u := range c.Users {
		switch {
		case !siteNameOK(u.Name):
			log.Printf("ssh: site user %q: not a name that may log in by password: skipped", u.Name)
		case !CryptUsable(u.Hash):
			log.Printf("ssh: site user %q: empty, locked or unsupported password hash: skipped", u.Name)
		case slices.ContainsFunc(users, func(x SiteUser) bool { return x.Name == u.Name }):
		default:
			users = append(users, u)
		}
	}
	var from []*net.IPNet
	for _, n := range c.From {
		if n != nil {
			from = append(from, n)
		}
	}
	var keys []ssh.PublicKey
	for _, k := range c.Keys {
		if k != nil && !slices.ContainsFunc(keys, func(x ssh.PublicKey) bool { return keyCred(x) == keyCred(k) }) {
			keys = append(keys, k)
		}
	}
	c.Users, c.From, c.Keys = users, from, keys
	rt := &s.site
	rt.mu.Lock()
	rt.cfg = c
	var cut []*siteConn
	for sc := range rt.conns {
		if !c.credOK(sc.user, sc.hash) {
			cut = append(cut, sc)
		}
	}
	rt.mu.Unlock()
	for _, sc := range cut {
		sc.revoked.Store(true)
		if !sc.console || sc.real.Load() {
			sc.close("site SSH logins are off or the user was removed or changed")
		}
	}
}

// siteVerify reports whether user/password is a site login allowed now,
// and the hash it matched. Always one crypt, known user or not.
func (s *SSHAdopt) siteVerify(user string, pw []byte) (string, bool) {
	s.site.mu.Lock()
	cfg := s.site.cfg
	s.site.mu.Unlock()
	u, ok := cfg.user(user)
	if !cfg.On || !ok || !siteNameOK(user) || cfg.NoPasswords {
		// as costly as a known user's check: a crypt's time depends on
		// the scheme, rounds and salt length, so with users configured
		// the decoy is the first user's hash (its result is discarded)
		decoy := dummyHash
		if cfg.On && len(cfg.Users) > 0 {
			decoy = cfg.Users[0].Hash
		}
		siteCrypt(decoy, string(pw))
		return "", false
	}
	if !siteCrypt(u.Hash, string(pw)) {
		return "", false
	}
	return u.Hash, true
}

// siteAllowed reports whether conn's user may still run a site session.
func (s *SSHAdopt) siteAllowed(c *siteConn) bool {
	if c.revoked.Load() || c.closing.Load() {
		return false
	}
	s.site.mu.Lock()
	defer s.site.mu.Unlock()
	return s.site.cfg.credOK(c.user, c.hash)
}

func (s *SSHAdopt) siteInit() {
	if s.site.conns == nil {
		s.site.conns = map[*siteConn]struct{}{}
		s.site.noted = map[string]time.Time{}
		s.site.preauth = map[string]int{}
		s.site.lim = newLoginLimiter(s.Site.Limits)
	}
}

func (o *SiteOptions) shell() string { return orDefault(o.Shell, "/bin/ash") }
func (o *SiteOptions) home() string  { return orDefault(o.Home, "/root") }
func (o *SiteOptions) path() string  { return orDefault(o.Path, "/usr/sbin:/usr/bin:/sbin:/bin") }
func (o *SiteOptions) maxConns() int { return intOrDefault(o.MaxConns, 8) }
func (o *SiteOptions) maxSess() int  { return intOrDefault(o.MaxSessions, 4) }
func (o *SiteOptions) idle() time.Duration {
	if o.IdleTimeout <= 0 {
		return 15 * time.Minute
	}
	return o.IdleTimeout
}
func (o *SiteOptions) authTimeout() time.Duration {
	if o.AuthTimeout <= 0 {
		return 30 * time.Second
	}
	return o.AuthTimeout
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func intOrDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// note logs a refusal for src at most once a minute per reason (a scanner
// must not flood the log); detail (such as the remaining wait) is logged
// with it but is not part of the reason.
func (s *SSHAdopt) note(src, reason, detail string) {
	k := src + " " + reason
	now := time.Now()
	s.site.mu.Lock()
	t, seen := s.site.noted[k]
	if !seen || now.Sub(t) > time.Minute {
		s.site.noted[k] = now
		if len(s.site.noted) > maxTrackedSources {
			for k2, t2 := range s.site.noted {
				if now.Sub(t2) > time.Minute {
					delete(s.site.noted, k2)
				}
			}
		}
	}
	s.site.mu.Unlock()
	if !seen || now.Sub(t) > time.Minute {
		log.Printf("ssh: site login from %s refused: %s%s", src, reason, detail)
	}
}

// logName is a client-chosen user name as a log line may carry it: at most
// 32 bytes (the longest site user name), so a huge name cannot fill the
// log (the agent's log lives in RAM).
func logName(name string) string {
	if len(name) > 32 {
		return strconv.Quote(name[:32]) + "..."
	}
	return strconv.Quote(name)
}

// siteAdmit decides whether a connection from a site source (not the
// console) is served; ok takes a connection slot and one of host's
// pre-login slots, released by serveSite. reason is "" when the source is
// not a site source at all (the caller logs that as before); detail goes
// with a refusal's log line.
func (s *SSHAdopt) siteAdmit(host string) (ok bool, reason, detail string) {
	ip := net.ParseIP(host)
	rt := &s.site
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if !rt.cfg.On || len(rt.cfg.Users) == 0 || !rt.cfg.from(ip) {
		return false, "", ""
	}
	if ok, wait, global := rt.lim.allow(host); !ok {
		detail := fmt.Sprintf(" (retry in %s)", wait.Round(time.Second))
		if global {
			return false, "too many failed logins from all sources", detail
		}
		return false, "too many failed logins", detail
	}
	if rt.preauth[host] >= maxPreAuthPerSource {
		return false, "too many connections not logged in", ""
	}
	if rt.open >= s.Site.maxConns() {
		return false, "too many connections", ""
	}
	rt.open++
	rt.preauth[host]++
	return true, "", ""
}

// loggedIn releases host's pre-login slot (once per admitted connection).
func (s *SSHAdopt) loggedIn(host string) {
	s.site.mu.Lock()
	defer s.site.mu.Unlock()
	if s.site.preauth[host]--; s.site.preauth[host] <= 0 {
		delete(s.site.preauth, host)
	}
}

// sitePassword is the password check for site sources.
func (s *SSHAdopt) sitePassword(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
	host := hostOf(c.RemoteAddr())
	if ok, _, _ := s.site.lim.allow(host); !ok {
		s.note(host, "too many failed logins", "")
		return nil, errSiteDenied
	}
	hash, ok := s.siteVerify(c.User(), pw)
	if !ok {
		s.site.lim.fail(host)
		log.Printf("ssh: site login REFUSED user=%s from %s", logName(c.User()), host)
		return nil, errSiteDenied
	}
	s.site.lim.success(host)
	log.Printf("ssh: site login user=%s from %s", logName(c.User()), host)
	return &ssh.Permissions{Extensions: map[string]string{permSiteUser: c.User(), permSiteHash: hash}}, nil
}

// sitePublicKey logs a site source in with one of the site's Device SSH
// keys, for a site user only (never root or a system account). A key the
// site does not have is refused without counting as a failed login: a
// client offers each of its keys in turn, and MaxAuthTries bounds them.
func (s *SSHAdopt) sitePublicKey(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	host := hostOf(c.RemoteAddr())
	if ok, _, _ := s.site.lim.allow(host); !ok {
		s.note(host, "too many failed logins", "")
		return nil, errSiteDenied
	}
	cred := keyCred(key)
	s.site.mu.Lock()
	ok := siteNameOK(c.User()) && s.site.cfg.credOK(c.User(), cred)
	s.site.mu.Unlock()
	if !ok {
		return nil, errSiteDenied
	}
	s.site.lim.success(host)
	log.Printf("ssh: site login user=%s from %s with key %s", logName(c.User()), host, ssh.FingerprintSHA256(key))
	return &ssh.Permissions{Extensions: map[string]string{permSiteUser: c.User(), permSiteHash: cred}}, nil
}

// consoleSite marks a console login that is also a site user's (Auth
// already accepted it: the console's decision is unchanged).
func (s *SSHAdopt) consoleSite(c ssh.ConnMetadata, pw []byte) *ssh.Permissions {
	if s.Site == nil {
		return nil
	}
	s.site.mu.Lock()
	_, known := s.site.cfg.user(c.User())
	on := s.site.cfg.On
	s.site.mu.Unlock()
	if !on || !known {
		return nil // not a site user: no second crypt for the console
	}
	if hash, ok := s.siteVerify(c.User(), pw); ok {
		return &ssh.Permissions{Extensions: map[string]string{permSiteUser: c.User(), permSiteHash: hash}}
	}
	return nil
}

func hostOf(a net.Addr) string {
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

// register adds a logged-in site connection; false when the user is no
// longer allowed (SetSite raced the login).
func (s *SSHAdopt) register(sc *siteConn) bool {
	rt := &s.site
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if !rt.cfg.credOK(sc.user, sc.hash) {
		return false
	}
	rt.conns[sc] = struct{}{}
	return true
}

func (s *SSHAdopt) unregister(sc *siteConn) {
	s.site.mu.Lock()
	delete(s.site.conns, sc)
	s.site.mu.Unlock()
	sc.hangupAll()
}

// watchIdle closes sc after IdleTimeout without traffic (once per
// connection).
func (s *SSHAdopt) watchIdle(sc *siteConn) {
	sc.watch.Do(func() {
		sc.touch()
		idle := s.Site.idle()
		go func() {
			t := time.NewTicker(max(min(idle/4, 30*time.Second), 10*time.Millisecond))
			defer t.Stop()
			for range t.C {
				if sc.closing.Load() {
					return
				}
				if time.Since(time.Unix(0, sc.last.Load())) > idle {
					sc.close("idle for " + idle.String())
					return
				}
			}
		}()
	})
}

// serveSite serves a connection from a site source (not the console).
func (s *SSHAdopt) serveSite(c net.Conn, cfg *ssh.ServerConfig, host string) {
	defer func() {
		s.site.mu.Lock()
		s.site.open--
		s.site.mu.Unlock()
	}()
	defer c.Close()
	c.SetDeadline(time.Now().Add(s.Site.authTimeout()))
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	s.loggedIn(host) // logged in or gone: no longer a pre-login slot
	if err != nil {
		return // the refusal, if it was one, is logged by sitePassword
	}
	c.SetDeadline(time.Time{})
	conn := &siteConn{user: sc.Permissions.Extensions[permSiteUser], hash: sc.Permissions.Extensions[permSiteHash],
		src: host, nc: c, procs: map[*siteProc]struct{}{}}
	if !s.register(conn) {
		log.Printf("ssh: site session user=%q from %s refused: the user is no longer allowed", conn.user, host)
		return
	}
	defer s.unregister(conn)
	s.watchIdle(conn)
	go ssh.DiscardRequests(reqs) // no port forwarding
	for nc := range chans {
		conn.touch()
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.Prohibited, "only sessions")
			continue
		}
		ch, in, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.siteSession(conn, ch, in)
	}
	conn.closing.Store(true)
}

// ptyRequest is an RFC 4254 pty-req.
type ptyRequest struct {
	Term          string
	Cols, Rows    uint32
	Width, Height uint32
	Modes         string
}

type winChange struct {
	Cols, Rows    uint32
	Width, Height uint32
}

// client environment a session may set (as dropbear and OpenSSH's default
// AcceptEnv): the locale only
func envAllowed(name, value string) bool {
	if name == "" || len(name) > 64 || len(value) > 256 || strings.ContainsAny(name, "=\x00") || strings.ContainsRune(value, 0) {
		return false
	}
	return name == "LANG" || strings.HasPrefix(name, "LC_")
}

// siteSession serves one session channel of a site connection. On a
// console connection, adoption commands, a shell without a PTY (the
// adoption line reader) and everything once site logins are off for the
// user go to the adoption parser exactly as before.
func (s *SSHAdopt) siteSession(conn *siteConn, ch ssh.Channel, in <-chan *ssh.Request) {
	defer ch.Close()
	var pty *ptyRequest
	var env []string
	for req := range in {
		conn.touch()
		switch req.Type {
		case "pty-req":
			var p ptyRequest
			if ssh.Unmarshal(req.Payload, &p) != nil || pty != nil {
				req.Reply(conn.console, nil) // the console always got true
				continue
			}
			pty = &p
			req.Reply(true, nil)
		case "env":
			var e struct{ Name, Value string }
			ok := ssh.Unmarshal(req.Payload, &e) == nil && envAllowed(e.Name, e.Value) && len(env) < 16
			if ok {
				env = append(env, e.Name+"="+e.Value)
			}
			req.Reply(ok || conn.console, nil) // the console always got true
		case "window-change":
			var w winChange
			if ssh.Unmarshal(req.Payload, &w) == nil && pty != nil {
				pty.Cols, pty.Rows = w.Cols, w.Rows
			}
			req.Reply(false, nil)
		case "exec":
			var p struct{ Cmd string }
			if ssh.Unmarshal(req.Payload, &p) != nil && !conn.console {
				req.Reply(false, nil)
				return
			}
			// every console command goes to the adoption parser: the
			// controller also sends a plain `reboot` (and syswrapper.sh
			// upgrade/unpair) over SSH, which the parser has always
			// answered without running, and a real reboot would bring a
			// RAM-only unit back as stock TP-Link
			if conn.console {
				s.adoptExec(ch, req, p.Cmd)
				return
			}
			s.runSite(conn, ch, in, req, p.Cmd, pty, env)
			return
		case "shell":
			if conn.console && (pty == nil || !s.siteAllowed(conn)) {
				s.adoptShell(ch, req)
				return
			}
			s.runSite(conn, ch, in, req, "", pty, env)
			return
		default: // subsystem (sftp), x11-req, auth-agent-req, ...
			req.Reply(false, nil)
		}
	}
}

// runSite runs a site user's shell (command "") or command on ch and
// returns when it has exited and its status was sent.
func (s *SSHAdopt) runSite(conn *siteConn, ch ssh.Channel, in <-chan *ssh.Request, req *ssh.Request, command string, pty *ptyRequest, env []string) {
	kind := "command"
	if command == "" {
		kind = "shell"
	}
	if pty != nil {
		kind += " (pty)"
	}
	if !s.siteAllowed(conn) {
		log.Printf("ssh: site %s user=%q from %s refused: site SSH logins are off or the user was removed", kind, conn.user, conn.src)
		req.Reply(false, nil)
		return
	}
	rt := &s.site
	rt.mu.Lock()
	if rt.sessions >= s.Site.maxSess() {
		rt.mu.Unlock()
		log.Printf("ssh: site %s user=%q from %s refused: %d sessions already", kind, conn.user, conn.src, s.Site.maxSess())
		req.Reply(false, nil)
		return
	}
	rt.sessions++
	rt.mu.Unlock()
	defer func() {
		rt.mu.Lock()
		rt.sessions--
		rt.mu.Unlock()
	}()
	if conn.console && !conn.real.Swap(true) {
		// the adoption connection's 2-minute deadline gives way to the
		// idle timeout once a real session runs
		conn.nc.SetDeadline(time.Time{})
	}
	conn.real.Store(true)
	s.watchIdle(conn)

	spec := procSpec{shell: s.Site.shell(), home: s.Site.home(), path: s.Site.path(), user: conn.user,
		command: command, env: env, pty: pty, client: conn.nc.RemoteAddr(), local: conn.nc.LocalAddr()}
	rw := &activityRW{ch: ch, c: conn}
	p, err := startSiteProc(spec, rw, &activityW{w: ch.Stderr(), c: conn})
	if err != nil {
		log.Printf("ssh: site %s user=%q from %s: start failed: %v", kind, conn.user, conn.src, err)
		req.Reply(false, nil)
		return
	}
	conn.mu.Lock()
	conn.procs[p] = struct{}{}
	conn.mu.Unlock()
	defer func() {
		conn.mu.Lock()
		delete(conn.procs, p)
		conn.mu.Unlock()
	}()
	// a SetSite or idle close that came while it started
	if conn.closing.Load() || !s.siteAllowed(conn) {
		p.hangup()
	}
	req.Reply(true, nil)
	log.Printf("ssh: site %s started user=%q from %s", kind, conn.user, conn.src)

	go func() {
		for r := range in {
			conn.touch()
			switch r.Type {
			case "window-change":
				var w winChange
				if ssh.Unmarshal(r.Payload, &w) == nil {
					p.resize(w.Cols, w.Rows)
				}
				r.Reply(false, nil)
			case "signal":
				var sig struct{ Name string }
				ok := ssh.Unmarshal(r.Payload, &sig) == nil && p.signal(sig.Name)
				r.Reply(ok, nil)
			default:
				r.Reply(false, nil)
			}
		}
		// the channel closed (the client went): hang the process up
		p.hangup()
	}()
	st := p.wait()
	if st.signal != "" {
		ch.SendRequest("exit-signal", false, ssh.Marshal(struct {
			Signal     string
			CoreDumped bool
			Error      string
			Lang       string
		}{st.signal, st.core, "", ""}))
		log.Printf("ssh: site %s ended user=%q from %s: signal %s", kind, conn.user, conn.src, st.signal)
	} else {
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(st.code)}))
		log.Printf("ssh: site %s ended user=%q from %s: exit %d", kind, conn.user, conn.src, st.code)
	}
	ch.CloseWrite()
}

// procSpec is what a site process runs.
type procSpec struct {
	shell, home, path, user string
	command                 string // "" = a login shell
	env                     []string
	pty                     *ptyRequest
	client, local           net.Addr
}

// environ is the session's environment, as dropbear sets it.
func (p procSpec) environ(tty string) []string {
	ch, cp, _ := net.SplitHostPort(p.client.String())
	lh, lp, _ := net.SplitHostPort(p.local.String())
	env := []string{"USER=" + p.user, "LOGNAME=" + p.user, "HOME=" + p.home, "SHELL=" + p.shell, "PATH=" + p.path,
		"SSH_CLIENT=" + ch + " " + cp + " " + lp, "SSH_CONNECTION=" + ch + " " + cp + " " + lh + " " + lp}
	if p.pty != nil {
		term := p.pty.Term
		if term == "" || len(term) > 64 || strings.ContainsAny(term, "\x00=/ ") {
			term = "vt100"
		}
		env = append(env, "TERM="+term, "SSH_TTY="+tty)
	}
	return append(env, p.env...)
}

// activityRW is the channel as the process sees it: traffic keeps the
// connection from idling out.
type activityRW struct {
	ch ssh.Channel
	c  *siteConn
}

func (a *activityRW) Read(b []byte) (int, error) {
	n, err := a.ch.Read(b)
	if n > 0 {
		a.c.touch()
	}
	return n, err
}

func (a *activityRW) Write(b []byte) (int, error) {
	a.c.touch()
	return a.ch.Write(b)
}

type activityW struct {
	w interface{ Write([]byte) (int, error) }
	c *siteConn
}

func (a *activityW) Write(b []byte) (int, error) {
	a.c.touch()
	return a.w.Write(b)
}

// exitState is how a site process ended.
type exitState struct {
	code   int
	signal string // without "SIG"; "" = exited
	core   bool
}
