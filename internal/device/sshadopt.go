// SPDX-License-Identifier: GPL-2.0-or-later

package device

// SSH adoption endpoint. UniFi Network 10.6 adopts a pending device by
// SSHing to it (user ubnt) and running
//   /usr/bin/syswrapper.sh set-adopt <inform url> <authkey>
// (open-unifi docs/PROTOCOL-mgmt.md §7; seen live on Network 10.6: "Invalid user
// ubnt from <console>" in the daemon host's own sshd log). The device reports the port
// in its inform payload (`sshd_port`).
//
// For the console this is not a shell: it only parses set-adopt (and
// set-inform), answers every other command with empty output and exit 0,
// and runs nothing. With Site set, the site's device users also get a
// real shell (sitessh.go); the console's adoption path stays as it is.
//
// Who may log in: only AllowFrom (the console's address); and, when Auth is
// set, only with a password Auth accepts. A pending AP takes any password
// (the console uses the factory login); the on-device agent sets Auth once
// adopted, so a set-adopt or set-inform then needs the site's device
// credential (docs/deco/interference-audit.md R12).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// AdoptRequest is what set-adopt delivered.
type AdoptRequest struct {
	URL, Key string
}

type SSHAdopt struct {
	Listen    string   // e.g. 192.168.1.50:2222
	AllowFrom []string // source IPs allowed to connect (the console)
	HostKey   string   // path to the PEM host key (created mode 600)
	Requests  chan AdoptRequest
	// Auth, when set, decides each password login (true = accept). nil
	// accepts any password. It is called from the SSH goroutines: it must
	// be safe for concurrent use. The password is never logged.
	Auth func(user string, password []byte) bool
	// Site, when set, also serves the site's device users (sitessh.go):
	// from the console as before, and from the sources SetSite allows.
	Site *SiteOptions
	mu   sync.Mutex
	ln   net.Listener
	site siteRuntime
}

var (
	setAdoptRE = regexp.MustCompile(`set-adopt\s+(\S+)\s+([0-9a-fA-F]{32})`)
	setInfRE   = regexp.MustCompile(`set-inform\s+(\S+)`)
)

func (s *SSHAdopt) Start() error {
	signer, err := loadOrCreateHostKey(s.HostKey)
	if err != nil {
		return err
	}
	// The console only accepts RSA host keys (rsa-sha2-512/256, ssh-rsa;
	// seen live on Network 10.6), like the dropbear on a real UAP.
	rsaSigner, err := loadOrCreateRSAHostKey(strings.TrimSuffix(s.HostKey, ".pem") + "_rsa.pem")
	if err != nil {
		return err
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			// Without Auth any password: the console uses the factory login
			// (ubnt) or the site's device password. The source IP is
			// already restricted.
			if s.Auth != nil && !s.Auth(c.User(), pw) {
				log.Printf("ssh-adopt: login REFUSED user=%q from %s (not the site's device credential)", c.User(), c.RemoteAddr())
				return nil, errors.New("ssh-adopt: access denied")
			}
			log.Printf("ssh-adopt: login user=%q from %s", c.User(), c.RemoteAddr())
			// a site user's login may also run a shell (sitessh.go)
			return s.consoleSite(c, pw), nil
		},
		ServerVersion: "SSH-2.0-dropbear_2019.78",
	}
	cfg.AddHostKey(rsaSigner)
	cfg.AddHostKey(signer)
	// site sources: the site users only, at most 3 tries per connection
	var siteCfg *ssh.ServerConfig
	if s.Site != nil {
		s.siteInit()
		// 6 tries (OpenSSH's default): a client offers each of its keys
		// before a password; password guessing is bounded by the limiter
		siteCfg = &ssh.ServerConfig{PasswordCallback: s.sitePassword, PublicKeyCallback: s.sitePublicKey,
			MaxAuthTries: 6, ServerVersion: cfg.ServerVersion}
		siteCfg.AddHostKey(rsaSigner)
		siteCfg.AddHostKey(signer)
	}
	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Printf("ssh-adopt: accept: %v", err)
				}
				return
			}
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			if !contains(s.AllowFrom, host) {
				if siteCfg != nil {
					if ok, reason, detail := s.siteAdmit(host); ok {
						go s.serveSite(c, siteCfg, host)
						continue
					} else if reason != "" {
						s.note(host, reason, detail)
						c.Close()
						continue
					}
				}
				log.Printf("ssh-adopt: refused connection from %s (not the console)", host)
				c.Close()
				continue
			}
			go s.serve(c, cfg)
		}
	}()
	return nil
}

func (s *SSHAdopt) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		s.ln.Close()
	}
}

func (s *SSHAdopt) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Minute))
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		log.Printf("ssh-adopt: handshake: %v", err)
		return
	}
	// a site user's login from the console (sitessh.go); nil otherwise
	var site *siteConn
	if p := sc.Permissions; p != nil && p.Extensions[permSiteUser] != "" && s.Site != nil {
		site = &siteConn{user: p.Extensions[permSiteUser], hash: p.Extensions[permSiteHash], src: hostOf(c.RemoteAddr()),
			console: true, nc: c, procs: map[*siteProc]struct{}{}}
		if s.register(site) {
			defer s.unregister(site)
		} else {
			site = nil
		}
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, in, err := nc.Accept()
		if err != nil {
			continue
		}
		if site != nil {
			go s.siteSession(site, ch, in)
			continue
		}
		go s.session(ch, in)
	}
	if site != nil {
		site.closing.Store(true)
	}
}

func (s *SSHAdopt) session(ch ssh.Channel, in <-chan *ssh.Request) {
	defer ch.Close()
	for req := range in {
		switch req.Type {
		case "exec":
			var p struct{ Cmd string }
			ssh.Unmarshal(req.Payload, &p)
			s.adoptExec(ch, req, p.Cmd)
			return
		case "shell":
			s.adoptShell(ch, req)
			return
		default:
			req.Reply(req.Type == "pty-req" || req.Type == "env", nil)
		}
	}
}

// adoptExec answers an exec request with the adoption parser: nothing
// runs, the exit status is 0.
func (s *SSHAdopt) adoptExec(ch ssh.Channel, req *ssh.Request, cmd string) {
	req.Reply(true, nil)
	s.command(cmd)
	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
}

// adoptShell answers a shell request with the adoption parser: commands
// are read line by line until EOF.
func (s *SSHAdopt) adoptShell(ch ssh.Channel, req *ssh.Request) {
	req.Reply(true, nil)
	buf, _ := io.ReadAll(io.LimitReader(ch, 64<<10))
	for _, line := range strings.Split(string(buf), "\n") {
		if strings.TrimSpace(line) != "" {
			s.command(line)
		}
	}
	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
}

func (s *SSHAdopt) command(cmd string) {
	if m := setAdoptRE.FindStringSubmatch(cmd); m != nil {
		log.Printf("ssh-adopt: set-adopt url=%s key=<masked>", m[1])
		s.Requests <- AdoptRequest{URL: m[1], Key: strings.ToLower(m[2])}
		return
	}
	if m := setInfRE.FindStringSubmatch(cmd); m != nil {
		log.Printf("ssh-adopt: set-inform url=%s", m[1])
		s.Requests <- AdoptRequest{URL: m[1]}
		return
	}
	log.Printf("ssh-adopt: command ignored: %q", maskHex(cmd))
}

var hex32 = regexp.MustCompile(`[0-9a-fA-F]{32}`)

func maskHex(s string) string { return hex32.ReplaceAllString(s, "<masked>") }

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(b)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "unifi-openwrt fake device")
	if err != nil {
		return nil, err
	}
	b := pem.EncodeToMemory(blk)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	return ssh.ParsePrivateKey(b)
}

// ApplyAdopt stores a set-adopt/set-inform request in the session.
func (x *Session) ApplyAdopt(r AdoptRequest) Outcome {
	o := Outcome{Changed: true, Immediate: true}
	if r.URL != "" {
		if err := CheckInformURL(r.URL); err == nil {
			x.S.InformURL = r.URL
		} else {
			o.Events = append(o.Events, fmt.Sprintf("ssh-adopt: ignored inform url %q: %v; keeping %s", r.URL, err, x.S.InformURL))
		}
	}
	if r.Key != "" {
		x.S.Key = r.Key
		x.S.Adopted = true
		o.Events = append(o.Events, "ADOPTED via SSH set-adopt: new authkey stored, inform_url="+x.S.InformURL)
	} else {
		o.Events = append(o.Events, "set-inform: inform_url="+x.S.InformURL)
	}
	return o
}

func loadOrCreateRSAHostKey(path string) (ssh.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(b)
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, fmt.Errorf("rsa host key: %w", err)
	}
	return ssh.ParsePrivateKey(b)
}
