// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The controller's Device SSH switch (sshd section; seen on .205): the
// users.N are sent either way.
const (
	sshdOnCfg  = "sshd.status=enabled\nsshd.auth.passwd=enabled\nsshd.1.status=enabled\nsshd.1.ifname=br0\n"
	sshdOffCfg = "sshd.status=disabled\nsshd.1.status=enabled\nsshd.1.ifname=lo\n"
)

func cfgReplyVersion(cfg, ver string) string {
	return strings.ReplaceAll(provisionReply(cfg), "00000000000000c1", ver)
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// stdLog captures the standard logger (internal/device logs there).
func stdLog(t *testing.T) *syncBuf {
	b := &syncBuf{}
	prev := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(prev) })
	return b
}

// siteExec runs cmd over SSH on the agent's port: output, exit status.
func siteExec(port int, user, pw, cmd string) (string, int, error) {
	c, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &ssh.ClientConfig{User: user,
		Auth: []ssh.AuthMethod{ssh.Password(pw)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		return "", -1, err
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		return "", -1, err
	}
	defer s.Close()
	out, err := s.Output(cmd)
	var ee *ssh.ExitError
	switch {
	case err == nil:
		return string(out), 0, nil
	case errors.As(err, &ee):
		return string(out), ee.ExitStatus(), nil
	}
	return string(out), -1, err
}

// Site users log in on sshd_port from a LAN host (here the management
// source 127.0.0.1; the console is elsewhere) while the controller's
// Device SSH switch is on; switching it off ends the open session and
// refuses logins while the account stays installed; on again works; a
// removed user is refused. root never logs in. No password or hash is
// logged.
func TestSiteSSHFollowsDeviceSSHSwitch(t *testing.T) {
	std := stdLog(t)
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply = true, true
		c.ConsoleIP = "192.0.2.10"
		c.MgmtSources = []string{"127.0.0.1"}
		o.siteShell = "/bin/sh"
	})
	os.MkdirAll(filepath.Join(h.root, "etc"), 0o755)
	os.WriteFile(filepath.Join(h.root, "etc/passwd"), []byte("root:x:0:0:root:/root:/bin/ash\n"), 0o644)
	os.WriteFile(filepath.Join(h.root, "etc/shadow"), []byte("root:$1$x$y:17603:0:99999:7:::\n"), 0o600)
	port := h.cfg.SSHDPort
	works := func() bool {
		out, code, err := siteExec(port, "siteadmin", "Hello world!", "echo hi; exit 4")
		return err == nil && out == "hi\n" && code == 4
	}
	refused := func() bool {
		_, _, err := siteExec(port, "siteadmin", "Hello world!", "true")
		return err != nil
	}

	h.ctl.queue(adoptReply, cfgReplyVersion(usersCfg+sshdOnCfg, "00000000000000c1"))
	h.start()
	eventually(t, "site login on", works)
	for _, c := range [][2]string{{"siteadmin", "wrong"}, {"root", "Hello world!"}, {"root", ""}} {
		if _, _, err := siteExec(port, c[0], c[1], "true"); err == nil {
			t.Errorf("%s/%q logged in", c[0], c[1])
		}
	}
	if !works() { // a success clears the failures
		t.Fatal("site login after refusals")
	}

	// an open session, then the switch goes off
	c, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &ssh.ClientConfig{User: "siteadmin",
		Auth: []ssh.AuthMethod{ssh.Password("Hello world!")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, _ := c.NewSession()
	r, _ := sess.StdoutPipe()
	if err := sess.Start("echo up; sleep 30"); err != nil {
		t.Fatal(err)
	}
	io.ReadFull(r, make([]byte, 3))
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	h.ctl.queue(cfgReplyVersion(usersCfg+sshdOffCfg, "00000000000000c2"))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the open session survived Device SSH off")
	}
	if !refused() {
		t.Error("login with Device SSH off")
	}
	eventually(t, "c2 provisioned", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c2" })
	if b, _ := os.ReadFile(filepath.Join(h.root, "etc/shadow")); !strings.Contains(string(b), "siteadmin:") {
		t.Error("the account was removed with the switch off (a UAP keeps it)")
	}

	h.ctl.queue(cfgReplyVersion(usersCfg+sshdOnCfg, "00000000000000c3"))
	eventually(t, "site login on again", works)

	// the user removed from the site
	h.ctl.queue(cfgReplyVersion(testCfg+"users.status=enabled\n"+sshdOnCfg, "00000000000000c4"))
	eventually(t, "removed user refused", refused)
	eventually(t, "account removed", func() bool {
		b, _ := os.ReadFile(filepath.Join(h.root, "etc/passwd"))
		return !strings.Contains(string(b), "siteadmin")
	})
	h.stop()

	all := h.logs.all() + "\n" + std.String()
	for _, want := range []string{
		fmt.Sprintf("site ssh: logins on port %d ON for siteadmin (password) from 127.0.0.1/32 and the console", port),
		fmt.Sprintf("site ssh: logins on port %d off (the controller's Device SSH Authentication is off", port),
		fmt.Sprintf("site ssh: logins on port %d off (no site user installed)", port),
		`ssh: site login REFUSED user="root" from 127.0.0.1`,
		`ssh: site session user="siteadmin" from 127.0.0.1 closed`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing log %q", want)
		}
	}
	if strings.Contains(all, "Hello world!") || strings.Contains(all, testUserHash) || strings.Contains(all, "saltstring") ||
		strings.Contains(all, "sleep 30") {
		t.Error("a password, hash or command was logged")
	}
}

// Observe mode never serves site logins (takeover only), even with the
// switch on and the console's adoption working as before.
func TestSiteSSHObserveModeOff(t *testing.T) {
	stdLog(t)
	h := newHarness(t, func(c *Config, o *options) {
		c.ConsoleIP = "192.0.2.10"
		c.MgmtSources = []string{"127.0.0.1"}
		o.siteShell = "/bin/sh"
	})
	h.ctl.queue(adoptReply, cfgReplyVersion(usersCfg+sshdOnCfg, "00000000000000c1"))
	h.start()
	eventually(t, "c1 reported", func() bool { return cfgversionOf(h.ctl.last()) == "00000000000000c1" })
	if _, _, err := siteExec(h.cfg.SSHDPort, "siteadmin", "Hello world!", "true"); err == nil {
		t.Error("site login in observe mode")
	}
	h.stop()
	if h.a.sa.Site != nil {
		t.Error("observe configuration has site logins configured")
	}
}
