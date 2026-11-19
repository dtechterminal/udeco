// SPDX-License-Identifier: GPL-2.0-or-later
package device

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newSiteKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func dialSiteKey(addr, user string, k ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(k)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
}

func keyRun(t *testing.T, c *ssh.Client, cmd string) (string, error) {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.Output(cmd)
	return string(out), err
}

// A site Device SSH key logs in as a site user (like a UniFi AP's
// dropbear), never as root or an unknown name; a key the site does not
// have is refused; removing the key or turning logins off cuts the
// session; with passwords disabled only keys work.
func TestSiteKeyLogin(t *testing.T) {
	logs := captureLog(t)
	s, addr := startSite(t, "192.0.2.1", nil, nil)
	good, other := newSiteKey(t), newSiteKey(t)
	users := []SiteUser{{Name: "siteadmin", Hash: siteHash}}
	from := []*net.IPNet{loopback}
	s.SetSite(SiteSSH{On: true, Users: users, From: from, Keys: []ssh.PublicKey{good.PublicKey()}})

	c, err := dialSiteKey(addr, "siteadmin", good)
	if err != nil {
		t.Fatalf("site key refused: %v", err)
	}
	defer c.Close()
	if out, err := keyRun(t, c, "echo $USER"); err != nil || out != "siteadmin\n" {
		t.Fatalf("command: %q %v", out, err)
	}
	for _, u := range []string{"root", "nobody", "someone"} {
		if c2, err := dialSiteKey(addr, u, good); err == nil {
			c2.Close()
			t.Errorf("key logged in as %s", u)
		}
	}
	if c2, err := dialSiteKey(addr, "siteadmin", other); err == nil {
		c2.Close()
		t.Error("a key the site does not have logged in")
	}

	// the key is removed: the open session ends, a new login is refused
	s.SetSite(SiteSSH{On: true, Users: users, From: from})
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("session of a removed key not cut")
	}
	if c2, err := dialSiteKey(addr, "siteadmin", good); err == nil {
		c2.Close()
		t.Error("removed key still logs in")
	}

	// passwords disabled: the password is refused, the key works
	s.SetSite(SiteSSH{On: true, Users: users, From: from, Keys: []ssh.PublicKey{good.PublicKey()}, NoPasswords: true})
	if c2, err := dialSite(addr, "siteadmin", sitePW); err == nil {
		c2.Close()
		t.Error("password accepted with passwords disabled")
	}
	c3, err := dialSiteKey(addr, "siteadmin", good)
	if err != nil {
		t.Fatalf("key refused with passwords disabled: %v", err)
	}
	// logins off: cut
	s.SetSite(SiteSSH{})
	go func() { done <- c3.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("key session not cut when logins went off")
	}
	_ = logs
}
