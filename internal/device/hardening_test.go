// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Vectors from the SHA-crypt specification, each re-checked with
// `openssl passwd -6 -salt <salt> <password>` (OpenSSL 4.1.0).
func TestVerifyCrypt(t *testing.T) {
	for _, c := range []struct{ hash, pw string }{
		{"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1", "Hello world!"},
		{"$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.", "Hello world!"},
		{"$6$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0", "This is just a test"},
		// a key longer than 64 bytes (150 x 'x')
		{"$6$ab$LRP9h1T43kFonxhIpSHQYzN2KQh8hcZ6EWHVcqNiGZyD6ZogL/HL9AR0L4FACZSZrFneqjoLD5uYdz8PiVPYj.", strings.Repeat("x", 150)},
	} {
		if !VerifyCrypt(c.hash, c.pw) {
			t.Errorf("%s: right password refused", c.hash[:12])
		}
		if VerifyCrypt(c.hash, c.pw+"!") || VerifyCrypt(c.hash, "") {
			t.Errorf("%s: wrong password accepted", c.hash[:12])
		}
	}
	for _, bad := range []string{"", "$1$abc$def", "$6$nosaltend", "$6$rounds=x$s$d", "$6$rounds=9999999$s$d", "plain"} {
		if VerifyCrypt(bad, "Hello world!") {
			t.Errorf("%q accepted", bad)
		}
	}
}

// R12: with Auth set, a wrong password never reaches set-adopt; the right
// one does. The test SSHes to a real listener on loopback.
func TestSSHAdoptAuth(t *testing.T) {
	dir := t.TempDir()
	s := &SSHAdopt{Listen: "127.0.0.1:0", AllowFrom: []string{"127.0.0.1"}, HostKey: filepath.Join(dir, "k.pem"),
		Requests: make(chan AdoptRequest, 4),
		Auth:     func(user string, pw []byte) bool { return user == "admin" && string(pw) == "right" }}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	addr := s.ln.Addr().String()
	run := func(user, pw string) error {
		c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(pw)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
		if err != nil {
			return err
		}
		defer c.Close()
		sess, err := c.NewSession()
		if err != nil {
			return err
		}
		defer sess.Close()
		return sess.Run("/usr/bin/syswrapper.sh set-adopt http://192.168.1.1:8080/inform " + newKey)
	}
	if err := run("admin", "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if err := run("ubnt", "right"); err == nil {
		t.Fatal("wrong user accepted")
	}
	select {
	case r := <-s.Requests:
		t.Fatalf("refused login delivered %+v", r)
	default:
	}
	if err := run("admin", "right"); err != nil {
		t.Fatalf("right credential: %v", err)
	}
	select {
	case r := <-s.Requests:
		if r.Key != newKey {
			t.Fatalf("%+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("set-adopt not delivered")
	}
}

func payloadCfgVersion(t *testing.T, x *Session) string {
	t.Helper()
	js, err := x.Payload(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(js, &m)
	v, _ := m["cfgversion"].(string)
	return v
}

// With DeferCfgAck the inform keeps the old cfgversion until the AP says
// the configuration is live, so a failed apply makes the controller
// provision again.
func TestDeferredCfgAck(t *testing.T) {
	x := newSession(t)
	x.DeferCfgAck = true
	handle(t, x, `{"_type":"setparam","mgmt_cfg":"authkey=`+newKey+`\ncfgversion=00a1\n"}`)
	if got := payloadCfgVersion(t, x); got != "0" {
		t.Fatalf("cfgversion reported before ack: %s", got)
	}
	o := handle(t, x, `{"_type":"setparam","cfgversion":"00b2","mgmt_cfg":"cfgversion=00b2\n","system_cfg":"radio.1.phyname=wifi0\n"}`)
	if !o.SystemCfg || o.CfgVersion != "00b2" || x.S.PendingCfgVersion != "00b2" || x.WantedCfgVersion() != "00b2" {
		t.Fatalf("outcome %+v pending %q", o, x.S.PendingCfgVersion)
	}
	if got := payloadCfgVersion(t, x); got != "0" {
		t.Fatalf("cfgversion reported before ack: %s", got)
	}
	if !x.AckCfgVersion("00b2") || x.S.PendingCfgVersion != "" {
		t.Fatalf("ack: %+v", x.S)
	}
	if got := payloadCfgVersion(t, x); got != "00b2" {
		t.Fatalf("after ack: %s", got)
	}
	if x.AckCfgVersion("00b2") {
		t.Error("second ack changed the state")
	}
	// the state survives a restart
	p := filepath.Join(t.TempDir(), "s.json")
	x.S.PendingCfgVersion = "00c3"
	x.S.Save(p)
	st, _, _ := Load(p)
	if st.PendingCfgVersion != "00c3" {
		t.Errorf("pending not saved: %+v", st)
	}
	// setdefault forgets it
	handle(t, x, `{"_type":"setdefault"}`)
	if x.S.PendingCfgVersion != "" || x.S.CfgVersion != "0" {
		t.Errorf("setdefault kept %+v", x.S)
	}

	// without DeferCfgAck (the emulators) it is reported at once
	y := newSession(t)
	handle(t, y, `{"_type":"setparam","cfgversion":"00d4","mgmt_cfg":"cfgversion=00d4\n"}`)
	if got := payloadCfgVersion(t, y); got != "00d4" || y.S.PendingCfgVersion != "" {
		t.Errorf("immediate ack: %s pending %q", got, y.S.PendingCfgVersion)
	}
}

// R7: no history copy named by an unset clock (2025 on a Deco before NTP).
func TestNoHistoryBeforeClockSet(t *testing.T) {
	x := newSession(t)
	if _, err := x.Handle([]byte(`{"_type":"setparam","system_cfg":"a.b=c\n"}`), time.Date(2025, 9, 12, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(x.StateDir, "system_cfg.txt")); err != nil {
		t.Fatal("system_cfg not saved")
	}
	if es, _ := os.ReadDir(filepath.Join(x.StateDir, "system_cfg.history")); len(es) != 0 {
		t.Errorf("history written with an unset clock: %v", es)
	}
	if _, err := x.Handle([]byte(`{"_type":"setparam","system_cfg":"a.b=d\n"}`), time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if es, _ := os.ReadDir(filepath.Join(x.StateDir, "system_cfg.history")); len(es) != 1 {
		t.Errorf("history: %v", es)
	}
}
