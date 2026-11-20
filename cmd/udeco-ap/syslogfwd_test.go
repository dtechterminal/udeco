// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/device"
)

// testSyslogKey is a fake syslog key (never a real one).
const testSyslogKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func TestUAFSyslogLine(t *testing.T) {
	for _, c := range []struct {
		in, want string
		sev      int
	}{
		{"Thu Nov 19 03:13:11 2026 authpriv.info dropbear[17719]: Exit (root) from <192.168.0.2:5>",
			"<86>Nov 19 03:13:11 deco U6-Lite,b2a7b9000001,6.7.54.15663: dropbear[17719]: Exit (root) from <192.168.0.2:5>", 6},
		{"Mon Nov  9 01:02:03 2026 daemon.err udeco-ap[5]: two  spaces kept",
			"<27>Nov  9 01:02:03 deco U6-Lite,b2a7b9000001,6.7.54.15663: udeco-ap[5]: two  spaces kept", 3},
		{"Mon Nov 9 01:02:03 2026 kern.debug kernel: [1.0] x", "<7>Nov  9 01:02:03 deco U6-Lite,b2a7b9000001,6.7.54.15663: kernel: [1.0] x", 7},
	} {
		got, sev, ok := uafSyslog(c.in, "deco", "U6-Lite,b2a7b9000001,6.7.54.15663:")
		if !ok || got != c.want || sev != c.sev {
			t.Errorf("%q:\n got %q sev %d\nwant %q sev %d", c.in, got, sev, c.want, c.sev)
		}
	}
	if got, sev, ok := uafSyslog("not a logread line", "deco", "T:"); !ok || sev != 6 || !strings.HasPrefix(got, "<14>") || !strings.HasSuffix(got, " deco T: not a logread line") {
		t.Errorf("unformatted line: %q %d %v", got, sev, ok)
	}
	if _, _, ok := uafSyslog("  ", "deco", "T:"); ok {
		t.Error("empty line sent")
	}
}

// fakeLog hands out one pipe per logread start.
type fakeLog struct{ w chan *io.PipeWriter }

func (f *fakeLog) follow(context.Context) (io.ReadCloser, error) {
	r, w := io.Pipe()
	f.w <- w
	return r, nil
}

func udpListener(t *testing.T) (*net.UDPConn, int) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, c.LocalAddr().(*net.UDPAddr).Port
}

func recvDatagram(t *testing.T, c *net.UDPConn) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 8192)
	n, err := c.Read(b)
	if err != nil {
		t.Fatalf("no datagram: %v", err)
	}
	return b[:n]
}

func syslogCfg(port int, encrypted bool) string {
	s := fmt.Sprintf("syslog.status=enabled\nsyslog.level=7\nsyslog.remote.ip=127.0.0.1\nsyslog.remote.port=%d\nsyslog.remote.status=enabled\n", port)
	if encrypted {
		s += "syslog.remote.encrypt=enabled\nsyslog.remote.key=" + testSyslogKey + "\n"
	}
	return s
}

// The controller's "this controller, encrypted" syslog: every log line at
// or above info reaches the controller's listener sealed with the device's
// syslog key and hash_id, tagged like a UAP's; debug lines are held back
// (syslog.level=7); the key never reaches the agent's log; and nothing on
// the unit is run (observe mode).
func TestSyslogEncryptedToController(t *testing.T) {
	lis, port := udpListener(t)
	fl := &fakeLog{w: make(chan *io.PipeWriter, 4)}
	h := newHarness(t, func(c *Config, o *options) { o.logFollow = fl.follow })
	h.ctl.queue(adoptReply, provisionReply(testCfg+syslogCfg(port, true)))
	h.start()
	var w *io.PipeWriter
	select {
	case w = <-fl.w:
	case <-time.After(5 * time.Second):
		t.Fatal("logread not started")
	}
	fmt.Fprintln(w, "Thu Nov 19 03:13:11 2026 daemon.debug hostapd: chatter")
	fmt.Fprintln(w, "Thu Nov 19 03:13:12 2026 daemon.notice udeco-ap[5]: hello controller")
	d := recvDatagram(t, lis)
	hash, msg, err := device.OpenSyslog(testSyslogKey, d)
	if err != nil {
		t.Fatalf("controller cannot open the datagram: %v", err)
	}
	if hash != h.a.x.S.HashID || hash == "" {
		t.Errorf("hash_id %q, inform's %q", hash, h.a.x.S.HashID)
	}
	want := "<29>Nov 19 03:13:12 deco-205 UAL6," + strings.ReplaceAll(unitMAC, ":", "") + ",6.7.54.15663: udeco-ap[5]: hello controller"
	if string(msg) != want {
		t.Errorf("message %q", msg)
	}
	// the system_cfg without syslog stops the forwarding: logread is closed
	h.ctl.queue(fmt.Sprintf(`{"_type":"setparam","cfgversion":"00000000000000c2","mgmt_cfg":"cfgversion=00000000000000c2\n","system_cfg":%q}`, testCfg))
	eventually(t, "logread closed", func() bool {
		_, err := fmt.Fprintln(w, "Thu Nov 19 03:13:13 2026 daemon.notice x: after")
		return err != nil
	})
	h.stop()
	logs := h.logs.all()
	if strings.Contains(logs, testSyslogKey) {
		t.Error("syslog key in the log")
	}
	for _, s := range []string{fmt.Sprintf("remote syslog: UniFi-encrypted to 127.0.0.1:%d (severity < 7)", port), "remote syslog: off"} {
		if !strings.Contains(logs, s) {
			t.Errorf("log lacks %q:\n%s", s, logs)
		}
	}
	for _, c := range h.rec.list() {
		t.Errorf("observe mode touched the unit: %s", c)
	}
}

// A syslog server of the user's own: plain RFC 3164 lines.
func TestSyslogPlain(t *testing.T) {
	lis, port := udpListener(t)
	fl := &fakeLog{w: make(chan *io.PipeWriter, 4)}
	h := newHarness(t, func(c *Config, o *options) { o.logFollow = fl.follow })
	h.ctl.queue(adoptReply, provisionReply(testCfg+syslogCfg(port, false)))
	h.start()
	w := <-fl.w
	fmt.Fprintln(w, "Thu Nov 19 03:13:12 2026 user.warn prog: plain line")
	d := recvDatagram(t, lis)
	h.stop()
	if !strings.HasPrefix(string(d), "<12>Nov 19 03:13:12 deco-205 UAL6,") || !strings.HasSuffix(string(d), ": prog: plain line") {
		t.Errorf("datagram %q", d)
	}
}

// The default log source runs `logread -f -l 1` and stops it on Close.
func TestLogFollowRunsLogread(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho \"args: $*\"\nexec sleep 30\n"
	if err := os.WriteFile(filepath.Join(dir, "logread"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	a := &agent{}
	rc, err := a.logFollow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(rc).ReadString('\n')
	if err != nil || line != "args: -f -l 1\n" {
		t.Errorf("logread ran with %q (%v)", line, err)
	}
	done := make(chan struct{})
	go func() { rc.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not stop logread")
	}
}
