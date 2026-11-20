// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/device"
)

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// lineReader reads the follower's lines with a deadline per line.
type lineReader struct {
	t     *testing.T
	lines chan string
}

func newLineReader(t *testing.T, rc io.Reader) *lineReader {
	lr := &lineReader{t: t, lines: make(chan string, 64)}
	go func() {
		sc := bufio.NewScanner(rc)
		for sc.Scan() {
			lr.lines <- sc.Text()
		}
		close(lr.lines)
	}()
	return lr
}

func (lr *lineReader) next() string {
	lr.t.Helper()
	select {
	case l, ok := <-lr.lines:
		if !ok {
			lr.t.Fatal("follower ended")
		}
		return l
	case <-time.After(5 * time.Second):
		lr.t.Fatal("no line from the follower")
	}
	return ""
}

func (lr *lineReader) none(d time.Duration) {
	lr.t.Helper()
	select {
	case l := <-lr.lines:
		lr.t.Fatalf("unexpected line %q", l)
	case <-time.After(d):
	}
}

// The follower starts at the end of the file (old lines are not resent),
// passes only whole lines, follows BusyBox syslogd's rotation (messages
// renamed to messages.0, a new messages created) without losing the lines
// written to the old file after the last read, then a truncation in place.
func TestFollowFileRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "messages")
	appendFile(t, path, "Nov 19 10:00:00 RIL user.info old: before the start\n")
	extra := make(chan string, 4)
	rc := followFile(context.Background(), path, 5*time.Millisecond, extra)
	defer rc.Close()
	lr := newLineReader(t, rc)
	lr.none(30 * time.Millisecond)

	appendFile(t, path, "line 1\nline 2 is ")
	if got := lr.next(); got != "line 1" {
		t.Fatalf("got %q", got)
	}
	lr.none(30 * time.Millisecond) // a half line waits
	appendFile(t, path, "complete\n")
	if got := lr.next(); got != "line 2 is complete" {
		t.Fatalf("got %q", got)
	}

	extra <- "Nov 19 10:00:01 udeco daemon.info udeco-ap[1]: own line"
	if got := lr.next(); !strings.HasSuffix(got, "own line") {
		t.Fatalf("own line: %q", got)
	}

	// rotation: syslogd renames the file, writes once more to it (as
	// far as the follower can tell), then starts a new one
	if err := os.Rename(path, path+".0"); err != nil {
		t.Fatal(err)
	}
	appendFile(t, path+".0", "last old line\n")
	appendFile(t, path, "first new line\n")
	if got := lr.next(); got != "last old line" {
		t.Fatalf("after rotation got %q, want the old file's last line first", got)
	}
	if got := lr.next(); got != "first new line" {
		t.Fatalf("after rotation got %q", got)
	}

	// truncation in place
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	lr.none(30 * time.Millisecond)
	appendFile(t, path, "after truncate\n")
	if got := lr.next(); got != "after truncate" {
		t.Fatalf("after truncation got %q", got)
	}
}

// A file that does not exist yet is waited for and then read from its start.
func TestFollowFileCreatedLater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages")
	ctx, cancel := context.WithCancel(context.Background())
	rc := followFile(ctx, path, 5*time.Millisecond, nil)
	lr := newLineReader(t, rc)
	lr.none(30 * time.Millisecond)
	appendFile(t, path, "hello\n")
	if got := lr.next(); got != "hello" {
		t.Fatalf("got %q", got)
	}
	cancel()
	select {
	case _, ok := <-lr.lines:
		if ok {
			t.Fatal("line after cancel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follower did not end with its context")
	}
}

func TestUAFSyslogBusyBoxFileLine(t *testing.T) {
	got, sev, ok := uafSyslog("Nov 19 17:34:44 reliance auth.info login[27865]: root login on 'pts/0'", "garage", "U7LT,b4a7c617e3f3,6.8.5.15602:")
	want := "<38>Nov 19 17:34:44 garage U7LT,b4a7c617e3f3,6.8.5.15602: login[27865]: root login on 'pts/0'"
	if !ok || got != want || sev != 6 {
		t.Errorf("got %q sev %d, want %q", got, sev, want)
	}
	got, sev, _ = uafSyslog("Jun 27 00:01:15 RIL local3.notice TCSysLog wlan[173]: x  y", "g", "T:")
	if got != "<157>Jun 27 00:01:15 g T: TCSysLog wlan[173]: x  y" || sev != 5 {
		t.Errorf("got %q sev %d", got, sev)
	}
}

// Platform jio-mtk: no logread; remote syslog (here UniFi-encrypted to the
// controller) follows syslogd's /var/log/messages from its end and merges
// the agent's own log lines in.
func TestSyslogJioFollowsMessages(t *testing.T) {
	lis, port := udpListener(t)
	var msgs string
	h := newHarness(t, func(c *Config, o *options) {
		c.Platform, c.Model = PlatformJio, "U7LT"
		o.t.logPoll = 5 * time.Millisecond
		msgs = filepath.Join(o.root, jioLogPath)
	})
	for _, f := range jioGateFiles {
		p := filepath.Join(h.root, f)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, nil, 0o644)
	}
	os.MkdirAll(filepath.Dir(msgs), 0o755)
	appendFile(t, msgs, "Jun 27 00:01:00 RIL syslog.info syslogd started: BusyBox v1.17.4\n")
	h.ctl.queue(adoptReply, provisionReply(testCfg+syslogCfg(port, true)))
	h.start()
	open := func() string {
		t.Helper()
		hash, msg, err := device.OpenSyslog(testSyslogKey, recvDatagram(t, lis))
		if err != nil || hash == "" {
			t.Fatalf("controller cannot open the datagram: %v (hash %q)", err, hash)
		}
		return string(msg)
	}
	// the line is appended until the follower has picked the file up (it
	// starts at the file's end, whenever forwarding starts)
	eventually(t, "a forwarded file line", func() bool {
		appendFile(t, msgs, "Nov 19 17:34:44 RIL daemon.notice prog[7]: from the file\n")
		lis.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		b := make([]byte, 8192)
		n, err := lis.Read(b)
		if err != nil {
			return false
		}
		_, m, err := device.OpenSyslog(testSyslogKey, b[:n])
		return err == nil && strings.HasSuffix(string(m), ": prog[7]: from the file")
	})
	drain(lis)
	h.a.logf("agent says %s", "hello")
	for {
		m := open() // fails the test when nothing more arrives
		if !strings.HasSuffix(m, ": agent says hello") {
			continue // another of the agent's own lines
		}
		if !strings.Contains(m, " udeco-ap[") || !strings.HasPrefix(m, "<30>") {
			t.Errorf("own line forwarded as %q", m)
		}
		break
	}
	if strings.Contains(h.logs.all(), "not forwarded on platform") {
		t.Error("jio still skips remote syslog")
	}
	h.stop()
	if strings.Contains(h.logs.all(), testSyslogKey) {
		t.Error("syslog key in the log")
	}
}

// drain discards the datagrams already queued on c.
func drain(c *net.UDPConn) {
	b := make([]byte, 8192)
	for {
		c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		if _, err := c.Read(b); err != nil {
			return
		}
	}
}
