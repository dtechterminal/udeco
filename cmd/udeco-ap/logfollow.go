// SPDX-License-Identifier: GPL-2.0-or-later

package main

// The log source for remote syslog on a unit without logread (platform
// jio-mtk). The JCOW414's syslogd is BusyBox 1.17 run as `syslogd -n -m 0`:
// no shared-memory buffer (-C), no remote target of its own (-R), so the
// only place its messages land is the file /var/log/messages (rotated by
// syslogd itself to messages.0 at -s, 200 kB by default). The agent follows
// that file like `tail -F` and, because its own log goes to stderr there
// (start.sh appends it to /tmp/udeco-bin/agent.log), merges its own lines
// in. syslogd is left exactly as init runs it.
//
// The kernel log is not merged: no klogd runs, and the ring is also where
// mtkwifi reads `iwpriv show stainfo` tables from (collector.go), which
// would flood the forwarding.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// jioLogPath: where the JCOW414's syslogd writes (/var -> /tmp/var).
	jioLogPath = "/var/log/messages"
	// logPoll: how often the followed file is checked for new lines and
	// for rotation.
	logPoll = time.Second
	// logLineMax: a longer unterminated tail is passed on as a line.
	logLineMax = 8000
)

// followFile streams the lines appended to path from now on, across
// rotation (the file renamed away and a new one created: what is left in
// the old file is read to its end first, then the new file from its start)
// and truncation (read again from the start). A missing file is waited for.
// extra lines (the agent's own) are merged in between whole file lines.
// The stream ends when ctx ends or the reader is closed.
func followFile(ctx context.Context, path string, poll time.Duration, extra <-chan string) io.ReadCloser {
	if poll <= 0 {
		poll = logPoll
	}
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		defer cancel()
		f := &fileFollower{path: path, w: pw}
		err := f.run(ctx, poll, extra)
		f.close()
		pw.CloseWithError(err)
	}()
	return &followStream{PipeReader: pr, cancel: cancel}
}

type followStream struct {
	*io.PipeReader
	cancel context.CancelFunc
}

func (s *followStream) Close() error {
	s.cancel()
	return s.PipeReader.Close()
}

type fileFollower struct {
	path string
	w    io.Writer
	f    *os.File
	fi   os.FileInfo // of f when it was opened
	off  int64       // bytes of f read so far
	part []byte      // an unterminated last line
}

func (ff *fileFollower) close() {
	if ff.f != nil {
		ff.f.Close()
		ff.f = nil
	}
}

func (ff *fileFollower) run(ctx context.Context, poll time.Duration, extra <-chan string) error {
	ff.open(true) // start at the end: what is already there is not resent
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case l := <-extra:
			if _, err := io.WriteString(ff.w, l+"\n"); err != nil {
				return err
			}
		case <-t.C:
			if err := ff.check(); err != nil {
				return err
			}
		}
	}
}

// open opens path; atEnd starts at its current end, else at its start.
func (ff *fileFollower) open(atEnd bool) {
	f, err := os.Open(ff.path)
	if err != nil {
		return
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return
	}
	ff.f, ff.fi, ff.off, ff.part = f, fi, 0, nil
	if atEnd {
		ff.off, _ = f.Seek(0, io.SeekEnd)
	}
}

// check passes on what was appended and follows a rotation or truncation.
func (ff *fileFollower) check() error {
	if ff.f == nil {
		ff.open(false) // created after the start (or after a rotation): all of it is new
		if ff.f == nil {
			return nil
		}
	}
	if err := ff.drain(); err != nil {
		return err
	}
	cur, err := os.Stat(ff.path)
	switch {
	case err != nil && errors.Is(err, os.ErrNotExist):
		return nil // renamed away, the new file not created yet: keep the old one
	case err != nil:
		return nil
	case !os.SameFile(cur, ff.fi):
		// rotated: read the old file to its end once more (syslogd may
		// have written to it between the drain above and its rename); a
		// line it left unterminated is passed on as it is
		if err := ff.drain(); err != nil {
			return err
		}
		if err := ff.flushPart(); err != nil {
			return err
		}
		ff.close()
		ff.open(false)
		if ff.f != nil {
			return ff.drain()
		}
	case cur.Size() < ff.off:
		// truncated in place: read again from the start
		if err := ff.flushPart(); err != nil {
			return err
		}
		ff.off, _ = ff.f.Seek(0, io.SeekStart)
		return ff.drain()
	}
	return nil
}

// drain reads f to its current end and writes the whole lines on.
func (ff *fileFollower) drain() error {
	buf := make([]byte, 32<<10)
	for {
		n, err := ff.f.ReadAt(buf, ff.off)
		if n > 0 {
			ff.off += int64(n)
			if werr := ff.lines(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil || n == 0 {
			return nil // io.EOF: everything there is was read
		}
	}
}

func (ff *fileFollower) lines(b []byte) error {
	ff.part = append(ff.part, b...)
	i := bytes.LastIndexByte(ff.part, '\n')
	if i < 0 {
		if len(ff.part) > logLineMax {
			return ff.flushPart()
		}
		return nil
	}
	if _, err := ff.w.Write(ff.part[:i+1]); err != nil {
		return err
	}
	ff.part = append(ff.part[:0], ff.part[i+1:]...)
	return nil
}

func (ff *fileFollower) flushPart() error {
	if len(ff.part) == 0 {
		return nil
	}
	_, err := ff.w.Write(append(ff.part, '\n'))
	ff.part = nil
	return err
}

// logTap hands the agent's own log lines to a running log follower
// (platform jio-mtk, log logStderr); without one it costs a mutex.
type logTap struct {
	mu sync.Mutex
	ch chan string
}

// attach starts handing lines out; detach stops it.
func (t *logTap) attach() <-chan string {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ch = make(chan string, 256)
	return t.ch
}

func (t *logTap) detach(ch <-chan string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ch != nil && (<-chan string)(t.ch) == ch {
		t.ch = nil
	}
}

// send passes one formatted log line on, in the file's format, without
// ever blocking the caller (a full queue drops the line).
func (t *logTap) send(now time.Time, format string, args ...any) {
	t.mu.Lock()
	ch := t.ch
	t.mu.Unlock()
	if ch == nil {
		return
	}
	msg := strings.ReplaceAll(fmt.Sprintf(format, args...), "\n", " ")
	l := fmt.Sprintf("%s udeco daemon.info udeco-ap[%d]: %s", now.Format(time.Stamp), os.Getpid(), msg)
	select {
	case ch <- l:
	default:
	}
}
