// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/inform"
)

// The minimal client against Go's own HTTP server: the request it sends is
// a well-formed POST (method, path, Host, Content-Type, Content-Length,
// body), and it reads Content-Length, chunked and 404 answers.
func TestHTTPPostAgainstServer(t *testing.T) {
	var got struct {
		method, path, host, ctype, ua string
		length                        int64
		body                          []byte
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path, got.host = r.Method, r.URL.RequestURI(), r.Host
		got.ctype, got.ua, got.length = r.Header.Get("Content-Type"), r.UserAgent(), r.ContentLength
		got.body, _ = io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/inform":
			w.Header().Set("Content-Length", "5")
			w.Write([]byte("hello"))
		case "/chunked":
			w.Write([]byte("abc"))
			w.(http.Flusher).Flush() // no Content-Length: chunked
			w.Write([]byte("def"))
		case "/empty":
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	body := []byte("TNBU\x00\x01binary\r\n\r\npayload")
	st, resp, err := httpPost(context.Background(), srv.URL+"/inform?x=1", body, 5*time.Second)
	if err != nil || st != 200 || string(resp) != "hello" {
		t.Fatalf("inform: %d %q %v", st, resp, err)
	}
	if got.method != "POST" || got.path != "/inform?x=1" || got.host != strings.TrimPrefix(srv.URL, "http://") ||
		got.ctype != "application/x-binary" || got.ua != "AirControl Agent v1.0" || got.length != int64(len(body)) || !bytes.Equal(got.body, body) {
		t.Errorf("request %+v", got)
	}
	// the texts on the wire are the shared constants
	if got.ctype != inform.ContentType || got.ua != inform.UserAgent || inform.MaxReply != 4<<20 {
		t.Errorf("inform.ContentType %q, inform.UserAgent %q, inform.MaxReply %d", inform.ContentType, inform.UserAgent, inform.MaxReply)
	}
	if st, resp, err := httpPost(context.Background(), srv.URL+"/chunked", nil, 5*time.Second); err != nil || st != 200 || string(resp) != "abcdef" {
		t.Errorf("chunked: %d %q %v", st, resp, err)
	}
	if st, resp, err := httpPost(context.Background(), srv.URL+"/empty", nil, 5*time.Second); err != nil || st != 200 || len(resp) != 0 {
		t.Errorf("empty: %d %q %v", st, resp, err)
	}
	if st, _, err := httpPost(context.Background(), srv.URL+"/nope", nil, 5*time.Second); err != nil || st != 404 {
		t.Errorf("404: %d %v", st, err)
	}
}

// rawServer answers every connection with resp (after reading the request
// head) and closes it; hang keeps the connection open without answering.
func rawServer(t *testing.T, resp string, hang bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" {
						break
					}
				}
				if hang {
					time.Sleep(5 * time.Second)
					return
				}
				c.Write([]byte(resp))
			}()
		}
	}()
	return "http://" + ln.Addr().String() + "/inform"
}

func TestHTTPPostResponses(t *testing.T) {
	big := strings.Repeat("x", inform.MaxReply+1)
	for _, c := range []struct {
		name, resp string
		status     int
		body       string
		err        bool
	}{
		{"read to EOF", "HTTP/1.0 200 OK\r\n\r\nall of it", 200, "all of it", false},
		{"100 continue first", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 200, "ok", false},
		{"chunk extension and trailer", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\nX-T: 1\r\n\r\n", 200, "abc", false},
		{"bad header case", "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok", 200, "ok", false},
		{"truncated body", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", 0, "", true},
		{"bad status line", "SSH-2.0-dropbear\r\n\r\n", 0, "", true},
		{"conflicting lengths", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok", 0, "", true},
		{"unknown encoding", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", 0, "", true},
		{"too large by length", "HTTP/1.1 200 OK\r\nContent-Length: 9999999999\r\n\r\n", 0, "", true},
		{"too large to EOF", "HTTP/1.1 200 OK\r\n\r\n" + big, 0, "", true},
		{"too large chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n500000\r\n", 0, "", true},
		{"header flood", "HTTP/1.1 200 OK\r\n" + strings.Repeat("X: y\r\n", 5000) + "\r\n", 0, "", true},
		{"no answer", "", 0, "", true},
	} {
		st, body, err := httpPost(context.Background(), rawServer(t, c.resp, false), []byte("x"), 5*time.Second)
		if (err != nil) != c.err || (!c.err && (st != c.status || string(body) != c.body)) {
			t.Errorf("%s: status %d body %.20q err %v", c.name, st, body, err)
		}
	}
}

// A controller that accepts but never answers costs at most the timeout;
// a cancelled context (SIGTERM) ends the POST at once.
func TestHTTPPostTimeoutAndCancel(t *testing.T) {
	u := rawServer(t, "", true)
	start := time.Now()
	if _, _, err := httpPost(context.Background(), u, nil, 100*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("timeout: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("timeout took %s", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start = time.Now()
	if _, _, err := httpPost(ctx, u, nil, time.Minute); !errors.Is(err, context.Canceled) {
		t.Errorf("cancel: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("cancel took %s", d)
	}
}

func TestHTTPPostRefusesOtherURLs(t *testing.T) {
	for _, u := range []string{"https://127.0.0.1:8443/inform", "ftp://127.0.0.1/x", "http:///inform", "http://user:pw@127.0.0.1/inform", "::"} {
		if _, _, err := httpPost(context.Background(), u, nil, time.Second); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

// endlessReader returns n bytes of fill (no newline) and counts what was read.
type endlessReader struct {
	n, read int
	fill    byte
}

func (e *endlessReader) Read(p []byte) (int, error) {
	if e.read >= e.n {
		return 0, io.EOF
	}
	k := min(len(p), e.n-e.read)
	for i := range p[:k] {
		p[i] = e.fill
	}
	e.read += k
	return k, nil
}

// A peer that answers with a line that never ends (status line, header,
// chunk size or trailer) must cost the header budget, not all the RAM: the
// reader stops at the budget instead of buffering the whole line first.
func TestHTTPPostEndlessLineIsBounded(t *testing.T) {
	const flood = 64 << 20
	for _, c := range []struct{ name, prefix string }{
		{"status line", ""},
		{"header", "HTTP/1.1 200 OK\r\nX-A: "},
		{"chunk size", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"},
		{"trailer", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-T: "},
	} {
		e := &endlessReader{n: flood, fill: '1'}
		r := bufio.NewReader(io.MultiReader(strings.NewReader(c.prefix), e))
		if _, _, err := readResponse(r); err == nil {
			t.Errorf("%s: endless line accepted", c.name)
		}
		if e.read > 1<<20 {
			t.Errorf("%s: read %d bytes of an endless line before giving up (want at most the header budget)", c.name, e.read)
		}
	}
}
