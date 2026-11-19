// SPDX-License-Identifier: GPL-2.0-or-later

package main

// A minimal HTTP/1.1 client for the inform POST. net/http (with crypto/tls,
// HTTP/2, IDNA and the proxy code it drags in) was the largest part of the
// agent's binary, which has to fit on /tp_data next to its config. The
// inform is one plain-HTTP POST to an IPv4 literal (config.go refuses
// anything else) with a short binary body and a short binary answer, so this
// speaks exactly that: one request per connection ("Connection: close"),
// Content-Length or chunked answers (or read to EOF), a size cap, and a
// deadline. No redirects, proxies, cookies, keep-alive or TLS.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// postFunc sends body to rawURL and returns the HTTP status and the answer's
// body. A status other than 200 is not an error.
type postFunc func(ctx context.Context, rawURL string, body []byte) (status int, resp []byte, err error)

const (
	informUA       = "AirControl Agent v1.0" // what UniFi APs send
	informMaxReply = 4 << 20                 // as the agent read net/http answers before
	informMaxHead  = 16 << 10                // status line plus headers
)

// httpPoster returns the inform client with an overall timeout per request.
func httpPoster(timeout time.Duration) postFunc {
	return func(ctx context.Context, rawURL string, body []byte) (int, []byte, error) {
		return httpPost(ctx, rawURL, body, timeout)
	}
}

func httpPost(ctx context.Context, rawURL string, body []byte, timeout time.Duration) (int, []byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0, nil, err
	}
	if u.Scheme != "http" || u.Hostname() == "" || u.User != nil {
		return 0, nil, fmt.Errorf("inform url %q: only http://host[:port]/path is supported", rawURL)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "80")
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	// a cancelled ctx (SIGTERM) unblocks a read or write at once
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	head := "POST " + path + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"User-Agent: " + informUA + "\r\n" +
		"Content-Type: application/x-binary\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write(append([]byte(head), body...)); err != nil {
		return 0, nil, ctxErr(ctx, err)
	}
	status, resp, err := readResponse(bufio.NewReader(conn))
	return status, resp, ctxErr(ctx, err)
}

// ctxErr prefers the context's reason over the I/O error it caused. The
// connection's deadline is the context's, and either timer may fire first:
// a timeout at or after the context's deadline is the context's too.
func ctxErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	var ne net.Error
	if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) && errors.As(err, &ne) && ne.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}

var errReplyTooLarge = fmt.Errorf("inform reply larger than %d bytes", informMaxReply)

// readResponse reads one HTTP/1.x response to a POST.
func readResponse(r *bufio.Reader) (int, []byte, error) {
	budget := informMaxHead
	line := func() (string, error) {
		s, err := readLine(r, &budget)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return s, err
	}
	var status int
	for {
		sl, err := line()
		if err != nil {
			return 0, nil, err
		}
		proto, rest, _ := strings.Cut(sl, " ")
		code, _, _ := strings.Cut(rest, " ")
		status, err = strconv.Atoi(code)
		if !strings.HasPrefix(proto, "HTTP/1.") || err != nil || len(code) != 3 {
			return 0, nil, fmt.Errorf("inform reply: bad status line %q", sl)
		}
		length, chunked := int64(-1), false
		for {
			h, err := line()
			if err != nil {
				return 0, nil, err
			}
			if h == "" {
				break
			}
			k, v, ok := strings.Cut(h, ":")
			if !ok {
				return 0, nil, fmt.Errorf("inform reply: bad header line %q", h)
			}
			v = strings.TrimSpace(v)
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "content-length":
				n, err := strconv.ParseInt(v, 10, 64)
				if err != nil || n < 0 || (length >= 0 && n != length) {
					return 0, nil, fmt.Errorf("inform reply: bad Content-Length %q", v)
				}
				length = n
			case "transfer-encoding":
				if !strings.EqualFold(v, "chunked") {
					return 0, nil, fmt.Errorf("inform reply: transfer encoding %q", v)
				}
				chunked = true
			}
		}
		if status >= 100 && status < 200 {
			continue // 100 Continue and the like: the real answer follows
		}
		var body []byte
		switch {
		case status == 204 || status == 304:
		case chunked:
			body, err = readChunked(r)
		case length >= 0:
			if length > informMaxReply {
				return status, nil, errReplyTooLarge
			}
			body = make([]byte, length)
			_, err = io.ReadFull(r, body)
		default: // no length: the server closes the connection at the end
			body, err = io.ReadAll(io.LimitReader(r, informMaxReply+1))
			if err == nil && len(body) > informMaxReply {
				err = errReplyTooLarge
			}
		}
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return status, body, err
	}
}

var errHeadTooLarge = errors.New("inform reply: header too large")

// readLine reads one line (without its CR LF) and takes its length from
// *budget. It never buffers more than the budget left: a peer that sends an
// endless line without a newline costs at most that, not all the RAM.
func readLine(r *bufio.Reader, budget *int) (string, error) {
	var b []byte
	for {
		frag, err := r.ReadSlice('\n')
		*budget -= len(frag)
		if *budget < 0 {
			return "", errHeadTooLarge
		}
		b = append(b, frag...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
}

// chunkLineMax bounds one chunk-size line (with its extensions).
const chunkLineMax = 4 << 10

// readChunked reads a chunked body (trailers are skipped). Each chunk-size
// line is bounded, and the trailers share one header budget.
func readChunked(r *bufio.Reader) ([]byte, error) {
	var body []byte
	trailers := informMaxHead
	for {
		lineBudget := chunkLineMax
		s, err := readLine(r, &lineBudget)
		if err != nil {
			return nil, err
		}
		sz, _, _ := strings.Cut(strings.TrimSpace(s), ";")
		n, err := strconv.ParseInt(sz, 16, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("inform reply: bad chunk size %q", strings.TrimSpace(s))
		}
		if int64(len(body))+n > informMaxReply {
			return nil, errReplyTooLarge
		}
		if n == 0 {
			for { // trailers up to the empty line
				t, err := readLine(r, &trailers)
				if err != nil {
					return nil, err
				}
				if t == "" {
					return body, nil
				}
			}
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return nil, err
		}
		body = append(body, chunk...)
		lineBudget = 2
		if crlf, err := readLine(r, &lineBudget); err != nil || crlf != "" {
			return nil, errors.New("inform reply: chunk not followed by CRLF")
		}
	}
}
