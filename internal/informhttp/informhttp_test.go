// SPDX-License-Identifier: GPL-2.0-or-later

package informhttp

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/inform"
)

// What cmd/udeco and upstream's uow put on the wire, as before they shared this:
// a POST of the packet as application/x-binary with Go's own User-Agent,
// and the answer read up to 4 MiB whatever the status.
func TestPoster(t *testing.T) {
	type seen struct {
		method, path, ctype, ua string
		body                    []byte
	}
	var got seen
	status, answer := 200, []byte("answer")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = seen{r.Method, r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("User-Agent"), b}
		w.WriteHeader(status)
		w.Write(answer)
	}))
	defer srv.Close()
	post := Poster(&http.Client{Timeout: 10 * time.Second})

	pkt := []byte{'T', 'N', 'B', 'U', 0, 1, 2, 3}
	st, body, err := post(srv.URL+"/inform", pkt)
	if err != nil || st != 200 || string(body) != "answer" {
		t.Fatalf("post: %d %q %v", st, body, err)
	}
	if got.method != "POST" || got.path != "/inform" || got.ctype != "application/x-binary" || !bytes.Equal(got.body, pkt) {
		t.Errorf("request %+v", got)
	}
	if got.ctype != inform.ContentType {
		t.Errorf("Content-Type %q is not inform.ContentType", got.ctype)
	}
	// only the AP agent claims to be a UniFi AP's client
	if got.ua == inform.UserAgent || !strings.HasPrefix(got.ua, "Go-http-client/") {
		t.Errorf("User-Agent %q, want net/http's own", got.ua)
	}

	// a status other than 200 is an answer, not an error
	status, answer = 404, []byte("no such device")
	if st, body, err := post(srv.URL+"/inform", pkt); err != nil || st != 404 || string(body) != "no such device" {
		t.Errorf("404: %d %q %v", st, body, err)
	}

	// an answer larger than inform.MaxReply is cut there
	status, answer = 200, bytes.Repeat([]byte("x"), inform.MaxReply+100)
	if st, body, err := post(srv.URL+"/inform", pkt); err != nil || st != 200 || len(body) != inform.MaxReply {
		t.Errorf("large answer: %d, %d bytes, %v", st, len(body), err)
	}
	if inform.MaxReply != 4<<20 {
		t.Errorf("inform.MaxReply = %d", inform.MaxReply)
	}

	srv.Close()
	if _, _, err := post(srv.URL+"/inform", pkt); err == nil || !strings.HasPrefix(err.Error(), `Post "`+srv.URL+`/inform": `) {
		t.Errorf("closed server: %v", err)
	}
	// a URL net/http cannot use is an error, not a crash
	if _, _, err := post("http://192.168.1.1:port/inform", pkt); err == nil {
		t.Error("bad URL posted")
	}
}
