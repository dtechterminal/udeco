// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/inform"
)

// The waits cmd/uow, cmd/udeco and cmd/udeco-ap each computed with their
// own copy of the expression.
func TestInformBackoff(t *testing.T) {
	s := time.Second
	for _, c := range []struct {
		interval time.Duration
		errs     int
		want     time.Duration
	}{
		{10 * s, 1, 10 * s}, {10 * s, 2, 20 * s}, {10 * s, 3, 40 * s}, {10 * s, 4, 60 * s}, {10 * s, 5, 60 * s}, {10 * s, 1000, 60 * s},
		{s, 1, 5 * s}, {s, 2, 10 * s}, {s, 3, 20 * s}, {s, 4, 40 * s}, {s, 5, 60 * s}, {s, 6, 60 * s},
		{0, 1, 5 * s}, {30 * s, 1, 30 * s}, {30 * s, 2, 60 * s}, {2 * time.Minute, 1, 60 * s},
		{10 * s, 0, 10 * s}, {10 * s, -3, 10 * s}, // not a bad answer: no backing off
	} {
		if got := InformBackoff(c.interval, c.errs); got != c.want {
			t.Errorf("InformBackoff(%s, %d) = %s, want %s", c.interval, c.errs, got, c.want)
		}
		if c.errs > 0 { // the expression as the three loops had it
			if old := min(max(c.interval, 5*s)*time.Duration(1<<min(c.errs-1, 4)), time.Minute); old != c.want {
				t.Errorf("the loops' expression gives %s for (%s, %d), the table says %s", old, c.interval, c.errs, c.want)
			}
		}
	}
	if DefaultInformInterval != 10*s || MinInformWait != s || ImmediateInformWait != 500*time.Millisecond {
		t.Errorf("timing %s %s %s", DefaultInformInterval, MinInformWait, ImmediateInformWait)
	}
}

// reply seals a controller answer for the test session's MAC.
func reply(t *testing.T, x *Session, key, js string) []byte {
	t.Helper()
	pkt, err := inform.Encode(x.Dev.MAC, key, inform.CBC, []byte(js), nil)
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

// InformOnce, case by case as cmd/uow's and cmd/udeco's informOnce had it:
// what counts as a bad answer, what is logged, when the state is saved.
func TestInformOnce(t *testing.T) {
	adopted := func(x *Session) { x.S.Key, x.S.Adopted = newKey, true }
	for _, c := range []struct {
		name   string
		setup  func(x *Session)
		status int
		body   func(t *testing.T, x *Session) []byte
		err    error

		ok       bool
		posts    int    // 1 unless the inform never left
		log      string // "" = nothing logged; else a line that must be there
		logLines int
		check    func(t *testing.T, x *Session, o Outcome, statePath string)
	}{
		{name: "payload fails", setup: func(x *Session) { x.S.InformURL = "http://[fd00::1]:8080/inform" },
			log: "payload: u7pg2: inform_url host must be IPv4", logLines: 1},
		{name: "encode fails", setup: func(x *Session) { x.S.Key = "not hex" }, log: "encode: ", logLines: 1},
		{name: "POST fails", err: errors.New("connection refused"), posts: 1, log: "POST: connection refused", logLines: 1},
		{name: "404 while pending", status: 404, posts: 1, ok: true},
		{name: "404 while adopted", setup: adopted, status: 404, posts: 1, log: "HTTP 404 while adopted (forgotten?)", logLines: 1},
		{name: "another status", status: 500, body: func(*testing.T, *Session) []byte { return []byte("abc") }, posts: 1,
			log: "HTTP 500 (3 bytes)", logLines: 1},
		{name: "empty answer", status: 200, posts: 1, ok: true},
		{name: "noop is not logged", status: 200, posts: 1, ok: true,
			body: func(t *testing.T, x *Session) []byte {
				return reply(t, x, inform.DefaultKeyHex, `{"_type":"noop","interval":7}`)
			},
			check: func(t *testing.T, x *Session, o Outcome, statePath string) {
				if o.Interval != 7*time.Second || o.Immediate {
					t.Errorf("outcome %+v", o)
				}
				if _, err := os.Stat(statePath); err == nil {
					t.Error("state saved though nothing changed")
				}
			}},
		{name: "an immediate noop is logged", status: 200, posts: 1, ok: true, log: "noop interval=7 immediate=1", logLines: 1,
			body: func(t *testing.T, x *Session) []byte {
				return reply(t, x, inform.DefaultKeyHex, `{"_type":"noop","interval":7,"immediate":1}`)
			}},
		{name: "adoption is logged and saved", status: 200, posts: 1, ok: true, log: "ADOPTED: new authkey stored", logLines: 1,
			body: func(t *testing.T, x *Session) []byte {
				return reply(t, x, inform.DefaultKeyHex, `{"_type":"setparam","mgmt_cfg":"cfgversion=1\nauthkey=`+newKey+`\n"}`)
			},
			check: func(t *testing.T, x *Session, o Outcome, statePath string) {
				st, found, err := Load(statePath)
				if err != nil || !found || !st.Adopted || st.Key != newKey || !o.Changed {
					t.Errorf("saved state %+v found=%v err=%v changed=%v", st.Adopted, found, err, o.Changed)
				}
			}},
		{name: "answer in the session's key", setup: adopted, status: 200, posts: 1, ok: true, log: "locate on", logLines: 1,
			body: func(t *testing.T, x *Session) []byte {
				return reply(t, x, newKey, `{"_type":"cmd","cmd":"set-locate"}`)
			},
			check: func(t *testing.T, x *Session, o Outcome, _ string) {
				if len(o.Actions) != 1 || o.Actions[0] != Action(ActLocate, ArgOn) {
					t.Errorf("actions %q", o.Actions)
				}
			}},
		{name: "answer in the factory key while adopted: second try", setup: adopted, status: 200, posts: 1, ok: true,
			log: "setdefault: back to the factory key", logLines: 1,
			body: func(t *testing.T, x *Session) []byte {
				return reply(t, x, inform.DefaultKeyHex, `{"_type":"setdefault"}`)
			},
			check: func(t *testing.T, x *Session, o Outcome, _ string) {
				if !o.Reset || x.S.Adopted || x.S.Key != inform.DefaultKeyHex {
					t.Errorf("outcome %+v, adopted %v", o, x.S.Adopted)
				}
			}},
		{name: "answer in a key the session does not hold", setup: adopted, status: 200, posts: 1,
			log: "reply did not decode: ", logLines: 1,
			body: func(t *testing.T, x *Session) []byte {
				return reply(t, x, strings.Repeat("ab", 16), `{"_type":"setdefault"}`)
			},
			check: func(t *testing.T, x *Session, o Outcome, _ string) {
				if !x.S.Adopted || o.Reset {
					t.Error("a reply in a foreign key was handled")
				}
			}},
		{name: "garbage", status: 200, posts: 1, log: "reply did not decode: ", logLines: 1,
			body: func(*testing.T, *Session) []byte { return []byte("<html>busy</html>") }},
		{name: "not JSON", status: 200, posts: 1, log: "reply is not JSON: ", logLines: 1,
			body: func(t *testing.T, x *Session) []byte { return reply(t, x, inform.DefaultKeyHex, `no json`) }},
		{name: "state cannot be saved: said, and still a good answer", status: 200, posts: 1, ok: true, log: "saving state: ", logLines: 2,
			setup: func(x *Session) { x.StateDir = filepath.Join(x.StateDir, "gone") },
			body: func(t *testing.T, x *Session) []byte {
				return reply(t, x, inform.DefaultKeyHex, `{"_type":"cmd","cmd":"set-locate"}`)
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newSession(t)
			if c.setup != nil {
				c.setup(x)
			}
			statePath := filepath.Join(x.StateDir, StateFile)
			var body []byte
			if c.body != nil {
				body = c.body(t, x)
			}
			posts := 0
			post := func(url string, pkt []byte) (int, []byte, error) {
				posts++
				if url != x.S.InformURL {
					t.Errorf("posted to %q, want %q", url, x.S.InformURL)
				}
				// what was posted is this session's inform
				if hdr, plain, err := inform.Decode(pkt, x.S.Key); err != nil || hdr.MAC.String() != x.Dev.MAC.String() || !strings.Contains(string(plain), `"inform_url"`) {
					t.Errorf("posted packet: %v", err)
				}
				return c.status, body, c.err
			}
			var lines []string
			o, ok := InformOnce(x, post, statePath, func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) })
			if ok != c.ok || posts != c.posts {
				t.Errorf("ok=%v posts=%d, want %v %d", ok, posts, c.ok, c.posts)
			}
			all := strings.Join(lines, "\n")
			if len(lines) != c.logLines || !strings.Contains(all, c.log) {
				t.Errorf("log (%d lines, want %d with %q):\n%s", len(lines), c.logLines, c.log, all)
			}
			if strings.Contains(all, newKey) || strings.Contains(all, inform.DefaultKeyHex) {
				t.Errorf("a key in the log:\n%s", all)
			}
			if c.check != nil {
				c.check(t, x, o, statePath)
			}
		})
	}
}
