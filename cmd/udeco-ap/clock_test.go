// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// sntpServer answers SNTP on 127.0.0.1 with its clock shifted by off.
func sntpServer(t *testing.T, off time.Duration, stratum byte) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		b := make([]byte, 128)
		for {
			n, from, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			if n < 48 {
				continue
			}
			r := make([]byte, 48)
			r[0] = 0<<6 | 4<<3 | 4
			r[1] = stratum
			copy(r[24:32], b[40:48]) // originate = the client's transmit
			now := ntpTime(time.Now().Add(off))
			binary.BigEndian.PutUint64(r[32:], now)
			binary.BigEndian.PutUint64(r[40:], now)
			c.WriteToUDP(r, from)
		}
	}()
	return c.LocalAddr().String()
}

// sntpVia is sntpOffset against a test server on a random port.
func sntpVia(addr string) func(context.Context, string, func() time.Time) (time.Duration, error) {
	return func(ctx context.Context, _ string, now func() time.Time) (time.Duration, error) {
		host, port, _ := net.SplitHostPort(addr)
		return sntpOffsetPort(ctx, host, port, now)
	}
}

func TestSNTPOffset(t *testing.T) {
	addr := sntpServer(t, 58*time.Second, 2)
	off, err := sntpVia(addr)(context.Background(), "", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if d := off - 58*time.Second; d.Abs() > 200*time.Millisecond {
		t.Errorf("offset %s, want about 58s", off)
	}
	bad := sntpServer(t, 0, 0) // kiss-o'-death / unsynchronised
	if _, err := sntpVia(bad)(context.Background(), "", time.Now); err == nil || !strings.Contains(err.Error(), "stratum 0") {
		t.Errorf("stratum 0 answer accepted: %v", err)
	}
}

func TestNTPTimeRoundTrip(t *testing.T) {
	now := time.Date(2026, 11, 19, 17, 34, 44, 123456789, time.UTC)
	if got := fromNTP(ntpTime(now)); got.Sub(now).Abs() > time.Microsecond {
		t.Errorf("round trip %s -> %s", now, got)
	}
}

func TestControllerOffset(t *testing.T) {
	t1 := time.Now()
	t4 := t1.Add(100 * time.Millisecond)
	srv := t1.Add(50*time.Millisecond + 58*time.Second)
	for _, js := range []string{
		`{"_type":"noop","interval":10,"server_time_in_utc":"` + itoa(srv.UnixMilli()) + `"}`,
		`{"_type":"noop","server_time_in_utc":` + itoa(srv.UnixMilli()) + `}`,
	} {
		s, ok := controllerOffset([]byte(js), t1, t4)
		if !ok || (s.off-58*time.Second).Abs() > 2*time.Millisecond {
			t.Errorf("%s: offset %s ok %v", js, s.off, ok)
		}
	}
	for _, js := range []string{`{"_type":"noop"}`, `{"server_time_in_utc":"1"}`, `{"server_time_in_utc":"x"}`, `not json`} {
		if _, ok := controllerOffset([]byte(js), t1, t4); ok {
			t.Errorf("%s gave a sample", js)
		}
	}
	if _, ok := controllerOffset([]byte(`{"server_time_in_utc":"`+itoa(srv.UnixMilli())+`"}`), t1, t1.Add(3*time.Second)); ok {
		t.Error("a slow round trip gave a sample")
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// clockAgent is an agent with just what clockCheck needs.
type clockRec struct {
	mu    sync.Mutex
	steps []time.Duration
	logs  []string
}

func clockAgent(t *testing.T, takeover bool, sntp func(context.Context, string, func() time.Time) (time.Duration, error), rec *clockRec) *agent {
	a := &agent{cfg: &Config{Platform: PlatformJio}, topo: newTopology()}
	a.takeover.Store(takeover)
	a.o.sntp = sntp
	a.o.setClock = func(to time.Time) error {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.steps = append(rec.steps, time.Until(to))
		return nil
	}
	a.o.logf = func(f string, args ...any) {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.logs = append(rec.logs, fmt.Sprintf(f, args...))
	}
	a.events = &eventLog{logf: a.o.logf}
	a.o.t.fill()
	a.t = a.o.t
	return a
}

// The clock is stepped when SNTP to the gateway shows it more than a
// second off, left alone within a second, and never touched in observe mode.
func TestClockCheckSNTP(t *testing.T) {
	rec := &clockRec{}
	a := clockAgent(t, true, sntpVia(sntpServer(t, 58*time.Second, 2)), rec)
	a.topo.gwIP.Store("192.168.0.1")
	if !a.clockCheck(context.Background(), &clockState{}) {
		t.Fatal("check failed")
	}
	if len(rec.steps) != 1 || (rec.steps[0]-58*time.Second).Abs() > 300*time.Millisecond {
		t.Fatalf("steps %v, want one of about +58s", rec.steps)
	}
	if !strings.Contains(strings.Join(rec.logs, "\n"), "clock: stepped +58.") {
		t.Errorf("step not logged: %q", rec.logs)
	}

	rec2 := &clockRec{}
	a2 := clockAgent(t, true, sntpVia(sntpServer(t, 300*time.Millisecond, 2)), rec2)
	a2.topo.gwIP.Store("192.168.0.1")
	cs := &clockState{}
	a2.clockCheck(context.Background(), cs)
	a2.clockCheck(context.Background(), cs)
	if len(rec2.steps) != 0 {
		t.Errorf("stepped within a second: %v", rec2.steps)
	}
	if n := strings.Count(strings.Join(rec2.logs, "\n"), "clock: within"); n != 1 {
		t.Errorf("'within' logged %d times: %q", n, rec2.logs)
	}

	rec3 := &clockRec{}
	a3 := clockAgent(t, false, sntpVia(sntpServer(t, time.Hour, 2)), rec3)
	a3.topo.gwIP.Store("192.168.0.1")
	a3.clockCheck(context.Background(), &clockState{})
	if len(rec3.steps) != 0 {
		t.Errorf("observe mode stepped the clock: %v", rec3.steps)
	}
}

// Without an NTP answer from the gateway (the UCG serves none) the last
// inform reply's server_time_in_utc is used; without either, nothing is
// stepped and the failure is logged once.
func TestClockCheckControllerFallback(t *testing.T) {
	noNTP := func(context.Context, string, func() time.Time) (time.Duration, error) {
		return 0, errors.New("i/o timeout")
	}
	rec := &clockRec{}
	a := clockAgent(t, true, noNTP, rec)
	a.topo.gwIP.Store("192.168.0.1")
	cs := &clockState{}
	if a.clockCheck(context.Background(), cs) || a.clockCheck(context.Background(), cs) {
		t.Fatal("check without a source succeeded")
	}
	if len(rec.steps) != 0 {
		t.Fatalf("stepped without a source: %v", rec.steps)
	}
	if n := strings.Count(strings.Join(rec.logs, "\n"), "clock: no time source"); n != 1 {
		t.Errorf("failure logged %d times: %q", n, rec.logs)
	}
	t1 := time.Now()
	srv := t1.Add(10 * time.Millisecond).Add(-5 * time.Second)
	a.noteControllerTime([]byte(`{"_type":"noop","server_time_in_utc":"`+itoa(srv.UnixMilli())+`"}`), t1, t1.Add(20*time.Millisecond))
	if !a.clockCheck(context.Background(), cs) {
		t.Fatal("check with a controller sample failed")
	}
	if len(rec.steps) != 1 || (rec.steps[0]+5*time.Second).Abs() > 300*time.Millisecond {
		t.Fatalf("steps %v, want one of about -5s", rec.steps)
	}
	if a.ctlClock.Load() != nil {
		t.Error("the sample taken against the old clock was kept")
	}
	if !strings.Contains(strings.Join(rec.logs, "\n"), "to the controller (inform reply)") {
		t.Errorf("source not logged: %q", rec.logs)
	}
}

// A time before clockFloor is never set.
func TestClockCheckFloor(t *testing.T) {
	rec := &clockRec{}
	back := func(context.Context, string, func() time.Time) (time.Duration, error) {
		return -time.Since(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)), nil
	}
	a := clockAgent(t, true, back, rec)
	a.topo.gwIP.Store("192.168.0.1")
	a.clockCheck(context.Background(), &clockState{})
	if len(rec.steps) != 0 {
		t.Errorf("stepped to 2000: %v", rec.steps)
	}
}

// A real SNTP failure names the socket's ephemeral local port ("read udp
// 192.168.0.51:40312->192.168.0.1:123: ... connection refused" against the
// UCG, which serves no NTP), a new one every check: the failure must still
// be logged once, not every clockRetry for as long as no source answers.
func TestClockCheckRealSNTPFailureLoggedOnce(t *testing.T) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	closed := c.LocalAddr().String()
	c.Close() // nothing listens there now
	rec := &clockRec{}
	a := clockAgent(t, true, sntpVia(closed), rec)
	a.topo.gwIP.Store("127.0.0.1")
	cs := &clockState{}
	for i := 0; i < 3; i++ {
		if a.clockCheck(context.Background(), cs) {
			t.Fatal("check against a closed port succeeded")
		}
	}
	if n := strings.Count(strings.Join(rec.logs, "\n"), "clock: no time source"); n != 1 {
		t.Errorf("failure logged %d times, want once: %q", n, rec.logs)
	}
}
