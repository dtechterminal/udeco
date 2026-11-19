// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Clock sync on platform jio-mtk. The JCOW414 runs no NTP client once its
// Jio services are down (jiosys; the owner's customInit only sets the date
// once at boot from an HTTP Date header), and its clock drifts: 58 s slow
// on 2026-11-19. WLAN schedules (schedule.go) and syslog timestamps follow
// the wall clock, so the agent keeps it right itself, takeover mode only
// (observe mode changes nothing on the unit):
//
//   - SNTP (RFC 4330) to the gateway first; the UCG answered no NTP on
//     2026-11-19 (nothing listens on :123), so
//   - else the controller's own time, server_time_in_utc in the last inform
//     reply (an answer sealed with the device key), corrected by half the
//     POST's round trip.
//
// The clock is stepped (settimeofday) only when it is more than clockMaxOff
// off, and every step is logged and kept in the event ring. Checks run
// clockFirst after the start and then every clockEvery (clockRetry after a
// failure). A step moves only wall-clock readings: the agent's timers,
// timeouts and intervals run on Go's monotonic clock, and the boot gate,
// counters and start guard use /proc/uptime, which a step does not touch.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

const (
	clockMaxOff = time.Second      // a smaller offset is left alone
	clockFirst  = 30 * time.Second // first check after the start (a reading and an inform first)
	clockEvery  = time.Hour        // re-check
	clockRetry  = time.Minute      // after a check that found no time source
	// clockFresh: an inform-reply sample older than this is not used
	clockFresh = 5 * time.Minute
	// clockMaxRTT: an inform POST slower than this gives no sample
	clockMaxRTT = 2 * time.Second
	sntpTimeout = 2 * time.Second
)

// clockFloor: no time source is believed before this (a source without a
// clock of its own answers 1970 or 2000).
var clockFloor = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// clockSample is the offset of the unit's clock from a time source (add
// it to the unit's time to get the source's).
type clockSample struct {
	off time.Duration
	at  time.Time // when it was taken (monotonic reading)
}

// noteControllerTime records the controller's time from an inform reply
// (plain JSON) that was sent at t1 and answered at t4 (any goroutine).
func (a *agent) noteControllerTime(plain []byte, t1, t4 time.Time) {
	if !a.cfg.jio() {
		return
	}
	if s, ok := controllerOffset(plain, t1, t4); ok {
		a.ctlClock.Store(&s)
	}
}

// controllerOffset reads server_time_in_utc (milliseconds, a string or a
// number) from a reply.
func controllerOffset(plain []byte, t1, t4 time.Time) (clockSample, bool) {
	rtt := t4.Sub(t1)
	if rtt < 0 || rtt > clockMaxRTT {
		return clockSample{}, false
	}
	var r struct {
		T json.RawMessage `json:"server_time_in_utc"`
	}
	if json.Unmarshal(plain, &r) != nil || len(r.T) == 0 {
		return clockSample{}, false
	}
	var str string
	raw := string(r.T)
	if json.Unmarshal(r.T, &str) == nil {
		raw = str
	}
	ms, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return clockSample{}, false
	}
	srv := time.UnixMilli(ms)
	if srv.Before(clockFloor) {
		return clockSample{}, false
	}
	mid := t1.Add(rtt / 2)
	return clockSample{off: srv.Sub(mid.Round(0)), at: t4}, true
}

// sntpOffset asks server (an IPv4 address, port 123) for the time once.
func sntpOffset(ctx context.Context, server string, now func() time.Time) (time.Duration, error) {
	return sntpOffsetPort(ctx, server, "123", now)
}

func sntpOffsetPort(ctx context.Context, server, port string, now func() time.Time) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, sntpTimeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort(server, port))
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	req := make([]byte, 48)
	req[0] = 0<<6 | 4<<3 | 3 // LI 0, version 4, client
	t1 := now()
	binary.BigEndian.PutUint64(req[40:], ntpTime(t1)) // transmit; the server echoes it as originate
	if _, err := c.Write(req); err != nil {
		return 0, err
	}
	resp := make([]byte, 128)
	for {
		n, err := c.Read(resp)
		if err != nil {
			return 0, err
		}
		t4 := now()
		if n < 48 || binary.BigEndian.Uint64(resp[24:]) != binary.BigEndian.Uint64(req[40:]) {
			continue // not the answer to this request
		}
		return sntpParse(resp[:n], t1, t4)
	}
}

// sntpParse checks an SNTP answer to a request sent at t1 and received at
// t4 and returns the clock offset ((T2-T1)+(T3-T4))/2.
func sntpParse(b []byte, t1, t4 time.Time) (time.Duration, error) {
	if len(b) < 48 {
		return 0, errors.New("short answer")
	}
	li, mode, stratum := b[0]>>6, b[0]&7, b[1]
	switch {
	case mode != 4:
		return 0, fmt.Errorf("answer mode %d, want 4 (server)", mode)
	case stratum == 0 || stratum > 15:
		return 0, fmt.Errorf("stratum %d (unsynchronised or kiss-o'-death)", stratum)
	case li == 3:
		return 0, errors.New("the server's clock is not synchronised")
	}
	t2, t3 := fromNTP(binary.BigEndian.Uint64(b[32:])), fromNTP(binary.BigEndian.Uint64(b[40:]))
	if t3.Before(clockFloor) || t2.Before(clockFloor) {
		return 0, fmt.Errorf("the server's time %s is implausible", t3.UTC().Format(time.RFC3339))
	}
	t1, t4 = t1.Round(0), t4.Round(0)
	return (t2.Sub(t1) + t3.Sub(t4)) / 2, nil
}

const ntpEpochOffset = 2208988800 // 1900-01-01 to 1970-01-01, seconds

func ntpTime(t time.Time) uint64 {
	ns := t.UnixNano()
	sec := uint64(ns/1e9) + ntpEpochOffset
	frac := uint64(ns%1e9) << 32 / 1e9
	return sec<<32 | frac
}

func fromNTP(v uint64) time.Time {
	sec := int64(v>>32) - ntpEpochOffset
	nsec := int64((v & 0xffffffff) * 1e9 >> 32)
	return time.Unix(sec, nsec)
}

// clockLoop keeps the unit's clock (platform jio-mtk); its own goroutine.
func (a *agent) clockLoop(ctx context.Context) {
	wait := a.t.clockFirst
	var cs clockState
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = a.t.clockEvery
		if !a.clockCheck(ctx, &cs) {
			wait = a.t.clockRetry
		}
	}
}

// clockState is what clockLoop logged last (no repeats every retry).
type clockState struct {
	lastErr string
	inSync  bool // "in sync" was logged since the last step or error
}

// clockCheck compares the clock with a time source and steps it when it
// is more than clockMaxOff off. false: no time source answered.
func (a *agent) clockCheck(ctx context.Context, cs *clockState) bool {
	if !a.takeover.Load() {
		return true // observe mode: the unit's clock is not the agent's
	}
	gw, _ := a.topo.gwIP.Load().(string)
	var off time.Duration
	var src string
	var err error
	if gw != "" {
		sntp := a.o.sntp
		if sntp == nil {
			sntp = sntpOffset
		}
		if off, err = sntp(ctx, gw, time.Now); err == nil {
			src = "the gateway " + gw + " (SNTP)"
		}
	} else {
		err = errors.New("no gateway known yet")
	}
	if src == "" {
		if s := a.ctlClock.Load(); s != nil && time.Since(s.at) < clockFresh {
			off, src = s.off, "the controller (inform reply)"
		}
	}
	if src == "" {
		if e := clockErrKey(err); e != cs.lastErr {
			cs.lastErr = e
			cs.inSync = false
			a.logf("clock: no time source (SNTP to the gateway: %s; no recent server_time_in_utc in an inform reply); retrying every %s", e, a.t.clockRetry)
		}
		return false
	}
	cs.lastErr = ""
	if off.Abs() <= clockMaxOff {
		if !cs.inSync {
			cs.inSync = true
			a.logf("clock: within %s of %s (no step; checked every %s)", off.Round(time.Millisecond), src, a.t.clockEvery)
		}
		return true
	}
	now := time.Now()
	to := now.Add(off)
	if to.Before(clockFloor) {
		a.logf("clock: %s gives %s, before %s: not stepping", src, to.UTC().Format(time.RFC3339), clockFloor.Format("2006-01-02"))
		return true
	}
	set := a.o.setClock
	if set == nil {
		set = setSystemClock
	}
	if err := set(to); err != nil {
		a.logf("clock: stepping %+.3f s to %s: %v", off.Seconds(), src, err)
		return true
	}
	a.ctlClock.Store(nil) // taken against the old clock
	cs.inSync = false
	a.event(fmt.Sprintf("clock: stepped %+.3f s to %s (was %s)", off.Seconds(), src, now.UTC().Format(time.RFC3339)))
	return true
}

// clockErrKey is what makes a failure new for clockState: a socket error
// without its addresses, which name a new ephemeral local port every check.
func clockErrKey(err error) string {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Op + " " + oe.Net + ": " + oe.Err.Error()
	}
	return err.Error()
}

// startClock runs clockLoop on platform jio-mtk.
func (a *agent) startClock(ctx context.Context) {
	if !a.cfg.jio() {
		return
	}
	a.bg.Add(1)
	go func() { defer a.bg.Done(); a.clockLoop(ctx) }()
}
