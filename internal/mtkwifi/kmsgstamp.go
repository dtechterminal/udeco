// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// The kernel's own times of the MT7603 sweep's lines (offchan.go), from
// /dev/kmsg: every record there is "<prio>,<seq>,<µs since boot>,<flags>;
// <text>", the time taken when the line was printed. The start line
// (ApSiteSurveyNew_by_wdev, printed in the request's ioctl) and the dwell's
// end line (time_diff, printed when the dwell timer's action runs) are
// stamped by the kernel, so the time between them is the visit's real
// length, whenever the agent gets to read them. A scan already running
// that takes the request over ends it sooner than the dwell can (within
// 140 ms for every scan but ACS); a real dwell of ms ends no sooner than
// dwellEarliest(ms) after its request.
//
// This replaces the early kernel-log read when /dev/kmsg is there: live on
// the Garage 2026-11-25 the klogctl read of the whole ring scheduled 20 ms
// before the dwell's earliest end took 21-135 ms on the unit's MIPS core,
// so it never ended in time and every visit was untrusted (no 2.4 GHz
// table at all). Without /dev/kmsg the early read stays.

// stampRec is one of the sweep's lines with its kernel time.
type stampRec struct {
	ts     time.Duration // since boot
	start  bool          // a start line (else a time_diff line)
	ch, ms int           // start line: channel, dwell
}

// kmsgStamps collects the sweep's start and end lines from /dev/kmsg.
type kmsgStamps struct {
	src    packetSource
	mu     sync.Mutex
	recs   []stampRec
	notify chan struct{}
	done   chan struct{}
}

func newKmsgStamps(src packetSource) *kmsgStamps {
	s := &kmsgStamps{src: src, notify: make(chan struct{}, 1), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		buf := make([]byte, 8192)
		for {
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			if r, ok := parseStampRec(string(buf[:n])); ok {
				s.mu.Lock()
				s.recs = append(s.recs, r)
				s.mu.Unlock()
				select {
				case s.notify <- struct{}{}:
				default:
				}
			}
		}
	}()
	return s
}

// parseStampRec reads one /dev/kmsg record: a start or time_diff line.
func parseStampRec(rec string) (stampRec, bool) {
	head, text, ok := strings.Cut(rec, ";")
	if !ok {
		return stampRec{}, false
	}
	f := strings.Split(head, ",")
	if len(f) < 3 {
		return stampRec{}, false
	}
	us, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil {
		return stampRec{}, false
	}
	text, _, _ = strings.Cut(text, "\n")
	r := stampRec{ts: time.Duration(us) * time.Microsecond}
	if m := visitStart.FindStringSubmatch(text); m != nil {
		r.start = true
		r.ch, _ = strconv.Atoi(m[2])
		r.ms, _ = strconv.Atoi(m[3])
		return r, true
	}
	if visitDone.MatchString(text) {
		return r, true
	}
	return stampRec{}, false
}

// mark is where a visit's records start.
func (s *kmsgStamps) mark() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.recs)
}

// dwell finds the visit's start line for ch and ms after mark and the first
// end line after it, and gives the kernel time between them; ok false when
// they have not come within wait (real time: the reader runs beside the
// sweep).
func (s *kmsgStamps) dwell(mark, ch, ms int, wait time.Duration) (time.Duration, bool) {
	deadline := time.Now().Add(wait)
	for {
		s.mu.Lock()
		d, ok := findDwell(s.recs[min(mark, len(s.recs)):], ch, ms)
		s.mu.Unlock()
		if ok {
			return d, true
		}
		left := time.Until(deadline)
		if left <= 0 {
			return 0, false
		}
		t := time.NewTimer(left)
		select {
		case <-s.notify:
		case <-t.C:
		}
		t.Stop()
	}
}

func findDwell(recs []stampRec, ch, ms int) (time.Duration, bool) {
	start := -1
	for i, r := range recs {
		if r.start && r.ch == ch && r.ms == ms {
			start = i
		}
	}
	if start < 0 {
		return 0, false
	}
	for _, r := range recs[start+1:] {
		if !r.start {
			return r.ts - recs[start].ts, true
		}
	}
	return 0, false
}

func (s *kmsgStamps) Close() {
	s.src.Close()
	<-s.done
}
