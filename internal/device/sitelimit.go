// SPDX-License-Identifier: GPL-2.0-or-later

package device

// Failed-login rate limiting for site SSH logins (sitessh.go): per source
// address, a few free failures and then an exponential backoff during which
// the source is refused before any password is checked; and globally, too
// many failures from all sources in a window refuse every site login for a
// while. A success clears its source's failures. The console's adoption
// logins are not limited (sshadopt.go: unchanged).

import (
	"sync"
	"time"
)

// LoginLimits tunes the failed-login limiter. Zero values take the
// defaults in brackets.
type LoginLimits struct {
	Free         int           // failures per source before the backoff starts [3]
	Base         time.Duration // the first backoff [2s]; it doubles per further failure
	Max          time.Duration // the longest backoff [5m]
	GlobalFails  int           // failures from all sources within GlobalWindow that block every source [20]
	GlobalWindow time.Duration // [1m]
	GlobalBlock  time.Duration // how long every source is then refused [1m]
	Now          func() time.Time
}

// maxTrackedSources bounds the per-source table; past it the oldest
// entries go (the global limit still holds).
const maxTrackedSources = 1024

type loginFails struct {
	n     int
	last  time.Time
	until time.Time
}

type loginLimiter struct {
	o           LoginLimits
	mu          sync.Mutex
	src         map[string]*loginFails
	recent      []time.Time // failures within GlobalWindow, oldest first
	globalUntil time.Time
}

func newLoginLimiter(o LoginLimits) *loginLimiter {
	if o.Free <= 0 {
		o.Free = 3
	}
	if o.Base <= 0 {
		o.Base = 2 * time.Second
	}
	if o.Max <= 0 {
		o.Max = 5 * time.Minute
	}
	if o.GlobalFails <= 0 {
		o.GlobalFails = 20
	}
	if o.GlobalWindow <= 0 {
		o.GlobalWindow = time.Minute
	}
	if o.GlobalBlock <= 0 {
		o.GlobalBlock = time.Minute
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &loginLimiter{o: o, src: map[string]*loginFails{}}
}

// allow reports whether src may try a login now, and if not for how long
// it must wait; global says the global limit refused it.
func (l *loginLimiter) allow(src string) (ok bool, wait time.Duration, global bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.o.Now()
	if now.Before(l.globalUntil) {
		return false, l.globalUntil.Sub(now), true
	}
	if f := l.src[src]; f != nil && now.Before(f.until) {
		return false, f.until.Sub(now), false
	}
	return true, 0, false
}

// fail records a failed login from src.
func (l *loginLimiter) fail(src string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.o.Now()
	f := l.src[src]
	if f == nil || now.Sub(f.last) > 2*l.o.Max {
		f = &loginFails{}
		l.prune(now)
		l.src[src] = f
	}
	f.n++
	f.last = now
	if over := f.n - l.o.Free; over > 0 {
		d := l.o.Base
		for i := 1; i < over && d < l.o.Max; i++ {
			d *= 2
		}
		f.until = now.Add(min(d, l.o.Max))
	}
	cut := 0
	for cut < len(l.recent) && now.Sub(l.recent[cut]) > l.o.GlobalWindow {
		cut++
	}
	l.recent = append(l.recent[cut:], now)
	if len(l.recent) >= l.o.GlobalFails {
		l.globalUntil = now.Add(l.o.GlobalBlock)
		l.recent = l.recent[:0]
	}
}

// success clears src's failures.
func (l *loginLimiter) success(src string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.src, src)
}

// prune drops stale sources, and the oldest ones while the table is full;
// callers hold l.mu.
func (l *loginLimiter) prune(now time.Time) {
	for k, f := range l.src {
		if now.Sub(f.last) > 2*l.o.Max && !now.Before(f.until) {
			delete(l.src, k)
		}
	}
	for len(l.src) >= maxTrackedSources {
		var oldest string
		var t time.Time
		for k, f := range l.src {
			if oldest == "" || f.last.Before(t) {
				oldest, t = k, f.last
			}
		}
		delete(l.src, oldest)
	}
}
