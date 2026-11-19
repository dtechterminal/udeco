// SPDX-License-Identifier: GPL-2.0-or-later

package mcinspect

import (
	"context"
	"errors"
	"time"
)

// Source delivers a VAP's group-addressed frames.
type Source interface {
	// Recv reads one frame into b. n is the frame's real length (it may
	// exceed len(b): the frame was cut to fit); outgoing tells a frame the
	// VAP sent from one a client sent. ErrTimeout means nothing arrived
	// within the poll interval.
	Recv(b []byte) (n int, outgoing bool, err error)
	Close() error
}

// ErrTimeout is Source.Recv's poll timeout.
var ErrTimeout = errors.New("mcinspect: timeout")

// Opener opens a Source on a VAP (Open on Linux; tests use fakes).
type Opener func(ifname string) (Source, error)

// snap is the receive buffer: headers plus the mDNS payloads of ordinary
// frames; longer frames are counted at their real length.
const snap = 2048

// Run reads src into t as VAP vif until ctx ends or src fails, then
// closes src. It returns the error that stopped it (nil when ctx ended).
func Run(ctx context.Context, t *Table, vif string, src Source, now func() time.Time) error {
	defer src.Close()
	b := make([]byte, snap)
	for ctx.Err() == nil {
		n, out, err := src.Recv(b)
		if errors.Is(err, ErrTimeout) {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		t.Observe(vif, b[:min(n, len(b))], n, out, now())
	}
	return nil
}
