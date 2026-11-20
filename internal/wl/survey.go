// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
)

// surveyState turns successive `wl chanim_stats us` rows of one radio into
// the monotonic cumulative apstate.Survey that Snapshot.Fields expects (it
// takes deltas between two snapshots).
//
// The driver counters are u64 values that can carry arbitrary ±k·2^32
// offsets after a radio re-init (collector.md, verifier), so raw values mean
// nothing on their own: only u64 modular differences between two rows of the
// same chanspec are used, and they are added to our own accumulators.
//
// Mapping (iw-survey meaning): Active = total_tm, Busy = busy_tm + tx (busy_tm
// leaves out our own transmit time), Rx = inbss, Tx = tx.
type surveyState struct {
	have bool
	prev chanimRow
	at   time.Time
	// accumulated µs: active, busy, rx, tx
	active, busy, rx, tx int64
}

// slackUs absorbs total_tm moving in 1 s steps while the other counters move
// continuously.
const slackUs = 1_000_000

// update folds one row in and returns the accumulated survey (ms).
func (s *surveyState) update(row chanimRow, now time.Time) apstate.Survey {
	if !s.have || row.Key != s.prev.Key {
		// first sample, or the radio moved to another primary channel:
		// start a new baseline, report nothing for this interval
		s.rebase(row, now)
		return s.survey()
	}
	dTotal := row.Total - s.prev.Total // modular u64
	if dTotal == 0 {
		// total_tm advances in whole seconds; keep the old baseline so the
		// next interval covers this one
		return s.survey()
	}
	dBusy := row.Busy - s.prev.Busy
	dRx := row.Inbss - s.prev.Inbss
	dTx := row.Tx - s.prev.Tx

	// A delta that cannot be real means the counters were reset or got a
	// new offset in between: re-baseline instead of reporting garbage.
	// total_tm never runs ahead of the wall clock by more than its step,
	// so the bound is wall + slack (a 2×wall bound would accept a +2^32 µs
	// offset jump after a gap of about 72 minutes).
	wallUs := uint64(max(0, now.Sub(s.at).Microseconds()))
	if dTotal > wallUs+2*slackUs || dBusy > dTotal+slackUs || dRx > dTotal+slackUs || dTx > dTotal+slackUs {
		s.rebase(row, now)
		return s.survey()
	}
	s.active += int64(dTotal)
	s.busy += int64(min(dBusy+dTx, dTotal))
	s.rx += int64(min(dRx, dTotal))
	s.tx += int64(min(dTx, dTotal))
	s.prev, s.at = row, now
	return s.survey()
}

func (s *surveyState) rebase(row chanimRow, now time.Time) {
	s.have, s.prev, s.at = true, row, now
}

func (s *surveyState) survey() apstate.Survey {
	return apstate.Survey{Active: s.active / 1000, Busy: s.busy / 1000, Rx: s.rx / 1000, Tx: s.tx / 1000}
}
