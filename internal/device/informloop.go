// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"strings"
	"time"

	"github.com/dtechterminal/udeco/internal/inform"
)

// The inform loop's timing, the same for every daemon here (upstream's uow,
// cmd/udeco, cmd/udeco-ap). Each keeps its own HTTP timeout.
const (
	// DefaultInformInterval is the time between informs until a reply
	// names another (Outcome.Interval).
	DefaultInformInterval = 10 * time.Second
	// MinInformWait is the shortest interval taken from a reply: the
	// controller asks for 1 s informs while the device is watched
	// (inform_min_interval, Session.Payload).
	MinInformWait = time.Second
	// ImmediateInformWait is the wait after a reply that asks for the
	// next inform at once (Outcome.Immediate).
	ImmediateInformWait = 500 * time.Millisecond

	// after a bad answer: at least backoffFloor, doubled for each further
	// one up to backoffDoublings times, and never above backoffMax
	backoffFloor     = 5 * time.Second
	backoffDoublings = 4
	backoffMax       = time.Minute
)

// InformBackoff is the wait before the next inform after errs bad answers
// in a row (1 or more), as a real AP spaces them: further and further
// apart, up to a minute. interval is the loop's current inform interval.
// For errs below 1 there is nothing to back off from: the interval itself.
func InformBackoff(interval time.Duration, errs int) time.Duration {
	if errs < 1 {
		return interval
	}
	return min(max(interval, backoffFloor)*time.Duration(1<<min(errs-1, backoffDoublings)), backoffMax)
}

// PostFunc sends one inform packet to url and returns the HTTP status and
// the answer's body. A status other than 200 is not an error.
type PostFunc func(url string, pkt []byte) (status int, body []byte, err error)

// InformOnce sends one inform and handles the answer: the payload is
// built and encoded with the session's key, posted, and a reply is
// decoded and handled (Session.Handle). Events go to logf, and a changed
// state is saved to statePath. ok is false for a bad answer (the loop
// counts those for InformBackoff): a failed POST, a status other than 200
// (but 404 while not adopted: pending is normal), or a reply that does
// not decode or parse.
//
// A reply that does not decode with the session's key is tried with the
// factory key. This is the inform of cmd/udeco and upstream's uow. The AP agent
// has its own, stricter one (cmd/udeco-ap informOnce): no factory-key
// retry, no unencrypted reply, and its own hooks around the reply.
func InformOnce(x *Session, post PostFunc, statePath string, logf func(format string, args ...any)) (o Outcome, ok bool) {
	js, err := x.Payload(time.Now())
	if err != nil {
		logf("payload: %v", err)
		return Outcome{}, false
	}
	pkt, err := inform.Encode(x.Dev.MAC, x.S.Key, x.Cipher(), js, nil)
	if err != nil {
		logf("encode: %v", err)
		return Outcome{}, false
	}
	status, body, err := post(x.S.InformURL, pkt)
	if err != nil {
		logf("POST: %v", err)
		return Outcome{}, false
	}
	switch status {
	case 200:
	case 404:
		if !x.S.Adopted {
			return Outcome{}, true // pending: normal
		}
		logf("HTTP 404 while adopted (forgotten?)")
		return Outcome{}, false
	default:
		logf("HTTP %d (%d bytes)", status, len(body))
		return Outcome{}, false
	}
	if len(body) == 0 {
		return Outcome{}, true // nothing for us this time
	}
	_, plain, err := inform.Decode(body, x.S.Key)
	if err != nil && x.S.Key != inform.DefaultKeyHex {
		_, plain, err = inform.Decode(body, inform.DefaultKeyHex)
	}
	if err != nil {
		logf("reply did not decode: %v", err)
		return Outcome{}, false
	}
	o, err = x.Handle(plain, time.Now())
	if err != nil {
		logf("%v", err)
		return o, false
	}
	for _, e := range o.Events {
		if !strings.HasPrefix(e, "noop ") || o.Immediate {
			logf("%s", e)
		}
	}
	if o.Changed {
		if err := x.S.Save(statePath); err != nil {
			logf("saving state: %v", err)
		}
	}
	return o, true
}
