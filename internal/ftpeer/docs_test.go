// SPDX-License-Identifier: GPL-2.0-or-later

package ftpeer

import (
	"fmt"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// docs/deco/features/ft-sae.md describes the announcements with this
// package's constants: the interval, the frame's EtherType and group
// address, the receiver's rate limits, the R0KH-ID length and the expiry
// (the TTL New gives a Service with no Options, as the agent starts it).
// Each phrase is the note's own prose with the number taken from the code.
func TestDocsFTSAELimits(t *testing.T) {
	ttl := New(Options{}).o.TTL
	for _, d := range []time.Duration{DefaultInterval, ttl} {
		if d <= 0 || d%time.Second != 0 {
			t.Fatalf("%s is not a whole number of seconds: reword the note and this test", d)
		}
	}
	repotest.MustHave(t, "docs/deco/features/ft-sae.md",
		fmt.Sprintf("Each agent sends, every %d s and at once after a change or on hearing a new unit,", DefaultInterval/time.Second),
		fmt.Sprintf("EtherType %#04x (IEEE local experimental) to %s,", EtherType, GroupMAC),
		fmt.Sprintf("within the rate limits (per source %v/s burst %v, all sources %v/s burst %v, checked before any cryptography)",
			srcRate, srcBurst, globalRate, globalBurst),
		fmt.Sprintf("(R0KH-ID 1-%d of `[0-9A-Za-z._:-]`, unicast MACs)", MaxR0KHIDLen),
		fmt.Sprintf("Peers expire after %d s without an announcement,", ttl/time.Second),
		fmt.Sprintf("ether proto %#04x` shows the announcements,", EtherType))
}
