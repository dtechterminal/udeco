// SPDX-License-Identifier: GPL-2.0-or-later

package mdnsbr

import (
	"fmt"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/repotest"
)

// The flood limits docs/deco/features/mdns-bridge.md gives are this
// package's: the duplicate window, the token buckets a Service gets when
// its Options name none (DefaultRates, as the agent starts it) and the
// number of source MACs tracked. Each phrase is the note's own prose with
// the number taken from the code.
func TestDocsMdnsBridgeLimits(t *testing.T) {
	if DedupWindow <= 0 || DedupWindow%time.Millisecond != 0 {
		t.Fatalf("DedupWindow %s is not a whole number of milliseconds: reword the note and this test", DedupWindow)
	}
	r := DefaultRates
	repotest.MustHave(t, "docs/deco/features/mdns-bridge.md",
		fmt.Sprintf("a message (source IP + payload) seen in the last %d ms is not forwarded again.", DedupWindow/time.Millisecond),
		fmt.Sprintf("Token buckets: %v frames/s (burst %v) per port, %v/s (burst %v) per source MAC (at most %d MACs tracked; new MACs are refused beyond that), %v/s (burst %v) sent in total.",
			r.PortPPS, r.PortBurst, r.MACPPS, r.MACBurst, maxMACBuckets, r.OutPPS, r.OutBurst))
}
