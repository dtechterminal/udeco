// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import (
	"fmt"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// The bounds docs/deco/features/snmp.md lists are this package's
// constants: the rate limit, the message size, the GetBulk cap, the
// varbind and OID limits, how long one reading of the unit serves requests
// and how often the interface counters are sampled. Each phrase is the
// note's own prose with the number taken from the code.
func TestDocsSNMPBounds(t *testing.T) {
	for _, d := range []time.Duration{treeTTL, counterSample} {
		if d <= 0 || d%time.Second != 0 {
			t.Fatalf("%s is not a whole number of seconds: reword the note and this test", d)
		}
	}
	repotest.MustHave(t, "docs/deco/features/snmp.md",
		fmt.Sprintf("The agent serves %d requests/s with bursts of %d across all sources.", rateLimit, rateBurst),
		fmt.Sprintf("Messages are at most %d bytes. GetBulk is cut to fit, and max-repetitions is capped at %d.", maxMsgSize, maxRepetitions),
		fmt.Sprintf("A request may carry at most %d varbinds and OIDs may have at most %d arcs.", maxVarBind, maxOIDArcs),
		fmt.Sprintf("One reading of /proc and /sys serves requests for %d s", treeTTL/time.Second),
		fmt.Sprintf("The counters are sampled every %d s while the agent runs,", counterSample/time.Second))
}
