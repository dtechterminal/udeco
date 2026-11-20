// SPDX-License-Identifier: GPL-2.0-or-later

package mcinspect

import (
	"fmt"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/repotest"
)

// The bounds docs/deco/features/multicast-inspect.md lists are this
// package's constants: the table sizes, the rows of one inform, the
// membership ageing and the records read from one mDNS message. Each
// phrase is the note's own prose with the number taken from the code.
func TestDocsMulticastInspectBounds(t *testing.T) {
	if MembershipAge <= 0 || MembershipAge%time.Second != 0 {
		t.Fatalf("MembershipAge %s is not a whole number of seconds: reword the note and this test", MembershipAge)
	}
	repotest.MustHave(t, "docs/deco/features/multicast-inspect.md",
		fmt.Sprintf("a group not reported for %d s (the U6 Pro's snooping ageing, `mcsd.conf`) goes.", MembershipAge/time.Second),
		fmt.Sprintf("mDNS from the client is parsed (compression, loop guard, at most %d records):", maxRecords),
		fmt.Sprintf("Bounds: %d clients per VAP; %d groups per client and per VAP, %d services, %d memberships per client; %d groups and %d services per inform row.",
			maxClients, maxGroups, maxServices, maxMembers, reportGroups, reportServices))
}
