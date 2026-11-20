// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/repotest"
	"github.com/dtechterminal/udeco/internal/rf"
)

// The numbers docs/deco/features/garage-parity.md and the README's JioFiber
// table give for this package's behaviour are the package's constants. The
// documents keep their prose: each phrase below is that prose with its
// number taken from the constant, so a changed constant fails here until
// the document says the same. A value the document gives in words or in
// another unit has its condition beside it.
func TestDocsGarageThresholds(t *testing.T) {
	const (
		note   = "docs/deco/features/garage-parity.md"
		readme = "README.md"
	)
	whole := func(d, unit time.Duration, name string) string {
		t.Helper()
		if d <= 0 || d%unit != 0 {
			t.Fatalf("%s is not a whole number of %s: reword the documents and this test", d, name)
		}
		return fmt.Sprintf("%d %s", d/unit, name)
	}
	s := func(d time.Duration) string { t.Helper(); return whole(d, time.Second, "s") }
	min := func(d time.Duration) string { t.Helper(); return whole(d, time.Minute, "min") }

	pmk, err := strconv.Atoi(pmkCacheMinutes)
	if err != nil || pmk <= 0 || pmk%60 != 0 {
		t.Fatalf("pmkCacheMinutes %q is not a whole number of hours: reword the documents and this test", pmkCacheMinutes)
	}
	dfsRange := fmt.Sprintf("%d-%d", chansDFS[0], chansDFS[len(chansDFS)-1])
	for i, ch := range chansDFS { // the documents give the DFS channels as one range of 20 MHz channels
		if ch != chansDFS[0]+4*i {
			t.Fatalf("chansDFS %v is not one range: reword the documents and this test", chansDFS)
		}
	}
	keep := ""
	for i, ch := range rf.NonOverlap24() {
		if i > 0 {
			keep += "/"
		}
		keep += strconv.Itoa(ch)
	}
	// the hold after radar is the driver's 30 min non-occupancy period and
	// a margin, which the note rounds up to the minute
	nop := (nopHold + time.Minute - 1).Truncate(time.Minute)

	for _, c := range []struct {
		rel, phrase string
		holds       bool
	}{
		// minimum RSSI (minrssi.go)
		{note, fmt.Sprintf("disconnects a station after %d readings in a row at least %s apart below the threshold (`DisConnectSta`), backing off %s doubling to %s per station,",
			minRSSIConseq, s(minRSSIGap), s(kickBackoff), min(kickBackoffMax)), true},
		// PMK cache and the automatic channel's skip list (features.go)
		{note, fmt.Sprintf("`PMKCachePeriod=%s` (minutes, the U6's %d h) on 5 GHz.", pmkCacheMinutes, pmk/60), true},
		{readme, fmt.Sprintf("| Group rekey, PMK cache | the WLAN's rekey per BSS; %d h PMK cache on 5 GHz | controller |", pmk/60), true},
		{note, "## 4. 2.4 GHz automatic channel: " + keep + " only", true},
		{note, "with channel auto, `AutoChannelSkipList=" + acsSkip24 + "`.", true},
		{readme, "| 2.4 GHz auto channel | " + keep + " only | always |", true},
		// uplink loss (uplinkloss.go)
		{note, "with no carrier on the uplink port (port 4) for " + s(uplinkLossAfter) + ", every SSID goes down except one management SSID", true},
		{note, "with carrier back for " + s(uplinkBackAfter) + " every SSID comes back. A new isolation waits " + min(uplinkIsoGap) + " after the last restore.", true},
		{note, "two restarts per radio per outage of " + s(uplinkLossAfter) + " or more.", true},
		// the settle time after a restart (restartgate.go)
		{note, "Clients that joined during the " + s(defaultSettle) + " settle after a restart", true},
		{readme, "never during a Wi-Fi apply, a radio restart or the " + s(defaultSettle) + " after it,", true},
		// DFS (dfs.go)
		{note, "with `dfs`, the controller's " + dfsRange + " (the only DFS channels of the MT7663's IN table;", true},
		{readme, "| DFS | " + dfsRange + ", CAC, radar followed and reported | `dfs` (off) |", true},
		{note, "the agent stays off the driver for " + s(dfsQuiet) + " (the 65 s CAC:", dfsQuiet > 65*time.Second},
		{note, "Radar is the driver's (CSA, a random new channel, 30 min NOP).", nopHold > 30*time.Minute},
		{note, "keeps the channel out for " + min(nop) + " (all of " + dfsRange + " at 80 MHz)", true},
	} {
		if !c.holds {
			t.Errorf("%s says %q, which the code's constant no longer is: reword the document and this test", c.rel, c.phrase)
			continue
		}
		repotest.MustHave(t, c.rel, c.phrase)
	}
}
