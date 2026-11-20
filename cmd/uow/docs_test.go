// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// docs/internals.md gives two of the daemon's own waits by number: how
// long a client stays below the minimum RSSI before it is kicked
// (lowRSSIFor) and how often an idle radio scans in the background
// (bgScanEvery). Each phrase is the document's own prose with the number
// taken from the constant.
func TestDocsDaemonWaits(t *testing.T) {
	if lowRSSIFor <= 0 || lowRSSIFor%time.Second != 0 || bgScanEvery <= 0 || bgScanEvery%time.Minute != 0 {
		t.Fatalf("lowRSSIFor %s, bgScanEvery %s: reword docs/internals.md and this test", lowRSSIFor, bgScanEvery)
	}
	repotest.MustHave(t, "docs/internals.md",
		fmt.Sprintf("the daemon also kicks clients below the minimum for %d s.", lowRSSIFor/time.Second),
		fmt.Sprintf("A background scan every %d minutes runs only on radios with no clients and no mesh uplink:", bgScanEvery/time.Minute))
}
