// SPDX-License-Identifier: GPL-2.0-or-later

package openwrt

import (
	"fmt"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// docs/internals.md gives the length of the timed ban that keeps a blocked
// client out where there is no hostapd_cli (BanTime).
func TestDocsBanTime(t *testing.T) {
	if BanTime <= 0 || BanTime%time.Second != 0 {
		t.Fatalf("BanTime %s is not a whole number of seconds: reword docs/internals.md and this test", BanTime)
	}
	repotest.MustHave(t, "docs/internals.md", fmt.Sprintf("Without hostapd_cli: a %d s `del_client` ban, refreshed.", BanTime/time.Second))
}
