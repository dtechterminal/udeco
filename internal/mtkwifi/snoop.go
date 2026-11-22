// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// IGMP/MLD snooping on the agent's VLAN bridges (br-v<vid>), as on the
// Deco (bcmwifi.BridgeSnoop, docs/deco/features/igmp-snooping.md):
// hash_max 2048, multicast_snooping 1, multicast_querier 0, written
// through sysfs where a value reads otherwise, when ensureVLAN makes the
// bridge and again each Tick (a drifted value is put back). The Garage's
// kernel (3.18.21) floods a group while no querier is seen on the VLAN
// (br_multicast_querier_exists), so a VLAN without a querier forwards as
// before. A file that is missing (a kernel without the option) is
// skipped. bdg2 (the LAN) is the vendor's and left alone; the radios'
// own multicast enhancement stays IgmpSnEnable. The hand-back deletes
// the bridges themselves.

// snoop sets br's snooping knobs where they read otherwise.
func (a *Applier) snoop(br string) {
	if a.o.DryRun {
		return
	}
	for _, k := range bcmwifi.BridgeSnoop {
		p := a.dev(filepath.Join("/sys/class/net", br, "bridge", k[0]))
		b, err := os.ReadFile(p)
		if err != nil || strings.TrimSpace(string(b)) == k[1] {
			continue
		}
		if err := os.WriteFile(p, []byte(k[1]+"\n"), 0o644); err != nil {
			a.o.Logf("mtkwifi: IGMP/MLD snooping on %s: %s: %v", br, k[0], err)
		}
	}
}

// snoopVLANs re-asserts snoop on every VLAN bridge of the agent's.
func (a *Applier) snoopVLANs() {
	ents, err := os.ReadDir(a.dev("/sys/class/net"))
	if err != nil {
		return
	}
	for _, e := range ents {
		if vlanBr.MatchString(e.Name()) {
			a.snoop(e.Name())
		}
	}
}
