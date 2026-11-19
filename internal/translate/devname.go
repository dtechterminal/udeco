// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"sort"
	"strings"
)

// devnameNotes notes the VAP devnames that more than one wireless section
// uses. The controller ties a VAP to its bridge (bridge.N.port.M.devname),
// MAC ACL, QoS and band steering by devname alone, so for such VAPs those
// are a guess: a VAP listed by a VLAN bridge puts every VAP of that name on
// the VLAN. It happens when the AP reports radio names the controller's
// naming scheme does not expect (a U6-Lite reporting wifi0/wifi1 instead of
// ra0/rai0 gets wifi1 for its first two 5 GHz SSIDs and its second
// 2.4 GHz one).
func devnameNotes(cfg Cfg, nb *noteList) {
	by := map[string][]string{}
	for _, n := range indices(cfg, "wireless") {
		if d := cfg["wireless."+n+".devname"]; d != "" {
			by[d] = append(by[d], "wireless."+n)
		}
	}
	var dups []string
	for d, ws := range by {
		if len(ws) > 1 {
			dups = append(dups, d)
		}
	}
	sort.Strings(dups)
	for _, d := range dups {
		nb.addf("devname %q names %d VAPs (%s): their bridge (VLAN), MAC filter and QoS entries cannot be told apart; the controller derived these names from the AP's radio names",
			d, len(by[d]), strings.Join(by[d], ", "))
	}
}
