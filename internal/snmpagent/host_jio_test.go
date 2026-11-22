// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import "testing"

// The JCOW414's interfaces: its MediaTek BSS netdevs (ra*/rai*, no sysfs
// wireless directory) are ieee80211, its switch port devices eth0.P.1
// l2vlan, bdg2 a bridge; a name that only starts like them is not Wi-Fi.
func TestIfTypeJCOW414(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{"sys/class/net/bdg2/type": "1\n", "sys/class/net/bdg2/bridge/": ""}
	for _, n := range []string{"ra0", "ra3", "rai0", "rai3", "apcli0", "apclii0", "wds0", "eth0.4.1", "radio1", "rai"} {
		files["sys/class/net/"+n+"/type"] = "1\n"
	}
	writeTree(t, root, files)
	h := newHost(root)
	for name, want := range map[string]int{"ra0": ifTypeIEEE80211, "ra3": ifTypeIEEE80211, "rai0": ifTypeIEEE80211,
		"rai3": ifTypeIEEE80211, "apcli0": ifTypeIEEE80211, "apclii0": ifTypeIEEE80211, "wds0": ifTypeIEEE80211,
		"eth0.4.1": ifTypeL2VLAN, "bdg2": ifTypeBridge, "radio1": ifTypeEthernet, "rai": ifTypeEthernet} {
		if got := h.ifType(name, "/sys/class/net/"+name); got != want {
			t.Errorf("ifType(%s) = %d, want %d", name, got, want)
		}
	}
}
