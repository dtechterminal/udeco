// SPDX-License-Identifier: GPL-2.0-or-later

package jioports

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/unit"
)

// VLANMACs reads the wired clients learned on unit port phys while its
// untagged device sits in a port-VLAN bridge br-vN (native VLAN N) instead
// of the LAN bridge, whose FDB the snapshot carries: the mac_table rows of
// br-vN's FDB entries on that port, tagged VLAN N. Without them the port's
// clients show under the switch the uplink plugs into, not under this unit.
// ok is false when the device is in no br-vN.
func VLANMACs(root string, phys int) (rows []map[string]any, ok bool) {
	dev := Untagged(phys)
	brs, _ := filepath.Glob(filepath.Join(root, "/sys/class/net", unit.VLANBridgePrefix+"*"))
	for _, dir := range brs {
		m := vlanBrRE.FindStringSubmatch(filepath.Base(dir))
		if m == nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "brif", dev)); err != nil {
			continue
		}
		vid, _ := strconv.Atoi(m[1])
		b, err := os.ReadFile(filepath.Join(root, "/sys/class/net", dev, "brport/port_no"))
		if err != nil {
			return []map[string]any{}, true
		}
		port, err := strconv.ParseInt(strings.TrimSpace(string(b)), 0, 32)
		if err != nil {
			return []map[string]any{}, true
		}
		fdb, _ := os.ReadFile(filepath.Join(dir, "brforward"))
		return apstate.MACRows(apstate.ParseBrforward(fdb), int(port), vid, ""), true
	}
	return nil, false
}
