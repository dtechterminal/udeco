// SPDX-License-Identifier: GPL-2.0-or-later

package openwrt

import "testing"

// The scripts the daemon runs on the AP, as they were when each wrote
// /etc/unifi-openwrt and the service's name out itself: the directory, the
// files in it and the service now come from paths.go, and what reaches
// the AP must not change by a byte.
func TestAPScriptsGolden(t *testing.T) {
	golden(t, "mesh_watch.sh", meshScript)
	golden(t, "mesh_sync.sh", meshSyncScript)
	golden(t, "mesh_off.sh", meshOffScript)
	golden(t, "snmp_sync.sh", snmpSyncScript)
	golden(t, "schedule.sh", scheduleScript)
	golden(t, "schedule_sync.sh", scheduleSyncScript("unifi_radio0_12 on - 0 0\nunifi_radio0_12 on mon 0800 0900\n"))
	golden(t, "schedule_sync_none.sh", scheduleSyncScript(""))
	golden(t, "users.sh", usersScript)
}
