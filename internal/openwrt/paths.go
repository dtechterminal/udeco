// SPDX-License-Identifier: GPL-2.0-or-later

package openwrt

// Where unifi-openwrt lives on the AP. The scripts this package runs there
// (mesh.go, schedule.go, snmp.go, users.go) are built from these constants.
// The package's own files name the same directory and service and cannot
// read them: packaging/files/etc/init.d/unifi-openwrt, packaging/install.sh
// and packaging/openwrt/unifi-openwrt/Makefile are held to them by
// TestInitScriptNames and TestStateDirWhereItIsMade.
const (
	// ConfDir holds what the daemon and its scripts keep on the AP: the
	// daemon's state directory (the init script's STATE), the mesh watcher
	// and its config, the WLAN schedule, snmpd.conf and the list of the
	// logins the daemon added.
	ConfDir = "/etc/unifi-openwrt"
	// Service is the procd service that runs the daemon and, as instances
	// of their own, the mesh watcher (meshInstance) and snmpd (snmpInstance).
	Service = "unifi-openwrt"
	// initScript is the service's init script: "reload" starts and stops
	// the instances whose files have come or gone.
	initScript = "/etc/init.d/" + Service
)
