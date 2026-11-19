// SPDX-License-Identifier: GPL-2.0-or-later

package translate

// Sections the Deco agent reads outside the WLAN intent, so the unhandled
// ledger (device.OpenLedger with Handled) does not list them:
//   - certs: RadSec certificates, read by radsecTLS for each TLS RADIUS
//     server (radsec.go);
//   - mdns_sd: the mDNS service bridge, read by internal/mdnsbr
//     (cmd/udeco-ap/mdnsbr.go).
//
// snmp is in handled already (cmd/udeco-ap/snmp.go, internal/snmpagent).
func init() {
	handled["certs"] = true
	handled["mdns_sd"] = true
}
