// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import "testing"

// The agent reads certs (RadSec), mdns_sd (mDNS bridge) and snmp (SNMP
// agent): none of them goes to the unhandled ledger.
func TestAgentSectionsHandled(t *testing.T) {
	for _, s := range []string{"certs", "mdns_sd", "snmp"} {
		if !Handled(s) {
			t.Errorf("%s not handled", s)
		}
	}
}
