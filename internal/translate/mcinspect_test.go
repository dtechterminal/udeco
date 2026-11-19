// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"reflect"
	"strings"
	"testing"
)

func TestMulticastInspect(t *testing.T) {
	// the lines the controller writes (docs/reference/u6pro/config-apply/
	// tmp_system.cfg.redacted: wireless.N.multicast.inspect=true)
	cfg := ParseCfg(strings.Join([]string{
		"wireless.1.devname=wifi0ap0", "wireless.1.status=enabled", "wireless.1.multicast.inspect=true",
		"wireless.2.devname=wifi1ap1", "wireless.2.status=enabled", "wireless.2.multicast.inspect=false",
		"wireless.3.devname=wifi1ap2", "wireless.3.status=disabled", "wireless.3.multicast.inspect=true",
		"wireless.4.devname=wifi1ap3", "wireless.4.status=enabled",
	}, "\n"))
	if got, want := MulticastInspect(cfg), map[string]bool{"wifi0ap0": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("MulticastInspect = %v, want %v", got, want)
	}
}
