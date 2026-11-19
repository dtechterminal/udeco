// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"strings"
	"testing"
)

func TestPathmonHandledAndNoted(t *testing.T) {
	if !Handled("pathmon") {
		t.Error("pathmon is not a handled section (it would land in the unhandled ledger)")
	}
	cfg := "pathmon.status=enabled\npathmon.target.1.type=gateway\npathmon.target.2.type=host\npathmon.target.2.addr=nas.lan\n"
	_, notes := IntentFromCfg(cfg)
	all := strings.Join(notes, "\n")
	if strings.Contains(all, "pathmon: not supported") {
		t.Errorf("pathmon still noted as unsupported:\n%s", all)
	}
	if !strings.Contains(all, `pathmon target 2: host address "nas.lan" is not an IPv4 address`) {
		t.Errorf("skipped host target not noted:\n%s", all)
	}
}
