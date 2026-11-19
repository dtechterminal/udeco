// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
)

// A rate-update from the controller on the captured unit, takeover with
// the real bcmwifi (DryRun): the session keeps the client's limit in
// state.json, bcmwifi is handed the list, -1/-1 for an unknown client
// changes nothing, the cmd is not reported as unhandled, and nothing on the
// unit changes. 88:57:1d:bb:bb:86 is a client of wl12 in the captures.
func TestE2EClientRateUpdate(t *testing.T) {
	const capSta = "88:57:1d:bb:bb:86"
	cfg, secrets := u6proSystemCfg(t)
	e := newE2E(t, cfg, true)
	e.ctl.reply = func(in e2eInform) string {
		switch e.ctlStep {
		case 0:
			e.ctlStep = 1
			return `{"_type":"cmd","cmd":"rate-update","mac":"88:57:1D:BB:BB:86","ul_max":1000,"ul_min":64,"dl_max":4000,"dl_min":64}`
		case 1:
			e.ctlStep = 2
			return `{"_type":"cmd","cmd":"rate-update","mac":"02:00:00:00:00:c1","ul_max":-1,"ul_min":64,"dl_max":-1,"dl_min":64}`
		}
		return ""
	}
	e.adopt()
	eventually(t, "the bcmwifi dry-run apply", func() bool { return strings.Contains(e.logs.all(), "is live") })
	eventually(t, "the list handed to bcmwifi", func() bool {
		return strings.Contains(e.logs.all(), "bcmwifi dry-run: per-client limits for ["+capSta+"]")
	})
	eventually(t, "the clear for an unknown client", func() bool {
		return strings.Contains(e.logs.all(), "cmd rate-update 02:00:00:00:00:c1 down=none up=none")
	})
	e.stop()

	e.checkFlow()
	if m := e.unit.mutating(); len(m) > 0 {
		t.Errorf("DryRun takeover issued %d mutating command(s): %q", len(m), m)
	}
	logs := e.logs.all()
	if !strings.Contains(logs, "cmd rate-update "+capSta+" down=4000kbit up=1000kbit") {
		t.Error("rate-update not logged")
	}
	for _, bad := range []string{`cmd "rate-update": ignored`, `action "rate-update`, "not supported on platform"} {
		if strings.Contains(logs, bad) {
			t.Errorf("log has %q", bad)
		}
	}
	b, err := os.ReadFile(e.a.statePath)
	if err != nil {
		t.Fatal(err)
	}
	var st device.State
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if r := st.ClientRates; len(r) != 1 || r[capSta].DownKbps != 4000 || r[capSta].UpKbps != 1000 {
		t.Errorf("state.json client_rates %+v", r)
	}
	// the reply fields are read: nothing for the unhandled ledger
	for _, u := range e.a.x.Unhandled.Entries() {
		if u.Name == "rate-update" || strings.HasSuffix(u.Name, "_max") || strings.HasSuffix(u.Name, "_min") {
			t.Errorf("reported as unhandled: %+v", u)
		}
	}
	e.checkNoSecrets(secrets)
}
