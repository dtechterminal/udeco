// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/device"
	"github.com/dtechterminal/udeco/internal/models"
)

// writeAdoptedState stores an adopted state (model "" = written by an
// earlier build) and points the fake controller at its key.
func writeAdoptedState(t *testing.T, h *harness, model string) {
	t.Helper()
	st := device.NewState(h.cfg.InformURL)
	st.Key, st.Adopted, st.Model, st.RadioNames = testKey, true, model, radioNamesMediaTek
	b, _ := json.Marshal(st)
	if err := os.WriteFile(h.a.statePath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	h.ctl.mu.Lock()
	h.ctl.key = testKey
	h.ctl.mu.Unlock()
}

// TestJioModelHeldByController: the Garage AP was adopted as U7LT by an
// earlier build (no model in state.json); its config now says UHDIW. The
// controller keeps U7LT for an adopted device, so the agent says so and
// claims no port VLANs: no switch bits, no port changes, until a Forget.
func TestJioModelHeldByController(t *testing.T) {
	h, pw := jioPortsHarness(t)
	writeAdoptedState(t, h, "")
	h.ctl.queue(provisionReply(testCfg + switchCfg))
	h.start()
	eventually(t, "the provision taken", func() bool { return h.ctl.pending() == 0 && h.ctl.count() >= 3 })
	m := h.ctl.last()
	h.stop()
	if int(num(m["fw_caps"]))&(models.FWCapQCASwitch|models.FWCapOWRTSwitch) != 0 {
		t.Errorf("switch bits claimed while UniFi holds U7LT: fw_caps %v", m["fw_caps"])
	}
	if ops := pw.opsList(); len(ops) != 0 {
		t.Errorf("ports changed: %v", ops)
	}
	logs := h.logs.all()
	for _, want := range []string{"MODEL NOT CHANGED IN UNIFI: this unit is adopted as U7LT", "ports: port VLANs are not applied"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %q:\n%s", want, logs)
		}
	}
	st, _, err := device.Load(h.a.statePath)
	if err != nil || st.Model != "U7LT" {
		t.Errorf("state model %q (%v), want the earlier build's U7LT recorded", st.Model, err)
	}
}

// TestJioModelAdoptedAsConfigured: a state adopted as UHDIW (or a new
// adoption) runs the ports as usual and records the model.
func TestJioModelAdoptedAsConfigured(t *testing.T) {
	h, pw := jioPortsHarness(t)
	writeAdoptedState(t, h, "UHDIW")
	h.ctl.queue(provisionReply(testCfg + switchCfg))
	h.start()
	eventually(t, "ports applied", func() bool { return len(pw.opsList()) >= 3 })
	h.stop()
	if strings.Contains(h.logs.all(), "MODEL NOT CHANGED") {
		t.Errorf("held model reported for a UHDIW adoption")
	}

	h2, pw2 := jioPortsHarness(t)
	h2.ctl.queue(adoptReply, provisionReply(testCfg+switchCfg))
	h2.start()
	eventually(t, "ports applied", func() bool { return len(pw2.opsList()) >= 3 })
	h2.stop()
	if st, _, err := device.Load(h2.a.statePath); err != nil || st.Model != "UHDIW" || !st.Adopted {
		t.Errorf("new adoption: model %q adopted %v (%v)", st.Model, st.Adopted, err)
	}
}
