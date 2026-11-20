// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/models"
)

// The model the controller holds for this unit.
//
// The controller takes a device's model from the discovery inform of a unit
// not adopted yet, and never from an adopted device's informs (Network
// 10.6.109: the adopted path copies serial, ip, version... but not the
// model; getModel() prefers the stored sysid). So a config that changes
// "model" on an adopted unit (jio-mtk: U7LT <-> UHDIW) leaves the old model
// in UniFi: a record of the old model fed the new model's informs. The
// state keeps the model it was adopted as (device.State.Model), and while
// it differs from the config the agent says so loudly and claims no port
// VLANs (the old model's record has no UAP-IW-HD switch rules). Forget the
// AP in UniFi and adopt it again (the pending entry shows the config's
// model), then restart the agent.

// legacyAdoptedModel is the model a state written before State.Model was
// adopted as: earlier builds accepted only U7LT on jio-mtk and UAL6 on a
// Deco. These are the codes those builds used, whatever the defaults
// (models.DecoAgentModel) become.
func (a *agent) legacyAdoptedModel() string {
	if a.cfg.jio() {
		return models.ModelU7LT
	}
	return models.ModelUAL6
}

// checkAdoptedModel fills st.Model for an adopted state of an earlier build
// and sets a.modelHeld when the controller holds another model than the
// config's. It reports whether st changed. Setup only.
func (a *agent) checkAdoptedModel(st *device.State) bool {
	changed := false
	if st.Adopted && st.Model == "" {
		st.Model = a.legacyAdoptedModel()
		changed = true
	}
	a.modelHeld = ""
	if st.Adopted && st.Model != a.cfg.Model {
		a.modelHeld = st.Model
	}
	return changed
}

// logModelHeld reports a held model (setup, once the event ring is open).
func (a *agent) logModelHeld() {
	if a.modelHeld == "" {
		return
	}
	a.event(fmt.Sprintf("MODEL NOT CHANGED IN UNIFI: this unit is adopted as %s and the controller keeps that model; the config says %s. "+
		"Port VLANs are off until it is adopted again: Forget the AP in UniFi, adopt it again (the pending entry must show %s), then restart the agent",
		a.modelHeld, a.cfg.Model, a.cfg.Model))
}

// modelAfterReset: the controller forgot the AP (setdefault); the next
// adoption takes the config's model. Loop goroutine.
func (a *agent) modelAfterReset() {
	if a.modelHeld == "" {
		return
	}
	a.logf("model: the controller forgot this unit (it was adopted as %s): adopting it again makes it a %s; restart the agent after the adoption to claim port VLANs",
		a.modelHeld, a.cfg.Model)
}
