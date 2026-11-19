// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/models"
)

// Radio naming (docs/deco/agent-design.md §3.8).
//
// The controller treats a U6-Lite as a MediaTek AP and names its VAPs after
// the radio_table names: ra0, ra1, ... on 2.4 GHz and rai0, rai1, ... on
// 5 GHz when the radios are reported as ra0 and rai0 (a real U6-Lite). With
// the Qualcomm names wifi0/wifi1 the devnames are wifi0, wifi1, wifi2, ... on
// 2.4 GHz and wifi1, wifi1, wifi2, ... on 5 GHz: the first two 5 GHz SSIDs
// share wifi1 (and a second or third 2.4 GHz SSID shares a 5 GHz name), so
// those VAPs cannot be told apart in system_cfg's bridge port lists (one of
// them is put on the other's bridge).
//
// The controller never drops a radio row it was sent (rows are matched by
// name), so renaming the radios of an adopted AP would leave it with four
// radios and every WLAN deployed twice per band. Hence the naming is part of
// the persisted state and changes only when the controller forgets the AP:
//   - a new state (no state.json): MediaTek names;
//   - a state written by an earlier build (no radio_names): Qualcomm names,
//     the ones that build reported, kept for as long as that adoption lasts;
//   - setdefault (the AP was removed from the controller): MediaTek names from
//     the next inform on, so the re-adoption starts with ra0/rai0.
const (
	radioNamesMediaTek = "mediatek"
	radioNamesQualcomm = "qualcomm"
)

// chooseRadioNames sets st.RadioNames when it is not chosen yet; found tells
// whether st was loaded from disk. It reports whether st changed.
func chooseRadioNames(st *device.State, found bool) bool {
	switch st.RadioNames {
	case radioNamesMediaTek, radioNamesQualcomm:
		return false
	}
	st.RadioNames = radioNamesMediaTek
	if found {
		st.RadioNames = radioNamesQualcomm
	}
	return true
}

// radioNameMap is apstate.CfgInfo.RadioNames for the state's naming (nil:
// wifiN by position).
func radioNameMap(naming string) map[string]string {
	if naming == radioNamesQualcomm {
		return nil
	}
	return models.DecoAgentRadioNames()
}

// renameRadios gives the session's static radio rows (inform.Device.Radios)
// the names of the state's naming. Loop goroutine (or setup).
func (a *agent) renameRadios() {
	names := radioNameMap(a.x.S.RadioNames)
	for i := range a.x.Dev.Radios {
		r := &a.x.Dev.Radios[i]
		if n := names[r.Radio]; n != "" {
			r.Name = n
		} else {
			r.Name = fmt.Sprintf("wifi%d", i)
		}
	}
}

// radioNamesAfterReset switches to MediaTek names once the controller has
// forgotten the AP (setdefault), and saves the state. Loop goroutine.
func (a *agent) radioNamesAfterReset() {
	if a.x.S.RadioNames == radioNamesMediaTek {
		return
	}
	a.x.S.RadioNames = radioNamesMediaTek
	a.renameRadios()
	if err := a.x.S.Save(a.statePath); err != nil {
		a.logf("state %s: %v", a.statePath, err)
	}
	a.logf("radio names: ra0/rai0 (MediaTek, as a real U6-Lite) from now on: the controller forgot this AP, so adopting it again starts without the old wifi0/wifi1 rows")
}

// logRadioNames says which naming the session reports, and what the
// Qualcomm one costs. Setup only.
func (a *agent) logRadioNames() {
	if a.x.S.RadioNames == radioNamesQualcomm {
		a.logf("radio names: wifi0/wifi1 (kept from the adoption made by an earlier build): the controller names the first two 5 GHz SSIDs (and the second 2.4 GHz one) wifi1, so such SSIDs on different networks share a bridge entry; Forget the AP in the controller and adopt it again to switch to ra0/rai0")
		return
	}
	a.logf("radio names: ra0/rai0 (MediaTek, as a real U6-Lite)")
}
