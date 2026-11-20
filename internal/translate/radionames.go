// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"strconv"

	"github.com/antoniocosta/unifi-openwrt/internal/rf"
)

// radioNames is the one table of the radio names UniFi uses (radio_table
// "name", system_cfg radio.N.phyname and wireless.N.parent) and the band
// each stands for when nothing else tells. Qualcomm APs name their radios
// by position (PositionalRadioName); MediaTek ones ra0 and rai0, the names
// the agent reports too (models.DecoAgentRadioNames; apstate's test holds
// the two together).
var radioNames = []struct {
	name, band string
	mtk        bool // a MediaTek name
}{
	{PositionalRadioName(0), rf.Band2G, false},
	{PositionalRadioName(1), rf.Band5G, false},
	{PositionalRadioName(2), rf.Band6G, false},
	{"ra0", rf.Band2G, true},
	{"rai0", rf.Band5G, true},
}

// PositionalRadioName is the name of a unit's i-th radio (from 0) when
// radios are named by position: wifi0, wifi1, ...
func PositionalRadioName(i int) string { return "wifi" + strconv.Itoa(i) }

// RadioNameBand is the band a radio's name stands for: wifi0 and ra0 ng,
// wifi1 and rai0 na, wifi2 6e. ok is false for any other name.
func RadioNameBand(name string) (band string, ok bool) { return radioNameBand(name, true) }

// qcaRadioBand is RadioNameBand without the MediaTek names, for the
// OpenWrt path (Plan, WLANs): its APs are adopted as Qualcomm models, and
// a parent named ra0 or rai0 has no band there.
func qcaRadioBand(name string) (band string, ok bool) { return radioNameBand(name, false) }

func radioNameBand(name string, mtk bool) (string, bool) {
	for _, r := range radioNames {
		if r.name == name && (mtk || !r.mtk) {
			return r.band, true
		}
	}
	return "", false
}
