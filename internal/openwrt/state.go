// SPDX-License-Identifier: GPL-2.0-or-later

package openwrt

// The reading model and its UniFi rendering live in internal/apstate, so a
// binary that only renders readings (the Deco agent) does not link this
// package's SSH client. The names stay here for the OpenWrt tools.

import "github.com/antoniocosta/unifi-openwrt/internal/apstate"

type (
	Snapshot      = apstate.Snapshot
	FDBEntry      = apstate.FDBEntry
	Radio         = apstate.Radio
	Survey        = apstate.Survey
	Station       = apstate.Station
	Port          = apstate.Port
	LLDPNeighbor  = apstate.LLDPNeighbor
	BSS           = apstate.BSS
	ChanSurvey    = apstate.ChanSurvey
	ScanResult    = apstate.ScanResult
	SpectrumEntry = apstate.SpectrumEntry
	RadioCaps     = apstate.RadioCaps
	CfgInfo       = apstate.CfgInfo
	SatResult     = apstate.SatResult
)

var (
	ParseScan    = apstate.ParseScan
	ParseSurvey  = apstate.ParseSurvey
	SurveyDelta  = apstate.SurveyDelta
	Spectrum     = apstate.Spectrum
	ScanTable    = apstate.ScanTable
	SpectrumRows = apstate.SpectrumRows
	SplitBands   = apstate.SplitBands
	KeepSeen     = apstate.KeepSeen
	InfoFromCfg  = apstate.InfoFromCfg
	WLANIDs      = apstate.WLANIDs
)

func freqChannel(f int) int       { return apstate.FreqChannel(f) }
func channelFreq(ch, ref int) int { return apstate.ChannelFreq(ch, ref) }

func parentDevice(bssid string, neigh map[string]string) string {
	return apstate.ParentDevice(bssid, neigh)
}
