// SPDX-License-Identifier: GPL-2.0-or-later

package device

import "strings"

// What a reply asks a real AP to do (Outcome.Actions): a verb, for some
// with an argument after a colon. The session writes these texts with
// Action and each agent's action switch reads them with SplitAction, so
// both sides name a verb by its constant. Actions lists them all: each
// agent's test holds its switch to that list.
const (
	ActReboot       = "reboot"        // restart the AP
	ActLED          = "led"           // led:on, led:off (mgmt_cfg led_enabled)
	ActLocate       = "locate"        // locate:on, locate:off
	ActKick         = "kick"          // kick:<mac>
	ActBlock        = "block"         // enforce the blocked list (State.Blocked)
	ActUnblock      = "unblock"       // unblock:<mac>; the new list follows with ActBlock
	ActScan         = "scan"          // neighbour scan
	ActScanBand     = "scan-band"     // scan-band:<band>: neighbour scan of one band
	ActSpectrumScan = "spectrum-scan" // RF scan
	ActQuickScan    = "quick-scan"    // quick-scan:<band>:<width in MHz, 0 = not sent>
	ActGuestAuth    = "guest-auth"    // guest-auth:<mac> (until State.Guests[mac])
	ActGuestUnauth  = "guest-unauth"  // guest-unauth:<mac>
	ActRateUpdate   = "rate-update"   // rate-update:<mac>: apply State.ClientRates
)

// ArgOn and ArgOff are the argument of ActLED and ActLocate.
const (
	ArgOn  = "on"
	ArgOff = "off"
)

// Actions are all the verbs. Each call returns a new slice.
func Actions() []string {
	return []string{ActReboot, ActLED, ActLocate, ActKick, ActBlock, ActUnblock, ActScan, ActScanBand, ActSpectrumScan,
		ActQuickScan, ActGuestAuth, ActGuestUnauth, ActRateUpdate}
}

// Action is the text of an action: the verb, then each argument after a
// colon.
func Action(verb string, args ...string) string {
	return strings.Join(append([]string{verb}, args...), ":")
}

// SplitAction is an action's verb and its argument ("" when it has none).
// The argument keeps its own colons: a MAC, or ActQuickScan's
// "<band>:<width>".
func SplitAction(a string) (verb, arg string) {
	verb, arg, _ = strings.Cut(a, ":")
	return verb, arg
}

// onOff is the argument for a switch that is on or off.
func onOff(on bool) string {
	if on {
		return ArgOn
	}
	return ArgOff
}
