// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Connection-timing events on the Garage (platform jio-mtk; sta_snoop,
// docs/deco/features/connection-events.md "Garage"). There is no hostapd:
// the steps a Deco takes from hostapd's log and control sockets come from
// the MediaTek drivers' own events (mtkwifi Events, EventsOptions.Steps),
// and the station's frames from the same read-only taps on its BSS
// (ra0-ra3, rai0-rai3):
//
//	driver step                          tracker input (as on the Deco)
//	Insert (MAC entry, at authentication) anchorAuth on the event's BSS
//	MT7663 0x200 associated              anchorAssoc
//	MT7663 0x20D/0x20E key done, WAPP 6  hapdmon.Connected (authorizes the
//	                                     open attempt only: mt_wifi also
//	                                     sends both at a group rekey's end,
//	                                     PeerGroupMsg2Action)
//	MT7663 0x207 MIC different, ECNT 14  hapdmon.PSKMismatch
//	MT7663 0x20B handshake timeout, ECNT 15  anchorEAPOLTimeout
//	Delete (released leave)              hapdmon.Disconnected (staFeed)
//
// The MT7663's system log events name the radio's main netdev, not the
// BSS: such a step goes on the station's open attempt's BSS, else the BSS
// the reading lists it on (connTracker.vifOf). The 2.4 GHz driver (the
// rebuilt MT7603) reports only the Insert: its stations are authorized at
// their first frame on the tap (connTracker.frameAuth), so its events
// carry assoc_delta and wpa_auth_delta 0 (not measured), and a failed
// 2.4 GHz join (wrong passphrase) is never reported.

import (
	"regexp"

	"github.com/dtechterminal/udeco/internal/hapdmon"
	"github.com/dtechterminal/udeco/internal/mtkwifi"
)

// mtkBSSRE: the JCOW414's BSS netdevs (mtkwifi.JCOW414 Ifaces).
var mtkBSSRE = regexp.MustCompile(`^rai?[0-9]$`)

// mtkBSS: vif is one of the JCOW414's BSS netdevs.
func mtkBSS(vif string) bool { return mtkBSSRE.MatchString(vif) }

// drvStep turns a driver join step into the tracker's input; ok false for
// a step that is none. A radio-wide event's BSS is left "" (vifOf).
func drvStep(e mtkwifi.DrvEvent) (connIn, bool) {
	vif := e.Ifname
	if !mtkBSS(vif) {
		vif = ""
	}
	anchor := func(k anchorKind) (connIn, bool) {
		return connIn{at: e.At, anchor: &staAnchor{Vif: vif, MAC: e.MAC, Kind: k}, drv: true}, true
	}
	sock := func(k hapdmon.Kind) (connIn, bool) {
		return connIn{at: e.At, sock: &hapdmon.Event{Vif: vif, MAC: e.MAC, Kind: k, At: e.At}, drv: true}, true
	}
	switch {
	case e.MAC == "" || normMAC(e.MAC) != e.MAC:
		return connIn{}, false
	case e.Kind == mtkwifi.DrvInsert:
		if vif == "" {
			return connIn{}, false // an Insert always names its BSS
		}
		return anchor(anchorAuth)
	case e.Kind == mtkwifi.DrvAssoc:
		// the system log names rai0 for every BSS of the radio
		vif = ""
		return anchor(anchorAssoc)
	case e.Kind == mtkwifi.DrvKeyDone:
		vif = ""
		return sock(hapdmon.Connected)
	case e.Kind == mtkwifi.DrvAuthorized:
		return sock(hapdmon.Connected)
	case e.Kind == mtkwifi.DrvMICDiff:
		vif = ""
		return sock(hapdmon.PSKMismatch)
	case e.Kind == mtkwifi.DrvHSTimeout:
		vif = ""
		return anchor(anchorEAPOLTimeout)
	case e.Kind == mtkwifi.DrvFailure && e.Reason == 14:
		return sock(hapdmon.PSKMismatch)
	case e.Kind == mtkwifi.DrvFailure && e.Reason == 15:
		return anchor(anchorEAPOLTimeout)
	}
	return connIn{}, false
}
