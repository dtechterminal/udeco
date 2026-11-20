// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"strconv"
	"strings"
)

// Live driver settings: what the drivers take only through `iwpriv set`
// (never from the profile), or take at once that way without a restart.
//
//   - each BSS's AssocReqRssiThres (Set_AP_ASSOC_REQ_RSSI_THRESHOLD: an
//     association request below it is refused; per BSS, -100..0, 0 off).
//     A radio restart is assumed to lose it, so it is sent again after
//     each one;
//   - the radio's power (RadioDef.TxLive), when only the power changed
//     (applyLive); a restart reads it from the profile.
//
// None of them is ever sent inside a radio restart or its settle time
// (restartgate.go): they are queued (a.due, a.txDue) and sent by the
// first Apply or Tick after the settle time, which hold a.mu.

// queueLive marks band's per-BSS settings for sending; tx also its power.
func (a *Applier) queueLive(band string, tx bool) {
	if a.due == nil {
		a.due, a.txDue = map[string]bool{}, map[string]bool{}
	}
	a.due[band] = true
	if tx {
		a.txDue[band] = true
	}
}

// flushLive sends the queued live settings of the radios a.live serves
// (a.mu held). Outside a restart's settle time only; a failure stays
// queued for the next Tick.
func (a *Applier) flushLive(ctx context.Context) {
	if a.settling() || a.live == nil {
		return
	}
	for _, rd := range a.o.Layout {
		if !a.due[rd.Band] {
			continue
		}
		rp := a.live[rd.Band]
		if !rp.On {
			delete(a.due, rd.Band)
			delete(a.txDue, rd.Band)
			continue
		}
		var errs []string
		if a.txDue[rd.Band] && rd.TxLive != "" && a.isUp(rd.Ifaces[0]) {
			if err := a.run(ctx, "iwpriv", rd.Ifaces[0], "set", rd.TxLive+"="+strconv.Itoa(rp.TxPct)); err != nil {
				errs = append(errs, err.Error())
			} else {
				delete(a.txDue, rd.Band)
			}
		}
		for i := range rp.BSS {
			ifc := a.ifaceOf(rd, rp, i)
			if !a.isUp(ifc) {
				continue
			}
			if err := a.run(ctx, "iwpriv", ifc, "set", "AssocReqRssiThres="+strconv.Itoa(rp.MinRSSI)); err != nil {
				errs = append(errs, err.Error())
			}
		}
		if len(errs) > 0 {
			a.o.Logf("mtkwifi: %s: live settings: %s (retried at the next tick)", rd.Band, strings.Join(errs, "; "))
			continue
		}
		delete(a.due, rd.Band)
	}
}

// ifaceOf is the netdev serving rp.BSS[i] on rd.
func (a *Applier) ifaceOf(rd RadioDef, rp RadioPlan, i int) string { return rd.Ifaces[rp.slot(i)] }

// bssOf maps rd's netdevs to the index of the BSS of rp each serves.
func bssOf(rd RadioDef, rp RadioPlan) map[string]int {
	m := map[string]int{}
	for i := range rp.BSS {
		if s := rp.slot(i); s < len(rd.Ifaces) {
			m[rd.Ifaces[s]] = i
		}
	}
	return m
}

// clearLive sets the per-BSS live settings back to the drivers' defaults
// on every up BSS of the radios the agent set them on (the hand-back:
// the vendor never sets them). Skipped inside a restart's settle time:
// the radio restart that follows is then the only reset.
func (a *Applier) clearLive(ctx context.Context) {
	if a.settling() {
		return
	}
	for _, rd := range a.o.Layout {
		if rp, ok := a.live[rd.Band]; !ok || !rp.On || rp.MinRSSI == 0 {
			continue
		}
		for _, ifc := range rd.Ifaces {
			if a.isUp(ifc) {
				_ = a.run(ctx, "iwpriv", ifc, "set", "AssocReqRssiThres=0")
			}
		}
	}
	a.due, a.txDue, a.weak = nil, nil, nil
}
