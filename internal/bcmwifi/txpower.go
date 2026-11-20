// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"encoding/json"
	"fmt"
	"math"
	"path"
	"strings"
)

// Transmit power presets (docs/deco/features/tx-power.md). A U6 Pro maps
// the controller's tx_power_mode onto its radio's range: high (and auto) =
// the radio's maximum for the channel and country, low = its minimum,
// medium = halfway, custom = the controller's dBm within the range. The
// X20's only knob is `wl txpwr_degrade` (quarter dB below the target
// power, live), so:
//
//   - the ceiling is the radio's `txpwr_target_max` read while
//     txpwr_degrade is 0 (the board and regulatory limit for the chanspec,
//     what high transmits), kept per radio and chanspec in
//     RunDir/txpwr-ceiling.json: whether the target maximum moves with
//     txpwr_degrade is not known, so a degraded reading never replaces a
//     learnt ceiling. A chanspec with none learnt yet (a degraded radio
//     after a reboot of the agent but not the unit, a channel change) takes
//     the reading plus the live degrade once, or the old chanspec's
//     ceiling, and keeps that.
//   - the floor is txMinDBm (5 dBm, as the collector's min_txpower).
//
// The controller is told the mode and the resulting dBm (TxPower), not
// "custom" and the target maximum.

// txMinDBm is the floor of the range (wl has no getter for it; the
// collector reports the same, internal/wl minTxDBm).
const txMinDBm = 5

// txpwrDegrade maps a UniFi tx power mode to wl txpwr_degrade (quarter-dB
// below the radio's ceiling, see above). ceiling <= 0: unknown.
func txpwrDegrade(r Radio, ceiling float64) (q int, note string) {
	mode := strings.ToLower(r.TxPowerMode)
	if ceiling <= 0 {
		switch mode {
		case "", "auto", "high":
			return 0, ""
		case "medium", "middle":
			return 12, "tx power ceiling unknown: medium is 3 dB below it"
		case "low":
			return 24, "tx power ceiling unknown: low is 6 dB below it"
		case "custom":
			return 0, "custom tx power: the radio's ceiling is unknown, using high"
		}
		return 0, fmt.Sprintf("tx power mode %q unknown, using high", r.TxPowerMode)
	}
	span := math.Max(0, ceiling-txMinDBm)
	switch mode {
	case "", "auto", "high":
		return 0, ""
	case "medium", "middle":
		return int(math.Round(span * 2)), ""
	case "low":
		return int(math.Round(span * 4)), ""
	case "custom":
		p := float64(r.TxPower)
		switch {
		case p > ceiling:
			note = fmt.Sprintf("custom tx power %d dBm above the radio's %.2f dBm: clamped", r.TxPower, ceiling)
			p = ceiling
		case p < txMinDBm:
			note = fmt.Sprintf("custom tx power %d dBm below the floor: clamped to %d dBm", r.TxPower, txMinDBm)
			p = txMinDBm
		}
		return int(math.Round((ceiling - p) * 4)), note
	}
	return 0, fmt.Sprintf("tx power mode %q unknown, using high", r.TxPowerMode)
}

// txReportFor is the mode and power the controller is told for r on a
// radio with ceiling, written with degrade q (dBm 0: unknown).
func txReportFor(r Radio, ceiling float64, q int) (mode string, dbm int) {
	switch mode = strings.ToLower(r.TxPowerMode); mode {
	case "":
		mode = "auto"
	case "middle":
		mode = "medium"
	case "auto", "high", "medium", "low", "custom":
	default:
		mode = "high"
	}
	if ceiling > 0 {
		dbm = int(math.Round(ceiling - float64(q)/4))
	}
	return mode, dbm
}

// txReport is a band's tx power as last planned.
type txReport struct {
	Mode string
	DBm  int
}

// TxPower is band's tx power mode and power (dBm) as the last plan set
// them; ok is false before a plan or for a band the agent does not run.
func (a *Applier) TxPower(band string) (mode string, dbm int, ok bool) {
	a.txMu.Lock()
	defer a.txMu.Unlock()
	r, ok := a.txRep[band]
	return r.Mode, r.DBm, ok && r.DBm > 0
}

// LiveChannel is band's control channel as the last plan read it (0
// before a plan).
func (a *Applier) LiveChannel(band string) int {
	a.txMu.Lock()
	defer a.txMu.Unlock()
	return a.liveCh[band]
}

func (a *Applier) setLiveChannel(band string, ch int) {
	a.txMu.Lock()
	defer a.txMu.Unlock()
	if a.liveCh == nil {
		a.liveCh = map[string]int{}
	}
	a.liveCh[band] = ch
}

func (a *Applier) setTxReport(band string, r txReport) {
	a.txMu.Lock()
	defer a.txMu.Unlock()
	if a.txRep == nil {
		a.txRep = map[string]txReport{}
	}
	a.txRep[band] = r
}

func (a *Applier) txCeilPath() string { return path.Join(a.o.RunDir, "txpwr-ceiling.json") }

// txCeiling is the radio's ceiling on cs (see above): the reading with no
// degrade (learnt), else the learnt one, else an estimate kept from now
// on. moved: cs is a chanspec the plan moves to (from cur), whose ceiling
// is the learnt one or cur's.
func (a *Applier) txCeiling(p string, cur, cs chanspec, degrade int, targetMax float64) (c float64, note string) {
	a.txMu.Lock()
	defer a.txMu.Unlock()
	if a.txCeil == nil {
		a.txCeil = map[string]float64{}
		if b, err := a.readFile(a.txCeilPath()); err == nil {
			_ = json.Unmarshal(b, &a.txCeil)
		}
	}
	key := func(c chanspec) string { return p + " " + c.String() }
	set := func(k string, v float64) {
		if a.txCeil[k] == v {
			return
		}
		a.txCeil[k] = v
		if a.o.DryRun {
			return
		}
		if b, err := json.Marshal(a.txCeil); err == nil {
			if err := writeFileAtomic(a.fsPath(a.txCeilPath()), b, 0o644); err != nil {
				a.o.Logf("bcmwifi: tx power ceiling: %v", err)
			}
		}
	}
	// the live chanspec's
	switch v, ok := a.txCeil[key(cur)]; {
	case degrade == 0 && targetMax > 0:
		set(key(cur), targetMax)
		c = targetMax
	case ok:
		c = v
	case targetMax > 0:
		c = targetMax + float64(degrade)/4
		set(key(cur), c)
		note = fmt.Sprintf("tx power ceiling on %s estimated from a degraded reading: %.2f dBm", cur, c)
	}
	if cs == cur {
		return c, note
	}
	if v, ok := a.txCeil[key(cs)]; ok {
		return v, ""
	}
	if c > 0 {
		set(key(cs), c)
		return c, fmt.Sprintf("tx power ceiling on %s taken from %s until it is read: %.2f dBm", cs, cur, c)
	}
	return 0, note
}
