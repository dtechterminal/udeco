// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
)

// ourVifs lists the vifs that have a control socket under CtrlDir, i.e. the
// BSSes the agent's hostapd serves now, without the placeholder wlN1.
func (a *Applier) ourVifs() []string {
	ents, err := os.ReadDir(a.fsPath(CtrlDir))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if ServedVif(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

// ServedVif reports whether a control socket under CtrlDir is a BSS the
// agent serves clients on (not the backhaul placeholder wlN1).
func ServedVif(name string) bool { return strings.HasPrefix(name, "wl") && !isBackhaul(name) }

func (a *Applier) hostapdCLI(ctx context.Context, vif string, args ...string) error {
	argv := append([]string{"-p", CtrlDir, "-i", vif}, args...)
	if a.o.DryRun {
		a.o.Logf("bcmwifi dry-run: hostapd_cli %s", strings.Join(argv, " "))
		return nil
	}
	out, err := a.o.Run.Run(ctx, "hostapd_cli", argv...)
	if err != nil {
		return fmt.Errorf("hostapd_cli -i %s %s: %w", vif, args[0], err)
	}
	if s := strings.TrimSpace(string(out)); !strings.HasSuffix(s, "OK") {
		return fmt.Errorf("hostapd_cli -i %s %s: %q", vif, args[0], firstLine(s))
	}
	return nil
}

// Kick deauthenticates mac from every BSS the agent serves (hostapd_cli
// deauthenticate; a station not on a BSS is unaffected). It returns
// ErrNotOwned when the agent serves no BSS, and an error only when no BSS
// accepted the request.
func (a *Applier) Kick(ctx context.Context, mac string) error {
	m := normMAC(mac)
	if m == "" {
		return fmt.Errorf("bcmwifi: kick: bad MAC %q", mac)
	}
	vifs := a.ourVifs()
	if len(vifs) == 0 {
		return ErrNotOwned
	}
	var lastErr error
	ok := 0
	for _, v := range vifs {
		if err := a.hostapdCLI(ctx, v, "deauthenticate", m); err != nil {
			lastErr = err
			continue
		}
		ok++
	}
	if ok == 0 {
		return fmt.Errorf("bcmwifi: kick %s: %w", m, lastErr)
	}
	return nil
}

func (a *Applier) blockedPath() string { return path.Join(a.o.RunDir, "blocked.txt") }

// loadBlocked returns the block list, reading RunDir/blocked.txt on first
// use (so an agent restart within a boot keeps it).
func (a *Applier) loadBlocked() []string {
	if a.blocked == nil {
		var macs []string
		if b, err := a.readFile(a.blockedPath()); err == nil {
			macs, _ = normMACs(strings.Fields(string(b)))
		}
		a.blocked = append([]string{}, macs...)
	}
	return append([]string(nil), a.blocked...)
}

// SetBlocked replaces the block list. Blocked stations are denied on every
// BSS through hostapd's deny list (file and live DENY_ACL), removed from
// allow-lists, put in the driver MAC filter (which also hides probe
// responses), and kicked; the flows of every newly blocked or unblocked
// station are flushed from the flow cache (audit R21). The list is kept in
// RunDir/blocked.txt and folded into every later Plan. When the agent does
// not own Wi-Fi yet, the list is only stored.
func (a *Applier) SetBlocked(ctx context.Context, macs []string) error {
	list, bad := normMACs(macs)
	if bad > 0 {
		a.o.Logf("bcmwifi: block list: %d invalid MACs ignored", bad)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	old := a.loadBlocked()
	if a.o.DryRun {
		a.o.Logf("bcmwifi dry-run: block list %v", list)
	} else {
		data := []byte(strings.Join(list, "\n"))
		if err := writeFileAtomic(a.fsPath(a.blockedPath()), data, 0o600); err != nil {
			return err
		}
		a.blocked = append([]string{}, list...)
	}
	d := a.applied
	if d == nil && len(a.ourVifs()) > 0 {
		if lg, err := a.loadLastGood(); err == nil {
			d = lg
		}
	}
	if d == nil {
		return nil
	}
	if err := a.refreshACLs(ctx, *d, old, list); err != nil {
		return err
	}
	added := minus(list, old)
	for _, m := range added {
		if err := a.Kick(ctx, m); err != nil && err != ErrNotOwned {
			a.o.Logf("bcmwifi: kick blocked %s: %v", m, err)
		}
	}
	for _, m := range append(added, minus(old, list)...) {
		if err := a.flushFlows(ctx, FlowScope{MAC: m}); err != nil {
			a.o.Logf("%v", err)
		}
	}
	return nil
}

// refreshACLs rewrites the ACL files and driver state of every placed vif
// for blocked, and updates the live hostapd and driver lists without a
// restart. hostapd's lists are changed by difference against the ones
// built from old (what the files, and so hostapd, hold now), never with
// CLEAR: with macaddr_acl=1 an emptied accept list disassociates every
// station on the BSS, so CLEAR-then-re-add would drop all clients of an
// allow-list SSID on each block-list change.
// macAuth tells whether s asks RADIUS about every station (hostapd
// macaddr_acl=2, no accept_mac_file).
func macAuth(s SSID) bool { return s.Radius != nil && s.Radius.MACAuth }

func (a *Applier) refreshACLs(ctx context.Context, d Desired, old, blocked []string) error {
	l := a.layout(d)
	served := map[string]bool{}
	for _, v := range a.ourVifs() {
		served[v] = true
	}
	for _, rl := range l.Radios {
		if len(rl.Used) == 0 {
			continue
		}
		maxSta := rl.Radio.MaxClients
		if maxSta <= 0 || maxSta > defaultMaxSta {
			maxSta = defaultMaxSta
		}
		var drv, prev []vifDriver
		var st []Step
		for _, u := range rl.Used {
			mac, err := a.bssid(ctx, u.Vif)
			if err != nil {
				return err
			}
			dv := driverFor(u, mac, maxSta, blocked, a.o.MinRates)
			drv = append(drv, dv)
			prev = append(prev, driverFor(u, mac, maxSta, old, a.o.MinRates))
			st = append(st, aclSteps(a.o.RunDir, dv)...)
			st = append(st, macSteps(u.Vif, dv.Macmode, dv.Maclist)...)
		}
		js, _ := json.MarshalIndent(drv, "", " ")
		st = append(st, writeStep("write driver state", drvPath(a.o.RunDir, rl.Primary), 0o644, js))
		if a.o.DryRun {
			a.logPlan("dry-run block list", Plan{Steps: st})
		} else if err := a.execute(ctx, st); err != nil {
			return err
		}
		for i, dv := range drv {
			if !served[dv.Vif] {
				continue
			}
			// hostapd 2.9 DENY_ACL/ACCEPT_ACL control commands. Accept-list
			// additions go first so an unblocked station is never missing
			// from both lists; removals disassociate exactly the removed
			// (newly blocked) stations.
			var cmds [][]string
			add := func(list string, macs []string) {
				for _, m := range macs {
					cmds = append(cmds, []string{list, "ADD_MAC", m})
				}
			}
			del := func(list string, macs []string) {
				for _, m := range macs {
					cmds = append(cmds, []string{list, "DEL_MAC", m})
				}
			}
			// hostapd keeps an accept list only where the conf loads one
			// (hostapd.go): under RADIUS MAC authentication (macaddr_acl=2)
			// hostapd checks its accept list before RADIUS, so an
			// ACCEPT_ACL entry would admit the station without asking. The
			// allow list is then the driver's alone (set above).
			accept := dv.Allow && !macAuth(rl.Used[i].SSID)
			if accept {
				add("ACCEPT_ACL", minus(dv.AcceptACL, prev[i].AcceptACL))
			}
			add("DENY_ACL", minus(dv.DenyACL, prev[i].DenyACL))
			if accept {
				del("ACCEPT_ACL", minus(prev[i].AcceptACL, dv.AcceptACL))
			}
			del("DENY_ACL", minus(prev[i].DenyACL, dv.DenyACL))
			for _, c := range cmds {
				if err := a.hostapdCLI(ctx, dv.Vif, c...); err != nil {
					a.o.Logf("bcmwifi: %v", err)
				}
			}
		}
	}
	return nil
}

// minus returns the elements of xs that are not in ys, in xs order.
func minus(xs, ys []string) []string {
	in := map[string]bool{}
	for _, y := range ys {
		in[y] = true
	}
	var out []string
	for _, x := range xs {
		if !in[x] {
			out = append(out, x)
		}
	}
	return out
}

// LED modes.
const (
	LEDOn        = "on"
	LEDOff       = "off"
	LEDLocate    = "locate"     // blink until LEDLocateOff
	LEDLocateOff = "locate-off" // back to the on/off state
)

// LED drives the status LED through TP-Link's leds daemon (kept running by
// decosys), using the daemon's own events, as checked on a unit
// (2026-11-19, user watching):
//
//   - normal: the conn controller's "online" state is steady green;
//   - off: the "off" event's "off" state turns every channel dark, and its
//     "done" state hands the LED back to conn (steady green);
//   - locate: the "zigbee" event's "identifying" state is a green blink
//     (690 ms on, 427 ms off), cleared with "done". The "off" event has a
//     higher priority than zigbee, so it is cleared for the blink and put
//     back afterwards when the LED is meant to be off.
//
// decosys stops conn-indicator (TP-Link's internet/mesh probe that sets the
// conn state), so whatever state it set last stays: after a reboot that is
// often "ap-lost" (red blink, the mesh master not yet seen) or "offline".
// "on" therefore also sets conn to "online" (verified on .232, 2026-11-19:
// event [1,2] red blink -> [1,0] steady green).
//
// The daemon has no white or blue pattern (green, red, a cyan WPS blink), so
// UniFi's LED colour is not carried. `leds switch` changes nothing visible on
// the X20, and a conn call with delay_on/delay_off left the LED dark, so
// neither is used.
func (a *Applier) LED(ctx context.Context, mode string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	ev := func(event, state string) []string {
		return []string{"call", "leds", event, `{"state":"` + state + `"}`}
	}
	dark := ev("off", "off")
	lit := ev("off", "done")
	online := ev("conn", "online")
	var calls [][]string
	switch strings.ToLower(mode) {
	case LEDOn:
		a.ledOn = true
		calls = [][]string{online, lit}
	case LEDOff:
		a.ledOn = false
		calls = [][]string{dark}
	case LEDLocate:
		calls = [][]string{lit, ev("zigbee", "identifying")}
	case LEDLocateOff, "unlocate":
		calls = [][]string{ev("zigbee", "done"), lit}
		if !a.ledOn {
			calls[1] = dark
		}
	default:
		return fmt.Errorf("bcmwifi: LED mode %q not on/off/locate/locate-off", mode)
	}
	for _, c := range calls {
		if a.o.DryRun {
			a.o.Logf("bcmwifi dry-run: ubus %s", strings.Join(c, " "))
			continue
		}
		if err := a.run(ctx, append([]string{"ubus"}, c...)...); err != nil {
			return fmt.Errorf("bcmwifi: LED %s: %w", mode, err)
		}
	}
	return nil
}
