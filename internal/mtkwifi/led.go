// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// The JCOW414's front LED is one RGB LED on three GPIOs, driven by the
// EcoNet LED table in /proc/tc3162/led_def. The firmware sets it with
// /bin/ledctl1 (called by led.lua, led_script.sh and the boot scripts),
// whose rows are "102 <gpio> <mode> <speed> 0", with
// 102 the status LED, mode 0 off, 1 on, 2 blink, and speed 0 fast or 2
// slow. It turns all three colours off before lighting one. Read from the
// unit (2026-11-19): RED=27, GREEN=25, BLUE=23, and row 102 at "27 2 0 0"
// (the red fast blink the firmware shows without its WAN, which is what a
// JCOW414 used as an AP shows forever). No sysfs LED class or GPIO export
// exists on this kernel. With the vendor daemons stopped (dumb-AP mode, all
// that runs is telnetd, getty, syslogd and the agent) nothing else writes
// the table; the firmware's WPS and WAN scripts would, if they ran.
//
// What the agent shows:
//
//   - normal (led_enabled): steady green, the firmware's own "all is well"
//     state, so it reads as healthy to anyone who knows the unit and
//     replaces the alarming red blink;
//   - off (led_enabled=false): all three colours dark;
//   - locate: blue fast blink (a colour and pattern the unit shows in no
//     other state the agent leaves it in), also when the LED is off, as a
//     UniFi AP does; locate-off goes back to green or dark;
//   - uplink lost (the uplink-loss hold, uplinkloss.go): red fast blink,
//     the firmware's own "no WAN" pattern (row 102 27 2 0 above), where a
//     U6 blinks its LED for a lost uplink. Locate and the LED off win over
//     it; the agent's stop (ReleaseLED) puts green back.
const (
	ledDefFile = "proc/tc3162/led_def"
	ledRow     = "102"
	ledRed     = "27"
	ledGreen   = "25"
	ledBlue    = "23"
)

// LED shows mode (bcmwifi.LEDOn, LEDOff, LEDLocate, LEDLocateOff) on the
// status LED. It touches no radio. It holds its own lock, so it does not
// wait for an apply.
func (a *Applier) LED(ctx context.Context, mode string) error {
	a.ledMu.Lock()
	defer a.ledMu.Unlock()
	on, locating := a.ledOn, a.locating
	switch strings.ToLower(mode) {
	case bcmwifi.LEDOn:
		on = true
	case bcmwifi.LEDOff:
		on = false
	case bcmwifi.LEDLocate:
		locating = true
	case bcmwifi.LEDLocateOff, "unlocate":
		locating = false
	default:
		return fmt.Errorf("mtkwifi: LED mode %q not on/off/locate/locate-off", mode)
	}
	// the controller's last word, even if this write fails: the next call
	// shows it
	a.ledOn, a.locating = on, locating
	show, err := a.drawLED(ctx)
	if err != nil {
		return fmt.Errorf("mtkwifi: LED %s: %w", mode, err)
	}
	a.o.Logf("mtkwifi: LED %s: %s", mode, show)
	return nil
}

// drawLED shows the LED state (ledMu held): "ledctl1 ALL off", then one
// colour.
func (a *Applier) drawLED(ctx context.Context) (string, error) {
	lines := []string{ledLine(ledRed, "0 0"), ledLine(ledGreen, "0 0"), ledLine(ledBlue, "0 0")}
	show := "dark"
	switch {
	case a.locating:
		lines, show = append(lines, ledLine(ledBlue, "2 0")), "blue fast blink"
	case a.ledOn && a.ledUplink:
		lines, show = append(lines, ledLine(ledRed, "2 0")), "red fast blink (uplink lost)"
	case a.ledOn:
		lines, show = append(lines, ledLine(ledGreen, "1 0")), "steady green"
	}
	return show, a.writeLED(ctx, lines)
}

// uplinkLED shows the uplink-loss hold (red fast blink) or its end. Only
// a change is drawn, and nothing shows over locate or a dark LED; a
// failed write is logged, never returned: the LED must not hold up the
// SSIDs.
func (a *Applier) uplinkLED(ctx context.Context, down bool) {
	a.ledMu.Lock()
	defer a.ledMu.Unlock()
	if a.ledUplink == down {
		return
	}
	a.ledUplink = down
	if a.locating || !a.ledOn {
		return
	}
	if show, err := a.drawLED(ctx); err != nil {
		a.o.Logf("mtkwifi: LED for the uplink: %v", err)
	} else {
		a.o.Logf("mtkwifi: LED: %s", show)
	}
}

// ReleaseLED ends the uplink-loss blink at the agent's stop (the SSIDs
// are left as they are, the LED goes back to the controller's setting).
func (a *Applier) ReleaseLED(ctx context.Context) { a.uplinkLED(ctx, false) }

func ledLine(gpio, action string) string { return ledRow + " " + gpio + " " + action + " 0" }

// writeLED writes each row with its own open and write, as the shell's
// echo does (the driver parses one row per write).
func (a *Applier) writeLED(ctx context.Context, lines []string) error {
	p := a.dev(ledDefFile)
	if a.o.DryRun {
		a.o.Logf("mtkwifi: dry run: %s <- %s", p, strings.Join(lines, " | "))
		return nil
	}
	for _, l := range lines {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.o.writeLED(p, l+"\n"); err != nil {
			return err
		}
	}
	return nil
}

// writeProc is the default Options.writeLED: no O_CREAT, so a unit without
// the LED table fails instead of growing a file.
func writeProc(p, s string) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(s)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
