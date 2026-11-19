// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Port VLAN bridging for internal/jioports. The JCOW414's switch ports are
// eth0.1 ... eth0.4; untagged frames of port P arrive tagged with VLAN 1 on
// eth0.P.1 (the LAN bridge's member) and a frame tagged N on eth0.P.N. A
// port's VLANs therefore go into the bridges the VLAN SSIDs use: VLAN N is
// br-vN, which also holds the uplink's eth0.4.N (ensureVLAN). The uplink
// port itself is never handed to these helpers' callers: every method
// refuses a device on the uplink's parent.

// portDevRE: a switch port's VLAN device, eth0.P.N.
var portDevRE = regexp.MustCompile(`^(eth[0-9]+\.[0-9]+)\.([0-9]+)$`)

// SetPortVLANs tells the applier which VLAN bridges the LAN ports use, so
// removing the bridges no SSID uses any more (cleanVLANs) keeps them.
func (a *Applier) SetPortVLANs(vids map[int]bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.portVLANs = map[int]bool{}
	for v, on := range vids {
		if on && v > 0 {
			a.portVLANs[v] = true
		}
	}
}

// LANBridge is the bridge of the untagged LAN (bdg2).
func (a *Applier) LANBridge() string { return a.o.Bridge }

// BridgeOf is the bridge dev is a member of ("" = none).
func (a *Applier) BridgeOf(dev string) string { return a.bridgeOf(dev) }

// Exists reports whether the network device dev exists.
func (a *Applier) Exists(dev string) bool { return a.exists(dev) }

// onUplink reports whether dev is the uplink port or one of its VLAN
// devices (eth0.4, eth0.4.N).
func (a *Applier) onUplink(dev string) bool {
	parent, err := a.vlanParent()
	if err != nil {
		return false
	}
	return dev == a.uplink || dev == parent || strings.HasPrefix(dev, parent+".")
}

// PortToBridge puts a LAN port's device into the LAN bridge (vid 0), into
// VLAN vid's bridge (created, with the uplink's VLAN device, when missing),
// or into no bridge at all (vid < 0: the port's untagged frames go nowhere).
func (a *Applier) PortToBridge(ctx context.Context, dev string, vid int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.onUplink(dev) {
		return fmt.Errorf("%s is on the uplink port: not changed", dev)
	}
	if !a.exists(dev) {
		return fmt.Errorf("%s: no such device", dev)
	}
	if vid >= 0 {
		return a.bridgeTo(ctx, dev, vid)
	}
	if cur := a.bridgeOf(dev); cur != "" {
		return a.run(ctx, "brctl", "delif", cur, dev)
	}
	return nil
}

// EnsurePortVLAN makes parent.vid (VLAN vid tagged on a LAN port) exist,
// be up and sit in VLAN vid's bridge, and returns its name.
func (a *Applier) EnsurePortVLAN(ctx context.Context, parent string, vid int) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if vid < 2 || vid > 4094 {
		return "", fmt.Errorf("VLAN %d: want 2-4094 (VLAN 1 is the port's untagged LAN)", vid)
	}
	if a.onUplink(parent) {
		return "", fmt.Errorf("%s is the uplink port: not changed", parent)
	}
	if !a.exists(parent) {
		return "", fmt.Errorf("%s: no such port", parent)
	}
	br, err := a.ensureVLAN(ctx, vid)
	if err != nil {
		return "", err
	}
	dev := parent + "." + strconv.Itoa(vid)
	if !a.exists(dev) {
		if err := a.run(ctx, "ip", "link", "add", "link", parent, "name", dev, "type", "vlan", "id", strconv.Itoa(vid)); err != nil {
			return "", err
		}
	}
	if cur := a.bridgeOf(dev); cur != br {
		if cur != "" {
			if err := a.run(ctx, "brctl", "delif", cur, dev); err != nil {
				return "", err
			}
		}
		if err := a.run(ctx, "brctl", "addif", br, dev); err != nil {
			return "", err
		}
	}
	return dev, a.run(ctx, "ip", "link", "set", dev, "up")
}

// DelPortVLAN removes a LAN port's tagged VLAN device (eth0.P.N, N > 1).
func (a *Applier) DelPortVLAN(ctx context.Context, dev string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := portDevRE.FindStringSubmatch(dev)
	if m == nil || m[2] == "1" {
		return fmt.Errorf("%s is not a port's tagged VLAN device", dev)
	}
	if a.onUplink(dev) {
		return fmt.Errorf("%s is on the uplink port: not changed", dev)
	}
	if !a.exists(dev) {
		return nil
	}
	return a.run(ctx, "ip", "link", "del", dev)
}

// PortVLANDevs lists parent's tagged VLAN devices (parent.N, N > 1) by
// VLAN.
func (a *Applier) PortVLANDevs(parent string) map[int]string {
	out := map[int]string{}
	ents, _ := os.ReadDir(a.dev("/sys/class/net"))
	for _, e := range ents {
		m := portDevRE.FindStringSubmatch(e.Name())
		if m == nil || m[1] != parent {
			continue
		}
		if v, err := strconv.Atoi(m[2]); err == nil && v > 1 {
			out[v] = e.Name()
		}
	}
	return out
}

// PruneVLANs removes the VLAN bridges neither the live SSIDs nor the ports
// use. With the vendor's Wi-Fi up (never taken over, or handed back:
// restoreBaseline) no SSID uses one, so only the ports' are kept. With the
// agent's profiles installed it does nothing until this process has
// applied (or found live) the controller's Wi-Fi: without that it cannot
// tell an SSID's bridge from an unused one.
func (a *Applier) PruneVLANs(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.o.DryRun {
		return nil
	}
	if a.live == nil {
		if a.Owned() {
			return nil
		}
		return a.cleanVLANs(ctx, nil)
	}
	return a.cleanVLANs(ctx, a.live)
}

// members lists the devices in bridge br.
func (a *Applier) members(br string) []string {
	var out []string
	ents, _ := os.ReadDir(a.dev("/sys/class/net"))
	for _, e := range ents {
		if a.bridgeOf(e.Name()) == br {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// rescuePorts runs before VLAN bridge br is deleted: a LAN port's
// untagged device in it goes back to the LAN bridge (deleting the bridge
// would leave the port in none) and a LAN port's tagged device in it is
// removed. The uplink's own VLAN device is the caller's.
func (a *Applier) rescuePorts(ctx context.Context, br string) error {
	var errs []error
	for _, dev := range a.members(br) {
		m := portDevRE.FindStringSubmatch(dev)
		if m == nil || a.onUplink(dev) {
			continue
		}
		if m[2] == "1" {
			a.o.Logf("mtkwifi: %s leaves %s (being removed) for the LAN bridge %s", dev, br, a.o.Bridge)
			if err := a.run(ctx, "brctl", "delif", br, dev); err != nil {
				errs = append(errs, err)
				continue
			}
			if err := a.run(ctx, "brctl", "addif", a.o.Bridge, dev); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err := a.run(ctx, "ip", "link", "del", dev); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// portVLANsUsed is a copy of the ports' VLANs (a.mu held).
func (a *Applier) portVLANsUsed() map[int]bool {
	out := map[int]bool{}
	for v := range a.portVLANs {
		out[v] = true
	}
	return out
}
