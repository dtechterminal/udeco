// SPDX-License-Identifier: GPL-2.0-or-later

package jioports

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The controller's switch section for an AP with a switch (fw_caps 0x10),
// as Network 10.6.109 writes it (com.ubnt.service.config.XHjguBsIf, the UAP
// system_cfg builder, and ubntconf.FYYpPfQAeOM, the per-port VLAN lines):
//
//	switch.status=enabled|disabled        the device's "Enable Port VLAN"
//	switch.vlan.status=enabled|disabled   (switch_vlan_enabled), both
//	switch.vlan.<i>.id=<vid>              one per VLAN the AP carries:
//	switch.vlan.<i>.mode=untagged|tagged  the WLANs' VLANs and the ports'
//	switch.vlan.<i>.status=enabled        networks (VLAN 1 untagged)
//	switch.port.<p>.name=Port 1
//	switch.port.<p>.opmode=switch
//	switch.port.<p>.status=disabled       port profile forward "disabled"
//	switch.port.<p>.pvid=<vid>            native VLAN, written when not 1
//	switch.vlan.<i>.port.<p>.mode=untagged|tagged|exclude
//
// The per-port mode lines exist only for a port whose forward is "native"
// or "customize" (every VLAN of the list gets one); a port on "all" gets
// none and carries each VLAN as the VLAN's own mode says. Without Enable
// Port VLAN only switch.status=disabled and the name/opmode lines come.

// PortWant is what the controller wants of one port.
type PortWant struct {
	// Native is where the port's untagged frames go: 0 = the LAN (bdg2),
	// N > 1 = VLAN N's bridge, -1 = nowhere (no native VLAN).
	Native int
	// Tagged are the VLANs carried tagged (sorted, each > 1).
	Tagged   []int
	Disabled bool
}

// Default reports whether p is the port as the vendor has it: untagged
// LAN only.
func (p PortWant) Default() bool { return p.Native == 0 && len(p.Tagged) == 0 && !p.Disabled }

func (p PortWant) String() string {
	if p.Disabled {
		return "disabled"
	}
	n := "LAN"
	switch {
	case p.Native < 0:
		n = "none"
	case p.Native > 0:
		n = "VLAN " + strconv.Itoa(p.Native)
	}
	if len(p.Tagged) == 0 {
		return "native " + n
	}
	t := make([]string, len(p.Tagged))
	for i, v := range p.Tagged {
		t[i] = strconv.Itoa(v)
	}
	return "native " + n + ", tagged " + strings.Join(t, ",")
}

// VLANs are the VLAN bridges p uses.
func (p PortWant) VLANs() []int {
	if p.Disabled {
		return nil
	}
	out := append([]int{}, p.Tagged...)
	if p.Native > 0 {
		out = append(out, p.Native)
	}
	return out
}

// Want is the switch section of a system_cfg.
type Want struct {
	// VLAN: Enable Port VLAN is on (switch.status and switch.vlan.status).
	VLAN bool
	// Ports by UniFi port index; a port not listed is Default.
	Ports map[int]PortWant
}

// Port is what the controller wants of UniFi port idx.
func (w Want) Port(idx int) PortWant { return w.Ports[idx] }

type vlanEntry struct {
	vid  int
	mode string
	port map[int]string // UniFi port -> untagged|tagged|exclude
}

// FromCfg reads the switch section of a parsed system_cfg (key -> value).
// The notes say what is not carried out (never secrets: the section has
// none).
func FromCfg(cfg map[string]string) (Want, []string) {
	w := Want{Ports: map[int]PortWant{}}
	var notes []string
	on := func(k string) bool { return cfg[k] == "enabled" }
	w.VLAN = on("switch.status") && on("switch.vlan.status")

	vlans := map[int]*vlanEntry{} // by list index
	pvid := map[int]int{}
	disabled := map[int]bool{}
	for k, v := range cfg {
		if !strings.HasPrefix(k, "switch.") {
			continue
		}
		f := strings.Split(k, ".")
		switch {
		case len(f) == 4 && f[1] == "port":
			p, err := strconv.Atoi(f[2])
			if err != nil || p < 1 {
				continue
			}
			switch f[3] {
			case "status":
				disabled[p] = v == "disabled"
			case "pvid":
				if n, err := strconv.Atoi(v); err == nil {
					pvid[p] = n
				}
			case "opmode":
				if v != "" && v != "switch" {
					notes = append(notes, fmt.Sprintf("switch port %d: op mode %q is not supported (switching only)", p, v))
				}
			case "autoneg", "speed", "duplex", "flowctrl":
				if f[3] != "autoneg" || v == "disabled" {
					notes = append(notes, fmt.Sprintf("switch port %d: %s is not applied (the unit's PHYs keep autonegotiation)", p, f[3]))
				}
			}
		case (len(f) == 4 || len(f) == 6) && f[1] == "vlan":
			i, err := strconv.Atoi(f[2])
			if err != nil {
				continue
			}
			e := vlans[i]
			if e == nil {
				e = &vlanEntry{port: map[int]string{}}
				vlans[i] = e
			}
			switch {
			case len(f) == 4 && f[3] == "id":
				e.vid, _ = strconv.Atoi(v)
			case len(f) == 4 && f[3] == "mode":
				e.mode = v
			case len(f) == 6 && f[3] == "port" && f[5] == "mode":
				if p, err := strconv.Atoi(f[4]); err == nil {
					e.port[p] = v
				}
			}
		}
	}
	for p, d := range disabled {
		if d {
			w.Ports[p] = PortWant{Disabled: true}
		}
	}
	if !w.VLAN {
		if len(vlans) > 0 || len(pvid) > 0 {
			notes = append(notes, "switch: port VLANs are off (Enable Port VLAN): every port carries the untagged LAN only")
		}
		return w, dedupe(notes)
	}

	// the VLAN list, in list order, with bad entries left out
	var idx []int
	for i := range vlans {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	var list []*vlanEntry
	hasLAN := false
	for _, i := range idx {
		e := vlans[i]
		if e.vid < 1 || e.vid > 4094 {
			notes = append(notes, fmt.Sprintf("switch.vlan.%d: VLAN id %d left out", i, e.vid))
			continue
		}
		hasLAN = hasLAN || e.vid == 1
		list = append(list, e)
	}
	ports := map[int]bool{}
	for p := range pvid {
		ports[p] = true
	}
	for _, e := range list {
		for p := range e.port {
			ports[p] = true
		}
	}
	// ports without per-port lines are on "all": any port the controller
	// named in a name/status line
	for k := range cfg {
		f := strings.Split(k, ".")
		if len(f) == 4 && f[0] == "switch" && f[1] == "port" {
			if p, err := strconv.Atoi(f[2]); err == nil && p > 0 {
				ports[p] = true
			}
		}
	}
	for p := range ports {
		if disabled[p] {
			continue
		}
		pw := PortWant{}
		explicit := false
		for _, e := range list {
			if _, ok := e.port[p]; ok {
				explicit = true
			}
		}
		untagged := false
		for _, e := range list {
			mode := e.port[p]
			if !explicit {
				mode = e.mode // "all": the VLAN's own mode
			}
			switch mode {
			case "untagged":
				if untagged {
					notes = append(notes, fmt.Sprintf("switch port %d: VLAN %d untagged as well: left out (one native VLAN per port)", p, e.vid))
					continue
				}
				untagged = true
				if e.vid == 1 {
					pw.Native = 0
				} else {
					pw.Native = e.vid
				}
			case "tagged":
				if e.vid == 1 {
					notes = append(notes, fmt.Sprintf("switch port %d: VLAN 1 tagged is not supported (VLAN 1 is the port's untagged LAN on this switch)", p))
					continue
				}
				pw.Tagged = append(pw.Tagged, e.vid)
			case "exclude", "":
			default:
				notes = append(notes, fmt.Sprintf("switch port %d: VLAN %d mode %q not understood: left out", p, e.vid, mode))
			}
		}
		// no untagged line: the pvid (written when not 1); else, when the
		// LAN (VLAN 1) is in the list and this port excludes it, none
		switch {
		case untagged:
		case pvid[p] > 1:
			pw.Native = pvid[p]
		case explicit && hasLAN:
			pw.Native = -1
		}
		sort.Ints(pw.Tagged)
		pw.Tagged = uniq(pw.Tagged, pw.Native)
		if !pw.Default() {
			w.Ports[p] = pw
		}
	}
	return w, dedupe(notes)
}

// uniq drops repeated VLANs and the native one.
func uniq(v []int, native int) []int {
	var out []int
	for i, x := range v {
		if x == native || (i > 0 && v[i-1] == x) {
			continue
		}
		out = append(out, x)
	}
	return out
}

func dedupe(s []string) []string {
	sort.Strings(s)
	var out []string
	for i, x := range s {
		if i == 0 || s[i-1] != x {
			out = append(out, x)
		}
	}
	return out
}
