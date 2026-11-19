// SPDX-License-Identifier: GPL-2.0-or-later

// Package snmpagent is a small read-only SNMP agent (v1, v2c and v3 USM) for
// the Deco agent: the UniFi site's SNMP settings, served from Go instead of
// the UAP's net-snmp snmpd. docs/deco/features/snmp.md.
//
// What the controller sends (Network 11.1.50; com.ubnt.service.config.
// RngEFIxepjqE, called by the AP generator XHjguBsIf with prefix "" and the
// key "community"), from the site setting "snmp" ({enabled, enabledV3,
// community .{1,256}, username [a-zA-Z0-9_-]{1,30}, x_password [^'"]{8,32}}):
//
//	snmp.status=enabled        when enabled, or enabledV3 and the device
//	                           has fw_caps 0x4000 (supportsSNMPv3)
//	snmp.version=1_2c|3|all
//	snmp.location=<device snmp_location>   (only when set)
//	snmp.contact=<device snmp_contact>     (only when set)
//	snmp.community=<community>             (enabled; default "public")
//	snmp.user.1.name=<username>            (enabledV3 and the bit)
//	snmp.user.1.password=<x_password>
//
// The UAP writes that as /etc/snmp.conf (sysLocation, sysContact,
// rocommunity, createUser + rouser authpriv) and runs snmpd from inittab.
package snmpagent

import (
	"fmt"
	"regexp"
	"strings"
)

// Config is the site's SNMP settings for this device.
type Config struct {
	V1V2c     bool   // SNMP v1 and v2c with Community (read-only)
	Community string // a secret: never logged
	V3        bool   // SNMPv3 USM user User, authPriv only
	User      string
	Password  string // a secret: never logged
	Location  string // sysLocation
	Contact   string // sysContact
}

// String describes c without its secrets.
func (c *Config) String() string {
	if c == nil {
		return "off"
	}
	var on []string
	if c.V1V2c {
		on = append(on, "v1/v2c (read-only community)")
	}
	if c.V3 {
		on = append(on, fmt.Sprintf("v3 user %q (authPriv)", c.User))
	}
	return strings.Join(on, " + ")
}

var (
	userRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,30}$`) // the controller's own check
	// the controller allows 8-32 characters other than quotes; RFC 3414
	// needs at least 8
	passRE = regexp.MustCompile(`^[^'"\x00-\x1f\x7f]{8,32}$`)
)

// maxDisplay is the DisplayString limit (SNMPv2-TC).
const maxDisplay = 255

// FromCfg reads system_cfg's snmp section (key=value pairs, as
// translate.ParseCfg returns them). nil means SNMP is off. Notes say what was
// left out and why; they never contain the community or the password.
func FromCfg(cfg map[string]string) (*Config, []string) {
	if cfg["snmp.status"] != "enabled" {
		return nil, nil
	}
	var notes []string
	c := &Config{}
	var v1, v3 bool
	switch v := cfg["snmp.version"]; v {
	case "1_2c":
		v1 = true
	case "3":
		v3 = true
	case "all":
		v1, v3 = true, true
	default:
		return nil, []string{fmt.Sprintf("snmp: version %q not understood: SNMP off", v)}
	}
	if v1 {
		switch cm := cfg["snmp.community"]; {
		case cm == "":
			notes = append(notes, "snmp: v1/v2c without a community: v1/v2c off")
		case len(cm) > 256 || strings.ContainsAny(cm, "\x00\r\n"):
			notes = append(notes, "snmp: community unusable (over 256 bytes or a control character): v1/v2c off")
		default:
			c.V1V2c, c.Community = true, cm
		}
	}
	if v3 {
		u, p := cfg["snmp.user.1.name"], cfg["snmp.user.1.password"]
		switch {
		case u == "" || p == "":
			notes = append(notes, "snmp: v3 without a user name and password: v3 off")
		case !userRE.MatchString(u):
			notes = append(notes, "snmp: v3 user name unusable (1-30 of a-z, A-Z, 0-9, _ and -): v3 off")
		case !passRE.MatchString(p):
			notes = append(notes, "snmp: v3 password unusable (8-32 printable characters, no quotes): v3 off")
		default:
			c.V3, c.User, c.Password = true, u, p
		}
	}
	if !c.V1V2c && !c.V3 {
		return nil, notes
	}
	c.Location = display(cfg["snmp.location"])
	c.Contact = display(cfg["snmp.contact"])
	return c, notes
}

// display makes s a DisplayString: one line, at most 255 bytes, cut on a
// UTF-8 boundary.
func display(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) <= maxDisplay {
		return s
	}
	cut := maxDisplay
	for cut > 0 && s[cut]&0xc0 == 0x80 {
		cut--
	}
	return s[:cut]
}
