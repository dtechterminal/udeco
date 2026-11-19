// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import (
	"strings"
	"testing"
)

func TestFromCfg(t *testing.T) {
	const comm, pass = "c0mmunity-secret", "v3-pass-secret"
	base := func(kv ...string) map[string]string {
		m := map[string]string{"snmp.status": "enabled"}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	cases := []struct {
		name   string
		cfg    map[string]string
		v1, v3 bool
		note   string
	}{
		{"off", map[string]string{}, false, false, ""},
		{"disabled", map[string]string{"snmp.status": "disabled", "snmp.community": comm}, false, false, ""},
		{"v1", base("snmp.version", "1_2c", "snmp.community", comm), true, false, ""},
		{"v3", base("snmp.version", "3", "snmp.user.1.name", "mon", "snmp.user.1.password", pass), false, true, ""},
		{"all", base("snmp.version", "all", "snmp.community", comm, "snmp.user.1.name", "mon_1", "snmp.user.1.password", pass), true, true, ""},
		{"all, v3 keys missing", base("snmp.version", "all", "snmp.community", comm), true, false, "v3 without a user"},
		{"v3 short password", base("snmp.version", "3", "snmp.user.1.name", "mon", "snmp.user.1.password", "short"), false, false, "password unusable"},
		{"v3 bad user", base("snmp.version", "3", "snmp.user.1.name", "a b", "snmp.user.1.password", pass), false, false, "user name unusable"},
		{"v3 quote in password", base("snmp.version", "3", "snmp.user.1.name", "mon", "snmp.user.1.password", `pass"word1`), false, false, "password unusable"},
		{"no version", base("snmp.community", comm), false, false, "version"},
		{"v1 no community", base("snmp.version", "1_2c"), false, false, "without a community"},
	}
	for _, c := range cases {
		got, notes := FromCfg(c.cfg)
		n := strings.Join(notes, "; ")
		if strings.Contains(n, comm) || strings.Contains(n, pass) {
			t.Errorf("%s: secret in notes %q", c.name, n)
		}
		if c.note != "" && !strings.Contains(n, c.note) {
			t.Errorf("%s: notes %q, want %q", c.name, n, c.note)
		}
		if !c.v1 && !c.v3 {
			if got != nil {
				t.Errorf("%s: %+v, want off", c.name, got)
			}
			continue
		}
		if got == nil || got.V1V2c != c.v1 || got.V3 != c.v3 {
			t.Errorf("%s: %+v", c.name, got)
			continue
		}
		if s := got.String(); strings.Contains(s, comm) || strings.Contains(s, pass) {
			t.Errorf("%s: secret in String %q", c.name, s)
		}
	}
	c, _ := FromCfg(base("snmp.version", "1_2c", "snmp.community", comm, "snmp.location", "hall\nway", "snmp.contact", strings.Repeat("é", 200)))
	if c.Location != "hall way" || len(c.Contact) > 255 || !strings.HasPrefix(c.Contact, "é") || strings.ToValidUTF8(c.Contact, "?") != c.Contact {
		t.Errorf("display strings: %q %q", c.Location, c.Contact)
	}
}
