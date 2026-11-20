// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import "testing"

func TestSyslog(t *testing.T) {
	cur := ParseUCI("system.@system[0]=system\n")
	var r Result
	enc := ParseCfg("syslog.status=enabled\nsyslog.remote.status=enabled\nsyslog.remote.ip=192.168.1.1\nsyslog.remote.port=5514\nsyslog.remote.encrypt=enabled\n")
	if ops := planSyslog(enc, cur, &r); len(ops) != 0 || len(r.Notes) != 1 {
		t.Fatalf("encrypted: %v %v", ops, r.Notes)
	}
	plain := ParseCfg("syslog.status=enabled\nsyslog.remote.status=enabled\nsyslog.remote.ip=192.168.1.20\nsyslog.remote.port=514\n")
	if ops := planSyslog(plain, cur, &r); len(ops) != 3 {
		t.Fatalf("plain: %v", ops)
	}
	set := ParseUCI("system.@system[0]=system\nsystem.@system[0].log_ip='192.168.1.20'\nsystem.@system[0].log_port='514'\nsystem.@system[0].log_proto='udp'\n")
	if ops := planSyslog(plain, set, &r); len(ops) != 0 {
		t.Fatalf("applied: %v", ops)
	}
	if ops := planSyslog(enc, set, &r); len(ops) != 2 {
		t.Fatalf("back to encrypted removes target: %v", ops)
	}
}

// The port for a system_cfg without syslog.remote.port. The intent gives
// DefaultSyslogPort to an encrypted target too, where cmd/uow's forwarder
// (syslogForwarder) takes DefaultEncryptedSyslogPort: kept as it is until
// one reader serves both.
func TestSyslogDefaultPorts(t *testing.T) {
	if DefaultSyslogPort != 514 || DefaultEncryptedSyslogPort != 5514 {
		t.Fatalf("default ports %d, %d", DefaultSyslogPort, DefaultEncryptedSyslogPort)
	}
	const base = "syslog.status=enabled\nsyslog.remote.status=enabled\nsyslog.remote.ip=192.168.1.20\n"
	const key = "syslog.remote.encrypt=enabled\nsyslog.remote.key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
	for _, c := range []struct {
		name, cfg string
		want      int
	}{
		{"plain, no port", base, DefaultSyslogPort},
		{"plain, port", base + "syslog.remote.port=1514\n", 1514},
		{"encrypted, no port: 514 as well", base + key, 514},
		{"encrypted, port", base + key + "syslog.remote.port=5514\n", 5514},
		{"port 0", base + "syslog.remote.port=0\n", DefaultSyslogPort},
		{"port out of range", base + "syslog.remote.port=65536\n", DefaultSyslogPort},
	} {
		var nb noteList
		s := intentSyslog(ParseCfg(c.cfg), &nb)
		if s == nil || s.Port != c.want {
			t.Errorf("%s: intent %+v, want port %d", c.name, s, c.want)
		}
	}
	// the OpenWrt plan: logd's log_port for a plain target without a port
	var r Result
	ops := planSyslog(ParseCfg(base), ParseUCI("system.@system[0]=system\n"), &r)
	port := ""
	for _, op := range ops {
		if op.Key == "system.@system[0].log_port" {
			port = op.Value
		}
	}
	if port != "514" {
		t.Errorf("log_port %q, want 514 (ops %v)", port, ops)
	}
}
