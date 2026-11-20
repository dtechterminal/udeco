// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSyslogSeal(t *testing.T) {
	key := strings.Repeat("0123456789abcdef", 4)
	id, err := NewHashID()
	if err != nil || len(id) != 16 {
		t.Fatalf("hash_id %q %v", id, err)
	}
	msg := []byte("<30>Nov 13 00:40:00 OnHub U7PG2,085566770001,6.8.2.15592: hostapd: phy1-ap0: AP-STA-CONNECTED")
	d, err := SealSyslog(key, id, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d[:9], []byte{0xAB, 0xCD, 0xDC, 0xBA, 1, 0, 0, 0, 1}) {
		t.Fatalf("header % x", d[:9])
	}
	gotID, got, err := OpenSyslog(key, d)
	if err != nil || gotID != id || !bytes.Equal(got, msg) {
		t.Fatalf("open: %q %q %v", gotID, got, err)
	}
	d[20] ^= 1 // the nonce is in the AAD: any header change must fail
	if _, _, err := OpenSyslog(key, d); err == nil {
		t.Error("tampered header accepted")
	}
	big, _ := SealSyslog(key, id, bytes.Repeat([]byte("x"), 9000))
	if len(big) > MaxSyslogDatagram {
		t.Errorf("datagram %d > %d", len(big), MaxSyslogDatagram)
	}
}

func TestSyslogTag(t *testing.T) {
	mac := net.HardwareAddr{0x08, 0x55, 0x66, 0x77, 0x00, 0x01}
	if got := SyslogTag("U7PG2", mac, "6.8.2.15592"); got != "U7PG2,085566770001,6.8.2.15592:" {
		t.Errorf("tag %q", got)
	}
	if got := SyslogTag("U6-Lite", net.HardwareAddr{0xB2, 0xA7, 0xB9, 0, 0, 0x01}, "6.7.54.15663"); got != "U6-Lite,b2a7b9000001,6.7.54.15663:" {
		t.Errorf("tag %q", got)
	}
}

// The priority tables as both forwarders had them (logread's names).
func TestSyslogPriorityTables(t *testing.T) {
	fac := map[string]int{"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
		"uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11, "local0": 16, "local1": 17, "local2": 18, "local3": 19,
		"local4": 20, "local5": 21, "local6": 22, "local7": 23}
	sev := map[string]int{"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warn": 4, "warning": 4, "notice": 5, "info": 6, "debug": 7}
	for name, want := range fac {
		if got, ok := SyslogFacility(name); !ok || got != want {
			t.Errorf("facility %s = %d, %v, want %d", name, got, ok, want)
		}
	}
	for name, want := range sev {
		if got, ok := SyslogSeverity(name); !ok || got != want {
			t.Errorf("severity %s = %d, %v, want %d", name, got, ok, want)
		}
	}
	if len(syslogFacilities) != len(fac) || len(syslogSeverities) != len(sev) {
		t.Errorf("%d facilities, %d severities", len(syslogFacilities), len(syslogSeverities))
	}
	// an unknown name is 0 and not ok: upstream's uow takes the 0, the agent the ok
	if got, ok := SyslogFacility("local8"); ok || got != 0 {
		t.Errorf("local8 = %d, %v", got, ok)
	}
	if got, ok := SyslogSeverity("panic"); ok || got != 0 {
		t.Errorf("panic = %d, %v", got, ok)
	}
}

// 50 lines a second, bursts of 100: what both forwarders counted by hand.
func TestSyslogLimiter(t *testing.T) {
	t0 := time.Unix(1794500000, 0)
	count := func(l *SyslogLimiter, at time.Time, tries int) (n int) {
		for i := 0; i < tries; i++ {
			if l.Allow(at) {
				n++
			}
		}
		return n
	}
	l := NewSyslogLimiter(t0)
	if n := count(l, t0, 500); n != 100 {
		t.Errorf("burst of %d, want 100", n)
	}
	if n := count(l, t0.Add(time.Second), 500); n != 50 {
		t.Errorf("%d lines after one second, want 50", n)
	}
	if n := count(l, t0.Add(time.Second+100*time.Millisecond), 500); n != 5 {
		t.Errorf("%d lines after 100 ms, want 5", n)
	}
	if n := count(l, t0.Add(time.Hour), 500); n != 100 {
		t.Errorf("%d lines after an idle hour, want 100 (the bucket's size)", n)
	}
	// the forwarders' own arithmetic, line by line
	tokens, last := 100.0, t0
	l = NewSyslogLimiter(t0)
	for i := 0; i < 2000; i++ {
		now := t0.Add(time.Duration(i*i) * 37 * time.Microsecond)
		tokens = min(100, tokens+now.Sub(last).Seconds()*50)
		last = now
		old := tokens >= 1
		if old {
			tokens--
		}
		if got := l.Allow(now); got != old {
			t.Fatalf("line %d: Allow = %v, the forwarders' count says %v", i, got, old)
		}
	}
	if SyslogRate != 50 || SyslogBurst != 100 || SyslogLineMax != 8192 {
		t.Errorf("limits %d %d %d", SyslogRate, SyslogBurst, SyslogLineMax)
	}
}
