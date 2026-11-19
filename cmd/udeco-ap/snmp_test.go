// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// test-only secrets (never real ones)
const (
	testSNMPCommunity = "pub-c0mmunity"
	testSNMPPassword  = "Pass-w0rd!"
)

func snmpCfg(version string) string {
	return "snmp.status=enabled\nsnmp.version=" + version + "\nsnmp.location=hall\nsnmp.community=" + testSNMPCommunity +
		"\nsnmp.user.1.name=monitor\nsnmp.user.1.password=" + testSNMPPassword + "\n"
}

// v2cGet is a hand-encoded SNMPv2c GetRequest (short-form lengths only).
func v2cGet(comm string, oids ...[]byte) []byte {
	t := func(tag byte, b ...[]byte) []byte {
		v := bytes.Join(b, nil)
		return append([]byte{tag, byte(len(v))}, v...)
	}
	var vbs [][]byte
	for _, o := range oids {
		vbs = append(vbs, t(0x30, t(0x06, o), []byte{0x05, 0}))
	}
	pdu := t(0xa0, []byte{2, 1, 7}, []byte{2, 1, 0}, []byte{2, 1, 0}, t(0x30, vbs...))
	return t(0x30, []byte{2, 1, 1}, t(0x04, []byte(comm)), pdu)
}

var (
	oidSysName     = []byte{0x2b, 6, 1, 2, 1, 1, 5, 0}
	oidSysLocation = []byte{0x2b, 6, 1, 2, 1, 1, 6, 0}
)

func snmpAsk(t *testing.T, addr net.Addr, req []byte) ([]byte, error) {
	t.Helper()
	c, err := net.Dial("udp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	b := make([]byte, 8192)
	n, err := c.Read(b)
	return b[:n], err
}

// The site's SNMP settings start a read-only agent (observe mode: nothing on
// the unit is run), answering v2c with the site community, taking the v3
// engine boots once, keeping the secrets out of the log; a system_cfg
// without snmp stops it.
func TestSNMPFollowsSystemCfg(t *testing.T) {
	conns := make(chan net.PacketConn, 4)
	h := newHarness(t, func(c *Config, o *options) {
		o.snmpListen = func(context.Context) (net.PacketConn, error) {
			pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err == nil {
				conns <- pc
			}
			return pc, err
		}
	})
	h.ctl.queue(adoptReply, provisionReply(testCfg+snmpCfg("all")))
	h.start()
	var pc net.PacketConn
	select {
	case pc = <-conns:
	case <-time.After(5 * time.Second):
		t.Fatal("SNMP agent not started")
	}
	var resp []byte
	eventually(t, "a v2c answer", func() bool {
		b, err := snmpAsk(t, pc.LocalAddr(), v2cGet(testSNMPCommunity, oidSysName, oidSysLocation))
		resp = b
		return err == nil && bytes.Contains(b, []byte("hall"))
	})
	if !bytes.Contains(resp, []byte("deco-205")) {
		t.Errorf("sysName missing from % x", resp)
	}
	if _, err := snmpAsk(t, pc.LocalAddr(), v2cGet("wrong", oidSysName)); err == nil {
		t.Error("a wrong community was answered")
	}
	b, err := os.ReadFile(filepath.Join(h.a.sessDir, "snmp-engine-boots"))
	if err != nil || strings.TrimSpace(string(b)) != "1" {
		t.Errorf("engine boots %q %v", b, err)
	}

	// SNMP turned off for the site: the agent stops
	h.ctl.queue(fmt.Sprintf(`{"_type":"setparam","cfgversion":"00000000000000c2","mgmt_cfg":"cfgversion=00000000000000c2\n","system_cfg":%q}`, testCfg))
	eventually(t, "the agent stopped", func() bool { return strings.Contains(h.logs.all(), "snmp: off") })
	if _, err := snmpAsk(t, pc.LocalAddr(), v2cGet(testSNMPCommunity, oidSysName)); err == nil {
		t.Error("answered after SNMP was turned off")
	}
	h.stop()
	logs := h.logs.all()
	if strings.Contains(logs, testSNMPCommunity) || strings.Contains(logs, testSNMPPassword) {
		t.Error("an SNMP secret is in the log")
	}
	if !strings.Contains(logs, `snmp: v1/v2c (read-only community) + v3 user "monitor" (authPriv)`) {
		t.Errorf("log lacks the SNMP setting:\n%s", logs)
	}
	for _, c := range h.rec.list() {
		t.Errorf("observe mode touched the unit: %s", c)
	}
}

// v3 with an unreadable engine-boots file stays off; v1/v2c still runs.
func TestSNMPv3FailsClosedWithoutBoots(t *testing.T) {
	conns := make(chan net.PacketConn, 4)
	h := newHarness(t, func(c *Config, o *options) {
		o.snmpListen = func(context.Context) (net.PacketConn, error) {
			pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err == nil {
				conns <- pc
			}
			return pc, err
		}
	})
	os.WriteFile(filepath.Join(h.a.sessDir, "snmp-engine-boots"), []byte("garbage"), 0o600)
	h.ctl.queue(adoptReply, provisionReply(testCfg+snmpCfg("all")))
	h.start()
	select {
	case <-conns:
	case <-time.After(5 * time.Second):
		t.Fatal("SNMP agent not started")
	}
	eventually(t, "v1/v2c only", func() bool { return strings.Contains(h.logs.all(), "snmp: v1/v2c (read-only community)") })
	h.stop()
	logs := h.logs.all()
	if !strings.Contains(logs, "snmp: v3 off: engine boots") || strings.Contains(logs, `v3 user "monitor"`) {
		t.Errorf("v3 not refused:\n%s", logs)
	}
}
