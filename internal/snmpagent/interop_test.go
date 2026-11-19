// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestNetSNMPInterop runs net-snmp's command-line tools against the agent
// on loopback. It needs snmpget/snmpbulkwalk on PATH and runs only when
// UDECO_SNMP_INTEROP=1 (CI and the device build do not have them).
func TestNetSNMPInterop(t *testing.T) {
	if os.Getenv("UDECO_SNMP_INTEROP") != "1" {
		t.Skip("set UDECO_SNMP_INTEROP=1 to run against net-snmp's tools")
	}
	if _, err := exec.LookPath("snmpget"); err != nil {
		t.Skip("snmpget not installed")
	}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := New(Options{Root: fixtureRoot(t), EngineID: testEngine, Boots: 7})
	s.SetConfig(&Config{V1V2c: true, Community: "interop-c", V3: true, User: "monitor", Password: "Pass-w0rd!", Location: "hall"})
	s.SetView(FromFields(informFields()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx, pc)
	target := "udp:" + pc.LocalAddr().String()

	runOID := func(name string, args ...string) string {
		t.Helper()
		oid := args[len(args)-1]
		argv := append(append([]string{}, args[:len(args)-1]...), target, oid)
		out, err := exec.Command(name, argv...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	base := []string{"-On", "-t", "2", "-r", "0"}
	v2 := append(append([]string{}, base...), "-v2c", "-c", "interop-c")
	if out := runOID("snmpget", append(v2, "1.3.6.1.2.1.1.6.0")...); !hasString(out, "hall") {
		t.Errorf("v2c get: %s", out)
	}
	if out := runOID("snmpbulkwalk", append(v2, "1.3.6.1.2.1.2.2.1.2")...); !hasString(out, "eth1") || !hasString(out, "br-lan") {
		t.Errorf("v2c bulkwalk: %s", out)
	}
	if out := runOID("snmpwalk", append(append(append([]string{}, base...), "-v1", "-c", "interop-c"), "1.3.6.1.4.1.41112.1.6.1.2.1.6")...); !hasString(out, "Home") {
		t.Errorf("v1 walk: %s", out)
	}
	for _, p := range [][2]string{{"MD5", "DES"}, {"SHA", "AES"}} {
		v3 := append(append([]string{}, base...), "-v3", "-l", "authPriv", "-u", "monitor", "-a", p[0], "-A", "Pass-w0rd!", "-x", p[1], "-X", "Pass-w0rd!")
		if out := runOID("snmpget", append(v3, "1.3.6.1.2.1.1.1.0")...); !strings.Contains(out, "U6-Lite 6.7.54.15663") {
			t.Errorf("v3 %s/%s get: %s", p[0], p[1], out)
		}
		if out := runOID("snmpbulkwalk", append(v3, "1.3.6.1.4.1.41112.1.6")...); !hasString(out, "Guests") {
			t.Errorf("v3 %s/%s bulkwalk: %s", p[0], p[1], out)
		}
	}
	// a wrong password is refused
	bad := append(append([]string{}, base...), "-v3", "-l", "authPriv", "-u", "monitor", "-a", "SHA", "-A", "Wrong-pass", "-x", "AES", "-X", "Wrong-pass", target, "1.3.6.1.2.1.1.1.0")
	if out, err := exec.Command("snmpget", bad...).CombinedOutput(); err == nil || strings.Contains(string(out), "U6-Lite") {
		t.Errorf("wrong password answered: %s", out)
	}
}

// hasString: net-snmp prints a string value with or without quotes.
func hasString(out, s string) bool {
	return strings.Contains(out, "STRING: "+s+"\n") || strings.Contains(out, `STRING: "`+s+`"`)
}
