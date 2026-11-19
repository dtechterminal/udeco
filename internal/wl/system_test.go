// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseProcFiles(t *testing.T) {
	total, idle := parseProcStat(string(fixture(t, "proc_stat.txt")))
	if total != 146532+174312+7024149+65+8086 || idle != 7024149+65 {
		t.Errorf("stat = %d, %d", total, idle)
	}
	if tt, ii := parseProcStat("intr 1 2 3\n"); tt != 0 || ii != 0 {
		t.Error("non-cpu line parsed")
	}
	mem := parseMeminfo(string(fixture(t, "proc_meminfo.txt")))
	for k, kb := range map[string]int64{"MemTotal": 252152, "MemFree": 19712, "Buffers": 16880, "Cached": 71932} {
		if mem[k] != kb*1024 {
			t.Errorf("%s = %d", k, mem[k])
		}
	}
	if gw := parseRoute(string(fixture(t, "proc_net_route.txt"))); gw != "192.168.0.1" {
		t.Errorf("gateway = %q", gw)
	}
	if gw := parseRoute("Iface\tDestination\tGateway\tFlags\nbr-lan\t0000A8C0\t00000000\t0001\n"); gw != "" {
		t.Errorf("no default route: %q", gw)
	}
	arp := parseARP(string(fixture(t, "proc_net_arp.txt")))
	if len(arp) != 5 || arp["1e:6a:1b:c5:04:c2"] != "192.168.0.1" || arp["b0:a7:b9:3e:16:94"] != "192.168.0.241" {
		t.Errorf("arp = %v", arp)
	}
	inc := parseARP("IP address HW type Flags HW address Mask Device\n10.0.0.9 0x1 0x0 00:00:00:00:00:00 * br-lan\n")
	if len(inc) != 0 {
		t.Errorf("incomplete entry kept: %v", inc)
	}
}

func TestParseBrforward(t *testing.T) {
	fdb := parseBrforward(fixture(t, "sys_class_net_br-lan_brforward.bin"))
	if len(fdb) != 45 {
		t.Fatalf("got %d entries", len(fdb))
	}
	if e := fdb[0]; e.MAC != "14:c1:4e:be:77:57" || e.Port != 1 || e.Local || e.Age != 19 {
		t.Errorf("entry 0 = %+v", e)
	}
	if e := fdb[1]; e.MAC != "be:a7:b9:3e:17:05" || e.Port != 4 || !e.Local || e.Age != 0 {
		t.Errorf("entry 1 = %+v", e)
	}
	// the same MAC/port/local set as the BusyBox hexdump of the same file
	// (taken moments apart, so ages differ)
	want := map[string]string{}
	for line := range strings.Lines(string(fixture(t, "hexdump_brforward.txt"))) {
		f := strings.Fields(line)
		if len(f) != 5 {
			continue
		}
		port, _ := strconv.Atoi(f[1])
		hi, _ := strconv.Atoi(f[4])
		mac := f[0][0:2] + ":" + f[0][2:4] + ":" + f[0][4:6] + ":" + f[0][6:8] + ":" + f[0][8:10] + ":" + f[0][10:12]
		want[mac] = strconv.Itoa(hi<<8|port) + "/" + f[2]
	}
	gw := false
	for _, e := range fdb {
		loc := "0"
		if e.Local {
			loc = "1"
		}
		if w, ok := want[e.MAC]; ok && w != strconv.Itoa(e.Port)+"/"+loc {
			t.Errorf("%s: binary %d/%s, hexdump %s", e.MAC, e.Port, loc, w)
		}
		if e.MAC == "1e:6a:1b:c5:04:c2" {
			gw = e.Port == 1 && !e.Local
		}
	}
	if !gw {
		t.Error("gateway MAC not on port 1")
	}
	// a short trailing record is ignored
	if got := parseBrforward(make([]byte, fdbRecordSize+5)); len(got) != 1 {
		t.Errorf("partial record: %d entries", len(got))
	}
	// port_hi extends the port number
	rec := make([]byte, fdbRecordSize)
	rec[6], rec[12] = 0x02, 0x01
	if got := parseBrforward(rec); got[0].Port != 0x102 {
		t.Errorf("port_hi: %d", got[0].Port)
	}
}

func TestProductInfoNeverLeaksKeys(t *testing.T) {
	c, _, _ := newTestCollector(t)
	model, release := c.productInfo()
	if model != "Deco X20 v2" || release != "1.3.0 Build 20250912 Rel. 56370" {
		t.Errorf("model %q, release %q", model, release)
	}
	got := tpKeyvals("product_name:X20\nkey:SECRET\npreconf_k:SECRET\n", "product_name")
	if len(got) != 1 || strings.Contains(got["product_name"], "SECRET") {
		t.Errorf("tpKeyvals returned %v", got)
	}
}
