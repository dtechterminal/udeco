// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// The JCOW414's wired ports are the switch port devices in bdg2
// (eth0.N.1). The VLAN parents eth0 and eth0.N are never ports: their
// counters are the CPU port's and wrap at 32 bits (eth0 read 1.49 GB while
// eth0.4.1 read 48.2 GB on 2026-11-19), so the uplink's if_table row must
// come from eth0.4.1 and its 64-bit counters.
func TestPortsAreSwitchPortDevices(t *testing.T) {
	root := t.TempDir()
	w := func(p, v string) {
		t.Helper()
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("/proc/uptime", "8207676.06 23118573.87")
	w("/proc/loadavg", "0.10 0.20 0.30 1/80 999")
	w("/proc/stat", "cpu 1 2 3 4 5 6 7")
	w("/proc/meminfo", "MemTotal: 1000 kB\nMemFree: 500 kB")
	dev := func(name string, rx, tx uint64, inBridge bool) {
		d := "/sys/class/net/" + name
		w(d+"/address", "b4:a7:c6:17:e3:f3")
		w(d+"/operstate", "up")
		w(d+"/speed", "1000")
		w(d+"/duplex", "full")
		w(d+"/statistics/rx_bytes", strconv.FormatUint(rx, 10))
		w(d+"/statistics/tx_bytes", strconv.FormatUint(tx, 10))
		if inBridge {
			w("/sys/class/net/bdg2/brif/"+name+"/port_no", "0x4")
			w(d+"/brport/port_no", "0x4")
		}
	}
	dev("eth0", 1494171840, 17674102, false)
	dev("eth0.4", 3166558382, 3450816276, false)
	dev("eth0.4.1", 48216226929, 28955672443, true)
	dev("eth0.1.1", 20752742692, 45666909354, true)
	w("/sys/class/net/bdg2/address", "b4:a7:c6:17:e3:f3")

	c := NewCollector(CollectorOptions{Root: root, Run: nil})
	s := &apstate.Snapshot{}
	if err := c.sys.ReadSystem(s); err != nil {
		t.Fatal(err)
	}
	got := map[string]apstate.Port{}
	for _, p := range s.Ports {
		got[p.Name] = p
	}
	if len(got) != 2 {
		t.Fatalf("ports %v, want only eth0.1.1 and eth0.4.1", s.Ports)
	}
	up, ok := got["eth0.4.1"]
	if !ok || up.RxBytes != 48216226929 || up.TxBytes != 28955672443 || up.BridgePort != 4 || !up.Up || up.Speed != 1000 {
		t.Errorf("eth0.4.1 %+v", up)
	}
	for _, n := range []string{"eth0", "eth0.4"} {
		if _, ok := got[n]; ok {
			t.Errorf("%s read as a port", n)
		}
	}
}
