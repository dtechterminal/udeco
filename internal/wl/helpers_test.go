// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixture reads testdata/<name>.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type response struct {
	out string
	err error
}

// fakeRunner serves `wl` calls from the captured fixtures: the call
// "wl -i wl0 chanim_stats us" reads testdata/wl_-i_wl0_chanim_stats_us.txt.
// An empty fixture with a .stderr file next to it is a failed call. over
// overrides a call with a queue of responses (the last one repeats).
type fakeRunner struct {
	mu    sync.Mutex
	over  map[string][]response
	calls []string
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := strings.Join(append([]string{name}, args...), " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, key)
	if q := f.over[key]; len(q) > 0 {
		r := q[0]
		if len(q) > 1 {
			f.over[key] = q[1:]
		}
		return []byte(r.out), r.err
	}
	file := filepath.Join("testdata", strings.Join(append([]string{name}, args...), "_")+".txt")
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("fake: no fixture for %q", key)
	}
	if se, err := os.ReadFile(file + ".stderr"); err == nil && len(b) == 0 {
		return nil, errors.New(strings.TrimSpace(string(se)))
	}
	return b, nil
}

func (f *fakeRunner) set(key string, rs ...response) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.over == nil {
		f.over = map[string][]response{}
	}
	f.over[key] = rs
}

func (f *fakeRunner) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// buildRoot assembles a device filesystem (/proc, /sys/class/net, /tmp)
// from the fixtures, as .205 looked when they were captured.
func buildRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	put := func(p, content string) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyTo := func(p, name string) { put(p, string(fixture(t, name))) }
	copyTo("/proc/uptime", "proc_uptime.txt")
	copyTo("/proc/loadavg", "proc_loadavg.txt")
	copyTo("/proc/stat", "proc_stat.txt")
	copyTo("/proc/meminfo", "proc_meminfo.txt")
	copyTo("/proc/net/route", "proc_net_route.txt")
	copyTo("/proc/net/arp", "proc_net_arp.txt")
	copyTo("/proc/sys/kernel/hostname", "proc_sys_kernel_hostname.txt")
	copyTo("/tmp/getfirm-product-info", "tmp_getfirm-product-info.txt")
	copyTo("/tmp/getfirm-soft-version", "tmp_getfirm-soft-version.txt")

	// every interface the unit had
	for _, n := range strings.Fields(string(fixture(t, "ls_sys_class_net.txt"))) {
		if err := os.MkdirAll(filepath.Join(root, "/sys/class/net", n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	copyTo("/sys/class/net/br-lan/address", "sys_class_net_br-lan_address.txt")
	copyTo("/sys/class/net/br-lan/brforward", "sys_class_net_br-lan_brforward.bin")
	for line := range strings.Lines(string(fixture(t, "sys_class_net_br-lan_brif_port_no.txt"))) {
		if f := strings.Fields(line); len(f) == 2 {
			put("/sys/class/net/br-lan/brif/"+f[0], "")
		}
	}
	// key=value dumps of /sys/class/net/<dev>
	sysDump := func(dev, name string) {
		sc := bufio.NewScanner(strings.NewReader(string(fixture(t, name))))
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if !ok {
				continue
			}
			switch {
			case k == "brport":
				if v != "" {
					put(devPath(dev, "brport/port_no"), v+"\n")
				}
			case k == "address" || k == "operstate" || k == "carrier" || k == "speed" || k == "duplex" || k == "ifindex" || k == "mtu" || k == "carrier_changes":
				put(devPath(dev, k), v+"\n")
			default:
				put(devPath(dev, "statistics/"+k), v+"\n")
			}
		}
	}
	sysDump("eth0", "sys_class_net_eth0.txt")
	sysDump("eth1", "sys_class_net_eth1.txt")
	for _, v := range []string{"wl01", "wl02", "wl11", "wl12", "wl13"} {
		sysDump(v, "sys_class_net_"+v+"_statistics.txt")
	}
	for _, v := range []string{"wl01", "wl02", "wl03", "wl04", "wl05", "wl06", "wl11", "wl12", "wl13", "wl14", "wl15", "wl16"} {
		put(devPath(v, "address"), strings.ToLower(string(fixture(t, "wl_-i_"+v+"_bssid.txt"))))
	}
	return root
}

// newTestCollector returns a Collector over buildRoot and a fakeRunner, with
// a settable clock.
func newTestCollector(t *testing.T) (*Collector, *fakeRunner, *time.Time) {
	t.Helper()
	fr := &fakeRunner{}
	c := New(Options{Root: buildRoot(t), Run: fr})
	now := time.Date(2026, 11, 18, 21, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	c.ifAddrs = func(name string) ([]net.Addr, error) {
		if name != "br-lan" {
			return nil, errors.New("no such interface")
		}
		ip, n, _ := net.ParseCIDR("192.168.0.205/24")
		n.IP = ip
		return []net.Addr{n}, nil
	}
	c.sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	return c, fr, &now
}
