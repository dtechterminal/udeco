// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/repotest"
)

// deploy/jio-start.sh's 2.4 GHz driver swap (drv2g), run without a device:
// ifconfig, rmmod, insmod, brctl, killall, reboot and sleep are fakes on PATH that log their
// arguments (and fail where a test says); /proc/modules and /sys/class/net
// are files in a temp dir. files go to $D, or to $R with an "R/" prefix.

type drv2gRun struct {
	d, r  string
	calls []string
}

func (g drv2gRun) has(name string) bool {
	_, err := os.Stat(filepath.Join(g.d, name))
	return err == nil
}

func runDrv2g(t *testing.T, modules string, fail map[string]bool, files map[string]string) drv2gRun {
	t.Helper()
	for _, tool := range []string{"sh", "gzip", "gunzip", "readlink"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	d, r, bin, sys := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	log := filepath.Join(t.TempDir(), "calls")
	for _, c := range []string{"ifconfig", "rmmod", "insmod", "brctl", "killall", "reboot", "sleep"} {
		body := "#!/bin/sh\necho \"" + c + " $*\" >> " + log + "\n"
		for k := range fail {
			if strings.HasPrefix(k, c+" ") {
				body += "[ \"" + c + " $*\" = \"" + k + "\" ] && exit 1\n"
			}
		}
		body += "exit 0\n"
		if err := os.WriteFile(filepath.Join(bin, c), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// ra0 up in bdg2, ra2 up in br-v4, ra1 down, ra3 absent
	for i, fl := range map[string]string{"ra0": "0x1303", "ra1": "0x1002", "ra2": "0x1303"} {
		os.MkdirAll(filepath.Join(sys, i, "brport"), 0o755)
		os.WriteFile(filepath.Join(sys, i, "flags"), []byte(fl+"\n"), 0o644)
	}
	os.Symlink("../../bdg2", filepath.Join(sys, "ra0", "brport", "bridge"))
	os.Symlink("../../br-v4", filepath.Join(sys, "ra2", "brport", "bridge"))
	mods := filepath.Join(t.TempDir(), "modules")
	os.WriteFile(mods, []byte(modules), 0o644)
	up := filepath.Join(t.TempDir(), "uptime")
	os.WriteFile(up, []byte("80.00 90.00\n"), 0o644)
	ko := filepath.Join(t.TempDir(), "mt7603wpa3.ko")
	os.WriteFile(ko, []byte("module\n"), 0o644)
	if out, err := exec.Command("gzip", ko).CombinedOutput(); err != nil {
		t.Fatalf("gzip: %v %s", err, out)
	}
	gz, _ := os.ReadFile(ko + ".gz")
	os.WriteFile(filepath.Join(d, "mt7603wpa3.ko.gz"), gz, 0o644)
	for name, body := range files {
		dir := d
		if n, ok := strings.CutPrefix(name, "R/"); ok {
			dir, name = r, n
		}
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
	}
	cmd := exec.Command("sh", filepath.Join(repotest.Root(t), filepath.FromSlash(jioStart)), "drv2g")
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"UDECO_D="+d, "UDECO_R="+r, "UDECO_UPTIME="+up, "UDECO_PROC_MODULES="+mods, "UDECO_SYSNET="+sys,
		"UDECO_MT7603_VENDOR=/vendor/mt7603eap.ko", "UDECO_WL_EVT=/vendor/wl_evt_driver.ko")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("drv2g: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(log)
	var calls []string
	if s := strings.TrimSpace(string(b)); s != "" {
		for _, c := range strings.Split(s, "\n") {
			calls = append(calls, strings.TrimSpace(c))
		}
	}
	return drv2gRun{d: d, r: r, calls: calls}
}

// in reports that want appear in calls in this order.
func in(calls []string, want ...string) bool {
	i := 0
	for _, c := range calls {
		if i < len(want) && c == want[i] {
			i++
		}
	}
	return i == len(want)
}

const vendorLoaded = "mt7603eap 1872527 4 wl_evt_driver, Live 0x00000000\nwl_evt_driver 1696 0 - Live 0x00000000\n"

func TestJioDrv2gSwaps(t *testing.T) {
	g := runDrv2g(t, vendorLoaded, nil, nil)
	if !in(g.calls, "ifconfig ra0 down", "killall wl_notifier", "rmmod wl_evt_driver", "rmmod mt7603eap",
		"insmod "+filepath.Join(g.r, "mt7603wpa3.ko"), "insmod /vendor/wl_evt_driver.ko", "ifconfig ra0 up",
		"ifconfig ra0 up", "brctl addif bdg2 ra0", "ifconfig ra2 up", "brctl addif br-v4 ra2") {
		t.Errorf("calls:\n%s", strings.Join(g.calls, "\n"))
	}
	for _, c := range g.calls {
		if c == "ifconfig ra1 up" || strings.HasPrefix(c, "insmod /vendor/mt7603eap") || c == "reboot" {
			t.Errorf("unexpected %q", c)
		}
	}
	if g.has("mt7603wpa3.failed") {
		t.Error("failed marker written")
	}
	ev, _ := os.ReadFile(filepath.Join(g.d, "guard.events"))
	if !strings.Contains(string(ev), "drv2g: mt7603wpa3 loaded (was up: ra0:bdg2 ra2:br-v4)") {
		t.Errorf("events: %s", ev)
	}
	if _, err := os.Stat(filepath.Join(g.r, "drv2g.done")); err != nil {
		t.Error("no done marker")
	}
}

// TestJioDrv2gFallsBack: ra0 doesn't come up on the rebuilt module: the
// vendor module goes back with the same netdevs up, and the swap is off.
func TestJioDrv2gFallsBack(t *testing.T) {
	g := runDrv2g(t, vendorLoaded, map[string]bool{"ifconfig ra0 up": true}, nil)
	if !in(g.calls, "rmmod mt7603eap", "insmod "+filepath.Join(g.r, "mt7603wpa3.ko"), "ifconfig ra0 up",
		"rmmod mt76x3_ap", "insmod /vendor/mt7603eap.ko", "insmod /vendor/wl_evt_driver.ko", "ifconfig ra0 up", "brctl addif bdg2 ra0") {
		t.Errorf("calls:\n%s", strings.Join(g.calls, "\n"))
	}
	if !g.has("mt7603wpa3.failed") {
		t.Error("no failed marker")
	}
	// ... and a module that won't unload reboots
	g = runDrv2g(t, vendorLoaded, map[string]bool{"ifconfig ra0 up": true, "rmmod mt76x3_ap": true}, nil)
	if !in(g.calls, "rmmod mt76x3_ap", "reboot") || !g.has("mt7603wpa3.failed") {
		t.Errorf("calls:\n%s", strings.Join(g.calls, "\n"))
	}
}

// TestJioDrv2gBusy: a vendor module still in use loads nothing and brings
// the netdevs back; the swap is tried again before the next agent start,
// and the third busy try in a boot turns it off.
func TestJioDrv2gBusy(t *testing.T) {
	busy := map[string]bool{"rmmod mt7603eap": true}
	g := runDrv2g(t, vendorLoaded, busy, nil)
	if !in(g.calls, "killall wl_notifier", "rmmod mt7603eap", "insmod /vendor/wl_evt_driver.ko", "ifconfig ra0 up", "brctl addif bdg2 ra0") {
		t.Errorf("calls:\n%s", strings.Join(g.calls, "\n"))
	}
	for _, c := range g.calls {
		if strings.Contains(c, "mt7603wpa3.ko") || strings.HasPrefix(c, "insmod /vendor/mt7603eap") {
			t.Errorf("unexpected %q", c)
		}
	}
	if g.has("mt7603wpa3.failed") {
		t.Error("failed marker on the first busy try")
	}
	if _, err := os.Stat(filepath.Join(g.r, "drv2g.done")); err == nil {
		t.Error("done marker left: no second try")
	}
	if b, _ := os.ReadFile(filepath.Join(g.r, "drv2g.busy")); strings.TrimSpace(string(b)) != "1" {
		t.Errorf("drv2g.busy %q", b)
	}
	ev, _ := os.ReadFile(filepath.Join(g.d, "guard.events"))
	if !strings.Contains(string(ev), "in use (mt7603eap 4 wl_evt_driver 0 ), try 1 of 3") {
		t.Errorf("events: %s", ev)
	}
	g = runDrv2g(t, vendorLoaded, busy, map[string]string{"R/drv2g.busy": "2\n"})
	if !g.has("mt7603wpa3.failed") {
		t.Error("third busy try: no failed marker")
	}
}

// TestJioDrv2gSkips: no swap with the failed marker, force-observe, the
// rebuilt module already loaded, or a second run in a boot.
func TestJioDrv2gSkips(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"failed": {"mt7603wpa3.failed": "x\n"}, "observe": {"force-observe": "x\n"},
	} {
		if g := runDrv2g(t, vendorLoaded, nil, files); len(g.calls) != 0 {
			t.Errorf("%s: calls %q", name, g.calls)
		}
	}
	if g := runDrv2g(t, "mt76x3_ap 1872527 4 - Live 0x0\n", nil, nil); len(g.calls) != 0 {
		t.Errorf("already swapped: calls %q", g.calls)
	}
}
