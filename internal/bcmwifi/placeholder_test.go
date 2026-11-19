// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The agent's hostapd conf: interface= is always wlN1 as a hidden WPA2-PSK
// placeholder with a random SSID and passphrase (never logged, only in the
// 0600 conf), kept BSS down after the start; the SSIDs are bss= sections
// with bssid=. The placeholder survives a re-plan and an agent restart, so
// an unchanged radio keeps its hostapd.
func TestPlaceholderConf(t *testing.T) {
	ctx := context.Background()
	confs := map[string]hapdPlaceholder{}
	for _, run := range []string{"a", "b"} {
		f := newFakeDev(t)
		var mu sync.Mutex
		var logs strings.Builder
		a := New(Options{Root: f.root, Run: f, VerifyTimeout: 4 * time.Second, Logf: func(format string, args ...any) {
			mu.Lock()
			fmt.Fprintf(&logs, format+"\n", args...)
			mu.Unlock()
		}})
		a.sleep = func(time.Duration) { f.tick() }
		d := twoSSIDs()
		p, err := a.Plan(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		ph := stepIndex(t, p, "keep placeholder wl01 down: wl -i wl01 bss down [optional]")
		if st := stepIndex(t, p, "start hostapd on wl0"); st > ph {
			t.Error("placeholder lowered before hostapd started")
		}
		if err := a.Apply(ctx, p); err != nil {
			t.Fatal(err)
		}
		conf, err := os.ReadFile(f.path("/tmp/udeco/hapd-wl0.conf"))
		if err != nil {
			t.Fatal(err)
		}
		head, _, _ := strings.Cut(string(conf), "bss=")
		for _, w := range []string{"interface=wl01\n", "ignore_broadcast_ssid=1\n", "wpa=2\n", "wpa_key_mgmt=WPA-PSK\n", "ssid=udeco-"} {
			if !strings.Contains(head, w) {
				t.Errorf("placeholder section lacks %q:\n%s", w, head)
			}
		}
		if strings.Contains(head, "bridge=") {
			t.Error("placeholder bridged")
		}
		pl, ok := parsePlaceholder(conf, "wl01")
		if !ok || len(pl.Passphrase) < 32 {
			t.Fatalf("placeholder %v", ok)
		}
		confs[run] = pl
		if strings.Count(string(conf), "bssid=") != strings.Count(string(conf), "bss=") {
			t.Errorf("a bss= section without bssid=:\n%s", conf)
		}
		// Never outside the conf: logs, plan text, baseline, last-good.
		for _, where := range []string{logs.String(), p.String()} {
			if strings.Contains(where, pl.Passphrase) {
				t.Error("placeholder passphrase leaked into logs or plan")
			}
		}
		_ = filepath.Walk(f.root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || strings.HasSuffix(path, "hapd-wl0.conf") {
				return nil
			}
			if b, _ := os.ReadFile(path); strings.Contains(string(b), pl.Passphrase) {
				t.Errorf("placeholder passphrase in %s", path)
			}
			return nil
		})
		if st, _ := os.Stat(f.path("/tmp/udeco/hapd-wl0.conf")); st.Mode().Perm() != 0o600 {
			t.Errorf("conf mode %o", st.Mode().Perm())
		}
		if f.state["wl01 bss"] != "down" {
			t.Error("placeholder BSS up")
		}
		// Stable: a re-plan, and a fresh Applier (agent restart), change
		// nothing.
		if p, _ := a.Plan(ctx, d); !p.Empty() {
			t.Fatalf("second plan:\n%s", p)
		}
		if p, _ := newTestApplier(f, false).Plan(ctx, d); !p.Empty() {
			t.Fatalf("plan after restart:\n%s", p)
		}
	}
	if confs["a"].Passphrase == confs["b"].Passphrase || confs["a"].SSID == confs["b"].SSID {
		t.Error("placeholder not random")
	}
}

// Lower and unbridge steps on a vif that no longer exists have nothing to
// do (live fact F2); a raise on it still fails.
func TestStepOnAbsentVif(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	f.killProc(10510, true) // deletes wl02..wl06
	if err := a.do(ctx, onVif("wl02", cmdStep("lower wl02", "wl", "-i", "wl02", "bss", "down"))); err != nil {
		t.Errorf("lower absent wl02 = %v", err)
	}
	if f.called("wl -i wl02") {
		t.Error("ran wl on an absent vif")
	}
	if err := a.do(ctx, Step{Kind: StepBridgeDel, Port: "wl02", IfPresent: "wl02"}); err != nil {
		t.Errorf("unbridge absent wl02 = %v", err)
	}
	if err := a.do(ctx, cmdStep("raise wl02", "wl", "-i", "wl02", "bss", "up")); err == nil || !strings.Contains(err.Error(), "adapter not found") {
		t.Errorf("raise absent wl02 = %v", err)
	}
	// Vanishing while the step runs (hostapd exit races the step).
	f.failOut = "wl: wl driver adapter not found"
	f.failOn = func(argv []string) bool {
		if strings.Join(argv, " ") == "wl -i wl12 bss down" {
			f.deleteVif("wl12")
			return true
		}
		return false
	}
	if err := a.do(ctx, onVif("wl12", cmdStep("lower wl12", "wl", "-i", "wl12", "bss", "down"))); err != nil {
		t.Errorf("lower vanishing wl12 = %v", err)
	}
	// An existing vif's failure is still a failure.
	f.failOn = func(argv []string) bool { return strings.Join(argv, " ") == "wl -i wl13 bss down" }
	if err := a.do(ctx, onVif("wl13", cmdStep("lower wl13", "wl", "-i", "wl13", "bss", "down"))); err == nil {
		t.Error("failure on an existing vif ignored")
	}
}

// A hostapd that never finishes its BSS setup fails the apply (and the
// hand-back runs) instead of configuring vifs that do not exist.
func TestStartWaitTimesOut(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	p, _ := a.Plan(ctx, twoSSIDs())
	f.reset()
	f.stall = true
	err := a.Apply(ctx, p)
	if err == nil || !strings.Contains(err.Error(), "hostapd setup not finished after 15s: wl02 does not exist") {
		t.Fatalf("Apply = %v", err)
	}
	// (Apply's baseline capture reads wl02's dwds; no setter may run. The
	// hand-back's TP-Link restart stalls too, so its raise of wl02 fails.)
	if f.called("wl -i wl02 dwds 0") {
		t.Error("configured wl02 before it existed")
	}
}

// The BSSIDs of vifs that only exist while a hostapd runs come from
// TP-Link's conf and the baseline, so placement and the conf still work
// after the vifs are gone.
func TestBSSIDOfAbsentVif(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	f.killProc(10510, true)
	f.killProc(10912, true)
	if !a.vifKnown("wl05") || a.vifKnown("wl07") {
		t.Errorf("vifKnown wl05=%t wl07=%t", a.vifKnown("wl05"), a.vifKnown("wl07"))
	}
	if m, err := a.bssid(ctx, "wl05"); err != nil || m != "ba:a7:b9:3e:17:07" {
		t.Errorf("bssid wl05 = %q %v", m, err)
	}
	d := twoSSIDs()
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatalf("Apply with every bss= vif absent = %v", err)
	}
	if f.state["wl02 bss"] != "up" || f.bridgeOf("wl12") != "br-lan" {
		t.Error("SSIDs not up")
	}
}
