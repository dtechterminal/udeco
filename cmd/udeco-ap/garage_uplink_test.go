// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/mtkwifi"
)

type uplinkWifi struct {
	wifiApplier
	calls []bool
}

func (u *uplinkWifi) SetUplinkDown(_ context.Context, down bool) error {
	u.calls = append(u.calls, down)
	return nil
}

// TestUplinkLossStep: the uplink port's carrier (switch port 4) drives
// the applier's isolation through mtkwifi.UplinkWatch, one call per
// change; no switch reading is no decision.
func TestUplinkLossStep(t *testing.T) {
	root := t.TempDir()
	status := filepath.Join(root, "proc/tc3162/eth_port_status")
	os.MkdirAll(filepath.Dir(status), 0o755)
	a := &agent{cfg: &Config{Platform: PlatformJio, Takeover: true, Apply: true}}
	a.o.root = root
	a.o.logf = func(string, ...any) {}
	a.events = &eventLog{path: filepath.Join(root, "events.log"), root: root, clock: time.Now, logf: a.o.logf}
	w := &uplinkWifi{}
	a.wifi = w
	var st uplinkState
	t0 := time.Unix(1_800_000_000, 0)
	ctx := context.Background()
	for s := 0; s < 20; s++ { // no reading at all
		a.uplinkStep(ctx, &st, t0.Add(time.Duration(s)*time.Second))
	}
	os.WriteFile(status, []byte("1 1 1 0\n"), 0o644)
	for s := 20; s < 40; s++ {
		a.uplinkStep(ctx, &st, t0.Add(time.Duration(s)*time.Second))
	}
	if len(w.calls) != 1 || !w.calls[0] {
		t.Fatalf("calls %v", w.calls)
	}
	os.WriteFile(status, []byte("1 1 1 1\n"), 0o644)
	for s := 40; s < 80; s++ {
		a.uplinkStep(ctx, &st, t0.Add(time.Duration(s)*time.Second))
	}
	if len(w.calls) != 2 || w.calls[1] {
		t.Fatalf("calls %v", w.calls)
	}
	b, _ := os.ReadFile(filepath.Join(root, "events.log"))
	if !strings.Contains(string(b), "UPLINK") {
		t.Errorf("events.log: %q", b)
	}
	_ = mtkwifi.UplinkWatch{}
}

func TestUplinkLossConfig(t *testing.T) {
	base := `{"inform_url":"http://192.168.1.1:8080/inform","console_ip":"192.168.1.2","platform":"jio-mtk","model":"U7LT","takeover":true,"apply":true`
	c, err := parseConfig([]byte(base + `}`))
	if err != nil || !c.uplinkLoss() {
		t.Errorf("default: %v %v", err, c)
	}
	c, err = parseConfig([]byte(base + `,"uplink_loss":false}`))
	if err != nil || c.uplinkLoss() {
		t.Errorf("off: %v", err)
	}
	if _, err := parseConfig([]byte(base + `,"uplink_loss_ssid":"Example Network"}`)); err != nil {
		t.Errorf("ssid: %v", err)
	}
	deco := `{"inform_url":"http://192.168.1.1:8080/inform","console_ip":"192.168.1.2","takeover":true`
	for _, k := range []string{`,"uplink_loss":true}`, `,"uplink_loss_ssid":"x"}`} {
		if _, err := parseConfig([]byte(deco + k)); err == nil {
			t.Errorf("Deco accepted %s", k)
		}
	}
}
