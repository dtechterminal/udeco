// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/models"
)

// mdns_bridge needs takeover and apply, hotspot2 needs takeover; both are
// off by default.
func TestConfigMdnsBridgeAndHotspot2(t *testing.T) {
	base := `{"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1"`
	for _, c := range []struct{ json, err string }{
		{`,"mdns_bridge":true}`, "mdns_bridge needs takeover and apply"},
		{`,"takeover":true,"mdns_bridge":true}`, "mdns_bridge needs takeover and apply"},
		{`,"hotspot2":true}`, "hotspot2 needs takeover"},
	} {
		if _, err := parseConfig([]byte(base + c.json)); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: %v", c.json, err)
		}
	}
	c, err := parseConfig([]byte(base + `,"takeover":true,"apply":true,"mdns_bridge":true,"hotspot2":true}`))
	if err != nil || !c.MdnsBridge || !c.Hotspot2 {
		t.Errorf("takeover+apply: %+v %v", c, err)
	}
	if c, err := parseConfig([]byte(base + `}`)); err != nil || c.MdnsBridge || c.Hotspot2 {
		t.Errorf("default: %+v %v", c, err)
	}
}

// Takeover claims RadSec (fw2_caps 0x80000); the mDNS bridge (fw2_caps
// 0x10000000) and Hotspot 2.0 (fw_caps 0x800000) only with their config
// keys; SNMPv3 (fw_caps 0x4000) in both modes. A drop to observe clears
// every takeover bit, fw2_caps included, and keeps SNMPv3.
func TestTakeoverClaimsAndDropClearsFW2(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) { c.Takeover = true })
	h.start()
	eventually(t, "takeover claims", func() bool {
		m := h.ctl.last()
		return m != nil && int(num(m["wifi_caps"]))&models.WifiCapRFScan != 0
	})
	m := h.ctl.last()
	if int(num(m["fw2_caps"])) != models.FW2CapRadSec || int(num(m["fw_caps"]))&models.FWCapHotspot2 != 0 ||
		int(num(m["fw_caps"]))&models.FWCapSNMPv3 == 0 {
		t.Errorf("takeover without keys: fw %v fw2 %v", m["fw_caps"], m["fw2_caps"])
	}
	h.a.submit("drop", func(ctx context.Context) { h.a.dropToObserve(ctx, "test") })
	eventually(t, "RadSec no longer claimed", func() bool {
		m := h.ctl.last()
		return m != nil && m["fw2_caps"] == nil
	})
	h.stop()
	m = h.ctl.last()
	if int(num(m["fw_caps"]))&models.DecoAgentTakeoverFWCaps != 0 || int(num(m["fw_caps"]))&models.FWCapSNMPv3 == 0 {
		t.Errorf("observe after the drop: fw %v", m["fw_caps"])
	}
}

func TestTakeoverClaimsWithKeys(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Apply, c.MdnsBridge, c.Hotspot2 = true, true, true, true
	})
	h.start()
	eventually(t, "takeover claims", func() bool {
		m := h.ctl.last()
		return m != nil && int(num(m["wifi_caps"]))&models.WifiCapRFScan != 0
	})
	h.stop()
	m := h.ctl.last()
	if int(num(m["fw2_caps"])) != models.FW2CapRadSec|models.FW2CapMdnsSdBridge ||
		int(num(m["fw_caps"]))&models.FWCapHotspot2 == 0 {
		t.Errorf("takeover with mdns_bridge and hotspot2: fw %v fw2 %v", m["fw_caps"], m["fw2_caps"])
	}
}

// scanGateCol is a collector that says whether it can scan (jio-mtk:
// mtkwifi.Collector.ScanSupported, true only with fresh site surveys).
type scanGateCol struct {
	*fakeCol
	can bool
}

func (c scanGateCol) ScanSupported() bool { return c.can }

// TestRFScanFollowsCollector: a collector that says it cannot scan keeps
// RF_SCAN unclaimed in takeover (the other takeover bits stay); one that
// can claims it.
func TestRFScanFollowsCollector(t *testing.T) {
	for _, can := range []bool{false, true} {
		h := newHarness(t, func(c *Config, o *options) {
			c.Takeover = true
			o.col = scanGateCol{fakeCol: o.col.(*fakeCol), can: can}
		})
		h.start()
		eventually(t, "takeover claims", func() bool {
			m := h.ctl.last()
			return m != nil && int(num(m["wifi_caps"]))&models.WifiCapLockAP != 0
		})
		if got := int(num(h.ctl.last()["wifi_caps"]))&models.WifiCapRFScan != 0; got != can {
			t.Errorf("ScanSupported %v: RF_SCAN claimed %v", can, got)
		}
		h.stop()
	}
}
