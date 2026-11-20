// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// TestJioDropToObserveEndsLocate: on jio-mtk nothing but the agent sets
// the front LED, and observe mode refuses every LED job, so the drop to
// observe ends a Locate blink itself (back to the led_enabled state).
func TestJioDropToObserveEndsLocate(t *testing.T) {
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover, c.Platform, c.Model = true, PlatformJio, "U7LT"
	})
	for _, f := range jioGateFiles {
		p := filepath.Join(h.root, f)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, nil, 0o644)
	}
	h.start()
	eventually(t, "enforce", func() bool { return h.rec.count("enforce") > 0 })
	h.a.submit("locate on", func(ctx context.Context) { h.a.led(ctx, bcmwifi.LEDLocate) })
	eventually(t, "locate", func() bool { return h.rec.index("led:"+bcmwifi.LEDLocate) >= 0 })
	h.a.submit("drop", func(ctx context.Context) { h.a.dropToObserve(ctx, "test") })
	eventually(t, "restore", func() bool { return h.rec.index("restore") >= 0 })
	eventually(t, "locate ended by the drop", func() bool {
		return h.rec.index("led:"+bcmwifi.LEDLocateOff) > h.rec.index("led:"+bcmwifi.LEDLocate)
	})
	h.stop()
}
