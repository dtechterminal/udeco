// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// scanPoll is how often Scan asks for results while the scan runs.
const scanPoll = 500 * time.Millisecond

// Scan runs an RF scan on the radio of band ("ng" or "na") and returns the
// neighbour networks it found (the controller's `cmd scan`: scan_table only;
// spectrum_table rows come from the spectrum runner, spectrum.go, §3.6).
//
// It runs `wl -i <radio> scan` (the radio leaves its channel briefly, as a
// UniFi RF scan does) and polls `wl scanresults` until the driver has them.
// It takes the same locks as a spectrum band: one scan at a time across
// radios, and while it runs Collect reports the radio's chanspec, noise and
// power as read before the scan (`wl chanspec` shows the scan channel during
// a scan [M T7]), never the scan channel.
func (c *Collector) Scan(ctx context.Context, band string) (*apstate.ScanResult, error) {
	return c.scan(ctx, band, func(string) []string { return []string{"scan"} })
}

// homeDwell: the passive listen on the radio's own channel (HomeScan).
const homeDwell = "110"

// HomeScan listens passively on the radio's own control channel only
// (`wl -i <radio> scan -t passive -p 110 -c <channel>`): the radio never
// leaves its channel, so clients are not disturbed. It is how a UniFi AP
// keeps its neighbour list fresh between RF scans: the U6 Pro reports the
// networks on its own channels every minute. Checked on .205 (2026-11-19):
// 2 networks on 2.4 GHz ch 9, 6 on 5 GHz ch 40, no station dropped.
func (c *Collector) HomeScan(ctx context.Context, band string) (*apstate.ScanResult, error) {
	var homeErr error
	res, err := c.scan(ctx, band, func(radio string) []string {
		out, err := c.wl(ctx, radio, "chanspec")
		if err != nil {
			homeErr = err
			return nil
		}
		cs, ok := parseChanspecHex(string(out))
		if !ok {
			homeErr = fmt.Errorf("wl -i %s chanspec: %q not understood", radio, strings.TrimSpace(string(out)))
			return nil
		}
		return []string{"scan", "-t", "passive", "-p", homeDwell, "-c", strconv.Itoa(cs.Control)}
	})
	if homeErr != nil {
		return nil, homeErr
	}
	return res, err
}

// scan runs one `wl scan` (args gives its arguments for the radio; nil
// stops before scanning) and reads its results.
func (c *Collector) scan(ctx context.Context, band string, args func(radio string) []string) (*apstate.ScanResult, error) {
	st, err := c.static(ctx)
	if err != nil {
		return nil, err
	}
	radio := ""
	for _, r := range st.radios {
		if r.band == band {
			radio = r.name
		}
	}
	if radio == "" {
		return nil, fmt.Errorf("wl: no radio for band %q", band)
	}
	if err := c.scanMu.LockCtx(ctx); err != nil {
		return nil, err
	}
	defer c.scanMu.Unlock()
	if err := c.holdCurrent(ctx, radio); err != nil {
		return nil, err
	}
	defer c.releaseCurrent(radio)

	a := args(radio)
	if a == nil {
		return nil, fmt.Errorf("wl: no scan arguments for %s", radio)
	}
	if _, err := c.wl(ctx, radio, a...); err != nil {
		return nil, err
	}
	pollCtx, cancel := context.WithTimeout(ctx, c.opt.ScanTimeout)
	defer cancel()
	var out []byte
	var lastErr error
	for {
		if err := c.sleep(pollCtx, scanPoll); err != nil {
			if errContains(lastErr, "Not Found") && ctx.Err() == nil {
				out = nil // the scan finished and found nothing
				break
			}
			return nil, fmt.Errorf("wl -i %s scanresults: %w (last: %v)", radio, err, lastErr)
		}
		out, err = c.wl(pollCtx, radio, "scanresults")
		if err == nil {
			break
		}
		// "Not Ready"/"Busy" while the scan runs, "Not Found" until a
		// result is in; anything else is a real failure.
		if !errContains(err, "Not Ready", "Busy", "Not Found") {
			return nil, err
		}
		lastErr = err
	}
	return &apstate.ScanResult{Band: band, Time: c.now(), BSS: parseScanResults(out, band)}, nil
}

// parseScanResults reads `wl scanresults`: one block per BSS, starting with
// an `SSID: "..."` line. The channel comes from the block's
// "Chanspec: ... (0x1906)" line when there is one, else from "Channel: 8u".
func parseScanResults(b []byte, band string) []apstate.BSS {
	var out []apstate.BSS
	var cur *apstate.BSS
	var cs chanspec
	var haveCS bool
	var sec apstate.SecInfo
	var chanText string
	flush := func() {
		if cur == nil || cur.BSSID == "" {
			cur = nil
			return
		}
		if !haveCS && chanText != "" {
			cs, haveCS = parseChanspecString(chanText, band)
		}
		if haveCS {
			cur.Channel, cur.Width = cs.Control, cs.Width
			cur.Freq = chanFreq(cs.Control, cs.Band)
			cur.CenterFreq = chanFreq(cs.Center, cs.Band)
		}
		cur.Security = apstate.SecurityLabel(sec)
		out = append(out, *cur)
		cur = nil
	}
	for line := range strings.Lines(string(b)) {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "SSID: ") {
			flush()
			cur = &apstate.BSS{SSID: parseSSID([]byte(t))}
			cs, haveCS, sec, chanText = chanspec{}, false, apstate.SecInfo{}, ""
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.HasPrefix(t, "Mode: "):
			// tab-separated "key: value" fields
			for _, f := range strings.Split(t, "\t") {
				k, v, _ := strings.Cut(f, ":")
				switch strings.TrimSpace(k) {
				case "RSSI":
					cur.Signal = int(firstInt(v))
				case "Channel":
					chanText = strings.TrimSpace(v)
				}
			}
		case strings.HasPrefix(t, "BSSID: "):
			f := strings.Fields(t)
			if mac, err := NormMAC(f[1]); err == nil {
				cur.BSSID = mac
			}
			if _, capText, ok := strings.Cut(t, "Capability:"); ok {
				for _, tok := range strings.Fields(capText) {
					sec.Privacy = sec.Privacy || tok == "WEP" || tok == "Privacy"
				}
			}
		case strings.HasPrefix(t, "RSN"):
			sec.RSN = true
		case t == "WPA:" || strings.HasPrefix(t, "WPA (") && strings.HasSuffix(t, ":"):
			sec.WPA = true
		case strings.HasPrefix(t, "AKM Suites"):
			_, suites, _ := strings.Cut(t, ":")
			sec.AKMs = append(sec.AKMs, strings.Fields(suites)...)
		case strings.HasPrefix(t, "multicast cipher") || strings.HasPrefix(t, "unicast cipher"):
			_, cs, _ := strings.Cut(t, ":")
			sec.Ciphers = append(sec.Ciphers, strings.Fields(cs)...)
		case strings.HasPrefix(t, "Chanspec:") && !haveCS:
			cs, haveCS = parseChanspecHex(t)
		}
	}
	flush()
	return out
}
