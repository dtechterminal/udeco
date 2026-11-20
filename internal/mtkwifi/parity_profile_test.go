// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// The U6 defaults and controller keys that ride the driver profile
// (docs/deco/features/garage-parity.md, items 2-8 and WirelessEvent).

// vendorParity is the parity snapshot's vendor values for the keys the
// batch rewrites (parity-snap garage-dat.txt).
const (
	vendorParityNG = "PMKCachePeriod=10\nWirelessEvent=0\nHT_BSSCoexistence=1\nAutoChannelSkipList=0\nBandSteering=1;1;1;1\n" +
		"WscConfMode=4;4;4;4\nWscConfStatus=2;2;2;2\nRekeyInterval=0;3600;3600;3600\nRekeyMethod=DISABLE;TIME;TIME;TIME\n"
	vendorParityNA = "PMKCachePeriod=10\nWirelessEvent=0\nHT_BSSCoexistence=0\nETxBfEnCond=1\nITxBfEn=1\nAutoChannelSkipList=165\n" +
		"BandSteering=0;1;1;1\nWscConfMode=4;4;4;4\nWscConfStatus=2;2;2;2\nRekeyInterval=3600;3600;3600;3600\nRekeyMethod=TIME;TIME;TIME;TIME\n"
)

func parityBase(band string) []byte {
	if band == "ng" {
		return []byte(baseDat + featNG + vendorParityNG)
	}
	return []byte(strings.Replace(baseDat, "MaxStaNum", "MbssMaxStaNum", 1) + featNA + vendorParityNA)
}

// TestProfileU6Defaults: WPS off and the vendor's band steering flag off
// on every slot; 2.4 GHz 20/40 coexistence off and 5 GHz implicit
// beamforming off (U6 disablecoext 1, implicitbf 0); 5 GHz driver
// wireless events on; the 5 GHz PMK cache 12 h.
func TestProfileU6Defaults(t *testing.T) {
	ps, _ := plans(twoSSIDs(), JCOW414, true)
	wantKeys(t, "ng", profile(parityBase("ng"), JCOW414[0], ps["ng"]), map[string]string{
		"WscConfMode": "0;0;0;0", "BandSteering": "0;0;0;0", "HT_BSSCoexistence": "0",
		"WscConfStatus": "2;2;2;2", "WirelessEvent": "0", "PMKCachePeriod": "10"})
	wantKeys(t, "na", profile(parityBase("na"), JCOW414[1], ps["na"]), map[string]string{
		"WscConfMode": "0;0;0;0", "BandSteering": "0;0;0;0", "ITxBfEn": "0", "ETxBfEnCond": "1",
		"WirelessEvent": "1", "PMKCachePeriod": "720", "HT_BSSCoexistence": "0"})
	if _, ok := getKey(profile(parityBase("ng"), JCOW414[0], ps["ng"]), "ITxBfEn"); ok {
		t.Error("ITxBfEn written to the MT7603 profile")
	}
}

// TestProfileGroupRekey: each served BSS's GTK rekey follows the
// controller (TIME and the interval, else DISABLE and 0; an open BSS is
// always DISABLE); the slots not served keep the vendor's values.
func TestProfileGroupRekey(t *testing.T) {
	d := twoSSIDs()
	d.SSIDs[0].GroupRekey = 3600
	d.SSIDs[1].GroupRekey = 600 // open: no GTK to rotate
	ps, _ := plans(d, JCOW414, false)
	if ps["ng"].BSS[0].GroupRekey != 3600 || ps["ng"].BSS[1].GroupRekey != 0 {
		t.Errorf("ng BSS rekey %d/%d", ps["ng"].BSS[0].GroupRekey, ps["ng"].BSS[1].GroupRekey)
	}
	wantKeys(t, "ng", profile(parityBase("ng"), JCOW414[0], ps["ng"]), map[string]string{
		"RekeyMethod": "TIME;DISABLE;TIME;TIME", "RekeyInterval": "3600;0;3600;3600"})
	d.SSIDs[0].GroupRekey = 0 // the controller's "never"
	ps, _ = plans(d, JCOW414, false)
	wantKeys(t, "na", profile(parityBase("na"), JCOW414[1], ps["na"]), map[string]string{
		"RekeyMethod": "DISABLE;TIME;TIME;TIME", "RekeyInterval": "0;3600;3600;3600"})
}

// TestProfileACSSkip: 2.4 GHz automatic channel skips everything but
// 1/6/11 (U6 block_acs_channel -band 1 2,3,4,5,7,8,9,10,...); a fixed
// channel keeps the vendor's list; 5 GHz is not touched.
func TestProfileACSSkip(t *testing.T) {
	d := twoSSIDs()
	d.Radios["ng"] = bcmwifi.Radio{Enabled: true, Channel: 0, Width: 20}
	d.Radios["na"] = bcmwifi.Radio{Enabled: true, Channel: 0, Width: 80}
	ps, _ := plans(d, JCOW414, false)
	wantKeys(t, "ng auto", profile(parityBase("ng"), JCOW414[0], ps["ng"]), map[string]string{"AutoChannelSkipList": "2;3;4;5;7;8;9;10"})
	wantKeys(t, "na auto", profile(parityBase("na"), JCOW414[1], ps["na"]), map[string]string{"AutoChannelSkipList": "165"})
	ps, _ = plans(twoSSIDs(), JCOW414, false)
	wantKeys(t, "ng fixed", profile(parityBase("ng"), JCOW414[0], ps["ng"]), map[string]string{"AutoChannelSkipList": "0"})
}

// TestProfileMcastPerBSS: on 5 GHz IgmpSnEnable is a per-BSS list and
// follows each SSID's multicast enhancement, off included; 2.4 GHz has
// one value and is never turned off.
func TestProfileMcastPerBSS(t *testing.T) {
	d := twoSSIDs()
	d.SSIDs = append(d.SSIDs, bcmwifi.SSID{ID: "c", SSID: "media", Bands: []string{"5g"}, Enabled: true,
		Security: "wpa2", Passphrase: "secret-media", MulticastToUnicast: true})
	ps, notes := plans(d, JCOW414, false)
	wantKeys(t, "na", profile(parityBase("na"), JCOW414[1], ps["na"]), map[string]string{"IgmpSnEnable": "0;1;1;1"})
	wantKeys(t, "ng", profile(parityBase("ng"), JCOW414[0], ps["ng"]), map[string]string{"IgmpSnEnable": "1"})
	if j := joined(notes); strings.Contains(j, "na: multicast enhancement") {
		t.Errorf("5 GHz per-BSS multicast enhancement noted as per radio: %q", notes)
	}
}

// TestFirstDeployOneRestartPerRadio: a unit running an older build's
// profiles (none of the batched keys) is brought to this build with
// exactly one down/up per radio, and the next plan changes nothing.
func TestFirstDeployOneRestartPerRadio(t *testing.T) {
	f := newFakeDev(t)
	for _, rd := range JCOW414 {
		p := filepath.Join(f.root, rd.Dat)
		os.WriteFile(p, parityBase(rd.Band), 0o644)
	}
	ctx := context.Background()
	d := home()
	d.SSIDs[0].GroupRekey = 3600
	old := newApplier(f)
	p, _ := old.Plan(ctx, d)
	if err := old.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	// the older build's profiles: the batch keys as the vendor had them
	for _, rd := range JCOW414 {
		path := filepath.Join(f.root, rd.Dat)
		b, _ := os.ReadFile(path)
		vend := parityBase(rd.Band)
		kv := map[string]string{}
		for _, k := range []string{"WscConfMode", "BandSteering", "RekeyMethod", "RekeyInterval", "PMKCachePeriod",
			"WirelessEvent", "ITxBfEn", "HT_BSSCoexistence", "AutoChannelSkipList", "IgmpSnEnable"} {
			if v, ok := getKey(vend, k); ok {
				kv[k] = v
			}
		}
		os.WriteFile(path, setKeys(b, kv), 0o600)
	}
	os.WriteFile(filepath.Join(f.root, "tmp/udeco", appliedFile), []byte("older-build\n"), 0o644)
	n := len(f.log)
	b := newApplier(f)
	p, _ = b.Plan(ctx, d)
	if err := b.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	downs := map[string]int{}
	for _, c := range restarts(f.log[n:]) {
		if strings.HasSuffix(c, " down") && (strings.HasPrefix(c, "ifconfig ra0 ") || strings.HasPrefix(c, "ifconfig rai0 ")) {
			downs[strings.Fields(c)[1]]++
		}
	}
	if downs["ra0"] != 1 || downs["rai0"] != 1 {
		t.Errorf("first deploy restarts: %v, want one per radio", downs)
	}
	n = len(f.log)
	p, _ = b.Plan(ctx, d)
	if err := b.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if r := restarts(f.log[n:]); len(r) > 0 {
		t.Errorf("second apply restarted: %v", r)
	}
}
