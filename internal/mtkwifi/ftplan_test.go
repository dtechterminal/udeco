// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/mtkft"
)

func ftLayoutBoth(sae2g bool) []RadioDef {
	l := append([]RadioDef(nil), JCOW414...)
	for i := range l {
		l[i].FT, l[i].FTSAE = true, true
		if l[i].Band == "ng" {
			l[i].SAE = sae2g
		}
	}
	return l
}

func ftDesired(sec string) bcmwifi.Desired {
	d := twoSSIDs()
	s := &d.SSIDs[0]
	s.Security, s.FT, s.FTSAE, s.FTKey = sec, true, true, testIAPPKey
	return d
}

// TestFTPlanDecosView: each band's BSS is in the mobility domain a Deco
// serves the SSID in (bcmwifi.SSIDMDID after its normalization), FT-SAE
// where the radio has SAE.
func TestFTPlanDecosView(t *testing.T) {
	d := ftDesired("wpa2wpa3")
	ps, notes := plans(d, ftLayoutBoth(true), true)
	norm, _ := bcmwifi.NormalizeFT(d.SSIDs[0])
	for _, band := range []string{"ng", "na"} {
		b := ps[band].BSS[0]
		if !b.FT || !b.FTSAE || b.MDID != bcmwifi.SSIDMDID(norm, band) {
			t.Errorf("%s: %+v, want FT-SAE in %04x", band, b, bcmwifi.SSIDMDID(norm, band))
		}
	}
	if ps["ng"].BSS[0].MDID == ps["na"].BSS[0].MDID {
		t.Errorf("FT-SAE SSIDs have one domain per band on the Decos")
	}
	if strings.Contains(joined(notes), "802.11r") {
		t.Errorf("notes %q", notes)
	}
	// the vendor 2.4 GHz driver (no SAE): FT-PSK only, in the Decos' 2.4 GHz domain
	ps, _ = plans(d, ftLayoutBoth(false), true)
	if b := ps["ng"].BSS[0]; b.Auth != "WPA2PSK" || !b.FT || b.FTSAE || b.MDID != bcmwifi.SSIDMDID(norm, "ng") {
		t.Errorf("ng without SAE %+v", b)
	}
	// ft_sae off on this unit (and so, by the same config, on the Decos):
	// FT-PSK in the SSID-wide domain; the MT7663 still offers FT-SAE (noted)
	l := ftLayoutBoth(true)
	for i := range l {
		l[i].FTSAE = false
	}
	ps, notes = plans(d, l, true)
	off := d.SSIDs[0]
	off.FTSAE, off.FTKey = false, ""
	off, _ = bcmwifi.NormalizeFT(off)
	if b := ps["na"].BSS[0]; !b.FT || b.FTSAE || b.MDID != bcmwifi.SSIDMDID(off, "na") || b.MDID != ps["ng"].BSS[0].MDID {
		t.Errorf("na without ft_sae %+v", b)
	}
	if !strings.Contains(joined(notes), `na: SSID "home": the driver offers FT-SAE with FT-PSK`) {
		t.Errorf("notes %q", notes)
	}
	// WPA3 only without a key: no FT (as a Deco), noted
	d = ftDesired("wpa3")
	d.SSIDs[0].FTKey = ""
	ps, notes = plans(d, ftLayoutBoth(true), true)
	if ps["na"].BSS[0].FT || !strings.Contains(joined(notes), "na: ssid a: 802.11r off: FT-SAE needs the controller's per-WLAN key") {
		t.Errorf("wpa3 without key %+v %q", ps["na"].BSS[0], notes)
	}
	// the controller's mobility domain is used as given
	d = ftDesired("wpa2")
	d.SSIDs[0].MobilityDomain = "ABCD"
	ps, _ = plans(d, ftLayoutBoth(true), true)
	if ps["na"].BSS[0].MDID != 0xabcd || ps["ng"].BSS[0].MDID != 0xabcd || ps["na"].BSS[0].FTSAE {
		t.Errorf("controller MDID %+v %+v", ps["na"].BSS[0], ps["ng"].BSS[0])
	}
	// enterprise and open: none
	d = ftDesired("open")
	ps, _ = plans(d, ftLayoutBoth(true), true)
	if ps["na"].BSS[0].FT {
		t.Errorf("open SSID with FT")
	}
}

// TestFTProfileKeys: the MT7663 gets mtkft.ProfileKeys (byte-swapped MDID,
// 24-character R0KH-ID), the MT7603 hostapd's order, FtSae and the 12 h
// PMK lifetime; a plan without FT writes no FT key at all.
func TestFTProfileKeys(t *testing.T) {
	d := ftDesired("wpa2wpa3")
	l := ftLayoutBoth(true)
	ps, _ := plans(d, l, true)
	na := ps["na"]
	na.BSS[0].R0KHID = mtkft.R0KHID(garageNA)
	md := ps["ng"].BSS[0].MDID
	wantKeys(t, "ng", profile(baseNG(), l[0], ps["ng"]), map[string]string{"FtSupport": "1;0;0;0", "FtSae": "1;0;0;0",
		"FtMdId1": fmt.Sprintf("%04x", md), "PMKCachePeriod": "720", "FtR0khId1": ""})
	wantKeys(t, "na", profile(baseNA(), l[1], na), map[string]string{"FtSupport": "1;0;0;0", "FtRic": "0;0;0;0", "FtOtd": "0;0;0;0",
		"FtMdId1": mtkft.MDIDValue(mtkft.MDID(na.BSS[0].MDID)), "FtR0khId1": mtkft.R0KHID(garageNA)})
	// pinned to slot 2
	ng := ps["ng"]
	ng.Slots = []int{2, 0}
	wantKeys(t, "ng slot", profile(baseNG(), l[0], ng), map[string]string{"FtSupport": "0;0;1;0", "FtMdId3": fmt.Sprintf("%04x", md), "FtMdId1": ""})
	// no FT: nothing written (the profile of an older agent)
	ps, _ = plans(twoSSIDs(), l, true)
	wantKeys(t, "off", profile(baseNG(), l[0], ps["ng"]), map[string]string{"FtSupport": "", "PMKCachePeriod": "", "FtSae": ""})
	wantKeys(t, "off na", profile(baseNA(), l[1], ps["na"]), map[string]string{"FtSupport": "", "FtMdId1": ""})
}

func writeNetdevAddr(t *testing.T, root, ifc, mac string) {
	t.Helper()
	p := filepath.Join(root, "sys/class/net", ifc)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "address"), []byte(mac+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestFTIDsAndLocals: the R0KH-ID comes from the slot's netdev; without an
// address the BSS has no FT (noted); FTLocals announces valid holders.
func TestFTIDsAndLocals(t *testing.T) {
	root := t.TempDir()
	writeNetdevAddr(t, root, "rai0", garageNA.String())
	writeNetdevAddr(t, root, "ra0", garageNG.String())
	a := New(Options{Root: root, FT: true, FTSAE: true, WPA3: true, Layout: ftLayoutBoth(true), roamIO: &fakeRoamIO{}})
	d := ftDesired("wpa2wpa3")
	ps, _ := plans(d, a.o.Layout, true)
	if n := a.ftIDs(ps); len(n) != 0 {
		t.Fatal(n)
	}
	if got := ps["na"].BSS[0].R0KHID; got != mtkft.R0KHID(garageNA) {
		t.Fatalf("R0KH-ID %q", got)
	}
	a.mu.Lock()
	a.live, a.desired = ps, d
	a.mu.Unlock()
	ls, err := a.FTLocals(t.Context(), d)
	if err != nil || len(ls) != 2 {
		t.Fatalf("locals %v %v", ls, err)
	}
	for _, l := range ls {
		if err := l.Holder.Valid(); err != nil || l.Bridge != "bdg2" || l.Key != testIAPPKey {
			t.Errorf("local %v: %v", l, err)
		}
	}
	if ls[0].Holder.R0KHID != garageNG.Hex() || ls[1].Holder.R0KHID != mtkft.R0KHID(garageNA) {
		t.Errorf("R0KH-IDs %q %q", ls[0].Holder.R0KHID, ls[1].Holder.R0KHID)
	}
	// no address: FT off on that BSS, noted
	b := New(Options{Root: t.TempDir(), FT: true, Layout: ftLayoutBoth(true)})
	ps, _ = plans(d, b.o.Layout, true)
	n := b.ftIDs(ps)
	if ps["na"].BSS[0].FT || len(n) != 1 || !strings.Contains(n[0], `na: SSID "home": 802.11r not served: the address of rai0`) {
		t.Fatalf("%+v %q", ps["na"].BSS[0], n)
	}
}

// TestWithDriverFT: only the module with the agent's FT interface turns
// 2.4 GHz FT on; ft off turns both radios' FT off with a reason.
func TestWithDriverFT(t *testing.T) {
	root := t.TempDir()
	if l := WithDriverFT(root, JCOW414); l[0].FT {
		t.Fatal("FT without kallsyms")
	}
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	ks := "c0a1b2c3 t FT_UDFT_GetEvents\t[mt76x3_ap]\n"
	_ = os.WriteFile(filepath.Join(root, "proc/kallsyms"), []byte("00000000 T FT_KDP_EventInform\n"+ks), 0o644)
	if l := WithDriverFT(root, JCOW414); !l[0].FT || !l[1].FT {
		t.Fatal("mt7603roam not detected")
	}
	// the SAE-only build: same module name, no such symbol
	_ = os.WriteFile(filepath.Join(root, "proc/kallsyms"), []byte("c0a1b2c3 t SAE_Init\t[mt76x3_ap]\n00000000 T FT_UDFT_GetEvents\n"), 0o644)
	if l := WithDriverFT(root, JCOW414); l[0].FT {
		t.Fatal("FT on the SAE-only module")
	}
	l := ftLayout(Options{Layout: JCOW414})
	if l[1].FT || l[1].NoFTWhy != "off in the agent's config (ft)" || !strings.Contains(l[0].NoFTWhy, "mt7603roam") {
		t.Fatalf("%+v", l)
	}
	_, notes := plans(ftDesired("wpa2"), l, true)
	if !strings.Contains(joined(notes), `na: SSID "home": 802.11r not served: off in the agent's config (ft)`) {
		t.Fatalf("notes %q", notes)
	}
}
