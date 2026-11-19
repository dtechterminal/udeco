// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

// macDump is the JCOW414's MT7603 table as printed (2026-11-19, keys in
// the log interleave with other driver lines).
const macDump = `<4>BA - Send ADDBA request. StartSeq = 1ee,  FrameLen = 33. BufSize = 64
Show_MacTable_Proc(): arg=
Dump MacTable entries info, EntType=0x20001

HT Operating Mode : 3


MAC                MODE AID  BSS PSM WMM MIMOPS RSSI0/1/2 PhMd  BW  MCS   SGI   STBC  Idle   Rate   QosMap
MWDSCap C0:F8:53:17:23:A7  200011    0   0   1   3      -70/-83/0  HTMIX 20M 7     1   1    300    72     0         , 2243253, 100%
NO                                                              MaxCap:HTMIX     20M   7     1   1    -    72

FC:3C:D7:31:00:CD  200012    2   0   1   3      -49/-52/0  HTMIX 20M 7     1   1    300    72     0         , 48895, 100%
NO                                                              MaxCap:HTMIX     20M   7     1   1    -    72

96:97:74:02:D6:8B  200014    0   0   1   3      -62/-64/0  HTMIX 20M 12    0   0    300    78     0         , 399302, 100%
NO                                                              MaxCap:HTMIX     20M   15    1   1    -    144
`

func TestParseMacTable(t *testing.T) {
	got := parseMacTable("old\nMAC                MODE AID  BSS PSM WMM MIMOPS RSSI0/1/2 PhMd  BW  MCS   SGI   STBC  Idle   Rate   QosMap\n" +
		"AA:AA:AA:AA:AA:AA  1 0 0 1 3 -1/-1/0 HTMIX 20M 7 1 1 300 72 0 , 5, 100%\n" + macDump)
	if len(got) != 3 {
		t.Fatalf("%d stations, want 3 (only the newest table): %+v", len(got), got)
	}
	s := got[0]
	if s.MAC != "c0:f8:53:17:23:a7" || s.bss != 0 || s.Signal != -70 || s.TxRate != 72000 || s.Connected != 2243253 ||
		!s.HT || s.VHT || s.MHz != 20 || s.NSS != 1 {
		t.Errorf("first station %+v", s)
	}
	if got[1].bss != 2 || got[1].Signal != -49 {
		t.Errorf("second station on BSS %d at %d dBm", got[1].bss, got[1].Signal)
	}
	if got[2].NSS != 2 || got[2].TxRate != 78000 {
		t.Errorf("third station NSS %d rate %d", got[2].NSS, got[2].TxRate)
	}
}

// TestParseShortTable: get_mac_table's short table (after a radio restart)
// has no signal or rate and is not parsed as stations.
func TestParseShortTable(t *testing.T) {
	short := "MAC           AP  AID PSM AUTHCTxR  LTxR  LDT       RxB       TxB       \nfc3cd73100cd  1   1   1   1   54    0     0         0         0\n"
	if got := parseMacTable(short); len(got) != 0 {
		t.Errorf("short table parsed: %+v", got)
	}
}

func TestNewLog(t *testing.T) {
	before := strings.Repeat("x", 300) + "MAC  MODE AID  BSS\nOLD"
	after := before + "\nMAC  MODE AID  BSS\nNEW"
	if got := newLog(before, after); !strings.Contains(got, "NEW") || strings.Contains(got, "OLD") {
		t.Errorf("newLog = %q", got)
	}
	// nothing printed for this request: no table, not the old one
	if got := parseMacTable(newLog(macDump, macDump)); len(got) != 0 {
		t.Errorf("stale table parsed: %d stations", len(got))
	}
}

// home is the controller's Wi-Fi at home plus the Garage AP's own SSIDs.
func home() bcmwifi.Desired {
	return bcmwifi.Desired{
		Radios: map[string]bcmwifi.Radio{"ng": {Enabled: true, Channel: 6, Width: 20}, "na": {Enabled: true, Channel: 36, Width: 80}},
		SSIDs: []bcmwifi.SSID{
			{ID: "a", SSID: "Example Network", Bands: []string{"2g", "5g"}, Enabled: true, Security: "wpa2wpa3", Passphrase: "secret-home"},
			{ID: "b", SSID: "olive#", Bands: []string{"5g"}, Enabled: true, Security: "wpa2", Passphrase: "secret-olive", VLAN: 3},
			{ID: "c", SSID: "ORCHID", Bands: []string{"2g"}, Enabled: true, Security: "wpa2", Passphrase: "secret-orchid"},
			{ID: "d", SSID: "Example Network(2.4GHz)", Bands: []string{"2g"}, Enabled: true, Security: "wpa2", Passphrase: "secret-home"},
			{ID: "e", SSID: "wpa3 only", Bands: []string{"2g"}, Enabled: true, Security: "wpa3", Passphrase: "secret-x123"},
		},
	}
}

func TestPlans(t *testing.T) {
	ps, notes := plans(home(), JCOW414, false)
	ng, na := ps["ng"], ps["na"]
	if !ng.On || len(ng.BSS) != 3 || ng.BSS[1].SSID != "ORCHID" || ng.Channel != 6 || ng.Width != 20 {
		t.Errorf("ng plan %+v", ng)
	}
	if !na.On || len(na.BSS) != 2 || na.BSS[1].VLAN != 3 || na.Width != 80 {
		t.Errorf("na plan %+v", na)
	}
	j := strings.Join(notes, "\n")
	if !strings.Contains(j, `"wpa3 only": security wpa3 is not supported`) || !strings.Contains(j, "served as WPA2 only") {
		t.Errorf("notes %q", notes)
	}
	d := home()
	d.Radios["na"] = bcmwifi.Radio{Enabled: false}
	if ps, _ := plans(d, JCOW414, false); ps["na"].On || len(ps["na"].BSS) != 0 {
		t.Errorf("disabled radio planned on: %+v", ps["na"])
	}
}

// TestPlansSAE: with WPA3 on, 5 GHz serves WPA2/WPA3 transition and
// WPA3-only with PMF; 2.4 GHz (MT7603, no SAE) stays WPA2.
func TestPlansSAE(t *testing.T) {
	d := home()
	d.SSIDs = append(d.SSIDs, bcmwifi.SSID{ID: "f", SSID: "wpa3 5", Bands: []string{"5g"}, Enabled: true, Security: "wpa3", Passphrase: "secret-y123"})
	ps, notes := plans(d, JCOW414, true)
	ng, na := ps["ng"], ps["na"]
	if ng.BSS[0].Auth != "WPA2PSK" || ng.BSS[0].PMF != 0 || len(ng.BSS) != 3 {
		t.Errorf("ng %+v", ng.BSS)
	}
	if len(na.BSS) != 3 || na.BSS[0].Auth != "WPA2PSKWPA3PSK" || na.BSS[0].PMF != 1 ||
		na.BSS[1].Auth != "WPA2PSK" || na.BSS[2].Auth != "WPA3PSK" || na.BSS[2].PMF != 2 {
		t.Errorf("na %+v", na.BSS)
	}
	j := strings.Join(notes, "\n")
	if !strings.Contains(j, `ng: SSID "wpa3 only": security wpa3 is not supported`) || !strings.Contains(j, `ng: SSID "Example Network": served as WPA2 only`) ||
		strings.Contains(j, `na: SSID "Example Network": served as WPA2`) {
		t.Errorf("notes %q", notes)
	}
	p := profile([]byte(baseDat), JCOW414[1], na)
	for k, v := range map[string]string{"AuthMode": "WPA2PSKWPA3PSK;WPA2PSK;WPA3PSK;WPA2PSK", "PMFMFPC": "1;0;1;0", "PMFMFPR": "0;0;1;0", "PMFSHA256": "0;0;0;0"} {
		if got, _ := getKey(p, k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	// 2.4 GHz profile gets no PMF keys; WPA3 off serves 5 GHz as WPA2
	if _, ok := getKey(profile([]byte(baseDat), JCOW414[0], ng), "PMFMFPC"); ok {
		t.Errorf("PMF keys written to the 2.4 GHz profile")
	}
	if ps, _ := plans(d, JCOW414, false); ps["na"].BSS[0].Auth != "WPA2PSK" || len(ps["na"].BSS) != 2 {
		t.Errorf("WPA3 off: na %+v", ps["na"].BSS)
	}
}

const baseDat = `Default
CountryCode=IN
AutoChannelSelect=3
Channel=0
BssidNum=4
HT_BW=1
HT_EXTCHA=1
TxPower=75
SSID1=Example Network(2.4GHz)
WPAPSK1=vendor-key
SSID2=JioFiber-TChru-BH
WPAPSK2=backhaul-key
SSID3=ORCHID
SSID4=Jio_3
HideSSID=0;1;0;0
AuthMode=WPA2PSK;WPA2PSK;WPA2PSK;WPA2PSK
EncrypType=AES;AES;AES;AES
NoForwarding=0;0;0;0
MaxStaNum=22;10;1;1
IEEE8021X=0;0;0;0
`

func TestProfile(t *testing.T) {
	ps, _ := plans(home(), JCOW414, false)
	p := profile([]byte(baseDat), JCOW414[0], ps["ng"])
	want := map[string]string{"AutoChannelSelect": "0", "Channel": "6", "HT_BW": "0", "TxPower": "100",
		"SSID1": "Example Network", "SSID2": "ORCHID", "SSID3": "Example Network(2.4GHz)", "SSID4": "Jio_3",
		"WPAPSK1": "secret-home", "WPAPSK2": "secret-orchid", "HideSSID": "0;0;0;0", "MaxStaNum": "32;32;32;1",
		"AuthMode": "WPA2PSK;WPA2PSK;WPA2PSK;WPA2PSK", "CountryCode": "IN", "BssidNum": "4"}
	for k, v := range want {
		if got, _ := getKey(p, k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(string(p), "Default\n") {
		t.Errorf("profile header lost")
	}
	// 5 GHz 80 MHz on 36: secondary above
	ps["na"] = RadioPlan{Band: "na", On: true, Channel: 36, Width: 80, TxPct: 100, BSS: ps["na"].BSS}
	p = profile([]byte(strings.Replace(baseDat, "MaxStaNum", "MbssMaxStaNum", 1)), JCOW414[1], ps["na"])
	for k, v := range map[string]string{"HT_BW": "1", "VHT_BW": "1", "HT_EXTCHA": "1", "SSID2": "olive#"} {
		if got, _ := getKey(p, k); got != v {
			t.Errorf("na %s = %q, want %q", k, got, v)
		}
	}
}

// ------------------------------------------------------------ fake device

type fakeDev struct {
	t    *testing.T
	root string
	log  []string
	fail map[string]bool // command prefixes that fail
}

func newFakeDev(t *testing.T) *fakeDev {
	f := &fakeDev{t: t, root: t.TempDir(), fail: map[string]bool{}}
	for _, d := range []string{"bdg2", "eth0.4", "eth0.4.1"} {
		f.mkdev(d, 1)
	}
	f.link("eth0.4.1", "bdg2")
	for _, rd := range JCOW414 {
		for i, ifc := range rd.Ifaces {
			up := 0
			if rd.Band == "ng" && (i == 0 || i == 2) {
				up = 1
			}
			f.mkdev(ifc, up)
			if up == 1 {
				f.link(ifc, "bdg2")
			}
		}
		p := filepath.Join(f.root, rd.Dat)
		os.MkdirAll(filepath.Dir(p), 0o755)
		dat := baseDat
		if rd.Band == "na" {
			dat = strings.Replace(dat, "MaxStaNum", "MbssMaxStaNum", 1)
		}
		os.WriteFile(p, []byte(dat), 0o644)
	}
	os.MkdirAll(filepath.Join(f.root, "tmp/udeco"), 0o755)
	return f
}

func (f *fakeDev) mkdev(name string, flags int) {
	d := filepath.Join(f.root, "sys/class/net", name)
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, "flags"), []byte(fmt.Sprintf("0x%x\n", 0x1000|flags)), 0o644)
}

func (f *fakeDev) setUp(name string, up bool) {
	v := 0x1000
	if up {
		v |= 1
	}
	os.WriteFile(filepath.Join(f.root, "sys/class/net", name, "flags"), []byte(fmt.Sprintf("0x%x\n", v)), 0o644)
}

func (f *fakeDev) link(dev, br string) {
	d := filepath.Join(f.root, "sys/class/net", dev, "brport")
	os.RemoveAll(d)
	if br == "" {
		return
	}
	os.MkdirAll(d, 0o755)
	os.Symlink("../../"+br, filepath.Join(d, "bridge"))
}

func (f *fakeDev) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.log = append(f.log, cmd)
	for p := range f.fail {
		if strings.HasPrefix(cmd, p) {
			return nil, errors.New("fails")
		}
	}
	switch name {
	case "ifconfig":
		f.setUp(args[0], args[1] == "up")
	case "brctl":
		switch args[0] {
		case "addif":
			f.link(args[2], args[1])
		case "delif":
			f.link(args[2], "")
		case "addbr":
			f.mkdev(args[1], 0)
		case "delbr":
			os.RemoveAll(filepath.Join(f.root, "sys/class/net", args[1]))
		}
	case "ip":
		switch {
		case args[0] == "link" && args[1] == "add":
			f.mkdev(args[4], 0)
		case args[0] == "link" && args[1] == "set":
			f.setUp(args[2], args[3] == "up")
		case args[0] == "link" && args[1] == "del":
			os.RemoveAll(filepath.Join(f.root, "sys/class/net", args[2]))
		}
	case "iwconfig":
		// the BSS serves its profile slot's SSID (the driver read the
		// profile when the radio's first BSS came up)
		for _, rd := range JCOW414 {
			for i, ifc := range rd.Ifaces {
				if ifc == args[0] {
					b, _ := os.ReadFile(filepath.Join(f.root, rd.Dat))
					s, _ := getKey(b, "SSID"+strconv.Itoa(i+1))
					if rd.Band == "na" { // the MT7663's line goes on
						return []byte(ifc + `  RTWIFI SoftAP  ESSID:"` + s + `"  Nickname:""` + "\n  NWID:off/any  Mode:Master  Channel=157\n"), nil
					}
					return []byte(ifc + `  RTWIFI SoftAP  ESSID:"` + s + `"  ` + "\n  Mode:Master  Channel=6\n"), nil
				}
			}
		}
	}
	return nil, nil
}

func (f *fakeDev) bridge(dev string) string {
	l, _ := os.Readlink(filepath.Join(f.root, "sys/class/net", dev, "brport/bridge"))
	return filepath.Base(l)
}

func (f *fakeDev) up(dev string) bool {
	b, _ := os.ReadFile(filepath.Join(f.root, "sys/class/net", dev, "flags"))
	v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 0, 64)
	return v&1 == 1
}

func newApplier(f *fakeDev) *Applier {
	return New(Options{Root: f.root, Run: f, RunDir: "/tmp/udeco", StateDir: "/state", Uplink: "eth0.4.1",
		VerifyTimeout: time.Millisecond, sleep: func(context.Context, time.Duration) error { return nil }})
}

func TestApplyAndRestart(t *testing.T) {
	f := newFakeDev(t)
	a := newApplier(f)
	ctx := context.Background()
	p, err := a.Plan(ctx, home())
	if err != nil || len(p.Steps) != 2 {
		t.Fatalf("plan: %d steps, %v", len(p.Steps), err)
	}
	for _, s := range p.Steps {
		if strings.Contains(s.Desc, "secret") {
			t.Errorf("step shows a passphrase: %s", s.Desc)
		}
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for dev, want := range map[string]string{"ra0": "bdg2", "ra1": "bdg2", "ra2": "bdg2", "rai0": "bdg2", "rai1": "br-v3", "eth0.4.3": "br-v3"} {
		if !f.up(dev) || f.bridge(dev) != want {
			t.Errorf("%s up=%v bridge %q, want up in %q", dev, f.up(dev), f.bridge(dev), want)
		}
	}
	if f.up("ra3") || f.up("rai2") {
		t.Errorf("unused BSS up")
	}
	if !a.Owned() {
		t.Errorf("not owned after apply")
	}
	if err := a.Verify(ctx, home()); err != nil {
		t.Errorf("verify: %v", err)
	}
	// the profile keeps the passphrase and is not world-readable
	if st, _ := os.Stat(filepath.Join(f.root, JCOW414[0].Dat)); st.Mode().Perm() != 0o600 {
		t.Errorf("profile mode %v", st.Mode().Perm())
	}
	// an agent restart: same Desired, nothing restarted
	n := len(f.log)
	b := newApplier(f)
	if p, _ := b.Plan(ctx, home()); !p.Empty() {
		t.Errorf("restart plan not empty: %+v", p.Steps)
	}
	if len(f.log) != n+5 { // the five iwconfig reads of the check
		t.Errorf("restart ran %v", f.log[n:])
	}
	// hide ORCHID and isolate olive#: live, no restart
	d := home()
	d.SSIDs[2].Hidden, d.SSIDs[1].Isolation = true, true
	p, _ = b.Plan(ctx, d)
	n = len(f.log)
	if err := b.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.log[n:] {
		if strings.HasPrefix(c, "ifconfig") {
			t.Errorf("live change restarted a BSS: %s", c)
		}
	}
	if !strings.Contains(strings.Join(f.log[n:], "\n"), "iwpriv ra1 set HideSSID=1") {
		t.Errorf("ORCHID not hidden live: %v", f.log[n:])
	}
	// olive# gone: its VLAN bridge is removed
	d.SSIDs = append(d.SSIDs[:1], d.SSIDs[2:]...)
	p, _ = b.Plan(ctx, d)
	if err := b.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "sys/class/net/br-v3")); err == nil {
		t.Errorf("br-v3 left behind")
	}
}

func TestApplyFailureRollsBackToVendor(t *testing.T) {
	f := newFakeDev(t)
	a := newApplier(f)
	ctx := context.Background()
	f.fail["ifconfig rai0 up"] = true
	p, _ := a.Plan(ctx, home())
	if err := a.Apply(ctx, p); err == nil {
		t.Fatal("apply succeeded")
	}
	delete(f.fail, "ifconfig rai0 up")
	if a.Owned() {
		t.Errorf("still owned after a rollback with no last-good")
	}
	if !f.up("ra0") || !f.up("ra2") || f.up("ra1") || f.bridge("ra2") != "bdg2" {
		t.Errorf("vendor BSS state not restored")
	}
	if b, _ := os.ReadFile(filepath.Join(f.root, JCOW414[0].Dat)); string(b) != baseDat {
		t.Errorf("vendor profile not restored")
	}
	if err := a.Apply(ctx, p); !errors.Is(err, bcmwifi.ErrDesiredFailed) {
		t.Errorf("same Desired retried: %v", err)
	}
	a.ForgetFailed()
	if err := a.Apply(ctx, p); err != nil {
		t.Errorf("after ForgetFailed: %v", err)
	}
}

func TestTickRepairsBridge(t *testing.T) {
	f := newFakeDev(t)
	a := newApplier(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, home())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	f.link("rai1", "bdg2") // someone moved olive# onto the LAN
	r, _ := a.Tick(ctx)
	if r.Steps != 1 || r.NeedsApply || f.bridge("rai1") != "br-v3" {
		t.Errorf("tick %+v, rai1 in %q", r, f.bridge("rai1"))
	}
	f.setUp("ra1", false)
	if r, _ := a.Tick(ctx); !r.NeedsApply {
		t.Errorf("BSS down not reported: %+v", r)
	}
}

func TestBlockedAndKick(t *testing.T) {
	f := newFakeDev(t)
	a := newApplier(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, home())
	a.Apply(ctx, p)
	n := len(f.log)
	if err := a.SetBlocked(ctx, []string{"aa:bb:cc:dd:ee:ff"}); err != nil {
		t.Fatal(err)
	}
	j := strings.Join(f.log[n:], "\n")
	if !strings.Contains(j, "iwpriv rai1 set AccessPolicy=2") || !strings.Contains(j, "iwpriv ra0 set ACLAddEntry=AA:BB:CC:DD:EE:FF") {
		t.Errorf("deny list not applied: %v", f.log[n:])
	}
	n = len(f.log)
	a.Kick(ctx, "aa:bb:cc:dd:ee:ff")
	if !strings.Contains(strings.Join(f.log[n:], "\n"), "iwpriv ra2 set DisConnectSta=AA:BB:CC:DD:EE:FF") {
		t.Errorf("kick: %v", f.log[n:])
	}
}

// TestLockToAP: UniFi's Lock to AP reaches the other APs as lock2ap deny
// entries in each SSID's MAC filter. They are written in place (no radio
// restart), folded with the block list, and the locked client is
// disconnected; an unlock clears them without a restart either.
func TestLockToAP(t *testing.T) {
	f := newFakeDev(t)
	a := newApplier(f)
	ctx := context.Background()
	d := home()
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if p, _ := a.Plan(ctx, d); !p.Empty() {
		t.Fatalf("unchanged Desired planned steps: %+v", p.Steps)
	}
	// lock the purifier elsewhere: deny on every SSID here
	locked := home()
	for i := range locked.SSIDs {
		locked.SSIDs[i].MACFilter = &bcmwifi.MACFilter{Policy: "deny", MACs: []string{"c8:5c:cc:d1:2e:c7"}}
	}
	a.SetBlocked(ctx, []string{"aa:bb:cc:dd:ee:ff"})
	p, _ = a.Plan(ctx, locked)
	if len(p.Steps) != 1 || !strings.Contains(p.Steps[0].Desc, "station ACLs") {
		t.Fatalf("lock plan %+v", p.Steps)
	}
	n := len(f.log)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	j := strings.Join(f.log[n:], "\n")
	if strings.Contains(j, "ifconfig") {
		t.Errorf("a lock restarted a radio: %v", f.log[n:])
	}
	for _, want := range []string{"iwpriv ra0 set AccessPolicy=2", "iwpriv ra0 set ACLAddEntry=C8:5C:CC:D1:2E:C7",
		"iwpriv ra0 set ACLAddEntry=AA:BB:CC:DD:EE:FF", "iwpriv rai0 set ACLAddEntry=C8:5C:CC:D1:2E:C7",
		"iwpriv ra0 set DisConnectSta=C8:5C:CC:D1:2E:C7"} {
		if !strings.Contains(j, want) {
			t.Errorf("missing %q in %v", want, f.log[n:])
		}
	}
	if p, _ := a.Plan(ctx, locked); !p.Empty() {
		t.Errorf("lock re-planned: %+v", p.Steps)
	}
	// an agent restart keeps the lock without a step (RunDir holds it)
	b := newApplier(f)
	b.SetBlocked(ctx, []string{"aa:bb:cc:dd:ee:ff"}) // the agent stores it before planning
	if p, _ := b.Plan(ctx, locked); !p.Empty() {
		t.Errorf("restart with a lock planned steps: %+v", p.Steps)
	}
	// unlock: back to the block list only, still no restart
	p, _ = a.Plan(ctx, d)
	n = len(f.log)
	if err := a.Apply(ctx, p); err != nil || len(p.Steps) != 1 {
		t.Fatalf("unlock: %v %+v", err, p.Steps)
	}
	j = strings.Join(f.log[n:], "\n")
	if strings.Contains(j, "ifconfig") || strings.Contains(j, "ACLAddEntry=C8:5C") || !strings.Contains(j, "ACLAddEntry=AA:BB") {
		t.Errorf("unlock: %v", f.log[n:])
	}
}

func TestWantACLsAllow(t *testing.T) {
	d := home()
	d.SSIDs[0].MACFilter = &bcmwifi.MACFilter{Policy: "allow", MACs: []string{"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"}}
	ps, _ := plans(d, JCOW414, false)
	w := wantACLs(d, ps, JCOW414, []string{"BB:BB:BB:BB:BB:BB"})
	if a := w["ra0"]; a.Policy != 1 || len(a.MACs) != 1 || a.MACs[0] != "AA:AA:AA:AA:AA:AA" {
		t.Errorf("allow list ra0 = %+v", a)
	}
	if a := w["ra1"]; a.Policy != 2 || len(a.MACs) != 1 {
		t.Errorf("block-only ra1 = %+v", a)
	}
	if k := keptOut(ifaceACL{Policy: 1, MACs: []string{"A", "B"}}, ifaceACL{Policy: 1, MACs: []string{"A"}}); len(k) != 1 || k[0] != "B" {
		t.Errorf("keptOut allow = %v", k)
	}
}

func TestTxPower(t *testing.T) {
	for _, c := range []struct {
		r    bcmwifi.Radio
		want int
	}{
		{bcmwifi.Radio{TxPowerMode: "auto"}, 100},
		{bcmwifi.Radio{TxPowerMode: "medium"}, 50},
		{bcmwifi.Radio{TxPowerMode: "custom", TxPower: 20}, 100},
		{bcmwifi.Radio{TxPowerMode: "custom", TxPower: 17}, 50},
		{bcmwifi.Radio{TxPowerMode: "custom", TxPower: 11}, 12},
	} {
		if got := txPct(c.r, 20); got != c.want {
			t.Errorf("txPct(%+v) = %d, want %d", c.r, got, c.want)
		}
	}
	if dbmOf(100, 20) != 20 || dbmOf(50, 20) != 17 || dbmOf(25, 20) != 14 {
		t.Errorf("dbmOf: %d %d %d", dbmOf(100, 20), dbmOf(50, 20), dbmOf(25, 20))
	}
}

func TestEssid(t *testing.T) {
	for out, want := range map[string]string{
		"ra0       RTWIFI SoftAP  ESSID:\"Example Network(2.4GHz)\"  \n          Mode:Master  Channel=1\n":         "Example Network(2.4GHz)",
		"rai0      RTWIFI SoftAP  ESSID:\"Example Network\"  Nickname:\"\"\n          NWID:off/any  Mode:Master\n": "Example Network",
		"rai1      RTWIFI SoftAP  ESSID:\"olive#\"  Nickname:\"\"\r\n":                                             "olive#",
	} {
		m := essidRE.FindStringSubmatch(out)
		if m == nil || m[1] != want {
			t.Errorf("ESSID of %q = %v, want %q", out, m, want)
		}
	}
}
