// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/translate"
)

// rebuilt is JCOW414 with the rebuilt MT7603 module loaded
// (WithDriverSAE): 802.1X on both radios.
func rebuilt(t *testing.T) []RadioDef {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "sys/module", SAEModule2G), 0o755)
	return WithDriverSAE(root, JCOW414)
}

const radiusDat = baseDat + `own_ip_addr=192.168.1.1
RADIUS_Key1=vendor-k1
RADIUS_Key2=vendor-k2
RADIUS_Key3=vendor-k3
RADIUS_Key4=vendor-k4
RADIUS_Port=1812;1852;1812;1812
RADIUS_Server=192.168.29.2;192.168.40.253;192.168.29.2;192.168.29.2
session_timeout_interval=1000000
EAPifname=bdg2
PreAuthifname=bdg2
PMFSHA256=0;0;0;0
`

func entHome() bcmwifi.Desired {
	return bcmwifi.Desired{
		Radios: map[string]bcmwifi.Radio{"ng": {Enabled: true, Channel: 6, Width: 20}, "na": {Enabled: true, Channel: 36, Width: 80}},
		SSIDs: []bcmwifi.SSID{
			{ID: "a", SSID: "Home", Bands: []string{"2g", "5g"}, Enabled: true, Security: "wpa2", Passphrase: "secret-home"},
			{ID: "e", SSID: "Corp", Bands: []string{"2g", "5g"}, Enabled: true, Security: translate.SecWPA2Ent,
				Radius: &bcmwifi.Radius{NASID: "garage", Auth: []bcmwifi.RadiusServer{{IP: "192.168.0.7", Port: 1812, Secret: "s3cret radius"}}}},
			{ID: "w", SSID: "Corp3", Bands: []string{"5g"}, Enabled: true, Security: translate.SecWPA3Ent, VLAN: 20, PMF: translate.PMFRequired,
				Radius: &bcmwifi.Radius{Auth: []bcmwifi.RadiusServer{{IP: "127.0.0.1", Port: 18123, Secret: "0123456789abcdef0123456789abcdef"}},
					Acct: []bcmwifi.RadiusServer{{IP: "192.168.0.7", Port: 1813, Secret: "x"}}}},
		},
	}
}

// TestPlansEnterprise: WPA2/WPA3-Enterprise is AuthMode WPA2 with the
// RADIUS client per BSS; WPA3-Enterprise has PMF required.
func TestPlansEnterprise(t *testing.T) {
	ps, notes := plans(entHome(), rebuilt(t), false)
	ng, na := ps["ng"], ps["na"]
	if len(ng.BSS) != 2 || len(na.BSS) != 3 {
		t.Fatalf("ng %d na %d BSSes; notes %q", len(ng.BSS), len(na.BSS), notes)
	}
	e := na.BSS[1]
	if e.Auth != "WPA2" || e.Encr != "AES" || e.PSK != "" || e.PMF != 0 || e.Radius == nil ||
		*e.Radius != (Dot1X{Server: "192.168.0.7", Port: 1812, Secret: "s3cret radius", NASID: "garage"}) {
		t.Errorf("wpa2-enterprise BSS %+v %+v", e, e.Radius)
	}
	if w := na.BSS[2]; w.Auth != "WPA2" || w.PMF != 2 || w.Radius == nil || w.Radius.Server != "127.0.0.1" || w.Radius.Port != 18123 {
		t.Errorf("wpa3-enterprise BSS %+v", w)
	}
	j := strings.Join(notes, "\n")
	if !strings.Contains(j, `na: SSID "Corp3": RADIUS accounting is not sent`) {
		t.Errorf("accounting not noted: %q", notes)
	}
	// the vendor MT7603 module: not served on 2.4 GHz, noted
	ps, notes = plans(entHome(), JCOW414, false)
	if len(ps["ng"].BSS) != 1 || len(ps["na"].BSS) != 3 {
		t.Errorf("vendor module: ng %d na %d BSSes", len(ps["ng"].BSS), len(ps["na"].BSS))
	}
	if !strings.Contains(strings.Join(notes, "\n"), `ng: SSID "Corp": security wpa2-enterprise is not served by this radio`) {
		t.Errorf("vendor module notes %q", notes)
	}
}

// TestPlansEnterpriseFailClosed: an enterprise SSID that cannot be served
// as asked is not served at all, never open.
func TestPlansEnterpriseFailClosed(t *testing.T) {
	for _, c := range []struct {
		name string
		mod  func(*bcmwifi.Radius)
		why  string
	}{
		{"no server", func(r *bcmwifi.Radius) { r.Auth = nil }, "without a RADIUS auth server"},
		{"hostname", func(r *bcmwifi.Radius) { r.Auth[0].IP = "radius.example" }, "not an IPv4 address"},
		{"ipv6", func(r *bcmwifi.Radius) { r.Auth[0].IP = "2001:db8::1" }, "not an IPv4 address"},
		{"semicolon", func(r *bcmwifi.Radius) { r.Auth[0].Secret = "a;b" }, "RADIUS secret cannot be written"},
		{"long", func(r *bcmwifi.Radius) { r.Auth[0].Secret = strings.Repeat("x", 65) }, "RADIUS secret cannot be written"},
		{"empty", func(r *bcmwifi.Radius) { r.Auth[0].Secret = "" }, "RADIUS secret cannot be written"},
		{"newline", func(r *bcmwifi.Radius) { r.Auth[0].Secret = "a\nb" }, "RADIUS secret cannot be written"},
		{"space", func(r *bcmwifi.Radius) { r.Auth[0].Secret = " ab" }, "RADIUS secret cannot be written"},
		{"filter", func(r *bcmwifi.Radius) { r.FilterID = "staff" }, "Filter-Id"},
		{"mac auth", func(r *bcmwifi.Radius) { r.MACAuth = true }, "RADIUS MAC authentication is not supported"},
	} {
		d := entHome()
		d.SSIDs = d.SSIDs[:2]
		c.mod(d.SSIDs[1].Radius)
		ps, notes := plans(d, rebuilt(t), false)
		for _, band := range []string{"ng", "na"} {
			for _, b := range ps[band].BSS {
				if b.SSID == "Corp" {
					t.Errorf("%s: served on %s as %s", c.name, band, b.Auth)
				}
			}
		}
		if !strings.Contains(strings.Join(notes, "\n"), c.why) {
			t.Errorf("%s: notes %q", c.name, notes)
		}
	}
	// the enterprise key off: no 802.1X on any radio
	f := newFakeDev(t)
	a := New(Options{Root: f.root, Run: f, RunDir: "/tmp/udeco"})
	if a.ServesDot1X() {
		t.Errorf("serves 802.1X without rtdot1xd")
	}
	installDot1xd(t, f.root)
	if a = New(Options{Root: f.root, Run: f, RunDir: "/tmp/udeco"}); !a.ServesDot1X() {
		t.Errorf("does not serve 802.1X with rtdot1xd")
	}
	if a = New(Options{Root: f.root, Run: f, RunDir: "/tmp/udeco", NoDot1X: true}); a.ServesDot1X() {
		t.Errorf("serves 802.1X with enterprise off")
	}
}

// TestProfileEnterprise: the RADIUS keys each driver reads, the EAP
// bridges without duplicates or stale entries, PMF required with
// 802.1X-SHA256 only for WPA3-Enterprise.
func TestProfileEnterprise(t *testing.T) {
	l := rebuilt(t)
	ps, _ := plans(entHome(), l, false)
	ng := profile([]byte(radiusDat), l[0], ps["ng"])
	for k, v := range map[string]string{
		"AuthMode": "WPA2PSK;WPA2;WPA2PSK;WPA2PSK", "EncrypType": "AES;AES;AES;AES", "IEEE8021X": "0;0;0;0",
		"RADIUS_Server": "192.168.29.2;192.168.0.7;192.168.29.2;192.168.29.2", "RADIUS_Port": "1812;1812;1812;1812",
		// the MT7603 takes every BSS's secret from RADIUS_Key1's list
		"RADIUS_Key1": "unused;s3cret radius;unused;unused", "RADIUS_Key2": "vendor-k2",
		"NasId2": "garage", "EAPifname": "bdg2;lo;lo;lo", "PreAuthifname": "bdg2;lo;lo;lo",
		"session_timeout_interval": "0", "own_ip_addr": "192.168.1.1", "PMFSHA256": "0;0;0;0",
	} {
		if got, _ := getKey(ng, k); got != v {
			t.Errorf("ng %s = %q, want %q", k, got, v)
		}
	}
	na := profile([]byte(strings.Replace(radiusDat, "MaxStaNum", "MbssMaxStaNum", 1)), l[1], ps["na"])
	for k, v := range map[string]string{
		"AuthMode": "WPA2PSK;WPA2;WPA2;WPA2PSK", "PMFMFPC": "0;0;1;0", "PMFMFPR": "0;0;1;0", "PMFSHA256": "0;0;1;0",
		"RADIUS_Server": "192.168.29.2;192.168.0.7;127.0.0.1;192.168.29.2", "RADIUS_Port": "1812;1812;18123;1812",
		// the MT7663 reads RADIUS_Key<n> per BSS
		"RADIUS_Key1": "vendor-k1", "RADIUS_Key2": "s3cret radius", "RADIUS_Key3": "0123456789abcdef0123456789abcdef",
		"EAPifname": "bdg2;br-v20;lo;lo",
	} {
		if got, _ := getKey(na, k); got != v {
			t.Errorf("na %s = %q, want %q", k, got, v)
		}
	}
	if _, ok := getKey(na, "NasId3"); ok {
		t.Errorf("NasId3 written without a NAS-Identifier")
	}
	// no enterprise SSID: the vendor's RADIUS keys stay as they are
	d := entHome()
	d.SSIDs = d.SSIDs[:1]
	ps, _ = plans(d, l, false)
	p := profile([]byte(radiusDat), l[0], ps["ng"])
	for _, k := range []string{"RADIUS_Key1", "RADIUS_Server", "EAPifname", "session_timeout_interval", "own_ip_addr"} {
		got, _ := getKey(p, k)
		want, _ := getKey([]byte(radiusDat), k)
		if got != want {
			t.Errorf("no enterprise: %s = %q, want the vendor's %q", k, got, want)
		}
	}
	// an unusable vendor own_ip_addr (rtdot1xd refuses 0)
	ps, _ = plans(entHome(), l, false)
	p = profile([]byte(strings.Replace(radiusDat, "own_ip_addr=192.168.1.1", "own_ip_addr=0.0.0.0", 1)), l[0], ps["ng"])
	if got, _ := getKey(p, "own_ip_addr"); got != "127.0.0.1" {
		t.Errorf("own_ip_addr = %q", got)
	}
}

// installDot1xd puts a stand-in rtdot1xd under root (never run).
func installDot1xd(t *testing.T, root string) {
	p := filepath.Join(root, Dot1xdPath)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte("#!/bin/false\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func fakeProc(t *testing.T, root string, pid int, argv ...string) {
	d := filepath.Join(root, "proc", strconv.Itoa(pid))
	os.MkdirAll(d, 0o755)
	if err := os.WriteFile(filepath.Join(d, "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestDot1xdSupervisor: rtdot1xd per enterprise radio after the settle
// time, never inside it; a copy not the agent's is stopped; a radio
// restart stops it first; the hand-back stops the agent's.
func TestDot1xdSupervisor(t *testing.T) {
	f := newFakeDev(t)
	installDot1xd(t, f.root)
	now := new(time.Duration)
	*now = time.Hour
	type sig struct {
		pid int
		sig syscall.Signal
	}
	var sigs []sig
	a := New(Options{Root: f.root, Run: f, RunDir: "/tmp/udeco", StateDir: "/state", Uplink: "eth0.4.1",
		VerifyTimeout: time.Millisecond, sleep: func(context.Context, time.Duration) error { return nil },
		mono: func() time.Duration { return *now },
		kill: func(pid int, s syscall.Signal) error { sigs = append(sigs, sig{pid, s}); return nil }})
	ctx := context.Background()
	fakeProc(t, f.root, 300, "/userfs/bin/rtdot1xd_AC") // the vendor's 5 GHz copy
	d := entHome()
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	n := len(f.log)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if c := cmdsFrom(f, n, "sh -c"); len(c) != 0 {
		t.Errorf("rtdot1xd started inside the settle time: %q", c)
	}
	if len(sigs) != 1 || sigs[0] != (sig{300, syscall.SIGTERM}) {
		t.Errorf("signals at the 5 GHz restart %v, want the vendor's copy stopped", sigs)
	}
	*now += time.Minute
	n = len(f.log)
	if _, err := a.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	// the 2.4 GHz radio runs the vendor module here: 5 GHz only
	want := "sh -c exec /userfs/bin/rtdot1xd -p rai -i rai0 </dev/null >/dev/null 2>&1"
	if c := cmdsFrom(f, n, "sh -c"); len(c) != 1 || c[0] != want {
		t.Fatalf("started %q, want %q", c, want)
	}
	// the vendor copy that ignored SIGTERM
	if len(sigs) != 2 || sigs[1] != (sig{300, syscall.SIGKILL}) {
		t.Errorf("signals %v, want SIGKILL to the vendor's copy", sigs)
	}
	os.RemoveAll(filepath.Join(f.root, "proc/300"))
	// running now: not started again, nothing signalled
	fakeProc(t, f.root, 400, Dot1xdPath, "-p", "rai", "-i", "rai0")
	sigs = nil
	n = len(f.log)
	a.Tick(ctx)
	if c := cmdsFrom(f, n, "sh -c"); len(c) != 0 || len(sigs) != 0 {
		t.Errorf("started again: %q, signals %v", c, sigs)
	}
	// it exits: started again, at most once a minute
	os.RemoveAll(filepath.Join(f.root, "proc/400"))
	*now += time.Second
	a.o.wall = func() time.Time { return time.Unix(1e9, 0) }
	n = len(f.log)
	a.Tick(ctx)
	a.Tick(ctx)
	if c := cmdsFrom(f, n, "sh -c"); len(c) != 1 {
		t.Errorf("restarts %q, want one", c)
	}
	fakeProc(t, f.root, 401, Dot1xdPath, "-p", "rai", "-i", "rai0")
	// the controller drops the enterprise SSIDs: 5 GHz restarts, rtdot1xd
	// is stopped and not started again
	sigs = nil
	d.SSIDs = d.SSIDs[:1]
	p, _ = a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 || sigs[0] != (sig{401, syscall.SIGTERM}) {
		t.Errorf("signals %v, want SIGTERM to 401", sigs)
	}
	os.RemoveAll(filepath.Join(f.root, "proc/401"))
	*now += time.Minute
	n = len(f.log)
	a.Tick(ctx)
	if c := cmdsFrom(f, n, "sh -c"); len(c) != 0 {
		t.Errorf("started without an enterprise SSID: %q", c)
	}
	// the hand-back stops the agent's copy
	fakeProc(t, f.root, 402, Dot1xdPath, "-p", "rai", "-i", "rai0")
	fakeProc(t, f.root, 403, "/userfs/bin/rtdot1xd") // not the agent's: left to the vendor
	sigs = nil
	if err := a.restoreBaseline(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 || sigs[0].pid != 402 {
		t.Errorf("hand-back signals %v, want 402 only", sigs)
	}
}

func TestProcPrefix(t *testing.T) {
	for argv, want := range map[string]string{
		"/userfs/bin/rtdot1xd":                   "ra",
		"/userfs/bin/rtdot1xd_AC":                "rai",
		"/userfs/bin/rtdot1xd -p rai -i rai0":    "rai",
		"/userfs/bin/rtdot1xd -prai":             "rai",
		"/userfs/bin/rtdot1xd -i ra0 -d 3 -p ra": "ra",
	} {
		if got := procPrefix(strings.Fields(argv)); got != want {
			t.Errorf("%s: %q, want %q", argv, got, want)
		}
	}
}
