// SPDX-License-Identifier: GPL-2.0-or-later

package deco

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

const (
	guestPSK = "guest-pass-9"
	newPSK   = "brand-new-Psk-77"
)

// vap renders one UniFi WLAN on one radio as system_cfg lines. Extra keys
// are "w.<key>=v" (wireless.N) or "a.<key>=v" (aaa.N).
func vap(n int, radio, ssid, psk string, extra ...string) string {
	w, a := fmt.Sprintf("wireless.%d.", n), fmt.Sprintf("aaa.%d.", n)
	lines := []string{w + "ssid=" + ssid, w + "parent=" + radio, w + fmt.Sprintf("devname=ath%d", n), w + "usage=user",
		a + "ssid=" + ssid}
	if psk != "" {
		lines = append(lines, a+"wpa=2", a+"wpa.key.1.mgmt=WPA-PSK", a+"wpa.psk="+psk)
	}
	for _, e := range extra {
		switch {
		case strings.HasPrefix(e, "w."):
			lines = append(lines, w+e[2:])
		case strings.HasPrefix(e, "a."):
			lines = append(lines, a+e[2:])
		default:
			lines = append(lines, e)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

const radios = "radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght20\nradio.2.phyname=wifi1\nradio.2.ieee_mode=11naht80\n"

func sysCfg(parts ...string) translate.Cfg {
	return translate.ParseCfg(radios + strings.Join(parts, ""))
}

// sameCfg is UniFi's view of exactly what the fixture's Deco runs.
func sameCfg(extraMain ...string) translate.Cfg {
	return sysCfg(vap(1, "wifi0", "Home", testPSK, extraMain...), vap(2, "wifi1", "Home", testPSK, extraMain...),
		vap(3, "wifi0", "Home-Guest", guestPSK, "a.is_guest=true"), vap(4, "wifi1", "Home-Guest", guestPSK, "a.is_guest=true"))
}

func curWireless(t *testing.T) *WirelessInfo { return loadState(t).Wireless.Value }

func cloneWI(t testing.TB, w *WirelessInfo) *WirelessInfo {
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	var c WirelessInfo
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

// bodyShape lists band -> object keys of a Set body, e.g. band2_4:host.
func bodyShape(t *testing.T, w *WirelessInfo) string {
	t.Helper()
	if w == nil {
		return ""
	}
	b, _ := json.Marshal(w)
	var m map[string]map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("body is not {band:{obj:...}}: %s", b)
	}
	var out []string
	for band, objs := range m {
		for k := range objs {
			out = append(out, band+":"+k)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestPlanWLAN(t *testing.T) {
	tests := []struct {
		name        string
		cfg         translate.Cfg
		cur         func(*WirelessInfo)
		host, guest string // body shape; "" = no Set
		changes     []string
		notes       []string
		check       func(*testing.T, *WLANPlan)
	}{
		{name: "no-op when equal", cfg: sameCfg()},
		{
			name: "new ssid and passphrase", cfg: sysCfg(vap(1, "wifi0", "NewHome", newPSK), vap(2, "wifi1", "NewHome", newPSK),
				vap(3, "wifi0", "Home-Guest", guestPSK, "a.is_guest=true"), vap(4, "wifi1", "Home-Guest", guestPSK, "a.is_guest=true")),
			host:    "band2_4:host,band5_1:host",
			changes: []string{`band2_4.host.ssid: "Home" -> "NewHome"`, `band5_1.host.ssid: "Home" -> "NewHome"`, "band2_4.host.password: <secret "},
			check: func(t *testing.T, p *WLANPlan) {
				h := p.Host.Band5G1.Host
				if string(*h.SSID) != "NewHome" || string(*h.Password) != newPSK || *h.EncryptionMode != "wpa2" || !*h.Enable ||
					h.IsSeparate == nil || *h.IsSeparate {
					t.Errorf("host: %+v", h)
				}
			},
		},
		{
			name: "hidden ssid", cfg: sameCfg("w.hide_ssid=true"), host: "band2_4:host,band5_1:host",
			changes: []string{"band2_4.host.enable_hide_ssid: false -> true", "band5_1.host.enable_hide_ssid: false -> true"},
		},
		{
			name: "wpa2/wpa3 transition", cfg: sameCfg("a.wpa.key.1.mgmt=SAE", "a.wpa3.support=enabled", "a.wpa3.transition=enabled"),
			host: "band2_4:host,band5_1:host", changes: []string{"band2_4.host.enable_wpa3: false -> true"},
			check: func(t *testing.T, p *WLANPlan) {
				if *p.Host.Band2G4.Host.EncryptionMode != "wpa2" {
					t.Error("encryption_mode must be left as it is")
				}
			},
		},
		{
			name: "wpa3 only", cfg: sameCfg("a.wpa.key.1.mgmt=SAE", "a.wpa3.support=enabled"),
			host: "band2_4:host,band5_1:host", changes: []string{"enable_wpa3: false -> true"}, notes: []string{"WPA3-only in UniFi"},
		},
		{
			name: "back to wpa2 from wpa3",
			cfg:  sameCfg(),
			cur: func(w *WirelessInfo) {
				on := true
				w.Band2G4.Host.EnableWPA3, w.Band5G1.Host.EnableWPA3 = &on, &on
			},
			host: "band2_4:host,band5_1:host", changes: []string{"band5_1.host.enable_wpa3: true -> false"},
		},
		{
			name: "band disable: 2.4 GHz only", cfg: sysCfg(vap(1, "wifi0", "Home", testPSK),
				vap(3, "wifi0", "Home-Guest", guestPSK, "a.is_guest=true"), vap(4, "wifi1", "Home-Guest", guestPSK, "a.is_guest=true")),
			host: "band2_4:host,band5_1:host", changes: []string{"band5_1.host.enable: true -> false"},
			notes: []string{"band5_1: no enabled UniFi WLAN on 5g"},
			check: func(t *testing.T, p *WLANPlan) {
				if !*p.Host.Band2G4.Host.Enable || *p.Host.Band5G1.Host.Enable {
					t.Error("per-band enable")
				}
			},
		},
		{
			name: "band disable via status", cfg: sameCfg("w.status=disabled"),
			notes: []string{"refusing to turn the main network off on every band"},
		},
		{
			name: "re-enable a band", cfg: sameCfg(),
			cur:  func(w *WirelessInfo) { off := false; w.Band5G1.Host.Enable = &off },
			host: "band2_4:host,band5_1:host", changes: []string{"band5_1.host.enable: false -> true"},
		},
		{
			name: "guest network change, hidden clamped",
			cfg: sysCfg(vap(1, "wifi0", "Home", testPSK), vap(2, "wifi1", "Home", testPSK),
				vap(3, "wifi0", "Visitors", "visit-pass-1", "a.is_guest=true", "w.hide_ssid=true"),
				vap(4, "wifi1", "Visitors", "visit-pass-1", "a.is_guest=true", "w.hide_ssid=true")),
			guest:   "band2_4:guest,band5_1:guest",
			changes: []string{`band2_4.guest.ssid: "Home-Guest" -> "Visitors"`, "band5_1.guest.password: <secret "},
			notes:   []string{"hidden SSID is not supported for the Deco guest network"},
			check: func(t *testing.T, p *WLANPlan) {
				g := p.Guest.Band2G4.Guest
				if string(*g.Password) != "visit-pass-1" || g.AccessDuration == nil || *g.AccessDuration != -1 || !*g.Enable {
					t.Errorf("guest keeps its other keys: %+v", g)
				}
			},
		},
		{
			name: "no guest in UniFi turns the Deco guest off", cfg: sysCfg(vap(1, "wifi0", "Home", testPSK), vap(2, "wifi1", "Home", testPSK)),
			guest: "band2_4:guest,band5_1:guest", changes: []string{"band2_4.guest.enable: true -> false"},
			notes: []string{"no guest WLAN in UniFi"},
		},
		{
			name: "open guest in UniFi leaves the Deco guest alone",
			cfg: sysCfg(vap(1, "wifi0", "Home", testPSK), vap(2, "wifi1", "Home", testPSK),
				vap(3, "wifi0", "Home-Guest", "", "a.is_guest=true"), vap(4, "wifi1", "Home-Guest", "", "a.is_guest=true")),
			notes: []string{"open network: not applied", `guest WLAN "Home-Guest" cannot be applied: the Deco guest network is left unchanged`},
			check: func(t *testing.T, p *WLANPlan) {
				if p.Guest != nil || strings.Contains(strings.Join(p.Notes, "\n"), "no guest WLAN in UniFi") {
					t.Errorf("guest planned: %+v notes %q", p.Guest, p.Notes)
				}
			},
		},
		{
			name: "enterprise guest in UniFi leaves the Deco guest alone",
			cfg: sysCfg(vap(1, "wifi0", "Home", testPSK), vap(2, "wifi1", "Home", testPSK),
				vap(3, "wifi0", "Corp-Guest", "", "a.is_guest=true", "a.wpa=2", "a.wpa.key.1.mgmt=WPA-EAP"),
				vap(4, "wifi1", "Corp-Guest", "", "a.is_guest=true", "a.wpa=2", "a.wpa.key.1.mgmt=WPA-EAP")),
			notes: []string{`guest WLAN "Corp-Guest" cannot be applied`},
			check: func(t *testing.T, p *WLANPlan) {
				if p.Guest != nil {
					t.Errorf("guest planned: %+v", p.Guest)
				}
			},
		},
		{
			name: "open network not applied", cfg: sysCfg(vap(1, "wifi0", "Cafe", ""), vap(2, "wifi1", "Cafe", "")),
			notes: []string{`open network: not applied`, "no usable main WLAN"},
		},
		{
			name: "enterprise not applied", cfg: sameCfg("a.wpa.key.1.mgmt=WPA-EAP"),
			notes: []string{"not supported (only WPA2/WPA3 personal)", "no usable main WLAN"},
		},
		{
			name: "unsupported features clamped", cfg: sameCfg("a.ft.status=enabled", "w.schedule_enabled=enabled", "w.l2_isolation=enabled"),
			notes: []string{`"Home": 802.11r, l2-isolation, schedule not supported by the Deco: clamped`},
		},
		{
			name: "mesh, element-adopt and radio settings skipped",
			cfg: sysCfg(vap(1, "wifi0", "Home", testPSK), vap(2, "wifi1", "Home", testPSK),
				vap(3, "wifi0", "Home-Guest", guestPSK, "a.is_guest=true"), vap(4, "wifi1", "Home-Guest", guestPSK, "a.is_guest=true"),
				vap(5, "wifi1", "vwire-1", "meshpsk-123", "w.vwire=enabled"), vap(6, "wifi0", "element-1", "elem-psk-1", "w.element_adopt=enabled"),
				"radio.1.channel=6\n"),
			notes: []string{`"vwire-1": mesh/uplink VAP, skipped`, `"element-1": UniFi element-adopt SSID, skipped`, "radio channel, width and tx power are not applied"},
		},
		{
			name: "second main network and per-radio ssids",
			cfg: sysCfg(vap(1, "wifi0", "Home", testPSK), vap(2, "wifi1", "Home-5G", "other-psk-12"),
				vap(3, "wifi0", "Home-Guest", guestPSK, "a.is_guest=true"), vap(4, "wifi1", "Home-Guest", guestPSK, "a.is_guest=true")),
			notes: []string{`WLAN "Home-5G" skipped: the Deco has one main network (using "Home")`},
		},
		{name: "no WLANs at all", cfg: sysCfg(), notes: []string{"no WLANs in system_cfg"}},
		{
			name: "wireless info not read", cfg: sameCfg(), cur: func(w *WirelessInfo) { *w = WirelessInfo{} },
			notes: []string{"no host network in the wireless info"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cur := curWireless(t)
			if tt.cur != nil {
				tt.cur(cur)
			}
			snapshot := cloneWI(t, cur)
			p := PlanWLAN(tt.cfg, cur)
			if got := bodyShape(t, p.Host); got != tt.host {
				t.Errorf("host body %q, want %q", got, tt.host)
			}
			if got := bodyShape(t, p.Guest); got != tt.guest {
				t.Errorf("guest body %q, want %q", got, tt.guest)
			}
			if p.Empty() != (tt.host == "" && tt.guest == "") || p.Empty() && len(p.Changes) > 0 {
				t.Errorf("empty=%t changes=%v", p.Empty(), p.Changes)
			}
			all := strings.Join(p.Changes, "\n")
			for _, c := range tt.changes {
				if !strings.Contains(all, c) {
					t.Errorf("change %q missing in:\n%s", c, all)
				}
			}
			notes := strings.Join(p.Notes, "\n")
			for _, n := range tt.notes {
				if !strings.Contains(notes, n) {
					t.Errorf("note %q missing in:\n%s", n, notes)
				}
			}
			out := p.String()
			for _, secret := range []string{testPSK, newPSK, guestPSK, "visit-pass-1", b64(testPSK), b64(newPSK), b64("visit-pass-1"), "meshpsk", "elem-psk"} {
				if strings.Contains(out, secret) {
					t.Fatalf("secret %q in plan:\n%s", secret, out)
				}
			}
			for _, body := range []*WirelessInfo{p.Host, p.Guest} {
				if body == nil {
					continue
				}
				js, _ := json.Marshal(body)
				for _, never := range []string{"radio", "config_spec", "backhaul", "iot", "amazon_ffs"} {
					if strings.Contains(string(js), `"`+never+`"`) {
						t.Errorf("Set body carries %s: %s", never, js)
					}
				}
			}
			if !jsonEqual(t, snapshot, cur) {
				t.Error("PlanWLAN mutated the cached wireless info")
			}
			if tt.check != nil {
				tt.check(t, &p)
			}
		})
	}
}

func jsonEqual(t *testing.T, a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// The host body is shaped like the app's example Set (P§8.4).
func TestPlanWLANBodyMatchesApp(t *testing.T) {
	cur := curWireless(t)
	p := PlanWLAN(sysCfg(vap(1, "wifi0", "NewSSID", "NewPassword"), vap(2, "wifi1", "NewSSID", "NewPassword"),
		vap(3, "wifi0", "Home-Guest", guestPSK, "a.is_guest=true"), vap(4, "wifi1", "Home-Guest", guestPSK, "a.is_guest=true")), cur)
	got, _ := json.Marshal(p.Host)
	host := `{"enable":true,"enable_hide_ssid":false,"enable_wpa3":false,"encryption_mode":"wpa2","is_separate":false,` +
		`"password":"TmV3UGFzc3dvcmQ=","ssid":"TmV3U1NJRA=="}`
	want := `{"band2_4":{"host":` + host + `},"band5_1":{"host":` + host + `}}`
	if string(got) != want {
		t.Fatalf("host body\n got %s\nwant %s", got, want)
	}
}

func TestWLANPatchRestore(t *testing.T) {
	backup := curWireless(t)
	p := PlanWLAN(sysCfg(vap(1, "wifi0", "NewHome", newPSK, "w.hide_ssid=true")), backup)
	if p.Host == nil {
		t.Fatal("no host plan")
	}
	body, patch := p.host.restore(backup)
	if bodyShape(t, body) != "band2_4:host,band5_1:host" {
		t.Fatalf("restore body %s", bodyShape(t, body))
	}
	if d := patch.diff(backup); len(d) > 0 {
		t.Fatalf("restore patch does not match the backup: %v", d)
	}
	if d := p.host.diff(backup); len(d) == 0 {
		t.Fatal("apply patch matches the backup")
	}
	if string(*body.Band5G1.Host.SSID) != "Home" || !*body.Band5G1.Host.Enable || string(*body.Band2G4.Host.Password) != testPSK {
		t.Fatalf("restore body: %+v", body.Band5G1.Host)
	}
}

// ---- apply engine ----

// fakeMesh stands in for the Mesh: device is what the Deco holds; poll
// copies it into the cache like a 0x4009 / 0x400f read.
type fakeMesh struct {
	t      *testing.T
	mu     sync.Mutex
	clock  *fakeClock
	device *WirelessInfo
	state  MeshState
	cmds   []Command
	ignore bool                 // accept Sets without applying them
	fail   func(n int) error    // error for the n-th Set (0-based)
	after  func(*fakeMesh, int) // runs after the n-th Set
	polls  map[uint16]int
}

func newFakeMesh(t *testing.T, clock *fakeClock) *fakeMesh {
	s := loadState(t)
	s.Devices.At, s.Wireless.At = clock.Now(), clock.Now()
	return &fakeMesh{t: t, clock: clock, device: cloneWI(t, s.Wireless.Value), state: *s, polls: map[uint16]int{}}
}

func (f *fakeMesh) Snapshot() MeshState { f.mu.Lock(); defer f.mu.Unlock(); return f.state }

func (f *fakeMesh) RequestPoll(op uint16) { f.mu.Lock(); f.polls[op]++; f.mu.Unlock() }

func (f *fakeMesh) Submit(c Command) <-chan CommandResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.cmds)
	f.cmds = append(f.cmds, c)
	ch := make(chan CommandResult, 1)
	var err error
	if f.fail != nil {
		err = f.fail(n)
	}
	if err == nil && !f.ignore {
		merge(f.device, c.Wireless)
	}
	if f.after != nil {
		f.after(f, n)
	}
	ch <- CommandResult{Kind: c.Kind, Opcode: OpSetWireless, Err: err}
	return ch
}

func merge(dev, body *WirelessInfo) {
	for _, s := range wirelessBands(body) {
		b := *s.b
		if b == nil {
			continue
		}
		d := bandNamed(dev, s.name)
		if b.Host != nil {
			h := *b.Host
			d.Host = &h
		}
		if b.Guest != nil {
			g := *b.Guest
			d.Guest = &g
		}
	}
}

// poll refreshes the cache from the device, as the Mesh's polls do.
func (f *fakeMesh) poll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.clock.Now()
	f.state.Wireless = Polled[WirelessInfo]{Value: cloneWI(f.t, f.device), At: now, OK: true}
	f.state.Devices.At = now
}

func (f *fakeMesh) setOnline(i int, online bool) {
	devs := *f.state.Devices.Value
	devs.DeviceList = append([]Deco(nil), devs.DeviceList...)
	devs.DeviceList[i].InetStatus, devs.DeviceList[i].GroupStatus = InetOnline, GroupConnected
	if !online {
		devs.DeviceList[i].InetStatus = InetOffline
	}
	f.state.Devices.Value = &devs
}

func (f *fakeMesh) sets() []Command {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Command(nil), f.cmds...)
}

type applyRig struct {
	t     *testing.T
	a     *WLANApplier
	fm    *fakeMesh
	clock *fakeClock
	logs  *syncBuf
	dir   string
}

func newApplyRig(t *testing.T, apply bool) *applyRig {
	clock := &fakeClock{t: fixtureAt}
	r := &applyRig{t: t, clock: clock, logs: &syncBuf{}, dir: t.TempDir()}
	r.fm = newFakeMesh(t, clock)
	var units []string
	for _, u := range testUnits {
		units = append(units, u.MAC)
	}
	r.a = NewWLANApplier(WLANConfig{Apply: apply, BackupDir: filepath.Join(r.dir, "backups"), Units: units, Logf: r.logs.logf}, r.fm)
	r.a.now = clock.Now
	return r
}

// tick advances the clock, lets the "Mesh" poll, then steps the applier.
func (r *applyRig) tick(d time.Duration) {
	r.clock.Add(d)
	r.fm.poll()
	r.a.Step()
}

func (r *applyRig) run(total, step time.Duration) {
	for end := r.clock.Now().Add(total); r.clock.Now().Before(end); {
		r.tick(step)
	}
}

func (r *applyRig) noSecrets() {
	r.t.Helper()
	for _, s := range []string{testPSK, newPSK, guestPSK, b64(testPSK), b64(newPSK), b64(guestPSK)} {
		if strings.Contains(r.logs.String(), s) {
			r.t.Fatalf("secret %q in logs:\n%s", s, r.logs.String())
		}
	}
}

func newCfg() translate.Cfg {
	return sysCfg(vap(1, "wifi0", "NewHome", newPSK), vap(2, "wifi1", "NewHome", newPSK),
		vap(3, "wifi0", "Home-Guest", guestPSK, "a.is_guest=true"), vap(4, "wifi1", "Home-Guest", guestPSK, "a.is_guest=true"))
}

func TestWLANApplyOffOrNotOwnerLogsOnly(t *testing.T) {
	for _, tt := range []struct {
		apply, owner bool
		why          string
	}{{false, true, "apply=false: log only"}, {true, false, "not the config owner: log only"}} {
		r := newApplyRig(t, tt.apply)
		r.a.Submit("deco-205", tt.owner, newCfg())
		r.run(time.Minute, time.Second)
		if n := len(r.fm.sets()); n != 0 {
			t.Fatalf("%s: %d Sets sent", tt.why, n)
		}
		if l := r.logs.String(); !strings.Contains(l, tt.why) || !strings.Contains(l, `"Home" -> "NewHome"`) {
			t.Fatalf("plan not logged: %s", l)
		}
		r.noSecrets()
	}
}

func TestWLANApplyVerified(t *testing.T) {
	r := newApplyRig(t, true)
	orig := cloneWI(t, r.fm.device)
	r.a.Submit("deco-241", true, sysCfg(vap(1, "wifi0", "Other", newPSK), vap(2, "wifi1", "Other", newPSK)))
	r.tick(5 * time.Second)
	r.a.Submit("deco-241", true, newCfg()) // the latest submission wins and restarts the debounce
	r.tick(9 * time.Second)
	if len(r.fm.sets()) != 0 {
		t.Fatal("sent before the debounce")
	}
	r.run(30*time.Second, time.Second)
	sets := r.fm.sets()
	if len(sets) != 1 || !sets[0].SkipRateLimit || string(*sets[0].Wireless.Band2G4.Host.SSID) != "NewHome" || sets[0].Wireless.Band2G4.Guest != nil {
		t.Fatalf("sets: %+v", sets)
	}
	if string(*r.fm.device.Band5G1.Host.SSID) != "NewHome" || r.a.phase != phaseIdle || r.a.Latched() {
		t.Fatalf("phase %v latched %t", r.a.phase, r.a.Latched())
	}
	if !strings.Contains(r.logs.String(), "apply verified") {
		t.Fatalf("not verified: %s", r.logs.String())
	}
	// The backup is the pre-change 0x4009, mode 0600.
	files, _ := filepath.Glob(filepath.Join(r.dir, "backups", "wireless-*.json"))
	if len(files) != 1 {
		t.Fatalf("backups: %v", files)
	}
	fi, _ := os.Stat(files[0])
	b, _ := os.ReadFile(files[0])
	var back WirelessInfo
	if err := json.Unmarshal(b, &back); err != nil || fi.Mode().Perm() != 0o600 || !jsonEqual(t, &back, orig) {
		t.Fatalf("backup %s mode %v: %s", files[0], fi.Mode(), b)
	}
	// A second change within 5 min waits for the rate limit.
	r.a.Submit("deco-241", true, sameCfg())
	r.run(2*time.Minute, 5*time.Second)
	if len(r.fm.sets()) != 1 || !strings.Contains(r.logs.String(), "rate-limited") {
		t.Fatalf("not rate-limited: %d sets", len(r.fm.sets()))
	}
	r.run(4*time.Minute, 5*time.Second)
	if len(r.fm.sets()) != 2 || string(*r.fm.device.Band2G4.Host.SSID) != "Home" {
		t.Fatalf("second apply: %d sets", len(r.fm.sets()))
	}
	r.noSecrets()
}

func TestWLANApplyHostThenGuest(t *testing.T) {
	r := newApplyRig(t, true)
	r.a.Submit("deco-241", true, sysCfg(vap(1, "wifi0", "NewHome", newPSK), vap(2, "wifi1", "NewHome", newPSK)))
	r.run(time.Minute, time.Second)
	sets := r.fm.sets()
	if len(sets) != 2 || sets[0].Wireless.Band2G4.Host == nil || sets[1].Wireless.Band2G4.Guest == nil || !sets[1].SkipRateLimit {
		t.Fatalf("want host then guest Set: %+v", sets)
	}
	if on(r.fm.device.Band2G4.Guest.Enable) || !strings.Contains(r.logs.String(), "apply verified") {
		t.Fatalf("guest still on or not verified:\n%s", r.logs.String())
	}
}

func TestWLANApplyRollsBackWhenAUnitDoesNotReturn(t *testing.T) {
	r := newApplyRig(t, true)
	orig := cloneWI(t, r.fm.device)
	r.fm.after = func(f *fakeMesh, n int) {
		if n == 0 {
			f.setOnline(1, false) // deco-205 drops off and stays away
		}
	}
	r.a.Submit("deco-241", true, newCfg())
	r.run(time.Minute, time.Second)
	if r.a.phase != phaseVerify || len(r.fm.sets()) != 1 {
		t.Fatalf("phase %v sets %d", r.a.phase, len(r.fm.sets()))
	}
	r.run(3*time.Minute, time.Second)
	sets := r.fm.sets()
	if len(sets) < 2 || !sets[1].SkipRateLimit {
		t.Fatalf("no rollback Set: %+v", sets)
	}
	rb := sets[1].Wireless
	if string(*rb.Band2G4.Host.SSID) != "Home" || string(*rb.Band5G1.Host.Password) != testPSK {
		t.Fatalf("rollback body: %+v", rb.Band2G4.Host)
	}
	if !r.a.Latched() || !strings.Contains(r.logs.String(), "ROLLED BACK") || !strings.Contains(r.logs.String(), "not back online") {
		t.Fatalf("latched=%t logs:\n%s", r.a.Latched(), r.logs.String())
	}
	if !jsonEqual(t, r.fm.device, orig) {
		t.Fatal("device not restored")
	}
	// Latched: further plans are logged only.
	r.a.Submit("deco-241", true, newCfg())
	r.run(time.Minute, time.Second)
	if len(r.fm.sets()) != len(sets) || !strings.Contains(r.logs.String(), "apply latched off after a rollback: log only") {
		t.Fatal("applied after the latch")
	}
	r.noSecrets()
}

func TestWLANApplyRollsBackWhenTheChangeDoesNotShow(t *testing.T) {
	r := newApplyRig(t, true)
	r.fm.ignore = true // the Deco answers error_code 0 but keeps the old settings
	r.a.Submit("deco-241", true, newCfg())
	r.run(4*time.Minute, time.Second)
	if !r.a.Latched() || !strings.Contains(r.logs.String(), "wireless info still differs") {
		t.Fatalf("logs:\n%s", r.logs.String())
	}
}

func TestWLANApplySetErrorRollsBackAtOnce(t *testing.T) {
	r := newApplyRig(t, true)
	r.fm.fail = func(n int) error {
		if n == 0 {
			return &AppError{Opcode: OpSetWireless, ErrorCode: -1}
		}
		return nil
	}
	r.a.Submit("deco-241", true, newCfg())
	r.run(20*time.Second, time.Second)
	sets := r.fm.sets()
	if len(sets) != 2 || !r.a.Latched() || !strings.Contains(r.logs.String(), "Set failed") {
		t.Fatalf("sets=%d latched=%t logs:\n%s", len(sets), r.a.Latched(), r.logs.String())
	}
}

func TestWLANApplyNotSentNoRollback(t *testing.T) {
	for _, err := range []error{ErrOwnerMismatch, ErrRateLimited, ErrNotConnected} {
		r := newApplyRig(t, true)
		r.fm.fail = func(int) error { return err }
		r.a.Submit("deco-241", true, newCfg())
		r.run(time.Minute, time.Second)
		if len(r.fm.sets()) != 1 || r.a.Latched() || r.a.phase != phaseIdle || !strings.Contains(r.logs.String(), "apply not sent") {
			t.Fatalf("%v: sets=%d latched=%t", err, len(r.fm.sets()), r.a.Latched())
		}
	}
}

func TestWLANRollbackGivesUpAfter30Min(t *testing.T) {
	r := newApplyRig(t, true)
	r.fm.ignore = true
	r.fm.fail = func(n int) error {
		if n > 0 {
			return errors.New("transport lost")
		}
		return nil
	}
	r.fm.after = func(f *fakeMesh, n int) {
		if n == 0 {
			// the Set took effect partially: SSID changed, so verify fails
			s := B64("Broken")
			h := *f.device.Band2G4.Host
			h.SSID = &s
			f.device.Band2G4.Host = &h
		}
	}
	r.a.Submit("deco-241", true, newCfg())
	r.run(40*time.Minute, 5*time.Second)
	n := len(r.fm.sets()) - 1
	if !r.a.Latched() || !strings.Contains(r.logs.String(), "ROLLBACK FAILED") || n < 50 || n > 62 {
		t.Fatalf("latched=%t rollback attempts=%d", r.a.Latched(), n)
	}
}

func TestWLANApplyNoChangeSendsNothing(t *testing.T) {
	r := newApplyRig(t, true)
	r.a.Submit("deco-241", true, sameCfg())
	r.run(time.Minute, time.Second)
	if len(r.fm.sets()) != 0 || !strings.Contains(r.logs.String(), "nothing to apply") {
		t.Fatalf("sets %d", len(r.fm.sets()))
	}
	if files, _ := filepath.Glob(filepath.Join(r.dir, "backups", "*")); len(files) != 0 {
		t.Fatalf("backup written for a no-op: %v", files)
	}
}

func TestWLANApplyRefusedWithoutBackupDir(t *testing.T) {
	r := newApplyRig(t, true)
	r.a.cfg.BackupDir = ""
	r.a.Submit("deco-241", true, newCfg())
	r.run(time.Minute, time.Second)
	if len(r.fm.sets()) != 0 || !strings.Contains(r.logs.String(), "backup failed") {
		t.Fatalf("sets %d", len(r.fm.sets()))
	}
}

// End to end through the real Mesh and the SSH emulator: the apply goes
// out as 0x4008, and the rollback Set passes the Mesh's 5-minute limit.
func TestWLANApplyThroughMesh(t *testing.T) {
	r := newRig(t, func(c *MeshConfig) { c.Apply = true })
	r.step()
	a := NewWLANApplier(WLANConfig{Apply: true, BackupDir: filepath.Join(r.dir, "backups"),
		Units: []string{"b0:a7:b9:3e:16:94", "b0:a7:b9:3e:17:00", "b0:a7:b9:3e:15:fc"}, Logf: r.logs.logf}, r.m)
	a.now = r.clock.Now
	tick := func(n int) {
		for i := 0; i < n; i++ {
			r.clock.Add(time.Second)
			a.Step()
			r.step()
		}
	}
	a.Submit("deco-241", true, sysCfg(vap(1, "wifi0", "Home2", newPSK), vap(2, "wifi1", "Home2", newPSK)))
	tick(15)
	if r.emu.count(OpSetWireless) != 1 {
		t.Fatalf("0x4008 sent %d times", r.emu.count(OpSetWireless))
	}
	sent := r.emu.params(t, OpSetWireless, 0)
	if !strings.Contains(sent, `"band2_4":{"host":`) || !strings.Contains(sent, b64("Home2")) || !strings.Contains(sent, b64(newPSK)) {
		t.Fatalf("0x4008 body: %s", sent)
	}
	// The emulated Deco keeps the old settings: verify fails, the rollback
	// Set goes out within 5 min of the first, and the latch follows.
	tick(200)
	if r.emu.count(OpSetWireless) < 2 {
		t.Fatalf("no rollback Set; logs:\n%s", r.logs.String())
	}
	if rb := r.emu.params(t, OpSetWireless, 1); !strings.Contains(rb, b64("Home")+`"`) || !strings.Contains(rb, b64(testPSK)) {
		t.Fatalf("rollback body: %s", rb)
	}
	tick(35) // the next 0x4009 read shows the old settings back
	if !a.Latched() || !strings.Contains(r.logs.String(), "ROLLED BACK") {
		t.Fatalf("logs:\n%s", r.logs.String())
	}
	r.noSecrets()
	for _, s := range []string{newPSK, b64(newPSK)} {
		if strings.Contains(r.logs.String(), s) {
			t.Fatalf("new PSK in logs")
		}
	}
}
