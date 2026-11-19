// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/ftpeer"
	"github.com/antoniocosta/unifi-openwrt/internal/inform"
	"github.com/antoniocosta/unifi-openwrt/internal/models"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// ftKeys are fake per-WLAN iapp_keys (32 hex digits, as the controller's
// x_iapp_key), by WLAN id of the MediaTek fixture.
var ftKeys = map[string]string{
	"2": "a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4",
	"3": "ffeeddccbbaa99887766554433221100",
	"4": "4e4f50515253545556575859e0e1e2e3",
}

// ftSAECfg is the MediaTek fixture as the controller sends it to an AP that
// claims radio_caps2 0x2 with fast roaming and WPA3 fast roaming on: every
// WPA2/WPA3 WLAN with ft.status and wpa3.ft.status enabled and its
// aaa.N.iapp_key. secrets are the passphrases and the keys.
func ftSAECfg(t *testing.T) (cfg string, secrets []string) {
	t.Helper()
	base, secrets := mtkCfg(t)
	var out []string
	for _, l := range strings.Split(base, "\n") {
		k, v, _ := strings.Cut(l, "=")
		if strings.HasSuffix(k, ".wpa3.ft.status") {
			l = k + "=enabled"
		}
		out = append(out, l)
		if strings.HasPrefix(k, "aaa.") && strings.HasSuffix(k, ".id") && ftKeys[v] != "" {
			out = append(out, strings.TrimSuffix(k, "id")+"iapp_key="+ftKeys[v])
		}
	}
	if !strings.Contains(base, "aaa.1.ft.status=enabled") {
		t.Fatal("fixture: fast roaming off")
	}
	for _, k := range ftKeys {
		secrets = append(secrets, k)
	}
	return strings.Join(out, "\n"), secrets
}

// hapdSections splits a hostapd conf into its bss= sections by SSID.
func hapdSections(conf string) map[string]string {
	out := map[string]string{}
	parts := strings.Split(conf, "\nbss=")
	for _, p := range parts[1:] {
		for _, l := range strings.Split(p, "\n") {
			if v, ok := strings.CutPrefix(l, "ssid="); ok {
				out[v] = "bss=" + strings.TrimSuffix(p, "\n") + "\n"
				break
			}
		}
	}
	return out
}

// The controller's FT-SAE settings and the WLAN's key reach bcmwifi; the
// key never appears in a note or a printed Desired.
func TestDesiredFromFTSAE(t *testing.T) {
	cfg, secrets := ftSAECfg(t)
	cfg = strings.Replace(cfg, "aaa.1.ft.status=enabled\n", "aaa.1.ft.status=enabled\naaa.1.mobility_domain=C0DE\naaa.1.ft_over_ds=1\n", 1)
	in, inNotes := translate.IntentFromCfg(cfg)
	d, notes := desiredFrom(in)
	if len(d.SSIDs) != 3 {
		t.Fatalf("ssids %v (notes %q)", d.SSIDs, inNotes)
	}
	for _, s := range d.SSIDs {
		if !s.FT || !s.FTSAE || s.FTKey != ftKeys[s.ID] {
			t.Errorf("%s: ft=%t ftsae=%t own key=%t", s.SSID, s.FT, s.FTSAE, s.FTKey == ftKeys[s.ID])
		}
		if s.ID == "2" && (s.MobilityDomain != "c0de" || !s.FTOverDS) {
			t.Errorf("%s: mdid %q over-DS %t", s.SSID, s.MobilityDomain, s.FTOverDS)
		}
	}
	all := strings.Join(append(inNotes, notes...), "\n") + fmt.Sprintf("%v %+v %#v %v", d.SSIDs, d.SSIDs, d.SSIDs, in)
	for _, s := range secrets {
		if strings.Contains(all, s) {
			t.Fatalf("secret printed: %s", all)
		}
	}
}

// wpa3 on (takeover), ft_sae at its default: the radios claim WPA3 and
// WPA3 fast roaming, and given the system_cfg the controller then sends
// (WPA2/WPA3 transition, fast roaming and WPA3 fast roaming on), every SSID
// serves FT-PSK and FT-SAE with its own WLAN's key, a mobility domain per
// band (one unit's two hostapds cannot pass a PMK-R1), PMK-R1 push, and no
// wildcard key holder (hostapd 2.9 never sends its broadcast PULL). Keys
// and passphrases stay out of logs, informs and files other than the
// hostapd conf.
func TestE2EFTSAE(t *testing.T) {
	cfg, secrets := ftSAECfg(t)
	e := newE2E(t, cfg, true, func(c *Config, o *options) { c.WPA3 = true })
	e.adopt()
	eventually(t, "the bcmwifi dry-run apply", func() bool { return strings.Contains(e.logs.all(), "is live") })
	e.stop()
	for _, c2 := range radioCaps2(t, e) {
		if c2&models.RadioCap2WPA3 == 0 || c2&models.RadioCap2WPA3FT == 0 {
			t.Errorf("radio_caps2 %#x lacks WPA3 or WPA3 fast roaming", c2)
		}
	}
	p, ok := e.wifi.lastPlan()
	if !ok {
		t.Fatal("no bcmwifi plan")
	}
	if n := strings.Join(p.Notes, "\n"); strings.Contains(n, "802.11r") || strings.Contains(n, "FT-SAE not built") {
		t.Errorf("802.11r noted: %q", p.Notes)
	}
	md := map[string]map[string]string{}
	for _, radio := range []string{"wl0", "wl1"} {
		for ssid, sec := range hapdSections(hapdConf(p, "/tmp/udeco/hapd-"+radio+".conf")) {
			if !strings.Contains(sec, "\nwpa_key_mgmt=WPA-PSK FT-PSK SAE FT-SAE\n") {
				t.Errorf("%s %q: no FT-PSK + FT-SAE:\n%s", radio, ssid, sec)
			}
			for _, l := range []string{"pmk_r1_push=1", "ft_psk_generate_local=1", "ft_over_ds=0", "sae_require_mfp=1", "ieee80211w=1"} {
				if !strings.Contains(sec, "\n"+l+"\n") {
					t.Errorf("%s %q: no %s", radio, ssid, l)
				}
			}
			if strings.Contains(sec, "ff:ff:ff:ff:ff:ff") || strings.Contains(sec, "00:00:00:00:00:00") {
				t.Errorf("%s %q: wildcard key holder", radio, ssid)
			}
			for _, l := range strings.Split(sec, "\n") {
				if v, ok := strings.CutPrefix(l, "mobility_domain="); ok {
					if md[ssid] == nil {
						md[ssid] = map[string]string{}
					}
					md[ssid][radio] = v
				}
			}
		}
	}
	if len(md) != 3 {
		t.Errorf("FT on %d SSIDs, want 3 (%v)", len(md), md)
	}
	for ssid, m := range md {
		if len(m) == 2 && m["wl0"] == m["wl1"] {
			t.Errorf("%q: one mobility domain on both bands (%s): a cross-band roam would try FT-SAE and fail", ssid, m["wl0"])
		}
	}
	e.checkNoSecrets(secrets)
}

// ft_sae false (the kill switch): the agent claims WPA3 (0x1) but not WPA3
// fast roaming (0x2), and even when the controller sends wpa3.ft.status
// enabled with a key, every SSID serves FT-PSK and SAE without FT-SAE and
// no key reaches any file.
func TestE2EFTSAEKillSwitch(t *testing.T) {
	cfg, secrets := ftSAECfg(t)
	off := false
	e := newE2E(t, cfg, true, func(c *Config, o *options) { c.WPA3, c.FTSAE = true, &off })
	e.adopt()
	eventually(t, "the bcmwifi dry-run apply", func() bool { return strings.Contains(e.logs.all(), "is live") })
	e.stop()
	for _, c2 := range radioCaps2(t, e) {
		if c2&models.RadioCap2WPA3 == 0 || c2&models.RadioCap2WPA3FT != 0 {
			t.Errorf("radio_caps2 %#x: want WPA3 without WPA3 fast roaming", c2)
		}
	}
	p, ok := e.wifi.lastPlan()
	if !ok {
		t.Fatal("no bcmwifi plan")
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "FT-SAE not built") {
		t.Errorf("notes %q", p.Notes)
	}
	n := 0
	for _, radio := range []string{"wl0", "wl1"} {
		for ssid, sec := range hapdSections(hapdConf(p, "/tmp/udeco/hapd-"+radio+".conf")) {
			n++
			if !strings.Contains(sec, "\nwpa_key_mgmt=WPA-PSK FT-PSK SAE\n") {
				t.Errorf("%s %q: want FT-PSK and SAE without FT-SAE:\n%s", radio, ssid, sec)
			}
			for _, k := range []string{"\nr0kh=", "\nr1kh=", "\npmk_r1_push="} {
				if strings.Contains(sec, k) {
					t.Errorf("%s %q: %s without FT-SAE", radio, ssid, strings.TrimSpace(k))
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no BSS sections")
	}
	for _, st := range p.Steps {
		for _, k := range ftKeys {
			if strings.Contains(string(st.Data), k) {
				t.Errorf("%s carries an FT key without FT-SAE", st.Path)
			}
		}
	}
	e.checkNoSecrets(secrets)
}

// ft_sae: absent follows wpa3, false turns FT-SAE off, true without wpa3
// is refused; unknown spellings are refused by the strict decoder.
func TestConfigFTSAE(t *testing.T) {
	base := `{"inform_url":"http://192.168.0.2:8080/inform","console_ip":"192.168.0.3","takeover":true`
	for _, c := range []struct {
		extra string
		want  bool
		err   string
	}{
		{``, false, ""},
		{`,"wpa3":true`, true, ""},
		{`,"wpa3":true,"ft_sae":true`, true, ""},
		{`,"wpa3":true,"ft_sae":false`, false, ""},
		{`,"ft_sae":true`, false, "ft_sae needs wpa3"},
		{`,"ft_sae":false`, false, ""},
		{`,"wpa3":true,"ftsae":true`, false, "unknown field"},
	} {
		cfg, err := parseConfig([]byte(base + c.extra + "}"))
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: err %v, want %q", c.extra, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.extra, err)
			continue
		}
		if cfg.ftSAE() != c.want {
			t.Errorf("%s: ftSAE %t, want %t", c.extra, cfg.ftSAE(), c.want)
		}
	}
}

// ftWifi is fakeWifi with FT-SAE: fixed local key holders, and a record of
// the peers handed over and the syncs.
type ftWifi struct {
	*fakeWifi
	locals []ftpeer.Local
	mu     sync.Mutex
	peers  []ftpeer.Peer
	syncs  int
}

func (w *ftWifi) ServesFTSAE() bool { return true }
func (w *ftWifi) FTLocals(context.Context, bcmwifi.Desired) ([]ftpeer.Local, error) {
	return w.locals, nil
}
func (w *ftWifi) SetFTPeers(p []ftpeer.Peer) { w.mu.Lock(); w.peers = p; w.mu.Unlock() }
func (w *ftWifi) SyncFTPeers(context.Context, bcmwifi.Desired) (bcmwifi.FTSync, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.syncs++
	return bcmwifi.FTSync{Added: []string{"wl12: r0kh x"}}, nil
}
func (w *ftWifi) state() ([]ftpeer.Peer, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.peers, w.syncs
}

// ftBus is an in-memory L2 segment per bridge.
type ftBus struct {
	mu    sync.Mutex
	conns map[string][]*ftBusConn
	wire  [][]byte
}

type ftBusConn struct {
	b      *ftBus
	br     string
	in     chan []byte
	closed chan struct{}
	once   sync.Once
}

func (b *ftBus) open(br string) (ftpeer.Conn, error) {
	c := &ftBusConn{b: b, br: br, in: make(chan []byte, 64), closed: make(chan struct{})}
	b.mu.Lock()
	b.conns[br] = append(b.conns[br], c)
	b.mu.Unlock()
	return c, nil
}

func (c *ftBusConn) Recv(p []byte) (int, error) {
	select {
	case f := <-c.in:
		return copy(p, f), nil
	case <-c.closed:
		return 0, net.ErrClosed
	case <-time.After(20 * time.Millisecond):
		return 0, ftpeer.ErrTimeout
	}
}

func (c *ftBusConn) Send(f []byte) error {
	c.b.mu.Lock()
	defer c.b.mu.Unlock()
	c.b.wire = append(c.b.wire, append([]byte(nil), f...))
	for _, o := range c.b.conns[c.br] {
		if o != c {
			select {
			case o.in <- append([]byte(nil), f...):
			default:
			}
		}
	}
	return nil
}

func (c *ftBusConn) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

// The agent glue: in takeover with apply and wpa3, the discovery runs; an
// apply announces the unit's key holders on their bridge, a peer unit's
// announcement reaches bcmwifi through a worker job (SetFTPeers, then a
// live SyncFTPeers), and a drop to observe withdraws the holders. Not
// started without apply, or with ft_sae false. The key is in no log line
// and not on the wire.
func TestFTSAEAgentGlue(t *testing.T) {
	const key = "a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4"
	off := false
	for _, c := range []struct {
		name string
		cfg  Config
		runs bool
	}{
		{"takeover apply wpa3", Config{Takeover: true, Apply: true, WPA3: true}, true},
		{"no apply (plans only)", Config{Takeover: true, WPA3: true}, false},
		{"ft_sae false", Config{Takeover: true, Apply: true, WPA3: true, FTSAE: &off}, false},
		{"no wpa3", Config{Takeover: true, Apply: true}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			bus := &ftBus{conns: map[string][]*ftBusConn{}}
			lg := &logBuf{}
			cfg := c.cfg
			w := &ftWifi{fakeWifi: &fakeWifi{rec: &recorder{}}, locals: []ftpeer.Local{
				{Holder: ftpeer.Holder{Band: "na", BSSID: "be:a7:b9:3e:17:05", R0KHID: "bea7b93e1705", R1KHID: "be:a7:b9:3e:17:05", MDID: 0xff24}, Bridge: "br-lan", Key: key}}}
			a := &agent{cfg: &cfg, o: options{logf: lg.logf, ftOpen: bus.open}, jobs: make(chan job, 8),
				x: &device.Session{Dev: inform.Device{MAC: net.HardwareAddr{0x02, 0xa0, 0, 0, 0, 1}}}}
			a.takeover.Store(true)
			a.wifi = w
			d := bcmwifi.Desired{}
			a.worker.applied = &d
			a.startFTPeers(ctx)
			if !c.runs {
				a.ftKick()
				a.ftSync(ctx)
				if a.ftp != nil || len(a.jobs) != 0 {
					t.Fatalf("discovery started")
				}
				if _, n := w.state(); n != 0 {
					t.Errorf("synced %d times", n)
				}
				return
			}
			// The other unit, same WLAN key, on br-lan.
			peer := ftpeer.New(ftpeer.Options{Unit: net.HardwareAddr{0x02, 0xb0, 0, 0, 0, 1}, Open: bus.open, Interval: time.Hour, MinGap: time.Millisecond})
			peer.SetLocals([]ftpeer.Local{{Holder: ftpeer.Holder{Band: "na", BSSID: "02:b0:00:00:01:02", R0KHID: "02b000000102", R1KHID: "02:b0:00:00:01:02", MDID: 0xff24},
				Bridge: "br-lan", Key: key}})
			done := make(chan struct{})
			go func() { defer close(done); peer.Run(ctx) }()

			a.markApplied(d) // an apply: queues the sync
			runJobs := func() {
				for {
					select {
					case j := <-a.jobs:
						j.fn(ctx)
					default:
						return
					}
				}
			}
			eventually(t, "the peer learns this unit", func() bool { runJobs(); return len(peer.Peers()) == 1 })
			eventually(t, "bcmwifi gets the peer", func() bool {
				runJobs()
				ps, n := w.state()
				return len(ps) == 1 && ps[0].BSSID == "02:b0:00:00:01:02" && n > 0
			})
			a.ftDrop()
			eventually(t, "the holders withdrawn", func() bool { return len(peer.Peers()) == 0 })
			cancel()
			<-done
			a.bg.Wait()
			if strings.Contains(lg.all(), key) {
				t.Error("key in a log line")
			}
			bus.mu.Lock()
			defer bus.mu.Unlock()
			for _, f := range bus.wire {
				if strings.Contains(string(f), key) || strings.Contains(fmt.Sprintf("%x", f), key) {
					t.Fatal("key on the wire")
				}
			}
		})
	}
}
