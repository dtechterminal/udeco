// SPDX-License-Identifier: GPL-2.0-or-later

package main

// runner presents one Deco unit to UniFi as an AP: a port of uow's inform
// loop (cmd/uow/main.go) on internal/device.Session, reading the Deco only
// from the Mesh cache (docs/deco/design.md §4). Controller actions go to the
// Mesh command queue; nothing here blocks on a Deco.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/deco"
	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/inform"
	"github.com/antoniocosta/unifi-openwrt/internal/openwrt"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

type runner struct {
	d     *daemon
	u     UnitConfig
	owner bool // the mesh master: the only runner whose Wi-Fi plan may be applied
	mac   net.HardwareAddr

	dir, statePath, cfgPath string
	x                       *device.Session
	col                     *deco.Collector
	prev                    *openwrt.Snapshot
	collectErr              string

	sa    *device.SSHAdopt
	adopt chan device.AdoptRequest

	// offline policy (design §4), owned by the loop goroutine
	everSeen bool
	offSince time.Time
	gateWhy  string
}

func newRunner(d *daemon, u UnitConfig, owner bool) (*runner, error) {
	mac, err := net.ParseMAC(u.MAC)
	if err != nil || len(mac) != 6 {
		return nil, fmt.Errorf("bad mac %q", u.MAC)
	}
	r := &runner{d: d, u: u, owner: owner, mac: mac}
	r.dir = filepath.Join(d.cfg.StateDir, "units", strings.ReplaceAll(u.MAC, ":", ""))
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		return nil, err
	}
	os.Chmod(r.dir, 0o700)
	r.statePath = filepath.Join(r.dir, "state.json")
	r.cfgPath = filepath.Join(r.dir, "system_cfg.txt")
	st, found, err := device.Load(r.statePath)
	if err != nil {
		return nil, err
	}
	if !found {
		st = device.NewState(d.cfg.InformURL)
		st.Version = d.profile.Version
	}
	r.x = &device.Session{
		S: st, Boot: time.Now(), StateDir: r.dir, SSHPort: u.SSHDPort, WifiCaps: d.cfg.WifiCaps,
		Dev: inform.Device{MAC: mac, IP: d.daemonIP, Netmask: d.cfg.Netmask, Gateway: d.cfg.Gateway,
			Hostname: u.Name, Model: d.profile.Model, ModelDisplay: d.profile.Display},
	}
	r.x.Unhandled, r.x.KnownSection = device.OpenLedger(filepath.Join(r.dir, "unhandled.json")), translate.Handled
	if r.x.S.HashID == "" {
		if r.x.S.HashID, err = device.NewHashID(); err != nil {
			return nil, err
		}
		if err := r.x.S.Save(r.statePath); err != nil {
			return nil, err
		}
	}
	r.x.RestoreFromMgmtCfg()
	radios := map[string]deco.RadioSpec{}
	for band, p := range d.profile.Radios {
		radios[band] = deco.RadioSpec{NSS: p.NSS, TxMin: p.MinTx, TxMax: p.MaxTx}
	}
	r.col, err = deco.NewCollector(deco.Unit{Name: u.Name, MAC: u.MAC, IP: u.IP},
		deco.CollectOptions{Netmask: d.cfg.Netmask, Gateway: d.cfg.Gateway, Radios: radios, HideWired: d.cfg.HideWired,
			MaxAge: d.maxAge()}, time.Now())
	if err != nil {
		return nil, err
	}
	r.x.Extra = r.extra
	r.logf("start: mac=%s deco ip=%s reported ip=%s sshd_port=%d adopted=%v gcm=%v cfgversion=%s owner=%v (state %s)",
		u.MAC, u.IP, d.daemonIP, u.SSHDPort, r.x.S.Adopted, r.x.S.GCM, r.x.S.CfgVersion, owner,
		map[bool]string{true: "loaded", false: "new"}[found])
	return r, nil
}

func (r *runner) logf(f string, a ...any) { log.Printf("["+r.u.Name+"] "+f, a...) }

// start opens the SSH adoption listener: the adopt request carries no MAC,
// so each emulated AP has its own port (design §1).
func (r *runner) start() error {
	r.adopt = make(chan device.AdoptRequest, 4)
	r.sa = &device.SSHAdopt{
		Listen:    net.JoinHostPort(r.d.h.sshListenHost, strconv.Itoa(r.u.SSHDPort)),
		AllowFrom: []string{r.d.cfg.ConsoleIP},
		HostKey:   filepath.Join(r.dir, "ssh_host_ed25519.pem"),
		Requests:  r.adopt,
	}
	if err := r.sa.Start(); err != nil {
		r.sa = nil
		return fmt.Errorf("ssh-adopt: %w", err)
	}
	r.logf("ssh-adopt listening on %s (only from %s)", r.sa.Listen, r.d.cfg.ConsoleIP)
	return nil
}

func (r *runner) close() {
	if r.sa != nil {
		r.sa.Close()
	}
}

// extra returns the inform fields read from the Mesh cache (design §4
// "Extra"). It never does I/O on a Deco.
func (r *runner) extra() map[string]any {
	now := time.Now()
	ms := r.d.mesh.Snapshot()
	s, err := r.col.Collect(&ms, now)
	if err != nil {
		if err.Error() != r.collectErr {
			r.logf("mesh cache: %v (reporting the last reading, or a skeleton)", err)
			r.collectErr = err.Error()
		}
		s = r.prev
		if s == nil {
			s = r.col.Skeleton(now)
		}
	} else {
		r.collectErr = ""
	}
	c := *s
	c.IP = r.reportIP(s)
	cfg, _ := os.ReadFile(r.cfgPath)
	info := openwrt.InfoFromCfg(string(cfg))
	info.Authorized = deco.GuestAuthorized(&c) // a Deco guest network has no portal
	f := c.Fields(r.prev, info, nil)
	if c.Hostname != "" {
		f["hostname"] = c.Hostname
	}
	r.prev = &c
	return f
}

// reportIP is the daemon IP (the controller SSHes there to adopt and
// re-provision), or with report_ip=deco and once adopted, the Deco's own.
func (r *runner) reportIP(s *openwrt.Snapshot) string {
	if r.d.cfg.ReportIP == "deco" && r.x.S.Adopted && s.IP != "" {
		return s.IP
	}
	return r.d.daemonIP
}

// gate is the offline policy (design §4): no informs while the master
// session has been down too long, for a unit never seen in device_list once
// the list has been read, or for a unit offline past the grace period.
func (r *runner) gate(s *deco.MeshState, now time.Time) (bool, string) {
	if d := s.DownFor(now); d > r.d.h.masterDownMax {
		why := "master session down for " + d.Round(time.Second).String()
		if s.Latched != "" {
			why += " (logins latched off: " + s.Latched + ")"
		}
		return false, why
	}
	if s.Devices.Value == nil {
		return true, "" // not read yet: skeleton
	}
	dev := deco.FindUnit(s, r.u.MAC)
	if dev == nil && !r.everSeen {
		return false, "refused: " + r.u.MAC + " is not in the mesh device_list"
	}
	// While the session is up, a device_list that stopped refreshing (or
	// predates the reconnect) says nothing about the unit now: treat it like
	// offline. While it is down, masterDownMax above governs.
	stale := s.Connected && !deco.Fresh(s, &s.Devices, now, r.d.maxAge())
	if !stale && deco.UnitOnline(dev) {
		r.everSeen, r.offSince = true, time.Time{}
		return true, ""
	}
	if r.offSince.IsZero() {
		r.offSince = now
	}
	if d := now.Sub(r.offSince); d >= r.d.h.offlineGrace {
		if stale {
			return false, "device_list not refreshed for " + d.Round(time.Second).String()
		}
		return false, "unit offline for " + d.Round(time.Second).String()
	}
	return true, ""
}

// loop is uow's main loop for one unit, until ctx ends or the controller
// removes the device (on_remove=stop).
func (r *runner) loop(ctx context.Context) {
	defer r.close()
	defer r.x.Unhandled.Flush()
	if len(r.x.S.Blocked) > 0 && r.x.S.Adopted {
		r.d.blocks.Seed(r.u.Name, r.x.S.Blocked)
	}
	if _, err := os.Stat(r.cfgPath); err == nil {
		r.planWLAN("startup")
	}
	h := r.d.h
	interval := 10 * time.Second
	errs := 0
	for {
		now := time.Now()
		ms := r.d.mesh.Snapshot()
		ok, why := r.gate(&ms, now)
		if why != r.gateWhy {
			switch {
			case why != "":
				r.logf("not informing: %s", why)
			case r.gateWhy != "":
				r.logf("informing again")
			}
			r.gateWhy = why
		}
		wait := h.gatedWait
		if ok {
			cfgBefore := r.x.S.CfgVersion
			next, good := r.informOnce()
			for _, a := range next.Actions {
				r.action(a)
			}
			if r.x.S.CfgVersion != cfgBefore && !next.Reset {
				r.planWLAN("cfgversion " + cfgBefore + " -> " + r.x.S.CfgVersion)
			}
			if next.Reset && r.d.cfg.OnRemove == "stop" {
				r.logf("STOP: removed from the controller (setdefault); on_remove=stop, the Deco is untouched")
				r.d.blocks.Drop(r.u.Name)
				return
			}
			if good {
				errs = 0
			} else {
				errs++
			}
			if next.Interval > 0 {
				interval = max(next.Interval, h.minWait)
			}
			if ie := time.Duration(r.d.cfg.InformInterval); ie > 0 && interval > ie {
				interval = max(ie, h.minWait)
			}
			wait = interval
			if next.Immediate {
				wait = h.immediateWait
			}
			if errs > 0 {
				// like a real AP: keep informing, further and further apart
				wait = min(max(interval, 5*time.Second)*time.Duration(1<<min(errs-1, 4)), time.Minute)
				if errs == 1 || errs%10 == 0 {
					r.logf("%d bad answer(s) in a row: next inform in %s", errs, wait)
				}
			}
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			r.logf("stopped")
			return
		case req := <-r.adopt:
			t.Stop()
			o := r.x.ApplyAdopt(req)
			for _, e := range o.Events {
				r.logf("%s", e)
			}
			if err := r.x.S.Save(r.statePath); err != nil {
				r.logf("saving state: %v", err)
			}
			select { // let the console finish its SSH job first
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		case <-t.C:
		}
	}
}

// informOnce sends one inform and handles the answer (cmd/uow/main.go
// informOnce). ok=false counts as a bad answer.
func (r *runner) informOnce() (device.Outcome, bool) {
	x := r.x
	js, err := x.Payload(time.Now())
	if err != nil {
		r.logf("payload: %v", err)
		return device.Outcome{}, false
	}
	pkt, err := inform.Encode(x.Dev.MAC, x.S.Key, x.Cipher(), js, nil)
	if err != nil {
		r.logf("encode: %v", err)
		return device.Outcome{}, false
	}
	req, _ := http.NewRequest(http.MethodPost, x.S.InformURL, bytes.NewReader(pkt))
	req.Header.Set("Content-Type", "application/x-binary")
	resp, err := r.d.h.httpClient.Do(req)
	if err != nil {
		r.logf("POST: %v", err)
		return device.Outcome{}, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		if !x.S.Adopted {
			return device.Outcome{}, true // pending: normal
		}
		r.logf("HTTP 404 while adopted (forgotten?)")
		return device.Outcome{}, false
	default:
		r.logf("HTTP %d (%d bytes)", resp.StatusCode, len(body))
		return device.Outcome{}, false
	}
	if len(body) == 0 {
		return device.Outcome{}, true
	}
	_, plain, err := inform.Decode(body, x.S.Key)
	if err != nil && x.S.Key != inform.DefaultKeyHex {
		_, plain, err = inform.Decode(body, inform.DefaultKeyHex)
	}
	if err != nil {
		r.logf("reply did not decode: %v", err)
		return device.Outcome{}, false
	}
	o, err := x.Handle(plain, time.Now())
	if err != nil {
		r.logf("%v", err)
		return o, false
	}
	for _, e := range o.Events {
		if !strings.HasPrefix(e, "noop ") || o.Immediate {
			r.logf("%s", e)
		}
	}
	if o.Changed {
		if err := x.S.Save(r.statePath); err != nil {
			r.logf("saving state: %v", err)
		}
	}
	return o, true
}

// planWLAN hands the saved system_cfg to the Wi-Fi applier, which logs the
// masked plan and queues it only for the master's runner with apply on.
func (r *runner) planWLAN(why string) {
	b, err := os.ReadFile(r.cfgPath)
	if err != nil {
		return
	}
	r.logf("Wi-Fi config from the controller (%s)", why)
	r.d.wlan.Submit(r.u.Name, r.owner, translate.ParseCfg(string(b)))
}

// action carries out a controller action (device.Outcome.Actions) through
// the Mesh command queue, or logs it when the Deco has no equivalent.
func (r *runner) action(a string) {
	verb, arg, _ := strings.Cut(a, ":")
	switch verb {
	case "reboot":
		r.logf("RESTART requested by the controller: Deco reboot (0x4016) via the master")
		r.await("reboot", r.d.mesh.Submit(deco.Command{Kind: deco.CmdReboot, MAC: r.u.MAC}))
	case "block":
		r.d.blocks.Set(r.u.Name, r.x.S.Blocked)
	case "unblock":
		// the new blocked list arrives with the "block" action
	case "locate":
		r.logf("locate %s: logged only (a Deco has no locate)", arg)
	case "led":
		r.logf("LED %s from the controller: not supported yet (logged only)", arg)
	case "kick":
		r.logf("kick %s: unsupported on Deco (no opcode); logged only", arg)
	case "scan", "spectrum-scan":
		r.logf("%s: unsupported on Deco; logged only", verb)
	case "guest-auth", "guest-unauth":
		r.logf("%s %s: a Deco guest network has no portal; ignored", verb, arg)
	default:
		r.logf("action %q: ignored", a)
	}
}

// await logs a command's result when it arrives, off the inform path.
func (r *runner) await(what string, ch <-chan deco.CommandResult) {
	go func() {
		res := <-ch
		switch {
		case res.Err != nil:
			r.logf("%s: not done: %v", what, res.Err)
		case res.DryRun:
			r.logf("%s: apply=false, not sent", what)
		default:
			r.logf("%s: accepted by the Deco", what)
		}
	}()
}
