// SPDX-License-Identifier: GPL-2.0-or-later

package main

// -discover and -print: the read-only first steps of the rollout
// (docs/deco/design.md §10). -discover sends TDP only. -print makes one SSH
// login, one pass of every poll, and prints the cache and the per-unit
// snapshots as JSON. Neither sends anything to UniFi or writes to a Deco;
// the TP-Link ID, its password, the owner hash and Wi-Fi passphrases are
// left out of the output.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/dtechterminal/udeco/internal/deco"
	"github.com/dtechterminal/udeco/internal/models"
)

// unitTDP is one unit's TDP reply, without the owner hash.
type unitTDP struct {
	Name         string         `json:"name"`
	IP           string         `json:"ip"`
	MAC          string         `json:"mac"` // configured
	Reply        *deco.DecoInfo `json:"reply,omitempty"`
	Error        string         `json:"error,omitempty"`
	OwnerMatches *bool          `json:"owner_matches,omitempty"` // md5/sha256(tplink_id) == TDP owner
	MACMatches   *bool          `json:"mac_matches,omitempty"`
}

// redactInfo copies d without the owner hash (a hash of the TP-Link ID).
func redactInfo(d *deco.DecoInfo) *deco.DecoInfo {
	if d == nil {
		return nil
	}
	c := *d
	if c.Owner != "" {
		c.Owner = "[redacted]"
	}
	return &c
}

func discoverer(h hooks) func(ctx context.Context, ip string) (*deco.DecoInfo, error) {
	if h.discover != nil {
		return h.discover
	}
	return func(ctx context.Context, ip string) (*deco.DecoInfo, error) {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		out, err := deco.DiscoverDeco(ctx, ip, false)
		if err != nil {
			return nil, err
		}
		if len(out) == 0 {
			return nil, errors.New("tdp: no reply")
		}
		return &out[0], nil
	}
}

// discoverOnly probes every unit over TDP and runs the login precheck
// against those replies. It never logs in and needs no password.
func discoverOnly(ctx context.Context, cfg *Config, sec Secrets, h hooks, out io.Writer) error {
	probe := discoverer(h)
	replies := map[string]*deco.DecoInfo{}
	var units []unitTDP
	for _, u := range cfg.Units {
		row := unitTDP{Name: u.Name, IP: u.IP, MAC: u.MAC}
		info, err := probe(ctx, u.IP)
		if err != nil {
			row.Error = err.Error()
		} else {
			replies[u.IP] = info
			om, mm := len(info.Owner) > 1 && info.OwnerMatches(sec.TPLinkID), deco.NormMAC(info.MAC) == u.MAC
			row.Reply, row.OwnerMatches, row.MACMatches = redactInfo(info), &om, &mm
		}
		units = append(units, row)
	}
	// The Mesh's own precheck, fed the replies above (no second probe).
	h.discover = func(_ context.Context, ip string) (*deco.DecoInfo, error) {
		if d := replies[ip]; d != nil {
			c := *d
			return &c, nil
		}
		return nil, errors.New("tdp: no reply")
	}
	if sec.Password == "" {
		sec.Password = "unused: -discover never logs in"
	}
	verdict := "ok: a login would be allowed"
	m, err := newMesh(cfg, sec, h, false)
	if err == nil {
		_, err = m.Precheck(ctx)
	}
	if err != nil {
		verdict = err.Error()
	}
	return writeJSON(out, map[string]any{"units": units, "precheck": verdict})
}

// printOut is the -print document.
type printOut struct {
	Generated time.Time                 `json:"generated"`
	Result    string                    `json:"result"`
	Mesh      deco.MeshState            `json:"mesh"`
	Live      *deco.LiveView            `json:"live"` // who is connected now, and where; null: no presence list read
	Units     map[string]map[string]any `json:"units"`
}

// printOnce logs in once, waits for every poll (or the -only subset) to run
// once, or the login to fail, or the session to drop, and prints the result.
// The Mesh is capped at one login (MaxLogins), so however long the deadline,
// it can never make a second login, and runs each Get until it succeeds
// once (MeshConfig.Once), so an answered Get is never re-sent. On every exit
// path the Mesh frees the token and sends BYE before printOnce returns.
func printOnce(ctx context.Context, cfg *Config, sec Secrets, h hooks, out io.Writer) error {
	h.fill()
	h.maxLogins = 1
	h.once = true
	m, err := newMesh(cfg, sec, h, false)
	if err != nil {
		return err
	}
	ops := m.PolledOps()
	if _, err := m.Precheck(ctx); err != nil {
		return err // refused, or the master did not answer: no login
	}
	rctx, cancel := context.WithTimeout(ctx, h.printTimeout)
	done := make(chan struct{})
	go func() { defer close(done); _ = m.Run(rctx) }()
	result, polled := "timeout before every poll ran", false
	for wait := true; wait; {
		s := m.Snapshot()
		switch {
		case s.Latched != "":
			result, wait = "logins latched off: "+s.Latched, false
		case !s.Connected && !s.ConnectedSince.IsZero():
			result, wait = "session lost: "+s.LastError, false
		case !s.Connected && !s.NextLoginAt.IsZero():
			result, wait = "login failed: "+s.LastError, false
		case s.Connected && allPolled(&s, ops):
			polled, wait = true, false
		}
		if !wait {
			break
		}
		select {
		case <-rctx.Done():
			wait = false
		case <-time.After(100 * time.Millisecond):
		}
	}
	cancel()
	<-done // the session is closed (token freed, BYE sent)

	s := m.Snapshot()
	if polled {
		result = pollVerdict(&s, ops) // from the state that is printed
	}
	now := time.Now()
	// Everything printed was read during this run: no age limit beyond it.
	maxAge := h.printTimeout + time.Minute
	live := deco.LiveClients(&s, now, maxAge)
	s.Wireless.Value = deco.MaskWireless(s.Wireless.Value)
	s.Master = redactInfo(s.Master)
	units := map[string]*deco.DecoInfo{}
	for k, v := range s.Units {
		units[k] = redactInfo(v)
	}
	s.Units = units
	po := printOut{Generated: now.UTC(), Result: result, Mesh: s, Live: live, Units: map[string]map[string]any{}}
	model, _ := models.Lookup(cfg.Model)
	prof := models.Profile(model)
	radios := map[string]deco.RadioSpec{}
	for band, p := range prof.Radios {
		radios[band] = deco.RadioSpec{NSS: p.NSS, TxMin: p.MinTx, TxMax: p.MaxTx}
	}
	for _, u := range cfg.Units {
		row := map[string]any{"ip": u.IP, "mac": u.MAC}
		c, err := deco.NewCollector(deco.Unit{Name: u.Name, MAC: u.MAC, IP: u.IP},
			deco.CollectOptions{Netmask: cfg.Netmask, Gateway: cfg.Gateway, Radios: radios, HideWired: cfg.HideWired, MaxAge: maxAge}, now)
		if err != nil {
			row["error"] = err.Error()
			po.Units[u.Name] = row
			continue
		}
		// Always a snapshot: the collected one, else the skeleton the
		// runner would inform with (device_list not read, e.g. under -only).
		snap, err := c.Collect(&s, now)
		row["snapshot_source"] = "collected"
		if err != nil {
			row["error"] = err.Error()
			row["snapshot_source"] = "skeleton"
			snap = c.Skeleton(now)
		}
		row["snapshot"] = snap
		if d := deco.FindUnit(&s, u.MAC); d != nil {
			row["online"] = deco.UnitOnline(d)
			if live != nil {
				n := 0
				for _, lc := range live.Clients {
					if lc.DeviceID == d.DeviceID {
						n++
					}
				}
				row["live_clients"] = n
			}
		}
		po.Units[u.Name] = row
	}
	if err := writeJSON(out, po); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("-print: %s", result)
	}
	return nil
}

func pollOf(s *deco.MeshState, op uint16) deco.PollInfo {
	p, _ := s.Poll(op)
	return p
}

// allPolled: every Get in ops ran at least once (succeeded, failed or was
// turned off).
func allPolled(s *deco.MeshState, ops []uint16) bool {
	for _, op := range ops {
		if !pollOf(s, op).Ran {
			return false
		}
	}
	return true
}

// pollVerdict is "ok" when every Get in ops succeeded (or the device does
// not support it), else the failures.
func pollVerdict(s *deco.MeshState, ops []uint16) string {
	var bad []string
	for _, op := range ops {
		if p := pollOf(s, op); !p.OK && !p.Disabled {
			bad = append(bad, fmt.Sprintf("%s(0x%04x): %s", pollNames[op], op, p.Err))
		}
	}
	if len(bad) == 0 {
		return "ok"
	}
	return "poll errors: " + strings.Join(bad, "; ")
}

// pollNames are the -only names of the polled Gets.
var pollNames = map[uint16]string{
	deco.OpGetDeviceList:      "devices",
	deco.OpGetClientList:      "clients",
	deco.OpGetClientSpeedList: "speeds",
	deco.OpGetIoTClientList:   "iot",
	deco.OpGetWireless:        "wireless",
	deco.OpGetDeviceEthPort:   "ports",
	deco.OpGetBlockList:       "blocks",
}

// onlyNames lists the -only names in the Mesh's poll order.
const onlyNames = "devices,speeds,iot,wireless,ports,blocks,clients"

// parseOnly parses -only: a comma list of poll names or opcodes (0x4012),
// kept in the given order.
func parseOnly(v string) ([]uint16, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	byName := map[string]uint16{}
	for op, n := range pollNames {
		byName[n] = op
	}
	var out []uint16
	seen := map[uint16]bool{}
	for _, f := range strings.Split(v, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		op, ok := byName[f]
		if !ok {
			n, err := strconv.ParseUint(strings.TrimPrefix(f, "0x"), 16, 16)
			if err != nil || pollNames[uint16(n)] == "" {
				return nil, fmt.Errorf("-only: %q is not one of %s or their opcodes", f, onlyNames)
			}
			op = uint16(n)
		}
		if seen[op] {
			return nil, fmt.Errorf("-only: %q listed twice", f)
		}
		seen[op] = true
		out = append(out, op)
	}
	return out, nil
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
