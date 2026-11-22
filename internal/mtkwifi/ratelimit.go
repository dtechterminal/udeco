// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/atomicfile"
	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// Speed limits (docs/deco/features/client-rate-limit.md, "Garage").
//
// The unit's kernel has no traffic control (CONFIG_NET_SCHED is off: no tc
// qdiscs, none loadable), so the Deco's tc trees cannot be built here. The
// agent's own kernel module udeco_rl (tools/udeco_rl, GPL) polices instead:
// a token bucket per station and direction, in bytes, on the bridge's
// FORWARD hook. Download is what leaves on a Wi-Fi port (ra*, rai*) to the
// station's MAC, upload what arrives on one from it. A bucket in debt drops;
// any other frame passes, so a limited station is slowed and never cut off,
// and its ARP, DHCP and IPv6 neighbour discovery always pass. The unit's
// own traffic, wired ports and stations without an entry are never touched.
// Jio's hardware NAT (hw_nat, the PPE) would forward a bound flow past the
// bridge: the module clears the FOE tag of every frame of a limited
// station, so its flows are never bound, and a "flush" line (sent with a
// table that added or changed a limit) drops the flows bound before.
//
// What the module polices is the table this file writes to /proc/udeco_rl,
// the same merge as bcmwifi wantShaping: per station, its own entry's
// limit (cmd rate-update, SetClientRates) in each direction the entry
// limits, else the limit of the SSID it is associated on (the WLAN's user
// group, from the readings: RateStations). Entries are keyed by MAC
// only, so a station's own limit holds on whichever SSID and radio of the
// unit it joins, from its first frame; an SSID's limit follows a station
// from the reading that shows it there (Tick, a reading, an apply).
//
// The table is written when it changes and at every Tick (the module keeps
// it across agent restarts; a reboot loses it and the startup hand-over
// writes it again). The module is loaded (insmod) only when a limit is
// wanted, and removed at the hand-back. With rate_limits off, or the
// module failing to load, nothing is applied and that is noted.

const (
	rlProc = "/proc/udeco_rl"
	// DefaultRateModule is where the deploy puts the module (gzip).
	DefaultRateModule = "/flash2/udeco/udeco_rl.ko.gz"
	rlModName         = "udeco_rl"
	rlVersion         = 1
	rlRatesFile       = "mtk-client-rates.json" // RunDir: the per-client list of this boot
	rlKoFile          = "udeco_rl.ko"           // RunDir: the module, uncompressed for insmod
	// rlRetry: a module that failed to load is tried again after this
	rlRetry = 10 * time.Minute
	// rlMaxEntries is the module's table size (RL_MAX)
	rlMaxEntries = 512
	// rlOffSuffix ends the plan note of an SSID's limit (features.go);
	// rateNotes drops the note or gives the limiter's own reason
	rlOffSuffix = " (rate_limits is off on this unit)"
)

var macRE = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// rlKernel is the kernel side of the limiter (procKernel; tests fake it).
type rlKernel interface {
	// Status reads the module's header; loaded is false without the module.
	Status() (st rlStatus, loaded bool, err error)
	Load(ctx context.Context) error
	Write(table string) error
	Unload(ctx context.Context) error
}

// rlStatus is the header line of /proc/udeco_rl.
type rlStatus struct {
	Version int
	Entries int
	HWNAT   string // live, absent
}

// parseRLStatus reads "udeco_rl 1 entries=N hwnat=live ...".
func parseRLStatus(b []byte) (rlStatus, error) {
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != rlModName {
		return rlStatus{}, fmt.Errorf("%s: unexpected header %q", rlProc, line)
	}
	v, err := strconv.Atoi(f[1])
	if err != nil {
		return rlStatus{}, fmt.Errorf("%s: unexpected header %q", rlProc, line)
	}
	st := rlStatus{Version: v}
	for _, kv := range f[2:] {
		k, val, _ := strings.Cut(kv, "=")
		switch k {
		case "entries":
			st.Entries, _ = strconv.Atoi(val)
		case "hwnat":
			st.HWNAT = val
		}
	}
	return st, nil
}

// procKernel is the module on the unit: /proc/udeco_rl, insmod, rmmod.
type procKernel struct{ a *Applier }

func (k procKernel) Status() (rlStatus, bool, error) {
	b, err := os.ReadFile(k.a.dev(rlProc))
	if errors.Is(err, os.ErrNotExist) {
		return rlStatus{}, false, nil
	}
	if err != nil {
		return rlStatus{}, true, err
	}
	st, err := parseRLStatus(b)
	return st, true, err
}

// Load installs the module from Options.RateModule (a .gz is unpacked into
// RunDir first).
func (k procKernel) Load(ctx context.Context) error {
	src := k.a.o.RateModule
	if src == "" {
		src = DefaultRateModule
	}
	b, err := os.ReadFile(k.a.dev(src))
	if err != nil {
		return err
	}
	if strings.HasSuffix(src, ".gz") {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return fmt.Errorf("%s: %w", src, err)
		}
		if b, err = io.ReadAll(zr); err != nil {
			return fmt.Errorf("%s: %w", src, err)
		}
	}
	ko := filepath.Join(k.a.o.RunDir, rlKoFile)
	if err := atomicfile.Write(k.a.dev(ko), k.a.dev(ko)+".tmp", b, 0o600); err != nil {
		return err
	}
	return k.a.run(ctx, "insmod", ko)
}

func (k procKernel) Write(table string) error {
	if k.a.o.DryRun {
		k.a.o.Logf("mtkwifi: dry run: %s <- %d line(s)", rlProc, strings.Count(table, "\n"))
		return nil
	}
	if f := k.a.onChange.Load(); f != nil {
		(*f)(context.Background())
	}
	// one write: the module takes the whole table or none of it
	f, err := os.OpenFile(k.a.dev(rlProc), os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte(table)); err != nil {
		f.Close()
		return fmt.Errorf("%s: %w", rlProc, err)
	}
	return f.Close()
}

func (k procKernel) Unload(ctx context.Context) error {
	if err := k.Write("clear\n"); err != nil {
		k.a.o.Logf("mtkwifi: speed limits: clearing the table: %v", err)
	}
	return k.a.run(ctx, "rmmod", rlModName)
}

// rlState is the limiter's state (under a.mu).
type rlState struct {
	rates  map[string]bcmwifi.RateLimit // per-client limits; nil = not read yet
	stas   map[string]string            // station MAC -> BSS netdev, the last reading
	table  map[string]bcmwifi.RateLimit // what the module was last given (nil: nothing this process)
	failed string                       // why the module could not be used
	failAt time.Duration                // Options.mono of the failure
	noted  bool                         // the rate_limits off note was logged
}

func (a *Applier) kernel() rlKernel {
	if a.o.rlKern != nil {
		return a.o.rlKern
	}
	return procKernel{a}
}

// loadRates returns the per-client list, reading RunDir on first use (an
// agent restart's first Tick, before the startup hand-over).
func (a *Applier) loadRates() map[string]bcmwifi.RateLimit {
	if a.rl.rates == nil {
		m := map[string]bcmwifi.RateLimit{}
		if b, err := os.ReadFile(a.dev(filepath.Join(a.o.RunDir, rlRatesFile))); err == nil {
			var raw map[string]bcmwifi.RateLimit
			if json.Unmarshal(b, &raw) == nil {
				m = normRates(raw)
			}
		}
		a.rl.rates = m
	}
	return a.rl.rates
}

// normRates drops bad MACs, directions without a positive limit and
// entries with no limit left (MACs lower case).
func normRates(in map[string]bcmwifi.RateLimit) map[string]bcmwifi.RateLimit {
	out := map[string]bcmwifi.RateLimit{}
	for mac, r := range in {
		m := strings.ToLower(strings.TrimSpace(mac))
		if !macRE.MatchString(m) {
			continue
		}
		r.DownKbps, r.UpKbps = max(r.DownKbps, 0), max(r.UpKbps, 0)
		if r.DownKbps == 0 && r.UpKbps == 0 {
			continue
		}
		out[m] = r
	}
	return out
}

// SetClientRates replaces the per-client limits (MAC -> kbit/s, 0 = that
// direction not limited by the client's own entry) and brings the module's
// table in line at once. It returns the number of stations whose limit was
// added, changed or removed. The list is kept in RunDir for an agent
// restart; a failed write there is only logged.
func (a *Applier) SetClientRates(ctx context.Context, rates map[string]bcmwifi.RateLimit) (int, error) {
	m := normRates(rates)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rl.rates = m
	if !a.o.DryRun {
		b, _ := json.MarshalIndent(m, "", " ")
		p := a.dev(filepath.Join(a.o.RunDir, rlRatesFile))
		if err := atomicfile.Write(p, p+".tmp", b, 0o644); err != nil {
			a.o.Logf("mtkwifi: speed limits: keeping the list in %s: %v", rlRatesFile, err)
		}
	}
	return a.syncRates(ctx)
}

// RateStations takes a reading's stations (which BSS each is on), so the
// SSID-wide limits follow them; the table is rewritten when that changes
// what is limited. It never waits (a reading during an apply is skipped).
func (a *Applier) RateStations(ctx context.Context, s *apstate.Snapshot) {
	if s == nil || !a.mu.TryLock() {
		return
	}
	defer a.mu.Unlock()
	if a.live == nil {
		return
	}
	served := map[string]bool{}
	for _, rd := range a.o.Layout {
		for i := range a.live[rd.Band].BSS {
			served[a.ifaceOf(rd, a.live[rd.Band], i)] = true
		}
	}
	stas := map[string]string{}
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			if !served[v.Iface] {
				continue
			}
			for _, st := range v.Stations {
				if m := strings.ToLower(st.MAC); macRE.MatchString(m) {
					stas[m] = v.Iface
				}
			}
		}
	}
	a.rl.stas = stas
	if _, err := a.syncRates(ctx); err != nil {
		a.o.Logf("mtkwifi: speed limits: %v (retried at the next tick)", err)
	}
}

// ssidLimits is each served BSS netdev's SSID-wide limit (its WLAN's user
// group), from what is live and the Desired it came from.
func (a *Applier) ssidLimits() map[string]bcmwifi.RateLimit {
	byID := map[string]bcmwifi.RateLimit{}
	for _, s := range a.desired.SSIDs {
		if r := s.RateLimit; r != nil && (r.DownKbps > 0 || r.UpKbps > 0) {
			byID[s.ID] = bcmwifi.RateLimit{DownKbps: max(r.DownKbps, 0), UpKbps: max(r.UpKbps, 0)}
		}
	}
	out := map[string]bcmwifi.RateLimit{}
	for _, rd := range a.o.Layout {
		rp := a.live[rd.Band]
		if !rp.On {
			continue
		}
		for i, b := range rp.BSS {
			if r, ok := byID[b.ID]; ok {
				out[a.ifaceOf(rd, rp, i)] = r
			}
		}
	}
	return out
}

// wantRates is the table the module should police: every per-client entry
// (by MAC, wherever the station is) with the SSID's limit in the directions
// the entry leaves open, and the SSID's limit for the other stations
// associated on a limited SSID. Nothing while the agent does not own Wi-Fi
// (before the first apply, after a hand-back): the list is only kept, and
// syncRates leaves the module alone.
func (a *Applier) wantRates() map[string]bcmwifi.RateLimit {
	want := map[string]bcmwifi.RateLimit{}
	if a.live == nil {
		return want
	}
	for m, r := range a.loadRates() {
		want[m] = r
	}
	lim := a.ssidLimits()
	for m, dev := range a.rl.stas {
		s, ok := lim[dev]
		if !ok {
			continue
		}
		r := want[m]
		if r.DownKbps <= 0 {
			r.DownKbps = s.DownKbps
		}
		if r.UpKbps <= 0 {
			r.UpKbps = s.UpKbps
		}
		want[m] = r
	}
	for m, r := range want {
		if r.DownKbps <= 0 && r.UpKbps <= 0 {
			delete(want, m)
		}
	}
	return want
}

// rlTable is the module's input for want: sorted "<mac> <down> <up>"
// lines, "flush" when a limit was added or changed (flows hw_nat bound
// before must take the bridge), "clear" for an empty table.
func rlTable(want map[string]bcmwifi.RateLimit, flush bool) string {
	if len(want) == 0 {
		return "clear\n"
	}
	macs := make([]string, 0, len(want))
	for m := range want {
		macs = append(macs, m)
	}
	sort.Strings(macs)
	var b strings.Builder
	for _, m := range macs {
		fmt.Fprintf(&b, "%s %d %d\n", m, want[m].DownKbps, want[m].UpKbps)
	}
	if flush {
		b.WriteString("flush\n")
	}
	return b.String()
}

// rateChanges counts the stations whose limit differs between old and
// new, and whether one was added or changed (not only removed).
func rateChanges(old, new map[string]bcmwifi.RateLimit) (n int, tighter bool) {
	for m, r := range new {
		if o, ok := old[m]; !ok || o != r {
			n++
			tighter = true
		}
	}
	for m := range old {
		if _, ok := new[m]; !ok {
			n++
		}
	}
	return n, tighter
}

// RateLimitsHealthy: the limiter applies the controller's limits (on, and
// the module loaded or not needed yet). The plan notes say otherwise.
func (a *Applier) RateLimitsHealthy() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.o.RateLimits && a.rl.failed == ""
}

// rateNotes rewrites the plan notes of the SSIDs' limits (a.mu held):
// none while the limiter works (or is not needed yet), the limiter's
// failure as their reason, as written by ssidNotes with rate_limits off.
func (a *Applier) rateNotes(notes []string) []string {
	if !a.o.RateLimits {
		return notes
	}
	out := notes[:0:0]
	for _, n := range notes {
		if !strings.HasSuffix(n, rlOffSuffix) {
			out = append(out, n)
			continue
		}
		if a.rl.failed != "" {
			out = append(out, strings.TrimSuffix(n, rlOffSuffix)+" (the station limiter is not working: "+a.rl.failed+")")
		}
	}
	return out
}

// tickRates is Apply's and Tick's sync (a.mu held): a failure is logged
// by rlFail and retried at the next tick.
func (a *Applier) tickRates(ctx context.Context) { _, _ = a.syncRates(ctx) }

// syncRates brings the module's table in line with wantRates (a.mu held).
// It returns the number of stations whose limit changed.
func (a *Applier) syncRates(ctx context.Context) (int, error) {
	want := a.wantRates()
	k := a.kernel()
	if !a.o.RateLimits {
		if len(want) > 0 && !a.rl.noted {
			a.rl.noted = true
			a.o.Logf("mtkwifi: speed limits for %d station(s) not applied: rate_limits is off on this unit", len(want))
		}
		if a.rl.table == nil {
			// a module an earlier run with rate_limits on left loaded
			a.rl.table = map[string]bcmwifi.RateLimit{}
			if _, loaded, _ := k.Status(); loaded {
				a.o.Logf("mtkwifi: speed limits: rate_limits is off: removing %s", rlModName)
				if err := k.Unload(ctx); err != nil {
					a.o.Logf("mtkwifi: speed limits: rmmod %s: %v", rlModName, err)
				}
			}
		}
		return 0, nil
	}
	if a.live == nil {
		// not owning Wi-Fi: before the first Plan of an agent restart (a
		// module left loaded keeps policing its table until the first
		// Tick rewrites it), or after the hand-back (which removed it)
		return 0, nil
	}
	if a.o.DryRun {
		n, _ := rateChanges(a.rl.table, want)
		if a.rl.table == nil || n > 0 {
			a.o.Logf("mtkwifi: dry run: speed limits for %d station(s) not applied", len(want))
		}
		a.rl.table = want
		return n, nil
	}
	st, loaded, err := k.Status()
	if err != nil {
		return 0, a.rlFail(err)
	}
	if !loaded {
		if len(want) == 0 {
			a.rl.table = map[string]bcmwifi.RateLimit{}
			return 0, nil // nothing wanted: the module is never loaded for nothing
		}
		if a.rl.failed != "" && a.o.mono()-a.rl.failAt < rlRetry {
			return 0, fmt.Errorf("speed limits not applied: %s", a.rl.failed)
		}
		a.o.Logf("mtkwifi: speed limits: loading %s for %d station(s)", rlModName, len(want))
		if err := k.Load(ctx); err != nil {
			return 0, a.rlFail(fmt.Errorf("insmod %s: %w", rlModName, err))
		}
		a.rl.table = nil // a fresh module has an empty table
		if st, loaded, err = k.Status(); err != nil || !loaded {
			if err == nil {
				err = fmt.Errorf("%s missing after insmod", rlProc)
			}
			return 0, a.rlFail(err)
		}
	}
	if st.Version != rlVersion {
		return 0, a.rlFail(fmt.Errorf("%s version %d, this agent speaks %d", rlModName, st.Version, rlVersion))
	}
	if len(want) > rlMaxEntries {
		a.o.Logf("mtkwifi: speed limits: %d stations, the module takes %d: the rest are not limited", len(want), rlMaxEntries)
		want = firstRates(want, rlMaxEntries)
	}
	old := a.rl.table
	if old != nil && st.Entries != len(old) {
		// the module lost or changed its table (reloaded by hand): rebuild
		a.o.Logf("mtkwifi: speed limits: %s holds %d entries, %d expected: rewritten", rlModName, st.Entries, len(old))
		old = nil
	}
	n, tighter := rateChanges(old, want)
	if old != nil && n == 0 {
		return 0, nil
	}
	if err := k.Write(rlTable(want, tighter && st.HWNAT == "live")); err != nil {
		return 0, a.rlFail(err)
	}
	if a.rl.failed != "" {
		a.o.Logf("mtkwifi: speed limits work again")
	}
	a.rl.failed, a.rl.table = "", want
	if n > 0 {
		a.o.Logf("mtkwifi: speed limits: %d station(s) changed, %d limited", n, len(want))
	}
	return n, nil
}

// rlFail records why the limiter does not work (noted in the plan, logged
// once per reason) and returns err.
func (a *Applier) rlFail(err error) error {
	if s := err.Error(); s != a.rl.failed {
		a.o.Logf("mtkwifi: speed limits not applied: %v", err)
		a.rl.failed = s
	}
	a.rl.failAt = a.o.mono()
	a.rl.table = nil
	return err
}

// firstRates keeps n entries of m, by MAC order (deterministic).
func firstRates(m map[string]bcmwifi.RateLimit, n int) map[string]bcmwifi.RateLimit {
	macs := make([]string, 0, len(m))
	for k := range m {
		macs = append(macs, k)
	}
	sort.Strings(macs)
	out := map[string]bcmwifi.RateLimit{}
	for _, k := range macs[:n] {
		out[k] = m[k]
	}
	return out
}

// rateHandBack removes the module and its table (the hand-back: the
// vendor's unit has no limiter). Nothing runs when it is not loaded.
func (a *Applier) rateHandBack(ctx context.Context) {
	a.rl.stas, a.rl.table = nil, nil
	k := a.kernel()
	if _, loaded, _ := k.Status(); !loaded {
		return
	}
	if err := k.Unload(ctx); err != nil {
		a.o.Logf("mtkwifi: speed limits: removing %s: %v", rlModName, err)
		return
	}
	a.o.Logf("mtkwifi: speed limits: %s removed (hand-back)", rlModName)
}

// RemoveRateLimiter is the observe-mode start's and the drop to observe's
// safety net: a udeco_rl an earlier takeover run left loaded is removed
// (its table cleared first). Nothing runs without one.
func RemoveRateLimiter(ctx context.Context, root string, run Runner, logf func(string, ...any)) error {
	// the layout without 802.1X: New's enterprise check is not this
	// removal's business (its log line would be noise here)
	l := append([]RadioDef(nil), JCOW414...)
	for i := range l {
		l[i].Dot1X = false
	}
	a := New(Options{Root: root, Run: run, Logf: logf, Layout: l})
	k := procKernel{a}
	if _, loaded, _ := k.Status(); !loaded {
		return nil
	}
	logf("mtkwifi: removing the %s an earlier run left loaded", rlModName)
	return k.Unload(ctx)
}
