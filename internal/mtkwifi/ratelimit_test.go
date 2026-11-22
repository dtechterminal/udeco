// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// fakeRL is udeco_rl as the agent sees it: loaded or not, the table of
// the last write (entries), its writes, loads and unloads.
type fakeRL struct {
	loaded  bool
	entries int
	version int
	hwnat   string
	loadErr error
	writes  []string
	loads   int
	unloads int
}

func newFakeRL() *fakeRL { return &fakeRL{version: rlVersion, hwnat: "live"} }

func (k *fakeRL) Status() (rlStatus, bool, error) {
	return rlStatus{Version: k.version, Entries: k.entries, HWNAT: k.hwnat}, k.loaded, nil
}

func (k *fakeRL) Load(context.Context) error {
	k.loads++
	if k.loadErr != nil {
		return k.loadErr
	}
	k.loaded, k.entries = true, 0
	return nil
}

func (k *fakeRL) Write(t string) error {
	if !k.loaded {
		return errors.New("no module")
	}
	k.writes = append(k.writes, t)
	k.entries = 0
	for _, l := range strings.Split(t, "\n") {
		if strings.Count(l, ":") == 5 {
			k.entries++
		}
	}
	return nil
}

func (k *fakeRL) Unload(context.Context) error {
	k.unloads++
	k.loaded, k.entries = false, 0
	return nil
}

func (k *fakeRL) last() string {
	if len(k.writes) == 0 {
		return ""
	}
	return k.writes[len(k.writes)-1]
}

const (
	rlSta  = "02:00:00:00:00:a1"
	rlSta2 = "02:00:00:00:00:a2"
)

// rlApplier is newApplier with the limiter on (or off), on k.
func rlApplier(f *fakeDev, k *fakeRL, on bool, now *time.Duration) *Applier {
	return New(Options{Root: f.root, Run: f, RunDir: "/tmp/udeco", StateDir: "/state", Uplink: "eth0.4.1",
		VerifyTimeout: time.Millisecond, sleep: func(context.Context, time.Duration) error { return nil },
		RateLimits: on, rlKern: k, mono: func() time.Duration { return *now }})
}

// rlSnap is a reading with each station on the netdev given.
func rlSnap(at map[string]string) *apstate.Snapshot {
	vaps := map[string]*apstate.Radio{}
	var order []string
	for mac, dev := range at {
		if vaps[dev] == nil {
			vaps[dev] = &apstate.Radio{Iface: dev}
			order = append(order, dev)
		}
		vaps[dev].Stations = append(vaps[dev].Stations, apstate.Station{MAC: strings.ToUpper(mac)})
	}
	r := apstate.Radio{Band: "ng"}
	for _, d := range order {
		r.VAPs = append(r.VAPs, *vaps[d])
	}
	return &apstate.Snapshot{Radios: []apstate.Radio{r}}
}

func rlApply(t *testing.T, a *Applier, d bcmwifi.Desired) bcmwifi.Plan {
	t.Helper()
	p, err := a.Plan(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	return p
}

// A client's own limit: kept before the takeover, loaded and written with
// the apply (a flush with it: hw_nat is live), by MAC on any SSID, nothing
// rewritten while nothing changes, cleared with -1/-1 (an empty list).
func TestClientRatesApplied(t *testing.T) {
	f, k, now := newFakeDev(t), newFakeRL(), time.Duration(1)
	a := rlApplier(f, k, true, &now)
	ctx := context.Background()
	if n, err := a.SetClientRates(ctx, map[string]bcmwifi.RateLimit{strings.ToUpper(rlSta): {DownKbps: 512, UpKbps: 768}, "bad": {DownKbps: 1}}); err != nil || n != 0 {
		t.Fatalf("before the takeover: %d, %v", n, err)
	}
	if k.loads != 0 {
		t.Fatal("module loaded before the agent owns Wi-Fi")
	}
	rlApply(t, a, home())
	if k.loads != 1 || k.last() != rlSta+" 512 768\nflush\n" {
		t.Fatalf("after apply: loads %d, table %q", k.loads, k.last())
	}
	// the station is on whichever SSID: its entry is by MAC
	a.RateStations(ctx, rlSnap(map[string]string{rlSta: "rai1"}))
	a.RateStations(ctx, rlSnap(map[string]string{rlSta: "ra1"}))
	if _, err := a.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(k.writes) != 1 {
		t.Errorf("rewritten without a change: %q", k.writes)
	}
	// down only: up is no longer limited
	if n, _ := a.SetClientRates(ctx, map[string]bcmwifi.RateLimit{rlSta: {DownKbps: 512, UpKbps: -1}}); n != 1 || k.last() != rlSta+" 512 0\nflush\n" {
		t.Errorf("changed: %d, %q", n, k.last())
	}
	// removed: the table empties, no flush (nothing to rebind), module kept
	if n, _ := a.SetClientRates(ctx, nil); n != 1 || k.last() != "clear\n" || !k.loaded {
		t.Errorf("cleared: %d, %q, loaded %v", n, k.last(), k.loaded)
	}
	b, err := os.ReadFile(filepath.Join(f.root, "tmp/udeco", rlRatesFile))
	if err != nil || strings.TrimSpace(string(b)) != "{}" {
		t.Errorf("kept list %q, %v", b, err)
	}
}

// An SSID's limit (its user group) holds for each station associated on
// it; a client's own entry overrides it per direction; leaving the SSID
// (to an unlimited one) drops the SSID's limit, never the client's own.
func TestSSIDRatesFollowStations(t *testing.T) {
	f, k, now := newFakeDev(t), newFakeRL(), time.Duration(1)
	a := rlApplier(f, k, true, &now)
	ctx := context.Background()
	d := home()
	d.SSIDs[0].RateLimit = &bcmwifi.RateLimit{DownKbps: 5000, UpKbps: 1000} // "Example Network": ra0, rai0
	p := rlApply(t, a, d)
	for _, n := range p.Notes {
		if strings.Contains(n, "rate limit") {
			t.Errorf("note with a working limiter: %s", n)
		}
	}
	if k.loads != 0 {
		t.Error("loaded with no station to limit")
	}
	a.SetClientRates(ctx, map[string]bcmwifi.RateLimit{rlSta: {DownKbps: 512}})
	a.RateStations(ctx, rlSnap(map[string]string{rlSta: "rai0", rlSta2: "ra0"}))
	want := rlSta + " 512 1000\n" + rlSta2 + " 5000 1000\nflush\n"
	if k.last() != want {
		t.Fatalf("table %q, want %q", k.last(), want)
	}
	// both move to olive# (no limit): only rlSta's own down limit is left
	a.RateStations(ctx, rlSnap(map[string]string{rlSta: "rai1", rlSta2: "rai1"}))
	if k.last() != rlSta+" 512 0\nflush\n" {
		t.Errorf("after the move: %q", k.last())
	}
	// a station on a netdev the agent does not serve is not taken
	a.RateStations(ctx, rlSnap(map[string]string{rlSta2: "ra3"}))
	if k.entries != 1 {
		t.Errorf("unserved netdev limited: %q", k.last())
	}
	// the SSID's limit removed: the plan applies live; the stations on it
	// are no longer limited at the next sync
	a.RateStations(ctx, rlSnap(map[string]string{rlSta2: "ra0"}))
	if k.entries != 2 {
		t.Fatalf("back on the limited SSID: %q", k.last())
	}
	rlApply(t, a, home())
	if k.last() != rlSta+" 512 0\n" { // only a removal: no flush
		t.Errorf("SSID limit removed: %q", k.last())
	}
}

// An agent restart: the list comes back from RunDir and the table is
// written again once (the module kept it, but this process does not know
// it is the same); a module that lost its table (rmmod/insmod by hand) is
// rewritten at the next Tick.
func TestRatesAcrossRestart(t *testing.T) {
	f, k, now := newFakeDev(t), newFakeRL(), time.Duration(1)
	a := rlApplier(f, k, true, &now)
	ctx := context.Background()
	rlApply(t, a, home())
	a.SetClientRates(ctx, map[string]bcmwifi.RateLimit{rlSta: {DownKbps: 512, UpKbps: 768}})
	n := len(k.writes)
	b := rlApplier(f, k, true, &now)
	// the startup hand-over comes before the first Plan: the module keeps
	// policing what it holds
	b.SetClientRates(ctx, map[string]bcmwifi.RateLimit{rlSta: {DownKbps: 512, UpKbps: 768}})
	if len(k.writes) != n || k.entries != 1 {
		t.Fatalf("startup hand-over touched the module: %q", k.writes[n:])
	}
	if p, _ := b.Plan(ctx, home()); !p.Empty() {
		t.Fatalf("restart plan %+v", p.Steps)
	}
	if _, err := b.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(k.writes) != n+1 || !strings.HasPrefix(k.last(), rlSta+" 512 768\n") || k.loads != 1 {
		t.Errorf("after restart: writes %q, loads %d", k.writes[n:], k.loads)
	}
	k.entries = 0 // the table lost
	b.Tick(ctx)
	if len(k.writes) != n+2 {
		t.Errorf("lost table not rewritten: %q", k.writes[n:])
	}
	b.Tick(ctx)
	if len(k.writes) != n+2 {
		t.Errorf("rewritten again: %q", k.writes[n:])
	}
}

// The hand-back (a rollback to the vendor's Wi-Fi) removes the module;
// the list is kept for the next takeover.
func TestRatesHandBack(t *testing.T) {
	f, k, now := newFakeDev(t), newFakeRL(), time.Duration(1)
	a := rlApplier(f, k, true, &now)
	ctx := context.Background()
	rlApply(t, a, home())
	a.SetClientRates(ctx, map[string]bcmwifi.RateLimit{rlSta: {DownKbps: 512, UpKbps: 768}})
	os.Remove(filepath.Join(f.root, "state", lastGoodFile))
	if err := a.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if k.loaded || k.unloads != 1 {
		t.Errorf("hand-back: loaded %v, unloads %d", k.loaded, k.unloads)
	}
	a.Tick(ctx)
	a.SetClientRates(ctx, map[string]bcmwifi.RateLimit{rlSta: {DownKbps: 256}})
	if k.loaded {
		t.Error("loaded again after the hand-back")
	}
}

// rate_limits off: nothing is loaded, the SSID's limit is noted as before
// (with the reason), logged once, and a module an earlier run left loaded
// is removed.
func TestRatesOff(t *testing.T) {
	f, k, now := newFakeDev(t), newFakeRL(), time.Duration(1)
	k.loaded, k.entries = true, 3
	var logs []string
	a := rlApplier(f, k, false, &now)
	a.o.Logf = func(s string, v ...any) { logs = append(logs, s) }
	ctx := context.Background()
	d := home()
	d.SSIDs[0].RateLimit = &bcmwifi.RateLimit{DownKbps: 5000, UpKbps: 1000}
	p := rlApply(t, a, d)
	if !strings.Contains(strings.Join(p.Notes, "\n"), `SSID "Example Network": per-client rate limit (down 5000, up 1000 kbit/s) not applied (rate_limits is off on this unit)`) {
		t.Errorf("notes %q", p.Notes)
	}
	if k.loaded || k.unloads != 1 {
		t.Errorf("leftover module: loaded %v, unloads %d", k.loaded, k.unloads)
	}
	for range 3 {
		a.SetClientRates(ctx, map[string]bcmwifi.RateLimit{rlSta: {DownKbps: 512}})
	}
	if k.loads != 0 || len(k.writes) != 0 {
		t.Errorf("off: loads %d writes %q", k.loads, k.writes)
	}
	if c := strings.Count(strings.Join(logs, "\n"), "rate_limits is off on this unit"); c != 1 {
		t.Errorf("off logged %d times: %q", c, logs)
	}
}

// A module that does not load: the plan notes it with the reason, it is
// tried again only after rlRetry, and the notes clear once it works.
func TestRatesLoadFailure(t *testing.T) {
	f, k, now := newFakeDev(t), newFakeRL(), time.Duration(1)
	k.loadErr = errors.New("invalid module format")
	a := rlApplier(f, k, true, &now)
	ctx := context.Background()
	d := home()
	d.SSIDs[0].RateLimit = &bcmwifi.RateLimit{DownKbps: 5000, UpKbps: 1000}
	rlApply(t, a, d)
	if _, err := a.SetClientRates(ctx, map[string]bcmwifi.RateLimit{rlSta: {DownKbps: 512}}); err == nil || k.loads != 1 {
		t.Fatalf("load failure: %v, loads %d", err, k.loads)
	}
	if a.RateLimitsHealthy() {
		t.Error("healthy with the module not loaded")
	}
	p, _ := a.Plan(ctx, d)
	if j := strings.Join(p.Notes, "\n"); !strings.Contains(j, "not applied (the station limiter is not working: insmod udeco_rl: invalid module format)") {
		t.Errorf("notes %q", p.Notes)
	}
	a.Tick(ctx)
	if k.loads != 1 {
		t.Errorf("retried within %v: %d loads", rlRetry, k.loads)
	}
	k.loadErr, now = nil, now+rlRetry
	a.Tick(ctx)
	if k.loads != 2 || k.last() != rlSta+" 512 0\nflush\n" || !a.RateLimitsHealthy() {
		t.Errorf("after the retry: loads %d, table %q", k.loads, k.last())
	}
	if p, _ := a.Plan(ctx, d); strings.Contains(strings.Join(p.Notes, "\n"), "rate limit") {
		t.Errorf("notes after recovery %q", p.Notes)
	}
}

// A module of another version is not written to; without hw_nat no flush
// is asked for.
func TestRatesVersionAndNoHWNAT(t *testing.T) {
	f, k, now := newFakeDev(t), newFakeRL(), time.Duration(1)
	k.version = 2
	a := rlApplier(f, k, true, &now)
	rlApply(t, a, home())
	if _, err := a.SetClientRates(context.Background(), map[string]bcmwifi.RateLimit{rlSta: {UpKbps: 768}}); err == nil || len(k.writes) != 0 {
		t.Errorf("version 2 written: %v %q", err, k.writes)
	}
	k.version, k.hwnat = rlVersion, "absent"
	now += rlRetry
	a.Tick(context.Background())
	if k.last() != rlSta+" 0 768\n" {
		t.Errorf("table %q", k.last())
	}
}

func TestParseRLStatus(t *testing.T) {
	st, err := parseRLStatus([]byte("udeco_rl 1 entries=2 hwnat=live untag=1 flush=1 burst_ms=250\n02:00:00:00:00:a1 512 768 1 2 3 4 5 6\n"))
	if err != nil || st.Version != 1 || st.Entries != 2 || st.HWNAT != "live" {
		t.Errorf("%+v %v", st, err)
	}
	for _, bad := range []string{"", "soft_rate_limit 1", "udeco_rl x entries=1"} {
		if _, err := parseRLStatus([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// procKernel on the unit's files: the module is unpacked into RunDir and
// insmod'ed from there; the table goes to /proc/udeco_rl in one write;
// the removal clears the table, then rmmod.
func TestProcKernel(t *testing.T) {
	f := newFakeDev(t)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("\x7fELF module"))
	zw.Close()
	os.MkdirAll(filepath.Join(f.root, "flash2/udeco"), 0o755)
	os.WriteFile(filepath.Join(f.root, DefaultRateModule), gz.Bytes(), 0o644)
	a := New(Options{Root: f.root, Run: f, RunDir: "/tmp/udeco"})
	k := procKernel{a}
	if _, loaded, err := k.Status(); loaded || err != nil {
		t.Fatalf("no module: loaded %v, %v", loaded, err)
	}
	ctx := context.Background()
	if err := k.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(f.root, "tmp/udeco", rlKoFile)); string(b) != "\x7fELF module" {
		t.Errorf("unpacked %q", b)
	}
	if f.log[len(f.log)-1] != "insmod /tmp/udeco/"+rlKoFile {
		t.Errorf("ran %q", f.log)
	}
	proc := filepath.Join(f.root, rlProc)
	os.MkdirAll(filepath.Dir(proc), 0o755)
	os.WriteFile(proc, []byte("udeco_rl 1 entries=0 hwnat=absent\n"), 0o600)
	if st, loaded, err := k.Status(); !loaded || err != nil || st.HWNAT != "absent" {
		t.Errorf("status %+v %v %v", st, loaded, err)
	}
	if err := k.Write(rlSta + " 512 768\n"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(proc); string(b) != rlSta+" 512 768\n" {
		t.Errorf("proc got %q", b)
	}
	var logs []string
	if err := RemoveRateLimiter(ctx, f.root, f, func(s string, v ...any) { logs = append(logs, s) }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(proc); string(b) != "clear\n" || f.log[len(f.log)-1] != "rmmod udeco_rl" || len(logs) != 1 {
		t.Errorf("removal: proc %q, ran %q, logs %q", b, f.log, logs)
	}
	os.Remove(proc)
	n := len(f.log)
	if err := RemoveRateLimiter(ctx, f.root, f, func(string, ...any) {}); err != nil || len(f.log) != n {
		t.Errorf("nothing loaded: ran %q, %v", f.log[n:], err)
	}
}
