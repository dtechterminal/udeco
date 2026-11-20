// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/rf"
)

// ScanPlan shapes one band measurement. DefaultScanPlan returns the design
// constants (§3.2, §3.3, §8); they are not configuration. Every call is
// `wl scan -t passive`, so nothing is ever sent off the home channel; on a
// passive (DFS, "RADAR Sensitive, Passive" in `wl chan_info`) channel the
// chunked call only listens longer (PassiveDwell).
type ScanPlan struct {
	Dwell        time.Duration // passive dwell per channel (`-p`, ms)
	PassiveDwell time.Duration // chunked dwell on a passive (DFS) channel; 0 = Dwell
	Passes       int           // passes over the band (pass 2 reversed)
	HomeGap      time.Duration // minimum time from "scanresults ready" to the next call
	Budget       time.Duration // SCANNING limit for the whole band
	Poll         time.Duration // scanresults poll interval
	CallMax      time.Duration // one -c call: no results by then -> scanabort, STALE
	MinHome      int           // home-record rewrites needed for the home control channel
	StaleReread  time.Duration // second chanim read for a STALE record
	BusyRetry    time.Duration // wait after "Busy" from `wl scan`
	BusyTries    int           // retries after "Busy"
	SweepGap     time.Duration // fallback: home time between sweeps (and before a retry)
	SweepMax     time.Duration // fallback: one sweep's result deadline

	AirtimeMax    float64       // gate: own airtime share above which the band waits
	GateDefer     time.Duration // gate: wait per deferral
	GateTries     int           // gate: deferrals before scanning anyway (0 = no gate)
	BusyHomeGap   time.Duration // gate: HomeGap used after the deferrals ran out
	AirtimeWindow time.Duration // gate fallback: chanim_stats us window

	ClientMinAge time.Duration // client guard: only stations associated this long count
	DropWindow   time.Duration // client guard: a drop this soon after an off-channel call may be scan-caused
	ActiveIdle   time.Duration // client guard: idle at most this long at a call's start = active in it
	MaxChurn     int           // client guard: background drops allowed per band; one more aborts
}

// DefaultScanPlan returns the REV2 constants. Labels: Dwell, CallMax 0.25 s
// worst case [M T3]; Passes, HomeGap, MinHome, gate and client numbers [A].
// PassiveDwell 200 ms is the driver's own passive dwell (`wl -i wl1
// scan_passive_time` = 200 on .205, 2026-11-19 [M]); that it fills the
// chanim record of a DFS channel is [A] (t9_wl1_dfs_in.txt).
func DefaultScanPlan() ScanPlan {
	return ScanPlan{
		Dwell: 110 * time.Millisecond, PassiveDwell: 200 * time.Millisecond, Passes: 2, HomeGap: 400 * time.Millisecond,
		Budget: 45 * time.Second, Poll: 50 * time.Millisecond, CallMax: time.Second,
		MinHome: 4, StaleReread: 100 * time.Millisecond,
		BusyRetry: time.Second, BusyTries: 3,
		SweepGap: 10 * time.Second, SweepMax: 5 * time.Second,
		AirtimeMax: 0.30, GateDefer: 20 * time.Second, GateTries: 3,
		BusyHomeGap: time.Second, AirtimeWindow: 5 * time.Second,
		ClientMinAge: 60 * time.Second, DropWindow: 2 * time.Second,
		ActiveIdle: 2 * time.Second, MaxChurn: 2,
	}
}

// SpectrumPhase is the radio's spectrum state (§7).
type SpectrumPhase string

const (
	PhaseIdle     SpectrumPhase = "idle"
	PhasePending  SpectrumPhase = "pending"  // airtime gate
	PhaseScanning SpectrumPhase = "scanning" // wl scan calls running
)

// Scan modes (§3.2, §3.3).
const (
	ModeChunked = "chunked"
	ModeSweep   = "sweep"
)

// ScanStep describes the `wl scan` call a guard is about to allow.
type ScanStep struct {
	Radio   string
	Mode    string
	Pass    int
	Call    int  // 1-based count of scan calls in this band
	Channel int  // the -c channel; 0 for a whole-band sweep
	Retry   bool // the end-of-pass retry of a STALE channel (or sweep retry)
}

// SpectrumRequest is one band of a quick-scan or of a manual spectrum-scan.
type SpectrumRequest struct {
	Widths    []int     // requested widths (MHz); each is clamped (§6.2); empty = {20}
	OwnBSSIDs []string  // our own BSSIDs, left out of P_bss
	Plan      *ScanPlan // nil = DefaultScanPlan()
	Manual    bool      // a manual spectrum-scan (reported in the status)
	SkipGate  bool      // skip the airtime gate (PENDING)
	Uplink    string    // current uplink interface; a wl vif of this radio skips it
	// Guard, if set, runs before every wl scan call after the built-in
	// checks; an error aborts the band (scanabort, ErrScanAborted).
	Guard func(ctx context.Context, s ScanStep) error
	// OnPhase, if set, is called on every phase change (not under a lock).
	OnPhase func(SpectrumPhase)
}

// SpectrumStatus is the per-radio state the inform needs (§7).
type SpectrumStatus struct {
	Radio, Band string
	Phase       SpectrumPhase
	Manual      bool      // the running (or last) band was a manual scan
	Abnormal    bool      // the last attempt failed or was aborted
	TableTime   time.Time // when the table in Rows was measured; zero = no table
	Rows        map[int][]SpectrumRow
}

// Age is spectrum_table_time: whole seconds since TableTime (0 without a
// table).
func (s SpectrumStatus) Age(now time.Time) int {
	if s.TableTime.IsZero() {
		return 0
	}
	return max(0, int(now.Sub(s.TableTime)/time.Second))
}

// SpectrumResult is what Run returns. Rows is set only on success.
type SpectrumResult struct {
	Radio, Band string
	Rows        map[int][]SpectrumRow // by clamped width
	Status      SpectrumStatus
	Diag        SpectrumDiag
}

// SpectrumDiag explains one band (successful or not), for the log and the
// local diagnostics file (§9).
type SpectrumDiag struct {
	Radio, Band   string
	Mode          string
	Fallback      string // why the radio switched to the sweep ("" = it did not now)
	Widths        []int
	HomeChanspec  string // e.g. "0x1907"
	HomeControl   int
	HomeWidth     int     // MHz of the home chanspec
	HomeNoise     int     // Nhome, dBm
	Baseline      float64 // B, median chanim noise of OK records off the home control channel
	HomeSamples   int     // |H|
	Airtime       float64
	AirtimeSource string
	Defers        int
	HomeGap       time.Duration
	BusyRetries   int
	Started, Done time.Time
	Calls         []CallDiag
	Channels      []ChannelStat
	Unmeasured    []int         // the radio's sticky set after this band
	Passive       []int         // passive (DFS) channels of the band, from `wl chan_info`
	Unheard       []int         // passive channels whose record no call refreshed: unmeasured for this band only
	Omitted       map[int][]int // width -> lowest channels of blocks left out (unmeasured parts)
	BSS           []apstate.BSS // merged neighbours, own BSSIDs left out
	Clients       int           // start set size (associated >= ClientMinAge)
	Drops         []DropDiag
	ChanspecAfter string
	Notes         []string
	Err           string
}

// CallDiag is one wl scan call.
type CallDiag struct {
	Pass, Channel int // Channel 0 = sweep
	Retry         bool
	Class         string // ok, zero, stale, home; "" for a sweep
	HomeRewrite   string // chunked off-channel calls: "ok", "zero", "same"
	BSS           int
	Took          time.Duration // start to scanresults ready
	Err           string
}

// DropDiag is one start-set client that left during the band.
type DropDiag struct {
	OUI        string
	Vif        string
	SinceCall  time.Duration // since the last off-channel call ended (-1: none yet)
	Associated bool          // listed in sta_info at the start of that call
	Idle       time.Duration // its idle time then (-1: unknown)
	TxFailRise bool          // its tx failures rose up to that call's start
	ScanCaused bool          // associated and active in that call, and gone within DropWindow
	Background int           // background drops of the band so far, this one included (0 if scan-caused)
}

// ChannelStat is what one 20 MHz channel measured in the band.
type ChannelStat struct {
	Channel, Freq                    int
	Class                            string // measured, unmeasured, missing
	Home                             bool   // the home control channel
	Samples                          int    // OK records folded in (home: rewrites)
	Zero, Stale                      int    // calls that ended ZERO / STALE (after retry)
	TxDur, Inbss, Obss, Nocat, Nopkt float64
	NoiseMin                         int
	Glitch, BadPLCP                  int     // sums
	PeakBSS                          float64 // P_bss, dBm; 0 = nothing overlaps
	NElev                            float64 // N_elev, dBm; 0 = none
	CtlBSS                           int     // BSSes with their control channel here
	Util, Interference               int     // the row values (measured only)
}

// Errors of Run. ErrIncomplete and ErrNoRows mean nothing was measured that
// can be sent; the old table stays.
var (
	ErrScanAborted       = errors.New("wl: spectrum scan aborted")
	ErrIncomplete        = errors.New("wl: spectrum scan missed channels")
	ErrNoRows            = errors.New("wl: spectrum scan has no row to send")
	ErrChanspecChanged   = errors.New("wl: radio not back on its home chanspec after the scan")
	ErrRadioSkipped      = errors.New("wl: radio not scanned")
	errBusy              = errors.New("wl scan stayed busy")
	errChanimUnparseable = errors.New("wl chanim_stats all: no version line")
)

// incompleteError names the blocks that needed a missing channel.
type incompleteError struct {
	width  int
	blocks []int
}

func (e *incompleteError) Error() string {
	return fmt.Sprintf("%v: %d MHz rows %v need a channel with no fresh record", ErrIncomplete, e.width, e.blocks)
}

func (e *incompleteError) Is(target error) bool { return target == ErrIncomplete }

// SpectrumRunner measures one radio for the controller's nightly `cmd quick-scan` and the
// manual `cmd spectrum-scan` (docs/deco/spectrum-design.md, REV2; section
// "Implementation (build)" at its end).
//
// API
//
//	r, err := col.Spectrum(ctx, "na")        // the runner of the 5 GHz radio
//	res, err := r.Run(ctx, wl.SpectrumRequest{
//		Widths:    []int{80},                   // quick-scan: {scan-bw}; manual: {20, 40, 80}
//		OwnBSSIDs: ourBSSIDs,                   // left out of the neighbour power
//		Uplink:    snap.UplinkName,             // a wl* uplink on this radio skips it
//		OnPhase:   func(p wl.SpectrumPhase) {}, // pending / scanning / idle, for informs
//	})
//	res.Rows[80]     // []SpectrumRow, nine keys each, only on success
//	res.Status       // Phase, Abnormal, TableTime, last good Rows (kept on failure)
//	res.Diag         // per channel classes, calls, BSSes, airtime, drops
//	r.Status()       // the same status at any time; Status().Age(now) in seconds
//	r.ClearTable()   // a manual spectrum-scan clears both radios first (§7)
//	r.RestoreTable(rows, at) // a table saved before an agent restart, into an empty runner
//	r.FitRestored(ctx)       // drops its rows the radio does not list now (after a caps change)
//	col.WithoutScan(ctx, fn) // run fn (health check) when no scan is running
//	wl.NewSpectrumRunner(radio, band, backend) // another driver's runner (spectrum_ext.go)
//
// One runner exists per radio and lives as long as the Collector; it keeps
// the radio's sticky unmeasured channels and its fallback (sweep) mode in
// memory until the agent restarts (§3.2, §3.3). Commands go through the
// Collector's Runner (Options.Run). One scan runs at a time across radios
// (Run and Scan share a lock); a second Run waits for the first or for ctx.
//
// Run, in order: skip checks (wireless uplink, dwds peers: ErrRadioSkipped,
// table and abnormal untouched); PENDING: the airtime gate (§8.1: `wl
// cca_get_stats -c 0 -s 5 -i`, mean ibss of the home control channel, else
// `chanim_stats us` twice with Δwall; above AirtimeMax it waits GateDefer, at
// most GateTries times, then scans with BusyHomeGap); SCANNING: home
// chanspec, `wl noise` and txpwr read once and published to Collect instead
// of live reads, start set of clients, chanim snapshot, then the chunked plan
// (§3.2) or the remembered sweep fallback (§3.3), then the chanspec check
// (§3.4) and the rows (§4-§6). A guard runs before every `wl scan`: ctx,
// Budget, client drop (§8.2: an active start-set client gone right after an
// off-channel call, or more than MaxChurn background drops) and
// SpectrumRequest.Guard; an abort returns ErrScanAborted. A channel a
// requested row needs that is still STALE after its retry ends the band
// early with ErrIncomplete, unless it is passive (DFS, `wl chan_info`): such
// a channel is unheard, unmeasured for this band only, and the band goes
// on. Passive channels get PassiveDwell; every call is `-t passive`. `wl scanabort` is sent only when a `wl scan` of
// ours may still be running (an error or cancel mid-call), never after the
// band stopped between calls, and never after "Busy" (that scan is
// acsd2's). On failure the previous table stays
// in the status, Abnormal becomes true and Rows is nil. The result is never
// nil; when ctx ends while another scan holds the lock, the band never
// starts and Abnormal is left as it was. The returned Rows are the
// caller's (the runner keeps its own copy).
//
// The ctx given to Run must allow the gate (GateTries × GateDefer, 60 s) plus
// the Budget (45 s); the Budget clock starts at SCANNING.
type SpectrumRunner struct {
	c           *Collector      // nil for an external runner
	ext         SpectrumBackend // NewSpectrumRunner: measures instead of c (spectrum_ext.go)
	radio, band string

	mu        sync.Mutex
	phase     SpectrumPhase
	manual    bool
	abnormal  bool
	tableTime time.Time
	rows      map[int][]SpectrumRow
	restored  bool         // rows are a RestoreTable's, not measured here (FitRestored)
	sticky    map[int]bool // unmeasured channels, until restart
	sweep     bool         // fallback mode, until restart
}

// Spectrum returns the runner of the radio on band ("ng" or "na"). The same
// runner is returned on every call.
func (c *Collector) Spectrum(ctx context.Context, band string) (*SpectrumRunner, error) {
	st, err := c.static(ctx)
	if err != nil {
		return nil, err
	}
	radio := ""
	for _, r := range st.radios {
		if r.band == band {
			radio = r.name
		}
	}
	if radio == "" {
		return nil, fmt.Errorf("wl: no radio for band %q", band)
	}
	c.specMu.Lock()
	defer c.specMu.Unlock()
	if c.spec == nil {
		c.spec = map[string]*SpectrumRunner{}
	}
	s := c.spec[radio]
	if s == nil {
		s = &SpectrumRunner{c: c, radio: radio, band: band, phase: PhaseIdle, sticky: map[int]bool{}}
		c.spec[radio] = s
	}
	return s, nil
}

// Radio is the radio's interface name (wl0, wl1).
func (s *SpectrumRunner) Radio() string { return s.radio }

// Status returns the radio's spectrum state. Rows is a copy.
func (s *SpectrumRunner) Status() SpectrumStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SpectrumStatus{Radio: s.radio, Band: s.band, Phase: s.phase, Manual: s.manual,
		Abnormal: s.abnormal, TableTime: s.tableTime, Rows: copyRows(s.rows)}
}

// copyRows copies a table by width (nil stays nil).
func copyRows(rows map[int][]SpectrumRow) map[int][]SpectrumRow {
	if rows == nil {
		return nil
	}
	out := make(map[int][]SpectrumRow, len(rows))
	for w, rs := range rows {
		out[w] = append([]SpectrumRow(nil), rs...)
	}
	return out
}

// ClearTable drops the radio's table (a manual spectrum-scan starts by
// clearing every radio's table, §7). Abnormal is left as it is.
func (s *SpectrumRunner) ClearTable() {
	s.mu.Lock()
	s.rows, s.tableTime, s.restored = nil, time.Time{}, false
	s.mu.Unlock()
}

// RestoreTable puts back a table measured at at before the agent
// restarted (cmd/udeco-ap keeps the last good one per band on flash). It
// goes in only when the runner has no table, so a band measured since (or
// running now and finishing later) wins; Status then reports it as any
// table, with Age counting from at. Abnormal and the phase are left as
// they are. It reports whether the table went in; rows are copied.
func (s *SpectrumRunner) RestoreTable(rows map[int][]SpectrumRow, at time.Time) bool {
	n := 0
	for _, rs := range rows {
		n += len(rs)
	}
	if n == 0 || at.IsZero() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.tableTime.IsZero() || s.rows != nil {
		return false
	}
	s.rows, s.tableTime, s.restored = copyRows(rows), at, true
	return true
}

// FitRestored keeps of a restored table (RestoreTable) only the rows the
// radio lists now: a live band builds its rows from `wl chanspecs` (a block
// per listed chanspec at each width, clamped to the widths listed), so a
// table saved under another country or width cap may hold rows a live one
// never would. A row stays when a listed chanspec of its width has its
// lowest channel and centre frequency. It is meant to run again whenever
// the caps may have changed (they are cached until Invalidate): the table
// stays "restored" until a band or ClearTable replaces it. A table with no
// row left is dropped. A measured table, or none, is not touched (0, 0).
// When the radio lists no 20 MHz channel of its band (caps read mid-change)
// the table is kept and err says so.
func (s *SpectrumRunner) FitRestored(ctx context.Context) (kept, dropped int, err error) {
	s.mu.Lock()
	restored := s.restored
	s.mu.Unlock()
	if !restored {
		return 0, 0, nil
	}
	blocks, err := s.listedBlocks(ctx)
	if err != nil {
		return 0, 0, err
	}
	type key struct{ w, ch, freq int }
	listed := map[key]bool{}
	has20 := false
	for _, bl := range blocks {
		listed[key{bl.Width, bl.Channel, bl.CenterFreq}] = true
		has20 = has20 || bl.Width == 20
	}
	if !has20 {
		if s.ext != nil {
			return 0, 0, errNoListed(s.radio, s.band)
		}
		return 0, 0, fmt.Errorf("wl -i %s: no %s channel listed", s.radio, s.band)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.restored { // a band or a clear replaced it meanwhile
		return 0, 0, nil
	}
	out := map[int][]SpectrumRow{}
	for w, rs := range s.rows {
		for _, r := range rs {
			if r.Width == w && listed[key{w, r.Channel, r.CenterFreq}] {
				out[w] = append(out[w], r)
				kept++
			} else {
				dropped++
			}
		}
	}
	switch {
	case kept == 0:
		s.rows, s.tableTime, s.restored = nil, time.Time{}, false
	case dropped > 0:
		s.rows = out
	}
	return kept, dropped, nil
}

func (s *SpectrumRunner) isSticky(ch int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sticky[ch]
}

func (s *SpectrumRunner) addSticky(ch int) {
	s.mu.Lock()
	s.sticky[ch] = true
	s.mu.Unlock()
}

func (s *SpectrumRunner) stickyList() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []int
	for ch := range s.sticky {
		out = append(out, ch)
	}
	sort.Ints(out)
	return out
}

func (s *SpectrumRunner) sweepMode() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweep
}

func (s *SpectrumRunner) setPhase(p SpectrumPhase, manual bool, cb func(SpectrumPhase)) {
	s.mu.Lock()
	s.phase, s.manual = p, manual
	s.mu.Unlock()
	if cb != nil {
		cb(p)
	}
}

// Run measures the radio's band once and builds rows at the requested
// widths. See the package section above for the sequence and the errors.
func (s *SpectrumRunner) Run(ctx context.Context, req SpectrumRequest) (*SpectrumResult, error) {
	if s.ext != nil {
		return s.runExt(ctx, req)
	}
	plan := DefaultScanPlan()
	if req.Plan != nil {
		plan = *req.Plan
	}
	c := s.c
	if err := c.scanMu.LockCtx(ctx); err != nil {
		// another scan held the lock until ctx ended: the band never
		// started, so the table and abnormal are left as they are (§7
		// "skipped: already in progress"); the result is still non-nil
		d := SpectrumDiag{Radio: s.radio, Band: s.band, Started: c.now(), Done: c.now(),
			Err: fmt.Sprintf("waiting for a running scan: %v", err)}
		return &SpectrumResult{Radio: s.radio, Band: s.band, Status: s.Status(), Diag: d}, err
	}
	defer c.scanMu.Unlock()

	b := &bandRun{c: c, s: s, req: req, plan: plan, radio: s.radio, band: s.band,
		own: map[string]bool{}, acc: map[int]*chanAcc{}, bss: map[string]apstate.BSS{}, unheard: map[int]bool{},
		diag: &SpectrumDiag{Radio: s.radio, Band: s.band, Started: c.now(), HomeGap: plan.HomeGap}}
	for _, m := range req.OwnBSSIDs {
		b.own[strings.ToLower(m)] = true
	}
	rows, err := b.run(ctx)
	d := b.diag
	d.Done = c.now()
	d.Unmeasured = s.stickyList()
	d.Unheard = sortedKeys(b.unheard)
	if err != nil {
		d.Err = err.Error()
	}

	s.finish(rows, d.Done, err, req.OnPhase)
	return &SpectrumResult{Radio: s.radio, Band: s.band, Rows: rows, Status: s.Status(), Diag: *d}, err
}

// finish ends a band: idle; on success the new table (measured at done),
// abnormal cleared; on a failure other than a skipped radio, abnormal set
// and the old table kept.
func (s *SpectrumRunner) finish(rows map[int][]SpectrumRow, done time.Time, err error, onPhase func(SpectrumPhase)) {
	s.mu.Lock()
	s.phase = PhaseIdle
	switch {
	case err == nil:
		// the runner keeps its own copy: the caller owns the returned rows
		s.rows, s.tableTime, s.abnormal, s.restored = copyRows(rows), done, false, false
	case !errors.Is(err, ErrRadioSkipped):
		s.abnormal = true
	}
	s.mu.Unlock()
	if onPhase != nil {
		onPhase(PhaseIdle)
	}
}

// chanAcc collects one 20 MHz channel's calls in a band.
type chanAcc struct {
	called, ok  int // passes that called it / ended OK
	zero, stale int
	missing     bool
	recs        []chanimRecord // OK records
}

// bandRun is one Run in progress.
type bandRun struct {
	c    *Collector
	s    *SpectrumRunner
	req  SpectrumRequest
	plan ScanPlan

	radio, band string
	specs       []chanspec
	chans       []int // 20 MHz channels, ascending
	home        chanspec
	ctl         int          // home control channel c_h
	passive     map[int]bool // passive (DFS) channels: longer dwell; STALE after retry = unheard
	unheard     map[int]bool // passive channels left unmeasured in this band (not sticky)
	nhome       float64
	own         map[string]bool
	homeGap     time.Duration
	mode        string

	start     time.Time // SCANNING start (Budget)
	snap      map[int]chanimRecord
	acc       map[int]*chanAcc
	homeRecs  []chanimRecord // H
	bss       map[string]apstate.BSS
	clients   map[string]string // start set: MAC -> vif
	vifs      []string
	churn     int                // background drops so far (§8.2)
	offSta    map[string]staSeen // start-set activity read at the start of the last off-channel call
	prevSta   map[string]staSeen // the read before that one
	lastOff   time.Time          // last off-channel call's results ready
	lastReady time.Time          // last call's results ready
	inFlight  bool               // a `wl scan` of ours may be running (scanabort on error)
	calls     int
	diag      *SpectrumDiag
}

// staSeen is a start-set station's activity as `wl sta_info all` showed it.
type staSeen struct {
	idle   time.Duration
	txFail int64
}

func (b *bandRun) note(format string, a ...any) {
	b.diag.Notes = append(b.diag.Notes, fmt.Sprintf(format, a...))
}

func (b *bandRun) run(ctx context.Context) (map[int][]SpectrumRow, error) {
	c := b.c
	st, err := c.static(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range st.radios {
		if r.name == b.radio {
			b.specs = r.specs
		}
	}
	for _, bl := range blocksFor(b.specs, b.band, 20) {
		b.chans = append(b.chans, bl.Center)
	}
	if len(b.chans) == 0 {
		return nil, fmt.Errorf("wl -i %s: no 20 MHz channels listed", b.radio)
	}
	if err := b.passiveChannels(ctx); err != nil {
		return nil, err
	}
	avail := radioWidths(b.specs, b.band)
	seen := map[int]bool{}
	reqW := b.req.Widths
	if len(reqW) == 0 {
		reqW = []int{20}
	}
	for _, w := range reqW {
		if cw := clampWidth(w, avail); !seen[cw] {
			seen[cw] = true
			b.diag.Widths = append(b.diag.Widths, cw)
		}
	}
	sort.Ints(b.diag.Widths)

	if err := b.skipCheck(ctx); err != nil {
		return nil, err
	}
	b.homeGap = b.plan.HomeGap
	if !b.req.SkipGate && b.plan.GateTries > 0 {
		b.s.setPhase(PhasePending, b.req.Manual, b.req.OnPhase)
		if err := b.gate(ctx); err != nil {
			return nil, err
		}
	}
	if err := b.register(ctx); err != nil {
		return nil, err
	}
	b.s.setPhase(PhaseScanning, b.req.Manual, b.req.OnPhase)
	rows, err := b.measure(ctx)
	if cerr := b.deregister(ctx); cerr != nil && err == nil {
		rows, err = nil, cerr
	}
	return rows, err
}

// skipCheck is §8.4 and the dwds note of §8.2: a radio that carries the
// uplink, or whose dwds (backhaul) vif has peers, is not scanned.
func (b *bandRun) skipCheck(ctx context.Context) error {
	up := b.req.Uplink
	if up == b.radio {
		return fmt.Errorf("%w: %s is the uplink", ErrRadioSkipped, up)
	}
	if m := vifName.FindStringSubmatch(up); m != nil && m[1] == b.radio {
		return fmt.Errorf("%w: uplink %s is on %s", ErrRadioSkipped, up, b.radio)
	}
	devs, err := b.c.netDevs()
	if err != nil {
		return err
	}
	for _, d := range devs {
		if m := vifName.FindStringSubmatch(d); m == nil || m[1] != b.radio {
			continue
		}
		out, err := b.c.wl(ctx, d, "bss")
		if err != nil || strings.TrimSpace(string(out)) != "up" {
			continue
		}
		out, err = b.c.wl(ctx, d, "dwds")
		if n, _ := parseInt(out); err != nil || n == 0 {
			continue
		}
		out, err = b.c.wl(ctx, d, "assoclist")
		if err == nil && len(parseAssoclist(out)) > 0 {
			return fmt.Errorf("%w: backhaul vif %s has peers", ErrRadioSkipped, d)
		}
	}
	return ctx.Err()
}

// parseAssoclist reads `wl assoclist` ("assoclist 8C:BF:EA:1D:BA:74" per
// line) into lower-case MACs.
func parseAssoclist(b []byte) []string {
	var out []string
	for line := range strings.Lines(string(b)) {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "assoclist" {
			if mac, err := netParseMAC(f[1]); err == nil {
				out = append(out, mac)
			}
		}
	}
	return out
}

// gate is PENDING (§8.1).
func (b *bandRun) gate(ctx context.Context) error {
	c := b.c
	out, err := c.wl(ctx, b.radio, "chanspec")
	if err != nil {
		return err
	}
	cs, ok := parseChanspecHex(string(out))
	if !ok {
		return fmt.Errorf("wl -i %s chanspec: cannot parse %q", b.radio, firstLine(string(out)))
	}
	for range b.plan.GateTries {
		own, src, err := c.OwnAirtime(ctx, b.radio, cs.Control, b.plan.AirtimeWindow)
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("%w: %v", ErrScanAborted, ctx.Err())
			}
			if b.diag.Defers == 0 {
				b.note("airtime gate: %v; scanning without it", err)
				return nil
			}
			// it already saw the load: keep the slower plan (§8.1)
			b.note("airtime gate: %v after a deferral", err)
			break
		}
		b.diag.Airtime, b.diag.AirtimeSource = own, src
		if own <= b.plan.AirtimeMax {
			return nil
		}
		b.diag.Defers++
		if err := c.sleep(ctx, b.plan.GateDefer); err != nil {
			return fmt.Errorf("%w: %v", ErrScanAborted, err)
		}
	}
	b.homeGap = max(b.plan.HomeGap, b.plan.BusyHomeGap)
	b.diag.HomeGap = b.homeGap
	b.note("own airtime above %.0f %% after %d deferrals: home gap %v", 100*b.plan.AirtimeMax, b.diag.Defers, b.homeGap)
	return nil
}

// OwnAirtime is our own airtime share (0..1) on the radio's home control
// channel (§8.1, REV2): the mean ibss % of `wl cca_get_stats -c 0 -s 5 -i`
// for homeControl; when that fails or has no row for it, (Δtx + Δinbss) /
// Δwall between two `chanim_stats us` reads window apart (0 = 5 s). src
// names the source used.
func (c *Collector) OwnAirtime(ctx context.Context, radio string, homeControl int, window time.Duration) (own float64, src string, err error) {
	out, err := c.wl(ctx, radio, "cca_get_stats", "-c", "0", "-s", "5", "-i")
	if err == nil {
		if v, ok := ownFromCCA(out, homeControl); ok {
			return v, "cca_get_stats", nil
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, "", err
	}
	if window <= 0 {
		window = 5 * time.Second
	}
	read := func() (chanimRow, time.Time, error) {
		out, err := c.wl(ctx, radio, "chanim_stats", "us")
		if err != nil {
			return chanimRow{}, time.Time{}, err
		}
		row, ok := parseChanimUs(out)
		if !ok {
			return chanimRow{}, time.Time{}, fmt.Errorf("wl -i %s chanim_stats us: no row", radio)
		}
		return row, c.now(), nil
	}
	a, ta, err := read()
	if err != nil {
		return 0, "", err
	}
	if err := c.sleep(ctx, window); err != nil {
		return 0, "", err
	}
	z, tz, err := read()
	if err != nil {
		return 0, "", err
	}
	wall := tz.Sub(ta).Microseconds()
	if z.Key != a.Key || wall <= 0 {
		return 0, "", fmt.Errorf("wl -i %s chanim_stats us: channel changed or no time passed", radio)
	}
	d := (z.Tx - a.Tx) + (z.Inbss - a.Inbss) // modular u64
	return min(1, float64(d)/float64(wall)), "chanim_stats us", nil
}

// bandSnap is what Collect reports for a radio while a band runs on it,
// read at band start (§8.7: `wl chanspec` shows the scan channel mid-call).
type bandSnap struct {
	chanspec, noise, txpwr []byte
}

// register reads the home chanspec, noise and power once and publishes them
// to Collect for the band's duration.
func (b *bandRun) register(ctx context.Context) error {
	c := b.c
	c.bandMu.Lock()
	defer c.bandMu.Unlock()
	out, err := c.wl(ctx, b.radio, "chanspec")
	if err != nil {
		return err
	}
	cs, ok := parseChanspecHex(string(out))
	if !ok || cs.Band != b.band {
		return fmt.Errorf("wl -i %s chanspec: cannot use %q for band %s", b.radio, firstLine(string(out)), b.band)
	}
	nout, err := c.wl(ctx, b.radio, "noise")
	if err != nil {
		return err
	}
	n, ok := parseInt(nout)
	if !ok {
		return fmt.Errorf("wl -i %s noise: cannot parse %q", b.radio, firstLine(string(nout)))
	}
	tx, _ := c.wl(ctx, b.radio, "txpwr_target_max")
	b.home, b.ctl, b.nhome = cs, cs.Control, float64(n)
	b.diag.HomeChanspec = fmt.Sprintf("0x%04x", cs.Raw)
	b.diag.HomeControl, b.diag.HomeWidth, b.diag.HomeNoise = cs.Control, cs.Width, int(n)
	c.publishBand(b.radio, &bandSnap{chanspec: out, noise: nout, txpwr: tx})
	return nil
}

// publishBand makes Collect report snap for radio (bandMu held).
func (c *Collector) publishBand(radio string, snap *bandSnap) {
	if c.bands == nil {
		c.bands = map[string]*bandSnap{}
	}
	c.bands[radio] = snap
}

// holdCurrent is register for the legacy Scan: it reads the radio's
// chanspec, noise and power before the scan and has Collect report them
// until releaseCurrent.
func (c *Collector) holdCurrent(ctx context.Context, radio string) error {
	c.bandMu.Lock()
	defer c.bandMu.Unlock()
	out, err := c.wl(ctx, radio, "chanspec")
	if err != nil {
		return err
	}
	if _, ok := parseChanspecHex(string(out)); !ok {
		return fmt.Errorf("wl -i %s chanspec: cannot parse %q", radio, firstLine(string(out)))
	}
	snap := &bandSnap{chanspec: out}
	if nout, err := c.wl(ctx, radio, "noise"); err == nil {
		snap.noise = nout
	}
	if tx, err := c.wl(ctx, radio, "txpwr_target_max"); err == nil {
		snap.txpwr = tx
	}
	c.publishBand(radio, snap)
	return nil
}

// releaseCurrent ends holdCurrent.
func (c *Collector) releaseCurrent(radio string) {
	c.bandMu.Lock()
	delete(c.bands, radio)
	c.bandMu.Unlock()
}

// deregister is §3.4: after the last call's results (or scanabort) the radio
// must be on the chanspec read at band start.
func (b *bandRun) deregister(ctx context.Context) error {
	c := b.c
	c.bandMu.Lock()
	defer c.bandMu.Unlock()
	delete(c.bands, b.radio)
	out, err := c.wl(context.WithoutCancel(ctx), b.radio, "chanspec")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrChanspecChanged, err)
	}
	cs, ok := parseChanspecHex(string(out))
	b.diag.ChanspecAfter = firstLine(string(out))
	if !ok || cs.Raw != b.home.Raw {
		return fmt.Errorf("%w: %s, was 0x%04x", ErrChanspecChanged, firstLine(string(out)), b.home.Raw)
	}
	return nil
}

// readCurrent reads what Collect reports about a radio's current channel:
// `wl chanspec`, `noise`, `txpwr_target_max` and `chanim_stats us`. While a
// spectrum band runs on the radio it returns the values read at band start
// and no chanim row (the survey is left unchanged), so an inform never shows
// the scan channel. The band lock is held across the reads, so a band cannot
// start in the middle of them.
func (c *Collector) readCurrent(ctx context.Context, radio string) radioCurrent {
	c.bandMu.Lock()
	defer c.bandMu.Unlock()
	if b := c.bands[radio]; b != nil {
		return radioCurrent{chanspec: b.chanspec, noise: b.noise, txpwr: b.txpwr, inBand: true}
	}
	var rc radioCurrent
	if rc.chanspec, rc.chanspecErr = c.wl(ctx, radio, "chanspec"); rc.chanspecErr != nil {
		return rc
	}
	if out, err := c.wl(ctx, radio, "noise"); err == nil {
		rc.noise = out
	}
	if out, err := c.wl(ctx, radio, "txpwr_target_max"); err == nil {
		rc.txpwr = out
	}
	if out, err := c.wl(ctx, radio, "chanim_stats", "us"); err == nil {
		if row, ok := parseChanimUs(out); ok {
			// stamp the row when it was read, not when the collection
			// began: earlier calls (the other radio, slow or timed-out
			// getters) must not skew the wall-clock plausibility check
			rc.us, rc.haveUs, rc.usAt = row, true, c.now()
		}
	}
	return rc
}

// radioCurrent is the result of readCurrent. nil noise/txpwr = not read.
type radioCurrent struct {
	chanspec     []byte
	chanspecErr  error
	noise, txpwr []byte
	us           chanimRow
	haveUs       bool
	usAt         time.Time
	inBand       bool
}

// WithoutScan runs fn while no scan (Scan or a spectrum band) runs, for
// reads that must not overlap one (§8.7 health check). It waits for a
// running scan or for ctx.
func (c *Collector) WithoutScan(ctx context.Context, fn func(context.Context) error) error {
	if err := c.scanMu.LockCtx(ctx); err != nil {
		return err
	}
	defer c.scanMu.Unlock()
	return fn(ctx)
}

// measure is SCANNING after register: the calls, then the rows.
func (b *bandRun) measure(ctx context.Context) (map[int][]SpectrumRow, error) {
	if err := b.scan(ctx); err != nil {
		return nil, err
	}
	return b.build()
}

// scan runs the band's calls. On an error while a `wl scan` of ours may
// still be running (started and not yet answered, or killed half way) it
// sends `wl scanabort` so the radio is home at once (§8.6). It sends none
// when the band stops between calls (guard, budget, a missing channel) or
// when `wl scan` stayed "Busy": that scan is someone else's (acsd2).
func (b *bandRun) scan(ctx context.Context) (err error) {
	c := b.c
	b.start = c.now()
	ctx, cancel := context.WithTimeout(ctx, b.plan.Budget+c.opt.CallTimeout) // backstop for the clock check
	defer cancel()
	defer func() {
		if err == nil {
			return
		}
		if ctx.Err() != nil && !errors.Is(err, ErrScanAborted) {
			err = fmt.Errorf("%w: %v", ErrScanAborted, err)
		}
		if b.inFlight {
			b.scanAbort(ctx)
		}
	}()
	if err := b.startClients(ctx); err != nil {
		return err
	}
	if b.snap, err = b.readChanim(ctx); err != nil {
		return err
	}
	b.mode = ModeChunked
	if b.s.sweepMode() {
		b.mode = ModeSweep
	}
	if b.mode == ModeChunked {
		reason, err := b.chunked(ctx)
		if err != nil {
			return err
		}
		if reason != "" {
			b.s.mu.Lock()
			b.s.sweep = true
			b.s.mu.Unlock()
			b.diag.Fallback, b.mode = reason, ModeSweep
			b.acc, b.homeRecs = map[int]*chanAcc{}, nil
		}
	}
	b.diag.Mode = b.mode
	if b.mode == ModeSweep {
		return b.sweepAll(ctx)
	}
	return nil
}

// scanAbort sends `wl scanabort` (ignoring ctx cancellation); our scan is
// no longer in flight afterwards.
func (b *bandRun) scanAbort(ctx context.Context) {
	b.inFlight = false
	if _, err := b.c.wl(context.WithoutCancel(ctx), b.radio, "scanabort"); err != nil {
		b.note("scanabort: %v", err)
	}
}

// startClients takes the start set of §8.2: stations of the radio's user
// vifs associated for at least ClientMinAge.
func (b *bandRun) startClients(ctx context.Context) error {
	c := b.c
	devs, err := c.netDevs()
	if err != nil {
		return err
	}
	c.mu.Lock()
	vaps, err := c.userVAPs(ctx, b.radio, devs, c.now())
	c.mu.Unlock()
	if err != nil {
		return err
	}
	b.clients = map[string]string{}
	for _, v := range vaps {
		out, err := c.wl(ctx, v.name, "sta_info", "all")
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			b.note("client guard: %v", err)
			continue
		}
		b.vifs = append(b.vifs, v.name)
		for _, st := range parseStaInfoAll(out) {
			if time.Duration(st.Connected)*time.Second >= b.plan.ClientMinAge {
				b.clients[st.MAC] = v.name
			}
		}
	}
	b.diag.Clients = len(b.clients)
	return nil
}

// guard runs before every wl scan call.
func (b *bandRun) guard(ctx context.Context, step ScanStep) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrScanAborted, err)
	}
	if b.c.now().Sub(b.start) >= b.plan.Budget {
		return fmt.Errorf("%w: budget %v spent", ErrScanAborted, b.plan.Budget)
	}
	off := step.Mode == ModeSweep || step.Channel != b.ctl
	if err := b.checkClients(ctx, off); err != nil {
		return err
	}
	if b.req.Guard != nil {
		if err := b.req.Guard(ctx, step); err != nil {
			return fmt.Errorf("%w: %v", ErrScanAborted, err)
		}
	}
	return nil
}

// checkClients is the client-drop rule of §8.2 (scan-safety review). Before
// every call the start set (stations associated for at least ClientMinAge
// when the band began; a station that joins later is never judged) is looked
// up in the vifs' assoclists. A start-set station that is gone is:
//   - scan-caused when it was listed in `sta_info all` at the start of the
//     last off-channel call, was active then (idle at most ActiveIdle, or
//     its tx failures rising since the read before), and left at most
//     DropWindow after that call: the band aborts at once;
//   - background churn otherwise (an idle IoT device on its own timer): up
//     to MaxChurn per band are allowed, one more aborts.
//
// A vif whose assoclist cannot be read is not judged this time. Before an
// off-channel call (off) the remaining start set's activity is read.
func (b *bandRun) checkClients(ctx context.Context, off bool) error {
	if len(b.clients) == 0 {
		return nil
	}
	present, judged := map[string]bool{}, map[string]bool{}
	for _, v := range b.vifs {
		out, err := b.c.wl(ctx, v, "assoclist")
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("%w: %v", ErrScanAborted, ctx.Err())
			}
			b.note("client guard: %v", err)
			continue
		}
		judged[v] = true
		for _, m := range parseAssoclist(out) {
			present[m] = true
		}
	}
	macs := make([]string, 0, len(b.clients))
	for m := range b.clients {
		macs = append(macs, m)
	}
	sort.Strings(macs)
	now := b.c.now()
	for _, m := range macs {
		vif := b.clients[m]
		if present[m] || !judged[vif] {
			continue
		}
		delete(b.clients, m)
		dd := DropDiag{OUI: m[:min(8, len(m))], Vif: vif, SinceCall: -1, Idle: -1}
		if !b.lastOff.IsZero() {
			dd.SinceCall = now.Sub(b.lastOff)
			if st, ok := b.offSta[m]; ok {
				dd.Associated, dd.Idle = true, st.idle
				if p, ok := b.prevSta[m]; ok && st.txFail > p.txFail {
					dd.TxFailRise = true
				}
				active := st.idle <= b.plan.ActiveIdle || dd.TxFailRise
				dd.ScanCaused = active && dd.SinceCall <= b.plan.DropWindow
			}
		}
		if dd.ScanCaused {
			b.diag.Drops = append(b.diag.Drops, dd)
			return fmt.Errorf("%w: client %s left %s %v after an off-channel call it was active in (idle %v at its start)",
				ErrScanAborted, dd.OUI, vif, dd.SinceCall, dd.Idle)
		}
		b.churn++
		dd.Background = b.churn
		b.diag.Drops = append(b.diag.Drops, dd)
		if b.churn > b.plan.MaxChurn {
			return fmt.Errorf("%w: %d start-set clients left during the band (more than %d background drops)",
				ErrScanAborted, b.churn, b.plan.MaxChurn)
		}
	}
	if off && len(b.clients) > 0 {
		return b.readActivity(ctx)
	}
	return nil
}

// readActivity reads `wl sta_info all` on the vifs that still have
// start-set clients: their idle time and tx failures at the start of the
// off-channel call about to run. A vif that cannot be read leaves its
// clients out of this read (a drop after the call is then background).
func (b *bandRun) readActivity(ctx context.Context) error {
	want := map[string]bool{}
	for _, v := range b.clients {
		want[v] = true
	}
	seen := map[string]staSeen{}
	for _, v := range b.vifs {
		if !want[v] {
			continue
		}
		out, err := b.c.wl(ctx, v, "sta_info", "all")
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("%w: %v", ErrScanAborted, ctx.Err())
			}
			b.note("client guard: %v", err)
			continue
		}
		for _, st := range parseStaInfoAll(out) {
			if b.clients[st.MAC] == v {
				seen[st.MAC] = staSeen{idle: time.Duration(st.Inactive) * time.Millisecond, txFail: st.TxFailed}
			}
		}
	}
	b.prevSta, b.offSta = b.offSta, seen
	return nil
}

// waitHome keeps at least the home gap between "results ready" and the
// next call (§3.2 step 6).
func (b *bandRun) waitHome(ctx context.Context) error {
	if b.lastReady.IsZero() {
		return nil
	}
	if d := b.homeGap - b.c.now().Sub(b.lastReady); d > 0 {
		if err := b.c.sleep(ctx, d); err != nil {
			return fmt.Errorf("%w: %v", ErrScanAborted, err)
		}
	}
	return nil
}

// busyError is `wl scan` still busy after the retries.
type busyError struct{ err error }

func (e *busyError) Error() string { return fmt.Sprintf("%v: %v", errBusy, e.err) }
func (e *busyError) Unwrap() error { return errBusy }

// wlAnswered reports whether a failed wl call is wl's own answer (it ran and
// exited non-zero), as opposed to a call killed at its timeout or cancelled
// (ExecRunner says "signal: killed"; Collector.wl adds the deadline) or one
// that never started (fork/exec). Only an answer can mean "this firmware
// rejects the -c syntax" (§3.3 fallback trigger).
func wlAnswered(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.Exited()
	}
	var pe *fs.PathError
	return !errors.As(err, &pe)
}

// startScan runs `wl scan args`, retrying "Busy" (§3.2 step 2).
//
// From the moment `wl scan` is run until its results are read (or scanabort
// is sent) the scan counts as in flight. An answer from wl itself (non-zero
// exit, Busy included) means no scan of ours started; a call killed at its
// timeout or by ctx may have started one, so it stays in flight.
func (b *bandRun) startScan(ctx context.Context, args []string) error {
	for try := 0; ; try++ {
		b.inFlight = true
		_, err := b.c.wl(ctx, b.radio, args...)
		if err == nil {
			return nil
		}
		if wlAnswered(err) {
			b.inFlight = false
		}
		if ctx.Err() != nil {
			return fmt.Errorf("%w: %v", ErrScanAborted, ctx.Err())
		}
		if !errContains(err, "Busy") {
			return err
		}
		if try >= b.plan.BusyTries {
			return &busyError{err}
		}
		b.diag.BusyRetries++
		if err := b.c.sleep(ctx, b.plan.BusyRetry); err != nil {
			return fmt.Errorf("%w: %v", ErrScanAborted, err)
		}
	}
}

// poll waits for `wl scanresults` (§3.2 step 3). ready is false when limit
// passed first; scanabort has then been sent. "Not Found" after the call's
// dwell counts as done with no BSS.
func (b *bandRun) poll(ctx context.Context, limit, dwell time.Duration) (out []byte, ready bool, err error) {
	c := b.c
	t0 := c.now()
	for {
		if err := c.sleep(ctx, b.plan.Poll); err != nil {
			return nil, false, fmt.Errorf("%w: %v", ErrScanAborted, err)
		}
		out, err := c.wl(ctx, b.radio, "scanresults")
		if err == nil {
			b.inFlight = false
			return out, true, nil
		}
		if ctx.Err() != nil {
			return nil, false, fmt.Errorf("%w: %v", ErrScanAborted, ctx.Err())
		}
		el := c.now().Sub(t0)
		if errContains(err, "Not Found") && el >= dwell {
			b.inFlight = false
			return nil, true, nil
		}
		if !errContains(err, "Not Ready", "Busy", "Not Found") {
			return nil, false, err
		}
		if el >= limit {
			b.scanAbort(ctx)
			return nil, false, nil
		}
	}
}

func (b *bandRun) readChanim(ctx context.Context) (map[int]chanimRecord, error) {
	out, err := b.c.wl(ctx, b.radio, "chanim_stats", "all")
	if err != nil {
		return nil, err
	}
	recs, ok := parseChanimRecords(out, b.band)
	if !ok {
		return nil, fmt.Errorf("wl -i %s: %w", b.radio, errChanimUnparseable)
	}
	return recs, nil
}

// mergeBSS folds a scanresults text into the band's neighbour list (by
// BSSID, strongest RSSI, own BSSIDs left out). It returns how many BSSes the
// text held.
func (b *bandRun) mergeBSS(out []byte) int {
	list := parseScanResults(out, b.band)
	for _, x := range list {
		k := strings.ToLower(x.BSSID)
		if b.own[k] {
			continue
		}
		if old, ok := b.bss[k]; !ok || x.Signal > old.Signal {
			b.bss[k] = x
		}
	}
	return len(list)
}

func (b *bandRun) accFor(ch int) *chanAcc {
	a := b.acc[ch]
	if a == nil {
		a = &chanAcc{}
		b.acc[ch] = a
	}
	return a
}

// record books one pass's final verdict for a channel.
func (b *bandRun) record(ch int, cls recordClass, r chanimRecord) {
	if cls == classHome {
		return
	}
	a := b.accFor(ch)
	a.called++
	switch cls {
	case classOK:
		a.ok++
		a.recs = append(a.recs, r)
	case classZero:
		a.zero++
		b.s.addSticky(ch)
	case classStale:
		a.stale++
		a.missing = true
	case classUnheard:
		a.stale++
		b.unheard[ch] = true
	}
}

// unmeasured reports whether ch has no row in this band: sticky (ZERO) or
// a passive channel no call refreshed (unheard).
func (b *bandRun) unmeasured(ch int) bool { return b.unheard[ch] || b.s.isSticky(ch) }

// passiveChannels reads the band's passive (DFS) channels from `wl
// chan_info` (a getter: "Channel 52\t5G Band, RADAR Sensitive, Passive").
// When it cannot be read or lists none of the band's channels, 5 GHz 52-144
// count as passive, as caps.DFS does.
func (b *bandRun) passiveChannels(ctx context.Context) error {
	b.passive = map[int]bool{}
	out, err := b.c.wl(ctx, b.radio, "chan_info")
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("%w: %v", ErrScanAborted, cerr)
	}
	info, ok := parseChanInfo(out, b.band)
	if err != nil || !ok {
		if err != nil {
			b.note("chan_info: %v; 52-144 taken as passive", err)
		}
		for _, ch := range b.chans {
			if rf.IsDFS(b.band, ch) {
				b.passive[ch] = true
			}
		}
	} else {
		for _, ch := range b.chans {
			if info[ch] {
				b.passive[ch] = true
			}
		}
	}
	b.diag.Passive = sortedKeys(b.passive)
	return nil
}

// dwell is the -p of a chunked call on ch.
func (b *bandRun) dwell(ch int) time.Duration {
	if b.passive[ch] && b.plan.PassiveDwell > 0 {
		return b.plan.PassiveDwell
	}
	return b.plan.Dwell
}

// unheardAfterRetry turns a passive channel's STALE after its retry into
// classUnheard: a DFS channel whose chanim record our passive call did not
// rewrite (.205 under IN, 2026-11-19: 56 kept cca_obss 1, glitch 0 across
// both calls) is not measured, and it stops nothing else. Its blocks get no
// row in this band, like UNII-3; the next band tries it again.
func (b *bandRun) unheardAfterRetry(ch int, cls recordClass) recordClass {
	if cls != classStale || !b.passive[ch] {
		return cls
	}
	b.note("passive channel %d not refreshed after its retry: unmeasured in this band", ch)
	return classUnheard
}

// chunked is §3.2. A non-empty reason means "switch to the sweep".
func (b *bandRun) chunked(ctx context.Context) (reason string, err error) {
	for pass := 1; pass <= b.plan.Passes; pass++ {
		order := make([]int, 0, len(b.chans))
		for i := range b.chans {
			ch := b.chans[i]
			if pass%2 == 0 {
				ch = b.chans[len(b.chans)-1-i]
			}
			if pass > 1 && b.unmeasured(ch) {
				continue
			}
			order = append(order, ch)
		}
		final := map[int]recordClass{}
		var retry []int
		for _, ch := range order {
			cls, r, fb, err := b.callOne(ctx, pass, ch, false)
			if err != nil || fb != "" {
				return fb, err
			}
			if cls == classStale {
				retry = append(retry, ch)
				continue
			}
			final[ch] = cls
			b.record(ch, cls, r)
		}
		trigger := func() string {
			if pass != 1 {
				return ""
			}
			if decided, fire, first := staleTrigger(order, b.ctl, final); decided && fire {
				return fmt.Sprintf("chunked records not refreshed: channels %d and %d stale after retry", first[0], first[1])
			}
			return ""
		}
		if fb := trigger(); fb != "" {
			return fb, nil
		}
		for _, ch := range retry {
			cls, r, fb, err := b.callOne(ctx, pass, ch, true)
			if err != nil || fb != "" {
				return fb, err
			}
			cls = b.unheardAfterRetry(ch, cls)
			final[ch] = cls
			b.record(ch, cls, r)
			if fb := trigger(); fb != "" {
				return fb, nil
			}
			if err := b.stopIfMissing(pass, order, final); err != nil {
				return "", err
			}
		}
	}
	return "", nil
}

// stopIfMissing ends the band early (no further calls, no scanabort: no
// call is running) once a channel a requested row needs is STALE after its
// retry: that row can no longer be built and the band would fail anyway
// with ErrIncomplete. In pass 1 it waits until the §3.3 fallback trigger is
// decided, since the sweep would measure the channel again.
func (b *bandRun) stopIfMissing(pass int, order []int, final map[int]recordClass) error {
	if pass == 1 {
		if decided, fire, _ := staleTrigger(order, b.ctl, final); !decided || fire {
			return nil
		}
	}
	for _, ch := range order {
		if final[ch] != classStale {
			continue
		}
		for _, w := range b.diag.Widths {
			var need []int
			for _, bl := range blocksFor(b.specs, b.band, w) {
				if slices.Contains(bl.Parts, ch) && !slices.ContainsFunc(bl.Parts, b.unmeasured) {
					need = append(need, bl.Parts[0])
				}
			}
			if len(need) > 0 {
				b.note("channel %d still stale after its retry in pass %d: band stopped early", ch, pass)
				return &incompleteError{width: w, blocks: need}
			}
		}
	}
	return nil
}

// staleTrigger evaluates the §3.3 fallback trigger on pass 1's final
// verdicts so far: the first two channels in call order other than c_h whose
// records are not ZERO both ended STALE after their retry. decided is false
// while one of them (or a channel before them) still waits for its retry.
func staleTrigger(order []int, ctl int, final map[int]recordClass) (decided, fire bool, first []int) {
	for _, ch := range order {
		if ch == ctl {
			continue
		}
		cls, ok := final[ch]
		if !ok {
			return false, false, nil
		}
		if cls == classZero || cls == classUnheard {
			continue
		}
		first = append(first, ch)
		if len(first) == 2 {
			return true, final[first[0]] == classStale && final[first[1]] == classStale, first
		}
	}
	return true, false, first
}

// callOne is one chunked call (§3.2 steps 1-6) for channel ch.
func (b *bandRun) callOne(ctx context.Context, pass, ch int, retry bool) (cls recordClass, rec chanimRecord, fallback string, err error) {
	c := b.c
	if err := b.waitHome(ctx); err != nil {
		return "", rec, "", err
	}
	b.calls++
	if err := b.guard(ctx, ScanStep{Radio: b.radio, Mode: ModeChunked, Pass: pass, Call: b.calls, Channel: ch, Retry: retry}); err != nil {
		return "", rec, "", err
	}
	cd := CallDiag{Pass: pass, Channel: ch, Retry: retry}
	defer func() { b.diag.Calls = append(b.diag.Calls, cd) }()
	t0 := c.now()
	dwell := b.dwell(ch)
	args := []string{"scan", "-t", "passive", "-p", strconv.Itoa(int(dwell / time.Millisecond)), "-c", strconv.Itoa(ch)}
	if err := b.startScan(ctx, args); err != nil {
		cd.Err = err.Error()
		var be *busyError
		switch {
		case errors.As(err, &be), errors.Is(err, ErrScanAborted):
			return "", rec, "", err
		case !wlAnswered(err):
			// killed at the call timeout or never started: not wl
			// rejecting -c (§3.3), and a killed call may have started a
			// scan, so the band ends here (scanabort follows)
			return "", rec, "", err
		case ch != b.ctl:
			return "", rec, fmt.Sprintf("wl scan -c %d failed: %v", ch, err), nil
		default:
			b.note("home control call -c %d: %v", ch, err)
			cd.Class = string(classHome)
			return classHome, rec, "", nil
		}
	}
	out, ready, err := b.poll(ctx, b.plan.CallMax, dwell)
	if err != nil {
		cd.Err = err.Error()
		return "", rec, "", err
	}
	b.lastReady = c.now()
	cd.Took = b.lastReady.Sub(t0)
	if ch != b.ctl {
		b.lastOff = b.lastReady
	}
	if ready {
		cd.BSS = b.mergeBSS(out)
	}
	after, err := b.readChanim(ctx)
	if err != nil {
		return "", rec, "", err
	}
	if ch == b.ctl {
		// its own call never writes a record and never leaves the
		// channel [M T8]: kept for its BSS list only
		b.snap = after
		cd.Class = string(classHome)
		return classHome, rec, "", nil
	}
	r0, had := b.snap[ch]
	r, has := after[ch]
	cls = classStale
	if ready {
		cls = classifyRecord(r0, r, had, has)
		if cls == classStale {
			if err := c.sleep(ctx, b.plan.StaleReread); err != nil {
				return "", rec, "", fmt.Errorf("%w: %v", ErrScanAborted, err)
			}
			if after, err = b.readChanim(ctx); err != nil {
				return "", rec, "", err
			}
			r, has = after[ch]
			cls = classifyRecord(r0, r, had, has)
		}
		// home rewrite (§3.2 step 4): never evidence for c itself
		h, hok := after[b.ctl]
		h0, hhad := b.snap[b.ctl]
		switch {
		case !hok:
		case hhad && h.same(h0):
			cd.HomeRewrite = "same"
		case h.zero():
			cd.HomeRewrite = string(classZero)
		default:
			cd.HomeRewrite = string(classOK)
			b.homeRecs = append(b.homeRecs, h)
		}
	}
	b.snap = after
	cd.Class = string(cls)
	return cls, r, "", nil
}

// sweepAll is the fallback of §3.3: whole-band passive sweeps, Passes of
// them SweepGap apart, each retried once for its STALE channels.
func (b *bandRun) sweepAll(ctx context.Context) error {
	for pass := 1; pass <= b.plan.Passes; pass++ {
		if pass > 1 {
			if err := b.sweepPause(ctx); err != nil {
				return err
			}
		}
		res, err := b.sweepOnce(ctx, pass, false, b.chans)
		if err != nil {
			return err
		}
		var stale []int
		for _, ch := range b.chans {
			if res[ch].cls == classStale {
				stale = append(stale, ch)
			}
		}
		if len(stale) > 0 {
			if err := b.sweepPause(ctx); err != nil {
				return err
			}
			again, err := b.sweepOnce(ctx, pass, true, stale)
			if err != nil {
				return err
			}
			for _, ch := range stale {
				v := again[ch]
				v.cls = b.unheardAfterRetry(ch, v.cls)
				res[ch] = v
			}
		}
		for _, ch := range b.chans {
			b.record(ch, res[ch].cls, res[ch].rec)
		}
	}
	return nil
}

// sweepPause is the home time between sweeps (SweepGap). The client guard
// runs HomeGap into it, as it does between chunked calls: a start-set
// station the last sweep cut off is judged within DropWindow of it. Judged
// only at the next sweep's guard, SweepGap later, every drop would count as
// background churn, so up to MaxChurn active clients could be cut off by
// the sweeps without the band stopping.
func (b *bandRun) sweepPause(ctx context.Context) error {
	first := min(b.homeGap, b.plan.SweepGap)
	if err := b.c.sleep(ctx, first); err != nil {
		return fmt.Errorf("%w: %v", ErrScanAborted, err)
	}
	if err := b.checkClients(ctx, false); err != nil {
		return err
	}
	if err := b.c.sleep(ctx, b.plan.SweepGap-first); err != nil {
		return fmt.Errorf("%w: %v", ErrScanAborted, err)
	}
	return nil
}

type sweepVerdict struct {
	cls recordClass
	rec chanimRecord
}

// sweepOnce runs one whole-band sweep and classifies chans against the
// snapshot before it. In a sweep the home control record is refreshed like
// any other (T1), so it is classified normally.
func (b *bandRun) sweepOnce(ctx context.Context, pass int, retry bool, chans []int) (map[int]sweepVerdict, error) {
	c := b.c
	if err := b.waitHome(ctx); err != nil {
		return nil, err
	}
	b.calls++
	if err := b.guard(ctx, ScanStep{Radio: b.radio, Mode: ModeSweep, Pass: pass, Call: b.calls, Retry: retry}); err != nil {
		return nil, err
	}
	cd := CallDiag{Pass: pass, Retry: retry}
	defer func() { b.diag.Calls = append(b.diag.Calls, cd) }()
	t0 := c.now()
	if err := b.startScan(ctx, []string{"scan", "-t", "passive", "-p", strconv.Itoa(int(b.plan.Dwell / time.Millisecond))}); err != nil {
		cd.Err = err.Error()
		return nil, err
	}
	out, ready, err := b.poll(ctx, b.plan.SweepMax, b.plan.Dwell)
	if err != nil {
		cd.Err = err.Error()
		return nil, err
	}
	b.lastReady = c.now()
	b.lastOff = b.lastReady
	cd.Took = b.lastReady.Sub(t0)
	if ready {
		cd.BSS = b.mergeBSS(out)
	}
	after, err := b.readChanim(ctx)
	if err != nil {
		return nil, err
	}
	res := map[int]sweepVerdict{}
	for _, ch := range chans {
		r0, had := b.snap[ch]
		r, has := after[ch]
		v := sweepVerdict{cls: classStale, rec: r}
		if ready {
			v.cls = classifyRecord(r0, r, had, has)
		}
		res[ch] = v
	}
	b.snap = after
	return res, nil
}

// build turns the band's records into ChannelStats and rows (§3.2 classes,
// §4, §5, §6).
func (b *bandRun) build() (map[int][]SpectrumRow, error) {
	d := b.diag
	homeChunked := b.mode == ModeChunked
	d.HomeSamples = len(b.homeRecs)

	var noises []float64
	for ch, a := range b.acc {
		if ch == b.ctl {
			continue
		}
		for _, r := range a.recs {
			noises = append(noises, float64(r.Noise))
		}
	}
	base, haveBase := median(noises)
	d.Baseline = base

	bss := make([]apstate.BSS, 0, len(b.bss))
	for _, x := range b.bss {
		bss = append(bss, x)
	}
	sort.Slice(bss, func(i, j int) bool { return bss[i].BSSID < bss[j].BSSID })
	d.BSS = bss

	vals := map[int]chanValue{}
	for _, ch := range b.chans {
		st := ChannelStat{Channel: ch, Freq: chanFreq(ch, b.band), Home: ch == b.ctl}
		a := b.acc[ch]
		if a == nil {
			a = &chanAcc{}
		}
		recs := a.recs
		st.Zero, st.Stale = a.zero, a.stale
		switch {
		case b.unmeasured(ch):
			st.Class = ClassUnmeasured
		case ch == b.ctl && homeChunked:
			recs = b.homeRecs
			st.Class = ClassMissing
			if len(recs) >= b.plan.MinHome {
				st.Class = ClassMeasured
			}
		case a.called == 0 || a.missing || a.ok < a.called:
			st.Class = ClassMissing
		default:
			st.Class = ClassMeasured
		}
		st.Samples = len(recs)
		if len(recs) > 0 {
			st.NoiseMin = recs[0].Noise
			for _, r := range recs {
				st.TxDur += float64(r.TxDur)
				st.Inbss += float64(r.Inbss)
				st.Obss += float64(r.Obss)
				st.Nocat += float64(r.Nocat)
				st.Nopkt += float64(r.Nopkt)
				st.NoiseMin = min(st.NoiseMin, r.Noise)
				st.Glitch += r.Glitch
				st.BadPLCP += r.BadPLCP
			}
			n := float64(len(recs))
			st.TxDur, st.Inbss, st.Obss, st.Nocat, st.Nopkt = st.TxDur/n, st.Inbss/n, st.Obss/n, st.Nocat/n, st.Nopkt/n
		}
		pb, havePB, nctl := peakBSS(bss, ch, b.band)
		ne, haveNE := elevatedNoise(recs, ch == b.ctl, b.nhome, base, haveBase)
		st.CtlBSS = nctl
		if havePB {
			st.PeakBSS = pb
		}
		if haveNE {
			st.NElev = ne
		}
		v := chanValue{Class: st.Class}
		if st.Class == ClassMeasured {
			v.Util, _ = meanUtil(recs)
			v.Interf = interferenceDBm(b.nhome, pb, havePB, ne, haveNE)
			st.Util, st.Interference = v.Util, v.Interf
		}
		vals[ch] = v
		d.Channels = append(d.Channels, st)
	}

	rows := map[int][]SpectrumRow{}
	for _, w := range d.Widths {
		rs, omitted, err := buildRows(vals, blocksFor(b.specs, b.band, w), b.band)
		if len(omitted) > 0 {
			if d.Omitted == nil {
				d.Omitted = map[int][]int{}
			}
			d.Omitted[w] = omitted
		}
		if err != nil {
			return nil, err
		}
		rows[w] = rs
	}
	return rows, nil
}

// ctxMutex is a mutex whose Lock can give up when a context ends. The zero
// value is unlocked.
type ctxMutex struct {
	once sync.Once
	ch   chan struct{}
}

func (m *ctxMutex) init() { m.once.Do(func() { m.ch = make(chan struct{}, 1) }) }

// Lock waits for the mutex.
func (m *ctxMutex) Lock() { m.init(); m.ch <- struct{}{} }

// LockCtx waits for the mutex or for ctx.
func (m *ctxMutex) LockCtx(ctx context.Context) error {
	m.init()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case m.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Unlock releases the mutex.
func (m *ctxMutex) Unlock() { <-m.ch }
