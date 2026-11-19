// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

// Spectrum on the MT7603 (2.4 GHz, ra0, mt7603eap.ko): the off-channel
// sweep, behind a wl.SpectrumRunner (wl.NewSpectrumRunner), so that the
// agent runs the controller's quick-scan and spectrum-scan, reports
// spectrum_table and keeps the table on flash exactly as on the Deco.
//
// The mechanism (Ghidra of mt7603eap.ko, and a live test on the unit
// 2026-11-20 with the mtkprobe tool; docs/deco/spectrum-design.md "MT7603
// off-channel sweep"):
//
//   - `iwpriv ra0 set ApOffChanScan=passive:<ch>:<ms>` takes the radio to
//     channel ch for one dwell of ms (u8, 10 ms timer) and back to its own
//     channel. It never changes the operating channel or restarts the AP
//     (live: the radio stayed on channel 6; a client pinged through a
//     13-visit sweep at 100 ms). ApSiteSurveyNew_by_wdev prints, at any
//     debug level, "ApSiteSurveyNew_by_wdev channel_index:<i> channel:<ch>
//     time:<ms>" when the visit starts; ScanNextChannel prints "SYNC - End
//     of SCAN, restore to <bw>MHz channel <home>, ..." when it is back, at
//     debug level 3 and up (the unit runs at the vendor's level: the live
//     test saw it on every visit). A channel off the driver's list is
//     refused by ChannelSanity: no visit and no start line.
//   - At the end of the dwell UpdateChannelInfo reads MIB 0x2c048 "Prim CCA
//     Time" (read-clear, 24 bits, µs) and stores score = max(0, 100 -
//     busy/4000) with the channel in the slot of the channel's list index.
//     The counter runs from its last read, so it is cleared (`show
//     mibinfo`, the only reader; it also prints ~40 lines to the kernel log
//     and clears the other MIB counters) right before each visit, or the
//     home channel's time since the last read is counted with the visit's.
//     Live: the pre-clear came ~1.2 ms before the request, and the slot's
//     busy time matched the driver's own debug print within 2.4 ms on four
//     channels (ch1 24 ms, ch6 40, ch10 44-46, ch11 68-70 of 200).
//   - OID 0x2014 (OID_802_11_GET_ACS_CHANNEL_SCORE) answers 444 bytes: u32
//     LE {score, channel} by list index, then AutoChannelAlg at u32 110.
//     Slots are not reset between visits (an earlier visit's value stays),
//     a slot never filled reads channel 0, and slots past the list are
//     uninitialised heap. Set-OID 0x8999 (OID_802_11_CHANNELINFO) copies
//     the channel list as 28-byte records {channel, index, ..., dfs at
//     0x18}, as many bytes as asked (the stack buffer is 1680). UNVERIFIED
//     live: when it fails or answers no list, the sweep uses 1..11 (the
//     unit's list: 12 and 13 are refused) plus whatever 0x2014 names at its
//     own index.
//   - Every visit runs BssTableInit, clearing the driver's neighbour table:
//     the neighbour survey runs after the sweep.
//
// One band: under the collector's scan lock (one sweep, site survey or
// survey read at a time), read the radio's channel (iwconfig) and width
// (profile HT_BW) and the channel list, then one visit per channel, one
// visit start every Every (1 s, so about 11 s for the band); before each
// visit the guard (the agent's scanBlock: observe mode, an apply or
// rollback, a TP-Link hold) and the restart gate (DriverRead, held for the
// visit only: an apply waits at most one visit) are checked, and the radio
// must be up; any of them stops the band (old table kept, abnormal). Each
// visit: kernel log read, pre-clear, the request, Dwell + Settle (250 ms),
// kernel log read, slot read. The visit is trusted only when the log added
// since the first read (anchored, newLogAnchored) holds exactly one start
// line of this radio, for this channel with this dwell, and then one end
// line back on the home channel, and the start line's slot names the
// channel. With a start and no end within EndWait more, the radio's state
// is unknown and the band stops; an end on another channel stops it too
// (wl.ErrChanspecChanged). A visit not trusted otherwise (another scan's
// lines, a slot from an earlier visit) is retried once after the last
// channel; still not trusted, the channel is missing and the band fails
// (wl.ErrIncomplete). A refused channel (anchored log, no line at all) is
// unmeasured: no row, nor any 40 MHz block containing it.
//
// Then the fresh site survey of the radio (freshSurvey, as Scan), whose
// neighbours give the interference and refresh scan_table, and a last
// iwconfig: the radio must still be on its channel. The collector's
// busy-time reading skips the interval that held the sweep (mibGap: the
// pre-clears stole the MIB counter), and Collect keeps its last reading
// while the band runs (scanning).
//
// Rows (as the Deco's, spectrum-design §4-§6): utilization = busy / dwell
// in % (busy = (100 - score) × 4 ms, so 2 % steps at 200 ms; off the home
// channel it is other networks' use; on the home channel the radio is in
// scan mode, beacons stopped, but our own clients may still send);
// interference = clamp(max(-95, strongest neighbour level on the channel
// from the survey, our own BSSIDs left out)), -95 standing in for the
// noise floor the driver does not give (Collect reports the same);
// interference_type [], other_bss_count, perf_index, total_samples 0. A
// 40 MHz row (lowest channel c, centre c+2, for every c whose c+4 is
// listed) is the max of its two 20 MHz channels' values, as the Deco's
// (§5): only 20 MHz visits are made.
//
// The MT7663 (5 GHz, rai0, in the kernel) has no ApOffChanScan: its band
// has no runner (RadioDef.Spectrum ""), and its spectrum commands keep the
// neighbour survey (SpectrumBySurvey). A 5 GHz backend would be another
// spectrumBackend kind behind the same runner.

// SpectrumOffChan is RadioDef.Spectrum for the MT7603's off-channel sweep.
const SpectrumOffChan = "offchan"

// ModeOffChan is wl.SpectrumDiag.Mode of the off-channel sweep.
const ModeOffChan = "offchan"

// offChanPlan is the sweep's timing (constants, not configuration).
type offChanPlan struct {
	Dwell   time.Duration // ApOffChanScan's dwell (10..255 ms)
	Settle  time.Duration // after the dwell, before the log and the slot are read
	EndWait time.Duration // more time for a late end line before the band stops
	EndPoll time.Duration // kernel-log re-read interval while waiting for it
	Every   time.Duration // from one visit's start to the next
	Budget  time.Duration // the whole band (sweep and survey)
}

// defaultOffChanPlan: the live test's 200 ms dwell and dwell + 250 ms
// wait; a visit a second.
var defaultOffChanPlan = offChanPlan{Dwell: 200 * time.Millisecond, Settle: 250 * time.Millisecond,
	EndWait: 2 * time.Second, EndPoll: 100 * time.Millisecond, Every: time.Second, Budget: time.Minute}

const (
	oidACSScore = 0x2014 // OID_802_11_GET_ACS_CHANNEL_SCORE
	oidChanInfo = 0x0999 // OID_802_11_CHANNELINFO (with oidSet)
	scoreBuf    = 512    // the driver copies 444 bytes whatever the length
	scoreSlots  = 55     // {score, channel} pairs in the 444 bytes
	chanRec     = 28     // one channel record of OID 0x8999
	chanBuf     = 16 * chanRec
	busyStep    = 4000 // µs per score point
	noiseFloor  = -95  // dBm: the stand-in noise floor (no driver reading)
)

// offChan is the MT7603 sweep of one radio.
type offChan struct {
	c  *Collector
	rd RadioDef

	mu    sync.Mutex
	chans []int  // the channel list last read (nil: read it again)
	src   string // where it came from
}

// newOffChan returns the radio's backend.
func newOffChan(c *Collector, rd RadioDef) *offChan { return &offChan{c: c, rd: rd} }

func (b *offChan) main() string { return b.rd.Ifaces[0] }

func (b *offChan) plan() offChanPlan {
	if b.c.o.offChan != nil {
		return *b.c.o.offChan
	}
	return defaultOffChanPlan
}

// widths are the row widths of the radio.
func (b *offChan) widths() []int {
	if b.rd.Band == "ng" {
		return []int{20, 40}
	}
	return []int{20, 40, 80}
}

// forget drops the cached channel list (Invalidate: after an apply).
func (b *offChan) forget() {
	b.mu.Lock()
	b.chans, b.src = nil, ""
	b.mu.Unlock()
}

// channels is the radio's channel list: OID 0x8999, else the fallback
// (fallbackChans). The caller holds the restart gate.
func (b *offChan) channels(p privIO) ([]int, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.chans != nil {
		return b.chans, b.src
	}
	buf := make([]byte, chanBuf)
	if err := p.OID(b.main(), oidChanInfo|oidSet, buf); err == nil {
		if l, ok := parseChanList(buf, b.rd.Band); ok {
			b.chans, b.src = l, "the driver's channel list"
			return b.chans, b.src
		}
	}
	sb := make([]byte, scoreBuf)
	if err := p.OID(b.main(), oidACSScore, sb); err != nil {
		sb = nil
	}
	b.chans, b.src = fallbackChans(sb, b.rd.Band), "1..11 and the score slots (no channel list from the driver)"
	return b.chans, b.src
}

// inBand: channel ch belongs to band (the other radio's driver prints the
// same lines for its own scans).
func inBand(ch int, band string) bool {
	if band == "ng" {
		return ch >= 1 && ch <= 14
	}
	return ch >= 32
}

// parseChanList reads OID 0x8999's records: channel at 0, list index at 1;
// the list ends at the first channel 0. ok only for a list of the band in
// order (index i at record i, channels ascending).
func parseChanList(b []byte, band string) ([]int, bool) {
	var out []int
	for i := 0; (i+1)*chanRec <= len(b); i++ {
		ch, idx := int(b[i*chanRec]), int(b[i*chanRec+1])
		if ch == 0 {
			break
		}
		if idx != i || !inBand(ch, band) || (len(out) > 0 && ch <= out[len(out)-1]) {
			return nil, false
		}
		out = append(out, ch)
	}
	return out, len(out) > 0
}

// fallbackChans is the 2.4 GHz list without OID 0x8999: 1..11 (the unit's
// country list), and every channel a score slot names at its own index
// (slot i holds list[i], and 2.4 GHz lists run 1, 2, ...: ch i+1 at i).
func fallbackChans(scores []byte, band string) []int {
	if band != "ng" {
		return nil
	}
	set := map[int]bool{}
	for _, ch := range chans24 {
		set[ch] = true
	}
	for i, s := range parseScores(scores) {
		if s.ch == i+1 && inBand(s.ch, band) {
			set[s.ch] = true
		}
	}
	out := make([]int, 0, len(set))
	for ch := range set {
		out = append(out, ch)
	}
	slices.Sort(out)
	return out
}

// slot is one {score, channel} pair of OID 0x2014.
type slot struct{ score, ch int }

// parseScores reads OID 0x2014's pairs (nil buffer: none).
func parseScores(b []byte) []slot {
	var out []slot
	for i := 0; i < scoreSlots && 8*i+8 <= len(b); i++ {
		out = append(out, slot{score: int(int32(binary.LittleEndian.Uint32(b[8*i:]))), ch: int(binary.LittleEndian.Uint32(b[8*i+4:]))})
	}
	return out
}

var (
	visitStart = regexp.MustCompile(`ApSiteSurveyNew_by_wdev channel_index:(\d+) channel:(\d+) time:(\d+)`)
	visitEnd   = regexp.MustCompile(`SYNC - End of SCAN, restore to \d+MHz channel (\d+)`)
)

// visitLog is what one visit's kernel-log lines say (of this radio's
// band only).
type visitLog struct {
	starts     int   // start lines for the channel
	others     int   // start lines for other channels of the band
	idx, ms    int   // the channel's (last) start line: list index, dwell
	ends       int   // end lines after the last start line of the band
	endsBefore int   // end lines of the band before it
	restore    []int // the channels the ends after it name
	any        bool  // any start or end line of the band
}

// parseVisitLog reads the lines a visit to ch added to the kernel log.
func parseVisitLog(log, band string, ch int) visitLog {
	v := visitLog{idx: -1}
	last := -1
	for _, m := range visitStart.FindAllStringSubmatchIndex(log, -1) {
		c, _ := strconv.Atoi(log[m[4]:m[5]])
		if !inBand(c, band) {
			continue
		}
		v.any, last = true, m[1]
		if c != ch {
			v.others++
			continue
		}
		v.starts++
		v.idx, _ = strconv.Atoi(log[m[2]:m[3]])
		v.ms, _ = strconv.Atoi(log[m[6]:m[7]])
	}
	for _, m := range visitEnd.FindAllStringSubmatchIndex(log, -1) {
		c, _ := strconv.Atoi(log[m[2]:m[3]])
		if !inBand(c, band) {
			continue
		}
		v.any = true
		if last >= 0 && m[0] > last {
			v.ends++
			v.restore = append(v.restore, c)
		} else {
			v.endsBefore++
		}
	}
	return v
}

// visit classes (wl.CallDiag.Class)
const (
	visitOK          = "ok"
	visitRefused     = "refused"     // no visit: off the driver's list
	visitUnconfirmed = "unconfirmed" // not trusted: retried, then missing
)

// visitResult is one visit.
type visitResult struct {
	class string
	busy  int    // µs over the dwell (visitOK)
	why   string // visitUnconfirmed
}

var errNoEnd = errors.New("mtkwifi: no \"End of SCAN\" line after an off-channel visit: the radio's return to its channel is not confirmed")

// homeOK: the end line's channel is the radio's own: its control channel,
// or at 40 MHz the centre the driver restores to (control ± 2).
func homeOK(restore, home, width int) bool {
	return restore == home || (width == 40 && (restore == home-2 || restore == home+2))
}

// visit makes one off-channel visit to ch (see the top of the file).
func (b *offChan) visit(ctx context.Context, p privIO, ch, home, width int, pl offChanPlan) (visitResult, error) {
	c := b.c
	main := b.main()
	done, ok := c.driverRead()
	if !ok {
		return visitResult{}, ErrRadioRestart
	}
	defer done()
	if !c.isUp(main) {
		return visitResult{}, ErrRadioDown
	}
	before, err := c.o.klog()
	if err != nil {
		return visitResult{}, fmt.Errorf("mtkwifi: kernel log: %w", err)
	}
	ms := int(pl.Dwell / time.Millisecond)
	if err := p.Show(main, "mibinfo"); err != nil {
		return visitResult{}, fmt.Errorf("mtkwifi: %s show mibinfo (pre-clear): %w", main, err)
	}
	if err := p.Set(main, fmt.Sprintf("ApOffChanScan=passive:%d:%d", ch, ms)); err != nil {
		return visitResult{}, fmt.Errorf("mtkwifi: %s set ApOffChanScan %d: %w", main, ch, err)
	}
	if err := c.o.sleep(ctx, pl.Dwell+pl.Settle); err != nil {
		// the visit runs on in the driver: let it end before the lock goes
		c.o.sleep(context.Background(), pl.EndWait)
		return visitResult{}, err
	}
	read := func() (visitLog, bool, error) {
		after, err := c.o.klog()
		if err != nil {
			return visitLog{}, false, fmt.Errorf("mtkwifi: kernel log: %w", err)
		}
		added, anchored := newLogAnchored(string(before), string(after))
		return parseVisitLog(added, b.rd.Band, ch), anchored, nil
	}
	v, anchored, err := read()
	if err != nil {
		return visitResult{}, err
	}
	if !anchored {
		// the ring wrapped past the anchor: nothing in the log can be
		// placed; give a visit that may run time to end
		c.o.sleep(ctx, pl.EndWait)
		return visitResult{class: visitUnconfirmed, why: "kernel log not anchored"}, nil
	}
	if !v.any {
		return visitResult{class: visitRefused}, nil
	}
	for waited := time.Duration(0); v.ends == 0 && waited < pl.EndWait; waited += pl.EndPoll {
		if err := c.o.sleep(ctx, pl.EndPoll); err != nil {
			return visitResult{}, err
		}
		if v, _, err = read(); err != nil {
			return visitResult{}, err
		}
	}
	if v.ends == 0 {
		return visitResult{}, fmt.Errorf("%w (channel %d)", errNoEnd, ch)
	}
	for _, r := range v.restore {
		if !homeOK(r, home, width) {
			return visitResult{}, fmt.Errorf("%w: back on channel %d after the visit to %d, not %d", wl.ErrChanspecChanged, r, ch, home)
		}
	}
	switch {
	case v.starts != 1 || v.others > 0 || v.ends != 1 || v.endsBefore > 0:
		return visitResult{class: visitUnconfirmed, why: fmt.Sprintf("%d start(s) for it, %d for others, %d end(s), %d earlier end(s)",
			v.starts, v.others, v.ends, v.endsBefore)}, nil
	case v.ms != ms:
		return visitResult{class: visitUnconfirmed, why: fmt.Sprintf("dwell %d ms, asked %d", v.ms, ms)}, nil
	}
	buf := make([]byte, scoreBuf)
	if err := p.OID(main, oidACSScore, buf); err != nil {
		return visitResult{}, fmt.Errorf("mtkwifi: %s OID 0x2014: %w", main, err)
	}
	slots := parseScores(buf)
	if v.idx < 0 || v.idx >= len(slots) || slots[v.idx].ch != ch || slots[v.idx].score < 0 || slots[v.idx].score > 100 {
		return visitResult{class: visitUnconfirmed, why: fmt.Sprintf("slot %d does not hold channel %d", v.idx, ch)}, nil
	}
	return visitResult{class: visitOK, busy: (100 - slots[v.idx].score) * busyStep}, nil
}

// homeChannel reads the radio's channel (iwconfig) and width (profile
// HT_BW) under the restart gate.
func (b *offChan) homeChannel(ctx context.Context) (home, width int, err error) {
	c := b.c
	done, ok := c.driverRead()
	if !ok {
		return 0, 0, ErrRadioRestart
	}
	defer done()
	if !c.isUp(b.main()) {
		return 0, 0, ErrRadioDown
	}
	out, err := c.o.Run.Run(ctx, "iwconfig", b.main())
	if err != nil {
		return 0, 0, fmt.Errorf("iwconfig %s: %w", b.main(), err)
	}
	m := chanRE.FindSubmatch(out)
	if m == nil {
		return 0, 0, fmt.Errorf("iwconfig %s: no channel", b.main())
	}
	home, _ = strconv.Atoi(string(m[1]))
	if home <= 0 {
		return 0, 0, fmt.Errorf("iwconfig %s: channel %d", b.main(), home)
	}
	return home, c.radioWidth(b.rd), nil
}

// listOf reads the channel list under the restart gate.
func (b *offChan) listOf(p privIO) ([]int, string, error) {
	done, ok := b.c.driverRead()
	if !ok {
		return nil, "", ErrRadioRestart
	}
	defer done()
	l, src := b.channels(p)
	return l, src, nil
}

// Measure implements wl.SpectrumBackend (see the top of the file).
func (b *offChan) Measure(ctx context.Context, req wl.SpectrumRequest, phase func(wl.SpectrumPhase)) (map[int][]wl.SpectrumRow, wl.SpectrumDiag, error) {
	c := b.c
	main, band := b.main(), b.rd.Band
	pl := b.plan()
	d := wl.SpectrumDiag{Mode: ModeOffChan, Started: c.o.now()}
	seen := map[int]bool{}
	reqW := req.Widths
	if len(reqW) == 0 {
		reqW = []int{20}
	}
	for _, w := range reqW {
		if cw := wl.ClampWidth(w, b.widths()); !seen[cw] {
			seen[cw] = true
			d.Widths = append(d.Widths, cw)
		}
	}
	slices.Sort(d.Widths)
	fail := func(err error) (map[int][]wl.SpectrumRow, wl.SpectrumDiag, error) {
		d.Done = c.o.now()
		return nil, d, err
	}
	if err := c.lockScan(ctx); err != nil {
		return fail(fmt.Errorf("waiting for a running scan: %w", err))
	}
	defer c.unlockScan()
	start := c.o.now()
	home, width, err := b.homeChannel(ctx)
	if err != nil {
		return fail(err)
	}
	d.HomeControl, d.HomeWidth, d.HomeNoise = home, width, noiseFloor
	open := c.o.priv
	if open == nil {
		open = openPriv
	}
	p, err := open()
	if err != nil {
		return fail(fmt.Errorf("mtkwifi: driver ioctls: %w", err))
	}
	defer p.Close()
	chans, src, err := b.listOf(p)
	if err != nil {
		return fail(err)
	}
	d.Notes = append(d.Notes, "channels from "+src)

	c.scanning.Store(true)
	defer c.scanning.Store(false)
	// the pre-clears and the visits stole the Prim CCA Time counter: the
	// next `show mibinfo` ask has no previous one to measure from
	defer c.mibGap(main)
	phase(wl.PhaseScanning)

	res := map[int]visitResult{}
	var lastStart time.Time
	calls := 0
	run := func(ch int, retry bool) error {
		calls++
		step := wl.ScanStep{Radio: main, Mode: ModeOffChan, Pass: 1, Call: calls, Channel: ch, Retry: retry}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: %v", wl.ErrScanAborted, err)
		}
		if c.o.now().Sub(start) > pl.Budget {
			return fmt.Errorf("%w: over the %v budget", wl.ErrScanAborted, pl.Budget)
		}
		if req.Guard != nil {
			if err := req.Guard(ctx, step); err != nil {
				return fmt.Errorf("%w: %v", wl.ErrScanAborted, err)
			}
		}
		if !lastStart.IsZero() {
			if wait := pl.Every - c.o.now().Sub(lastStart); wait > 0 {
				if err := c.o.sleep(ctx, wait); err != nil {
					return fmt.Errorf("%w: %v", wl.ErrScanAborted, err)
				}
			}
		}
		lastStart = c.o.now()
		v, err := b.visit(ctx, p, ch, home, width, pl)
		cd := wl.CallDiag{Pass: 1, Channel: ch, Retry: retry, Class: v.class, Took: c.o.now().Sub(lastStart)}
		if err != nil {
			cd.Err = err.Error()
		} else if v.why != "" {
			cd.Err = v.why
		}
		d.Calls = append(d.Calls, cd)
		if err != nil {
			return err
		}
		res[ch] = v
		return nil
	}
	for _, ch := range chans {
		if err := run(ch, false); err != nil {
			return fail(err)
		}
	}
	for _, ch := range chans {
		if res[ch].class == visitUnconfirmed {
			if err := run(ch, true); err != nil {
				return fail(err)
			}
		}
	}

	// a channel still missing after its retry fails the band before the
	// survey takes the radio off its channel again
	if err := b.rowsCheck(chans, res, d.Widths); err != nil {
		return fail(err)
	}

	// the neighbours: every visit cleared the driver's table
	sctx, cancel := context.WithTimeout(ctx, max(pl.Budget-c.o.now().Sub(start), time.Second))
	sr, err := c.freshSurvey(sctx, band, main)
	cancel()
	if err != nil {
		return fail(fmt.Errorf("neighbour survey after the sweep: %w", err))
	}
	own := map[string]bool{}
	for _, m := range req.OwnBSSIDs {
		own[strings.ToLower(m)] = true
	}
	for _, x := range sr.BSS {
		if !own[strings.ToLower(x.BSSID)] {
			d.BSS = append(d.BSS, x)
		}
	}
	if now, _, err := b.homeChannel(ctx); err != nil {
		return fail(err)
	} else if now != home {
		return fail(fmt.Errorf("%w: on channel %d after the band, was %d", wl.ErrChanspecChanged, now, home))
	}

	vals := map[int]wl.SpectrumChannel{}
	var busy []string
	ms := int(pl.Dwell / time.Millisecond)
	for _, ch := range chans {
		v := res[ch]
		st := wl.ChannelStat{Channel: ch, Freq: chanFreq24(ch, band), Home: ch == home, Samples: 1}
		switch v.class {
		case visitOK:
			util := min(100, (v.busy+ms*5)/(ms*10))
			in, nctl := wl.NeighbourInterference(noiseFloor, d.BSS, ch, band)
			vals[ch] = wl.SpectrumChannel{Class: wl.ClassMeasured, Util: util, Interference: in}
			st.Class, st.Util, st.Interference, st.CtlBSS = wl.ClassMeasured, util, in, nctl
			busy = append(busy, fmt.Sprintf("%d:%d", ch, v.busy/1000))
		case visitRefused:
			vals[ch] = wl.SpectrumChannel{Class: wl.ClassUnmeasured}
			st.Class, st.Samples = wl.ClassUnmeasured, 0
			d.Unmeasured = append(d.Unmeasured, ch)
		default:
			vals[ch] = wl.SpectrumChannel{Class: wl.ClassMissing}
			st.Class, st.Samples = wl.ClassMissing, 0
		}
		d.Channels = append(d.Channels, st)
	}
	d.Notes = append(d.Notes, fmt.Sprintf("busy ms of %d by channel %s", ms, strings.Join(busy, " ")))
	rows := map[int][]wl.SpectrumRow{}
	for _, w := range d.Widths {
		rs, omitted, err := wl.BuildSpectrumRows(band, w, blockLows(chans, w), vals)
		if len(omitted) > 0 {
			if d.Omitted == nil {
				d.Omitted = map[int][]int{}
			}
			d.Omitted[w] = omitted
		}
		if err != nil {
			return fail(err)
		}
		rows[w] = rs
	}
	d.Done = c.o.now()
	return rows, d, nil
}

// rowsCheck builds the rows from the visits alone (no interference yet):
// wl.ErrIncomplete when a requested row needs a missing channel, ErrNoRows
// when none is left.
func (b *offChan) rowsCheck(chans []int, res map[int]visitResult, widths []int) error {
	vals := map[int]wl.SpectrumChannel{}
	for _, ch := range chans {
		switch res[ch].class {
		case visitOK:
			vals[ch] = wl.SpectrumChannel{Class: wl.ClassMeasured}
		case visitRefused:
			vals[ch] = wl.SpectrumChannel{Class: wl.ClassUnmeasured}
		default:
			vals[ch] = wl.SpectrumChannel{Class: wl.ClassMissing}
		}
	}
	for _, w := range widths {
		if _, _, err := wl.BuildSpectrumRows(b.rd.Band, w, blockLows(chans, w), vals); err != nil {
			return err
		}
	}
	return nil
}

// blockLows lists the lowest channels of the blocks of width w over chans:
// every channel at 20 MHz; at 40 (2.4 GHz) every c whose c+4 is listed.
// Wider blocks are not built from the list (no 5 GHz backend yet).
func blockLows(chans []int, w int) []int {
	switch w {
	case 20:
		return chans
	case 40:
		var out []int
		for _, ch := range chans {
			if slices.Contains(chans, ch+4) {
				out = append(out, ch)
			}
		}
		return out
	}
	return nil
}

// chanFreq24 is the 20 MHz channel's centre frequency.
func chanFreq24(ch int, band string) int {
	if band == "ng" {
		if ch == 14 {
			return 2484
		}
		return 2407 + 5*ch
	}
	return 5000 + 5*ch
}

// Listed implements wl.SpectrumBackend: the blocks of the channel list
// (read under the restart gate when not cached).
func (b *offChan) Listed(context.Context) ([]wl.SpectrumBlock, error) {
	b.mu.Lock()
	chans := b.chans
	b.mu.Unlock()
	if chans == nil {
		open := b.c.o.priv
		if open == nil {
			open = openPriv
		}
		p, err := open()
		if err != nil {
			return nil, err
		}
		defer p.Close()
		if chans, _, err = b.listOf(p); err != nil {
			return nil, err
		}
	}
	var out []wl.SpectrumBlock
	for _, w := range b.widths() {
		for _, lo := range blockLows(chans, w) {
			centre := lo
			if w > 20 {
				centre = lo + (w/10 - 2)
			}
			out = append(out, wl.SpectrumBlock{Channel: lo, Width: w, CenterFreq: chanFreq24(centre, b.rd.Band)})
		}
	}
	return out, nil
}
