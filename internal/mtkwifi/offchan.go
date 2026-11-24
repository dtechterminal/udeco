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
	"syscall"
	"time"

	"github.com/dtechterminal/udeco/internal/rf"
	"github.com/dtechterminal/udeco/internal/wl"
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
//     13-visit sweep at 100 ms). The kernel log, at the module's own debug
//     level (RTDebugLevel starts at 2 in its .data; the live tests of
//     2026-11-20 03:4x printed exactly these two lines for a 50 ms visit):
//     ApSiteSurveyNew_by_wdev prints "ApSiteSurveyNew_by_wdev
//     channel_index:<i> channel:<ch> time:<ms>" (at any level) when the
//     request is queued, and at the end of the dwell UpdateChannelInfo
//     prints "time_diff:<t> Busytime:<x> AvgNF:<dBm>" (level 2 and up
//     in the vendor's mt7603eap; level 1 and up in mt7603roam, live
//     2026-11-23: it printed at the module's default level and at
//     Debug=1, more than 1 s after the request, and Debug=0 silenced it),
//     t = ms since ScanNextChannel armed the dwell timer, + 1, as a u8
//     (live: 44 for 50 ms: the timer is armed for ms/10 jiffies at HZ 100;
//     Busytime is the CCA/NAV/TX register, not the score's unit). It
//     prints it only while the ScanCtrl state is 1 or 2, which
//     Set_ApOffChanScan_Proc sets in the ioctl itself (state 1, one
//     channel), never for a full-band survey, and APScanTimeoutAction
//     restores the radio to its channel right after it in the same call.
//     The start line's only caller is Set_ApOffChanScan_Proc: every other
//     scan (`set SiteSurvey`, ACS, the driver's own scans) goes through
//     ApSiteSurvey and prints nothing at level 2. A scan already
//     running when the request comes (the ioctl does not check) takes it
//     over: the MLME drops our request (APInvalidStateWhenScan), and the
//     running scan's next channel timeout sees the off-channel state, ends
//     the scan with our list index, writes its own busy time into our slot
//     labelled with our channel and prints one time_diff, timed from the
//     last real off-channel dwell's start (stale: any value, a fitting one
//     too), then restores the radio. Our start line, then exactly one
//     time_diff: our visit never ran. At level 3 there is more: "start
//     offchannel scan on <ch> : channel list index = 0"
//     (APMlmeScanReqAction: none for a request taken over) and "SYNC - End
//     of SCAN, restore to <bw>MHz channel <home>, ..." (scan_ch_restore);
//     used when present, never needed. An off-channel scan of more than
//     one channel (never ours) prints "Next OFFChannel scan for : ..." at
//     any level as it moves on. A channel off the driver's list is
//     refused by ChannelSanity: no visit, no start line, and the ioctl
//     fails with EINVAL (the handler returns 0, which RTMPAPPrivIoctlSet
//     maps to -EINVAL; live: channel 13). Its "Network is down" return
//     reads as success with no visit.
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
// visit start every Every (1 s, so about 11 s for the band). Before each
// visit (quiet): the kernel log since the sweep's last read (all of it
// before the first band) must hold no off-channel scan the agent did not
// start: no start line, of any channel or radio, and no "Next OFFChannel
// scan" line (foreignScans; every line of the sweep's own is in a visit's
// log, and the agent starts no other scan while the lock is held), and the
// last visit's log no other scan's line. Else that scan may still run and
// would take the visit over: the sweep waits ForeignQuiet (2 s; one
// ApOffChanScan visit is 255 ms at most) and looks at what came in the
// wait: nothing, and it goes on; more, and the band stops
// (errForeignScan). Then the guard (the agent's scanBlock: observe mode,
// an apply or rollback, a TP-Link hold) and the restart gate (DriverRead,
// held for the visit only: an apply waits at most one visit) are checked,
// and the radio must be up; any of them stops the band (old table kept,
// abnormal). Each visit: the request's buffer built, pre-clear, the
// request (nothing between the two syscalls), the early kernel-log read
// EarlyLead (20 ms) before the dwell could end (dwellEarliest: 190 ms at
// 200), the log read again at Dwell + Settle (250 ms), the radio's channel
// (iwconfig), slot read. The visit's log is everything after quiet's read
// (anchored, newLogAnchored). An end line (time_diff, or at level 3 "End
// of SCAN") after our start line by the early read is not our dwell's: a
// scan the agent did not start (most print no line at all) was running
// and took the request over, and its value can fit ours; the visit is not
// trusted, nor is one whose early read ended too late to tell. Otherwise
// the visit is trusted only when its log holds exactly one start line, of
// this radio's band, for this channel with this dwell, then exactly one
// time_diff line and none before it, its time fitting the dwell (dwellOK:
// (dwell/10 - 1) × 10 to dwell + 60 ms), no other scan's line (another
// channel's start line, a channel-0 one, one of the other radio: the
// time_diff line names neither channel nor radio; a "Next OFFChannel scan"
// line), the level-3 lines, when there are any, agreeing (one "start
// offchannel scan" for it, one "End of SCAN" after it, none before), no
// MIB block but the pre-clear's (another `show mibinfo` would have cleared
// the counter in the dwell), the pre-clear-to-request time within
// PreClearMax, and the start line's slot names the channel. Not caught:
// a scan with no line whose channel timer fires after the early read. Only
// ACS scans dwell that long (400 ms a channel: `set AutoChannelSel`, or
// the driver's periodic check, which runs only with a check period set
// and no station associated; other scans dwell 140 ms at most); one that
// takes a visit over at level 2 ends it with a time_diff in the dwell's
// window roughly one time in six, and its busy time is trusted. With a
// start and neither a time_diff nor an "End of SCAN" within EndWait more,
// the visit's end is unknown and the band stops (errNoEnd: also what a
// debug level below 2 gives); an operating channel other than the band's
// home after a visit (iwconfig: the configured channel, which a visit
// never changes, so this catches an AP restart or a channel change; the
// radio's return itself is the time_diff, after which APScanTimeoutAction
// restores it in the same call), or an "End of SCAN" on another channel,
// stops it too (wl.ErrChanspecChanged). A visit not trusted otherwise
// (another scan's lines, a slot from an earlier visit, a request that
// started no visit, a visit taken over) is retried once after the last
// channel; still not trusted, the channel is missing and the band fails
// (wl.ErrIncomplete). A refused channel (EINVAL, and no start line for it
// in the anchored log) is unmeasured: no row, nor any 40 MHz block
// containing it; any other ioctl error stops the band.
//
// Then the fresh site survey of the radio (freshSurvey, as Scan), whose
// neighbours give the interference and refresh scan_table, and a last
// iwconfig: the radio must still be on its channel. The collector's
// busy-time reading skips the interval that held the sweep (mibGap: the
// pre-clears stole the MIB counter), and Collect keeps its last reading
// while the band runs (scanning, set only once no Collect is reading the
// driver: startScanning).
//
// Rows (as the Deco's, spectrum-design §4-§6): utilization = busy / dwell
// in % (busy = (100 - score) × 4 ms, so 2 % steps at 200 ms; off the home
// channel it is other networks' use; on the home channel the radio is in
// scan mode, beacons stopped and its own transmissions suspended, but our
// own stations may still send: their receive airtime as the collector last
// estimated it (radioReading.staRx, from the station counters, when fresh)
// is taken off the home visit's busy time, as §4.1 leaves our own traffic
// out);
// interference = clamp(max(-95, strongest neighbour level on the channel
// from the survey, our own BSSIDs left out)), -95 standing in for the
// noise floor the driver does not give (Collect reports the same);
// interference_type [], other_bss_count, perf_index, total_samples 0. A
// 40 MHz row (lowest channel c, centre c+2, for every c whose c+4 is
// listed) is the max of its two 20 MHz channels' values, as the Deco's
// (§5): only 20 MHz visits are made.
//
// The MT7663 (5 GHz, rai0, in the kernel) has no ApOffChanScan: its band
// has the driver's Channel_Info visit instead (SpectrumChanInfo,
// offchan5.go) behind the same runner.

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
	// PreClearMax: the longest time from the pre-clear's start to the
	// request's return a visit may take (the home channel's busy time in
	// between counts as the visit's; live with the probe: ~1.2 ms)
	PreClearMax time.Duration
	// ForeignQuiet: how long the sweep waits after an off-channel scan it
	// did not start shows in the kernel log, before it looks again (one
	// ApOffChanScan visit is at most 255 ms; a list scan prints a "Next
	// OFFChannel scan" line per channel)
	ForeignQuiet time.Duration
	// EarlyLead: the early log read is made this long before the dwell's
	// earliest end (dwellEarliest)
	EarlyLead time.Duration
}

// defaultOffChanPlan: the live test's 200 ms dwell and dwell + 250 ms
// wait; a visit a second.
var defaultOffChanPlan = offChanPlan{Dwell: 200 * time.Millisecond, Settle: 250 * time.Millisecond,
	EndWait: 2 * time.Second, EndPoll: 100 * time.Millisecond, Every: time.Second, Budget: time.Minute,
	PreClearMax: 10 * time.Millisecond, ForeignQuiet: 2 * time.Second, EarlyLead: 20 * time.Millisecond}

const (
	oidACSScore = 0x2014 // OID_802_11_GET_ACS_CHANNEL_SCORE
	oidChanInfo = 0x0999 // OID_802_11_CHANNELINFO (with oidSet)
	scoreBuf    = 512    // the driver copies 444 bytes whatever the length
	scoreSlots  = 55     // {score, channel} pairs in the 444 bytes
	chanRec     = 28     // one channel record of OID 0x8999
	chanBuf     = 16 * chanRec
	busyStep    = 4000             // µs per score point
	noiseFloor  = rf.NoiseFloorDBm // dBm: the stand-in noise floor (no driver reading)
)

// ownAirKeep: how old the collector's estimate of our stations' airtime
// may be for the home visit to use it (Measure).
const ownAirKeep = 2 * time.Minute

// offChan is the MT7603 sweep of one radio.
type offChan struct {
	c  *Collector
	rd RadioDef

	mu    sync.Mutex
	chans []int  // the channel list last read (nil: read it again)
	src   string // where it came from

	// the kernel log as the sweep last read it (its tail: the anchor of
	// the next read; "" before the first band), and whether what it read
	// last held another scan's lines. Used under the collector's scan lock
	// only (Measure).
	seen  string
	dirty bool
	// stamps: the kernel's times of the sweep's lines (kmsgstamp.go),
	// while a band runs; nil without /dev/kmsg (the early read decides)
	stamps *kmsgStamps
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
	// UpdateChannelInfo at the end of an ApOffChanScan dwell: ms from the
	// dwell's start + 1, as a u8 (debug level 2 and up, the module's
	// default); it names no channel and no radio
	visitDone = regexp.MustCompile(`time_diff:(\d+) Busytime:`)
	// debug level 3 only, extra evidence when present (never required):
	// APMlmeScanReqAction when the MLME takes an off-channel request up,
	// and scan_ch_restore when the radio is back
	visitBegun = regexp.MustCompile(`start offchannel scan on (\d+) : channel list index`)
	visitEnd   = regexp.MustCompile(`SYNC - End of SCAN, restore to \d+MHz channel (\d+)`)
	// APScanTimeoutAction, at any debug level, when an off-channel scan of
	// more than one channel moves on to its next one (never for ours: one
	// channel a request)
	nextOffChan = regexp.MustCompile(`Next OFFChannel scan for :`)
)

// foreignScans counts the lines of off-channel scans in log, a part of the
// kernel log that holds none of the sweep's own visits: every start line
// (ApSiteSurveyNew_by_wdev, whose only caller is Set_ApOffChanScan_Proc:
// someone else's `set ApOffChanScan`, channel 0 included, on either radio)
// and every "Next OFFChannel scan" line.
func foreignScans(log string) int {
	return len(visitStart.FindAllStringIndex(log, -1)) + len(nextOffChan.FindAllStringIndex(log, -1))
}

// visitLog is what one visit's kernel-log lines say.
type visitLog struct {
	// start lines for other channels of the band, for channel 0 (someone
	// else's ApOffChanScan with no channel, either radio), or for a channel
	// of the other band (the end line names no radio); "start offchannel
	// scan" lines for another channel, or for this one before its start
	// line; "Next OFFChannel scan" lines (a list scan that is not ours)
	others     int
	starts     int   // start lines for the channel
	idx, ms    int   // the channel's (last) start line: list index, dwell
	mib        int   // MIB blocks (Prim CCA Time lines): the pre-clear's, and any other reader's
	done       []int // the time_diff values after the channel's start line
	doneBefore int   // time_diff lines before it (another off-channel visit's)
	// debug level 3 lines (none at the module's default level)
	begun         int   // "start offchannel scan" lines for the channel after its start line
	restore       []int // the channels the "End of SCAN" lines after the band's last start line name
	restoreBefore int   // "End of SCAN" lines of the band before it
}

// level3: the log holds debug-level-3 lines of the band (then they must
// agree with the visit).
func (v visitLog) level3() bool { return v.begun > 0 || len(v.restore) > 0 || v.restoreBefore > 0 }

// parseVisitLog reads the lines a visit to ch added to the kernel log.
func parseVisitLog(log, band string, ch int) visitLog {
	v := visitLog{idx: -1, mib: strings.Count(log, "Prim CCA Time"), others: len(nextOffChan.FindAllStringIndex(log, -1))}
	last, own := -1, -1
	for _, m := range visitStart.FindAllStringSubmatchIndex(log, -1) {
		c, _ := strconv.Atoi(log[m[4]:m[5]])
		if c == 0 || !inBand(c, band) {
			// someone else's ApOffChanScan with no channel (this radio or
			// the other) or the other radio's visit: a scan that is not
			// ours, whose end line could pass for ours
			v.others++
			continue
		}
		last = m[1]
		if c != ch {
			v.others++
			continue
		}
		v.starts++
		own = m[1]
		v.idx, _ = strconv.Atoi(log[m[2]:m[3]])
		v.ms, _ = strconv.Atoi(log[m[6]:m[7]])
	}
	for _, m := range visitDone.FindAllStringSubmatchIndex(log, -1) {
		if own >= 0 && m[0] > own {
			t, _ := strconv.Atoi(log[m[2]:m[3]])
			v.done = append(v.done, t)
		} else {
			v.doneBefore++
		}
	}
	for _, m := range visitBegun.FindAllStringSubmatchIndex(log, -1) {
		c, _ := strconv.Atoi(log[m[2]:m[3]])
		switch {
		case !inBand(c, band):
		case c != ch || own < 0 || m[0] < own:
			v.others++
		default:
			v.begun++
		}
	}
	for _, m := range visitEnd.FindAllStringSubmatchIndex(log, -1) {
		c, _ := strconv.Atoi(log[m[2]:m[3]])
		if !inBand(c, band) {
			continue
		}
		if last >= 0 && m[0] > last {
			v.restore = append(v.restore, c)
		} else {
			v.restoreBefore++
		}
	}
	return v
}

// dwellOK: time_diff t (UpdateChannelInfo: (ms since ScanNextChannel armed
// the dwell timer) + 1, kept as a u8) fits a dwell of ms. The timer is
// armed for ms/10 jiffies (RTMP_OS_Add_Timer: ms × 100 / 1000, HZ 100), so
// it fires more than (ms/10 - 1) × 10 ms after the start, and the MLME
// runs APScanTimeoutAction after it: from (ms/10 - 1) × 10 to ms + 60
// (dwellLate) is accepted (live: 44 at 50 ms).
func dwellOK(t, ms int) bool {
	lo, hi := max(0, (ms/10-1)*10), ms+dwellLate
	for x := t; x <= hi; x += 256 {
		if x >= lo {
			return true
		}
	}
	return false
}

// stampWait: how long (real time) a visit waits for its /dev/kmsg records
// once the kernel log shows its end (the reader runs beside the sweep).
const stampWait = 500 * time.Millisecond

// dwellLate: how much later than the asked dwell its end may be printed
// (the timer's last jiffy and the MLME task's delay).
const dwellLate = 60

// dwellEarliest: no dwell of ms ends sooner after its request: the timer is
// armed (ScanNextChannel, after the request) for ms/10 jiffies and fires
// more than (ms/10 - 1) jiffies later (dwellOK's lower bound).
func dwellEarliest(ms int) time.Duration {
	return time.Duration(max(0, (ms/10-1)*10)) * time.Millisecond
}

// errForeignScan: an off-channel scan the sweep did not start is in the
// kernel log and still comes after the wait for it to end.
var errForeignScan = errors.New("mtkwifi: an off-channel scan the sweep did not start (an ApSiteSurveyNew_by_wdev or \"Next OFFChannel scan\" line) is in the kernel log, and more of it came while waiting for it to end: a visit now could be taken over by it")

// visit classes (wl.CallDiag.Class)
const (
	visitOK          = "ok"
	visitRefused     = "refused"     // no visit: off the driver's list
	visitUnconfirmed = "unconfirmed" // not trusted: retried, then missing
)

// visitResult is one visit.
type visitResult struct {
	class string
	busy  int           // µs over the dwell (visitOK)
	why   string        // visitUnconfirmed
	gap   time.Duration // from the pre-clear's start to the request's return
	early time.Duration // from the pre-clear's start to the early log read's end (0: none)
}

// errNoEnd: a visit started and no end of its dwell was logged. The
// time_diff line needs the driver's debug level 2 or more in the vendor's
// mt7603eap, 1 or more in mt7603roam (each module's default). With
// mt7603roam only `iwpriv ra0 set Debug=0` silences it (Debug=1 still
// prints it, live 2026-11-23); with mt7603eap Debug=0 or 1 does. Every band
// then stops here.
var errNoEnd = errors.New("mtkwifi: no \"time_diff\" line (UpdateChannelInfo, the end of the dwell) after an off-channel visit's start: its end is not confirmed (the line needs the driver's default debug level: Debug=0 silences it)")

// logTail is the end of a kernel-log read that anchors the next read
// (newLogAnchored compares no more).
func logTail(b []byte) string {
	if len(b) > 256 {
		b = b[len(b)-256:]
	}
	return string(b)
}

// quiet runs before each visit: the kernel log since the sweep's last read
// (all of it before the first band, or when the ring wrapped past that
// read: a line of an earlier sweep then costs one wait) must hold no
// off-channel scan the sweep did not start (foreignScans), and the last
// visit's log no other scan's line. The agent starts no other scan of the
// radio while the sweep holds the scan lock,
// and every one of the sweep's own lines is in a visit's log, so such a
// scan is someone else's and may still run: a visit now would be taken
// over by it. The log lines carry no time, so the sweep waits ForeignQuiet
// (longer than any off-channel visit, 255 ms at most; a list scan prints a
// line per channel) and looks at what came in the wait: nothing, and the
// scan has ended; more, and the band stops (errForeignScan). It returns
// how many lines it waited for (0: no wait).
func (b *offChan) quiet(ctx context.Context, pl offChanPlan) (int, error) {
	c := b.c
	now, err := c.o.klog()
	if err != nil {
		return 0, fmt.Errorf("mtkwifi: kernel log: %w", err)
	}
	added, _ := newLogAnchored(b.seen, string(now))
	n := foreignScans(added)
	if b.dirty {
		n = max(n, 1)
	}
	b.seen = logTail(now)
	if n == 0 {
		return 0, nil
	}
	if err := c.o.sleep(ctx, pl.ForeignQuiet); err != nil {
		return n, fmt.Errorf("%w: %v", wl.ErrScanAborted, err)
	}
	again, err := c.o.klog()
	if err != nil {
		return n, fmt.Errorf("mtkwifi: kernel log: %w", err)
	}
	added, anchored := newLogAnchored(b.seen, string(again))
	b.seen = logTail(again)
	if m := foreignScans(added); m > 0 || !anchored {
		b.dirty = true
		return n, fmt.Errorf("%w (%d line(s) before a %v wait, %d in it)", errForeignScan, n, pl.ForeignQuiet, m)
	}
	b.dirty = false
	return n, nil
}

// homeOK: the "End of SCAN" line's channel is the radio's own: its control channel,
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
	// the visit's log is what came after the sweep's last read (quiet's,
	// right before this visit): a line in between is in it too
	before := b.seen
	ms := int(pl.Dwell / time.Millisecond)
	// built before the pre-clear: nothing between it and the request but
	// the two syscalls
	arg := cstr(fmt.Sprintf("ApOffChanScan=passive:%d:%d", ch, ms))
	read := func() (visitLog, bool, error) {
		after, err := c.o.klog()
		if err != nil {
			return visitLog{}, false, fmt.Errorf("mtkwifi: kernel log: %w", err)
		}
		added, anchored := newLogAnchored(before, string(after))
		v := parseVisitLog(added, b.rd.Band, ch)
		b.seen, b.dirty = logTail(after), v.others > 0 || !anchored
		return v, anchored, nil
	}
	mark := 0
	if b.stamps != nil {
		mark = b.stamps.mark()
	}
	t0 := c.o.now()
	if err := p.Show(main, "mibinfo"); err != nil {
		return visitResult{}, fmt.Errorf("mtkwifi: %s show mibinfo (pre-clear): %w", main, err)
	}
	setErr := p.Set(main, arg)
	gap := c.o.now().Sub(t0)
	if setErr != nil {
		// ChannelSanity refuses a channel off the driver's list: the
		// handler returns 0, which the ioctl reports as EINVAL, and no
		// visit starts (no start line)
		if errors.Is(setErr, syscall.EINVAL) {
			if v, anchored, err := read(); err == nil && anchored && v.starts == 0 {
				return visitResult{class: visitRefused, gap: gap}, nil
			}
		}
		return visitResult{gap: gap}, fmt.Errorf("mtkwifi: %s set ApOffChanScan %d: %w", main, ch, setErr)
	}
	sleep := func(d time.Duration) error {
		if err := c.o.sleep(ctx, d); err != nil {
			// the visit runs on in the driver: let it end before the lock goes
			c.o.sleep(context.Background(), pl.EndWait)
			return err
		}
		return nil
	}
	// the early read, just before the dwell could end: an end line after
	// our start line then is not our dwell's. A scan already running when
	// the request came (one the agent did not start; at level 2 most print
	// no line at all) takes it over: Set_ApOffChanScan_Proc sets the
	// off-channel state in the ioctl, the MLME drops our request
	// (APInvalidStateWhenScan), and the running scan's next channel timeout
	// ends with our list index: one time_diff, timed from the last real
	// off-channel dwell, and its busy time in our slot
	var early time.Duration
	hijacked := false
	earliest := dwellEarliest(ms)
	earlyRead := earliest > 2*pl.EarlyLead && b.stamps == nil
	if earlyRead {
		if err := sleep(earliest - pl.EarlyLead - c.o.now().Sub(t0)); err != nil {
			return visitResult{gap: gap}, err
		}
		v, anchored, err := read()
		if err != nil {
			return visitResult{gap: gap}, err
		}
		early = c.o.now().Sub(t0)
		hijacked = anchored && early < earliest && (len(v.done) > 0 || len(v.restore) > 0)
	}
	if err := sleep(pl.Dwell + pl.Settle - c.o.now().Sub(t0)); err != nil {
		return visitResult{gap: gap, early: early}, err
	}
	// the radio's operating channel (iwconfig) after the visit: an AP
	// restart or a channel change moves it. It is the configured channel,
	// which an off-channel visit never changes, not proof of the radio's
	// return: that is the time_diff line, after which APScanTimeoutAction
	// restores the radio in the same call (at debug level 2 nothing logs
	// it)
	backHome := func() error {
		now, err := b.opChannel(ctx)
		if err != nil {
			return err
		}
		if now != home {
			return fmt.Errorf("%w: on channel %d after the visit to %d, was %d", wl.ErrChanspecChanged, now, ch, home)
		}
		return nil
	}
	v, anchored, err := read()
	if err != nil {
		return visitResult{gap: gap}, err
	}
	if !anchored {
		// the ring wrapped past the anchor: nothing in the log can be
		// placed; give a visit that may run time to end
		if err := c.o.sleep(ctx, pl.EndWait); err != nil {
			return visitResult{gap: gap}, err
		}
		if err := backHome(); err != nil {
			return visitResult{gap: gap}, err
		}
		return visitResult{class: visitUnconfirmed, why: "kernel log not anchored", gap: gap}, nil
	}
	if v.starts == 0 {
		// the driver took the request but started no visit (its "Network
		// is down" return reads as success): no measurement, not a
		// refused channel
		return visitResult{class: visitUnconfirmed, why: "the request started no visit (no start line)", gap: gap}, nil
	}
	// ended: a time_diff after our start line, or (debug level 3) an "End
	// of SCAN" after it
	ended := func(v visitLog) bool { return len(v.done) > 0 || len(v.restore) > 0 }
	for waited := time.Duration(0); !ended(v) && waited < pl.EndWait; waited += pl.EndPoll {
		if err := c.o.sleep(ctx, pl.EndPoll); err != nil {
			return visitResult{}, err
		}
		if v, _, err = read(); err != nil {
			return visitResult{}, err
		}
	}
	if !ended(v) {
		return visitResult{}, fmt.Errorf("%w (channel %d)", errNoEnd, ch)
	}
	for _, r := range v.restore {
		if !homeOK(r, home, width) {
			return visitResult{}, fmt.Errorf("%w: back on channel %d after the visit to %d, not %d", wl.ErrChanspecChanged, r, ch, home)
		}
	}
	if err := backHome(); err != nil {
		return visitResult{}, err
	}
	unconfirmed := func(format string, a ...any) (visitResult, error) {
		return visitResult{class: visitUnconfirmed, why: fmt.Sprintf(format, a...), gap: gap, early: early}, nil
	}
	if b.stamps != nil {
		// the kernel's times: the end line no sooner after the start line
		// than the dwell can end (kmsgstamp.go)
		took, ok := b.stamps.dwell(mark, ch, ms, stampWait)
		switch {
		case !ok:
			return unconfirmed("no start and end line for it in /dev/kmsg")
		case took < earliest:
			hijacked = true
			return unconfirmed("the end line came %v after the start line (kernel times), before the dwell could end (%v): a scan already running took the request over",
				took, earliest)
		}
	}
	switch {
	case hijacked:
		// its time_diff is timed from an older dwell and may fit ours
		return unconfirmed("an end line by the early read (%v after the pre-clear), before the dwell could end (%v): a scan already running took the request over",
			early, earliest)
	case earlyRead && early >= earliest:
		// read too late to tell a running scan's end from the dwell's
		return unconfirmed("the early log read ended %v after the pre-clear, not before the dwell's earliest end (%v)", early, earliest)
	case v.starts != 1 || v.others > 0:
		return unconfirmed("%d start(s) for it, %d other scan line(s)", v.starts, v.others)
	case len(v.done) != 1 || v.doneBefore > 0:
		// none (debug level 3: an "End of SCAN" and no time_diff): not an
		// off-channel dwell's end. More, or one before our start: another
		// off-channel visit's
		return unconfirmed("%d time_diff line(s) after its start, %d before: the driver did not run this visit alone", len(v.done), v.doneBefore)
	case v.level3() && (v.begun != 1 || len(v.restore) != 1 || v.restoreBefore > 0):
		return unconfirmed("debug level 3: %d \"start offchannel scan\" line(s) for it, %d \"End of SCAN\" line(s) after it, %d before",
			v.begun, len(v.restore), v.restoreBefore)
	case !dwellOK(v.done[0], ms):
		return unconfirmed("dwell ended at time_diff %d, asked %d ms", v.done[0], ms)
	case v.ms != ms:
		return unconfirmed("dwell %d ms, asked %d", v.ms, ms)
	case v.mib > 1:
		// another `show mibinfo` read-cleared Prim CCA Time in the dwell
		return unconfirmed("%d MIB reads in the visit (another reader cleared the busy counter)", v.mib)
	case pl.PreClearMax > 0 && gap > pl.PreClearMax:
		return unconfirmed("pre-clear to request %v (over %v: home-channel time counted)", gap, pl.PreClearMax)
	}
	buf := make([]byte, scoreBuf)
	if err := p.OID(main, oidACSScore, buf); err != nil {
		return visitResult{}, fmt.Errorf("mtkwifi: %s OID 0x2014: %w", main, err)
	}
	slots := parseScores(buf)
	if v.idx < 0 || v.idx >= len(slots) || slots[v.idx].ch != ch || slots[v.idx].score < 0 || slots[v.idx].score > 100 {
		return unconfirmed("slot %d does not hold channel %d", v.idx, ch)
	}
	return visitResult{class: visitOK, busy: (100 - slots[v.idx].score) * busyStep, gap: gap, early: early}, nil
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
	if home, err = b.opChannel(ctx); err != nil {
		return 0, 0, err
	}
	return home, c.radioWidth(b.rd), nil
}

// opChannel reads the radio's operating channel (iwconfig); the caller
// holds the restart gate.
func (b *offChan) opChannel(ctx context.Context) (int, error) {
	out, err := b.c.o.Run.Run(ctx, "iwconfig", b.main())
	if err != nil {
		return 0, fmt.Errorf("iwconfig %s: %w", b.main(), err)
	}
	m := chanRE.FindSubmatch(out)
	if m == nil {
		return 0, fmt.Errorf("iwconfig %s: no channel", b.main())
	}
	ch, _ := strconv.Atoi(string(m[1]))
	if ch <= 0 {
		return 0, fmt.Errorf("iwconfig %s: channel %d", b.main(), ch)
	}
	return ch, nil
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
	openK := c.o.kmsg
	if openK == nil {
		openK = openKmsgFile
	}
	if src, err := openK(); err != nil {
		d.Notes = append(d.Notes, fmt.Sprintf("no /dev/kmsg times (%v): the early log read decides a takeover", err))
	} else {
		b.stamps = newKmsgStamps(src)
		defer func() { b.stamps.Close(); b.stamps = nil }()
		d.Notes = append(d.Notes, "a takeover told by the kernel's times of the start and end lines (/dev/kmsg)")
	}

	// waits for a Collect reading the driver (its `show mibinfo` would
	// clear the counter in a visit's dwell); none starts one after
	c.startScanning()
	defer c.scanning.Store(false)
	// the pre-clears and the visits stole the Prim CCA Time counter: the
	// next `show mibinfo` ask has no previous one to measure from
	defer c.mibGap(main)
	ownRx := c.ownUplink(main, c.o.now())
	phase(wl.PhaseScanning)

	res := map[int]visitResult{}
	var lastStart time.Time
	var maxGap, maxEarly time.Duration
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
		n, err := b.quiet(ctx, pl)
		if n > 0 {
			d.Notes = append(d.Notes, fmt.Sprintf("before the visit to %d: %d line(s) of an off-channel scan the sweep did not start; waited %v", ch, n, pl.ForeignQuiet))
		}
		if err != nil {
			d.Calls = append(d.Calls, wl.CallDiag{Pass: 1, Channel: ch, Retry: retry, Err: err.Error()})
			return err
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
		maxGap, maxEarly = max(maxGap, v.gap), max(maxEarly, v.early)
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
			busyUs := v.busy
			if ch == home && ownRx > 0 {
				// our own stations' uplink in the dwell (the radio
				// stays on their channel): not other networks' use
				// (spectrum-design §4.1 leaves our own traffic out)
				own := min(busyUs, int(ownRx*int64(ms)/1000))
				busyUs -= own
				d.Notes = append(d.Notes, fmt.Sprintf("home channel %d: %d of %d ms busy left out as our stations' estimated uplink",
					ch, own/1000, v.busy/1000))
			}
			util := min(100, (busyUs+ms*5)/(ms*10))
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
	d.Notes = append(d.Notes, fmt.Sprintf("busy ms of %d by channel %s", ms, strings.Join(busy, " ")),
		fmt.Sprintf("pre-clear to request: longest %v", maxGap))
	if maxEarly > 0 {
		d.Notes = append(d.Notes, fmt.Sprintf("pre-clear to the early log read's end: longest %v (the dwell ends %v after its request at the earliest)", maxEarly, dwellEarliest(ms)))
	}
	rows := map[int][]wl.SpectrumRow{}
	for _, w := range d.Widths {
		rs, omitted, err := wl.BuildSpectrumRows(band, w, blockLows(band, chans, w), vals)
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
	return rowsCheck(b.rd.Band, chans, res, widths)
}

func rowsCheck(band string, chans []int, res map[int]visitResult, widths []int) error {
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
		if _, _, err := wl.BuildSpectrumRows(band, w, blockLows(band, chans, w), vals); err != nil {
			return err
		}
	}
	return nil
}

// blockLows lists the lowest channels of the blocks of width w over chans:
// every channel at 20 MHz; at 40 on 2.4 GHz every c whose c+4 is listed;
// on 5 GHz the rf.Blocks5G blocks of w whose 20 MHz channels are all
// listed.
func blockLows(band string, chans []int, w int) []int {
	if w == 20 {
		return chans
	}
	var out []int
	if band == "ng" {
		if w == 40 {
			for _, ch := range chans {
				if slices.Contains(chans, ch+4) {
					out = append(out, ch)
				}
			}
		}
		return out
	}
	for _, lo := range rf.Blocks5G(w) {
		all := true
		for i := 0; i < w/20; i++ {
			all = all && slices.Contains(chans, lo+4*i)
		}
		if all {
			out = append(out, lo)
		}
	}
	return out
}

// listedBlocks are the blocks of chans at each width.
func listedBlocks(band string, chans, widths []int) []wl.SpectrumBlock {
	var out []wl.SpectrumBlock
	for _, w := range widths {
		for _, lo := range blockLows(band, chans, w) {
			centre := lo
			if w > 20 {
				centre = lo + (w/10 - 2)
			}
			out = append(out, wl.SpectrumBlock{Channel: lo, Width: w, CenterFreq: chanFreq24(centre, band)})
		}
	}
	return out
}

// chanFreq24 is the 20 MHz channel's centre frequency.
func chanFreq24(ch int, band string) int { return rf.ChanFreq(band, ch) }

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
	return listedBlocks(b.rd.Band, chans, b.widths()), nil
}
