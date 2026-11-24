// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/dtechterminal/udeco/internal/rf"
	"github.com/dtechterminal/udeco/internal/wl"
)

// Spectrum on the MT7663 (5 GHz, rai0, mt_wifi built into the kernel): the
// driver's own off-channel visit, Channel_Info_MsgHandle, behind the same
// wl.SpectrumRunner as the MT7603's sweep (offchan.go). Ghidra of the
// kernel's mt_wifi (MT7613_JCO4032_MESH V6.0.2.0) and live tests on the
// Garage unit 2026-11-24 (the off5probe tool; docs/deco/spectrum-design.md
// "MT7663 off-channel visit"):
//
//   - The request is set-OID 0x955 (ioctl 0x8BE1, flags 0x8955), a
//     160-byte message: [0] 0x22 (off-channel scan), [1..16] the
//     interface, [36..40] up to five channels, [41..45] their scan types
//     (0x80 passive), [46..50] their dwells in ms (u8), [52] u32 LE the
//     number of channels (below 6). RTMPAPSetInformation hands it to
//     Channel_Info_MsgHandle, which queues an off-channel scan of the list
//     (ApSiteSurveyNew_by_wdev: TakeChannelOpCharge, the radio's beacons
//     stopped, BssTableInit clearing the neighbour table) and returns 0.
//     The ioctl succeeds whether or not a visit starts.
//   - At each channel's end (sync_fsm_scan_timeout_action, then
//     scan_next_channel's finish path for the last) the driver sends an
//     IWEVCUSTOM event, flags 0x955, 160 bytes: [0] 0x23, [1..16] the
//     interface, 0x24 the channel, 0x25 its index in the driver's channel
//     list (255: not in it), 0x28 the noise floor (s32: the band's running
//     average, not the visited channel's), then u32 LE µs rx 0x2c, tx 0x30,
//     OBSS 0x34 and channel busy 0x38 (MIB 0x2d048 Prim CCA time,
//     read-cleared as the visit starts), 0x3c a DFS flag, 0x3d the dwell
//     the driver measured (ms, u8). Live: 200 ms asked, 192-196 measured;
//     ch 36 0.6 ms busy, ch 149 (home) 17 ms, ch 165 0.03 ms; a DFS
//     channel (52) came back after 2 ms: such a short dwell measured
//     nothing (unmeasured, visitRefused). The radio was back on its own
//     channel after every visit (SIOCGIWFREQ before and after), and the
//     driver's one-second ReadChannelStats reads other registers (0x2d050,
//     0x2d098, 0x2d09c), so no reader of ours or the driver's clears the
//     busy counter mid-dwell: the agent's own 5 GHz reading is `show
//     bgndscaninfo`, paused while the band runs (startScanning).
//   - A request the driver drops sends nothing. Live 2026-11-24 the radio's
//     CNTL state machine was stuck in CNTL_WAIT_DISASSOC (debug level 4:
//     "cntl_mlme_error_handle [rai0 ]: [CNTL_WAIT_DISASSOC][CNTL_MLME_SCAN]
//     ... ERR"): every visit, and every normal 5 GHz site survey, was
//     dropped (the survey found only the home channel's neighbours) until
//     the radio was restarted. The cause (Ghidra, and the agent's KDP 0x52
//     counters of that day): FT_R1KHInfoMaintenance aged an R1KH entry of
//     an associated station and disassociated it on the AP wdev; the AP's
//     CNTL has no disassoc confirm, so it never left that state
//     (mtkft.R1KHTableSize). The agent keeps entries from aging
//     (mtkft.DriverKeyLife, pmkCacheMinutes). A band with no event at all
//     fails with errNoChanInfo saying so; the agent does not restart the
//     radio for it (its clients would drop).
//
// One band: under the collector's scan lock, the radio's channel and width,
// the channel list (the one the agent serves: chans5, and 52-64 with DFS:
// bandChannels), then one visit per channel, one visit start every Every
// (1 s), each a single passive channel of Dwell (200 ms). Before each
// visit: the guard, the restart gate (held for the visit only), the radio
// up. The visit is the request and the wait for its event (the interface
// and channel matching) up to Dwell + EventWait. No event: the visit is
// retried once after the last channel, then the channel is missing; a band
// with no event at all stops after the first pass (errNoChanInfo). An event
// whose measured dwell is under half the asked one (the driver cut it
// short) is retried the same way; short again, the channel is unmeasured. Then
// the fresh site survey (the visits cleared the neighbour table) and the
// radio's channel, as the MT7603's sweep.
//
// Rows: utilization = busy / the measured dwell, our stations' estimated
// uplink taken off the home channel's (as the MT7603's); interference from
// the survey's neighbours over the stand-in noise floor; 40 and 80 MHz
// blocks (rf.Blocks5G, every channel listed) the max of their 20 MHz
// channels (spectrum-design §5).

// SpectrumChanInfo is RadioDef.Spectrum for the MT7663's off-channel visit.
const SpectrumChanInfo = "chaninfo"

// ModeChanInfo is wl.SpectrumDiag.Mode of the MT7663's visits.
const ModeChanInfo = "chaninfo"

// chanInfoPlan is the band's timing (constants, not configuration).
type chanInfoPlan struct {
	Dwell     time.Duration // one channel's dwell (u8 ms)
	EventWait time.Duration // after the dwell, how long the visit's event may take
	Every     time.Duration // from one visit's start to the next
	Budget    time.Duration // the whole band (visits and survey)
}

var defaultChanInfoPlan = chanInfoPlan{Dwell: 200 * time.Millisecond, EventWait: 1500 * time.Millisecond,
	Every: time.Second, Budget: time.Minute}

const (
	oidChanInfoMsg = 0x0955 // the Channel_Info message (set) and its event (IWEVCUSTOM flags)
	chanInfoLen    = 0xa0
	chanInfoReq    = 0x22 // [0] of the request: off-channel scan
	chanInfoRes    = 0x23 // [0] of the event: one channel's result
	chanPassive    = 0x80
)

// ChanInfo is one channel's result (the 0x955 event).
type ChanInfo struct {
	Channel, Index int // Index 255: not in the driver's list
	NF             int // dBm, the band's running average
	RxUs, TxUs     uint32
	OBSSUs, BusyUs uint32
	DFS            bool
	MeasuredMs     int
}

// parseChanInfo reads the 0x955 event's data.
func parseChanInfo(d []byte) (ChanInfo, bool) {
	if len(d) < 0x3e || d[0] != chanInfoRes {
		return ChanInfo{}, false
	}
	le := binary.LittleEndian
	return ChanInfo{Channel: int(d[0x24]), Index: int(d[0x25]), NF: int(int32(le.Uint32(d[0x28:]))),
		RxUs: le.Uint32(d[0x2c:]), TxUs: le.Uint32(d[0x30:]), OBSSUs: le.Uint32(d[0x34:]), BusyUs: le.Uint32(d[0x38:]),
		DFS: d[0x3c] != 0, MeasuredMs: int(d[0x3d])}, true
}

// chanInfoRequest is the request for one passive visit of ch for ms.
func chanInfoRequest(ifname string, ch, ms int) []byte {
	b := make([]byte, chanInfoLen)
	b[0] = chanInfoReq
	copy(b[1:17], ifname)
	b[36], b[41], b[46] = byte(ch), chanPassive, byte(ms)
	binary.LittleEndian.PutUint32(b[52:], 1)
	return b
}

// errNoChanInfo: no visit of the band answered.
var errNoChanInfo = errors.New("mtkwifi: the 5 GHz driver answered no off-channel visit (no 0x955 event): its scan state machine is likely stuck in CNTL_WAIT_DISASSOC (an aged FT key holder entry disassociated a station: mtkft.R1KHTableSize; a 5 GHz site survey then finds only the home channel's neighbours too); a restart of the 5 GHz radio clears it")

// chanInfo is the MT7663 backend of one radio.
type chanInfo struct {
	c  *Collector
	rd RadioDef
}

func newChanInfo(c *Collector, rd RadioDef) *chanInfo { return &chanInfo{c: c, rd: rd} }

func (b *chanInfo) main() string { return b.rd.Ifaces[0] }

func (b *chanInfo) plan() chanInfoPlan {
	if b.c.o.chanInfo != nil {
		return *b.c.o.chanInfo
	}
	return defaultChanInfoPlan
}

func (b *chanInfo) widths() []int { return []int{20, 40, 80} }

// forget: the list is the agent's own (bandChannels), nothing cached.
func (b *chanInfo) forget() {}

func (b *chanInfo) channels() []int { return b.c.bandChannels(b.rd) }

// chanInfoListener delivers the radio's 0x955 events from its own
// rtnetlink socket (RTMGRP_LINK; the agent's Events listener ignores them).
type chanInfoListener struct {
	src  packetSource
	ev   chan ChanInfo
	done chan struct{}
}

func (b *chanInfo) listen() (*chanInfoListener, error) {
	open := b.c.o.rtnl
	if open == nil {
		open = openRTNLSocket
	}
	src, err := open()
	if err != nil {
		return nil, err
	}
	l := &chanInfoListener{src: src, ev: make(chan ChanInfo, 16), done: make(chan struct{})}
	main := b.main()
	go func() {
		defer close(l.done)
		buf := make([]byte, 64<<10)
		for {
			n, err := src.Read(buf)
			if errors.Is(err, syscall.ENOBUFS) {
				continue // the socket overflowed: what is next still counts
			}
			if err != nil {
				return
			}
			for _, e := range parseRTNL(buf[:n]) {
				if e.Kind != DrvChanInfo || e.Ifname != main || e.ChanInfo == nil {
					continue
				}
				select {
				case l.ev <- *e.ChanInfo:
				default:
				}
			}
		}
	}()
	return l, nil
}

func (l *chanInfoListener) Close() {
	l.src.Close()
	<-l.done
}

// drain drops the events already delivered (a late one of an earlier visit).
func (l *chanInfoListener) drain() {
	for {
		select {
		case <-l.ev:
		default:
			return
		}
	}
}

// wait is the event of the visit to ch, up to d.
func (l *chanInfoListener) wait(ctx context.Context, ch int, d time.Duration) (ChanInfo, bool, error) {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case e := <-l.ev:
			if e.Channel == ch {
				return e, true, nil
			}
		case <-t.C:
			return ChanInfo{}, false, nil
		case <-ctx.Done():
			return ChanInfo{}, false, fmt.Errorf("%w: %v", wl.ErrScanAborted, ctx.Err())
		}
	}
}

// visit is one channel: the request, then its event.
func (b *chanInfo) visit(ctx context.Context, p privIO, l *chanInfoListener, ch int, retry bool, pl chanInfoPlan) (visitResult, ChanInfo, error) {
	c := b.c
	done, ok := c.driverRead()
	if !ok {
		return visitResult{}, ChanInfo{}, ErrRadioRestart
	}
	defer done()
	if !c.isUp(b.main()) {
		return visitResult{}, ChanInfo{}, ErrRadioDown
	}
	ms := int(pl.Dwell / time.Millisecond)
	req := chanInfoRequest(b.main(), ch, ms)
	l.drain()
	if err := p.OID(b.main(), oidChanInfoMsg|oidSet, req); err != nil {
		return visitResult{}, ChanInfo{}, fmt.Errorf("mtkwifi: off-channel request for %d: %w", ch, err)
	}
	e, ok, err := l.wait(ctx, ch, pl.Dwell+pl.EventWait)
	switch {
	case err != nil:
		return visitResult{}, ChanInfo{}, err
	case !ok:
		return visitResult{class: visitUnconfirmed, why: "no event from the driver (the request was dropped)"}, ChanInfo{}, nil
	case e.MeasuredMs*2 < ms && !retry:
		// live: once in a while on any channel (ch 36, 161); retried
		return visitResult{class: visitUnconfirmed, why: fmt.Sprintf("the driver left after %d of %d ms", e.MeasuredMs, ms)}, e, nil
	case e.MeasuredMs*2 < ms:
		// again: the channel is cut short every time (live: DFS 52 after
		// 2 ms): unmeasured, not missing
		return visitResult{class: visitRefused, why: fmt.Sprintf("the driver left after %d of %d ms, on its retry too", e.MeasuredMs, ms)}, e, nil
	}
	return visitResult{class: visitOK, busy: int(e.BusyUs)}, e, nil
}

// Measure implements wl.SpectrumBackend (see the top of the file).
func (b *chanInfo) Measure(ctx context.Context, req wl.SpectrumRequest, phase func(wl.SpectrumPhase)) (map[int][]wl.SpectrumRow, wl.SpectrumDiag, error) {
	c := b.c
	main, band := b.main(), b.rd.Band
	pl := b.plan()
	d := wl.SpectrumDiag{Mode: ModeChanInfo, Started: c.o.now()}
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
	oc := &offChan{c: c, rd: b.rd} // its channel readers (homeChannel)
	home, width, err := oc.homeChannel(ctx)
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
	l, err := b.listen()
	if err != nil {
		return fail(fmt.Errorf("mtkwifi: driver events: %w", err))
	}
	defer l.Close()
	chans := b.channels()
	d.Notes = append(d.Notes, "channels the agent serves on the band")

	c.startScanning()
	defer c.scanning.Store(false)
	ownRx := c.ownUplink(main, c.o.now())
	phase(wl.PhaseScanning)

	res := map[int]visitResult{}
	evs := map[int]ChanInfo{}
	answered := 0
	var lastStart time.Time
	calls := 0
	run := func(ch int, retry bool) error {
		calls++
		step := wl.ScanStep{Radio: main, Mode: ModeChanInfo, Pass: 1, Call: calls, Channel: ch, Retry: retry}
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
		v, e, err := b.visit(ctx, p, l, ch, retry, pl)
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
		if v.class != visitUnconfirmed || e.Channel == ch {
			answered++ // an event came, even for a short dwell
		}
		if v.class != visitUnconfirmed {
			evs[ch] = e
		}
		res[ch] = v
		return nil
	}
	for _, ch := range chans {
		if err := run(ch, false); err != nil {
			return fail(err)
		}
	}
	if answered == 0 && len(chans) > 0 {
		return fail(errNoChanInfo)
	}
	for _, ch := range chans {
		if res[ch].class == visitUnconfirmed {
			if err := run(ch, true); err != nil {
				return fail(err)
			}
		}
	}
	if err := rowsCheck(band, chans, res, d.Widths); err != nil {
		return fail(err)
	}

	// the neighbours: every visit cleared the driver's table
	sctx, cancel := context.WithTimeout(ctx, max(pl.Budget-c.o.now().Sub(start), time.Second))
	sr, err := c.freshSurvey(sctx, band, main)
	cancel()
	if err != nil {
		return fail(fmt.Errorf("neighbour survey after the visits: %w", err))
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
	if now, _, err := oc.homeChannel(ctx); err != nil {
		return fail(err)
	} else if now != home {
		return fail(fmt.Errorf("%w: on channel %d after the band, was %d", wl.ErrChanspecChanged, now, home))
	}

	vals := map[int]wl.SpectrumChannel{}
	var busy []string
	nf := 0
	for _, ch := range chans {
		v, e := res[ch], evs[ch]
		st := wl.ChannelStat{Channel: ch, Freq: rf.ChanFreq(band, ch), Home: ch == home, Samples: 1}
		switch v.class {
		case visitOK:
			m := max(e.MeasuredMs, 1)
			busyUs := v.busy
			if ch == home && ownRx > 0 {
				ownUs := min(busyUs, int(ownRx*int64(m)/1000))
				busyUs -= ownUs
				d.Notes = append(d.Notes, fmt.Sprintf("home channel %d: %d of %d µs busy left out as our stations' estimated uplink", ch, ownUs, v.busy))
			}
			util := min(100, (busyUs*100+m*500)/(m*1000))
			in, nctl := wl.NeighbourInterference(noiseFloor, d.BSS, ch, band)
			vals[ch] = wl.SpectrumChannel{Class: wl.ClassMeasured, Util: util, Interference: in}
			st.Class, st.Util, st.Interference, st.CtlBSS = wl.ClassMeasured, util, in, nctl
			busy = append(busy, fmt.Sprintf("%d:%d/%d", ch, v.busy, m))
			nf = e.NF
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
	d.Notes = append(d.Notes, fmt.Sprintf("busy µs/measured ms by channel %s", strings.Join(busy, " ")))
	if nf != 0 {
		d.Notes = append(d.Notes, fmt.Sprintf("the driver's band noise average %d dBm (not per channel: not used)", nf))
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

// Listed implements wl.SpectrumBackend: the blocks of the channel list.
func (b *chanInfo) Listed(context.Context) ([]wl.SpectrumBlock, error) {
	return listedBlocks(b.rd.Band, b.channels(), b.widths()), nil
}

// spectrumBackend is a radio's backend behind its runner.
type spectrumBackend interface {
	wl.SpectrumBackend
	forget() // the cached channel list is read again (Invalidate)
}

var _ spectrumBackend = (*chanInfo)(nil)
var _ spectrumBackend = (*offChan)(nil)
