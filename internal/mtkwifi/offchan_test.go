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
	"testing"
	"time"
	"unsafe"

	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

// fakeMT7603 is mt7603eap.ko's private ioctls on the test unit, as the
// module does them (offchan.go top; Ghidra and the 2026-11-20 live test):
// `show mibinfo` prints the MIB block to the kernel log; ApOffChanScan for
// a listed channel prints the visit's start line (ApSiteSurveyNew_by_wdev),
// the MLME's "start offchannel scan" line (APMlmeScanReqAction) and its
// stay-time line (ScanNextChannel), writes the visit's score into the
// channel's slot and prints the end line on the way back home; an unlisted
// channel is refused without a line, and the ioctl fails with EINVAL
// (Set_ApOffChanScan_Proc returns 0 on ChannelSanity, RTMPAPPrivIoctlSet
// maps 0 to -EINVAL); 0x2014 answers the slots, 0x8999 the channel list.
type fakeMT7603 struct {
	d     *klogDev
	ck    *clock
	list  []int       // the driver's channel list; nil: OID 0x8999 fails
	busy  map[int]int // channel -> busy µs over the dwell
	stale map[int]int // channel -> visits whose slot is not written
	extra map[int]int // channel -> visits overlapped by another channel's request
	// hijack: channel -> visits ended by a scan already running (one that
	// prints no start line): our start line, a slot written with that
	// scan's busy time (hijackBusy), its end line, and no visit of ours
	hijack     map[int]int
	hijackBusy int
	silent     map[int]int           // channel -> sets that succeed with no visit and no line ("Network is down")
	slowShow   map[int]time.Duration // channel -> the pre-clear before its visit takes this long (once)
	noEnd      bool                  // no level-3 lines: no "start offchannel scan", stay-time or "End of SCAN" (a debug level below 3)
	away       int                   // the end line restores to this channel (0: home)
	home       int                   // the radio's channel
	slots      [55][2]uint32
	calls      []string // "<t> show mibinfo", "<t> set ...", "<t> oid 0x2014"
	hook       func(call string)
	setErr     error

	pendingSlow bool // a pre-clear the next set's slowShow applies to
}

func newFakeMT7603(d *klogDev, ck *clock) *fakeMT7603 {
	f := &fakeMT7603{d: d, ck: ck, list: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, busy: map[int]int{}, stale: map[int]int{}, extra: map[int]int{},
		hijack: map[int]int{}, silent: map[int]int{}, slowShow: map[int]time.Duration{}, home: 6}
	// slots past the list hold heap garbage
	for i := 11; i < 55; i++ {
		f.slots[i] = [2]uint32{0xdeadbeef, uint32(i * 7)}
	}
	return f
}

func (f *fakeMT7603) note(s string) {
	f.calls = append(f.calls, fmt.Sprintf("%d %s", f.ck.t.UnixMilli(), s))
	if f.hook != nil {
		f.hook(s)
	}
}

func (f *fakeMT7603) Show(ifname, what string) error {
	f.note("show " + ifname + " " + what)
	if what == "mibinfo" {
		f.d.log.WriteString(mibFixtureLines)
		// the next visit's channel is not known here: slowShow applies to
		// the visit after the pre-clear (the next set)
		f.pendingSlow = true
	}
	return nil
}

func (f *fakeMT7603) Set(ifname string, b []byte) error {
	if len(b) == 0 || b[len(b)-1] != 0 {
		return errors.New("fake: set argument not NUL-terminated")
	}
	arg := string(b[:len(b)-1])
	f.note("set " + ifname + " " + arg)
	if f.setErr != nil {
		return f.setErr
	}
	var ch, ms int
	if _, err := fmt.Sscanf(arg, "ApOffChanScan=passive:%d:%d", &ch, &ms); err != nil {
		return errors.New("fake: bad set " + arg)
	}
	if d, ok := f.slowShow[ch]; ok && f.pendingSlow {
		// the time from the pre-clear to this request
		delete(f.slowShow, ch)
		f.ck.t = f.ck.t.Add(d)
	}
	f.pendingSlow = false
	idx := slices.Index(f.list, ch)
	if idx < 0 {
		return syscall.EINVAL // ChannelSanity: "wrong channel number" (debug only), no visit
	}
	if f.silent[ch] > 0 {
		f.silent[ch]--
		return nil
	}
	fmt.Fprintf(&f.d.log, "<4>ApSiteSurveyNew_by_wdev channel_index:%d channel:%d time:%d\n", idx, ch, ms)
	if f.hijack[ch] > 0 {
		f.hijack[ch]--
		f.slots[idx] = [2]uint32{uint32(max(0, 100-f.hijackBusy/4000)), uint32(ch)}
		fmt.Fprintf(&f.d.log, "<4>SYNC - End of SCAN, restore to 20MHz channel %d, Total BSS[03]\n", f.home)
		return nil
	}
	if !f.noEnd {
		fmt.Fprintf(&f.d.log, "<4>[APMlmeScanReqAction][2098] start offchannel scan on %d : channel list index = 0\n", ch)
		fmt.Fprintf(&f.d.log, "<4>[ScanNextChannel][696] stay time configured of channel index = 0 time = %d\n", ms)
	}
	if f.extra[ch] > 0 {
		f.extra[ch]--
		fmt.Fprintf(&f.d.log, "<4>ApSiteSurveyNew_by_wdev channel_index:0 channel:1 time:%d\n", ms)
	}
	if f.stale[ch] > 0 {
		f.stale[ch]--
	} else {
		score := max(0, 100-f.busy[ch]/4000)
		f.slots[idx] = [2]uint32{uint32(score), uint32(ch)}
	}
	if !f.noEnd {
		back := f.home
		if f.away != 0 {
			back = f.away
		}
		fmt.Fprintf(&f.d.log, "<4>SYNC - End of SCAN, restore to 20MHz channel %d, Total BSS[03]\n", back)
	}
	return nil
}

func (f *fakeMT7603) OID(ifname string, flags uint16, buf []byte) error {
	f.note(fmt.Sprintf("oid %s 0x%x", ifname, flags))
	switch flags {
	case oidACSScore:
		for i, s := range f.slots {
			if 8*i+8 > len(buf) {
				break
			}
			binary.LittleEndian.PutUint32(buf[8*i:], s[0])
			binary.LittleEndian.PutUint32(buf[8*i+4:], s[1])
		}
		return nil
	case oidChanInfo | oidSet:
		if f.list == nil {
			return errors.New("fake: OID 0x8999 refused")
		}
		for i, ch := range f.list {
			buf[chanRec*i], buf[chanRec*i+1] = byte(ch), byte(i)
		}
		return nil
	}
	return errors.New("fake: unknown OID")
}

func (f *fakeMT7603) Close() error { return nil }

// sets lists the ApOffChanScan channels in order.
func (f *fakeMT7603) sets() []int {
	var out []int
	for _, c := range f.calls {
		var t int64
		var ch, ms int
		if _, err := fmt.Sscanf(c, "%d set ra0 ApOffChanScan=passive:%d:%d", &t, &ch, &ms); err == nil {
			out = append(out, ch)
		}
	}
	return out
}

// mibFixtureLines is what one `show mibinfo` adds to the kernel log.
var mibFixtureLines = "<4>MIB Status Control=0x7fffffff\n<4>===Phy/Timing Related Counters===\n<4>\tPrim CCA Time=0x45b5af\n"

// offChanUnit is a FreshScan collector of the JCOW414 with the fake
// MT7603, a survey that changes once SiteSurvey=1 is set, and a wall clock
// the collector's sleeps move on.
func offChanUnit(t *testing.T) (*Collector, *fakeMT7603, *klogDev, *clock) {
	t.Helper()
	d := newKlogDev(t)
	ck := &clock{t: time.Unix(1_000_000, 0)}
	f := newFakeMT7603(d, ck)
	old := fixture(t, "site_survey_ra0.txt")
	d.survey["ra0"] = "ra0       get_site_survey:\nTotal=0\n"
	d.next["ra0"] = old
	d.after = 1 // the survey's own reads: the new table from the second on
	c := newTestCollector(d, ck, true)
	c.o.priv = func() (privIO, error) { return f, nil }
	return c, f, d, ck
}

// The whole sweep: one visit per listed channel, one a second, each right
// after its own MIB pre-clear; then the neighbour survey (the visits
// cleared the driver's neighbour table); rows at 20 and 40 MHz from the
// busy time (utilisation of the dwell) and the survey's neighbours
// (interference); the next mibinfo reading is skipped (mibGap).
func TestOffChanSweep(t *testing.T) {
	c, f, d, ck := offChanUnit(t)
	ctx := context.Background()
	// busy µs of the 200 ms dwell (the live test: ch1 24 ms, ch6 40,
	// ch10 44-46, ch11 68-70)
	f.busy = map[int]int{1: 24000, 6: 40000, 10: 44000, 11: 68000, 3: 3999}
	c.mib["ra0"] = &mibReading{}

	r, err := c.Spectrum(ctx, "ng")
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := c.Spectrum(ctx, "ng"); again != r || r.Radio() != "ra0" {
		t.Fatalf("Spectrum: not one runner per radio (%p %p) or radio %q", again, r, r.Radio())
	}
	var phases []wl.SpectrumPhase
	res, err := r.Run(ctx, wl.SpectrumRequest{Widths: []int{20, 40, 80}, Manual: true,
		OwnBSSIDs: []string{"AA:A7:B9:3E:16:90"}, // ours: left out of the interference
		OnPhase:   func(p wl.SpectrumPhase) { phases = append(phases, p) }})
	if err != nil {
		t.Fatalf("Run: %v (diag %+v)", err, res.Diag)
	}
	if got := f.sets(); !slices.Equal(got, f.list) {
		t.Errorf("visited %v, want %v", got, f.list)
	}
	// each visit: show mibinfo, then the set, with no time between; a
	// second from one visit's start to the next
	var lastSet int64
	for i, call := range f.calls {
		var at int64
		var rest string
		fmt.Sscanf(call, "%d %s", &at, &rest)
		if !strings.Contains(call, "ApOffChanScan") {
			continue
		}
		prev := f.calls[i-1]
		if !strings.HasSuffix(prev, "show ra0 mibinfo") || !strings.HasPrefix(prev, fmt.Sprint(at)+" ") {
			t.Errorf("visit %q not right after its pre-clear (%q)", call, prev)
		}
		if lastSet != 0 && at-lastSet < 1000 {
			t.Errorf("visit %q %d ms after the previous one", call, at-lastSet)
		}
		lastSet = at
	}
	// the survey after the sweep
	cmds := d.iwpriv()
	si := slices.Index(cmds, "iwpriv ra0 set SiteSurvey=1")
	if si < 0 {
		t.Fatalf("no survey after the sweep: %v", cmds)
	}
	if !slices.Equal(phases, []wl.SpectrumPhase{wl.PhaseScanning, wl.PhaseIdle}) {
		t.Errorf("phases %v", phases)
	}
	if m := c.mib["ra0"]; !m.gap {
		t.Error("no mib gap after the sweep: the next cu_total would count the pre-clears' stolen time")
	}
	if c.scanning.Load() {
		t.Error("still scanning after the band")
	}

	dg := res.Diag
	if dg.Mode != ModeOffChan || dg.HomeControl != 6 || dg.HomeWidth != 40 || !slices.Equal(dg.Widths, []int{20, 40}) {
		t.Errorf("diag mode %q home %d/%d widths %v", dg.Mode, dg.HomeControl, dg.HomeWidth, dg.Widths)
	}
	if len(dg.BSS) != 15 {
		t.Errorf("%d neighbours, want 15 (16 surveyed, ours left out)", len(dg.BSS))
	}
	rows20 := res.Rows[20]
	if len(rows20) != 11 || len(res.Rows[40]) != 7 || len(res.Rows) != 2 {
		t.Fatalf("rows: %d at 20, %d at 40, widths %d", len(rows20), len(res.Rows[40]), len(res.Rows))
	}
	byCh := map[int]wl.SpectrumRow{}
	for _, row := range rows20 {
		byCh[row.Channel] = row
		if row.Width != 20 || row.CenterFreq != 2407+5*row.Channel || row.InterferenceType == nil {
			t.Errorf("row %+v", row)
		}
	}
	// busy (100 - score) * 4 ms over the 200 ms dwell
	for ch, want := range map[int]int{1: 12, 6: 20, 10: 22, 11: 34, 2: 0, 3: 0} {
		if got := byCh[ch].Utilization; got != want {
			t.Errorf("ch %d utilization %d, want %d", ch, got, want)
		}
	}
	// strongest neighbour on the channel: ch 1 -67 (Neighbour00 primary),
	// ch 11 -60 (the -57 on 11 is ours), ch 8 overlaps only
	if byCh[1].Interference != -67 || byCh[11].Interference != -60 {
		t.Errorf("interference ch1 %d ch11 %d, want -67 -60", byCh[1].Interference, byCh[11].Interference)
	}
	for _, row := range res.Rows[40] {
		lo, hi := byCh[row.Channel], byCh[row.Channel+4]
		if row.Width != 40 || row.CenterFreq != 2407+5*(row.Channel+2) ||
			row.Utilization != max(lo.Utilization, hi.Utilization) || row.Interference != max(lo.Interference, hi.Interference) {
			t.Errorf("40 MHz row %+v from %+v and %+v", row, lo, hi)
		}
	}
	st := r.Status()
	if st.Abnormal || st.TableTime.IsZero() || len(st.Rows[20]) != 11 {
		t.Errorf("status %+v", st)
	}
	_ = ck
}

// A channel the driver refuses (ChannelSanity: no visit, no line) is
// absent, with every block containing it; the band succeeds.
func TestOffChanRefusedChannel(t *testing.T) {
	c, f, _, _ := offChanUnit(t)
	f.list = nil // the list OID fails: 1..11 are tried
	ctx := context.Background()
	f.busy[1] = 8000
	// the driver's list is 1..10: 11 is refused
	driverList := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	f.list = nil
	r, _ := c.Spectrum(ctx, "ng")
	refuse := &refusingMT7603{fakeMT7603: f, list: driverList}
	c.o.priv = func() (privIO, error) { return refuse, nil }
	res, err := r.Run(ctx, wl.SpectrumRequest{Widths: []int{40}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := f.sets(); !slices.Equal(got, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}) {
		t.Errorf("visited %v (the fallback list is 1..11)", got)
	}
	var lows []int
	for _, row := range res.Rows[40] {
		lows = append(lows, row.Channel)
	}
	if !slices.Equal(lows, []int{1, 2, 3, 4, 5, 6}) || res.Diag.Omitted[40][0] != 7 {
		t.Errorf("40 MHz rows %v, omitted %v: block 7 (7+11) needs the refused 11", lows, res.Diag.Omitted)
	}
}

// refusingMT7603 has no channel-list OID and refuses channels off its
// list, as ChannelSanity does.
type refusingMT7603 struct {
	*fakeMT7603
	list []int
}

func (f *refusingMT7603) Set(ifname string, arg []byte) error {
	f.fakeMT7603.list = f.list
	defer func() { f.fakeMT7603.list = nil }()
	return f.fakeMT7603.Set(ifname, arg)
}

func (f *refusingMT7603) OID(ifname string, flags uint16, buf []byte) error {
	if flags == oidACSScore {
		return f.fakeMT7603.OID(ifname, flags, buf)
	}
	f.note(fmt.Sprintf("oid %s 0x%x", ifname, flags))
	return errors.New("fake: refused")
}

// A visit whose slot does not name its channel (never written) is not
// trusted: it is visited again at the end of the sweep. A visit another
// request overlapped (a second start line) is not trusted either; missed
// twice, the channel fails the band (the old table stays, abnormal).
func TestOffChanUnconfirmedVisit(t *testing.T) {
	c, f, d, _ := offChanUnit(t)
	ctx := context.Background()
	f.stale[4] = 1
	r, _ := c.Spectrum(ctx, "ng")
	if _, err := r.Run(ctx, wl.SpectrumRequest{}); err != nil {
		t.Fatalf("one stale visit, retried: %v", err)
	}
	if got := f.sets(); len(got) != 12 || got[11] != 4 {
		t.Errorf("visits %v: want 1..11 and 4 again", got)
	}
	good := r.Status()

	f.calls = nil
	f.extra[4] = 2
	res, err := r.Run(ctx, wl.SpectrumRequest{})
	if !errors.Is(err, wl.ErrIncomplete) {
		t.Fatalf("overlapped twice: %v (diag %+v)", err, res.Diag.Calls)
	}
	if n := strings.Count(strings.Join(d.iwpriv(), "\n"), "SiteSurvey=1"); n != 1 {
		t.Errorf("%d surveys: the failed band surveyed", n)
	}
	if st := r.Status(); !st.Abnormal || !st.TableTime.Equal(good.TableTime) {
		t.Errorf("failed band: %+v", st)
	}
}

// parseVisitLog counts this radio's start and end lines around the visit.
func TestParseVisitLog(t *testing.T) {
	log := "<4>x\n<4>ApSiteSurveyNew_by_wdev channel_index:3 channel:4 time:200\n" + mibFixtureLines +
		"<4>SYNC - End of SCAN, restore to 20MHz channel 6, Total BSS[02]\n"
	v := parseVisitLog(log, "ng", 4)
	if v.starts != 1 || v.idx != 3 || v.ms != 200 || v.ends != 1 || !slices.Equal(v.restore, []int{6}) || v.others != 0 || v.endsBefore != 0 {
		t.Errorf("visit %+v", v)
	}
	// the 5 GHz radio's own scans are not this radio's
	v = parseVisitLog("<4>ApSiteSurveyNew_by_wdev channel_index:0 channel:36 time:0\n<4>SYNC - End of SCAN, restore to 80MHz channel 157, Total BSS[02]\n"+log, "ng", 4)
	if v.starts != 1 || v.others != 0 || v.ends != 1 || v.endsBefore != 0 {
		t.Errorf("with a 5 GHz scan: %+v", v)
	}
	// an end before the start: another scan was running
	v = parseVisitLog("<4>SYNC - End of SCAN, restore to 20MHz channel 6, Total BSS[02]\n"+log, "ng", 4)
	if v.endsBefore != 1 {
		t.Errorf("end before the start: %+v", v)
	}
	v = parseVisitLog("<4>ApSiteSurveyNew_by_wdev channel_index:0 channel:1 time:200\n"+log, "ng", 4)
	if v.others != 1 {
		t.Errorf("another channel's visit: %+v", v)
	}
	// channel 0 is a full-band survey of either radio: a foreign scan, not
	// nothing
	v = parseVisitLog(log+"<4>ApSiteSurveyNew_by_wdev channel_index:0 channel:0 time:0\n", "ng", 4)
	if v.others != 1 {
		t.Errorf("a full-band survey's start line: %+v", v)
	}
}

// Without the end line (the driver's debug level below 3) no visit can be
// confirmed to have ended: the band stops at the first visit, before any
// other channel is visited or the survey runs.
func TestOffChanNoEndLine(t *testing.T) {
	c, f, d, _ := offChanUnit(t)
	f.noEnd = true
	r, _ := c.Spectrum(context.Background(), "ng")
	_, err := r.Run(context.Background(), wl.SpectrumRequest{})
	if err == nil || !strings.Contains(err.Error(), "End of SCAN") {
		t.Fatalf("Run: %v", err)
	}
	if got := f.sets(); len(got) != 1 {
		t.Errorf("visits %v after an unconfirmed return", got)
	}
	if slices.Contains(d.iwpriv(), "iwpriv ra0 set SiteSurvey=1") {
		t.Error("surveyed after the band stopped")
	}
	if !r.Status().Abnormal {
		t.Error("not abnormal")
	}
}

// The radio restored to a channel that is not its own: the band stops.
func TestOffChanNotBackHome(t *testing.T) {
	c, f, _, _ := offChanUnit(t)
	f.away = 3
	r, _ := c.Spectrum(context.Background(), "ng")
	if _, err := r.Run(context.Background(), wl.SpectrumRequest{}); !errors.Is(err, wl.ErrChanspecChanged) || len(f.sets()) != 1 {
		t.Errorf("Run: %v after %v", err, f.sets())
	}
}

// Gates: a radio restart (or its settle time) stops the band before the
// next visit; so does the agent's guard (an apply starting, observe mode);
// a down radio is never asked.
func TestOffChanGates(t *testing.T) {
	ctx := context.Background()
	t.Run("restart", func(t *testing.T) {
		c, f, _, _ := offChanUnit(t)
		open := true
		c.FollowRestarts(gateFunc(func() (func(), bool) { return func() {}, open }))
		f.hook = func(call string) {
			if strings.Contains(call, "passive:3:") {
				open = false
			}
		}
		r, _ := c.Spectrum(ctx, "ng")
		if _, err := r.Run(ctx, wl.SpectrumRequest{}); !errors.Is(err, ErrRadioRestart) || !slices.Equal(f.sets(), []int{1, 2, 3}) {
			t.Errorf("Run: %v, visits %v", err, f.sets())
		}
	})
	t.Run("guard", func(t *testing.T) {
		c, f, _, _ := offChanUnit(t)
		var steps []wl.ScanStep
		guard := func(_ context.Context, s wl.ScanStep) error {
			steps = append(steps, s)
			if s.Channel == 5 {
				return errors.New("a Wi-Fi apply or rollback is running")
			}
			return nil
		}
		r, _ := c.Spectrum(ctx, "ng")
		if _, err := r.Run(ctx, wl.SpectrumRequest{Guard: guard}); !errors.Is(err, wl.ErrScanAborted) || !slices.Equal(f.sets(), []int{1, 2, 3, 4}) {
			t.Errorf("Run: %v, visits %v", err, f.sets())
		}
		if len(steps) != 5 || steps[0].Radio != "ra0" || steps[0].Mode != ModeOffChan || steps[4].Call != 5 {
			t.Errorf("guard steps %+v", steps)
		}
	})
	t.Run("down", func(t *testing.T) {
		c, f, d, _ := offChanUnit(t)
		d.setUp("ra0", false)
		r, _ := c.Spectrum(ctx, "ng")
		if _, err := r.Run(ctx, wl.SpectrumRequest{}); !errors.Is(err, ErrRadioDown) || len(f.calls) != 0 {
			t.Errorf("Run: %v, driver asked %v", err, f.calls)
		}
	})
}

// Only the MT7603 has the off-channel sweep, and only with site_survey
// (FreshScan): 5 GHz keeps the neighbour survey; without FreshScan neither
// band has a runner or a survey.
func TestSpectrumPerBand(t *testing.T) {
	ctx := context.Background()
	c, _, _, _ := offChanUnit(t)
	if _, err := c.Spectrum(ctx, "na"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("na runner: %v", err)
	}
	if no, by := c.SpectrumBySurvey("na"); !no || !by {
		t.Errorf("na: no runner %v, by survey %v", no, by)
	}
	if no, _ := c.SpectrumBySurvey("ng"); no {
		t.Error("ng: no runner")
	}
	d := newKlogDev(t)
	off := newTestCollector(d, &clock{t: time.Unix(1_000_000, 0)}, false)
	if _, err := off.Spectrum(ctx, "ng"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("ng runner without site_survey: %v", err)
	}
	for _, band := range []string{"ng", "na"} {
		if no, by := off.SpectrumBySurvey(band); !no || by {
			t.Errorf("%s without site_survey: no runner %v, by survey %v", band, no, by)
		}
	}
}

// A restored table keeps the rows of the channel list (FitRestored).
func TestOffChanListed(t *testing.T) {
	c, f, _, _ := offChanUnit(t)
	f.list = []int{1, 2, 3, 4, 5, 6, 7, 8, 9}
	r, _ := c.Spectrum(context.Background(), "ng")
	saved := map[int][]wl.SpectrumRow{
		20: {{Channel: 1, Width: 20, CenterFreq: 2412}, {Channel: 11, Width: 20, CenterFreq: 2462}},
		40: {{Channel: 5, Width: 40, CenterFreq: 2442}, {Channel: 6, Width: 40, CenterFreq: 2447}},
	}
	r.RestoreTable(saved, time.Now().Add(-time.Hour))
	kept, dropped, err := r.FitRestored(context.Background())
	if err != nil || kept != 2 || dropped != 2 {
		t.Errorf("fit: kept %d dropped %d, %v", kept, dropped, err)
	}
}

func TestParseChanList(t *testing.T) {
	b := make([]byte, chanBuf)
	for i, ch := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} {
		b[chanRec*i], b[chanRec*i+1] = byte(ch), byte(i)
	}
	if got, ok := parseChanList(b, "ng"); !ok || !slices.Equal(got, chans24) {
		t.Errorf("list %v %v", got, ok)
	}
	b[chanRec*3+1] = 9 // index out of order
	if _, ok := parseChanList(b, "ng"); ok {
		t.Error("a broken list accepted")
	}
	if _, ok := parseChanList(make([]byte, chanBuf), "ng"); ok {
		t.Error("an empty list accepted")
	}
	// the score slots name the channels at their own index (ch i+1 at i)
	s := make([]byte, scoreBuf)
	for i, ch := range []int{1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13} {
		binary.LittleEndian.PutUint32(s[8*i+4:], uint32(ch))
	}
	binary.LittleEndian.PutUint32(s[8*20+4:], 21) // garbage past the list
	if got := fallbackChans(s, "ng"); !slices.Equal(got, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13}) {
		t.Errorf("fallback %v", got)
	}
}

// struct iwreq is 32 bytes with the iw_point after the 16-byte name, on
// the unit's 32-bit kernel and on a 64-bit one.
func TestIwreqLayout(t *testing.T) {
	buf := cstr("mibinfo")
	r, err := newIwreq("ra0", buf, 0x2014)
	if err != nil {
		t.Fatal(err)
	}
	if unsafe.Sizeof(*r) != 32 || unsafe.Offsetof(r.data) != 16 {
		t.Errorf("iwreq %d bytes, union at %d", unsafe.Sizeof(*r), unsafe.Offsetof(r.data))
	}
	ps := unsafe.Sizeof(uintptr(0))
	raw := unsafe.Slice((*byte)(unsafe.Pointer(r)), 32)
	if string(raw[:4]) != "ra0\x00" || binary.LittleEndian.Uint16(raw[16+ps:]) != 8 || binary.LittleEndian.Uint16(raw[18+ps:]) != 0x2014 {
		t.Errorf("iwreq bytes % x", raw)
	}
	if _, err := newIwreq("a-very-long-ifname", buf, 0); err == nil {
		t.Error("an over-long name accepted")
	}
}

// A set the driver takes without starting a visit (Set_ApOffChanScan_Proc
// returns non-zero from its "Network is down" branch, which the ioctl
// reports as success) is not a refused channel: it leaves no row and no
// error, so the table would go out with a hole. It is retried; missed
// twice, the band fails.
func TestOffChanSilentSet(t *testing.T) {
	c, f, _, _ := offChanUnit(t)
	ctx := context.Background()
	f.silent[4] = 1
	r, _ := c.Spectrum(ctx, "ng")
	res, err := r.Run(ctx, wl.SpectrumRequest{})
	if err != nil {
		t.Fatalf("one silent set, retried: %v", err)
	}
	if got := f.sets(); len(got) != 12 || got[11] != 4 {
		t.Errorf("visits %v: want 1..11 and 4 again", got)
	}
	if len(res.Rows[20]) != 11 {
		t.Errorf("%d rows, want 11", len(res.Rows[20]))
	}
	f.calls = nil
	f.silent[4] = 2
	if _, err := r.Run(ctx, wl.SpectrumRequest{}); !errors.Is(err, wl.ErrIncomplete) {
		t.Errorf("silent twice: %v", err)
	}
}

// A scan already running when the request comes (a driver scan through
// ApSiteSurvey prints no start line) takes our list index and ends with its
// own end line: our start line and one end line, the slot naming our
// channel, but the MLME never started our visit ("start offchannel scan"
// missing) and the slot holds that scan's busy time. Not trusted: visited
// again.
func TestOffChanHijackedVisit(t *testing.T) {
	c, f, _, _ := offChanUnit(t)
	ctx := context.Background()
	f.busy[4] = 8000
	f.hijack[4], f.hijackBusy = 1, 160000
	r, _ := c.Spectrum(ctx, "ng")
	res, err := r.Run(ctx, wl.SpectrumRequest{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := f.sets(); len(got) != 12 || got[11] != 4 {
		t.Errorf("visits %v: want 1..11 and 4 again", got)
	}
	for _, row := range res.Rows[20] {
		if row.Channel == 4 && row.Utilization != 4 {
			t.Errorf("ch 4 utilization %d, want 4 (the real visit, not the other scan's 80)", row.Utilization)
		}
	}
}

// Another `show mibinfo` during a visit (an agent reading, or someone on
// the unit) read-clears Prim CCA Time partway through the dwell: the slot's
// busy time is too low. Two MIB blocks in the visit's log: not trusted.
func TestOffChanSecondMibRead(t *testing.T) {
	c, f, d, _ := offChanUnit(t)
	ctx := context.Background()
	once := true
	f.hook = func(call string) {
		if once && strings.Contains(call, "passive:3:") {
			once = false
			d.log.WriteString(mibFixtureLines)
		}
	}
	r, _ := c.Spectrum(ctx, "ng")
	if _, err := r.Run(ctx, wl.SpectrumRequest{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := f.sets(); len(got) != 12 || got[11] != 3 {
		t.Errorf("visits %v: want 1..11 and 3 again", got)
	}
}

// The pre-clear must come right before the request, or the home channel's
// busy time in between is counted as the visit's (live: ~1.2 ms). A visit
// whose pre-clear-to-request time is long is not trusted; the longest time
// of the band is in the diag.
func TestOffChanPreClearGap(t *testing.T) {
	c, f, _, _ := offChanUnit(t)
	ctx := context.Background()
	f.slowShow[2] = 30 * time.Millisecond
	r, _ := c.Spectrum(ctx, "ng")
	res, err := r.Run(ctx, wl.SpectrumRequest{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := f.sets(); len(got) != 12 || got[11] != 2 {
		t.Errorf("visits %v: want 1..11 and 2 again", got)
	}
	if !slices.ContainsFunc(res.Diag.Notes, func(n string) bool { return strings.Contains(n, "pre-clear to request") }) {
		t.Errorf("no pre-clear gap in the notes %q", res.Diag.Notes)
	}
}

// A Collect already reading the radio (it holds c.mu, and its `show
// mibinfo` would read-clear the counter in a visit's dwell) is waited for
// before the first visit.
func TestOffChanWaitsForCollect(t *testing.T) {
	c, f, _, _ := offChanUnit(t)
	ctx := context.Background()
	visited := make(chan struct{})
	var once bool
	f.hook = func(call string) {
		if !once && strings.HasPrefix(call, "show ") {
			once = true
			close(visited)
		}
	}
	r, _ := c.Spectrum(ctx, "ng")
	c.mu.Lock() // a Collect in flight
	done := make(chan error, 1)
	go func() {
		_, err := r.Run(ctx, wl.SpectrumRequest{})
		done <- err
	}()
	select {
	case <-visited:
		c.mu.Unlock()
		<-done
		t.Fatal("a visit started while a Collect was reading the radio")
	case <-time.After(300 * time.Millisecond):
	}
	c.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(f.sets()) != 11 {
		t.Errorf("visits %v", f.sets())
	}
}

// While a sweep or survey runs, Collect never asks the driver, even for a
// radio it has no reading of yet (none to keep).
func TestCollectNoReadWhileScanning(t *testing.T) {
	c, _, d, _ := offChanUnit(t)
	c.scanning.Store(true)
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range d.iwpriv() {
		if strings.HasPrefix(cmd, "iwpriv ra0 ") {
			t.Errorf("asked %q while scanning", cmd)
		}
	}
	if _, ok := c.cache["ra0"]; ok {
		t.Error("an empty reading was kept")
	}
}

// On the home channel the radio stays where our own stations are: their
// uplink in the dwell is not other networks' use (spectrum-design §4.1
// leaves our own traffic out). The stations' receive airtime the collector
// estimates (µs a second) is taken off the home visit's busy time.
func TestOffChanHomeOwnUplink(t *testing.T) {
	c, f, d, ck := offChanUnit(t)
	ctx := context.Background()
	f.busy[6], f.busy[1] = 40000, 40000
	table := d.next["ra0"]
	c.cache["ra0"] = &radioReading{at: ck.t, staRx: 100_000} // 10 % of the air
	r, _ := c.Spectrum(ctx, "ng")
	res, err := r.Run(ctx, wl.SpectrumRequest{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, row := range res.Rows[20] {
		switch row.Channel {
		case 6:
			if row.Utilization != 10 {
				t.Errorf("home ch 6 utilization %d, want 10 (40 ms busy less 20 ms of our stations' uplink, of 200)", row.Utilization)
			}
		case 1:
			if row.Utilization != 20 {
				t.Errorf("ch 1 utilization %d, want 20 (off the home channel nothing is taken off)", row.Utilization)
			}
		}
	}
	// a stale estimate (after an apply) or an old one is not used
	c.cache["ra0"] = &radioReading{at: ck.t, staRx: 100_000, stale: true}
	d.survey["ra0"], d.next["ra0"], d.reads = "ra0       get_site_survey:\nTotal=0\n", table, 0 // a new survey again
	if res, err = r.Run(ctx, wl.SpectrumRequest{}); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	for _, row := range res.Rows[20] {
		if row.Channel == 6 && row.Utilization != 20 {
			t.Errorf("stale estimate used: home utilization %d", row.Utilization)
		}
	}
}
