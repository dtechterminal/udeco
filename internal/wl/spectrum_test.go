// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is the Collector's clock and sleep in the spectrum tests: a
// sleep advances the clock at once.
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	sleeps []time.Duration
}

func (k *fakeClock) Now() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.t
}

func (k *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	k.mu.Lock()
	k.t = k.t.Add(d)
	k.sleeps = append(k.sleeps, d)
	k.mu.Unlock()
	return nil
}

func (k *fakeClock) slept(d time.Duration) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := 0
	for _, s := range k.sleeps {
		if s == d {
			n++
		}
	}
	return n
}

// capCall is one CALL of a T4 capture: its BSS lines and the chanim read
// right after it.
type capCall struct {
	pass, ch int
	bss      []string
	chanim   string
}

type t4Capture struct {
	chanspec, noise, initial string
	calls                    []capCall
}

// loadT4 cuts a t4_*_chunked.txt capture into the initial chanim read and
// the per-call reads, as taken on .205.
func loadT4(t *testing.T, name string) t4Capture {
	t.Helper()
	var cp t4Capture
	for line := range strings.Lines(string(fixture(t, "spectrum/"+name))) {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case f[0] == "HDR" && cp.chanspec == "":
			_, rest, _ := strings.Cut(line, "chanspec=")
			cp.chanspec, rest, _ = strings.Cut(rest, " noise=")
			cp.noise, _, _ = strings.Cut(rest, " ")
		case f[0] == "CALL":
			c := capCall{}
			for _, kv := range f[2:] {
				k, v, _ := strings.Cut(kv, "=")
				n, _ := strconv.Atoi(v)
				switch k {
				case "pass":
					c.pass = n
				case "ch":
					c.ch = n
				}
			}
			cp.calls = append(cp.calls, c)
		case f[0] == "BSS" && len(cp.calls) > 0:
			cp.calls[len(cp.calls)-1].bss = append(cp.calls[len(cp.calls)-1].bss, strings.TrimSpace(line))
		}
	}
	blocks := chanimBlocks(t, name)
	if len(blocks) < len(cp.calls)+1 {
		t.Fatalf("%s: %d chanim blocks for %d calls", name, len(blocks), len(cp.calls))
	}
	cp.initial = blocks[0]
	for i := range cp.calls {
		cp.calls[i].chanim = blocks[i+1]
	}
	return cp
}

// bssText turns compact "BSS <bssid> <rssi> (<chanspec>)" lines into `wl
// scanresults` text.
func bssText(lines []string) string {
	var b strings.Builder
	for _, l := range lines {
		f := strings.Fields(l)
		fmt.Fprintf(&b, "SSID: \"\"\nMode: Managed\tRSSI: %s dBm\tSNR: 0 dB\tnoise: -95 dBm\nBSSID: %s\tCapability: ESS\n\tChanspec: %s\n\n", f[2], f[1], f[3])
	}
	return b.String()
}

// replay serves one radio's `wl` calls: from a T4 capture (per channel and
// occurrence) or from synthetic records (onScan). Everything else goes to
// the fixture fakeRunner.
type replay struct {
	base  *fakeRunner
	clk   *fakeClock
	radio string
	band  string

	mu        sync.Mutex
	chanspecs []string // served in order; the last repeats
	duringCS  string   // `wl chanspec` while a scan call runs ("" = home)
	noise     string
	cca       string // cca_get_stats output; "" = exit 255
	text      string // chanim_stats all when recs is nil
	recs      map[int]chanimRecord
	byCh      map[int][]capCall
	used      map[int]int
	pending   *capCall
	polls     int
	during    bool
	notReady  bool // scanresults stays "Not Ready" until scanabort
	n         int  // scan calls so far
	preScan   func(r *replay, ch int) error
	onScan    func(r *replay, ch, occ int) error
	block     func(r *replay, ch int) // unlocked, before a scan call is served
	calls     []string
	scanAt    []time.Time
	readyAt   []time.Time
	deferRec  *chanimRecord
	deferN    int
}

func newReplay(radio, band string) *replay {
	return &replay{base: &fakeRunner{}, radio: radio, band: band, used: map[int]int{},
		clk: &fakeClock{t: time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)}}
}

// scanChannel is the -c value of a scan command (0 for a sweep).
func scanChannel(cmd string) int {
	f := strings.Fields(cmd)
	for i := range f {
		if f[i] == "-c" && i+1 < len(f) {
			n, _ := strconv.Atoi(f[i+1])
			return n
		}
	}
	return 0
}

func (r *replay) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := strings.Join(append([]string{name}, args...), " ")
	cmd, ok := strings.CutPrefix(key, "wl -i "+r.radio+" ")
	if ok && strings.HasPrefix(cmd, "scan ") && r.block != nil {
		r.block(r, scanChannel(cmd))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, key)
	if !ok {
		return r.base.Run(ctx, name, args...)
	}
	switch {
	case cmd == "chanspec":
		if r.during && r.duringCS != "" {
			return []byte(r.duringCS + "\n"), nil
		}
		cs := r.chanspecs[0]
		if len(r.chanspecs) > 1 {
			r.chanspecs = r.chanspecs[1:]
		}
		return []byte(cs + "\n"), nil
	case cmd == "noise":
		return []byte(r.noise + "\n"), nil
	case cmd == "chanim_stats all":
		return []byte(r.chanim()), nil
	case strings.HasPrefix(cmd, "cca_get_stats"):
		if r.cca == "" {
			return []byte("Summaries:\nCannot find a good channel due to: Only 1 channel input\n"), errors.New("exit status 255: error")
		}
		return []byte(r.cca), nil
	case cmd == "scanabort":
		r.during, r.notReady = false, false
		return nil, nil
	case strings.HasPrefix(cmd, "scan "):
		ch := scanChannel(cmd)
		if r.preScan != nil {
			if err := r.preScan(r, ch); err != nil {
				return nil, err
			}
		}
		occ := r.used[ch]
		r.used[ch]++
		r.n++
		r.polls = 0
		r.pending = &capCall{}
		if r.onScan != nil {
			if err := r.onScan(r, ch, occ); err != nil {
				r.pending = nil
				return nil, err
			}
		} else if occ < len(r.byCh[ch]) {
			c := r.byCh[ch][occ]
			r.pending, r.text = &c, c.chanim
		}
		r.during = true
		r.scanAt = append(r.scanAt, r.clk.Now())
		return nil, nil
	case cmd == "scanresults":
		if r.pending == nil {
			return nil, errors.New("wl: Not Found")
		}
		if r.polls == 0 || r.notReady {
			r.polls++
			return nil, errors.New("wl: Not Ready")
		}
		r.during = false
		r.readyAt = append(r.readyAt, r.clk.Now())
		return []byte(bssText(r.pending.bss)), nil
	}
	return r.base.Run(ctx, name, args...)
}

func (r *replay) chanim() string {
	if r.recs == nil {
		return r.text
	}
	if r.deferRec != nil {
		if r.deferN--; r.deferN <= 0 {
			r.recs[r.deferRec.Channel] = *r.deferRec
			r.deferRec = nil
		}
	}
	return renderChanim(r.recs)
}

func renderChanim(recs map[int]chanimRecord) string {
	var b strings.Builder
	b.WriteString("version: 3 \nCHAN Interference Measurement:\nStats during last scan:\n")
	chs := make([]int, 0, len(recs))
	for ch := range recs {
		chs = append(chs, ch)
	}
	sort.Ints(chs)
	for _, ch := range chs {
		x := recs[ch]
		fmt.Fprintf(&b, " chanspec: 0x%04x crsglitch cnt: %d bad plcp: %d noise: %d\n\t cca_txdur: %d cca_inbss: %d cca_obss:%d cca_nocat: %d cca_nopkt: %d\n",
			x.CS, x.Glitch, x.BadPLCP, x.Noise, x.TxDur, x.Inbss, x.Obss, x.Nocat, x.Nopkt)
	}
	return b.String() + "\n"
}

// scans returns the radio's scan commands in order.
func (r *replay) scans() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, c := range r.calls {
		if strings.HasPrefix(c, "wl -i "+r.radio+" scan ") {
			out = append(out, strings.TrimPrefix(c, "wl -i "+r.radio+" "))
		}
	}
	return out
}

func (r *replay) count(cmd string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if c == "wl -i "+r.radio+" "+cmd {
			n++
		}
	}
	return n
}

// newSpecCollector builds a Collector over the fixture tree whose wl calls
// for r.radio go to r.
func newSpecCollector(t *testing.T, r *replay) *Collector {
	t.Helper()
	c := New(Options{Root: buildRoot(t), Run: r})
	c.now, c.sleep = r.clk.Now, r.clk.Sleep
	c.ifAddrs = func(name string) ([]net.Addr, error) {
		ip, n, _ := net.ParseCIDR("192.168.0.205/24")
		n.IP = ip
		return []net.Addr{n}, nil
	}
	return c
}

// t4Replay replays a T4 band: home chanspec and noise from its HDR line,
// per-call chanim and BSSes, the T5 cca_get_stats output for the gate.
func t4Replay(t *testing.T, file, radio, band string, cca int) *replay {
	t.Helper()
	cp := loadT4(t, file)
	r := newReplay(radio, band)
	r.chanspecs, r.noise, r.text = []string{cp.chanspec}, cp.noise, cp.initial
	r.byCh = map[int][]capCall{}
	for _, c := range cp.calls {
		r.byCh[c.ch] = append(r.byCh[c.ch], c)
	}
	r.cca = ccaSections(t, "t5_cca_variants.txt")[cca]
	return r
}

func spectrumOf(t *testing.T, c *Collector, band string) *SpectrumRunner {
	t.Helper()
	s, err := c.Spectrum(context.Background(), band)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rowsSummary(rows []SpectrumRow) (chans, util, interf []int) {
	for _, r := range rows {
		chans, util, interf = append(chans, r.Channel), append(util, r.Utilization), append(interf, r.Interference)
	}
	return
}

func channelStat(d SpectrumDiag, ch int) ChannelStat {
	for _, s := range d.Channels {
		if s.Channel == ch {
			return s
		}
	}
	return ChannelStat{}
}

// TestMeasureSpectrumChunked replays the real T4 wl0 band (22 calls, real
// pre/post chanim per call). Expected rows are spectrum-design §2.2 / §4.2
// REV2 (math.Round): ch9 from 20 home rewrites, primary-channel rule.
func TestMeasureSpectrumChunked(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	c := newSpecCollector(t, r)
	s := spectrumOf(t, c, "ng")
	var phases []SpectrumPhase
	guards := 0
	res, err := s.Run(context.Background(), SpectrumRequest{
		Widths:  []int{20, 40},
		Guard:   func(ctx context.Context, st ScanStep) error { guards++; return nil },
		OnPhase: func(p SpectrumPhase) { phases = append(phases, p) },
	})
	if err != nil {
		t.Fatalf("%v (diag %+v)", err, res.Diag.Notes)
	}
	d := res.Diag
	if d.Mode != ModeChunked || d.Fallback != "" || d.HomeControl != 9 || d.HomeNoise != -93 || d.HomeChanspec != "0x1907" {
		t.Errorf("mode %q fallback %q home %d noise %d cs %s", d.Mode, d.Fallback, d.HomeControl, d.HomeNoise, d.HomeChanspec)
	}
	var want []string
	for _, ch := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1} {
		want = append(want, "scan -t passive -p 110 -c "+strconv.Itoa(ch)) // decimal, never 0x1001 [M T2]
	}
	if got := r.scans(); !reflect.DeepEqual(got, want) {
		t.Errorf("scan calls:\n%v\nwant\n%v", got, want)
	}
	if guards != 22 {
		t.Errorf("guard ran %d times", guards)
	}
	for _, cd := range d.Calls {
		if cd.Retry || cd.Class == string(classStale) || cd.Class == string(classZero) {
			t.Errorf("call %+v: the home control call must not be stale (T4 rule)", cd)
		}
	}
	for i := 1; i < len(r.scanAt); i++ {
		if gap := r.scanAt[i].Sub(r.readyAt[i-1]); gap < 400*time.Millisecond {
			t.Errorf("call %d: %v home before it", i+1, gap)
		}
	}
	chans, util, interf := rowsSummary(res.Rows[20])
	if !reflect.DeepEqual(chans, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}) ||
		!reflect.DeepEqual(util, []int{18, 6, 10, 5, 4, 20, 6, 11, 30, 21, 11}) ||
		!reflect.DeepEqual(interf, []int{-69, -59, -56, -54, -53, -53, -53, -53, -50, -54, -56}) {
		t.Errorf("ng/20 rows:\n chans %v\n util %v\n interference %v", chans, util, interf)
	}
	h := channelStat(d, 9)
	if d.HomeSamples != 20 || h.Samples != 20 || h.Class != ClassMeasured || !h.Home {
		t.Errorf("home: |H| %d, stat %+v", d.HomeSamples, h)
	}
	if len(d.BSS) != 24 {
		t.Errorf("%d BSSes merged, T4 found 24", len(d.BSS))
	}
	if d.Airtime != 0.066 || d.AirtimeSource != "cca_get_stats" || d.Defers != 0 {
		t.Errorf("gate: %v %s %d", d.Airtime, d.AirtimeSource, d.Defers)
	}
	if !reflect.DeepEqual(phases, []SpectrumPhase{PhasePending, PhaseScanning, PhaseIdle}) {
		t.Errorf("phases %v", phases)
	}
	st := res.Status
	if st.Abnormal || st.Phase != PhaseIdle || !st.TableTime.Equal(d.Done) || !reflect.DeepEqual(st.Rows, res.Rows) {
		t.Errorf("status %+v", st)
	}
	if r.count("scanabort") != 0 {
		t.Error("scanabort sent on a clean band")
	}
}

// TestBuildRowsHomeFromRewrites: the home block's utilization is the max of
// its parts with the home part from H (§5 REV2).
func TestBuildRowsHomeFromRewrites(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{Widths: []int{40}})
	if err != nil {
		t.Fatal(err)
	}
	chans, util, interf := rowsSummary(res.Rows[40])
	// pairs (c, c+4): 1l 18, 2l 20, 3l 10, 4l 11, 5l (home block 9u) 30, 6l 21, 7l 11 [§5 REV2]
	if !reflect.DeepEqual(chans, []int{1, 2, 3, 4, 5, 6, 7}) || !reflect.DeepEqual(util, []int{18, 20, 10, 11, 30, 21, 11}) || interf[4] != -50 {
		t.Errorf("ng/40: %v %v %v", chans, util, interf)
	}
	if res.Rows[40][4].CenterFreq != 2442 {
		t.Errorf("5l centre %d", res.Rows[40][4].CenterFreq)
	}
	if _, ok := res.Rows[20]; ok {
		t.Error("rows at a width that was not asked for")
	}
}

// TestMeasureSpectrumZeroRecordIsUnmeasured replays the real T4 wl1 band:
// 149-165 ZERO -> unmeasured, no rows for them or their blocks, no fallback,
// pass 2 skips them (13 calls, not 18).
func TestMeasureSpectrumZeroRecordIsUnmeasured(t *testing.T) {
	r := t4Replay(t, "t4_wl1_chunked.txt", "wl1", "na", 2)
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "na").Run(context.Background(), SpectrumRequest{Widths: []int{20, 40, 80}})
	if err != nil {
		t.Fatalf("%v %v", err, res.Diag.Notes)
	}
	d := res.Diag
	var got []int
	for _, sc := range r.scans() {
		got = append(got, scanChannel(sc))
	}
	if !reflect.DeepEqual(got, []int{36, 40, 44, 48, 149, 153, 157, 161, 165, 48, 44, 40, 36}) {
		t.Errorf("calls %v", got)
	}
	if d.Mode != ModeChunked || d.Fallback != "" || !reflect.DeepEqual(d.Unmeasured, []int{149, 153, 157, 161, 165}) {
		t.Errorf("mode %s fallback %q unmeasured %v", d.Mode, d.Fallback, d.Unmeasured)
	}
	chans, util, interf := rowsSummary(res.Rows[20])
	if !reflect.DeepEqual(chans, []int{36, 40, 44, 48}) || !reflect.DeepEqual(interf, []int{-78, -72, -78, -78}) || !reflect.DeepEqual(util, []int{2, 8, 2, 4}) {
		t.Errorf("na/20: %v %v %v", chans, util, interf)
	}
	chans, util, interf = rowsSummary(res.Rows[40])
	if !reflect.DeepEqual(chans, []int{36, 44}) || !reflect.DeepEqual(util, []int{8, 4}) || !reflect.DeepEqual(interf, []int{-72, -78}) {
		t.Errorf("na/40: %v %v %v", chans, util, interf)
	}
	if rows := res.Rows[80]; len(rows) != 1 || rows[0].Channel != 36 || rows[0].CenterFreq != 5210 || rows[0].Utilization != 8 || rows[0].Interference != -72 {
		t.Errorf("na/80: %+v", rows)
	}
	if !reflect.DeepEqual(d.Omitted, map[int][]int{20: {149, 153, 157, 161, 165}, 40: {149, 157}, 80: {149}}) {
		t.Errorf("omitted %v", d.Omitted)
	}
	for _, ch := range []int{149, 153, 157, 161, 165} {
		if st := channelStat(d, ch); st.Class != ClassUnmeasured || st.Zero != 1 || st.Util != 0 {
			t.Errorf("ch%d %+v", ch, st)
		}
	}
	if res.Status.Abnormal {
		t.Error("a table without UNII-3 is not abnormal (§6.6 REV2)")
	}
}

// synth sets up synthetic chanim records for a radio whose home control
// channel is home: every off-channel call writes a fresh record for its
// channel and rewrites the home record; a sweep (ch 0) refreshes them all.
// custom, if set, runs after that and may change anything.
func synth(r *replay, chans []int, home int, custom func(r *replay, ch, occ int) error) {
	csOf := func(ch int) uint16 {
		if r.band == "ng" {
			return 0x1000 | uint16(ch)
		}
		return 0xd000 | uint16(ch)
	}
	fresh := func(ch, n int) chanimRecord {
		return chanimRecord{CS: csOf(ch), Channel: ch, Glitch: 100 + n, BadPLCP: 1, Noise: -101, Obss: 2, Nocat: 1, Nopkt: 1}
	}
	homeRec := func(n int) chanimRecord {
		return chanimRecord{CS: csOf(home), Channel: home, Glitch: 300 + n, Noise: -95, TxDur: 5, Obss: 5, Nocat: 2, Nopkt: 1}
	}
	r.recs = map[int]chanimRecord{}
	for _, ch := range chans {
		r.recs[ch] = fresh(ch, 0)
	}
	r.recs[home] = homeRec(0)
	r.onScan = func(r *replay, ch, occ int) error {
		switch {
		case ch == 0:
			for _, x := range chans {
				r.recs[x] = fresh(x, r.n)
			}
			r.recs[home] = homeRec(r.n)
		case ch != home:
			r.recs[ch] = fresh(ch, r.n)
			r.recs[home] = homeRec(r.n)
		}
		if custom != nil {
			return custom(r, ch, occ)
		}
		return nil
	}
}

var (
	ngChans = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	naChans = []int{36, 40, 44, 48, 149, 153, 157, 161, 165}
)

func synthReplay(band string, custom func(r *replay, ch, occ int) error) *replay {
	if band == "ng" {
		r := newReplay("wl0", "ng")
		r.chanspecs, r.noise = []string{"9u (0x1907)"}, "-93"
		synth(r, ngChans, 9, custom)
		return r
	}
	r := newReplay("wl1", "na")
	r.chanspecs, r.noise = []string{"40/80 (0xe12a)"}, "-96"
	synth(r, naChans, 40, custom)
	return r
}

// TestUnmeasuredIsSticky: 149's near-empty record (glitch 8, nopkt 1, T2)
// passes both rules in pass 1; a later ZERO makes it unmeasured for this
// band and the next, even when the next band's records look OK.
func TestUnmeasuredIsSticky(t *testing.T) {
	band := 1
	r := synthReplay("na", func(r *replay, ch, occ int) error {
		if ch == 149 && band == 1 {
			r.recs[149] = chanimRecord{CS: 0xd095, Channel: 149, Noise: -100}
			if occ == 0 {
				r.recs[149] = chanimRecord{CS: 0xd095, Channel: 149, Glitch: 8, Noise: -99, Nopkt: 1}
			}
		}
		return nil
	})
	c := newSpecCollector(t, r)
	s := spectrumOf(t, c, "na")
	req := SpectrumRequest{Widths: []int{20, 80}, SkipGate: true}
	res, err := s.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if st := channelStat(res.Diag, 149); st.Class != ClassUnmeasured || st.Zero != 1 {
		t.Errorf("band 1: 149 %+v", st)
	}
	chans, _, _ := rowsSummary(res.Rows[20])
	if slices.Contains(chans, 149) || len(chans) != 8 || len(res.Rows[80]) != 1 {
		t.Errorf("band 1 rows: 20 %v, 80 %+v", chans, res.Rows[80])
	}
	n1 := len(r.scans())
	band = 2
	res, err = s.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if st := channelStat(res.Diag, 149); st.Class != ClassUnmeasured || st.Samples != 1 {
		t.Errorf("band 2: 149 %+v (probed once, still unmeasured)", st)
	}
	c149 := 0
	for _, sc := range r.scans()[n1:] {
		if scanChannel(sc) == 149 {
			c149++
		}
	}
	if c149 != 1 {
		t.Errorf("band 2 called 149 %d times; pass 2 must skip it", c149)
	}
	if chans, _, _ := rowsSummary(res.Rows[20]); slices.Contains(chans, 149) {
		t.Errorf("band 2 rows %v", chans)
	}
}

// TestHomeRewriteZeroDropped: all-zero home rewrites (wl1 after -c 157,
// T2) are not folded into H; fewer than MinHome leaves the home control
// channel missing and the band incomplete.
func TestHomeRewriteZeroDropped(t *testing.T) {
	r := synthReplay("na", func(r *replay, ch, occ int) error {
		if r.n > 3 && ch != 40 {
			r.recs[40] = chanimRecord{CS: 0xd028, Channel: 40, Noise: -96 - r.n%2}
		}
		return nil
	})
	c := newSpecCollector(t, r)
	s := spectrumOf(t, c, "na")
	res, err := s.Run(context.Background(), SpectrumRequest{Widths: []int{20}, SkipGate: true})
	if !errors.Is(err, ErrIncomplete) || res.Rows != nil {
		t.Fatalf("err %v rows %v", err, res.Rows)
	}
	// calls 1 (36) and 3 (44) rewrote the home record; call 2 is the home
	// control call itself; every later rewrite is all-zero
	if res.Diag.HomeSamples != 2 || channelStat(res.Diag, 40).Class != ClassMissing {
		t.Errorf("|H| %d, 40 %+v", res.Diag.HomeSamples, channelStat(res.Diag, 40))
	}
	zero := 0
	for _, cd := range res.Diag.Calls {
		if cd.HomeRewrite == string(classZero) {
			zero++
		}
	}
	if zero == 0 || !res.Status.Abnormal {
		t.Errorf("zero rewrites %d, abnormal %v", zero, res.Status.Abnormal)
	}
}

func TestMeasureSpectrumStaleRetry(t *testing.T) {
	cases := []struct {
		name    string
		stale   int // 1: first read only, 2: both reads, 3: call and retry
		retried bool
		err     error
	}{
		{"fresh on the re-read", 1, false, nil},
		{"fresh on the retry", 2, true, nil},
		{"stale after retry", 3, true, ErrIncomplete},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := synthReplay("ng", nil)
			old := r.recs[3]
			first := r.onScan
			r.onScan = func(r *replay, ch, occ int) error {
				if err := first(r, ch, occ); err != nil {
					return err
				}
				if ch != 3 || r.used[3] > 2 {
					return nil
				}
				switch {
				case tc.stale == 1 && occ == 0:
					d := r.recs[3]
					r.recs[3], r.deferRec, r.deferN = old, &d, 2
				case tc.stale == 2 && occ == 0, tc.stale == 3 && occ <= 1:
					r.recs[3] = old
				}
				return nil
			}
			c := newSpecCollector(t, r)
			res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{SkipGate: true})
			if !errors.Is(err, tc.err) && !(err == nil && tc.err == nil) {
				t.Fatalf("err %v", err)
			}
			var pass1, retries []int
			for _, cd := range res.Diag.Calls {
				if cd.Pass == 1 {
					pass1 = append(pass1, cd.Channel)
				}
				if cd.Retry {
					retries = append(retries, cd.Channel)
				}
			}
			if wantR := map[bool][]int{true: {3}}[tc.retried]; !reflect.DeepEqual(retries, wantR) {
				t.Errorf("retried %v, want %v", retries, wantR)
			}
			want := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
			if tc.retried {
				want = append(want, 3)
			}
			if !reflect.DeepEqual(pass1, want) {
				t.Errorf("pass 1 calls %v", pass1)
			}
			if r.clk.slept(100*time.Millisecond) == 0 {
				t.Error("no 100 ms re-read")
			}
			if tc.err != nil {
				// still STALE after its retry: the 20 MHz row for 3 can no
				// longer be built, so pass 2 is not run (12 calls, not 23)
				// and, with no call running, no scanabort is sent
				if n := len(res.Diag.Calls); n != 12 || r.count("scanabort") != 0 {
					t.Errorf("%d calls, %d scanabort after the early stop", n, r.count("scanabort"))
				}
				if !strings.Contains(err.Error(), "[3]") {
					t.Errorf("err %v does not name block 3", err)
				}
			} else if st := channelStat(res.Diag, 3); st.Class != ClassMeasured {
				t.Errorf("ch3 %+v", st)
			}
			if res.Diag.Fallback != "" {
				t.Errorf("fallback %q", res.Diag.Fallback)
			}
		})
	}
}

// TestMeasureSpectrumFallsBackToSweep: -c calls never refresh chanim (a
// firmware unlike .205). The first two non-home channels end STALE after
// their retry -> whole-band sweeps at -p 110, remembered for the radio.
func TestMeasureSpectrumFallsBackToSweep(t *testing.T) {
	r := synthReplay("ng", nil)
	first := r.onScan
	r.onScan = func(r *replay, ch, occ int) error {
		if ch == 0 {
			return first(r, ch, occ)
		}
		return nil // -c leaves every record as it was
	}
	c := newSpecCollector(t, r)
	s := spectrumOf(t, c, "ng")
	res, err := s.Run(context.Background(), SpectrumRequest{SkipGate: true})
	if err != nil {
		t.Fatalf("%v %v", err, res.Diag.Notes)
	}
	sc := r.scans()
	var chunked, sweeps int
	for _, x := range sc {
		if scanChannel(x) != 0 {
			chunked++
		} else if x == "scan -t passive -p 110" {
			sweeps++
		}
	}
	// 11 calls of pass 1, then the retries of 1 and 2 decide it
	if chunked != 13 || sweeps != 2 || len(sc) != 15 {
		t.Errorf("%d chunked, %d sweeps: %v", chunked, sweeps, sc)
	}
	if res.Diag.Mode != ModeSweep || res.Diag.Fallback == "" || len(res.Rows[20]) != 11 {
		t.Errorf("mode %s fallback %q rows %d", res.Diag.Mode, res.Diag.Fallback, len(res.Rows[20]))
	}
	if st := channelStat(res.Diag, 9); st.Class != ClassMeasured || st.Samples != 2 {
		t.Errorf("home in a sweep is classified like any channel: %+v", st)
	}
	// the gap is HomeGap, the client guard, then the rest (sweepPause)
	if n := r.clk.slept(10*time.Second - DefaultScanPlan().HomeGap); n != 1 {
		t.Errorf("sweep gap slept %d times", n)
	}
	// remembered: the next band starts with the sweep
	res, err = s.Run(context.Background(), SpectrumRequest{SkipGate: true})
	if err != nil || res.Diag.Mode != ModeSweep || res.Diag.Fallback != "" || scanChannel(r.scans()[15]) != 0 {
		t.Errorf("second band: %v mode %s fallback %q", err, res.Diag.Mode, res.Diag.Fallback)
	}
}

// TestMeasureSpectrumHexRejectedFallsBack: a -c syntax the firmware rejects
// (exit 254, as hex was on .205) switches to the sweep at once.
func TestMeasureSpectrumHexRejectedFallsBack(t *testing.T) {
	r := synthReplay("ng", nil)
	r.preScan = func(r *replay, ch int) error {
		if ch != 0 {
			return fmt.Errorf("exit status 254: could not parse chanspec starting at \"%d\"", ch)
		}
		return nil
	}
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{SkipGate: true})
	if err != nil {
		t.Fatal(err)
	}
	if sc := r.scans(); len(sc) != 3 || scanChannel(sc[0]) != 1 || res.Diag.Mode != ModeSweep || !strings.Contains(res.Diag.Fallback, "-c 1") {
		t.Errorf("calls %v mode %s fallback %q", sc, res.Diag.Mode, res.Diag.Fallback)
	}
}

// TestMeasureSpectrumStaleRecordIsMissing: chanim never changes, neither
// for -c nor for the sweep. Retry, switch to the sweep, never rows built
// from the unchanged records; the old table stays.
func TestMeasureSpectrumStaleRecordIsMissing(t *testing.T) {
	r := synthReplay("ng", nil)
	r.onScan = func(r *replay, ch, occ int) error { return nil }
	c := newSpecCollector(t, r)
	s := spectrumOf(t, c, "ng")
	old := map[int][]SpectrumRow{20: {{Channel: 1, Width: 20, CenterFreq: 2412, Utilization: 1, Interference: -90}}}
	oldTime := r.clk.Now().Add(-time.Hour)
	s.rows, s.tableTime = old, oldTime
	res, err := s.Run(context.Background(), SpectrumRequest{SkipGate: true})
	if !errors.Is(err, ErrIncomplete) || res.Rows != nil {
		t.Fatalf("err %v rows %v", err, res.Rows)
	}
	if n := r.count("scanabort"); n != 0 {
		t.Errorf("%d scanabort after a band that finished its calls", n)
	}
	if res.Diag.Mode != ModeSweep || res.Diag.Fallback == "" {
		t.Errorf("mode %s fallback %q", res.Diag.Mode, res.Diag.Fallback)
	}
	st := res.Status
	if !st.Abnormal || !reflect.DeepEqual(st.Rows, old) || !st.TableTime.Equal(oldTime) || st.Age(r.clk.Now()) < 3600 {
		t.Errorf("status %+v", st)
	}
}

// TestAllZeroBandFails: every channel ZERO (and every home rewrite zero) ->
// the band fails, the previous table stays.
func TestAllZeroBandFails(t *testing.T) {
	zero := false
	r := synthReplay("na", func(r *replay, ch, occ int) error {
		if zero {
			for _, x := range naChans {
				r.recs[x] = chanimRecord{CS: 0xd000 | uint16(x), Channel: x, Noise: -100 - r.n%2}
			}
		}
		return nil
	})
	c := newSpecCollector(t, r)
	s := spectrumOf(t, c, "na")
	good, err := s.Run(context.Background(), SpectrumRequest{SkipGate: true})
	if err != nil {
		t.Fatal(err)
	}
	zero = true
	res, err := s.Run(context.Background(), SpectrumRequest{SkipGate: true})
	if err == nil || res.Rows != nil {
		t.Fatalf("all-zero band: %v %v", err, res.Rows)
	}
	if !res.Status.Abnormal || !reflect.DeepEqual(res.Status.Rows, good.Rows) || !res.Status.TableTime.Equal(good.Status.TableTime) {
		t.Errorf("status %+v", res.Status)
	}
	for _, st := range res.Diag.Channels {
		if st.Channel != 40 && st.Class != ClassUnmeasured {
			t.Errorf("ch%d %s", st.Channel, st.Class)
		}
	}

	// in sweep mode the home channel is ZERO too: nothing measurable -> no rows
	r2 := synthReplay("na", func(r *replay, ch, occ int) error {
		for _, x := range naChans {
			r.recs[x] = chanimRecord{CS: 0xd000 | uint16(x), Channel: x, Noise: -100 - r.n%2}
		}
		return nil
	})
	s2 := spectrumOf(t, newSpecCollector(t, r2), "na")
	s2.sweep = true
	if _, err := s2.Run(context.Background(), SpectrumRequest{SkipGate: true}); !errors.Is(err, ErrNoRows) {
		t.Errorf("sweep all zero: %v", err)
	}
}

func TestMeasureSpectrumBusyRetry(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	busy := 2
	r.preScan = func(r *replay, ch int) error {
		if busy > 0 {
			busy--
			return errors.New("wl: Busy")
		}
		return nil
	}
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{SkipGate: true})
	if err != nil || res.Diag.BusyRetries != 2 || r.clk.slept(time.Second) != 2 || len(res.Rows[20]) != 11 {
		t.Errorf("err %v, %d busy retries, %d 1 s sleeps", err, res.Diag.BusyRetries, r.clk.slept(time.Second))
	}

	// still busy after 3 retries: the band fails, the mode is kept
	r = t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	r.preScan = func(r *replay, ch int) error { return errors.New("wl: Busy") }
	c = newSpecCollector(t, r)
	s := spectrumOf(t, c, "ng")
	res, err = s.Run(context.Background(), SpectrumRequest{SkipGate: true})
	// no scanabort: the running scan is someone else's (acsd2)
	if !errors.Is(err, errBusy) || len(r.scans()) != 4 || s.sweepMode() || !res.Status.Abnormal || r.count("scanabort") != 0 {
		t.Errorf("err %v, %d scan calls, sweep %v", err, len(r.scans()), s.sweepMode())
	}
}

func TestMeasureSpectrumGuardAbort(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{SkipGate: true,
		Guard: func(ctx context.Context, st ScanStep) error {
			if st.Call == 5 {
				return errors.New("stop")
			}
			return nil
		}})
	// the guard stops the band between calls: no scan of ours is running,
	// so no scanabort (it would only cut short whatever else scans)
	if !errors.Is(err, ErrScanAborted) || len(r.scans()) != 4 || r.count("scanabort") != 0 || res.Rows != nil || !res.Status.Abnormal {
		t.Errorf("err %v, %d scans, %d scanabort", err, len(r.scans()), r.count("scanabort"))
	}
	if r.count("chanspec") != 2 || res.Diag.ChanspecAfter != "9u (0x1907)" {
		t.Errorf("chanspec reads %d, after %q", r.count("chanspec"), res.Diag.ChanspecAfter)
	}
}

func TestMeasureSpectrumBudget(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	c := newSpecCollector(t, r)
	plan := DefaultScanPlan()
	plan.Budget = 3 * time.Second
	res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{SkipGate: true, Plan: &plan})
	// the budget is checked between calls: nothing of ours is in flight
	if !errors.Is(err, ErrScanAborted) || r.count("scanabort") != 0 || res.Rows != nil {
		t.Errorf("err %v, scanabort %d", err, r.count("scanabort"))
	}
	if n := len(r.scans()); n < 4 || n > 8 {
		t.Errorf("%d calls inside a 3 s budget", n)
	}
}

func TestMeasureSpectrumCancel(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	ctx, cancel := context.WithCancel(context.Background())
	r.block = func(r *replay, ch int) {
		if ch == 3 {
			cancel()
		}
	}
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "ng").Run(ctx, SpectrumRequest{SkipGate: true})
	if !errors.Is(err, ErrScanAborted) || r.count("scanabort") != 1 || !res.Status.Abnormal {
		t.Errorf("err %v, scanabort %d", err, r.count("scanabort"))
	}
}

// TestMeasureSpectrumCallMax: a call whose results never come is aborted
// at CallMax and counts as STALE (retried at the end of the pass).
func TestMeasureSpectrumCallMax(t *testing.T) {
	r := synthReplay("ng", func(r *replay, ch, occ int) error {
		r.notReady = ch == 4 && occ == 0
		return nil
	})
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{SkipGate: true})
	if err != nil || r.count("scanabort") != 1 || channelStat(res.Diag, 4).Class != ClassMeasured {
		t.Fatalf("err %v, scanabort %d, ch4 %+v", err, r.count("scanabort"), channelStat(res.Diag, 4))
	}
	if cd := res.Diag.Calls[3]; cd.Channel != 4 || cd.Class != string(classStale) || cd.Took < time.Second {
		t.Errorf("call 4 %+v", cd)
	}
}

func TestMeasureSpectrumChanspecRestored(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	r.chanspecs = []string{"9u (0x1907)", "9u (0x1907)", "1 (0x1001)"} // gate, band start, after
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{})
	if !errors.Is(err, ErrChanspecChanged) || res.Rows != nil || !res.Status.Abnormal || res.Diag.ChanspecAfter != "1 (0x1001)" {
		t.Errorf("err %v, status %+v", err, res.Status)
	}
}

const wl02Clients = "assoclist 8C:BF:EA:1D:BA:74\nassoclist F8:17:2D:6A:16:CC\nassoclist FC:3C:D7:CA:38:BB\nassoclist F4:CF:A2:1E:72:64\n"

func without(list string, macs ...string) string {
	for _, m := range macs {
		list = strings.Replace(list, "assoclist "+m+"\n", "", 1)
	}
	return list
}

// staRow is one station of a synthetic `wl sta_info all`.
type staRow struct {
	mac         string
	idle, inNet int // seconds
	fail        int // tx failures
}

func staText(rows ...staRow) string {
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "[VER 8] STA %s:\n\t idle %d seconds\n\t in network %d seconds\n\t tx failures: %d\n", r.mac, r.idle, r.inNet, r.fail)
	}
	return b.String()
}

const (
	cA, cB, cC, cD = "8C:BF:EA:1D:BA:74", "F8:17:2D:6A:16:CC", "FC:3C:D7:CA:38:BB", "F4:CF:A2:1E:72:64"
)

// assocSeq is n assoclist reads of the four wl02 clients, the i-th without
// the MACs gone[i] lists (the last one repeats).
func assocSeq(gone ...[]string) []response {
	out := make([]response, len(gone))
	for i, g := range gone {
		out[i] = response{out: without(wl02Clients, g...)}
	}
	return out
}

func repeatN[T any](n int, v T) []T {
	out := make([]T, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// TestClientDropIdleIoTNoAbort: an idle start-set station (an IoT device
// on its own timer, idle 30 s at the start of every call) leaves right
// after an off-channel call: background churn, the band completes. A
// station that joined after the band started is never judged.
func TestClientDropIdleIoTNoAbort(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	sta := staText(staRow{cA, 30, 1200, 0}, staRow{cB, 0, 900, 0}, staRow{cC, 1, 900, 0}, staRow{cD, 3, 10, 0})
	r.base.set("wl -i wl02 sta_info all", response{out: sta})
	// gone after call 5 (off-channel): A (idle) and D (joined 10 s before the band)
	r.base.set("wl -i wl02 assoclist", append(assocSeq(repeatN(5, []string(nil))...), assocSeq([]string{cA, cD})...)...)
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{SkipGate: true})
	if err != nil || len(res.Rows[20]) != 11 {
		t.Fatalf("idle IoT drop aborted the band: %v", err)
	}
	d := res.Diag
	if d.Clients != 3 || len(d.Drops) != 1 {
		t.Fatalf("clients %d drops %+v", d.Clients, d.Drops)
	}
	if dd := d.Drops[0]; dd.OUI != "8c:bf:ea" || dd.ScanCaused || !dd.Associated || dd.Idle != 30*time.Second || dd.Background != 1 || dd.SinceCall < 0 || dd.SinceCall > 2*time.Second {
		t.Errorf("drop %+v", dd)
	}
}

// TestClientDropActiveAborts: a station active at the start of an
// off-channel call (idle 0 s, or its tx failures rising) that is gone right
// after it aborts the band at once. No scanabort: the call had finished.
func TestClientDropActiveAborts(t *testing.T) {
	for _, tc := range []struct {
		name string
		sta  []response
	}{
		{"idle 0 s", []response{{out: staText(staRow{cA, 20, 1200, 0}, staRow{cB, 0, 900, 0})}}},
		{"tx failures rising", []response{
			{out: staText(staRow{cA, 20, 1200, 0}, staRow{cB, 9, 900, 4})}, // start set
			{out: staText(staRow{cA, 20, 1200, 0}, staRow{cB, 9, 900, 4})}, // before call 1
			{out: staText(staRow{cA, 20, 1200, 0}, staRow{cB, 9, 900, 7})}, // before call 2
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
			r.base.set("wl -i wl02 sta_info all", tc.sta...)
			r.base.set("wl -i wl02 assoclist", assocSeq(nil, nil, []string{cB})...)
			c := newSpecCollector(t, r)
			res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{SkipGate: true})
			if !errors.Is(err, ErrScanAborted) || len(r.scans()) != 2 || r.count("scanabort") != 0 || !res.Status.Abnormal {
				t.Fatalf("err %v, %d scans, %d scanabort", err, len(r.scans()), r.count("scanabort"))
			}
			if d := res.Diag.Drops; len(d) != 1 || !d[0].ScanCaused || !d[0].Associated || d[0].OUI != "f8:17:2d" || d[0].Vif != "wl02" {
				t.Errorf("drops %+v", d)
			}
		})
	}
}

// TestClientDropChurnAborts: three idle start-set stations leave one after
// the other: two background drops are allowed, the third aborts.
func TestClientDropChurnAborts(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	r.base.set("wl -i wl02 sta_info all", response{out: staText(staRow{cA, 40, 1200, 0}, staRow{cB, 40, 900, 0}, staRow{cC, 40, 900, 0}, staRow{cD, 40, 900, 0})})
	seq := assocSeq(repeatN(3, []string(nil))...)
	seq = append(seq, assocSeq(repeatN(4, []string{cA})...)...)
	seq = append(seq, assocSeq([]string{cA, cC}, []string{cA, cC}, []string{cA, cC, cD})...)
	r.base.set("wl -i wl02 assoclist", seq...)
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{SkipGate: true})
	if !errors.Is(err, ErrScanAborted) || len(r.scans()) != 9 || !strings.Contains(err.Error(), "3 start-set clients") {
		t.Fatalf("err %v, %d scans", err, len(r.scans()))
	}
	d := res.Diag.Drops
	if len(d) != 3 || d[0].ScanCaused || d[1].ScanCaused || d[2].ScanCaused || d[2].Background != 3 {
		t.Errorf("drops %+v", d)
	}
	// the first background drop alone does not abort (pre-change: the
	// second drop of any kind did)
	r = t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	r.base.set("wl -i wl02 sta_info all", response{out: staText(staRow{cA, 40, 1200, 0}, staRow{cB, 40, 900, 0}, staRow{cC, 40, 900, 0})})
	r.base.set("wl -i wl02 assoclist", append(assocSeq(nil, []string{cA}), assocSeq([]string{cA, cC})...)...)
	if res, err := spectrumOf(t, newSpecCollector(t, r), "ng").Run(context.Background(), SpectrumRequest{SkipGate: true}); err != nil || len(res.Diag.Drops) != 2 {
		t.Errorf("two background drops: %v %+v", err, res.Diag.Drops)
	}
}

// TestClientDropSweepScanCaused: in the fallback sweep (about 1.5 s off
// channel per pass) a station active at the start of a sweep and gone
// right after it aborts the band at once. The guard looks HomeGap into the
// SweepGap pause, not 10 s later at the next sweep, where the drop would be
// taken for background churn and the band would go on.
func TestClientDropSweepScanCaused(t *testing.T) {
	r := synthReplay("ng", nil)
	r.base.set("wl -i wl02 sta_info all", response{out: staText(staRow{cA, 30, 1200, 0}, staRow{cB, 0, 900, 0})})
	r.base.set("wl -i wl02 assoclist", assocSeq(nil, []string{cB})...)
	s := spectrumOf(t, newSpecCollector(t, r), "ng")
	s.sweep = true
	res, err := s.Run(context.Background(), SpectrumRequest{SkipGate: true})
	if !errors.Is(err, ErrScanAborted) || len(r.scans()) != 1 || !res.Status.Abnormal {
		t.Fatalf("err %v, %d scans: %v", err, len(r.scans()), r.scans())
	}
	if d := res.Diag.Drops; len(d) != 1 || !d[0].ScanCaused || d[0].OUI != "f8:17:2d" || d[0].SinceCall > DefaultScanPlan().DropWindow {
		t.Errorf("drops %+v", d)
	}
}

func TestRadioSkipped(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	c := newSpecCollector(t, r)
	s := spectrumOf(t, c, "ng")
	res, err := s.Run(context.Background(), SpectrumRequest{Uplink: "wl02"})
	if !errors.Is(err, ErrRadioSkipped) || len(r.scans()) != 0 || res.Status.Abnormal {
		t.Errorf("wireless uplink: %v, %d scans, abnormal %v", err, len(r.scans()), res.Status.Abnormal)
	}
	// a dwds (backhaul) vif with a peer: a wireless child would lose its link
	r.base.set("wl -i wl01 assoclist", response{out: "assoclist 00:11:22:33:44:55\n"})
	if _, err := s.Run(context.Background(), SpectrumRequest{}); !errors.Is(err, ErrRadioSkipped) || len(r.scans()) != 0 {
		t.Errorf("backhaul peer: %v", err)
	}
	if _, err := c.Spectrum(context.Background(), "6e"); err == nil {
		t.Error("6 GHz runner")
	}
}

func TestOwnBSSIDsLeftOut(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	c := newSpecCollector(t, r)
	res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{SkipGate: true, OwnBSSIDs: []string{"B4:A7:C6:17:E3:F4"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range res.Diag.BSS {
		if b.BSSID == "b4:a7:c6:17:e3:f4" {
			t.Error("own BSSID in the neighbour list")
		}
	}
	if len(res.Diag.BSS) != 23 {
		t.Errorf("%d BSSes", len(res.Diag.BSS))
	}
}

// TestAirtimeGateDefers: own airtime 50 % three times -> three 20 s
// deferrals, then the band runs with a 1 s home gap (§8.1).
func TestAirtimeGateDefers(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	r.cca = strings.Repeat("9   1004  500 50% High    100 10% Low      0  0% Low    4003\n", 5)
	c := newSpecCollector(t, r)
	var phases []SpectrumPhase
	res, err := spectrumOf(t, c, "ng").Run(context.Background(), SpectrumRequest{OnPhase: func(p SpectrumPhase) { phases = append(phases, p) }})
	if err != nil {
		t.Fatal(err)
	}
	d := res.Diag
	if d.Defers != 3 || d.Airtime != 0.5 || d.HomeGap != time.Second || r.clk.slept(20*time.Second) != 3 || r.count("cca_get_stats -c 0 -s 5 -i") != 3 {
		t.Errorf("defers %d airtime %v gap %v", d.Defers, d.Airtime, d.HomeGap)
	}
	for i := 1; i < len(r.scanAt); i++ {
		if gap := r.scanAt[i].Sub(r.readyAt[i-1]); gap < time.Second {
			t.Errorf("call %d: home gap %v", i+1, gap)
		}
	}
	if !reflect.DeepEqual(phases, []SpectrumPhase{PhasePending, PhaseScanning, PhaseIdle}) {
		t.Errorf("phases %v", phases)
	}
}

func usRow(tx, inbss, total uint64) string {
	return "version: 3 \nus version: 2 \nchanspec  tx  inbss  obss  nocat  nopkt  doze  txop  goodtx  badtx  total_tm  busy_tm  pri20  sec20  sec40\n" +
		fmt.Sprintf("0x1907  %d  %d  1  1  1  0  1  1  1  %d  5  1  1  0\n", tx, inbss, total)
}

func TestOwnAirtime(t *testing.T) {
	r := newReplay("wl9", "ng") // not a radio of the fixture: every call goes to base
	c := newSpecCollector(t, r)
	fr := r.base
	v := ccaSections(t, "t5_cca_variants.txt")

	fr.set("wl -i wl0 cca_get_stats -c 0 -s 5 -i", response{out: v[0]})
	if own, src, err := c.OwnAirtime(context.Background(), "wl0", 9, 0); err != nil || src != "cca_get_stats" || own != 0.066 {
		t.Errorf("cca: %v %s %v", own, src, err)
	}

	// exit 255 (or no row for the home channel): chanim_stats us over the
	// wall clock. total_tm moved 1.004 s in 2 s of wall time; tx 0.3 s -> 0.15, not 0.30
	fr.set("wl -i wl0 cca_get_stats -c 0 -s 5 -i", response{out: v[1], err: errors.New("exit status 255: error")})
	var big uint64 = 1<<64 - 100_000 // u64 wrap between the reads
	fr.set("wl -i wl0 chanim_stats us", response{out: usRow(big, 7, 4_000_000)}, response{out: usRow(big+300_000, 7, 5_004_000)})
	own, src, err := c.OwnAirtime(context.Background(), "wl0", 9, 2*time.Second)
	if err != nil || src != "chanim_stats us" || own < 0.1499 || own > 0.1501 {
		t.Errorf("fallback: %v %s %v", own, src, err)
	}
	fr.set("wl -i wl0 cca_get_stats -c 0 -s 5 -i", response{out: v[0]})
	if _, _, err := c.OwnAirtime(context.Background(), "wl0", 6, 2*time.Second); err != nil {
		t.Errorf("no cca row for 6, chanim fallback: %v", err)
	}
}

// TestCollectDuringScanKeepsHomeChanspec: while a band runs, Collect
// reports the band-start chanspec and never reads `wl chanspec`, which
// shows the scan channel mid-call [M T7].
func TestCollectDuringScanKeepsHomeChanspec(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	r.duringCS = "1 (0x1001)"
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.block = func(r *replay, ch int) {
		once.Do(func() {
			r.mu.Lock()
			r.during = true
			r.mu.Unlock()
			close(entered)
			<-release
		})
	}
	c := newSpecCollector(t, r)
	s := spectrumOf(t, c, "ng")
	done := make(chan error)
	go func() {
		_, err := s.Run(context.Background(), SpectrumRequest{SkipGate: true})
		done <- err
	}()
	<-entered
	if st := s.Status(); st.Phase != PhaseScanning {
		t.Errorf("phase %s", st.Phase)
	}
	snap, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rad := range snap.Radios {
		if rad.Iface == "wl0" {
			found = true
			if rad.Channel != 9 || rad.Width != 40 || rad.Noise != -93 {
				t.Errorf("wl0 during the band: channel %d width %d noise %d", rad.Channel, rad.Width, rad.Noise)
			}
		}
	}
	if !found {
		t.Error("no wl0 in the snapshot")
	}
	if n := r.count("chanspec"); n != 1 {
		t.Errorf("%d chanspec reads during the band (only the band-start one allowed)", n)
	}
	if n := r.count("chanim_stats us"); n != 0 {
		t.Errorf("chanim_stats us read during the band")
	}
	// a health check waits for the band
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c.WithoutScan(ctx, func(context.Context) error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("WithoutScan during a band: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ran := false
	if err := c.WithoutScan(context.Background(), func(context.Context) error { ran = true; return nil }); err != nil || !ran {
		t.Errorf("WithoutScan after the band: %v %v", err, ran)
	}
	// after the band Collect reads the radio again
	if _, err := c.Collect(context.Background()); err != nil || r.count("chanspec") != 3 {
		t.Errorf("after: %v, %d chanspec reads", err, r.count("chanspec"))
	}
}

func TestSpectrumStatusClear(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	c := newSpecCollector(t, r)
	s := spectrumOf(t, c, "ng")
	if s2 := spectrumOf(t, c, "ng"); s2 != s || s.Radio() != "wl0" {
		t.Error("runner not reused")
	}
	if st := s.Status(); st.Phase != PhaseIdle || st.Rows != nil || st.Age(r.clk.Now()) != 0 {
		t.Errorf("fresh status %+v", st)
	}
	res, err := s.Run(context.Background(), SpectrumRequest{SkipGate: true})
	if err != nil {
		t.Fatal(err)
	}
	r.clk.Sleep(context.Background(), 90*time.Second)
	if st := s.Status(); st.Age(r.clk.Now()) != 90 || len(st.Rows[20]) != 11 {
		t.Errorf("age %d", st.Age(r.clk.Now()))
	}
	st := s.Status()
	st.Rows[20][0].Utilization = 99 // a copy
	if s.Status().Rows[20][0].Utilization == 99 || res.Rows[20][0].Utilization == 99 {
		t.Error("status rows alias the runner's")
	}
	s.ClearTable()
	if st := s.Status(); st.Rows != nil || !st.TableTime.IsZero() {
		t.Errorf("cleared %+v", st)
	}
}

// TestSpectrumRestoreTable: a table saved before an agent restart goes back
// into an empty runner with its own measurement time (Age counts from it),
// as a copy; a runner that already has a table (a band measured since)
// keeps it; ClearTable and a new band replace a restored table as any other.
func TestSpectrumRestoreTable(t *testing.T) {
	r := t4Replay(t, "t4_wl0_chunked.txt", "wl0", "ng", 0)
	c := newSpecCollector(t, r)
	s := spectrumOf(t, c, "ng")
	at := r.clk.Now().Add(-3 * time.Hour)
	saved := map[int][]SpectrumRow{20: {{Channel: 1, Width: 20, CenterFreq: 2412, Utilization: 7, Interference: -80}}}
	if s.RestoreTable(nil, at) || s.RestoreTable(saved, time.Time{}) {
		t.Error("restored an empty table or one without a time")
	}
	if !s.RestoreTable(saved, at) {
		t.Fatal("not restored into an empty runner")
	}
	saved[20][0].Utilization = 99 // the runner keeps a copy
	st := s.Status()
	if st.Age(r.clk.Now()) != 3*3600 || len(st.Rows[20]) != 1 || st.Rows[20][0].Utilization != 7 || st.Abnormal {
		t.Errorf("restored status %+v age %d", st, st.Age(r.clk.Now()))
	}
	if s.RestoreTable(map[int][]SpectrumRow{40: {{Channel: 1, Width: 40}}}, at.Add(time.Hour)) {
		t.Error("a second restore replaced the table")
	}
	// a new band replaces it
	if _, err := s.Run(context.Background(), SpectrumRequest{SkipGate: true}); err != nil {
		t.Fatal(err)
	}
	if st := s.Status(); len(st.Rows[20]) != 11 || st.Age(r.clk.Now()) != 0 {
		t.Errorf("after a band: %d rows, age %d", len(st.Rows[20]), st.Age(r.clk.Now()))
	}
	if s.RestoreTable(saved, at) {
		t.Error("restored over a measured table")
	}
	s.ClearTable()
	if !s.RestoreTable(saved, at) || s.Status().Rows[20][0].Utilization != 99 {
		t.Error("not restored after a clear")
	}
}
