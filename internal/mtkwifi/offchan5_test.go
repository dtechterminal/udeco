// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/wl"
)

// chanSource is an rtnetlink socket fed by the fake driver.
type chanSource struct {
	ch   chan []byte
	done chan struct{}
	once sync.Once
}

func newChanSource() *chanSource {
	return &chanSource{ch: make(chan []byte, 64), done: make(chan struct{})}
}

func (s *chanSource) Read(b []byte) (int, error) {
	select {
	case p := <-s.ch:
		return copy(b, p), nil
	case <-s.done:
		return 0, errors.New("closed")
	}
}

func (s *chanSource) Close() error { s.once.Do(func() { close(s.done) }); return nil }

// fakeMT7663 answers the Channel_Info request as the driver does: one
// 0x955 event at the dwell's end, on the interface's rtnetlink message.
type fakeMT7663 struct {
	ck       *clock
	src      *chanSource
	busy     map[int]int // channel -> busy µs
	measured map[int]int // channel -> measured ms (default: the dwell - 4)
	drop     map[int]int // channel -> requests dropped before one is answered
	noise    bool        // send an other radio's event and a stale one first
	// onceShort: the channel's measured value applies to its first visit
	// only (then the dwell - 4)
	onceShort map[int]bool
	reqs      [][]byte
	at        []time.Time
}

func (f *fakeMT7663) Show(string, string) error { return nil }
func (f *fakeMT7663) Set(string, []byte) error  { return nil }
func (f *fakeMT7663) Close() error              { return nil }

func chanInfoEvent(ch, busy, ms int) []byte {
	d := make([]byte, chanInfoLen)
	d[0] = chanInfoRes
	copy(d[1:], "rai0")
	d[0x24], d[0x25] = byte(ch), 0
	binary.LittleEndian.PutUint32(d[0x28:], uint32(0xffffffa4)) // -92
	binary.LittleEndian.PutUint32(d[0x38:], uint32(busy))
	d[0x3d] = byte(ms)
	return d
}

func (f *fakeMT7663) OID(ifname string, flags uint16, buf []byte) error {
	if flags != oidChanInfoMsg|oidSet || ifname != "rai0" {
		return syscall.EINVAL
	}
	f.reqs = append(f.reqs, slices.Clone(buf))
	f.at = append(f.at, f.ck.t)
	ch := int(buf[36])
	if f.drop[ch] > 0 {
		f.drop[ch]--
		return nil
	}
	ms := int(buf[46]) - 4
	if m, ok := f.measured[ch]; ok {
		ms = m
		if f.onceShort[ch] {
			delete(f.measured, ch)
		}
	}
	if f.noise {
		f.src.ch <- rtnlFrame("ra0", 8, oidChanInfoMsg, chanInfoEvent(ch, 99_000, ms))      // the other radio
		f.src.ch <- rtnlFrame("rai0", 9, oidChanInfoMsg, chanInfoEvent(ch+100, 99_000, ms)) // another channel
	}
	f.src.ch <- rtnlFrame("rai0", 9, oidChanInfoMsg, chanInfoEvent(ch, f.busy[ch], ms))
	return nil
}

// chanInfoUnit is a FreshScan collector of the JCOW414 with the fake
// MT7663, its 5 GHz radio up on channel 157, and a survey that changes once
// SiteSurvey=1 is set.
func chanInfoUnit(t *testing.T, pl chanInfoPlan) (*Collector, *fakeMT7663, *klogDev, *clock) {
	t.Helper()
	d := newKlogDev(t)
	d.setUp("rai0", true)
	ck := &clock{t: time.Unix(1_000_000, 0)}
	d.survey["rai0"] = "rai0      get_site_survey:\nTotal=0\n"
	d.next["rai0"] = fixture(t, "site_survey_rai0.txt")
	d.after = 1
	c := newTestCollector(d, ck, true)
	f := &fakeMT7663{ck: ck, busy: map[int]int{}, measured: map[int]int{}, drop: map[int]int{}}
	c.o.priv = func() (privIO, error) { return f, nil }
	c.o.rtnl = func() (packetSource, error) { f.src = newChanSource(); return f.src, nil }
	c.o.chanInfo = &pl
	return c, f, d, ck
}

var testChanInfoPlan = chanInfoPlan{Dwell: 200 * time.Millisecond, EventWait: 50 * time.Millisecond, Every: time.Second, Budget: time.Minute}

// The whole band: one passive 200 ms visit per channel the agent serves, a
// second apart, each confirmed by its own event (another radio's and
// another channel's are not taken); the survey after; rows at 20, 40 and
// 80 MHz from busy / measured dwell, our stations' uplink taken off home.
func TestChanInfoSweep(t *testing.T) {
	c, f, d, ck := chanInfoUnit(t, testChanInfoPlan)
	ctx := context.Background()
	f.noise = true
	f.busy = map[int]int{36: 39200, 44: 98000, 157: 29400, 165: 1960}
	c.cache["rai0"] = &radioReading{at: ck.t, staRx: 50_000} // 9.8 ms of the 196

	r, err := c.Spectrum(ctx, "na")
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Run(ctx, wl.SpectrumRequest{Widths: []int{20, 40, 80, 160}, Manual: true})
	if err != nil {
		t.Fatalf("Run: %v (diag %+v)", err, res.Diag)
	}
	var got []int
	for i, q := range f.reqs {
		got = append(got, int(q[36]))
		if len(q) != 160 || q[0] != 0x22 || string(q[1:5]) != "rai0" || q[5] != 0 || q[41] != 0x80 || q[46] != 200 ||
			binary.LittleEndian.Uint32(q[52:]) != 1 || q[37] != 0 {
			t.Errorf("request %d: % x", i, q[:56])
		}
		if i > 0 && f.at[i].Sub(f.at[i-1]) < time.Second {
			t.Errorf("visit %d %v after the previous one", i, f.at[i].Sub(f.at[i-1]))
		}
	}
	if !slices.Equal(got, chans5) {
		t.Errorf("visited %v, want %v", got, chans5)
	}
	if !slices.Contains(d.iwpriv(), "iwpriv rai0 set SiteSurvey=1") {
		t.Errorf("no survey after the visits: %v", d.iwpriv())
	}
	if c.scanning.Load() {
		t.Error("still scanning after the band")
	}
	dg := res.Diag
	if dg.Mode != ModeChanInfo || dg.HomeControl != 157 || !slices.Equal(dg.Widths, []int{20, 40, 80}) {
		t.Errorf("diag mode %q home %d widths %v", dg.Mode, dg.HomeControl, dg.Widths)
	}
	if len(res.Rows[20]) != 9 || len(res.Rows[40]) != 4 || len(res.Rows[80]) != 2 {
		t.Fatalf("rows: %d at 20, %d at 40, %d at 80", len(res.Rows[20]), len(res.Rows[40]), len(res.Rows[80]))
	}
	by := map[int]wl.SpectrumRow{}
	for _, row := range res.Rows[20] {
		by[row.Channel] = row
		if row.CenterFreq != 5000+5*row.Channel {
			t.Errorf("row %+v", row)
		}
	}
	for ch, want := range map[int]int{36: 20, 44: 50, 157: 10, 165: 1, 40: 0} {
		if by[ch].Utilization != want {
			t.Errorf("ch %d utilization %d, want %d", ch, by[ch].Utilization, want)
		}
	}
	// ch 36's strongest neighbour: ORCHID_5 at -70
	if by[36].Interference != -70 {
		t.Errorf("ch 36 interference %d, want -70", by[36].Interference)
	}
	var lows80 []int
	for _, row := range res.Rows[80] {
		lows80 = append(lows80, row.Channel)
		if row.Channel == 36 && (row.Utilization != 50 || row.CenterFreq != 5210) {
			t.Errorf("80 MHz row %+v: the max of 36-48, centre 42", row)
		}
	}
	if !slices.Equal(lows80, []int{36, 149}) {
		t.Errorf("80 MHz blocks %v", lows80)
	}
}

// No visit answered (the driver's scan state machine stuck): the band
// stops after one pass with errNoChanInfo, and asks no survey.
func TestChanInfoNoEvents(t *testing.T) {
	c, f, d, _ := chanInfoUnit(t, chanInfoPlan{Dwell: 20 * time.Millisecond, EventWait: 5 * time.Millisecond, Every: time.Second, Budget: time.Minute})
	for _, ch := range chans5 {
		f.drop[ch] = 9
	}
	r, _ := c.Spectrum(context.Background(), "na")
	_, err := r.Run(context.Background(), wl.SpectrumRequest{})
	if !errors.Is(err, errNoChanInfo) {
		t.Fatalf("Run: %v", err)
	}
	if len(f.reqs) != len(chans5) {
		t.Errorf("%d requests, want one pass of %d", len(f.reqs), len(chans5))
	}
	if slices.Contains(d.iwpriv(), "iwpriv rai0 set SiteSurvey=1") {
		t.Error("survey after a band with no answer")
	}
}

// A dwell cut short once is retried, and the retry's value used.
func TestChanInfoShortOnce(t *testing.T) {
	c, f, _, _ := chanInfoUnit(t, testChanInfoPlan)
	f.measured[161] = 30
	f.busy[161] = 39200
	f.onceShort = map[int]bool{161: true}
	r, _ := c.Spectrum(context.Background(), "na")
	res, err := r.Run(context.Background(), wl.SpectrumRequest{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Diag.Unmeasured) != 0 || len(f.reqs) != len(chans5)+1 {
		t.Errorf("unmeasured %v, %d requests", res.Diag.Unmeasured, len(f.reqs))
	}
	for _, row := range res.Rows[20] {
		if row.Channel == 161 && row.Utilization != 20 {
			t.Errorf("ch 161 after its retry: %+v", row)
		}
	}
}

// A dropped request is retried once after the last channel.
func TestChanInfoRetry(t *testing.T) {
	c, f, _, _ := chanInfoUnit(t, testChanInfoPlan)
	f.drop[40] = 1
	f.busy[40] = 19600
	r, _ := c.Spectrum(context.Background(), "na")
	res, err := r.Run(context.Background(), wl.SpectrumRequest{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(f.reqs) != len(chans5)+1 || f.reqs[len(f.reqs)-1][36] != 40 {
		t.Errorf("%d requests, last for %d", len(f.reqs), f.reqs[len(f.reqs)-1][36])
	}
	for _, row := range res.Rows[20] {
		if row.Channel == 40 && row.Utilization != 10 {
			t.Errorf("ch 40 after its retry: %+v", row)
		}
	}
	// twice dropped: missing, the band incomplete
	c2, f2, _, _ := chanInfoUnit(t, testChanInfoPlan)
	f2.drop[40] = 2
	r2, _ := c2.Spectrum(context.Background(), "na")
	if _, err := r2.Run(context.Background(), wl.SpectrumRequest{}); !errors.Is(err, wl.ErrIncomplete) {
		t.Errorf("twice dropped: %v", err)
	}
}

// With DFS the agent serves 52-64 too; the driver leaves such a channel
// after 2 ms (live): unmeasured, its blocks left out, the band succeeds.
func TestChanInfoShortDwell(t *testing.T) {
	c, f, _, _ := chanInfoUnit(t, testChanInfoPlan)
	c.o.DFS = true
	for _, ch := range chansDFS {
		f.measured[ch] = 2
	}
	r, _ := c.Spectrum(context.Background(), "na")
	res, err := r.Run(context.Background(), wl.SpectrumRequest{Widths: []int{20, 40, 80}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(f.reqs) != 17 {
		t.Errorf("%d requests, want 13 and the 4 DFS channels' retries", len(f.reqs))
	}
	if !slices.Equal(res.Diag.Unmeasured, chansDFS) {
		t.Errorf("unmeasured %v", res.Diag.Unmeasured)
	}
	for _, w := range []int{20, 40, 80} {
		for _, row := range res.Rows[w] {
			if row.Channel >= 52 && row.Channel <= 64 {
				t.Errorf("%d MHz row of a DFS channel: %+v", w, row)
			}
		}
	}
	if len(res.Rows[20]) != 9 || len(res.Rows[40]) != 4 || len(res.Rows[80]) != 2 {
		t.Errorf("rows: %d at 20, %d at 40, %d at 80", len(res.Rows[20]), len(res.Rows[40]), len(res.Rows[80]))
	}
}

// The event as the Garage's driver sent it (2026-11-24, ch 36, 50 ms).
func TestParseChanInfo(t *testing.T) {
	d := make([]byte, chanInfoLen)
	d[0] = 0x23
	copy(d[1:], "rai0")
	raw, _ := hex.DecodeString(strings.ReplaceAll("24 00 00 00 a4 ff ff ff 00 00 00 00 00 00 00 00 32 02 00 00 6c 01 00 00 00 2e 00 00", " ", ""))
	copy(d[0x24:], raw)
	e, ok := customEvent("rai0", 0x955, d)
	if !ok || e.Kind != DrvChanInfo || e.ChanInfo == nil {
		t.Fatalf("event %+v %v", e, ok)
	}
	want := ChanInfo{Channel: 36, NF: -92, OBSSUs: 562, BusyUs: 364, MeasuredMs: 46}
	if *e.ChanInfo != want {
		t.Errorf("parsed %+v, want %+v", *e.ChanInfo, want)
	}
	if _, ok := customEvent("rai0", 0x955, d[:0x30]); ok {
		t.Error("a short 0x955 event parsed")
	}
	d[0] = 0x22
	if _, ok := customEvent("rai0", 0x955, d); ok {
		t.Error("a 0x955 that is not a result parsed")
	}
}

// The MT7663 keeps changing a listed neighbour's RSSI after its survey:
// the survey ends once the neighbours listed stay the same for scanSettle,
// not at the context's end.
func TestFreshSurveySettlesOnNeighbours(t *testing.T) {
	d := newKlogDev(t)
	d.setUp("rai0", true)
	ck := &clock{t: time.Unix(1_000_000, 0)}
	table := fixture(t, "site_survey_rai0.txt")
	d.survey["rai0"] = "rai0      get_site_survey:\nTotal=0\n"
	d.next["rai0"] = table
	d.after = 1
	c := newTestCollector(d, ck, true)
	flip := false
	d.hook = func(cmd string) {
		if cmd == "iwpriv rai0 get_site_survey" && d.survey["rai0"] != "rai0      get_site_survey:\nTotal=0\n" {
			flip = !flip
			if flip {
				d.survey["rai0"] = strings.Replace(table, "-70      50", "-71      48", 1)
			} else {
				d.survey["rai0"] = table
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := ck.t
	res, err := c.Scan(ctx, "na")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if took := ck.t.Sub(start); took > 5*time.Second || len(res.BSS) == 0 {
		t.Errorf("survey took %v (fake), %d BSSes: it should settle %v after the neighbours stop changing", took, len(res.BSS), scanSettle)
	}
}
