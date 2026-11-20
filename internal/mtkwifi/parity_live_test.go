// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// clocked is an applier on f whose monotonic clock the test moves.
func clocked(f *fakeDev) (*Applier, *time.Duration) {
	now := new(time.Duration)
	*now = time.Hour
	a := New(Options{Root: f.root, Run: f, RunDir: "/tmp/udeco", StateDir: "/state", Uplink: "eth0.4.1",
		VerifyTimeout: time.Millisecond, sleep: func(context.Context, time.Duration) error { return nil },
		mono: func() time.Duration { return *now }})
	return a, now
}

func cmdsFrom(f *fakeDev, n int, prefix string) []string {
	var out []string
	for _, c := range f.log[n:] {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// TestTxPowerBrackets: the controller's power maps onto the MT76 power
// drop brackets (txpower-kick spec), and the profile's percentage reads
// back as the bracket's drop below the board maximum.
func TestTxPowerBrackets(t *testing.T) {
	for _, c := range []struct {
		r    bcmwifi.Radio
		want int
		note bool
	}{
		{bcmwifi.Radio{TxPowerMode: "auto"}, 100, false},
		{bcmwifi.Radio{TxPowerMode: "high"}, 100, false},
		{bcmwifi.Radio{TxPowerMode: "medium"}, 50, false},
		{bcmwifi.Radio{TxPowerMode: "low"}, 25, false},
		{bcmwifi.Radio{TxPowerMode: "custom", TxPower: 20}, 100, false},
		{bcmwifi.Radio{TxPowerMode: "custom", TxPower: 19}, 75, false},
		{bcmwifi.Radio{TxPowerMode: "custom", TxPower: 18}, 50, false},
		{bcmwifi.Radio{TxPowerMode: "custom", TxPower: 17}, 50, false},
		{bcmwifi.Radio{TxPowerMode: "custom", TxPower: 14}, 25, false},
		{bcmwifi.Radio{TxPowerMode: "custom", TxPower: 11}, 12, false},
		{bcmwifi.Radio{TxPowerMode: "custom", TxPower: 8}, 6, false},
		{bcmwifi.Radio{TxPowerMode: "custom", TxPower: 3}, 6, true},
	} {
		got, note := txPctNote(c.r, 20)
		if got != c.want || (note != "") != c.note {
			t.Errorf("txPct(%+v) = %d %q, want %d (note %t)", c.r, got, note, c.want, c.note)
		}
	}
	for pct, drop := range map[int]int{100: 0, 91: 0, 90: 1, 61: 1, 60: 3, 31: 3, 30: 6, 16: 6, 15: 9, 10: 9, 9: 12, 1: 12, 150: 0} {
		for _, band := range []string{"ng", "na"} {
			if got := dropOf(pct, band); got != drop {
				t.Errorf("dropOf(%d, %s) = %d, want %d", pct, band, got, drop)
			}
		}
	}
	if dropOf(0, "ng") != 12 || dropOf(0, "na") != 0 {
		t.Errorf("dropOf(0): ng %d na %d", dropOf(0, "ng"), dropOf(0, "na"))
	}
	if txDBm(25, JCOW414[0]) != 14 || txDBm(25, JCOW414[1]) != 17 {
		t.Errorf("TxPower=25: ng %d na %d dBm", txDBm(25, JCOW414[0]), txDBm(25, JCOW414[1]))
	}
}

// TestTxPowerLive: a power change alone restarts nothing; once no radio
// restart is settling, it goes live with the per-chip command (TxPower on
// the MT7603, PowerDropCtrl on the MT7663), and the profile follows.
func TestTxPowerLive(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	ctx := context.Background()
	d := home()
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	*now += time.Minute
	d.Radios["ng"] = bcmwifi.Radio{Enabled: true, Channel: 6, Width: 20, TxPowerMode: "medium"}
	d.Radios["na"] = bcmwifi.Radio{Enabled: true, Channel: 36, Width: 80, TxPowerMode: "low"}
	p, _ = a.Plan(ctx, d)
	if s := radioSteps(p); len(s) > 0 {
		t.Errorf("power change planned a restart: %v", s)
	}
	n := len(f.log)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if r := restarts(f.log[n:]); len(r) > 0 {
		t.Errorf("power change restarted: %v", r)
	}
	got := strings.Join(cmdsFrom(f, n, "iwpriv"), "\n")
	if !strings.Contains(got, "iwpriv ra0 set TxPower=50") || !strings.Contains(got, "iwpriv rai0 set PowerDropCtrl=25") ||
		strings.Contains(got, "rai0 set TxPower") {
		t.Errorf("live power commands:\n%s", got)
	}
	if v, _ := getKey(readDat(t, f, 0), "TxPower"); v != "50" {
		t.Errorf("ng profile TxPower=%s", v)
	}
}

// TestLiveSettingsWaitForSettle: after a radio restart the per-BSS live
// settings (minimum RSSI) wait for the settle time to end and go out from
// Tick; never inside the restart.
func TestLiveSettingsWaitForSettle(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	ctx := context.Background()
	d := home()
	d.Radios["ng"] = bcmwifi.Radio{Enabled: true, Channel: 6, Width: 20, MinRSSI: -75}
	p, _ := a.Plan(ctx, d)
	n := len(f.log)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if c := cmdsFrom(f, n, "iwpriv ra0 set AssocReqRssiThres"); len(c) > 0 {
		t.Errorf("sent inside the restart's settle time: %v", c)
	}
	a.Tick(ctx)
	if c := cmdsFrom(f, n, "iwpriv ra0 set AssocReqRssiThres"); len(c) > 0 {
		t.Errorf("sent by a Tick inside the settle time: %v", c)
	}
	*now += time.Minute
	m := len(f.log)
	a.Tick(ctx)
	got := strings.Join(cmdsFrom(f, m, "iwpriv"), "\n")
	for _, w := range []string{"iwpriv ra0 set AssocReqRssiThres=-75", "iwpriv ra1 set AssocReqRssiThres=-75",
		"iwpriv ra2 set AssocReqRssiThres=-75", "iwpriv rai0 set AssocReqRssiThres=0", "iwpriv rai1 set AssocReqRssiThres=0"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in\n%s", w, got)
		}
	}
	// sent once: the next Tick has nothing to send
	m = len(f.log)
	a.Tick(ctx)
	if c := cmdsFrom(f, m, "iwpriv"); len(c) > 0 {
		t.Errorf("sent again: %v", c)
	}
	// a threshold change alone is live, no restart
	d.Radios["ng"] = bcmwifi.Radio{Enabled: true, Channel: 6, Width: 20, MinRSSI: -70}
	p, _ = a.Plan(ctx, d)
	m = len(f.log)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if r := restarts(f.log[m:]); len(r) > 0 {
		t.Errorf("threshold change restarted: %v", r)
	}
	if c := cmdsFrom(f, m, "iwpriv ra0 set AssocReqRssiThres=-70"); len(c) != 1 {
		t.Errorf("threshold change: %v", f.log[m:])
	}
}

func weakSnap(at time.Time, sig int) *apstate.Snapshot {
	return &apstate.Snapshot{Time: at, Radios: []apstate.Radio{{Band: "ng", VAPs: []apstate.Radio{
		{Iface: "ra0", Stations: []apstate.Station{{MAC: "aa:bb:cc:dd:ee:01", Signal: sig}, {MAC: "aa:bb:cc:dd:ee:02", Signal: -50}}},
	}}}}
}

// TestKickWeak: a station below the radio's minimum RSSI for
// minRSSIConseq readings in a row (at least minRSSIGap apart) is
// disconnected from its BSS; it is not kicked again during its back-off;
// a good reading starts the count over; no kick while a restart settles.
func TestKickWeak(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	ctx := context.Background()
	d := home()
	d.Radios["ng"] = bcmwifi.Radio{Enabled: true, Channel: 6, Width: 20, MinRSSI: -75}
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1_800_000_000, 0)
	// settling: nothing, however weak
	for i := 0; i < 5; i++ {
		if k := a.KickWeak(ctx, weakSnap(t0.Add(time.Duration(i)*10*time.Second), -90)); len(k) > 0 {
			t.Fatalf("kicked while settling: %v", k)
		}
	}
	*now += time.Minute
	t0 = t0.Add(time.Minute)
	var kicked []string
	for i := 0; i < minRSSIConseq; i++ {
		// a reading 1 s after another does not count
		kicked = append(kicked, a.KickWeak(ctx, weakSnap(t0.Add(time.Duration(i)*10*time.Second-time.Second), -90))...)
		kicked = append(kicked, a.KickWeak(ctx, weakSnap(t0.Add(time.Duration(i)*10*time.Second), -90))...)
		if i < minRSSIConseq-1 && len(kicked) > 0 {
			t.Fatalf("kicked after %d readings", i+1)
		}
	}
	if len(kicked) != 1 || kicked[0] != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("kicked %v", kicked)
	}
	if c := cmdsFrom(f, 0, "iwpriv ra0 set DisConnectSta=AA:BB:CC:DD:EE:01"); len(c) != 1 {
		t.Errorf("disconnect commands %v", c)
	}
	// back-off: still weak, not kicked again at once
	t1 := t0.Add(time.Duration(minRSSIConseq) * 10 * time.Second)
	for i := 0; i < minRSSIConseq+1; i++ {
		if k := a.KickWeak(ctx, weakSnap(t1.Add(time.Duration(i)*5*time.Second), -90)); len(k) > 0 {
			t.Fatalf("kicked again during back-off: %v", k)
		}
	}
	// a good reading resets the count of another weak spell
	b := New(Options{Root: f.root, Run: f, RunDir: "/tmp/udeco", mono: func() time.Duration { return *now }})
	b.live, b.desired = a.live, a.desired
	b.KickWeak(ctx, weakSnap(t0, -90))
	b.KickWeak(ctx, weakSnap(t0.Add(10*time.Second), -60))
	if k := b.KickWeak(ctx, weakSnap(t0.Add(20*time.Second), -90)); len(k) > 0 {
		t.Errorf("kicked across a good reading: %v", k)
	}
	// no minimum RSSI: never
	c := New(Options{Root: f.root, Run: f, RunDir: "/tmp/udeco", mono: func() time.Duration { return *now }})
	c.live = map[string]RadioPlan{"ng": {Band: "ng", On: true}}
	for i := 0; i < 5; i++ {
		if k := c.KickWeak(ctx, weakSnap(t0.Add(time.Duration(i)*10*time.Second), -95)); len(k) > 0 {
			t.Errorf("kicked without a minimum: %v", k)
		}
	}
}

func readDat(t *testing.T, f *fakeDev, i int) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.root, JCOW414[i].Dat))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestHandBackClearsMinRSSI: giving Wi-Fi back to the vendor clears the
// thresholds the agent set (the vendor never sets one) before the radios
// restart with the vendor's profiles.
func TestHandBackClearsMinRSSI(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	ctx := context.Background()
	d := home()
	d.Radios["ng"] = bcmwifi.Radio{Enabled: true, Channel: 6, Width: 20, MinRSSI: -75}
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	*now += time.Minute
	a.Tick(ctx)
	os.Remove(filepath.Join(f.root, "state", lastGoodFile))
	n := len(f.log)
	if err := a.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	clear, down := -1, -1
	for i, c := range f.log[n:] {
		if c == "iwpriv ra0 set AssocReqRssiThres=0" && clear < 0 {
			clear = i
		}
		if c == "ifconfig ra0 down" && down < 0 {
			down = i
		}
	}
	if clear < 0 || down < 0 || clear > down {
		t.Errorf("hand-back: clear at %d, down at %d:\n%s", clear, down, strings.Join(f.log[n:], "\n"))
	}
}

// TestCollectorTxMode: the collector reports the power the profile gives
// (the bracket's drop below the maximum) with the controller's mode the
// applier recorded for the radio.
func TestCollectorTxMode(t *testing.T) {
	f := newFakeDev(t)
	a, _ := clocked(f)
	ctx := context.Background()
	d := home()
	d.Radios["ng"] = bcmwifi.Radio{Enabled: true, Channel: 6, Width: 20, TxPowerMode: "medium"}
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if m := readTxModes(f.root, "/tmp/udeco"); m["ng"] != "medium" || m["na"] != "auto" {
		t.Errorf("recorded modes %v", m)
	}
	c := NewCollector(CollectorOptions{Root: f.root, Run: f, RunDir: "/tmp/udeco"})
	r := apstate.Radio{}
	c.radioTx(&r, JCOW414[0])
	if r.TxPower != 17 || r.TxPowerMode != "medium" {
		t.Errorf("ng: %d dBm, mode %q", r.TxPower, r.TxPowerMode)
	}
}
