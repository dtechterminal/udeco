// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// ledFake is a fake root with the LED table, recording each row written
// through the real writer.
type ledFake struct {
	root string
	rows []string
}

func newLEDFake(t *testing.T, withTable bool) (*ledFake, *Applier) {
	t.Helper()
	f := &ledFake{root: t.TempDir()}
	if withTable {
		p := filepath.Join(f.root, ledDefFile)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("102     27      2       0       0\n"), 0o644)
	}
	a := New(Options{Root: f.root, Run: newFakeDev(t), RunDir: "/tmp/udeco", StateDir: "/state",
		writeLED: func(p, s string) error {
			f.rows = append(f.rows, strings.TrimSuffix(s, "\n"))
			return writeProc(p, s)
		}})
	return f, a
}

func (f *ledFake) take() []string { r := f.rows; f.rows = nil; return r }

func (f *ledFake) table(t *testing.T) string {
	b, err := os.ReadFile(filepath.Join(f.root, ledDefFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestLED: each state is ledctl1's "ALL off" then at most one colour, and
// locate wins over on/off until locate-off.
func TestLED(t *testing.T) {
	f, a := newLEDFake(t, true)
	ctx := context.Background()
	allOff := []string{"102 27 0 0 0", "102 25 0 0 0", "102 23 0 0 0"}
	green := append(append([]string{}, allOff...), "102 25 1 0 0")
	blue := append(append([]string{}, allOff...), "102 23 2 0 0")
	steps := []struct {
		mode string
		want []string
	}{
		{bcmwifi.LEDOn, green},
		{bcmwifi.LEDLocate, blue},
		{bcmwifi.LEDOff, blue}, // still locating: the blink stays
		{bcmwifi.LEDLocateOff, allOff},
		{bcmwifi.LEDLocate, blue}, // locate shows with the LED off too
		{"unlocate", allOff},
		{"ON", green},
	}
	for _, s := range steps {
		if err := a.LED(ctx, s.mode); err != nil {
			t.Fatalf("%s: %v", s.mode, err)
		}
		if got := f.take(); strings.Join(got, "|") != strings.Join(s.want, "|") {
			t.Errorf("%s wrote %q, want %q", s.mode, got, s.want)
		}
		if got, want := f.table(t), s.want[len(s.want)-1]+"\n"; got != want {
			t.Errorf("%s: table holds %q, want %q", s.mode, got, want)
		}
	}
}

func TestLEDErrors(t *testing.T) {
	ctx := context.Background()
	f, a := newLEDFake(t, true)
	if err := a.LED(ctx, "rainbow"); err == nil {
		t.Error("unknown mode accepted")
	}
	if len(f.take()) != 0 {
		t.Error("unknown mode wrote rows")
	}

	// no LED table (another unit, or the kernel moved it): an error, and no
	// file appears under /proc
	f, a = newLEDFake(t, false)
	if err := a.LED(ctx, bcmwifi.LEDOn); err == nil {
		t.Error("LED with no table: no error")
	}
	if _, err := os.Stat(filepath.Join(f.root, ledDefFile)); !os.IsNotExist(err) {
		t.Errorf("table created: %v", err)
	}
	// a failed write still records the controller's word: locate-off after
	// a failed "off" goes dark
	f, a = newLEDFake(t, true)
	os.Remove(filepath.Join(f.root, ledDefFile))
	if err := a.LED(ctx, bcmwifi.LEDOff); err == nil {
		t.Fatal("no error")
	}
	os.WriteFile(filepath.Join(f.root, ledDefFile), nil, 0o644)
	f.take()
	if err := a.LED(ctx, bcmwifi.LEDLocateOff); err != nil {
		t.Fatal(err)
	}
	if got := f.take(); len(got) != 3 || got[2] != "102 23 0 0 0" {
		t.Errorf("after a failed off, locate-off wrote %q", got)
	}
}

func TestLEDDryRun(t *testing.T) {
	f, a := newLEDFake(t, true)
	a.o.DryRun = true
	if err := a.LED(context.Background(), bcmwifi.LEDLocate); err != nil {
		t.Fatal(err)
	}
	if len(f.take()) != 0 || f.table(t) != "102     27      2       0       0\n" {
		t.Error("dry run wrote the LED table")
	}
}

// The uplink-loss hold shows the firmware's own "no WAN" pattern, the red
// fast blink (row 102 27 2 0, read on the unit 2026-11-19), under the
// controller's LED setting and locate; the agent's stop puts green back.
func TestLEDUplinkDown(t *testing.T) {
	f, a := newLEDFake(t, true)
	ctx := context.Background()
	allOff := []string{"102 27 0 0 0", "102 25 0 0 0", "102 23 0 0 0"}
	green := append(append([]string{}, allOff...), "102 25 1 0 0")
	blue := append(append([]string{}, allOff...), "102 23 2 0 0")
	red := append(append([]string{}, allOff...), "102 27 2 0 0")
	check := func(step string, want []string) {
		t.Helper()
		if got := f.take(); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s wrote %q, want %q", step, got, want)
		}
	}
	if err := a.LED(ctx, bcmwifi.LEDOn); err != nil {
		t.Fatal(err)
	}
	check("on", green)
	a.uplinkLED(ctx, true)
	check("uplink down", red)
	a.uplinkLED(ctx, true)
	check("uplink down again", nil)
	_ = a.LED(ctx, bcmwifi.LEDLocate)
	check("locate in the hold", blue)
	_ = a.LED(ctx, bcmwifi.LEDLocateOff)
	check("locate-off in the hold", red)
	_ = a.LED(ctx, bcmwifi.LEDOff)
	check("off in the hold", allOff)
	a.uplinkLED(ctx, false)
	check("uplink back, LED off", nil) // dark stays dark: nothing to write
	a.uplinkLED(ctx, true)
	check("uplink down, LED off", nil)
	_ = a.LED(ctx, bcmwifi.LEDOn)
	check("on in the hold", red)
	a.ReleaseLED(ctx)
	check("release", green)
	a.ReleaseLED(ctx)
	check("release again", nil)
	a.uplinkLED(ctx, false)
	check("uplink back after release", nil)
}
