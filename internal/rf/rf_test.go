// SPDX-License-Identifier: GPL-2.0-or-later

package rf

import (
	"slices"
	"testing"
)

func TestBandNames(t *testing.T) {
	if got := Bands(); !slices.Equal(got, []string{"ng", "na"}) {
		t.Errorf("Bands() = %v", got)
	}
	// a caller may reorder its copy
	b := Bands()
	slices.Reverse(b)
	if got := Bands(); !slices.Equal(got, []string{"ng", "na"}) {
		t.Errorf("Bands() after a caller's Reverse = %v", got)
	}
	for _, c := range []struct{ band, old string }{{"ng", "2g"}, {"na", "5g"}, {"6e", "6g"}} {
		if got := Legacy(c.band); got != c.old {
			t.Errorf("Legacy(%q) = %q, want %q", c.band, got, c.old)
		}
		if got := FromLegacy(c.old); got != c.band {
			t.Errorf("FromLegacy(%q) = %q, want %q", c.old, got, c.band)
		}
	}
	for _, s := range []string{"", "2g", "NG", "wifi0", "5ghz"} {
		if got := Legacy(s); got != "" {
			t.Errorf("Legacy(%q) = %q, want none", s, got)
		}
	}
	for _, s := range []string{"", "ng", "2G", "2.4g"} {
		if got := FromLegacy(s); got != "" {
			t.Errorf("FromLegacy(%q) = %q, want none", s, got)
		}
	}
}

func TestNorm(t *testing.T) {
	for in, want := range map[string]string{
		"ng": "ng", "2g": "ng", "2.4g": "ng", "2ghz": "ng", "2.4ghz": "ng", "NG": "ng", "2.4GHz": "ng",
		"na": "na", "5g": "na", "5ghz": "na", "NA": "na", "5GHz": "na",
		" ng": "ng", "na ": "na", "\t5g\n": "na", // spaces around a name are ignored
		"": "", "6e": "", "6g": "", "ac": "", "2.4": "", "n g": "",
	} {
		if got := Norm(in); got != want {
			t.Errorf("Norm(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsDFS(t *testing.T) {
	for _, c := range []struct {
		band string
		ch   int
		want bool
	}{
		{"na", 48, false}, {"na", 51, false}, {"na", 52, true}, {"na", 64, true}, {"na", 100, true},
		{"na", 144, true}, {"na", 145, false}, {"na", 149, false}, {"na", 165, false},
		{"ng", 52, false}, {"6e", 100, false}, {"", 100, false},
	} {
		if got := IsDFS(c.band, c.ch); got != c.want {
			t.Errorf("IsDFS(%q, %d) = %v", c.band, c.ch, got)
		}
	}
}

func TestChanFreq(t *testing.T) {
	for _, c := range []struct {
		band     string
		ch, want int
	}{
		{"ng", 1, 2412}, {"ng", 6, 2437}, {"ng", 11, 2462}, {"ng", 13, 2472},
		{"ng", 14, 2484}, // not 2407 + 5*14
		{"na", 36, 5180}, {"na", 42, 5210}, {"na", 100, 5500}, {"na", 149, 5745}, {"na", 165, 5825},
		{"na", 14, 5070}, // only 2.4 GHz has the channel 14 exception
	} {
		if got := ChanFreq(c.band, c.ch); got != c.want {
			t.Errorf("ChanFreq(%q, %d) = %d, want %d", c.band, c.ch, got, c.want)
		}
	}
}

// The block table and the block arithmetic are two ways to the same
// answer: for every listed block, every channel in it has that block's
// start by BlockStart and that block's channels by SubChannels.
func TestBlocks5G(t *testing.T) {
	want := map[int][]int{
		40:  {36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157, 165, 173},
		80:  {36, 52, 100, 116, 132, 149, 165},
		160: {36, 100, 149},
	}
	for width, firsts := range want {
		got := Blocks5G(width)
		if !slices.Equal(got, firsts) {
			t.Errorf("Blocks5G(%d) = %v, want %v", width, got, firsts)
		}
		got[0] = 0 // a caller's copy
		if again := Blocks5G(width); !slices.Equal(again, firsts) {
			t.Errorf("Blocks5G(%d) after a caller's write = %v", width, again)
		}
		n := width / 20
		for _, f := range firsts {
			block := make([]int, n)
			for i := range block {
				block[i] = f + 4*i
			}
			for _, ch := range block {
				if got := BlockStart(ch, width); got != f {
					t.Errorf("BlockStart(%d, %d) = %d, want %d", ch, width, got, f)
				}
				if got := SubChannels(ch, width); !slices.Equal(got, block) {
					t.Errorf("SubChannels(%d, %d) = %v, want %v", ch, width, got, block)
				}
			}
		}
	}
	for _, width := range []int{0, 20, 320} {
		if got := Blocks5G(width); got != nil {
			t.Errorf("Blocks5G(%d) = %v, want none", width, got)
		}
	}
	// no block: BlockStart says so, SubChannels still answers
	for _, c := range []struct{ ch, width int }{{6, 40}, {68, 40}, {96, 80}, {144, 160}, {181, 40}, {36, 20}} {
		if got := BlockStart(c.ch, c.width); got != 0 {
			t.Errorf("BlockStart(%d, %d) = %d, want 0", c.ch, c.width, got)
		}
	}
	for _, c := range []struct {
		ch, width int
		want      []int
	}{
		{36, 20, []int{36}}, {165, 20, []int{165}}, {44, 0, []int{44}}, {44, 10, []int{44}},
		{48, 40, []int{44, 48}}, {64, 80, []int{52, 56, 60, 64}}, {161, 80, []int{149, 153, 157, 161}},
		{112, 160, []int{100, 104, 108, 112, 116, 120, 124, 128}},
		{144, 160, []int{132, 136, 140, 144, 148, 152, 156, 160}}, // no such block: arithmetic only
	} {
		if got := SubChannels(c.ch, c.width); !slices.Equal(got, c.want) {
			t.Errorf("SubChannels(%d, %d) = %v, want %v", c.ch, c.width, got, c.want)
		}
	}
}

func TestOnly20MHz(t *testing.T) {
	for _, c := range []struct {
		band string
		ch   int
		want bool
	}{{"na", 165, true}, {"na", 161, false}, {"na", 169, false}, {"ng", 165, false}, {"", 165, false}} {
		if got := Only20MHz(c.band, c.ch); got != c.want {
			t.Errorf("Only20MHz(%q, %d) = %v", c.band, c.ch, got)
		}
	}
}

func TestNonOverlap24(t *testing.T) {
	got := NonOverlap24()
	if !slices.Equal(got, []int{1, 6, 11}) {
		t.Errorf("NonOverlap24() = %v", got)
	}
	got[0] = 0
	if again := NonOverlap24(); !slices.Equal(again, []int{1, 6, 11}) {
		t.Errorf("NonOverlap24() after a caller's write = %v", again)
	}
}

func TestNoiseFloor(t *testing.T) {
	if NoiseFloorDBm != -95 {
		t.Errorf("NoiseFloorDBm = %d", NoiseFloorDBm)
	}
}

// OpClass is 802.11-2020 Table E-4's 20 MHz classes, channel by channel:
// every channel of a class, nothing between or around them.
func TestOpClass(t *testing.T) {
	want := map[string]map[int]int{Band2G: {14: 82}, Band5G: {}}
	for ch := 1; ch <= 13; ch++ {
		want[Band2G][ch] = 81
	}
	for _, c := range []struct{ class, first, last int }{
		{115, 36, 48}, {118, 52, 64}, {121, 100, 144}, {124, 149, 161}, {125, 165, 177},
	} {
		for ch := c.first; ch <= c.last; ch += 4 {
			want[Band5G][ch] = c.class
		}
	}
	for _, band := range []string{Band2G, Band5G, Band6G, "", "5g"} {
		for ch := -1; ch <= 200; ch++ {
			if got := OpClass(band, ch); got != want[band][ch] {
				t.Errorf("OpClass(%q, %d) = %d, want %d", band, ch, got, want[band][ch])
			}
		}
	}
	for ch := -1; ch <= 200; ch++ {
		b := ChanBand(ch)
		if OpClass(Band2G, ch) != 0 && b != Band2G || OpClass(Band5G, ch) != 0 && b != Band5G {
			t.Errorf("ChanBand(%d) = %q, not the band of its operating class", ch, b)
		}
	}
}
