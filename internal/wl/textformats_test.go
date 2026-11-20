// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/rf"
)

// The Broadcom text formats this package reads for bcmwifi too: each has
// one reader here.

func TestParseChanspecText(t *testing.T) {
	for _, c := range []struct {
		in             string
		control, width int
	}{
		{"6", 6, 20}, {"7u", 7, 40}, {"1l", 1, 40}, {"44l", 44, 40}, {"153u", 153, 40},
		{"36/80", 36, 80}, {"100/160", 100, 160}, {"36/40", 36, 40}, {" 44/80\n", 44, 80},
		{"36/7", 36, 7}, // the width is not checked here
	} {
		control, width, err := ParseChanspecText(c.in)
		if err != nil || control != c.control || width != c.width {
			t.Errorf("ParseChanspecText(%q) = %d, %d, %v, want %d, %d", c.in, control, width, err, c.control, c.width)
		}
	}
	for in, want := range map[string]string{
		"":       "bad channel",
		"x":      "bad channel",
		"0":      "bad channel",
		"-4":     "bad channel",
		"l":      "bad channel",
		"6U":     "bad channel",
		"x/80":   "bad channel",
		"36l/80": "bad channel",
		"44 l":   "bad channel",
		"36/x":   `strconv.Atoi: parsing "x": invalid syntax`,
		"36/":    `strconv.Atoi: parsing "": invalid syntax`,
		"36/80u": `strconv.Atoi: parsing "80u": invalid syntax`, // the "/" before the u
		"36/8/1": `strconv.Atoi: parsing "8/1": invalid syntax`,
	} {
		if _, _, err := ParseChanspecText(in); err == nil || err.Error() != want {
			t.Errorf("ParseChanspecText(%q): %v, want %q", in, err, want)
		}
	}
}

// parseChanspecString adds the band and the centre to ParseChanspecText:
// whatever the one fails on, the other fails on, and channel and width are
// the same.
func TestParseChanspecStringFollowsText(t *testing.T) {
	for _, in := range []string{"6", "7u", "1l", "44l", "36/80", "161/80", "100/160", "36/40", "165/80", "",
		"x", "0", "36/x", "36/80u", "6U", "l", "36l/80"} {
		control, width, err := ParseChanspecText(in)
		cs, ok := parseChanspecString(in, "na")
		if ok && (err != nil || cs.Control != control || cs.Width != width) {
			t.Errorf("%q: parseChanspecString %+v, ParseChanspecText %d %d %v", in, cs, control, width, err)
		}
		if err != nil && ok {
			t.Errorf("%q: parseChanspecString took what ParseChanspecText refused (%v)", in, err)
		}
	}
	// no centre: a width's block that does not hold the channel
	if cs, ok := parseChanspecString("144/160", "na"); ok {
		t.Errorf("144/160 parsed: %+v", cs)
	}
}

// The centre of a block is its first channel (rf's table) plus half the
// block.
func TestBlockCenter(t *testing.T) {
	for _, c := range []struct{ ch, width, want int }{
		{36, 40, 38}, {40, 40, 38}, {149, 40, 151}, {36, 80, 42}, {48, 80, 42}, {161, 80, 155},
		{100, 160, 114}, {128, 160, 114}, {144, 160, 0}, {6, 40, 0}, {36, 20, 0},
	} {
		if got := blockCenter(c.ch, c.width); got != c.want {
			t.Errorf("blockCenter(%d, %d) = %d, want %d", c.ch, c.width, got, c.want)
		}
	}
	for _, width := range []int{40, 80, 160} {
		for _, f := range rf.Blocks5G(width) {
			if got, want := blockCenter(f, width), f+(width/5-4)/2; got != want {
				t.Errorf("blockCenter(%d, %d) = %d, want %d", f, width, got, want)
			}
		}
	}
}

// bw_cap is one bit per width: BWCap sets the bits up to a width,
// BWCapMaxWidth reads the widest one back.
func TestBWCap(t *testing.T) {
	for _, c := range []struct{ width, want int }{
		{0, 1}, {20, 1}, {39, 1}, {40, 3}, {79, 3}, {80, 7}, {159, 7}, {160, 15}, {320, 15},
	} {
		if got := BWCap(c.width); got != c.want {
			t.Errorf("BWCap(%d) = %#x, want %#x", c.width, got, c.want)
		}
	}
	for _, c := range []struct{ v, want int }{
		{0, 0}, {1, 20}, {3, 40}, {2, 40}, {7, 80}, {4, 80}, {15, 160}, {8, 160}, {0x10, 0}, {0x13, 40},
	} {
		if got := BWCapMaxWidth(c.v); got != c.want {
			t.Errorf("BWCapMaxWidth(%#x) = %d, want %d", c.v, got, c.want)
		}
	}
	for _, width := range []int{20, 40, 80, 160} {
		if got := BWCapMaxWidth(BWCap(width)); got != width {
			t.Errorf("BWCapMaxWidth(BWCap(%d)) = %d", width, got)
		}
	}
}

func TestParseCountryRev(t *testing.T) {
	for _, c := range []struct {
		in, code string
		rev      int
	}{
		{"US (US/0) UNITED STATES", "US", 0},
		{"IN (IN/288) INDIA", "IN", 288},
		{"#a (#a/0) <unknown>", "#a", 0},
		{"  CA (CA/2)\n", "CA", 2},
		{"DE", "DE", -1},
		{"DE (DE) GERMANY", "DE", -1},
		{"DE (DE/x) GERMANY", "DE", -1},
		{"DE DE/3", "DE", -1}, // the rev is read from "(code/rev)" only
		{"", "", -1},
	} {
		code, rev := ParseCountry(c.in)
		if code != c.code || rev != c.rev {
			t.Errorf("ParseCountry(%q) = %q, %d, want %q, %d", c.in, code, rev, c.code, c.rev)
		}
		if got := parseCountry([]byte(c.in)); got != c.code {
			t.Errorf("parseCountry(%q) = %q, want %q", c.in, got, c.code)
		}
	}
	code, rev := ParseCountry(string(fixture(t, "wl_-i_wl0_country.txt")))
	if code != "US" || rev != 0 {
		t.Errorf("fixture: %q, %d", code, rev)
	}
}
