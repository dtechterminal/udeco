// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

import (
	"errors"
	"math"
	"testing"
)

// ParseCPULine on what each caller hands it: internal/wl the first line
// of /proc/stat, upstream's openwrt package the output of `head -1 /proc/stat`. The
// answers are what the two gave while each summed the line itself.
func TestParseCPULine(t *testing.T) {
	for _, c := range []struct {
		in          string
		total, idle int64
	}{
		{"cpu  146532 0 174312 7024149 65 0 8086 0 0 0", 7353144, 7024214},
		{"cpu  146532 0 174312 7024149 65 0 8086 0 0 0\n", 7353144, 7024214},
		{"cpu 1 2 3 4 5 6 7\n", 28, 9},
		{"cpu 1 2 3 4\n", 10, 4},
		{"cpu 1 2 3\n", 0, 0},
		{"cpu0 1 2 3 4 5\n", 0, 0},
		{"intr 1 2 3\n", 0, 0},
		{"cpu 1 x 3 4 5\n", 13, 9},
		{"cpu 1 2 3 -4 5\n", 7, 1},
		{"cpu 1 2 3 4 5 99999999999999999999\n", math.MinInt64 + 14, 9}, // out of range counts as the largest int64: the sum wraps
		{"", 0, 0},
		// more than one line is the caller's business: every field is summed
		{"cpu 1 2 3 4 5\ncpu0 9 9 9 9 9\n", 60, 9},
	} {
		if total, idle := ParseCPULine(c.in); total != c.total || idle != c.idle {
			t.Errorf("ParseCPULine(%q) = %d, %d; want %d, %d", c.in, total, idle, c.total, c.idle)
		}
	}
}

func TestParseUptime(t *testing.T) {
	for _, c := range []struct {
		in   string
		want float64
		err  string
	}{
		{in: "18381.41 70236.05\n", want: 18381.41},
		{in: "90.00 100.00\n", want: 90},
		{in: "  8207676.06", want: 8207676.06},
		{in: "0.99 1\n", want: 0.99},
		{in: "", err: "empty /proc/uptime"},
		{in: " \n", err: "empty /proc/uptime"},
		{in: "junk 1\n", err: `strconv.ParseFloat: parsing "junk": invalid syntax`},
		{in: "1e999\n", want: math.Inf(1), err: `strconv.ParseFloat: parsing "1e999": value out of range`},
	} {
		got, err := ParseUptime(c.in)
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if (c.err == "empty /proc/uptime") != errors.Is(err, ErrNoUptime) {
			t.Errorf("ParseUptime(%q): error %v, ErrNoUptime is for a text with no field", c.in, err)
		}
		if got != c.want || msg != c.err {
			t.Errorf("ParseUptime(%q) = %v, %q; want %v, %q", c.in, got, msg, c.want, c.err)
		}
	}
}
