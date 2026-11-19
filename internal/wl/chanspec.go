// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"strconv"
	"strings"
)

// chanspec is a decoded Broadcom chanspec (wl 17.10, d11ac format).
type chanspec struct {
	Raw     uint16
	Band    string // "ng" (2.4 GHz) or "na" (5 GHz)
	Control int    // primary 20 MHz channel
	Center  int    // centre channel of the whole width
	Width   int    // MHz
}

const (
	csChanMask = 0x00ff
	csSBMask   = 0x0700
	csSBShift  = 8
	csBWMask   = 0x3800
	csBandMask = 0xc000
	csBand2G   = 0x0000
	csBand5G   = 0xc000
)

// decodeChanspec decodes a raw chanspec. Only 2.4 and 5 GHz chanspecs of
// 20/40/80/160 MHz are accepted.
func decodeChanspec(cs uint16) (chanspec, bool) {
	c := chanspec{Raw: cs, Center: int(cs & csChanMask)}
	switch cs & csBandMask {
	case csBand2G:
		c.Band = "ng"
	case csBand5G:
		c.Band = "na"
	default:
		return c, false
	}
	switch cs & csBWMask {
	case 0x1000:
		c.Width = 20
	case 0x1800:
		c.Width = 40
	case 0x2000:
		c.Width = 80
	case 0x2800:
		c.Width = 160
	default:
		return c, false
	}
	if c.Center == 0 {
		return c, false
	}
	c.Control = c.Center
	if c.Width > 20 {
		sb := int(cs&csSBMask) >> csSBShift
		c.Control = c.Center - (c.Width/10 - 2) + 4*sb
	}
	return c, c.Control > 0
}

// parseChanspecHex finds the "(0x....)" part of wl output such as
// "44/80 (0xe22a)" or "Chanspec: 5GHz channel 42 80MHz (0xe22a)" and decodes
// it.
func parseChanspecHex(s string) (chanspec, bool) {
	i := strings.Index(s, "(0x")
	if i < 0 {
		return chanspec{}, false
	}
	rest := s[i+1:]
	end := strings.IndexByte(rest, ')')
	if end < 0 {
		return chanspec{}, false
	}
	n, err := strconv.ParseUint(rest[:end], 0, 16)
	if err != nil {
		return chanspec{}, false
	}
	return decodeChanspec(uint16(n))
}

// parseChanspecString decodes wl's text form of a chanspec: "6", "7u",
// "44l", "36/80", "36/160". band is "ng" or "na" (the text has no band).
func parseChanspecString(s, band string) (chanspec, bool) {
	s = strings.TrimSpace(s)
	c := chanspec{Band: band, Width: 20}
	num := s
	switch {
	case strings.HasSuffix(s, "u"), strings.HasSuffix(s, "l"):
		num = s[:len(s)-1]
		c.Width = 40
	case strings.Contains(s, "/"):
		var w string
		num, w, _ = strings.Cut(s, "/")
		n, err := strconv.Atoi(w)
		if err != nil {
			return c, false
		}
		c.Width = n
	}
	ch, err := strconv.Atoi(num)
	if err != nil || ch <= 0 {
		return c, false
	}
	c.Control, c.Center = ch, ch
	switch {
	case c.Width == 40 && strings.HasSuffix(s, "u"):
		c.Center = ch - 2
	case c.Width == 40 && strings.HasSuffix(s, "l"):
		c.Center = ch + 2
	case c.Width == 40, c.Width == 80, c.Width == 160:
		// "36/40" style or wider: the block the control channel falls in.
		c.Center = blockCenter(ch, c.Width)
	}
	return c, c.Center > 0
}

// blockCenter returns the centre channel of the 5 GHz 40/80/160 MHz block
// that holds control channel ch (0 when there is none).
func blockCenter(ch, width int) int {
	firsts := map[int][]int{
		40:  {36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157, 165, 173},
		80:  {36, 52, 100, 116, 132, 149, 165},
		160: {36, 100, 149},
	}[width]
	for _, f := range firsts {
		if ch >= f && ch < f+width/5 {
			return f + (width/5-4)/2
		}
	}
	return 0
}

// chanFreq returns the centre frequency in MHz of a channel in a band.
func chanFreq(ch int, band string) int {
	if band == "ng" {
		if ch == 14 {
			return 2484
		}
		return 2407 + 5*ch
	}
	return 5000 + 5*ch
}
