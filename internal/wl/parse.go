// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"math"
	"math/bits"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// Parsers for the output of read-only `wl` getters (wl 17.10.121.39, as
// captured in testdata/). Each takes raw stdout.

// parseInt reads a single integer value ("-98", "3", "0x3", "1").
func parseInt(b []byte) (int64, bool) {
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(f[0], 0, 64)
	return n, err == nil
}

// parseSSID reads `wl ssid`: `Current SSID: "Example Network"`. wl escapes a
// backslash as `\\` and a non-printable byte as `\xHH`; both are undone.
func parseSSID(b []byte) string {
	s := string(b)
	i, j := strings.IndexByte(s, '"'), strings.LastIndexByte(s, '"')
	if i < 0 || j <= i {
		return ""
	}
	return unescapeSSID(s[i+1 : j])
}

func unescapeSSID(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			if s[i+1] == '\\' {
				out = append(out, '\\')
				i++
				continue
			}
			if s[i+1] == 'x' && i+3 < len(s) {
				if n, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					out = append(out, byte(n))
					i += 3
					continue
				}
			}
		}
		out = append(out, s[i])
	}
	return string(out)
}

// wpa_auth bits (Broadcom wlioctl.h).
const (
	authWPA1X       = 0x0002
	authWPAPSK      = 0x0004
	authWPA21X      = 0x0040
	authWPA2PSK     = 0x0080
	authWPA21X256   = 0x1000
	authWPA2PSK256  = 0x8000
	authWPA3SAE     = 0x40000
	authWPA3Suite1X = 0x400000
)

// parseWPAAuth reads `wl wpa_auth` ("0x40080 WPA2-PSK SAE") into an
// iwinfo-style authentication string: "psk", "sae", "psk+sae", "8021x",
// or "none" for an open network. "" means the output was not understood.
func parseWPAAuth(b []byte) string {
	n, ok := parseInt(b)
	if !ok {
		return ""
	}
	var parts []string
	if n&(authWPA1X|authWPA21X|authWPA21X256|authWPA3Suite1X) != 0 {
		parts = append(parts, "8021x")
	}
	if n&(authWPAPSK|authWPA2PSK|authWPA2PSK256) != 0 {
		parts = append(parts, "psk")
	}
	if n&authWPA3SAE != 0 {
		parts = append(parts, "sae")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "+")
}

// ParseCountry reads `wl country` ("US (US/0) UNITED STATES"): the code
// ("US") and the regulatory revision (0); rev is -1 when the output does
// not give one. It is the one reader of that output.
func ParseCountry(s string) (code string, rev int) {
	rev = -1
	f := strings.Fields(s)
	if len(f) == 0 {
		return "", rev
	}
	if len(f) > 1 && strings.HasPrefix(f[1], "(") {
		in := strings.Trim(f[1], "()")
		if i := strings.IndexByte(in, '/'); i >= 0 {
			if r, err := strconv.Atoi(in[i+1:]); err == nil {
				rev = r
			}
		}
	}
	return f[0], rev
}

// parseCountry reads `wl country` ("US (US/0) UNITED STATES") -> "US".
func parseCountry(b []byte) string {
	code, _ := ParseCountry(string(b))
	return code
}

// firstField returns the first whitespace-separated token of b.
func firstField(b []byte) string {
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// parseCap reads `wl cap` (space-separated capability tokens) into a set.
func parseCap(b []byte) map[string]bool {
	m := map[string]bool{}
	for _, t := range strings.Fields(string(b)) {
		m[t] = true
	}
	return m
}

// maxBSS is the largest "mbssN" token of `wl cap` (mbss8 -> 8), or 1.
func maxBSS(capSet map[string]bool) int {
	n := 1
	for t := range capSet {
		if v, ok := strings.CutPrefix(t, "mbss"); ok {
			if k, err := strconv.Atoi(v); err == nil && k > n {
				n = k
			}
		}
	}
	return n
}

// parseRevinfo reads the chip name from `wl revinfo` ("deviceid 0x4491"
// -> "Broadcom BCM4491").
func parseRevinfo(b []byte) string {
	for line := range strings.Lines(string(b)) {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "deviceid" {
			if n, err := strconv.ParseUint(f[1], 0, 32); err == nil {
				return "Broadcom BCM" + strconv.FormatUint(n, 16)
			}
		}
	}
	return ""
}

// parseTxpwrTargetMax reads `wl txpwr_target_max`
// ("Maximum Tx Power Target (chanspec:0x1804):\t24.00  24.00") and returns
// the highest per-core value in dBm.
func parseTxpwrTargetMax(b []byte) (float64, bool) {
	s := string(b)
	if i := strings.LastIndex(s, "):"); i >= 0 {
		s = s[i+2:]
	}
	best, ok := math.Inf(-1), false
	for _, f := range strings.Fields(s) {
		if v, err := strconv.ParseFloat(f, 64); err == nil {
			best, ok = max(best, v), true
		}
	}
	return best, ok
}

// parseChanspecTxpwrMax reads `wl chanspec_txpwr_max`, one row per chanspec
// ("2l\t(0x1804)\t25.50(dbm)"), into chanspec -> dBm.
func parseChanspecTxpwrMax(b []byte) map[uint16]float64 {
	m := map[uint16]float64{}
	for line := range strings.Lines(string(b)) {
		cs, ok := parseChanspecHex(line)
		if !ok {
			continue
		}
		f := strings.Fields(line)
		v, err := strconv.ParseFloat(strings.TrimSuffix(f[len(f)-1], "(dbm)"), 64)
		if err == nil {
			m[cs.Raw] = v
		}
	}
	return m
}

// parseChanspecs reads `wl chanspecs` ("36/80 (0xe02a)" per line).
func parseChanspecs(b []byte) []chanspec {
	var out []chanspec
	for line := range strings.Lines(string(b)) {
		if cs, ok := parseChanspecHex(line); ok {
			out = append(out, cs)
		}
	}
	return out
}

// channelsByWidth groups chanspecs into width -> sorted control channels.
func channelsByWidth(list []chanspec) map[int][]int {
	seen := map[int]map[int]bool{}
	for _, cs := range list {
		if seen[cs.Width] == nil {
			seen[cs.Width] = map[int]bool{}
		}
		seen[cs.Width][cs.Control] = true
	}
	out := map[int][]int{}
	for w, set := range seen {
		for ch := range set {
			out[w] = append(out[w], ch)
		}
		sort.Ints(out[w])
	}
	return out
}

// chanimRow is the cumulative-µs row of `wl chanim_stats us`. The values
// are raw u64 driver counters that may carry ±k·2^32 offsets after a radio
// re-init: only modular differences between two rows are meaningful.
type chanimRow struct {
	Key                    uint16 // the 20 MHz primary chanspec the row is for
	Tx, Inbss, Busy, Total uint64
}

// parseChanimUs reads `wl chanim_stats us`. Columns are found by the header
// line, so a reordered or longer header still parses.
func parseChanimUs(b []byte) (chanimRow, bool) {
	var hdr []string
	for line := range strings.Lines(string(b)) {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == "chanspec" {
			hdr = f
			continue
		}
		if hdr == nil || !strings.HasPrefix(f[0], "0x") {
			continue
		}
		key, err := strconv.ParseUint(f[0], 0, 16)
		if err != nil {
			return chanimRow{}, false
		}
		row := chanimRow{Key: uint16(key)}
		need := map[string]*uint64{"tx": &row.Tx, "inbss": &row.Inbss, "busy_tm": &row.Busy, "total_tm": &row.Total}
		for i, name := range hdr {
			p, ok := need[name]
			if !ok || i >= len(f) {
				continue
			}
			v, err := strconv.ParseUint(f[i], 10, 64)
			if err != nil {
				return chanimRow{}, false
			}
			*p = v
			delete(need, name)
		}
		return row, len(need) == 0
	}
	return chanimRow{}, false
}

// colonPairs splits "a: 1 b c: 2 d:3" into {"a": "1", "b c": "2", "d": "3"}:
// each value is the first token after a colon, the key is the text since the
// previous value.
func colonPairs(line string) map[string]string {
	m := map[string]string{}
	rest := line
	for {
		k, after, ok := strings.Cut(rest, ":")
		if !ok {
			return m
		}
		after = strings.TrimLeft(after, " \t")
		v, tail, _ := strings.Cut(after, " ")
		m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		rest = tail
	}
}

// parseStaInfoAll reads `wl -i <vap> sta_info all`: one block per client,
// each starting "[VER 8] STA 8C:BF:EA:1D:BA:74:". Lines are matched by label,
// so a missing line leaves its field at zero. Noise is left at zero (the
// caller fills in the radio's noise floor).
func parseStaInfoAll(b []byte) []apstate.Station {
	var out []apstate.Station
	var st *apstate.Station
	var avgRSSI, noiseFloor int
	var smoothed, haveSmoothed = 0, false
	var chanMHz int
	var failures int64
	var haveExhausted bool
	var nssHT, nssVHT, nssHE int
	var lastSet *int // the rate set a continuation line (": 0x2 ...") belongs to
	// notAssoc: the block's "state:" line lacks ASSOCIATED. sta_info all
	// also lists the driver's leftover records of stations that left (empty
	// state, idle for many minutes, RSSI 0; seen on .205 2026-11-19): a
	// Galaxy Watch reported that way by two APs made the controller flip it
	// between them ~20 times a minute at "0 dBm". A block without a state
	// line counts as associated.
	var notAssoc bool
	flush := func() {
		if st == nil {
			return
		}
		if notAssoc {
			st = nil
			return
		}
		switch {
		case haveSmoothed && smoothed != 0:
			st.Signal = smoothed
		default:
			st.Signal = avgRSSI
		}
		st.SignalAvg = st.Signal
		if avgRSSI != 0 {
			st.SignalAvg = avgRSSI
		}
		st.Noise = noiseFloor // replaced by the radio's noise when known
		if st.MHz == 0 {
			st.MHz = chanMHz
		}
		if !haveExhausted {
			st.TxFailed = failures
		}
		switch {
		case nssHE > 0:
			st.NSS = nssHE
		case nssVHT > 0:
			st.NSS = nssVHT
		default:
			st.NSS = nssHT
		}
		out = append(out, *st)
		st = nil
	}
	for line := range strings.Lines(string(b)) {
		t := strings.TrimSpace(line)
		if mac, ok := staHeader(t); ok {
			flush()
			st = &apstate.Station{MAC: mac}
			avgRSSI, noiseFloor, smoothed, haveSmoothed, chanMHz, failures, haveExhausted = 0, 0, 0, false, 0, 0, false
			nssHT, nssVHT, nssHE, lastSet = 0, 0, 0, nil
			notAssoc = false
			continue
		}
		if st == nil {
			continue
		}
		if rest, ok := strings.CutPrefix(t, "state:"); ok {
			notAssoc = !slices.Contains(strings.Fields(rest), "ASSOCIATED") // and parsed on below
		}
		if set, rest, ok := staRateSet(t); ok {
			switch set {
			case "MCS":
				nssHT = max(nssHT, htNSS(rest))
				lastSet = nil
			case "VHT":
				nssVHT, lastSet = max(nssVHT, mcsxNSS(rest)), &nssVHT
			case "HE":
				nssHE, lastSet = max(nssHE, mcsxNSS(rest)), &nssHE
			case "":
				if lastSet != nil {
					*lastSet = max(*lastSet, mcsxNSS(rest))
				}
			}
			continue
		}
		if lastSet == &nssHE {
			// HE SET block: "20/40/80 MHz:" width headers, then one
			// "NSS<n> Tx: 0-11  Rx: 0-11" line per stream count
			if strings.HasSuffix(t, "MHz:") {
				continue
			}
			if r, found := strings.CutPrefix(t, "NSS"); found {
				if d, _, ok := strings.Cut(r, " "); ok {
					if v, err := strconv.Atoi(d); err == nil && v > 0 && v <= 8 {
						nssHE = max(nssHE, v)
					}
				}
				continue
			}
		}
		lastSet = nil
		switch {
		case strings.HasPrefix(t, "idle ") && strings.HasSuffix(t, " seconds"):
			st.Inactive = 1000 * firstInt(t[len("idle "):])
			continue
		case strings.HasPrefix(t, "in network ") && strings.HasSuffix(t, " seconds"):
			st.Connected = firstInt(t[len("in network "):])
			continue
		case strings.HasPrefix(t, "chanspec "):
			if cs, ok := parseChanspecHex(t); ok {
				chanMHz = cs.Width
			}
			continue
		case strings.HasPrefix(t, "flags 0x"):
			_, toks, _ := strings.Cut(t, ":")
			for _, tok := range strings.Fields(toks) {
				switch tok {
				case "N_CAP":
					st.HT = true
				case "VHT_CAP":
					st.VHT = true
				case "HE_CAP":
					st.HE = true
				}
			}
			continue
		case strings.HasPrefix(t, "link bandwidth = "):
			st.MHz = int(firstInt(t[len("link bandwidth = "):]))
			continue
		}
		label, val, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch label {
		case "state":
			st.Authorized = strings.Contains(" "+val+" ", " AUTHORIZED ")
		case "tx ucast bytes":
			st.TxBytes = counter(val)
		case "tx ucast pkts":
			st.TxPackets = counter(val)
		case "rx data bytes":
			st.RxBytes = counter(val)
		case "rx data pkts":
			st.RxPackets = counter(val)
		case "rate of last tx pkt":
			st.TxRate = int(firstInt(val))
		case "rate of last rx pkt":
			st.RxRate = int(firstInt(val))
		case "tx pkts retries":
			st.TxRetries = counter(val)
		case "tx pkts retry exhausted":
			st.TxFailed, haveExhausted = counter(val), true
		case "tx failures":
			failures = counter(val)
		case "smoothed rssi":
			smoothed, haveSmoothed = int(firstInt(val)), true
		case "per antenna average rssi of rx data frames":
			avgRSSI = strongest(val)
		case "per antenna noise floor":
			noiseFloor = strongest(val)
		}
	}
	flush()
	return out
}

// staHeader matches "[VER 8] STA 8C:BF:EA:1D:BA:74:" (the "[VER n]" part is
// optional) and returns the lower-case MAC.
func staHeader(t string) (string, bool) {
	if strings.HasPrefix(t, "[VER") {
		_, t, _ = strings.Cut(t, "]")
		t = strings.TrimSpace(t)
	}
	rest, ok := strings.CutPrefix(t, "STA ")
	if !ok {
		return "", false
	}
	mac := strings.TrimSuffix(strings.TrimSpace(rest), ":")
	hw, err := netParseMAC(mac)
	if err != nil {
		return "", false
	}
	return hw, true
}

// strongest returns the highest non-zero dBm value of a per-antenna list
// ("-69 -63 0 0" -> -63); 0 when all are zero.
func strongest(s string) int {
	best := 0
	for _, f := range strings.Fields(s) {
		v, err := strconv.Atoi(f)
		if err != nil || v == 0 {
			continue
		}
		if best == 0 || v > best {
			best = v
		}
	}
	return best
}

// firstInt parses the leading integer of s ("13500 kbps - 1000 kbps" -> 13500).
func firstInt(s string) int64 {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.ParseInt(f[0], 10, 64)
	return n
}

// counter parses an unsigned driver counter; values beyond int64 (never seen)
// saturate rather than wrap negative.
func counter(s string) int64 {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	n, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil {
		return 0
	}
	if n > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(n)
}

// popcount of a chain mask such as `wl hw_txchain` ("3" -> 2).
func popcount(n int64) int { return bits.OnesCount64(uint64(n)) }

// staRateSet recognises wl sta_info's rate-set lines: "MCS SET : [ 0 1 .. ]"
// (HT), "VHT SET : 0x1 1x1 .. 9x1" and "HE SET : .." (one "<mcs>x<nss>"
// token per supported MCS), and their continuation lines ": 0x2 1x2 .."
// (the next stream count; wlu.c prints one line per NSS). set is "MCS",
// "VHT", "HE", or "" for a continuation.
func staRateSet(t string) (set, rest string, ok bool) {
	for _, s := range []string{"MCS", "VHT", "HE"} {
		if after, found := strings.CutPrefix(t, s+" SET"); found {
			if _, r, c := strings.Cut(after, ":"); c {
				return s, r, true
			}
		}
	}
	if r, found := strings.CutPrefix(t, ":"); found && strings.Contains(r, "x") {
		return "", r, true
	}
	return "", "", false
}

// htNSS is the HT stream count of an MCS SET list: MCS 0-7 is one stream,
// 8-15 two, and so on (MCS 32 is the 40 MHz duplicate rate, not a stream).
func htNSS(list string) int {
	n := 0
	for _, f := range strings.Fields(strings.Trim(strings.TrimSpace(list), "[]")) {
		if v, err := strconv.Atoi(f); err == nil && v >= 0 && v < 32 {
			n = max(n, v/8+1)
		}
	}
	return n
}

// mcsxNSS is the highest NSS of "<mcs>x<nss>" tokens.
func mcsxNSS(list string) int {
	n := 0
	for _, f := range strings.Fields(list) {
		if _, b, ok := strings.Cut(f, "x"); ok {
			if v, err := strconv.Atoi(b); err == nil && v > 0 && v <= 8 {
				n = max(n, v)
			}
		}
	}
	return n
}
