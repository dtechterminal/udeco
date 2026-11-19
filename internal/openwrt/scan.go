// SPDX-License-Identifier: GPL-2.0-or-later

package openwrt

import (
	"fmt"
	"strings"
)

// Scan runs an active scan on an AP interface (ap-force: a UAP's RF scan
// also leaves the channel briefly) and reads the channel survey around it.
// perStep: channels per off-channel step (1 on a radio with clients: about
// 0.1 s away, then 1 s back on its channel).
func (cl *Client) Scan(iface string, perStep int) ([]BSS, []ChanSurvey, error) {
	if perStep < 1 || perStep > 8 {
		perStep = 4
	}
	if !ifaceSafe(iface) {
		return nil, nil, fmt.Errorf("scan: bad interface %q", iface)
	}
	// One full-band scan gives each 5 GHz channel too short a dwell on
	// ath10k (it found only the AP's own channel; a one-channel scan of 149
	// found the UniFi console's AP at -41 dBm, docs/internals.md). So: 4 channels at a
	// time, a short pause between (clients get the radio back).
	out, err := cl.Run(fmt.Sprintf(`IF=%[1]s
N=%[2]d
phy=$(cat /sys/class/net/$IF/phy80211/name) || exit 1
iw dev $IF survey dump; echo @@SCAN@@
set -- $(iw phy $phy info | awk '/^[ \t]+\* [0-9]+(\.[0-9]+)? MHz/ && !/disabled/ {print int($2)}')
while [ $# -gt 0 ]; do
	chunk="$1"; shift
	i=1; while [ $i -lt $N ] && [ $# -gt 0 ]; do chunk="$chunk $1"; shift; i=$((i+1)); done
	iw dev $IF scan freq $chunk ap-force 2>/dev/null || { sleep 1; iw dev $IF scan freq $chunk ap-force 2>/dev/null; }
	sleep 0.3 2>/dev/null || sleep 1
done
echo @@SURVEY@@; iw dev $IF survey dump`, iface, perStep))
	if err != nil {
		return nil, nil, fmt.Errorf("scan %s: %v (%s)", iface, err, firstLine(string(out)))
	}
	s := string(out)
	before, rest, ok1 := strings.Cut(s, "@@SCAN@@")
	scan, after, ok2 := strings.Cut(rest, "@@SURVEY@@")
	if !ok1 || !ok2 {
		return nil, nil, fmt.Errorf("scan %s: unexpected output", iface)
	}
	// each step prints the whole cache: keep the newest copy of each BSS
	// (the kernel drops entries after 30 s, so a final dump would lose the
	// first channels of a slow scan)
	all := ParseScan(scan)
	idx := map[string]int{}
	var bss []BSS
	for _, b := range all {
		if i, ok := idx[b.BSSID]; ok {
			bss[i] = b
			continue
		}
		idx[b.BSSID] = len(bss)
		bss = append(bss, b)
	}
	return bss, SurveyDelta(ParseSurvey(before), ParseSurvey(after)), nil
}

func ifaceSafe(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}

// ScanIface is the daemon's listen-only interface on a spare radio (the
// OnHub's third radio: 2.4 + 5 GHz, one antenna, unused by OpenWrt's
// config). Scanning there never takes a client radio off its channel
// (docs/internals.md). The collector skips it (collectScript), so the UniFi
// doesn't see an extra radio.
const ScanIface = "uowscan0"

// EnsureScanIface creates ScanIface on a radio that has no interface at all
// (managed mode, never associated) and returns whether it exists.
func (cl *Client) EnsureScanIface() bool {
	out, err := cl.Run(`IF=` + ScanIface + `
if [ -e /sys/class/net/$IF ]; then ip link set $IF up 2>/dev/null; echo ok; exit 0; fi
used=" $(cat /sys/class/net/*/phy80211/name 2>/dev/null | tr '\n' ' ')"
for d in /sys/class/ieee80211/*; do
	p=$(basename $d)
	case "$used" in *" $p "*) continue;; esac
	iw phy $p interface add $IF type managed 2>/dev/null && ip link set $IF up 2>/dev/null && { echo ok; exit 0; }
done
echo none`)
	return err == nil && strings.TrimSpace(string(out)) == "ok"
}

// ScanSpare runs one full scan on ScanIface: every band the spare radio
// has, with the channel survey around it.
func (cl *Client) ScanSpare() ([]BSS, []ChanSurvey, error) {
	out, err := cl.Run("iw dev " + ScanIface + " survey dump; echo @@SCAN@@; iw dev " + ScanIface + " scan || { sleep 2; iw dev " + ScanIface + " scan; }; echo @@SURVEY@@; iw dev " + ScanIface + " survey dump")
	if err != nil {
		return nil, nil, fmt.Errorf("scan %s: %v (%s)", ScanIface, err, firstLine(string(out)))
	}
	before, rest, ok1 := strings.Cut(string(out), "@@SCAN@@")
	scan, after, ok2 := strings.Cut(rest, "@@SURVEY@@")
	if !ok1 || !ok2 {
		return nil, nil, fmt.Errorf("scan %s: unexpected output", ScanIface)
	}
	return ParseScan(scan), SurveyDelta(ParseSurvey(before), ParseSurvey(after)), nil
}
