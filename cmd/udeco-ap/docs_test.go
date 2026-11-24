// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/dtechterminal/udeco/internal/repotest"
)

// Tests that hold the documents to the agent: the code paths they name,
// and the numbers of the agent's own behaviour that the feature notes and
// the README state. The documents keep their prose. Each sentence below is
// that prose with its number taken from the constant, so a changed
// constant fails here until the sentence says the same.
//
// The numbers of the dated analyses are left out on purpose
// (docs/deco/interference-audit.md, docs/deco/features/dfs.md, the dated
// sections 3.6 to 3.9 of docs/deco/agent-design.md, docs/reference): they
// say what was measured or decided on their date. The resource watchdog's
// limits (boot.go) are stated only there. The one part of those sections
// that is held is the capability table of 3.6 with the Result paragraph
// under it, which is the reference for what the agent claims
// (internal/models, and docsCapabilityWords below).

// ---------------------------------------------------------------- paths

// pathPrefixes are the top-level directories a document names code by.
var pathPrefixes = []string{"cmd/", "internal/", "deploy/", "packaging/", "tools/", "docs/"}

// docPathSkip lists what the path check leaves alone, each with its reason.
var docPathSkip = struct {
	dirs  map[string]string            // every document under the directory
	paths map[string]map[string]string // document -> path as written -> reason
}{
	dirs: map[string]string{
		// studies of a real U6 Pro against the upstream tree as it was on
		// their date (upstream's openwrt/unifi.go has moved since)
		"docs/reference/u6pro/": "dated study of the upstream tree",
	},
	paths: map[string]map[string]string{
		"docs/internals.md": {
			"docs/PROTOCOL*.md": "files of the projects the protocol was learnt from, not of this repository",
			"docs/PROTOCOL.md":  "a file of unifi-emu, not of this repository",
		},
	},
}

var (
	docTick = regexp.MustCompile("`([^`\n]+)`")
	docBare = regexp.MustCompile(`(?:^|[\s("'\[])((?:cmd|internal|deploy|packaging|tools|docs)/[^\s` + "`" + `]+)`)
	docLink = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	docHead = regexp.MustCompile(`(?m)^#{1,6} +(.+?) *$`)
)

// docPath is the file or directory a document's token names: the token up
// to its first blank, without a line citation (":164-175"), an anchor, the
// rest of a Markdown link and trailing punctuation.
func docPath(tok string) string {
	tok, _, _ = strings.Cut(tok, " ")
	tok, _, _ = strings.Cut(tok, "](")
	tok, _, _ = strings.Cut(tok, ":")
	tok, _, _ = strings.Cut(tok, "#")
	return strings.TrimRight(tok, ".,;)*")
}

// slug is the anchor GitHub gives a heading: lower case, letters, digits,
// "-" and "_" kept, a blank becomes "-", everything else is dropped.
func slug(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

// Every path a document names exists: the code paths in backticks or in
// the running text that start at one of the repository's top directories,
// and the targets of its relative links (a link's anchor is a heading of
// the file it points to). design.md's "R/..." citations are paths of the
// upstream tree and are not read as paths of this one. Line numbers are
// not checked.
func TestDocsPathsExist(t *testing.T) {
	root := repotest.Root(t)
	exists := func(rel string) bool {
		if strings.ContainsAny(rel, "*?[") {
			m, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(rel)))
			return len(m) > 0
		}
		_, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
		return err == nil
	}
	anchors := map[string]map[string]bool{}
	hasAnchor := func(rel, a string) bool {
		if anchors[rel] == nil {
			anchors[rel] = map[string]bool{}
			seen := map[string]int{} // a repeated heading gets "-1", "-2", ...
			for _, m := range docHead.FindAllStringSubmatch(repotest.Read(t, rel), -1) {
				a := slug(m[1])
				if n := seen[a]; n > 0 {
					anchors[rel][fmt.Sprintf("%s-%d", a, n)] = true
				} else {
					anchors[rel][a] = true
				}
				seen[a]++
			}
		}
		return anchors[rel][a]
	}
	checked, skipped := 0, map[string]bool{}
docs:
	for _, md := range repotest.Markdown(t) {
		for dir := range docPathSkip.dirs {
			if strings.HasPrefix(md, dir) {
				skipped[dir] = true
				continue docs
			}
		}
		text := repotest.Read(t, md)
		check := func(tok string) {
			p := docPath(tok)
			ok := false
			for _, pre := range pathPrefixes {
				ok = ok || strings.HasPrefix(p, pre)
			}
			if !ok || strings.ContainsAny(p, "<>{}$") {
				return // not a path of this tree, or one with a placeholder
			}
			if _, skip := docPathSkip.paths[md][p]; skip {
				skipped[md+" "+p] = true
				return
			}
			checked++
			if !exists(p) {
				t.Errorf("%s names %s, which does not exist", md, p)
			}
		}
		for _, m := range docTick.FindAllStringSubmatch(text, -1) {
			check(m[1])
		}
		for _, m := range docBare.FindAllStringSubmatch(docTick.ReplaceAllString(text, "` `"), -1) {
			check(m[1])
		}
		for _, m := range docLink.FindAllStringSubmatch(text, -1) {
			target, anchor, _ := strings.Cut(m[1], "#")
			if strings.Contains(target, ":") {
				continue // a URL
			}
			file := md
			if target != "" {
				file = filepath.ToSlash(filepath.Join(filepath.Dir(md), filepath.FromSlash(target)))
				checked++
				if !exists(file) {
					t.Errorf("%s links to %s, which does not exist", md, m[1])
					continue
				}
			}
			if anchor != "" && strings.HasSuffix(file, ".md") && !hasAnchor(file, anchor) {
				t.Errorf("%s links to %s: %s has no heading with that anchor", md, m[1], file)
			}
		}
	}
	if checked < 300 {
		t.Errorf("%d paths checked: the documents were not read", checked)
	}
	// a skip that no longer skips anything is a stale entry
	for dir := range docPathSkip.dirs {
		if !skipped[dir] {
			t.Errorf("docPathSkip: no document under %s", dir)
		}
	}
	for md, paths := range docPathSkip.paths {
		for p := range paths {
			if !skipped[md+" "+p] {
				t.Errorf("docPathSkip: %s no longer names %s", md, p)
			}
			if exists(p) {
				t.Errorf("docPathSkip: %s exists now, so %s need not be skipped", p, md)
			}
		}
	}
}

// ----------------------------------------------------------- thresholds

// docClaim is one sentence of a document. holds is false when a constant
// no longer has the value the sentence gives in words ("a minute", "the
// hour"): the sentence and this test are then reworded together.
type docClaim struct {
	rel, phrase string
	holds       bool
}

func checkDocClaims(t *testing.T, claims []docClaim) {
	t.Helper()
	texts := map[string]string{}
	for _, c := range claims {
		if !c.holds {
			t.Errorf("%s says %q, which the code's constant no longer is: reword the document and this test", c.rel, c.phrase)
			continue
		}
		if _, ok := texts[c.rel]; !ok {
			texts[c.rel] = flat(repotest.Read(t, c.rel))
		}
		if !strings.Contains(texts[c.rel], c.phrase) {
			t.Errorf("%s does not have %q", c.rel, c.phrase)
		}
	}
}

// docUnits writes a duration the way the documents do: "5 s", "10 min",
// "2 h". The test fails when d is not a whole number of the unit.
type docUnits struct{ t *testing.T }

func (u docUnits) whole(d, unit time.Duration, name string) string {
	u.t.Helper()
	if d <= 0 || d%unit != 0 {
		u.t.Fatalf("%s is not a whole number of %s: reword the documents and this test", d, name)
	}
	return fmt.Sprintf("%d %s", d/unit, name)
}
func (u docUnits) s(d time.Duration) string   { u.t.Helper(); return u.whole(d, time.Second, "s") }
func (u docUnits) min(d time.Duration) string { u.t.Helper(); return u.whole(d, time.Minute, "min") }
func (u docUnits) h(d time.Duration) string   { u.t.Helper(); return u.whole(d, time.Hour, "h") }
func (u docUnits) minutes(d time.Duration) string {
	u.t.Helper()
	return u.whole(d, time.Minute, "minutes")
}

const (
	docReadme    = "README.md"
	docDesign    = "docs/deco/agent-design.md"
	docPackaging = "packaging/deco/README.md"
	docNotes     = "docs/deco/features/"
)

// The Deco's uplink-loss hold (uplink.go).
func TestDocsUplinkLoss(t *testing.T) {
	u := docUnits{t}
	var tm timing
	tm.fill()
	const note = docNotes + "uplink-loss.md"
	checkDocClaims(t, []docClaim{
		{note, "a watcher reads `/sys/class/net/<uplink>/carrier` every second", tm.uplinkPoll == time.Second},
		{note, "No carrier for " + u.s(uplinkLostAfter) + ": SSIDs down. Carrier again for " + u.s(uplinkBackAfter) + " (a shorter return changes nothing): SSIDs up.", true},
		{note, "A failed change is retried after " + u.s(uplinkRetry) + ";", true},
		{note, "the agent's own ICMP echo to the gateway every " + u.s(tm.gwProbe) + " (" + u.s(gwProbeTimeout) + " timeout); unanswered for " + u.s(gwDownAfter) +
			" counts as a lost uplink with the carrier up, and an answer (plus " + u.s(uplinkBackAfter) + " of carrier) brings the SSIDs back.", tm.gwProbe == gwProbeEvery},
		{docReadme, "No carrier on the uplink port for " + u.s(uplinkLostAfter) + " takes every SSID down (no radio restart); " + u.s(uplinkBackAfter) + " of carrier brings them back.", true},
		{docReadme, "`\"uplink_gateway_down\": true` also counts a gateway unanswered for " + u.s(gwDownAfter) + ".", true},
		{docDesign, "every served SSID goes `wl bss down` after " + u.s(uplinkLostAfter) + " without carrier on the tracked uplink port and back up after " + u.s(uplinkBackAfter) + " of carrier,", true},
		{docDesign, "a gateway unanswered by the agent's own ICMP echo for " + u.s(gwDownAfter) + " also counts as a lost uplink", true},
	})
}

// Minimum RSSI on the Deco (minrssi.go).
func TestDocsMinRSSI(t *testing.T) {
	u := docUnits{t}
	const note = docNotes + "min-rssi.md"
	// a beacon interval is about a tenth of a second
	timer := fmt.Sprintf("disassociation timer %d beacon intervals, about %d s", minRSSIDisassocTBTT, minRSSIDisassocTBTT/10)
	checkDocClaims(t, []docClaim{
		{note, fmt.Sprintf("a client on a band with a minimum qualifies after %d readings in a row below it;", minRSSIBelow), true},
		{note, timer, minRSSIDisassocTBTT%10 == 0},
		{note, "still on that BSS " + u.s(minRSSIKickAfter) + " later, or right away when no other AP was heard", true},
		{note, "it is kicked with a " + u.s(minRSSIBan) + " ban on that BSS", true},
		{note, "the ban is lifted after " + u.s(minRSSIBan) + "; nothing more is done to the client for " + u.minutes(minRSSIHold) + ";", true},
		{docReadme, fmt.Sprintf("A client below the controller's minimum for %d readings is asked to leave (802.11v, disassociation imminent), then disconnected with a %s ban on that BSS;",
			minRSSIBelow, u.s(minRSSIBan)), true},
	})
}

// Restrict to 5 GHz (no2ghz.go).
func TestDocsNo2GHz(t *testing.T) {
	u := docUnits{t}
	const note = docNotes + "no2ghz.md"
	checkDocClaims(t, []docClaim{
		{note, fmt.Sprintf("5 GHz BSS within the last hour at %d dBm or better", no2ghzMin5), no2ghzRecent == time.Hour},
		{note, fmt.Sprintf("and its 2.4 GHz signal is %d dBm or better", no2ghzMin24), true},
		{note, "at most once per " + u.minutes(no2ghzEvery) + ", whatever the band steering mode", true},
		{note, "still on the 2.4 GHz BSS a minute later without having been seen on 5 GHz in between", no2ghzJudge == time.Minute},
		{note, "when it was seen on 5 GHz within the last " + u.minutes(no2ghzBanRecent) + " (an older sighting asks but never bans)", true},
		{note, "is kept off the 2.4 GHz BSS for one minute", no2ghzDeny == time.Minute},
		{note, "plus a deauth from that vif), at most once per hour;", no2ghzDenyEvery == time.Hour},
		{docReadme, "Dual-band clients seen on the SSID's 5 GHz BSS within the hour with a usable signal are asked (802.11v) to leave 2.4 GHz;", no2ghzRecent == time.Hour},
		{docReadme, "one that ignores it is kept off 2.4 GHz for a minute, at most once an hour.", no2ghzDeny == time.Minute && no2ghzDenyEvery == time.Hour},
	})
}

// Gratuitous ARP on association, on both platforms (garp.go, garage.go).
func TestDocsAssocGARP(t *testing.T) {
	u := docUnits{t}
	checkDocClaims(t, []docClaim{
		{docNotes + "assoc-garp.md", "At most once per station per " + u.s(garpEvery) + ";", true},
		{docNotes + "assoc-garp.md", "seen by the connection-event taps within the last hour on a BSS of the same bridge", staIPKeep == time.Hour},
		{docNotes + "assoc-garp.md", "An address stays known for an hour:", staIPKeep == time.Hour},
		{docNotes + "garage-parity.md", "at most every " + u.s(garpGap) + " per station;", true},
	})
}

// The Roaming Assistant (roaming.go).
func TestDocsRoamingAssistant(t *testing.T) {
	u := docUnits{t}
	var tm timing
	tm.fill()
	const note = docNotes + "roaming-assistant.md"
	// the waits after requests that did not help: doubled up to the cap
	var steps []string
	for d := 2 * roamHold; d < roamHoldMax; d *= 2 {
		steps = append(steps, strings.TrimSuffix(u.min(d), " min"))
	}
	const example = -75 // the note's example threshold: the controller's default on 5 GHz
	checkDocClaims(t, []docClaim{
		{note, fmt.Sprintf("stayed below the threshold in at least %d readings in a row and for at least %s (`roamBelow`, `timing.roamSustain`).", roamBelow, u.s(tm.roamSustain)), tm.roamSustain == roamSustain},
		{note, fmt.Sprintf("heard within the last %s (`roamCandAge`) at the threshold + %d dB or better (`roamCandMargin`, e.g. %d dBm for %d). Up to %d are named, strongest first.",
			u.min(roamCandAge), roamCandMargin, example+roamCandMargin, example, roamScanCands), true},
		{note, "This is logged once per client per hour (`roamNoCandLog`).", roamNoCandLog == time.Hour},
		{note, "After a request the same client is not asked again for " + u.min(roamHold) + " (`roamHold`).", true},
		{note, "on the same BSS " + u.min(roamJudge) + " after the request (`roamJudge`)", true},
		{note, "A client that comes back within " + u.min(roamReturn) + " (`roamReturn`) counts the same way. Each such outcome doubles the wait: " +
			strings.Join(steps, ", ") + " min, capped at " + u.h(roamHoldMax) + " (`roamHoldMax`). A client that stays away for " + u.min(roamReturn) + " ends the backoff.", len(steps) > 0},
		{note, fmt.Sprintf("At most %d requests are sent per reading, weakest client first.", roamPerRead), true},
		{note, "the client is held for " + u.h(roamNoBTMHold) + " (`roamNoBTMHold`)", true},
		{note, fmt.Sprintf("disassoc_imminent=1 disassoc_timer=%d pref=1 abridged=1", roamDisassocTBTT), true},
		{note, fmt.Sprintf("when the timer (%d beacon intervals, about %d s) runs out", roamDisassocTBTT, roamDisassocTBTT/10), roamDisassocTBTT%10 == 0},
		// the capability table's row of the feature
		{docDesign, fmt.Sprintf("to a BTM-capable station that stayed below the threshold for at least %d readings in a row and %s; no candidate, no request", roamBelow, u.min(roamSustain)), true},
	})
}

// The boot gate and the crash-loop guard (boot.go).
func TestDocsBootGate(t *testing.T) {
	u := docUnits{t}
	checkDocClaims(t, []docClaim{
		{docReadme, fmt.Sprintf("until the agent's boot gate opens (at least %d s).", gateMinUptime), true},
		{docReadme, fmt.Sprintf("TP-Link's boot has finished (at least %d s); then the agent takes over.", gateMinUptime), true},
		{docPackaging, fmt.Sprintf("(at least %d s, TP-Link's boot finished)", gateMinUptime), true},
		{docDesign, fmt.Sprintf("A crash loop (%d starts in %s of uptime) leaves the agent in observe mode", crashStarts, u.min(crashWindow)), true},
	})
}

// Connection-timing events (staconn.go).
func TestDocsConnectionEvents(t *testing.T) {
	u := docUnits{t}
	const note = docNotes + "connection-events.md"
	checkDocClaims(t, []docClaim{
		{note, fmt.Sprintf("Frames go to a ring of %d that drops the oldest", snoopMax), true},
		{note, "soft failure: authorized " + u.s(staConnJudge) + " ago without that (unanswered queries older than " + u.s(staDNSTimeout) + " are `dns_timeouts`,", true},
		{note, "a success within " + u.minutes(staConnFixup) + " after a soft failure sends a fixup", true},
		{note, "failure: never authorized " + u.s(staConnJudge) + " after it started and not associated in the reading;", true},
	})
}

// The capability words the agent informs are the ones the Result paragraph
// of agent-design.md's capability table quotes. checkFlow calls this with
// the last inform of each end-to-end run (observe, takeover with none of
// the optional keys); internal/models holds the same paragraph to the
// profile it computes.
func docsCapabilityWords(t *testing.T, takeover bool, inform map[string]any) {
	t.Helper()
	w := func(k string) int64 { return int64(num(inform[k])) }
	claims := []docClaim{
		{docDesign, fmt.Sprintf("Observe mode: `wifi_caps %d` (WPA3), `fw_caps %#x` (", w("wifi_caps"), w("fw_caps")), true},
		{docDesign, fmt.Sprintf("`fw3_caps %#x` (path monitoring), no wifi_caps2/fw2_caps/hw_caps.", w("fw3_caps")),
			inform["wifi_caps2"] == nil && inform["fw2_caps"] == nil && inform["hw_caps"] == nil},
	}
	if takeover {
		claims = []docClaim{
			{docDesign, fmt.Sprintf("Takeover: `wifi_caps %d` (%#x: WPA3 | RF_SCAN | BANDSTEER | WPA_PSK_FILE | LOCK_AP,", w("wifi_caps"), w("wifi_caps")), true},
			{docDesign, fmt.Sprintf("`wifi_caps2 %#x` (Roaming Assistant, quick scan), `fw_caps %#x` (+ RADIUS filter;", w("wifi_caps2"), w("fw_caps")), true},
			{docDesign, fmt.Sprintf("`fw2_caps %#x` (RadSec;", w("fw2_caps")), true},
			{docDesign, fmt.Sprintf("`fw3_caps %#x` (+ multicast inspect)", w("fw3_caps")), inform["hw_caps"] == nil},
		}
	}
	checkDocClaims(t, claims)
}
