// SPDX-License-Identifier: GPL-2.0-or-later

package deco

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
)

// The protocol document's opcode table (section 8) has a row for every
// opcode constant of schemas.go, so an opcode added to the code is added
// to the table. A row names its opcodes in its first cell: one, several
// ("0x401a / 0x401b") or a range ("0x4402-0x4407").
func TestDocsOpcodeTable(t *testing.T) {
	const doc, src = "docs/deco/deco-tmp-protocol.md", "internal/deco/schemas.go"
	text := repotest.Read(t, doc)
	_, sec, ok := strings.Cut(text, "\n## 8. Opcodes the wrapper needs\n")
	if !ok {
		t.Fatalf("%s has no section 8", doc)
	}
	sec, _, _ = strings.Cut(sec, "\n### ")
	rows := map[int64]bool{}
	hex := regexp.MustCompile(`0x[0-9a-f]{4}`)
	span := regexp.MustCompile(`^(0x[0-9a-f]{4})-(0x[0-9a-f]{4})$`)
	num := func(s string) int64 {
		n, err := strconv.ParseInt(s, 0, 64)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, l := range strings.Split(sec, "\n") {
		cells := strings.Split(l, "|")
		if len(cells) < 3 || !strings.HasPrefix(strings.TrimSpace(cells[1]), "0x") {
			continue
		}
		cell := strings.TrimSpace(cells[1])
		if m := span.FindStringSubmatch(cell); m != nil {
			for o := num(m[1]); o <= num(m[2]); o++ {
				rows[o] = true
			}
			continue
		}
		for _, h := range hex.FindAllString(cell, -1) {
			rows[num(h)] = true
		}
	}
	consts := repotest.IntConsts(t, src)
	// the constants as read from the source are the compiled ones
	for name, v := range map[string]uint16{"OpNegotiation": OpNegotiation, "OpGetMLO": OpGetMLO, "OpAccountModify": OpAccountModify, "OpSetClientAccess": OpSetClientAccess} {
		if consts[name] != int64(v) {
			t.Fatalf("%s reads %s as %#x, it is %#x", src, name, consts[name], v)
		}
	}
	n := 0
	for name, v := range consts {
		if !strings.HasPrefix(name, "Op") {
			continue
		}
		n++
		if !rows[v] {
			t.Errorf("%s section 8 has no row for %s (0x%04x)", doc, name, v)
		}
	}
	if n < 30 {
		t.Errorf("%s: found %d Op constants, the table is not checked", src, n)
	}
}

// The documents of the off-device daemon tell the reader how long it waits
// and how often it reads. They keep their prose; each sentence below is
// that prose with its numbers taken from the constants, so a changed
// constant fails here until the sentence is brought up to it.
func TestDocsTimers(t *testing.T) {
	const readme, design = "docs/deco/README.md", "docs/deco/design.md"
	whole := func(d, unit time.Duration, name string) string {
		if d <= 0 || d%unit != 0 {
			t.Fatalf("%s is not a whole number of %s: reword the documents and this test", d, name)
		}
		return fmt.Sprintf("%d %s", d/unit, name)
	}
	secs := func(d time.Duration) string { return whole(d, time.Second, "s") }
	mins := func(d time.Duration) string { return whole(d, time.Minute, "min") }

	m, err := NewMesh(MeshConfig{MasterIP: "192.168.0.241", MasterMAC: "b0:a7:b9:3e:16:94", TPLinkID: "a@b.c", Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	// what NewMesh fills in is what the constants say
	for name, c := range map[string][2]time.Duration{
		"Poll":            {m.cfg.Poll, DefaultPoll},
		"ClientsEvery":    {m.cfg.ClientsEvery, MinClientsEvery},
		"WirelessEvery":   {m.cfg.WirelessEvery, defaultWirelessEvery},
		"PortsEvery":      {m.cfg.PortsEvery, defaultPortsEvery},
		"BlocksEvery":     {m.cfg.BlocksEvery, defaultBlocksEvery},
		"RedialMin":       {m.cfg.RedialMin, RedialFloor},
		"RedialMax":       {m.cfg.RedialMax, RedialCeiling},
		"RequestTimeout":  {m.cfg.RequestTimeout, DefaultRequestTimeout},
		"CommandTimeout":  {m.cfg.CommandTimeout, defaultCommandTimeout},
		"WLANMinInterval": {m.cfg.WLANMinInterval, WLANMinInterval},
		"Heartbeat":       {m.cfg.Heartbeat, DefaultHeartbeat},
	} {
		if c[0] != c[1] {
			t.Errorf("NewMesh leaves %s at %s, the constant is %s", name, c[0], c[1])
		}
	}
	if DefaultRequestTimeout != 45*time.Second || defaultMaxAge != 45*time.Second || MaxAge(0) != defaultMaxAge || MaxAge(20*time.Second) != time.Minute {
		t.Errorf("DefaultRequestTimeout %s, defaultMaxAge %s, MaxAge(0) %s, MaxAge(20s) %s", DefaultRequestTimeout, defaultMaxAge, MaxAge(0), MaxAge(20*time.Second))
	}

	// the login backoff as the Mesh computes it: 1, 2, 4, 8 then 15 min
	var steps []string
	n := 1
	for ; m.backoff(n) < m.cfg.RedialMax; n++ {
		steps = append(steps, strings.TrimSuffix(mins(m.backoff(n)), " min"))
		if n > 20 {
			t.Fatal("the login backoff never reaches RedialCeiling")
		}
	}
	backoff := strings.Join(steps, ", ") + " then " + mins(m.backoff(n))

	// BYE reasons by how long they hold the next login off
	reasons := func(d time.Duration) []string {
		var out []string
		for r, v := range byeDelay {
			if v == d {
				out = append(out, fmt.Sprint(r))
			}
		}
		sort.Strings(out)
		return out
	}
	busy, restart := byeDelay[3], byeDelay[4] // CLIENT_LIMIT, SYSTEM_REBOOT
	busyR, restartR := reasons(busy), reasons(restart)
	if len(busyR) != 2 || len(restartR) != 2 || len(byeDelay) != 4 {
		t.Fatalf("byeDelay %v: the documents name two reasons for each of two delays", byeDelay)
	}

	words := map[int]string{2: "two", 3: "three", 4: "four", 5: "five"}
	rejects, ok := words[disableAfter]
	if !ok {
		t.Fatalf("disableAfter %d: reword the documents and this test", disableAfter)
	}
	op := func(o uint16) string { return fmt.Sprintf("0x%04x", o) }
	slow := AppRequestTimeout(OpGetClientList)

	for rel, phrases := range map[string][]string{
		readme: {
			"It polls the device list, client speeds (" + op(OpGetClientSpeedList) + ") and IoT clients (" + op(OpGetIoTClientList) + ") every " + secs(DefaultPoll) +
				", Wi-Fi info every " + secs(defaultWirelessEvery) + ", port status every " + mins(defaultPortsEvery) +
				", the block list every " + secs(defaultBlocksEvery) + " and the slow client list (" + op(OpGetClientList) +
				", names and last known placement) every " + mins(MinClientsEvery) + ",",
			"Logins are at least " + secs(RedialFloor) + " apart, backing off " + backoff + ". A session that lasts " + mins(stableAfter) + " resets the backoff.",
			"a BYE \"auth changed\" (" + fmt.Sprint(byeAuthChanged) + ")",
			"| BYE back-off | " + mins(busy) + " for reasons " + busyR[0] + " and " + busyR[1] + " (the app may hold the session); " +
				mins(restart) + " for " + restartR[0] + " and " + restartR[1] + " (reboot or upgrade). |",
			"| BYE " + busyR[0] + " or " + busyR[1] + " in the logs | The Deco app holds the session. udeco waits " + mins(busy) + " before logging in again. |",
			"The firmware rejects that read " + rejects + " times in a row.",
			"every unit back within " + mins(WLANVerifyWindow) + ".",
			"| Debounce | Waits " + secs(WLANDebounce) + " for UniFi's changes to settle. |",
			"| Rate limit | At most one apply per " + mins(WLANMinInterval) + ". |",
			"resent every " + secs(WLANRollbackEvery) + " for up to " + mins(WLANRollbackFor) + ".",
		},
		design: {
			"`RequestTimeout = " + DefaultRequestTimeout.String() + "` (the app's " + secs(appTimeoutDefault) + " + " + secs(appTimeoutSlack) + "); " +
				op(OpGetClientList) + " gets " + secs(slow) + ", as in the app (`postRequestForGet(..., " + fmt.Sprint(int(appTimeouts[OpGetClientList]/time.Second)) + "L)`",
			"plus " + secs(appTimeoutSlack) + " at `apps/network/tmp/i0.java:581`",
			"at least " + secs(RedialFloor) + " apart, with exponential backoff up to " + mins(RedialCeiling) + ".",
			"On reason " + busyR[0] + " (CLIENT_LIMIT) or " + busyR[1] + " (USER_COUNT_EXCEED), back off for " + mins(busy) + ".",
			"On reason " + restartR[0] + " (reboot) or " + restartR[1] + " (upgrade), back off for " + mins(restart) + ".",
			"On reason " + fmt.Sprint(byeAuthChanged) + " (auth changed), latch off.",
			"| Device list | " + op(OpGetDeviceList) + " | " + secs(DefaultPoll) + " | |",
			"| Client speeds (presence) | " + op(OpGetClientSpeedList) + " | " + secs(DefaultPoll) + " | `" + pollComponent[OpGetClientSpeedList] + "` |",
			"| IoT clients | " + op(OpGetIoTClientList) + " | " + secs(DefaultPoll) + " | `" + pollComponent[OpGetIoTClientList] + "` |",
			"| Wireless info | " + op(OpGetWireless) + " | " + secs(defaultWirelessEvery) + ", and after every apply | |",
			"| Port status | " + op(OpGetDeviceEthPort) + " for all device_ids | " + mins(defaultPortsEvery) + " | |",
			"| Block list | " + op(OpGetBlockList) + " | " + secs(defaultBlocksEvery) + " | |",
			"| Client list (enrichment) | " + op(OpGetClientList) + " | `clients_every`, default and minimum " + mins(MinClientsEvery) +
				"; `no_client_list` turns it off | `" + pollComponent[OpGetClientList] + "` |",
			"While the slow " + op(OpGetClientList) + " blocks the session (up to its " + secs(slow) + " budget)",
			"which is debounced by " + secs(WLANDebounce) + ".",
			"**Debounce** for " + secs(WLANDebounce) + ",",
			"**Verify.** Within " + mins(WLANVerifyWindow) + ", all of these must hold:",
			"every " + secs(WLANRollbackEvery) + " for up to " + mins(WLANRollbackFor) + ". Then **latch apply off**",
			"**Rate-limit:** at most one apply per " + mins(WLANMinInterval) + ".",
		},
	} {
		for _, p := range phrases {
			repotest.MustContain(t, rel, p)
		}
	}

	// the design's table lists the polls in the order the Mesh runs them
	doc := repotest.Read(t, design)
	at := 0
	for _, o := range m.PolledOps() {
		i := strings.Index(doc[at:], "| "+op(o)+" ")
		if i < 0 {
			t.Fatalf("%s: the polling table does not have %s after the polls before it (the Mesh's order is %x)", design, op(o), m.PolledOps())
		}
		at += i
	}
}
