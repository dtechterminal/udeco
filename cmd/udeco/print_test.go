// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/deco"
)

func printResult(t *testing.T, out []byte) string {
	t.Helper()
	var po struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(out, &po); err != nil {
		t.Fatalf("-print output: %v\n%s", err, out)
	}
	return po.Result
}

// The live failure: the device never answers 0x4012. With the client list
// on its own budget, -print reports it, the other polls still run on the
// same login (one timeout is not a dropped session), and the exit frees the
// token and sends BYE.
func TestPrintOnceClientListNoReply(t *testing.T) {
	logs := captureLog(t)
	emu := newDecoEmu(t)
	emu.setSilent(deco.OpGetClientList)
	cfg := testConfig(t, "http://127.0.0.1:9/inform", t.TempDir())
	h := testHooks(emu)
	h.opTimeouts = map[uint16]time.Duration{deco.OpGetClientList: 300 * time.Millisecond}
	h.printTimeout = 20 * time.Second
	h.trace = log.Printf
	var out bytes.Buffer
	err := printOnce(context.Background(), cfg, Secrets{TPLinkID: testTPLinkID, Password: testPassword}, h, &out)
	if err == nil || !strings.Contains(err.Error(), "poll errors: clients(0x4012)") {
		t.Fatalf("err %v\n%s", err, logs.String())
	}
	if r := printResult(t, out.Bytes()); !strings.HasPrefix(r, "poll errors: clients(0x4012): ") || strings.Contains(r, "speeds") {
		t.Fatalf("result %q", r)
	}
	for _, op := range []uint16{deco.OpGetClientSpeedList, deco.OpGetWireless, deco.OpGetBlockList, deco.OpGetDeviceEthPort} {
		if emu.count(op) != 1 {
			t.Errorf("0x%04x polled %d times after the 0x4012 timeout", op, emu.count(op))
		}
	}
	if conns, tries, logins := emu.counts(); conns != 1 || tries != 1 || logins != 1 {
		t.Errorf("ssh: conns=%d password attempts=%d logins=%d", conns, tries, logins)
	}
	if emu.count(deco.OpcodeTokenFree) != 1 {
		t.Errorf("token not freed")
	}
	waitFor(t, "BYE", 3*time.Second, func() bool { return emu.byeCount() == 1 })
	l := logs.String()
	if !strings.Contains(l, "trace: req 0x4012 start (budget 300ms)") || !strings.Contains(l, "trace: tmp +") {
		t.Errorf("-trace lines missing:\n%s", l)
	}
	noSecrets(t, "-print -trace logs", l)
	noSecrets(t, "-print output", out.String(), md5hex(testTPLinkID))
}

// The -print deadline ends while a Get is in flight: nothing more is sent
// on the expired context, and the exit still frees the token and sends BYE.
func TestPrintOnceDeadlineMidRequest(t *testing.T) {
	captureLog(t)
	emu := newDecoEmu(t)
	emu.setSilent(deco.OpGetClientSpeedList) // second in the poll order
	cfg := testConfig(t, "http://127.0.0.1:9/inform", t.TempDir())
	h := testHooks(emu)
	h.printTimeout = 2 * time.Second // 0x4014 keeps its 45 s budget
	var out bytes.Buffer
	start := time.Now()
	err := printOnce(context.Background(), cfg, Secrets{TPLinkID: testTPLinkID, Password: testPassword}, h, &out)
	if err == nil || !strings.Contains(err.Error(), "timeout before every poll ran") {
		t.Fatalf("err %v", err)
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("-print took %s", el)
	}
	if n := emu.count(deco.OpGetIoTClientList) + emu.count(deco.OpGetWireless) + emu.count(deco.OpGetClientList); n != 0 {
		t.Fatalf("%d request(s) sent after the deadline", n)
	}
	if emu.count(deco.OpcodeTokenFree) != 1 {
		t.Errorf("token not freed")
	}
	waitFor(t, "BYE", 3*time.Second, func() bool { return emu.byeCount() == 1 })
	if _, _, logins := emu.counts(); logins != 1 {
		t.Errorf("%d logins", logins)
	}
}

// printDoc is the part of the -print document the tests read.
type printDoc struct {
	Result string         `json:"result"`
	Mesh   deco.MeshState `json:"mesh"`
	Live   *deco.LiveView `json:"live"`
	Units  map[string]struct {
		Error          string           `json:"error"`
		SnapshotSource string           `json:"snapshot_source"`
		Snapshot       *json.RawMessage `json:"snapshot"`
		LiveClients    *int             `json:"live_clients"`
	} `json:"units"`
}

func parsePrint(t *testing.T, out []byte) printDoc {
	t.Helper()
	var d printDoc
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("-print output: %v\n%s", err, out)
	}
	return d
}

// The live run: -only clients. Every unit still gets a snapshot (the
// skeleton, since device_list was not read), with the reason.
func TestPrintOnceOnlyClientsHasSnapshots(t *testing.T) {
	captureLog(t)
	emu := newDecoEmu(t)
	cfg := testConfig(t, "http://127.0.0.1:9/inform", t.TempDir())
	h := testHooks(emu)
	h.only = []uint16{deco.OpGetClientList}
	var out bytes.Buffer
	if err := printOnce(context.Background(), cfg, Secrets{TPLinkID: testTPLinkID, Password: testPassword}, h, &out); err != nil {
		t.Fatal(err)
	}
	d := parsePrint(t, out.Bytes())
	if d.Result != "ok" || !d.Mesh.Clients.OK || emu.count(deco.OpGetClientList) != 1 {
		t.Fatalf("result %q clients %+v sent %d", d.Result, d.Mesh.Clients, emu.count(deco.OpGetClientList))
	}
	if len(d.Units) != len(testUnits) {
		t.Fatalf("units %v", d.Units)
	}
	for name, u := range d.Units {
		if u.Snapshot == nil || u.SnapshotSource != "skeleton" || !strings.Contains(u.Error, "device_list not read") {
			t.Errorf("%s: snapshot missing or unexplained: %+v", name, u)
		}
	}
}

// The full -print: the live view places the emulated phone (present in
// 0x4014, placed by the 0x4012 entry) on deco-205's 5 GHz radio.
func TestPrintOnceLiveView(t *testing.T) {
	captureLog(t)
	emu := newDecoEmu(t)
	cfg := testConfig(t, "http://127.0.0.1:9/inform", t.TempDir())
	h := testHooks(emu)
	var out bytes.Buffer
	if err := printOnce(context.Background(), cfg, Secrets{TPLinkID: testTPLinkID, Password: testPassword}, h, &out); err != nil {
		t.Fatal(err)
	}
	d := parsePrint(t, out.Bytes())
	if d.Live == nil || len(d.Live.Clients) != 1 || d.Live.Placed != 1 {
		t.Fatalf("live %+v", d.Live)
	}
	lc := d.Live.Clients[0]
	if lc.MAC != "aa:bb:cc:dd:ee:01" || lc.DeviceID != "dev205" || lc.Link != "band5" || lc.PlacedBy != deco.SrcClients ||
		lc.Name != "phone" || !slices.Equal(lc.Seen, []string{deco.SrcSpeeds, deco.SrcClients}) {
		t.Fatalf("live client %+v", lc)
	}
	u := d.Units["deco-205"]
	if u.SnapshotSource != "collected" || u.LiveClients == nil || *u.LiveClients != 1 ||
		!strings.Contains(string(*u.Snapshot), `"aa:bb:cc:dd:ee:01"`) {
		t.Fatalf("deco-205: %+v", u)
	}
	for op, want := range map[uint16]int{deco.OpGetDeviceList: 1, deco.OpGetClientSpeedList: 1, deco.OpGetIoTClientList: 1,
		deco.OpGetClientList: 1, deco.OpGetWireless: 1} {
		if got := emu.count(op); got != want {
			t.Errorf("0x%04x sent %d times, want %d", op, got, want)
		}
	}
}

// -only runs just the listed Gets.
func TestPrintOnceOnly(t *testing.T) {
	captureLog(t)
	emu := newDecoEmu(t)
	cfg := testConfig(t, "http://127.0.0.1:9/inform", t.TempDir())
	h := testHooks(emu)
	h.only = []uint16{deco.OpGetClientSpeedList, deco.OpGetWireless}
	var out bytes.Buffer
	if err := printOnce(context.Background(), cfg, Secrets{TPLinkID: testTPLinkID, Password: testPassword}, h, &out); err != nil {
		t.Fatal(err)
	}
	if r := printResult(t, out.Bytes()); r != "ok" {
		t.Fatalf("result %q", r)
	}
	for op, want := range map[uint16]int{deco.OpGetClientSpeedList: 1, deco.OpGetWireless: 1, deco.OpGetClientList: 0,
		deco.OpGetDeviceList: 0, deco.OpGetDeviceEthPort: 0, deco.OpGetBlockList: 0} {
		if got := emu.count(op); got != want {
			t.Errorf("0x%04x sent %d times, want %d", op, got, want)
		}
	}
}

func TestParseOnly(t *testing.T) {
	got, err := parseOnly(" clients, 0x4014 ,Devices,4009, IoT")
	if err != nil || !slices.Equal(got, []uint16{deco.OpGetClientList, deco.OpGetClientSpeedList, deco.OpGetDeviceList,
		deco.OpGetWireless, deco.OpGetIoTClientList}) {
		t.Fatalf("%x %v", got, err)
	}
	if got, err := parseOnly("0x4040"); err != nil || !slices.Equal(got, []uint16{deco.OpGetIoTClientList}) {
		t.Fatalf("0x4040: %x %v", got, err)
	}
	for _, n := range strings.Split(onlyNames, ",") {
		if _, err := parseOnly(n); err != nil {
			t.Errorf("listed -only name %q rejected: %v", n, err)
		}
	}
	for _, bad := range []string{"clients,clients", "0x4001", "nope", "clients,"} {
		if _, err := parseOnly(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
