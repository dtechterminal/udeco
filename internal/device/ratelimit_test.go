// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The controller's per-client limit (QNAsAi: "cmd", "rate-update", "mac",
// "ul_max", qos_rate_max_up (-1 none), "ul_min", 64, "dl_max",
// qos_rate_max_down, "dl_min", 64).
func TestRateUpdate(t *testing.T) {
	x := &Session{StateDir: t.TempDir(), Unhandled: OpenLedger(t.TempDir() + "/u.json")}
	now := time.Unix(1_800_000_000, 0)
	const mac = "02:00:00:00:00:a2"
	h := func(js string) Outcome {
		t.Helper()
		o, err := x.Handle([]byte(js), now)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	o := h(`{"_type":"cmd","cmd":"rate-update","mac":"02:00:00:00:00:A2","ul_max":1000,"ul_min":64,"dl_max":4000,"dl_min":64}`)
	if !reflect.DeepEqual(o.Actions, []string{"rate-update:" + mac}) || !o.Changed ||
		x.S.ClientRates[mac] != (ClientRate{DownKbps: 4000, UpKbps: 1000, Set: now.Unix()}) {
		t.Fatalf("set: %+v %v", o, x.S.ClientRates)
	}
	// the same again: applied again (the client may have re-joined), no
	// state change
	if o = h(`{"_type":"cmd","cmd":"rate-update","mac":"02:00:00:00:00:a2","ul_max":1000,"dl_max":4000}`); o.Changed || len(o.Actions) != 1 {
		t.Errorf("repeat: %+v", o)
	}
	// one direction only; numbers as strings are read too
	o = h(`{"_type":"cmd","cmd":"rate-update","mac":"02:00:00:00:00:a2","ul_max":-1,"dl_max":"2500"}`)
	if !o.Changed || x.S.ClientRates[mac].DownKbps != 2500 || x.S.ClientRates[mac].UpKbps != 0 {
		t.Errorf("down only: %+v %v", o, x.S.ClientRates)
	}
	if !strings.Contains(strings.Join(o.Events, "\n"), "cmd rate-update "+mac+" down=2500kbit up=none") {
		t.Errorf("events %q", o.Events)
	}
	// -1/-1 clears the entry
	o = h(`{"_type":"cmd","cmd":"rate-update","mac":"02:00:00:00:00:a2","ul_max":-1,"ul_min":64,"dl_max":-1,"dl_min":64}`)
	if !o.Changed || len(x.S.ClientRates) != 0 || !reflect.DeepEqual(o.Actions, []string{"rate-update:" + mac}) {
		t.Errorf("clear: %+v %v", o, x.S.ClientRates)
	}
	// bad MAC, no limits at all: ignored
	for _, js := range []string{
		`{"_type":"cmd","cmd":"rate-update","mac":"02:00:00:00:00:a2; reboot","ul_max":1,"dl_max":1}`,
		`{"_type":"cmd","cmd":"rate-update","mac":"02:00:00:00:00:a2"}`,
	} {
		if o = h(js); len(o.Actions) != 0 || o.Changed {
			t.Errorf("%s accepted: %+v", js, o)
		}
	}
	// the fields are read: nothing about them in the ledger, only the
	// limit-less cmd above
	for _, u := range x.Unhandled.Entries() {
		if u.Kind == "field" {
			t.Errorf("field reported unhandled: %+v", u)
		}
	}
}

// The list is bounded: the entry set longest ago makes room.
func TestRateUpdateBounded(t *testing.T) {
	x := &Session{StateDir: t.TempDir()}
	start := time.Unix(1_800_000_000, 0)
	for i := 0; i <= MaxClientRates; i++ {
		js := fmt.Sprintf(`{"_type":"cmd","cmd":"rate-update","mac":"02:00:00:00:%02x:%02x","ul_max":-1,"dl_max":100}`, i>>8, i&0xff)
		if _, err := x.Handle([]byte(js), start.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if len(x.S.ClientRates) != MaxClientRates {
		t.Fatalf("%d entries", len(x.S.ClientRates))
	}
	if _, ok := x.S.ClientRates["02:00:00:00:00:00"]; ok {
		t.Error("oldest entry kept")
	}
	if _, ok := x.S.ClientRates[fmt.Sprintf("02:00:00:00:%02x:%02x", MaxClientRates>>8, MaxClientRates&0xff)]; !ok {
		t.Error("newest entry dropped")
	}
}
