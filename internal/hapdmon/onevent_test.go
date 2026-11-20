// SPDX-License-Identifier: GPL-2.0-or-later

package hapdmon

import "testing"

// OnEvent sees every event as it is received; Take still returns it.
func TestOnEvent(t *testing.T) {
	var got []Event
	m := New(Options{OnEvent: func(e Event) { got = append(got, e) }})
	m.push(Event{Vif: "wl12", MAC: "d2:f7:e5:58:6f:89", Kind: Connected})
	if len(got) != 1 || got[0].Kind != Connected {
		t.Fatalf("OnEvent got %v", got)
	}
	if evs, _ := m.Take(); len(evs) != 1 {
		t.Fatalf("Take %v", evs)
	}
}
