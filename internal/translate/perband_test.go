// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// nonZero sets v (addressable) to a value that is not its zero value.
func nonZero(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int:
		v.SetInt(7)
	default:
		t.Fatalf("nonZero: no value for a %s", v.Kind())
	}
}

// The per-band settings of a WLAN are one list: BandWLAN's fields. The
// names mergeVAPs tells apart from "any other difference" (bandFields) are
// those fields, each is a WLANIntent field of the same name and type, and
// bandWLAN copies every one of them.
func TestBandWLANFields(t *testing.T) {
	bt, wt := reflect.TypeOf(BandWLAN{}), reflect.TypeOf(WLANIntent{})
	var names []string
	w := reflect.New(wt).Elem()
	for i := 0; i < bt.NumField(); i++ {
		f := bt.Field(i)
		names = append(names, strings.ToLower(f.Name))
		wf, ok := wt.FieldByName(f.Name)
		if !ok || wf.Type != f.Type {
			t.Errorf("BandWLAN.%s: WLANIntent has no field of that name and type", f.Name)
			continue
		}
		nonZero(t, w.FieldByName(f.Name))
	}
	sort.Strings(names)

	// the fourteen settings a WLAN may have per band today: a new one is a
	// decision (every backend's ForBand or its notes), so it is added here
	want := []string{"bsstransition", "ft", "ftoverds", "ftsae", "grouprekey", "hidden", "isolation", "mobilitydomain",
		"multicasttounicast", "pmf", "proxyarp", "rrm", "security", "uapsd"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("BandWLAN fields %v, want %v", names, want)
	}
	var keys []string
	for k := range bandFields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, names) {
		t.Errorf("bandFields %v, BandWLAN's fields are %v", keys, names)
	}

	got := reflect.ValueOf(bandWLAN(w.Interface().(WLANIntent)))
	for i := 0; i < bt.NumField(); i++ {
		if name := bt.Field(i).Name; !reflect.DeepEqual(got.Field(i).Interface(), w.FieldByName(name).Interface()) {
			t.Errorf("bandWLAN drops %s", name)
		}
	}

	// and differing reports each of them under the name bandFields has
	for i := 0; i < bt.NumField(); i++ {
		name := bt.Field(i).Name
		a := reflect.New(wt).Elem()
		nonZero(t, a.FieldByName(name))
		if d := differing(WLANIntent{}, a.Interface().(WLANIntent)); len(d) != 1 || !bandFields[d[0]] {
			t.Errorf("%s: differing = %v, not one per-band field", name, d)
		}
	}
}
