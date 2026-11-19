// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"reflect"
	"strings"
	"testing"
)

// lockCfg is a two-band WLAN as Network 11.1.50 provisions it to an AP that
// is NOT the one a client is locked to: the wireless section's constant
// mac_acl (status enabled, policy deny, no MACs: XHjguBsIf), and the
// macacl section from ubntconf.dwuoZJCFG, one entry per VAP devname (the
// WLAN's athdev) with the client as a typed entry. The controller's
// xTNsE builds each entry list: no MAC filter -> policy deny with the
// lock2ap MACs; a deny filter -> the union (a MAC in both keeps type
// user); an allow filter -> the allow list minus the clients locked to
// another AP (no lock2ap entry at all).
func lockCfg(policy string, entries ...string) string {
	var b strings.Builder
	b.WriteString("radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght20\nradio.2.phyname=wifi1\nradio.2.ieee_mode=11acvht80\n")
	for i, dev := range []string{"ath0", "ath1"} {
		n := string(rune('1' + i))
		parent := []string{"wifi0", "wifi1"}[i]
		b.WriteString("wireless." + n + ".ssid=net\nwireless." + n + ".id=w1\nwireless." + n + ".parent=" + parent +
			"\nwireless." + n + ".devname=" + dev + "\nwireless." + n + ".mac_acl.status=enabled\nwireless." + n + ".mac_acl.policy=deny\n")
	}
	b.WriteString("macacl.status=enabled\n")
	for i, dev := range []string{"ath0", "ath1"} {
		p := "macacl." + string(rune('1'+i)) + "."
		b.WriteString(p + "status=enabled\n" + p + "devname=" + dev + "\n" + p + "acl.status=enabled\n" + p + "acl.policy=" + policy + "\n")
		for j, e := range entries {
			mac, typ, _ := strings.Cut(e, "/")
			q := p + "acl." + string(rune('1'+j)) + "."
			b.WriteString(q + "status=enabled\n" + q + "mac=" + mac + "\n" + q + "type=" + typ + "\n")
		}
	}
	return b.String()
}

func TestLockToAPEntriesBecomeTheWLANFilter(t *testing.T) {
	tests := []struct {
		name string
		cfg  string
		want *MACFilter
	}{
		{"locked elsewhere, no filter", lockCfg("deny", "AA:BB:CC:00:00:01/lock2ap"),
			&MACFilter{Policy: "deny", MACs: []string{"aa:bb:cc:00:00:01"}}},
		{"locked elsewhere plus a deny filter", lockCfg("deny", "aa:bb:cc:00:00:01/lock2ap", "aa:bb:cc:00:00:02/user"),
			&MACFilter{Policy: "deny", MACs: []string{"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"}}},
		// allow list aa..02 + aa..03 with aa..01 locked elsewhere: the
		// controller sends the list without aa..01.
		{"allow filter minus the locked client", lockCfg("allow", "aa:bb:cc:00:00:02/user", "aa:bb:cc:00:00:03/user"),
			&MACFilter{Policy: "allow", MACs: []string{"aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, notes := IntentFromCfg(tc.cfg)
			if len(in.WLANs) != 1 {
				t.Fatalf("%d WLANs, want 1 (two bands merged); notes %v", len(in.WLANs), notes)
			}
			w := in.WLANs[0]
			if !reflect.DeepEqual(w.MACFilter, tc.want) {
				t.Errorf("MACFilter = %+v, want %+v", w.MACFilter, tc.want)
			}
			if len(w.Bands) != 2 {
				t.Errorf("bands %v", w.Bands)
			}
			for _, n := range notes {
				if strings.Contains(n, "mac") || strings.Contains(n, "acl") || strings.Contains(n, "differ") {
					t.Errorf("unexpected note %q", n)
				}
			}
		})
	}
}

// The locked AP itself (and every AP once the lock is removed, or while the
// locked AP is offline: the controller's failover) gets no lock2ap entry:
// macacl.status=disabled when no WLAN has a filter.
func TestLockToAPNoEntryMeansNoFilter(t *testing.T) {
	cfg := strings.Replace(lockCfg("deny"), "macacl.status=enabled", "macacl.status=disabled", 1)
	in, _ := IntentFromCfg(cfg)
	if len(in.WLANs) != 1 || in.WLANs[0].MACFilter != nil {
		t.Fatalf("WLANs %+v", in.WLANs)
	}
}
