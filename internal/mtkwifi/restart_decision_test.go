// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

// withVendorFeatures puts the feature keys the unit's vendor profiles have
// (featNG/featNA) into the fake device's profiles, before any baseline is
// captured.
func withVendorFeatures(t *testing.T, f *fakeDev) {
	t.Helper()
	for _, rd := range JCOW414 {
		p := filepath.Join(f.root, rd.Dat)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		feat := featNG
		if rd.Band == "na" {
			feat = featNA
		}
		if err := os.WriteFile(p, append(b, feat...), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func restarts(log []string) []string {
	var out []string
	for _, c := range log {
		if strings.HasPrefix(c, "ifconfig ") {
			out = append(out, c)
		}
	}
	return out
}

func radioSteps(p bcmwifi.Plan) []string {
	var out []string
	for _, s := range p.Steps {
		if strings.Contains(s.Desc, "restart") || strings.Contains(s.Desc, "radio off") {
			out = append(out, s.Desc)
		}
	}
	return out
}

// TestNewBuildKeepsUnchangedRadios: an agent of another build (its plan
// JSON, so its mtk-applied hash, differs) finds the radios serving what it
// would write, byte for byte: nothing is restarted. A radio whose
// installed profile differs from what the new build renders is restarted.
func TestNewBuildKeepsUnchangedRadios(t *testing.T) {
	f := newFakeDev(t)
	withVendorFeatures(t, f)
	ctx := context.Background()
	d := home()
	a := newApplier(f)
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	// the previous build's hash of its own plans
	applied := filepath.Join(f.root, "tmp/udeco", appliedFile)
	if err := os.WriteFile(applied, []byte("0123456789abcdef-older-build\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	n := len(f.log)
	b := newApplier(f)
	p, err := b.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if s := radioSteps(p); len(s) > 0 {
		t.Errorf("unchanged radios planned for a restart: %v", s)
	}
	if !p.Empty() {
		if err := b.Apply(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if r := restarts(f.log[n:]); len(r) > 0 {
		t.Errorf("a new build restarted unchanged radios: %v", r)
	}
	if err := b.Verify(ctx, d); err != nil {
		t.Errorf("verify: %v", err)
	}

	// the 2.4 GHz profile on the unit is not what this build writes (a
	// DTIM the older build did not know): that radio alone is restarted
	ng := filepath.Join(f.root, JCOW414[0].Dat)
	dat, _ := os.ReadFile(ng)
	os.WriteFile(ng, []byte(strings.Replace(string(dat), "DtimPeriod=2", "DtimPeriod=3", 1)), 0o600)
	os.WriteFile(applied, []byte("0123456789abcdef-older-build\n"), 0o644)
	n = len(f.log)
	c := newApplier(f)
	p, _ = c.Plan(ctx, d)
	if s := radioSteps(p); len(s) != 1 || !strings.HasPrefix(s[0], "ng: profile and restart") {
		t.Errorf("changed 2.4 GHz profile: steps %v", s)
	}
	if err := c.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, r := range restarts(f.log[n:]) {
		if strings.Contains(r, "rai") {
			t.Errorf("the 5 GHz radio was restarted: %s", r)
		}
	}
	if len(restarts(f.log[n:])) == 0 {
		t.Error("the changed 2.4 GHz radio was not restarted")
	}

	// no finished apply in this boot (no mtk-applied): every radio is
	// restarted, as before
	os.Remove(applied)
	n = len(f.log)
	e := newApplier(f)
	p, _ = e.Plan(ctx, d)
	if s := radioSteps(p); len(s) != 2 {
		t.Errorf("without mtk-applied: steps %v, want both radios", s)
	}
}

// TestNoRestartWithoutProfileChange: a plan change the written profile
// does not show (multicast enhancement on while the vendor already has
// IGMP snooping on; DTIM asked equal to the vendor's) restarts nothing.
func TestNoRestartWithoutProfileChange(t *testing.T) {
	f := newFakeDev(t)
	withVendorFeatures(t, f)
	ctx := context.Background()
	a := newApplier(f)
	d := home()
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*bcmwifi.Desired){
		"multicast enhancement": func(d *bcmwifi.Desired) { d.SSIDs[2].MulticastToUnicast = true },
		"DTIM 2":                func(d *bcmwifi.Desired) { d.SSIDs[2].DTIM = map[string]int{"ng": 2} },
	} {
		d2 := home()
		change(&d2)
		p, _ := a.Plan(ctx, d2)
		if s := radioSteps(p); len(s) > 0 {
			t.Errorf("%s: planned %v", name, s)
		}
		n := len(f.log)
		if err := a.Apply(ctx, p); err != nil {
			t.Fatal(err)
		}
		if r := restarts(f.log[n:]); len(r) > 0 {
			t.Errorf("%s restarted a radio: %v", name, r)
		}
		// back
		p, _ = a.Plan(ctx, d)
		if err := a.Apply(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	// a DTIM the vendor's profile does not have still restarts the radio
	d2 := home()
	d2.SSIDs[2].DTIM = map[string]int{"ng": 1}
	p, _ = a.Plan(ctx, d2)
	if s := radioSteps(p); len(s) != 1 || !strings.HasPrefix(s[0], "ng: profile and restart") {
		t.Errorf("DTIM 1: steps %v", s)
	}
}

// TestPlanJSONWithoutNewFeatures: a plan that asks for none of 802.11k/v
// or U-APSD marshals as an older build's did (its hash and last-good stay
// the same).
func TestPlanJSONWithoutNewFeatures(t *testing.T) {
	ps, _ := plans(twoSSIDs(), JCOW414, false)
	j, _ := json.Marshal(ps)
	for _, k := range []string{`"RRM"`, `"BTM"`, `"UAPSD"`, `"DTIM"`, `"BasicRate"`, `"IgmpSn"`} {
		if strings.Contains(string(j), k) {
			t.Errorf("%s in the plan JSON of a Desired that does not ask for it", k)
		}
	}
}
