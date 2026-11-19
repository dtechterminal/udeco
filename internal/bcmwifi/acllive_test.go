// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"os"
	"strings"
	"testing"
)

const (
	lockedMAC  = "aa:bb:cc:00:00:01" // a client the controller locked to another AP
	blockedMAC = "aa:bb:cc:00:00:0b" // a blocked client (blocked_sta)
)

// applied takes the fake unit over with d and clears the call log.
func appliedUnit(t *testing.T, d Desired) (*fakeDev, *Applier) {
	t.Helper()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	p, err := a.Plan(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	f.reset()
	return f, a
}

// planApply plans and applies d, failing the test on an error.
func planApply(t *testing.T, a *Applier, d Desired) Plan {
	t.Helper()
	p, err := a.Plan(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	return p
}

// restarted reports whether any hostapd was stopped or started.
func restarted(f *fakeDev) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c[0] == "hostapd" || c[0] == "kill" {
			return true
		}
	}
	return false
}

func fileLines(t *testing.T, f *fakeDev, p string) []string {
	t.Helper()
	b, err := os.ReadFile(f.path(p))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

func withDeny(d Desired, macs ...string) Desired {
	d.SSIDs[1].MACFilter = &MACFilter{Policy: "deny", MACs: macs}
	return d
}

// A client locked to another AP arrives as a deny entry in the WLAN's MAC
// filter (translate: macacl ... type=lock2ap). It is enforced on every BSS
// of the WLAN without restarting hostapd (which would drop every client of
// the radio, on every AP of the site, at each lock change), and it is
// lifted the same way; the block list is kept throughout.
func TestLockToAPDenyIsAppliedLive(t *testing.T) {
	ctx := context.Background()
	f, a := appliedUnit(t, twoSSIDs())
	if err := a.SetBlocked(ctx, []string{blockedMAC}); err != nil {
		t.Fatal(err)
	}
	f.reset()

	locked := withDeny(twoSSIDs(), lockedMAC)
	p := planApply(t, a, locked)
	if p.disruptive || restarted(f) {
		t.Fatalf("lock change restarted hostapd:\n%s", p)
	}
	for _, s := range p.Foreign {
		if strings.Contains(s, "not set by the agent") {
			t.Errorf("our own driver filter reported as foreign: %s", s)
		}
	}
	for _, vif := range []string{"wl02", "wl12"} { // the WLAN's two BSSes
		for _, want := range []string{
			"hostapd_cli -p /var/run/udeco-hostapd -i " + vif + " DENY_ACL ADD_MAC " + lockedMAC,
			"wl -i " + vif + " mac " + lockedMAC,
		} {
			if !f.called(want) {
				t.Errorf("missing %q", want)
			}
		}
		if got := fileLines(t, f, "/tmp/udeco/"+vif+".deny"); strings.Join(got, " ") != lockedMAC+" "+blockedMAC {
			t.Errorf("%s.deny = %v, want the lock and the block", vif, got)
		}
	}
	if f.called("-i wl03 DENY_ACL ADD_MAC " + lockedMAC) {
		t.Error("lock entry applied to a WLAN whose filter does not have it")
	}
	if f.called("DEL_MAC "+blockedMAC) || f.called("CLEAR") {
		t.Error("the lock change touched the block list entry")
	}
	if !f.called("fc flush --mac " + lockedMAC) {
		t.Error("flows of the newly denied station not flushed")
	}
	if p, _ := a.Plan(ctx, locked); !p.Empty() {
		t.Errorf("plan after the live update not empty:\n%s", p)
	}

	// Unlock (or the locked AP went offline: the controller drops the entry).
	f.reset()
	p = planApply(t, a, twoSSIDs())
	if p.disruptive || restarted(f) {
		t.Fatalf("unlock restarted hostapd:\n%s", p)
	}
	for _, s := range p.Foreign {
		if strings.Contains(s, "not set by the agent") {
			t.Errorf("the lifted lock entry reported as foreign: %s", s)
		}
	}
	if !f.called("-i wl12 DENY_ACL DEL_MAC " + lockedMAC) {
		t.Error("lock entry not removed from hostapd")
	}
	if f.called("DEL_MAC " + blockedMAC) {
		t.Error("unlock removed the blocked station")
	}
	if got := fileLines(t, f, "/tmp/udeco/wl12.deny"); strings.Join(got, " ") != blockedMAC {
		t.Errorf("wl12.deny after unlock = %v", got)
	}
	if got := f.maclist["wl12"]; len(got) != 1 || !strings.EqualFold(got[0], blockedMAC) {
		t.Errorf("driver deny list after unlock = %v", got)
	}
	if p, _ := a.Plan(ctx, twoSSIDs()); !p.Empty() {
		t.Errorf("plan after unlock not empty:\n%s", p)
	}
}

// The block list and the lock entries are one union: unblocking a station
// that is also locked elsewhere keeps it denied, and unlocking a blocked
// station keeps it blocked.
func TestLockToAPAndBlockListDoNotClobber(t *testing.T) {
	ctx := context.Background()
	both := withDeny(twoSSIDs(), lockedMAC)
	f, a := appliedUnit(t, both)
	if err := a.SetBlocked(ctx, []string{lockedMAC}); err != nil {
		t.Fatal(err)
	}
	f.reset()
	if err := a.SetBlocked(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if f.called("-i wl12 DENY_ACL DEL_MAC " + lockedMAC) {
		t.Error("unblock lifted the lock entry")
	}
	if got := fileLines(t, f, "/tmp/udeco/wl12.deny"); strings.Join(got, " ") != lockedMAC {
		t.Errorf("wl12.deny after unblock = %v", got)
	}

	if err := a.SetBlocked(ctx, []string{lockedMAC}); err != nil {
		t.Fatal(err)
	}
	f.reset()
	planApply(t, a, twoSSIDs()) // unlock
	if f.called("DEL_MAC " + lockedMAC) {
		t.Error("unlock lifted the block")
	}
	if got := fileLines(t, f, "/tmp/udeco/wl12.deny"); strings.Join(got, " ") != lockedMAC {
		t.Errorf("wl12.deny after unlock = %v", got)
	}
}

// On an allow-list WLAN the controller leaves a client locked elsewhere out
// of the list: it is taken off hostapd's accept list by difference (never
// CLEAR, which would disassociate every station), without a restart.
func TestLockToAPAllowListLive(t *testing.T) {
	ctx := context.Background()
	allow := func(macs ...string) Desired {
		d := twoSSIDs()
		d.SSIDs[1].MACFilter = &MACFilter{Policy: "allow", MACs: macs}
		return d
	}
	f, a := appliedUnit(t, allow(lockedMAC, "aa:bb:cc:00:00:02"))
	p := planApply(t, a, allow("aa:bb:cc:00:00:02"))
	if p.disruptive || restarted(f) {
		t.Fatalf("restarted:\n%s", p)
	}
	if !f.called("-i wl12 ACCEPT_ACL DEL_MAC " + lockedMAC) {
		t.Error("locked client not taken off the accept list")
	}
	if f.called("CLEAR") || f.called("ACCEPT_ACL ADD_MAC aa:bb:cc:00:00:02") {
		t.Error("accept list rebuilt instead of changed by difference")
	}
	if got := fileLines(t, f, "/tmp/udeco/wl12.accept"); strings.Join(got, " ") != "aa:bb:cc:00:00:02" {
		t.Errorf("wl12.accept = %v", got)
	}
	f.reset()
	planApply(t, a, allow(lockedMAC, "aa:bb:cc:00:00:02"))
	if restarted(f) || !f.called("-i wl12 ACCEPT_ACL ADD_MAC "+lockedMAC) {
		t.Error("unlock not applied live on the accept list")
	}
	if p, _ := a.Plan(ctx, allow(lockedMAC, "aa:bb:cc:00:00:02")); !p.Empty() {
		t.Errorf("plan not empty:\n%s", p)
	}
}

// With RADIUS MAC authentication hostapd asks RADIUS (macaddr_acl=2) and
// loads no accept list; an ACCEPT_ACL entry would admit the station
// without asking. The allow list is then the driver's alone.
func TestLockToAPAllowListWithMACAuthSkipsHostapdAccept(t *testing.T) {
	d := func(macs ...string) Desired {
		d := twoSSIDs()
		d.SSIDs[1].Radius = &Radius{MACAuth: true, Auth: []RadiusServer{{IP: "192.0.2.10", Port: 1812, Secret: "radius-secret-1"}}}
		d.SSIDs[1].MACFilter = &MACFilter{Policy: "allow", MACs: macs}
		return d
	}
	f, a := appliedUnit(t, d("aa:bb:cc:00:00:02"))
	p := planApply(t, a, d(lockedMAC, "aa:bb:cc:00:00:02"))
	if p.disruptive || restarted(f) {
		t.Fatalf("restarted:\n%s", p)
	}
	if f.called("ACCEPT_ACL") {
		t.Error("ACCEPT_ACL sent to a MAC-auth BSS")
	}
	if !f.called("wl -i wl12 mac " + lockedMAC) {
		t.Error("driver allow list not updated")
	}
}

// Anything besides the station ACLs still reconciles the radio in full.
func TestLockToAPWithOtherChangeStillReconciles(t *testing.T) {
	f, a := appliedUnit(t, twoSSIDs())
	d := withDeny(twoSSIDs(), lockedMAC)
	d.SSIDs[1].Hidden = true
	p := planApply(t, a, d)
	if !p.disruptive || !restarted(f) {
		t.Fatalf("a hidden-SSID change with a lock change was not a full reconcile:\n%s", p)
	}
	if got := fileLines(t, f, "/tmp/udeco/wl12.deny"); strings.Join(got, " ") != lockedMAC {
		t.Errorf("wl12.deny = %v", got)
	}
	// Switching the WLAN from deny to allow changes hostapd's macaddr_acl:
	// also a full reconcile.
	f.reset()
	d.SSIDs[1].MACFilter = &MACFilter{Policy: "allow", MACs: []string{"aa:bb:cc:00:00:02"}}
	if p := planApply(t, a, d); !p.disruptive {
		t.Errorf("deny -> allow applied live:\n%s", p)
	}
}

// A hostapd conf change (here the passphrase, which is in the conf only)
// together with a lock change: hostapd must restart to load it.
func TestLockToAPWithConfOnlyChangeReconciles(t *testing.T) {
	f, a := appliedUnit(t, twoSSIDs())
	d := withDeny(twoSSIDs(), lockedMAC)
	d.SSIDs[1].Passphrase = "another-passphrase-2"
	if p := planApply(t, a, d); !p.disruptive || !restarted(f) {
		t.Fatalf("a passphrase change with a lock change was applied live:\n%s", p)
	}
}

// Stored driver state that differs from the wanted one outside the ACLs
// (iovars only the full path sets): full reconcile, not a live ACL update.
func TestLockToAPWithDriverStateDriftReconciles(t *testing.T) {
	f, a := appliedUnit(t, twoSSIDs())
	p := f.path("/tmp/udeco/drv-wl1.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	drifted := strings.Replace(string(b), `"bss_maxassoc": `, `"bss_maxassoc": 1`, 1)
	if drifted == string(b) {
		t.Fatalf("no bss_maxassoc in %s", b)
	}
	if err := os.WriteFile(p, []byte(drifted), 0o644); err != nil {
		t.Fatal(err)
	}
	pl, err := a.Plan(context.Background(), withDeny(twoSSIDs(), lockedMAC))
	if err != nil {
		t.Fatal(err)
	}
	if !pl.disruptive {
		t.Errorf("driver state drift hidden behind a live ACL update:\n%s", pl)
	}
}

// A stored driver state that cannot be read is no basis for a difference:
// full reconcile.
func TestLockToAPUnreadableDriverStateReconciles(t *testing.T) {
	f, a := appliedUnit(t, twoSSIDs())
	if err := os.WriteFile(f.path("/tmp/udeco/drv-wl1.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := a.Plan(context.Background(), withDeny(twoSSIDs(), lockedMAC))
	if err != nil {
		t.Fatal(err)
	}
	if !p.disruptive {
		t.Errorf("planned live without a readable driver state:\n%s", p)
	}
}
