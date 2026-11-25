// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/ftpeer"
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

// Anything besides the station ACLs and the live settings still reconciles
// the radio in full.
func TestLockToAPWithOtherChangeStillReconciles(t *testing.T) {
	f, a := appliedUnit(t, twoSSIDs())
	d := withDeny(twoSSIDs(), lockedMAC)
	d.SSIDs[1].UAPSD = !d.SSIDs[1].UAPSD
	p := planApply(t, a, d)
	if !p.disruptive || !restarted(f) {
		t.Fatalf("a U-APSD change with a lock change was not a full reconcile:\n%s", p)
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
	// (not rrm or wnm: those wait for the next radio down/up, heldDriver)
	drifted := strings.Replace(string(b), `"rrm_nbr_scan": 0`, `"rrm_nbr_scan": 7`, 1)
	if drifted == string(b) {
		t.Fatalf("no rrm_nbr_scan in %s", b)
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

// Hide SSID, client isolation, max clients and multicast enhancement are
// taken by the running BSS (driver iovar plus hostapd SET): no hostapd
// restart, no radio down/up, and the conf file holds the new value for the
// next start. The other SSIDs of the radio are not touched.
func TestSettingsAppliedLive(t *testing.T) {
	ctx := context.Background()
	f, a := appliedUnit(t, twoSSIDs())

	d := twoSSIDs()
	d.SSIDs[1].Hidden = true
	d.SSIDs[1].Isolation = true
	d.SSIDs[1].MulticastToUnicast = true
	na := d.Radios["na"]
	na.MaxClients = 64
	d.Radios["na"] = na
	p := planApply(t, a, d)
	if p.disruptive || restarted(f) {
		t.Fatalf("settings change restarted hostapd:\n%s", p)
	}
	if f.called("wl -i wl1 down") || f.called("wl -i wl0 down") {
		t.Fatalf("settings change took a radio down:\n%s", p)
	}
	for _, want := range []string{
		"wl -i wl12 closednet 1", "wl -i wl12 ap_isolate 1", "wl -i wl12 bss_maxassoc 64", "wl -i wl12 wmf_bss_enable 1",
		"hostapd_cli -p /var/run/udeco-hostapd -i wl12 set ignore_broadcast_ssid 1",
		"hostapd_cli -p /var/run/udeco-hostapd -i wl12 set ap_isolate 1",
		"hostapd_cli -p /var/run/udeco-hostapd -i wl12 set max_num_sta 64",
		"hostapd_cli -p /var/run/udeco-hostapd -i wl12 set multicast_to_unicast 1",
		"wl -i wl02 closednet 1",
	} {
		if !f.called(want) {
			t.Errorf("missing %q", want)
		}
	}
	if f.called("wl -i wl02 bss_maxassoc") || f.called("-i wl03 closednet") || f.called("-i wl03 ap_isolate") || f.called("-i wl03 set ") {
		t.Errorf("a radio or SSID the change does not concern was touched:\n%s", p)
	}
	conf := string(mustRead(t, f, "/tmp/udeco/hapd-wl1.conf"))
	for _, want := range []string{"ignore_broadcast_ssid=1", "ap_isolate=1", "max_num_sta=64", "multicast_to_unicast=1"} {
		if !strings.Contains(conf, "\n"+want+"\n") {
			t.Errorf("hapd-wl1.conf lacks %s", want)
		}
	}
	if p, _ := a.Plan(ctx, d); !p.Empty() {
		t.Errorf("plan after the live update not empty:\n%s", p)
	}

	// And back, together with a lock change: still live.
	f.reset()
	p = planApply(t, a, withDeny(twoSSIDs(), lockedMAC))
	if p.disruptive || restarted(f) {
		t.Fatalf("settings revert with a lock change restarted hostapd:\n%s", p)
	}
	for _, want := range []string{
		"wl -i wl12 closednet 0", "hostapd_cli -p /var/run/udeco-hostapd -i wl12 set multicast_to_unicast 0",
		"hostapd_cli -p /var/run/udeco-hostapd -i wl12 DENY_ACL ADD_MAC " + lockedMAC,
	} {
		if !f.called(want) {
			t.Errorf("missing %q", want)
		}
	}
	if p, _ := a.Plan(ctx, withDeny(twoSSIDs(), lockedMAC)); !p.Empty() {
		t.Errorf("plan after the revert not empty:\n%s", p)
	}
}

// 802.11k (wl rrm is refused unless the whole radio is down), an SSID
// rename, a passphrase or an added SSID still reconcile the radio in full.
func TestNonLiveSettingsReconcile(t *testing.T) {
	for name, mod := range map[string]func(*Desired){
		"802.11k":    func(d *Desired) { d.SSIDs[1].RRM = !d.SSIDs[1].RRM },
		"rename":     func(d *Desired) { d.SSIDs[1].SSID = "Renamed" },
		"passphrase": func(d *Desired) { d.SSIDs[1].Passphrase = "another-passphrase-2" },
		"hidden+dtim": func(d *Desired) {
			d.SSIDs[1].Hidden = true
			d.SSIDs[1].DTIM = map[string]int{"na": 3, "ng": 3}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, a := appliedUnit(t, twoSSIDs())
			d := twoSSIDs()
			mod(&d)
			if p := planApply(t, a, d); !p.disruptive || !restarted(f) {
				t.Errorf("applied live:\n%s", p)
			}
		})
	}
}

func mustRead(t *testing.T, f *fakeDev, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(f.path(p))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestConfLiveDiff(t *testing.T) {
	base := "interface=wl11\nssid=ph\nignore_broadcast_ssid=1\nbss=wl12\nssid=A\nignore_broadcast_ssid=0\nmax_num_sta=128\nbss=wl13\nssid=B\nignore_broadcast_ssid=0\n"
	for _, c := range []struct {
		name, new string
		want      []confSet
		ok        bool
	}{
		{"same", base, nil, true},
		{"hide wl13", strings.Replace(base, "ssid=B\nignore_broadcast_ssid=0", "ssid=B\nignore_broadcast_ssid=1", 1), []confSet{{"wl13", "ignore_broadcast_ssid", "1"}}, true},
		{"m2u added", base + "multicast_to_unicast=1\n", []confSet{{"wl13", "multicast_to_unicast", "1"}}, true},
		{"placeholder changed", strings.Replace(base, "ignore_broadcast_ssid=1", "ignore_broadcast_ssid=0", 1), nil, false},
		{"static changed", strings.Replace(base, "ssid=A", "ssid=C", 1), nil, false},
		{"bss removed", strings.Split(base, "bss=wl13")[0], nil, false},
		{"ft peers ignored", base + "r0kh=x\n", nil, true},
	} {
		got, ok := confLiveDiff([]byte(base), []byte(c.new))
		if ok != c.ok || !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v %v, want %v %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

// A radio serving FT-SAE writes the RRB receive shim at every plan
// (rrb.go). An unchanged shim must not stop a lock change from being
// applied live: on the units (FT-SAE on the main WLAN) each lock change
// restarted hostapd on both radios of every Deco, dropping all clients.
func TestLockToAPLiveWithRRBShim(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	a.o.WPA3, a.o.FTSAE = true, true
	d := Desired{Country: "IN", Radios: map[string]Radio{"ng": {Enabled: true, Channel: 6}, "na": {Enabled: true, Channel: 44, Width: 80}}}
	s := ftTransition()
	s.Bands = []string{"ng", "na"}
	d.SSIDs = []SSID{s}
	a.SetFTPeers([]ftpeer.Peer{ftPeer("02:11:22:33:44:24", "ng", s.SSID, testFTKey, "br-lan")})
	applyOK(t, a, d)
	if _, err := os.Stat(f.path(rrbShimPath("/tmp/udeco"))); err != nil {
		t.Fatalf("setup: no RRB shim: %v", err)
	}
	f.reset()

	locked := d
	locked.SSIDs = []SSID{s}
	locked.SSIDs[0].MACFilter = &MACFilter{Policy: "deny", MACs: []string{lockedMAC}}
	p := planApply(t, a, locked)
	if p.disruptive || restarted(f) {
		t.Fatalf("lock change on an FT-SAE radio restarted hostapd:\n%s", p)
	}
	if !f.called("DENY_ACL ADD_MAC " + lockedMAC) {
		t.Errorf("lock entry not added to hostapd live:\n%s", p)
	}
	if p, _ := a.Plan(ctx, locked); !p.Empty() {
		t.Errorf("plan after the live update not empty:\n%s", p)
	}
}
