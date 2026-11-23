// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"bytes"
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/ftpeer"
)

// confBSSIDs are the bssid= lines of a hostapd conf.
func confBSSIDs(t *testing.T, f *fakeDev, radio string) []string {
	t.Helper()
	b, err := os.ReadFile(f.path("/tmp/udeco/hapd-" + radio + ".conf"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "bssid="); ok {
			out = append(out, v)
		}
	}
	return out
}

// An FT-SAE SSID gets the RRB receive path (rrb.go): the shim written to
// RunDir and preloaded into each radio's hostapd, the conf naming the
// shim's build, and a broute chain handing 0x88b7 frames for its BSSIDs to
// hostapd. The chain is rebuilt when something removes it and goes with
// the hand-back.
func TestRRBReceivePath(t *testing.T) {
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

	shim, err := os.ReadFile(f.path(rrbShimPath("/tmp/udeco")))
	if err != nil || !bytes.Equal(shim, rrbShim) || len(rrbShim) == 0 {
		t.Fatalf("shim %d bytes (%v), want the embedded %d", len(shim), err, len(rrbShim))
	}
	if st, _ := os.Stat(f.path(rrbShimPath("/tmp/udeco"))); st.Mode().Perm() != 0o755 {
		t.Errorf("shim mode %v", st.Mode())
	}
	var bssids []string
	for _, radio := range []string{"wl0", "wl1"} {
		b, _ := os.ReadFile(f.path("/tmp/udeco/hapd-" + radio + ".conf"))
		if !strings.HasPrefix(string(b), "# udeco: RRB receive shim "+rrbShimID()+" preloaded\n") {
			t.Errorf("%s conf does not name the shim:\n%.120s", radio, b)
		}
		want := "LD_PRELOAD=" + rrbShimPath("/tmp/udeco") + " " + ConfPath("/tmp/udeco", radio)
		if !slices.Contains(f.hapdEnv, want) {
			t.Errorf("hostapd on %s not started with the shim: %q", radio, f.hapdEnv)
		}
		bssids = append(bssids, confBSSIDs(t, f, radio)...)
	}
	c := f.ebr.chains[chainRRB]
	if c == nil || c.policy != "RETURN" {
		t.Fatalf("broute chain %+v", c)
	}
	var want []string
	for _, b := range bssids {
		want = append(want, "-p 0x88b7 -d "+b+" -j DROP")
	}
	if len(want) != 2 || !slices.Equal(c.rules, want) {
		t.Errorf("rules %q, want %q", c.rules, want)
	}
	if br := f.ebr.chains["BROUTING"].rules; !slices.Equal(br, []string{"-j " + chainRRB}) {
		t.Errorf("BROUTING %q", br)
	}
	if p2, _ := a.Plan(ctx, d); !p2.Empty() {
		t.Fatalf("plan after apply:\n%s", p2)
	}

	// something removes it: Tick rebuilds it without touching hostapd
	starts := len(f.hapdEnv)
	f.ebr.chains["BROUTING"].rules = nil
	r, err := a.Tick(ctx)
	if err != nil || r.NeedsApply {
		t.Fatalf("tick %+v %v", r, err)
	}
	if !slices.Equal(f.ebr.chains["BROUTING"].rules, []string{"-j " + chainRRB}) || len(r.Foreign) == 0 {
		t.Errorf("not rebuilt: %q foreign %q", f.ebr.chains["BROUTING"].rules, r.Foreign)
	}
	if len(f.hapdEnv) != starts {
		t.Errorf("hostapd restarted for the chain: %q", f.hapdEnv[starts:])
	}

	if err := a.handback(ctx); err != nil {
		t.Fatal(err)
	}
	if f.ebr.chains[chainRRB] != nil || len(f.ebr.chains["BROUTING"].rules) != 0 {
		t.Errorf("broute chain left after hand-back: %+v %q", f.ebr.chains[chainRRB], f.ebr.chains["BROUTING"].rules)
	}
}

// FT-PSK alone derives its keys locally: no shim, no env, no chain.
func TestRRBNotForFTPSK(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	applyOK(t, a, twoSSIDs()) // a-main: FT, WPA2/WPA3 but no FT-SAE
	if len(f.hapdEnv) != 0 {
		t.Errorf("hostapd started with %q", f.hapdEnv)
	}
	if _, err := os.Stat(f.path(rrbShimPath("/tmp/udeco"))); err == nil {
		t.Error("shim written")
	}
	if f.ebr.chains[chainRRB] != nil {
		t.Errorf("chain %+v", f.ebr.chains[chainRRB])
	}
	b, _ := os.ReadFile(f.path("/tmp/udeco/hapd-wl0.conf"))
	if strings.Contains(string(b), "RRB receive shim") {
		t.Error("conf names the shim")
	}
}

// The embedded shim is an ARM soft-float shared object (the X20's
// userland, ld-linux.so.3) exporting bind, send and close.
func TestRRBShimBinary(t *testing.T) {
	b := rrbShim
	if len(b) < 52 || string(b[:4]) != "\x7fELF" || b[4] != 1 || b[5] != 1 {
		t.Fatal("not a 32-bit little-endian ELF")
	}
	le16 := func(o int) int { return int(b[o]) | int(b[o+1])<<8 }
	le32 := func(o int) uint32 { return uint32(b[o]) | uint32(b[o+1])<<8 | uint32(b[o+2])<<16 | uint32(b[o+3])<<24 }
	if et, em, flags := le16(16), le16(18), le32(36); et != 3 || em != 40 || flags != 0x05000200 {
		t.Errorf("e_type %d e_machine %d e_flags %#x, want ET_DYN, EM_ARM, EABI5 soft-float", et, em, flags)
	}
	for _, sym := range []string{"bind\x00", "send\x00", "close\x00", "syscall\x00", "libc.so.6\x00"} {
		if !bytes.Contains(b, []byte(sym)) {
			t.Errorf("no %q in the shim", strings.TrimSuffix(sym, "\x00"))
		}
	}
}
