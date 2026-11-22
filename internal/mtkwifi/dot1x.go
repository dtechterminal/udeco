// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/translate"
	"github.com/dtechterminal/udeco/internal/unit"
)

// WPA2/WPA3-Enterprise (802.1X) on the MediaTek drivers.
//
// Both drivers split 802.1X the vendor's way: the driver advertises the
// RSNE (AuthMode WPA2), holds every station's port closed until it has a
// PMK, and passes EAPOL up the BSS netdev; Jio's rtdot1xd (the MediaTek
// authenticator, /userfs/bin/rtdot1xd) reads the RADIUS settings from the
// driver (ioctl 0x8be1, OID 0x0540: DOT1X_CMM_CONF, 0xd79 bytes, built from
// the profile when the radio comes up), runs EAP with the RADIUS server
// over UDP and hands the PMK to the driver. Without rtdot1xd an enterprise
// BSS beacons but no station gets past EAPOL: it fails closed, never open.
//
// Read from the binaries and the rebuilt MT7603 source (docs/deco/features/
// radius-macauth-hs20-radsec.md, Garage):
//   - rtdot1xd main: -p <netdev prefix> -i <main netdev>, forks, no setsid;
//     PF_PACKET sockets (0x888e, 0x88c7) on every EAPifname/PreAuthifname
//     entry the driver reports, SIOCGIFHWADDR on <prefix>0..N: any failure
//     ends it. It never re-reads the driver's config by itself (SIGHUP
//     re-reads it without reopening the sockets), and the driver never
//     tells it: it is restarted after every radio restart.
//   - profile keys: RADIUS_Server, RADIUS_Port (;-lists per BSS),
//     RADIUS_Key1 as a ;-list of every BSS's secret on the MT7603 (its
//     "prev format"; an empty entry would shift the rest), RADIUS_Key<n>
//     per BSS on the MT7663; own_ip_addr, session_timeout_interval (0 =
//     no deauth timer of rtdot1xd's own), EAPifname/PreAuthifname,
//     NasId<n>.
//   - the drivers keep EAPifname entries a later profile no longer lists
//     (no reset at a re-read), and rtdot1xd opens one socket per entry with
//     no de-duplication: the list is the distinct bridges, padded with "lo"
//     (a socket there never sees an EAPOL frame) so no stale bridge stays.
//   - WPA3-Enterprise is AuthMode WPA2 with PMF required: both RSNE
//     builders then advertise AKM 00-0f-ac:5 (802.1X-SHA256) only.
//   - neither driver nor rtdot1xd has RADIUS MAC authentication, Filter-Id
//     or accounting: an SSID asking for MAC authentication or a Filter-Id
//     is not served (features.go ssidNotes, dot1xOf), accounting servers
//     are noted.
//
// RadSec reaches rtdot1xd as it reaches hostapd on the Deco: the agent
// rewrites the WLAN's servers to its proxy's 127.0.0.1 endpoints
// (cmd/udeco-ap radsec.go) before the plan is made; rtdot1xd adds a
// Message-Authenticator to every request, which the proxy requires.

// Dot1xdPath is Jio's rtdot1xd.
const Dot1xdPath = "/userfs/bin/rtdot1xd"

// Dot1X is one enterprise BSS's RADIUS client settings. Secret is a secret.
type Dot1X struct {
	Server string // IPv4
	Port   int
	Secret string
	NASID  string `json:",omitempty"` // NasId<n>; "" = none
}

// maxRadiusSecret: DOT1X_CMM_CONF has 64 bytes per secret.
const maxRadiusSecret = 64

// maxNASID: DOT1X_CMM_CONF has 16 bytes for the NAS-Identifier.
const maxNASID = 16

// dot1xOf is s's 802.1X client on rd, or nil and why it cannot be served.
func dot1xOf(s bcmwifi.SSID, rd RadioDef) (*Dot1X, string) {
	switch {
	case !rd.Dot1X:
		return nil, fmt.Sprintf("security %s is not served by this radio (the %s driver without 802.1X, rtdot1xd missing, or enterprise off)", s.Security, rd.HWName)
	case s.Security == translate.SecWPA3Ent && !rd.SAE:
		return nil, "WPA3-Enterprise needs PMF, which this driver lacks"
	case s.Radius == nil || len(s.Radius.Auth) == 0:
		return nil, "WPA-Enterprise without a RADIUS auth server"
	case s.Radius.FilterID != "":
		// the Filter-Id lets the server tell this WLAN's users apart:
		// served without it, the server could admit users it means to
		// keep off
		return nil, "the RADIUS filter (Filter-Id) cannot be sent by rtdot1xd"
	}
	x := s.Radius.Auth[0]
	ip := net.ParseIP(x.IP).To4()
	if ip == nil || ip.IsUnspecified() {
		return nil, fmt.Sprintf("RADIUS server %q is not an IPv4 address", x.IP)
	}
	port := x.Port
	if port == 0 {
		port = 1812
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Sprintf("RADIUS port %d is not valid", x.Port)
	}
	if !profileSecret(x.Secret) {
		return nil, fmt.Sprintf("the RADIUS secret cannot be written to the driver profile (1-%d characters, no ';', control characters or spaces at either end)", maxRadiusSecret)
	}
	d := &Dot1X{Server: ip.String(), Port: port, Secret: x.Secret}
	if n := s.Radius.NASID; n != "" && len(n) <= maxNASID && profileSecret(n) {
		d.NASID = n
	}
	return d, ""
}

// profileSecret: v can be one entry of a driver profile ;-list, as is.
func profileSecret(v string) bool {
	if v == "" || len(v) > maxRadiusSecret || strings.TrimSpace(v) != v {
		return false
	}
	return strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f || r == ';' }) < 0
}

// dot1xNotes notes what of s's RADIUS settings an enterprise BSS on rd
// does not carry.
func dot1xNotes(s bcmwifi.SSID, rd RadioDef, note func(string, ...any)) {
	r := s.Radius
	if len(r.Auth) > 1 {
		note("%s: SSID %q: only the first RADIUS auth server is used (no failover to the other %d)", rd.Band, s.SSID, len(r.Auth)-1)
	}
	if len(r.Acct) > 0 {
		note("%s: SSID %q: RADIUS accounting is not sent (rtdot1xd has no accounting client)", rd.Band, s.SSID)
	}
	if n := r.NASID; n != "" && (len(n) > maxNASID || !profileSecret(n)) {
		note("%s: SSID %q: NAS-Identifier %q is not sent (at most %d characters, no ';' or control characters)", rd.Band, s.SSID, n, maxNASID)
	}
	if r.OwnIP != "" {
		note("%s: SSID %q: own IP %s not applied: NAS-IP-Address stays the profile's own_ip_addr", rd.Band, s.SSID, r.OwnIP)
	}
}

// hasDot1X: rp serves an enterprise BSS.
func hasDot1X(rp RadioPlan) bool {
	return slices.ContainsFunc(rp.BSS, func(b BSS) bool { return b.Radius != nil })
}

// lanBridge is the bridge of a BSS without a VLAN (Options.Bridge's
// default; the agent never sets another).
const lanBridge = unit.JioLANBridge

// dot1xKeys writes rp's 802.1X keys into kv. A radio without an enterprise
// BSS keeps the vendor's values (its profile does not change).
func dot1xKeys(kv map[string]string, base []byte, rd RadioDef, rp RadioPlan) {
	if !rp.On || !hasDot1X(rp) {
		return
	}
	n := len(rd.Ifaces)
	vendor := func(key string, slot int, def string) string {
		return strings.Split(listKey(base, key, n, nil, def), ";")[slot]
	}
	var srv, port []string
	keys := make([]string, n)
	var bridges []string
	for i := range keys {
		keys[i] = "unused" // never empty: the MT7603's list collapses empty entries
	}
	for i, b := range rp.BSS {
		slot := rp.slot(i)
		if b.Radius == nil {
			srv = append(srv, vendor("RADIUS_Server", slot, "0.0.0.0"))
			port = append(port, vendor("RADIUS_Port", slot, "1812"))
			continue
		}
		srv, port = append(srv, b.Radius.Server), append(port, strconv.Itoa(b.Radius.Port))
		if slot < n {
			keys[slot] = b.Radius.Secret
		}
		if !rd.RadiusKeyList {
			kv[fmt.Sprintf("RADIUS_Key%d", slot+1)] = b.Radius.Secret
		}
		if b.Radius.NASID != "" {
			kv[fmt.Sprintf("NasId%d", slot+1)] = b.Radius.NASID
		}
		br := lanBridge
		if b.VLAN > 0 {
			br = vlanBridge(b.VLAN)
		}
		if !slices.Contains(bridges, br) {
			bridges = append(bridges, br)
		}
	}
	kv["RADIUS_Server"] = slotKey(base, "RADIUS_Server", n, rp, srv, "0.0.0.0")
	kv["RADIUS_Port"] = slotKey(base, "RADIUS_Port", n, rp, port, "1812")
	if rd.RadiusKeyList {
		kv["RADIUS_Key1"] = strings.Join(keys, ";")
	}
	for len(bridges) < n {
		bridges = append(bridges, "lo")
	}
	kv["EAPifname"] = strings.Join(bridges, ";")
	kv["PreAuthifname"] = kv["EAPifname"]
	// the RADIUS server's Session-Timeout still applies (rtdot1xd
	// ieee802_1x_receive_auth); 0 adds no timer of its own
	kv["session_timeout_interval"] = "0"
	// NAS-IP-Address: the vendor's (rtdot1xd refuses 0); the requests
	// leave from the unit's own address whatever it says
	if v, _ := getKey(base, "own_ip_addr"); !validOwnIP(v) {
		kv["own_ip_addr"] = "127.0.0.1"
	}
}

func validOwnIP(v string) bool {
	first, _, _ := strings.Cut(v, ";")
	ip := net.ParseIP(first).To4()
	return ip != nil && !ip.IsUnspecified()
}

// ------------------------------------------------------- the supervisor

// dot1xState is the rtdot1xd supervisor's memory (a.mu).
type dot1xState struct {
	termed map[int]bool         // sent SIGTERM: SIGKILL at the next pass, never kept
	last   map[string]time.Time // band: the last start
	starts map[string]int       // band: starts not yet seen running
}

// dot1xRetry is the least time between two starts of a band's rtdot1xd.
const dot1xRetry = time.Minute

type dot1xProc struct {
	pid  int
	argv []string
}

// dot1xPrefix is rd's netdev prefix (ra, rai): rtdot1xd's -p.
func dot1xPrefix(rd RadioDef) string { return strings.TrimRight(rd.Ifaces[0], "0123456789") }

// procPrefix is the netdev prefix a running rtdot1xd serves: its -p, else
// what its name selects (rtdot1xd_AC: rai; else ra).
func procPrefix(argv []string) string {
	for i, a := range argv[1:] {
		if a == "-p" && i+2 < len(argv) {
			return argv[i+2]
		}
		if v, ok := strings.CutPrefix(a, "-p"); ok && v != "" {
			return v
		}
	}
	if path.Base(argv[0]) == "rtdot1xd_AC" {
		return "rai"
	}
	return "ra"
}

// dot1xProcs lists the running rtdot1xd processes (the vendor's too).
func (a *Applier) dot1xProcs() []dot1xProc {
	ents, err := os.ReadDir(a.dev("proc"))
	if err != nil {
		return nil
	}
	var out []dot1xProc
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}
		b, err := os.ReadFile(filepath.Join(a.dev("proc"), e.Name(), "cmdline"))
		if err != nil || len(b) == 0 {
			continue
		}
		argv := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if n := path.Base(argv[0]); n == "rtdot1xd" || n == "rtdot1xd_AC" {
			out = append(out, dot1xProc{pid: pid, argv: argv})
		}
	}
	slices.SortFunc(out, func(x, y dot1xProc) int { return x.pid - y.pid })
	return out
}

// dot1xArgv is what rd's rtdot1xd runs as for rp (nil: none wanted).
func (a *Applier) dot1xArgv(rd RadioDef, rp RadioPlan) []string {
	if !rd.Dot1X || !rp.On || !hasDot1X(rp) {
		return nil
	}
	first := -1 // the BSS netdev that read the profile (the lowest slot)
	for i := range rp.BSS {
		if first < 0 || rp.slot(i) < rp.slot(first) {
			first = i
		}
	}
	return []string{a.o.Dot1xd, "-p", dot1xPrefix(rd), "-i", a.ifaceOf(rd, rp, first)}
}

// dot1xSignal sends sig to pid (never in a dry run).
func (a *Applier) dot1xSignal(ctx context.Context, pid int, sig syscall.Signal) {
	if a.o.DryRun {
		a.o.Logf("mtkwifi: dry run: kill -%d %d (rtdot1xd)", sig, pid)
		return
	}
	if f := a.onChange.Load(); f != nil {
		(*f)(ctx)
	}
	if err := a.o.kill(pid, sig); err != nil && err != syscall.ESRCH {
		a.o.Logf("mtkwifi: rtdot1xd %d: kill -%d: %v", pid, sig, err)
	}
}

// dot1xStop ends a process: SIGTERM, then SIGKILL at a later pass.
func (a *Applier) dot1xStop(ctx context.Context, p dot1xProc) {
	if a.d1x.termed == nil {
		a.d1x.termed = map[int]bool{}
	}
	sig := syscall.SIGTERM
	if a.d1x.termed[p.pid] {
		sig = syscall.SIGKILL
	}
	a.d1x.termed[p.pid] = true
	a.dot1xSignal(ctx, p.pid, sig)
}

// dot1xStopBand stops every rtdot1xd serving rd (the radio restarts: what
// it read from the driver is stale; a.mu held).
func (a *Applier) dot1xStopBand(ctx context.Context, rd RadioDef) {
	pre := dot1xPrefix(rd)
	for _, p := range a.dot1xProcs() {
		if procPrefix(p.argv) == pre {
			a.o.Logf("mtkwifi: %s: stopping rtdot1xd %d (%s)", rd.Band, p.pid, strings.Join(p.argv, " "))
			a.dot1xStop(ctx, p)
		}
	}
}

// dot1xStopAll stops the agent's rtdot1xd processes (the hand-back: the
// vendor's Wi-Fi of this boot ran none of them).
func (a *Applier) dot1xStopAll(ctx context.Context) {
	for _, p := range a.dot1xProcs() {
		if p.argv[0] == a.o.Dot1xd && slices.Contains(p.argv, "-p") {
			a.o.Logf("mtkwifi: stopping rtdot1xd %d (hand-back)", p.pid)
			a.dot1xStop(ctx, p)
		}
	}
	a.d1x.last, a.d1x.starts = nil, nil
}

// dot1xSync keeps one rtdot1xd per radio that serves an enterprise BSS,
// run as dot1xArgv says, and none else (the vendor's, a stale one, a
// second copy). Never inside a radio restart's settle time (its first
// ioctls are driver reads the restart gate holds back); a.mu held.
func (a *Applier) dot1xSync(ctx context.Context) {
	if a.settling() || a.live == nil {
		return
	}
	procs := a.dot1xProcs()
	alive := map[int]bool{}
	for _, p := range procs {
		alive[p.pid] = true
	}
	for pid := range a.d1x.termed {
		if !alive[pid] {
			delete(a.d1x.termed, pid)
		}
	}
	if a.d1x.last == nil {
		a.d1x.last, a.d1x.starts = map[string]time.Time{}, map[string]int{}
	}
	for _, rd := range a.o.Layout {
		want := a.dot1xArgv(rd, a.live[rd.Band])
		pre := dot1xPrefix(rd)
		running := false
		for _, p := range procs {
			if procPrefix(p.argv) != pre {
				continue
			}
			if want != nil && !running && !a.d1x.termed[p.pid] && slices.Equal(p.argv, want) {
				running = true
				continue
			}
			a.o.Logf("mtkwifi: %s: rtdot1xd %d (%s) is not the agent's: stopped", rd.Band, p.pid, strings.Join(p.argv, " "))
			a.dot1xStop(ctx, p)
		}
		switch {
		case want == nil:
			delete(a.d1x.starts, rd.Band)
			continue
		case running:
			a.d1x.starts[rd.Band] = 0
			continue
		}
		now := a.o.wall()
		if t, ok := a.d1x.last[rd.Band]; ok && !now.Before(t) && now.Sub(t) < dot1xRetry { // a clock set back does not hold it
			continue
		}
		a.d1x.last[rd.Band] = now
		a.d1x.starts[rd.Band]++
		if k := a.d1x.starts[rd.Band]; k > 1 {
			a.o.Logf("mtkwifi: %s: rtdot1xd is not running (start %d): the enterprise SSIDs admit nobody until it runs", rd.Band, k)
		}
		// stdio to /dev/null: it forks without closing them, and a write to
		// the agent's closed pipe would end it (SIGPIPE)
		cmd := "exec " + strings.Join(want, " ") + " </dev/null >/dev/null 2>&1"
		if err := a.run(ctx, "sh", "-c", cmd); err != nil {
			a.o.Logf("mtkwifi: %s: starting rtdot1xd: %v", rd.Band, err)
			continue
		}
		a.o.Logf("mtkwifi: %s: rtdot1xd started (%s)", rd.Band, strings.Join(want, " "))
	}
}

// ServesDot1X reports whether some radio serves WPA2/WPA3-Enterprise
// (RadioDef.Dot1X after New): the agent claims RadSec on platform jio-mtk
// only then.
func (a *Applier) ServesDot1X() bool {
	return slices.ContainsFunc(a.o.Layout, func(rd RadioDef) bool { return rd.Dot1X })
}
