// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Connection-timing events (docs/deco/features/connection-events.md): the
// STA_ASSOC_TRACKER success / failure / "soft failure" / fixup a UniFi AP
// sends for each connection attempt, which feed the controller's WiFi
// Connectivity view and its per-AP connection metrics.
//
// What the controller reads (Network 11.1.50, devmgr.w.a.qeIWtmwxgQ and
// mMObEXELV): event_id, event_type, mac, vap, auth_ts (the attempt's
// time, unique per AP: the metrics are keyed on it), auth_rssi (else
// avg_rssi: below -75 dBm the counters are dropped), assoc_delta,
// auth_delta, wpa_auth_delta, ip_delta (counted for ip_assign_type "dhcp"
// only), traffic_delta (microseconds; only 0 < d <= 60 s counts),
// assoc_failures, auth_failures, wpa_auth_failures, ip_failures,
// traffic_failures, radius_auth_status ("success"/"failure"),
// arp_reply_gw_seen and dns_resp_seen ("yes"/"no"), dns_timeouts,
// dns_responses. An event is a success unless it is a failure and either
// it is a soft failure with ip_assign_type "roam" or traffic_delta > 0
// and dns_responses > 0.
//
// Where the agent gets them (takeover on the Deco, sta_snoop on):
//   - hostapd's syslog lines (a `logread -f` follower; the time is when
//     the line arrived): "IEEE 802.11: authenticated", "associated",
//     "WPA: pairwise key handshake completed", "WPA: FT authentication
//     already completed" (a fast transition), "EAPOL-Key timeout", and
//     "disassociated"/"deauthenticated";
//   - the hostapd control sockets (hapdmon): AP-STA-CONNECTED (the station
//     is authorized), AP-STA-POSSIBLE-PSK-MISMATCH, CTRL-EVENT-EAP-*,
//     AP-REJECTED-MAX-STA;
//   - the station's own frames on the VAP (internal/stasnoop, AF_PACKET
//     with a kernel filter for ARP, DHCP and DNS): its DHCP exchange, its
//     first frame, the gateway's ARP reply, its DNS queries and answers
//     (IPv4 or IPv6; a query is answered by a response of its family with
//     its id), and a DNS-over-TLS server accepting its connection.
//
// An attempt starts at the first anchor of a station not in an open
// attempt. The deltas are the steps between anchors: assoc_delta
// authenticated -> associated, wpa_auth_delta associated -> authorized,
// ip_delta authorized -> DHCP ACK, traffic_delta authorized -> its first
// frame; auth_delta is 0 (the driver authenticates; only the end is
// logged). It is judged at each reading:
//   - authorized, with an address, a frame and a DNS answer: "success";
//   - authorized staConnJudge ago without that: "soft failure" (an
//     unanswered query older than staDNSTimeout is a dns_timeout, no
//     address an ip_failure, no frame a traffic_failure); a success within
//     staConnFixup after that sends a "fixup" with the completed values;
//     but an attempt lacking only the DNS answer, with no plaintext query
//     and a DNS-over-TLS server that accepted its connection, is set
//     aside unjudged: its DNS cannot be read, and the controller would
//     count the missing answer as a failure (dnsUnseen); a plaintext
//     answer within staConnFixup after that (a fallback) still sends a
//     "success", and nothing else is ever sent for it;
//   - never authorized staConnJudge after it started, and not associated
//     in the reading: "failure" (PSK mismatches and EAPOL timeouts count as
//     wpa_auth_failures, a full BSS as an assoc_failure, an EAP rejection
//     sets radius_auth_status).
// A station that leaves while authorized is judged at once. Nothing is
// judged on a BSS without a tap: without the DNS answer every attempt
// would read as a soft failure.
//
// sta_roam (and wifi_caps2 0x2000, supportsRoamTopologyStats) is not
// sent: it needs the AP a client roamed from, which the agent does not
// know; the controller's roaming detector takes the success events and
// the association/sta_leave pairs instead (staevents.go).

import (
	"bufio"
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/hapdmon"
	"github.com/dtechterminal/udeco/internal/stasnoop"
)

const (
	staConnJudge  = 30 * time.Second // an attempt is judged this long after authorization (or its start)
	staConnFixup  = 2 * time.Minute  // a late success after a soft failure is a fixup within this
	staDNSTimeout = 5 * time.Second  // an unanswered DNS query this old is a timeout
	staConnMax    = 256              // open attempts at most (the oldest go)
	staIPKeep     = time.Hour        // a station's last address is remembered this long (GARP)
	anchorMax     = 512              // syslog anchors kept between readings
	snoopMax      = 1024             // frames kept between readings
	snoopRetry    = time.Minute      // a tap that failed is opened again after this
	// anchorSkew: a syslog anchor arrives through syslogd and logread,
	// later than the control socket's AP-STA-CONNECTED it belongs to.
	anchorSkew = time.Second
)

// anchorKind is one hostapd syslog line that marks a step.
type anchorKind int

const (
	anchorAuth anchorKind = iota + 1
	anchorAssoc
	anchorWPA
	anchorFT
	anchorLeave
	anchorEAPOLTimeout
)

// staAnchor is one parsed hostapd syslog line.
type staAnchor struct {
	Vif, MAC string
	Kind     anchorKind
}

// parseAnchor reads "... hostapd: wl12: STA <mac> <text>".
func parseAnchor(line string) (staAnchor, bool) {
	i := strings.Index(line, "hostapd: ")
	if i < 0 {
		return staAnchor{}, false
	}
	f := strings.SplitN(line[i+len("hostapd: "):], " ", 4)
	if len(f) < 4 || !strings.HasSuffix(f[0], ":") || f[1] != "STA" {
		return staAnchor{}, false
	}
	mac := normMAC(f[2])
	if mac == "" {
		return staAnchor{}, false
	}
	a := staAnchor{Vif: strings.TrimSuffix(f[0], ":"), MAC: mac}
	switch t := f[3]; {
	case strings.HasPrefix(t, "IEEE 802.11: authenticated"):
		a.Kind = anchorAuth
	case strings.HasPrefix(t, "IEEE 802.11: associated"), strings.HasPrefix(t, "IEEE 802.11: reassociated"):
		a.Kind = anchorAssoc
	case strings.HasPrefix(t, "IEEE 802.11: disassociated"), strings.HasPrefix(t, "IEEE 802.11: deauthenticated"):
		a.Kind = anchorLeave
	case strings.HasPrefix(t, "WPA: pairwise key handshake completed"):
		a.Kind = anchorWPA
	case strings.HasPrefix(t, "WPA: FT authentication already completed"):
		a.Kind = anchorFT
	case strings.Contains(t, "EAPOL-Key timeout"):
		a.Kind = anchorEAPOLTimeout
	default:
		return staAnchor{}, false
	}
	return a, true
}

// replayedLine: a log line stamped (busybox logread: "Fri Nov 20 12:00:00
// 2026 ...") more than a second before the follower started, i.e. the
// buffered line `logread -f -l 1` prints first. An unparsable stamp is not
// a replay.
func replayedLine(line string, started time.Time) bool {
	if len(line) < len(time.ANSIC) {
		return false
	}
	t, err := time.ParseInLocation(time.ANSIC, line[:len(time.ANSIC)], started.Location())
	return err == nil && started.Sub(t) > time.Second
}

// normMAC is a MAC address in lower case ("" when it is none): the colon
// form only, as hostapd and the kernel print it (wl.NormMAC also takes
// net.ParseMAC's other spellings).
func normMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 17 {
		return ""
	}
	for i := 0; i < 17; i++ {
		c := s[i]
		if i%3 == 2 {
			if c != ':' {
				return ""
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	return s
}

// connIn is one input of the tracker, in time order.
type connIn struct {
	at     time.Time
	anchor *staAnchor
	sock   *hapdmon.Event
	frame  *stasnoop.Obs
	// drv: a driver's step (the Garage, staconn_jio.go): its Connected
	// only authorizes an open attempt (the drivers also report the end of
	// each group rekey), never starts one
	drv bool
}

// connReading is what the tracker needs from a reading.
type connReading struct {
	now time.Time
	// read: when the reading started (feed.read; zero: no socket feed).
	// staevents holds a socket authorization from after it for the next
	// reading's association event; that attempt's success or fixup waits
	// for that reading too (never before its association)
	read    time.Time
	up      int64             // the reading's uptime
	vifs    map[string]string // BSS interface -> vap_table name
	snooped map[string]bool   // the BSSes with a running tap
	// snoopSince: when each BSS's tap (re)opened. An attempt authorized
	// before it (a tap that died with its vif at a hostapd restart) had its
	// DHCP and DNS unseen: it is dropped, never judged.
	snoopSince map[string]time.Time
	signal     map[string]int  // station -> signal (dBm)
	assoc      map[string]bool // stations associated in the reading
	// staVif: station -> the BSS it is on in the reading (a driver step
	// that names no BSS is put there: staconn_jio.go)
	staVif map[string]string
	gwMAC  string
	gwIP   string
}

// assocPending: a's association event waits for the next reading
// (authorized on the socket after this reading started).
func (r connReading) assocPending(a *connAttempt) bool {
	return !r.read.IsZero() && !a.sockAt.IsZero() && !a.sockAt.Before(r.read)
}

// connAttempt is one station's connection attempt.
type connAttempt struct {
	mac, vif   string
	start      time.Time // first anchor
	auth       time.Time // authenticated (syslog)
	assoc      time.Time // associated
	wpa        time.Time // authorized: the 4-way handshake (or FT) is done
	authorized bool
	sockAt     time.Time // hostapd's AP-STA-CONNECTED (socket) for this attempt
	ft         bool
	eapStart   time.Time
	eapDone    time.Time
	radius     string // "success" / "failure" / ""
	ipAt       time.Time
	ip         string
	ipType     string // "dhcp" / "static" / "roam"
	dhcpTries  int
	naks       int
	traffic    time.Time // its first frame after authorization
	arpGW      bool      // it asked for the gateway's address
	arpGWReply bool      // and the gateway answered
	dnsQ       map[uint32]time.Time
	dnsQueries int
	dnsResp    int
	dot        bool // a DNS-over-TLS server accepted its connection
	// byFrame: authorized taken from its first frame on the tap (the
	// Garage's 2.4 GHz driver reports no 4-way handshake): its
	// wpa_auth_delta is not known
	byFrame    bool
	wpaFails   int
	assocFails int
	rssi       int // the first signal seen (auth_rssi)
	soft       time.Time
	held       time.Time // set aside at the judge time with no verdict (dnsUnseen)
	id         string    // event_id, once given: one per attempt, reused by its fixup
	ts         float64   // auth_ts, once given
}

// connTracker turns the inputs into events (loop goroutine).
type connTracker struct {
	att    map[string]*connAttempt
	lastTS float64
	seq    uint64
	// ips: station -> its last address and the bridge it was seen on; read
	// by the GARP goroutine too (garp.go), hence ipMu
	ipMu sync.Mutex
	ips  map[string]staIP
	// bridgeOf names a BSS's bridge (nil: unknown, ""); cached per judge
	bridgeOf func(vif string) string
	brCache  map[string]string
	in       []connIn
	gone     []*connAttempt // authorized attempts that ended, to judge
	// frameAuth (the Garage): a station's first frame on its BSS's tap
	// authorizes an attempt no driver event authorized (a PSK station's
	// data frames pass only after the 4-way handshake)
	frameAuth bool
	// staVif: the judge's reading's station -> BSS (connReading.staVif)
	staVif map[string]string
}

type staIP struct {
	ip string
	at time.Time
	br string // the bridge of the BSS it was seen on
}

func newConnTracker() *connTracker {
	return &connTracker{att: map[string]*connAttempt{}, ips: map[string]staIP{}}
}

// add queues one input (they are applied in time order by judge).
func (c *connTracker) add(in connIn) { c.in = append(c.in, in) }

// ipOf is a station's address when known lately on bridge br: an address
// seen on another bridge (another network) is none.
func (c *connTracker) ipOf(mac, br string, now time.Time) (string, bool) {
	c.ipMu.Lock()
	defer c.ipMu.Unlock()
	s, ok := c.ips[mac]
	if !ok || now.Sub(s.at) > staIPKeep || s.br != br {
		return "", false
	}
	return s.ip, true
}

func (c *connTracker) setIP(mac, ip, br string, at time.Time) {
	c.ipMu.Lock()
	defer c.ipMu.Unlock()
	c.ips[mac] = staIP{ip, at, br}
}

func (c *connTracker) forgetIP(mac string) {
	c.ipMu.Lock()
	defer c.ipMu.Unlock()
	delete(c.ips, mac)
}

// bridge is vif's bridge (cached for one judge).
func (c *connTracker) bridge(vif string) string {
	if c.bridgeOf == nil {
		return ""
	}
	if br, ok := c.brCache[vif]; ok {
		return br
	}
	if c.brCache == nil {
		c.brCache = map[string]string{}
	}
	br := c.bridgeOf(vif)
	c.brCache[vif] = br
	return br
}

// open returns mac's open attempt on vif, starting one at at.
func (c *connTracker) open(mac, vif string, at time.Time) *connAttempt {
	a := c.att[mac]
	if a != nil && a.vif == vif {
		return a
	}
	c.retire(mac)
	if len(c.att) >= staConnMax {
		var old string
		for m, x := range c.att {
			if old == "" || x.start.Before(c.att[old].start) {
				old = m
			}
		}
		delete(c.att, old)
	}
	a = &connAttempt{mac: mac, vif: vif, start: at, dnsQ: map[uint32]time.Time{}}
	c.att[mac] = a
	return a
}

// vifOf is the BSS of a step that names none (a radio-wide driver event):
// the station's open attempt's, else the reading's; "" when neither.
func (c *connTracker) vifOf(mac, vif string) string {
	if vif != "" {
		return vif
	}
	if a := c.att[mac]; a != nil {
		return a.vif
	}
	return c.staVif[mac]
}

func (c *connTracker) apply(in connIn, gwMAC, gwIP string) {
	switch {
	case in.anchor != nil:
		x := in.anchor
		if x.Vif == "" {
			y := *x
			y.Vif = c.vifOf(x.MAC, "")
			if y.Vif == "" {
				return // no BSS to put it on
			}
			x = &y
		}
		a := c.att[x.MAC]
		switch x.Kind {
		case anchorAuth, anchorAssoc:
			if a != nil && a.authorized && a.vif == x.Vif && !in.at.Before(a.wpa) && in.at.Sub(a.wpa) < anchorSkew {
				// the syslog line of the (re)association AP-STA-CONNECTED
				// already reported, arriving late through syslogd and
				// logread (an FT reassociation logs it in the same call):
				// part of this attempt, not a new one
				break
			}
			if a != nil && (a.authorized || a.vif != x.Vif) {
				c.retire(x.MAC) // a new attempt
			}
			a = c.open(x.MAC, x.Vif, in.at)
			if x.Kind == anchorAuth {
				a.auth = in.at
			} else {
				a.assoc = in.at
			}
		case anchorWPA:
			if a != nil && a.wpa.IsZero() {
				a.wpa = in.at
			}
		case anchorFT:
			if a != nil {
				a.ft = true
			}
		case anchorEAPOLTimeout:
			if a != nil && !a.authorized {
				a.wpaFails++
			}
		case anchorLeave:
			// an authorized attempt is judged at the next reading; one
			// never authorized stays open (the station may try again)
			if a != nil && a.authorized {
				c.retire(x.MAC)
			}
		}
	case in.sock != nil:
		ev := in.sock
		if ev.Vif == "" {
			e := *ev
			e.Vif = c.vifOf(ev.MAC, "")
			if e.Vif == "" {
				return
			}
			ev = &e
		}
		a := c.att[ev.MAC]
		switch ev.Kind {
		case hapdmon.Connected:
			if in.drv && (a == nil || a.authorized || a.vif != ev.Vif) {
				break // a group rekey's end, or a step of an attempt not seen
			}
			if a == nil || a.authorized || a.vif != ev.Vif {
				c.retire(ev.MAC)
				a = c.open(ev.MAC, ev.Vif, in.at)
			}
			a.authorized = true
			a.sockAt = in.at
			if a.wpa.IsZero() {
				a.wpa = in.at
			}
		case hapdmon.Disconnected:
			if a != nil && a.authorized {
				c.retire(ev.MAC)
			}
		case hapdmon.PSKMismatch:
			c.open(ev.MAC, ev.Vif, in.at).wpaFails++
		case hapdmon.RejectedMaxSta:
			c.open(ev.MAC, ev.Vif, in.at).assocFails++
		case hapdmon.EAPStarted:
			c.open(ev.MAC, ev.Vif, in.at).eapStart = in.at
		case hapdmon.EAPSuccess:
			a := c.open(ev.MAC, ev.Vif, in.at)
			a.radius, a.eapDone = "success", in.at
		case hapdmon.EAPFailure:
			a := c.open(ev.MAC, ev.Vif, in.at)
			a.radius, a.eapDone = "failure", in.at
		case hapdmon.EAPTimeout:
			// TIMEOUT-FAILURE(2): the authentication server (or the
			// station's EAP) timed out, not the 4-way handshake
			a := c.open(ev.MAC, ev.Vif, in.at)
			a.radius, a.eapDone = "failure", in.at
		}
	case in.frame != nil:
		c.frame(*in.frame, in.at, gwMAC, gwIP)
	}
}

// retire takes mac's attempt out of the open ones: an authorized one not
// judged yet is judged at the next reading, whatever its age (its station
// left, or started again); any other is dropped.
func (c *connTracker) retire(mac string) {
	a := c.att[mac]
	if a == nil {
		return
	}
	delete(c.att, mac)
	if a.authorized && a.soft.IsZero() && len(c.gone) < staConnMax {
		c.gone = append(c.gone, a)
	}
}

func (c *connTracker) frame(o stasnoop.Obs, at time.Time, gwMAC, gwIP string) {
	mac := o.Station()
	if mac == "" {
		return
	}
	// what the station's own frames say about its address
	switch {
	case o.Kind == stasnoop.DHCPAck && o.Out && o.YourIP != "" && o.YourIP != "0.0.0.0":
		c.setIP(mac, o.YourIP, c.bridge(o.Vif), at)
	case !o.Out && !o.V6 && o.Kind != stasnoop.DHCPDiscover && o.Kind != stasnoop.DHCPRequest && o.SrcIP != "" && o.SrcIP != "0.0.0.0":
		c.setIP(mac, o.SrcIP, c.bridge(o.Vif), at)
	}
	a := c.att[mac]
	if c.frameAuth && a != nil && a.vif == o.Vif && !a.authorized && !o.Out {
		a.authorized, a.byFrame, a.wpa, a.sockAt = true, true, at, at
	}
	if a == nil || a.vif != o.Vif || !a.authorized {
		return
	}
	if !o.Out && a.traffic.IsZero() {
		a.traffic = at
	}
	switch o.Kind {
	case stasnoop.DHCPDiscover, stasnoop.DHCPRequest:
		if !o.Out {
			a.dhcpTries++
		}
	case stasnoop.DHCPAck:
		if o.Out && a.ipType != "dhcp" {
			a.ip, a.ipAt, a.ipType = o.YourIP, at, "dhcp"
		}
	case stasnoop.DHCPNak:
		if o.Out {
			a.naks++
		}
	case stasnoop.ARPRequest:
		if !o.Out && gwIP != "" && o.DstIP == gwIP {
			a.arpGW = true
		}
	case stasnoop.ARPReply:
		if o.Out && (o.SrcIP == gwIP && gwIP != "" || o.Src == gwMAC && gwMAC != "") {
			a.arpGWReply = true
		}
	case stasnoop.DNSQuery:
		if !o.Out {
			a.dnsQueries++
			if len(a.dnsQ) < 64 {
				a.dnsQ[dnsKey(o)] = at
			}
		}
	case stasnoop.DNSResponse:
		if o.Out {
			if _, ok := a.dnsQ[dnsKey(o)]; ok {
				delete(a.dnsQ, dnsKey(o))
				a.dnsResp++
			}
		}
	case stasnoop.DoTSynAck:
		if o.Out {
			a.dot = true
		}
	}
	// an address used without DHCP: kept from before (static, or a roam)
	if !o.Out && !o.V6 && a.ipType == "" && o.Kind != stasnoop.DHCPDiscover && o.Kind != stasnoop.DHCPRequest &&
		o.SrcIP != "" && o.SrcIP != "0.0.0.0" {
		a.ip, a.ipType = o.SrcIP, "static"
		if a.ft {
			a.ipType = "roam"
		}
	}
}

// dnsKey is a DNS message's key among its attempt's open queries: its id,
// kept apart per address family (an IPv6 response never answers an IPv4
// query with the same id).
func dnsKey(o stasnoop.Obs) uint32 {
	if o.V6 {
		return o.ID | 1<<16
	}
	return o.ID
}

// judge applies the queued inputs in time order and sends the attempts'
// events through push.
func (c *connTracker) judge(r connReading, push func(map[string]any)) {
	in := c.in
	c.in = nil
	c.brCache = nil
	c.staVif = r.staVif
	sort.SliceStable(in, func(i, j int) bool { return in[i].at.Before(in[j].at) })
	for _, x := range in {
		c.apply(x, r.gwMAC, r.gwIP)
	}
	c.ipMu.Lock()
	for m, s := range c.ips {
		if r.now.Sub(s.at) > staIPKeep {
			delete(c.ips, m)
		}
	}
	c.ipMu.Unlock()
	gone := c.gone
	c.gone = nil
	for _, a := range gone {
		vap := r.vifs[a.vif]
		if vap == "" || !r.snooped[a.vif] || r.beforeTap(a) {
			continue
		}
		if r.assocPending(a) {
			c.gone = append(c.gone, a)
			continue
		}
		c.rssi(a, r)
		switch {
		case a.complete():
			push(c.event(a, "success", vap, r))
		case a.dnsUnseen() || !a.held.IsZero():
		default:
			push(c.event(a, "soft failure", vap, r))
		}
	}
	macs := make([]string, 0, len(c.att))
	for m := range c.att {
		macs = append(macs, m)
	}
	sort.Strings(macs)
	for _, m := range macs {
		a := c.att[m]
		c.rssi(a, r)
		vap := r.vifs[a.vif]
		switch {
		case vap == "" || !r.snooped[a.vif]:
			if r.now.Sub(a.started()) > staConnFixup {
				delete(c.att, m)
			}
		case a.authorized && r.beforeTap(a):
			delete(c.att, m) // its frames went unseen: no basis for a verdict
		case !a.authorized:
			if r.now.Sub(a.started()) < staConnJudge {
				continue
			}
			delete(c.att, m)
			if r.assoc[m] || a.assoc.IsZero() && a.wpaFails == 0 && a.assocFails == 0 && a.radius == "" {
				continue // associated after all (a part the agent did not see), or no attempt to speak of
			}
			push(c.event(a, "failure", vap, r))
		case a.complete() && r.assocPending(a):
			continue // its association event rides the next reading
		case a.complete():
			typ := "success"
			if !a.soft.IsZero() {
				typ = "fixup"
			}
			push(c.event(a, typ, vap, r))
			delete(c.att, m)
		case !a.soft.IsZero():
			if r.now.Sub(a.soft) > staConnFixup {
				delete(c.att, m)
			}
		case !a.held.IsZero():
			if r.now.Sub(a.held) > staConnFixup {
				delete(c.att, m)
			}
		case r.now.Sub(a.wpa) >= staConnJudge && a.dnsUnseen():
			a.held = r.now // its DNS went encrypted: no basis for a verdict; a later answer is still a success
		case r.now.Sub(a.wpa) >= staConnJudge:
			a.soft = r.now
			push(c.event(a, "soft failure", vap, r))
		}
	}
}

// beforeTap: a was authorized before its BSS's tap (re)opened.
func (r connReading) beforeTap(a *connAttempt) bool {
	since, ok := r.snoopSince[a.vif]
	return ok && !a.wpa.IsZero() && a.wpa.Before(since)
}

// rssi keeps the attempt's first signal (auth_rssi).
func (c *connTracker) rssi(a *connAttempt, r connReading) {
	if sig := r.signal[a.mac]; sig != 0 && a.rssi == 0 {
		a.rssi = sig
	}
}

// complete: an address, a frame and a DNS answer (the controller's success).
func (a *connAttempt) complete() bool {
	return a.ipType != "" && !a.traffic.IsZero() && a.dnsResp > 0
}

// dnsUnseen: a lacks only the DNS answer, and its DNS went where the tap
// cannot read it: no plaintext query, and a DNS-over-TLS server accepted
// its connection. The controller counts a soft failure without
// dns_responses as a failure, and success needs dns_responses > 0, so
// such an attempt is set aside rather than sent as a false failure: only a
// later success (a plaintext fallback answered) is ever sent for it.
// A roam's soft failure is a success to the controller and is still sent.
func (a *connAttempt) dnsUnseen() bool {
	return a.dot && a.dnsQueries == 0 && a.ipType != "" && a.ipType != "roam" && !a.traffic.IsZero()
}

// started is when the attempt began: its first anchor.
func (a *connAttempt) started() time.Time { return a.start }

// delta is b - a in microseconds when both are known and b is later.
func delta(a, b time.Time) int64 {
	if a.IsZero() || b.IsZero() || !b.After(a) {
		return 0
	}
	return b.Sub(a).Microseconds()
}

// event builds one STA_ASSOC_TRACKER payload.
func (c *connTracker) event(a *connAttempt, typ, vap string, r connReading) map[string]any {
	if a.ts == 0 {
		ts := float64(a.started().UnixMicro()) / 1e6
		if ts <= c.lastTS {
			ts = c.lastTS + 1e-6
		}
		a.ts, c.lastTS = ts, ts
	}
	if a.id == "" {
		c.seq++
		a.id = fmt.Sprintf("%x-%x", int64(a.ts*1e6), c.seq)
	}
	ev := map[string]any{
		"message_type": staTracker, "event_type": typ, "event_id": a.id,
		"mac": a.mac, "vap": vap, "auth_ts": a.ts, "last_seen": r.up, "assoc_status": 0,
		"auth_rssi": a.rssi, "avg_rssi": r.signal[a.mac],
		"assoc_delta": delta(a.auth, a.assoc), "wpa_auth_delta": delta(a.assoc, a.wpa),
		"ip_delta": int64(0), "traffic_delta": int64(0),
		"assoc_failures": a.assocFails, "auth_failures": 0, "wpa_auth_failures": a.wpaFails,
		"ip_failures": 0, "traffic_failures": 0, "dns_timeouts": 0, "dns_responses": a.dnsResp,
	}
	if ev["avg_rssi"] == 0 {
		ev["avg_rssi"] = a.rssi
	}
	// no signal known (a station that failed before any reading listed
	// it): no RSSI rather than 0, which the controller's -75 dBm gate on
	// non-success counters would take as a strong one
	if a.rssi == 0 {
		delete(ev, "auth_rssi")
	}
	if ev["avg_rssi"] == 0 {
		delete(ev, "avg_rssi")
	}
	if a.ft {
		ev["auth_algo"] = "ft"
	}
	if a.byFrame {
		ev["wpa_auth_delta"] = int64(0) // the handshake's end is not known
	}
	if a.radius != "" {
		// 802.1X (deco-crosscheck): auth_delta EAP-STARTED -> EAP-SUCCESS,
		// wpa_auth_delta from the end of EAP-SUCCESS; EAP-FAILURE or
		// TIMEOUT-FAILURE is an auth_failure. auth_delta is omitted for PSK.
		ev["radius_auth_status"] = a.radius
		ev["radius_auth_delta"] = delta(a.eapStart, a.eapDone)
		if a.radius == "success" {
			ev["auth_delta"] = delta(a.eapStart, a.eapDone)
			if !a.eapDone.IsZero() {
				ev["wpa_auth_delta"] = delta(a.eapDone, a.wpa)
			}
		} else {
			ev["auth_failures"] = 1
		}
	}
	if typ == "failure" {
		if a.wpaFails == 0 && a.assocFails == 0 && a.radius != "failure" {
			ev["wpa_auth_failures"] = 1 // associated, never authorized
		}
		return ev
	}
	if a.ipType != "" {
		ev["ip_assign_type"] = a.ipType
	}
	if a.ipType == "dhcp" {
		ev["ip_delta"] = delta(a.wpa, a.ipAt)
	}
	if a.ipType == "" {
		ev["ip_failures"] = 1 + a.naks
	} else {
		ev["ip_failures"] = a.naks
	}
	ev["traffic_delta"] = delta(a.wpa, a.traffic)
	if a.traffic.IsZero() {
		ev["traffic_failures"] = 1
	} else if ev["traffic_delta"] == int64(0) {
		ev["traffic_delta"] = int64(1) // in the same microsecond: still traffic
	}
	timeouts := 0
	for _, q := range a.dnsQ {
		if r.now.Sub(q) >= staDNSTimeout {
			timeouts++
		}
	}
	ev["dns_timeouts"] = timeouts
	switch {
	case a.dnsResp > 0:
		ev["dns_resp_seen"] = "yes"
	case a.dnsQueries > 0:
		ev["dns_resp_seen"] = "no"
	}
	switch {
	case a.arpGWReply:
		ev["arp_reply_gw_seen"] = "yes"
	case a.arpGW:
		ev["arp_reply_gw_seen"] = "no"
	}
	return ev
}

// connState is the agent's part: the tracker, the anchor follower's
// queue and the taps.
type connState struct {
	t       *connTracker
	anchors *anchorRing
	ring    *stasnoop.Ring
	open    stasnoop.Opener // nil = stasnoop.Open
	readers map[string]context.CancelFunc
	failed  map[string]time.Time
	died    map[string]time.Time // a running tap that ended (ENETDOWN: its vif went with a hostapd restart)
	since   map[string]time.Time // when each running tap opened
	done    chan string
	logged  map[string]bool
}

// anchorRing keeps the newest anchorMax anchors for the loop.
type anchorRing struct {
	mu      sync.Mutex
	in      []connIn
	dropped int
}

func (r *anchorRing) add(in connIn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.in) >= anchorMax {
		r.in = r.in[1:]
		r.dropped++
	}
	r.in = append(r.in, in)
}

func (r *anchorRing) take() ([]connIn, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	in, d := r.in, r.dropped
	r.in, r.dropped = nil, 0
	return in, d
}

// staSnoopOn: connection-timing events unless sta_snoop is false.
func (c *Config) staSnoopOn() bool { return c.StaSnoop == nil || *c.StaSnoop }

// startConnEvents starts the syslog anchor follower (takeover on the
// Deco, sta_snoop on). The taps follow the readings (connReading). On the
// Garage (platform jio-mtk) the anchors are the drivers' join steps
// (startDriverEvents feeds a.drvSteps; staconn_jio.go) and there is no
// hostapd log to follow; its GARP is garage.go's.
func (a *agent) startConnEvents(ctx context.Context) {
	if !a.cfg.staSnoopOn() {
		return
	}
	t := newConnTracker()
	t.bridgeOf = a.bridgeName
	anchors := &anchorRing{}
	if a.cfg.jio() {
		t.frameAuth = true
		if a.drvSteps != nil {
			anchors = a.drvSteps
		}
	}
	a.conn = &connState{t: t, anchors: anchors, ring: stasnoop.NewRing(snoopMax),
		open: a.o.snoopOpen, readers: map[string]context.CancelFunc{}, failed: map[string]time.Time{},
		died: map[string]time.Time{}, since: map[string]time.Time{},
		done: make(chan string, 16), logged: map[string]bool{}}
	if a.cfg.jio() {
		return
	}
	a.startGARP(ctx) // garp.go: on the socket event, not the reading
	a.sta.algo = a.authAlgo
	r := a.conn.anchors
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		wait := time.Second
		for ctx.Err() == nil {
			rc, err := a.logFollow(ctx)
			if err == nil {
				stop := context.AfterFunc(ctx, func() { rc.Close() }) // unblocks the scan
				sc := bufio.NewScanner(rc)
				sc.Buffer(make([]byte, 4096), 4096)
				started, first := time.Now(), true
				for sc.Scan() {
					if first && replayedLine(sc.Text(), started) {
						first = false
						continue // logread -l 1 replays the newest buffered line
					}
					first = false
					if x, ok := parseAnchor(sc.Text()); ok {
						r.add(connIn{at: time.Now(), anchor: &x})
					}
				}
				stop()
				rc.Close()
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait = min(2*wait, time.Minute)
		}
	}()
}

// authAlgo is an association's auth_algo (staevents.go; loop goroutine):
// "ft" when the station's attempt is a fast transition (its FT syslog line,
// in the tracker or still in the anchor ring), "sae" on a WPA3-only SSID
// served with wpa3, else "open".
func (a *agent) authAlgo(mac, ssid string) string {
	if cs := a.conn; cs != nil {
		if x := cs.t.att[mac]; x != nil && x.ft || cs.anchors.ft(mac) {
			return "ft"
		}
	}
	if pol := a.policy.Load(); a.cfg.WPA3 && pol != nil && pol.sae[ssid] {
		return "sae"
	}
	return "open"
}

// ft: an FT anchor of mac waits in the ring.
func (r *anchorRing) ft(mac string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, in := range r.in {
		if in.anchor != nil && in.anchor.MAC == mac && in.anchor.Kind == anchorFT {
			return true
		}
	}
	return false
}

// connReading feeds one reading to the tracker and queues its events
// (loop goroutine, after staEvents.observe with the same feed).
func (a *agent) connReading(ctx context.Context, s *apstate.Snapshot, f map[string]any, feed *staFeed) {
	cs := a.conn
	if cs == nil || feed == nil {
		return
	}
	now := feed.now
	served := map[string]bool{}
	if a.takeover.Load() && !a.shed.Load() {
		for vif := range feed.vifs {
			if strings.HasPrefix(vif, "wl") || a.cfg.jio() && mtkBSS(vif) {
				served[vif] = true
			}
		}
	}
	a.snoopReconcile(ctx, cs, served, now)
	in, dropped := cs.anchors.take()
	if dropped > 0 {
		a.logf("connection events: %d hostapd log lines (Garage: driver steps) dropped", dropped)
	}
	for i := range feed.evs {
		ev := feed.evs[i]
		in = append(in, connIn{at: ev.At, sock: &ev})
	}
	arp := s.ARP
	a.garpARP.Store(&arp) // the GARP's fallback source (garp.go)
	obs, odrop := cs.ring.Take()
	if odrop > 0 && !cs.logged["drop"] {
		cs.logged["drop"] = true
		a.logf("connection events: %d snooped frames dropped (more than %d between readings)", odrop, snoopMax)
	}
	for i := range obs {
		in = append(in, connIn{at: obs[i].At, frame: &obs[i]})
	}
	for _, x := range in {
		cs.t.add(x)
	}
	r := connReading{now: now, read: feed.read, vifs: feed.vifs, snooped: map[string]bool{}, snoopSince: map[string]time.Time{},
		signal: map[string]int{}, assoc: map[string]bool{}, staVif: map[string]string{}}
	r.up, _ = toInt64(f["uptime"])
	for vif := range cs.readers {
		r.snooped[vif] = true
		r.snoopSince[vif] = cs.since[vif]
	}
	for _, rd := range s.Radios {
		for _, v := range rd.VAPs {
			for _, st := range v.Stations {
				m := strings.ToLower(st.MAC)
				r.assoc[m] = true
				r.staVif[m] = v.Iface
				if st.Signal != 0 {
					r.signal[m] = st.Signal
				}
			}
		}
	}
	r.gwIP, _ = a.topo.gwIP.Load().(string)
	r.gwMAC, _ = a.topo.gwMAC.Load().(string)
	cs.t.judge(r, a.sta.push)
}

// snoopReconcile runs a tap on every served BSS and stops the others.
func (a *agent) snoopReconcile(ctx context.Context, cs *connState, want map[string]bool, now time.Time) {
drain:
	for {
		select {
		case vif := <-cs.done:
			if c := cs.readers[vif]; c != nil {
				// opened again at once (its vif is usually back within
				// seconds of a hostapd restart), then at every reading
				// for snoopRetry before the slow retry
				c()
				delete(cs.readers, vif)
				delete(cs.since, vif)
				cs.died[vif] = now
			}
		default:
			break drain
		}
	}
	for vif, cancel := range cs.readers {
		if !want[vif] {
			cancel()
			delete(cs.readers, vif)
			delete(cs.since, vif)
		}
	}
	open := cs.open
	if open == nil {
		open = stasnoop.Open
	}
	var start []string
	for vif := range want {
		died, ok := cs.died[vif]
		recent := ok && now.Sub(died) < snoopRetry
		if cs.readers[vif] == nil && (recent || cs.failed[vif].IsZero() || now.Sub(cs.failed[vif]) >= snoopRetry) {
			start = append(start, vif)
		}
	}
	sort.Strings(start)
	for _, vif := range start {
		src, err := open(vif)
		if err != nil {
			if cs.failed[vif].IsZero() {
				a.logf("connection events: tap on %s: %v (retrying every %s)", vif, err, snoopRetry)
			}
			cs.failed[vif] = now
			continue
		}
		delete(cs.failed, vif)
		delete(cs.died, vif)
		rctx, cancel := context.WithCancel(ctx)
		cs.readers[vif] = cancel
		cs.since[vif] = now
		a.bg.Add(1)
		go func(vif string) {
			defer a.bg.Done()
			if err := stasnoop.Run(rctx, cs.ring, vif, src, time.Now); err != nil && rctx.Err() == nil {
				a.logf("connection events: tap on %s: %v", vif, err)
				select {
				case cs.done <- vif:
				default:
				}
			}
		}(vif)
	}
}
