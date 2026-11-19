// SPDX-License-Identifier: GPL-2.0-or-later

package main

// The agent: one UniFi AP (a U6-Lite) per Deco unit, running on the unit.
// The inform loop is cmd/udeco/runner.go without the mesh gate: it reads
// the unit with internal/wl, informs through internal/device, and hands
// anything that changes the unit to the Wi-Fi worker (wifi.go), so an apply
// never delays an inform.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/ftpeer"
	"github.com/antoniocosta/unifi-openwrt/internal/inform"
	"github.com/antoniocosta/unifi-openwrt/internal/jioports"
	"github.com/antoniocosta/unifi-openwrt/internal/jiosys"
	"github.com/antoniocosta/unifi-openwrt/internal/lldp"
	"github.com/antoniocosta/unifi-openwrt/internal/models"
	"github.com/antoniocosta/unifi-openwrt/internal/mtkwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/pathmon"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

// collector is what the agent uses of *wl.Collector.
type collector interface {
	Collect(ctx context.Context) (*apstate.Snapshot, error)
	Caps(ctx context.Context) (wl.Caps, error)
	// Scan is the neighbour scan (`cmd scan`, scan_table only).
	Scan(ctx context.Context, band string) (*apstate.ScanResult, error)
	// HomeScan listens on the radio's own channel only (homeListen).
	HomeScan(ctx context.Context, band string) (*apstate.ScanResult, error)
	// Spectrum is the band's spectrum runner (quick-scan, spectrum-scan).
	Spectrum(ctx context.Context, band string) (*wl.SpectrumRunner, error)
	// WithoutScan runs fn while no scan runs (the health check reads `wl`
	// state a scan aliases, spectrum-design §8.7); it waits for a running
	// scan or for ctx.
	WithoutScan(ctx context.Context, fn func(context.Context) error) error
	Invalidate()
}

// sysManager is what the agent uses of *decosys.Manager.
type sysManager interface {
	Enforce(ctx context.Context) (decosys.Report, error)
	Egress(ctx context.Context, on bool) error
	// Ingress is the inbound fence UDECO-IN (R5): installed in R1 phase 1,
	// before the unit is read, and re-asserted every gate check and tick.
	Ingress(ctx context.Context, on bool) error
	Restore(ctx context.Context) error
	// RestoreLoopGuard puts back the Ethernet ports an earlier takeover
	// run's loop guard took out of br-lan (Options.LoopGuardFile), and
	// nothing else (observe-mode start).
	RestoreLoopGuard(ctx context.Context) error
	// SetLAN hands over what the readings tell (gateway, subnet, lease):
	// unknown in phase 1, and the lease may change.
	SetLAN(l decosys.LAN) bool
	// Counts is the self-check's foreign-state tally (R10).
	Counts() map[string]int
	// FlushFlows is R21 for the agent's own datapath changes (loop guard).
	FlushFlows(ctx context.Context, s decosys.FlowScope) error
}

// wifiApplier is what the agent uses of *bcmwifi.Applier.
type wifiApplier interface {
	Plan(ctx context.Context, d bcmwifi.Desired) (bcmwifi.Plan, error)
	Apply(ctx context.Context, p bcmwifi.Plan) error
	Verify(ctx context.Context, d bcmwifi.Desired) error
	Rollback(ctx context.Context) error
	Kick(ctx context.Context, mac string) error
	SetBlocked(ctx context.Context, macs []string) error
	LED(ctx context.Context, mode string) error
	ForgetFailed()
	// Tick repairs drift that needs no hostapd restart (driver MAC
	// filters, WDS peers, bridge membership, guest chains, rate limits).
	Tick(ctx context.Context) (bcmwifi.TickReport, error)
	// AuthorizeGuest / UnauthorizeGuest: the controller's authorize-guest
	// and unauthorize-guest (and the agent's expiry of them).
	AuthorizeGuest(ctx context.Context, mac string) error
	UnauthorizeGuest(ctx context.Context, mac string) error
	// SetUplink: the wired port VLAN devices hang off moved (R9).
	SetUplink(port string)
}

// steerer is bcmwifi's 802.11v BSS transition request (hostapd_cli
// bss_tm_req) to the station mac associated on vif, naming targetBSSID (one
// of the agent's own BSSes) as the only candidate. Optional: the BANDSTEER
// capability bit is claimed only when the Wi-Fi backend has it.
type steerer interface {
	SteerToBand(ctx context.Context, vif, mac, targetBSSID string) error
}

// The real packages satisfy what the agent uses of them.
var (
	_ sysManager  = (*decosys.Manager)(nil)
	_ wifiApplier = (*bcmwifi.Applier)(nil)
	_ steerer     = (*bcmwifi.Applier)(nil)
	_ collector   = (*wl.Collector)(nil)
	_ sysManager  = (*jiosys.Manager)(nil)
	_ wifiApplier = (*mtkwifi.Applier)(nil)
	_ collector   = (*mtkwifi.Collector)(nil)
)

type runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Locations (device paths; Root is prepended).
const (
	defaultRunDir = "/tmp/udeco" // ramfs: lock, PID file, start log, bcmwifi run files
	sessionSub    = "session"    // under the config's directory: state.json, system_cfg, keys (0700)
	wifiStateSub  = "state"      // under the config's directory: bcmwifi last-good
	eventsFile    = "events.log" // under the config's directory: rare-event ring (R13)
)

// timing holds the agent's waits; zero values take the defaults.
type timing struct {
	interval      time.Duration // inform interval until the controller sets one (10 s)
	minWait       time.Duration // floor of the inform interval (1 s)
	immediateWait time.Duration // after an "inform now" reply (500 ms)
	retryWait     time.Duration // no reading of the unit yet (5 s)
	enforceEvery  time.Duration // decosys.Enforce, egress, Wi-Fi health (60 s)
	jobTimeout    time.Duration // one Wi-Fi job, an apply with its rollback included (5 min)
	collectTO     time.Duration // one collection (20 s)
	scanTO        time.Duration // one band of a neighbour scan (60 s)
	spectrumTO    time.Duration // one spectrum band: airtime gate (60 s) + Budget (45 s) + margin (2 min)
	healthWait    time.Duration // the health check's wait for a running scan (150 s)
	gateEvery     time.Duration // boot gate re-check (5 s)
	fastEnforce   time.Duration // Enforce interval right after the gate opened (5 s)
	fastMin       time.Duration // fast Enforce lasts at least this long (3 min)
	resourceEvery time.Duration // R4 check (60 s)
	scheduleEvery time.Duration // WLAN schedule evaluation (60 s)
	lldpEvery     time.Duration // LLDP transmit interval (30 s)
	selfCheck     time.Duration // R10 self-check summary (5 min)
	informTO      time.Duration // one inform POST, connect to last byte (10 s)
	portsWatch    time.Duration // the LAN port monitor's pass (5 s; ports.go)
	clockFirst    time.Duration // first clock check after the start (30 s; clock.go)
	clockEvery    time.Duration // clock re-check (1 h)
	clockRetry    time.Duration // clock re-check after no time source answered (1 min)
	logPoll       time.Duration // remote syslog on jio-mtk: log file poll (1 s; logfollow.go)
	portsRetry    time.Duration // the longest inform wait while a port change waits for confirmation (15 s)
}

func (t *timing) fill() {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&t.interval, 10*time.Second)
	def(&t.minWait, time.Second)
	def(&t.immediateWait, 500*time.Millisecond)
	def(&t.retryWait, 5*time.Second)
	def(&t.enforceEvery, 60*time.Second)
	def(&t.jobTimeout, 5*time.Minute)
	def(&t.collectTO, 20*time.Second)
	def(&t.scanTO, 60*time.Second)
	def(&t.spectrumTO, 2*time.Minute)
	def(&t.healthWait, 150*time.Second)
	def(&t.gateEvery, 5*time.Second)
	def(&t.fastEnforce, 5*time.Second)
	def(&t.fastMin, 3*time.Minute)
	def(&t.resourceEvery, 60*time.Second)
	def(&t.scheduleEvery, 60*time.Second)
	def(&t.lldpEvery, 30*time.Second)
	def(&t.selfCheck, 5*time.Minute)
	def(&t.informTO, 10*time.Second)
	def(&t.portsWatch, 5*time.Second)
	def(&t.clockFirst, clockFirst)
	def(&t.clockEvery, clockEvery)
	def(&t.clockRetry, clockRetry)
	def(&t.logPoll, logPoll)
	def(&t.portsRetry, 15*time.Second)
}

// options are the agent's environment; tests replace the edges.
type options struct {
	root         string // filesystem root, "/" on the device
	base         string // device dir of the config (/tp_data/udeco)
	runDir       string // device run dir (/tmp/udeco)
	forceObserve string // non-empty: start in observe mode whatever the config says (why)
	run          runner
	col          collector
	newSys       func(decosys.Options) sysManager
	newWifi      func(bcmwifi.Options) wifiApplier
	post         postFunc // the inform POST; nil = the minimal HTTP/1.1 client (post.go)
	sshListen    string   // SSH-adopt bind host; "" = 0.0.0.0
	siteShell    string   // site SSH users' shell; "" = /bin/ash (sitessh.go)
	logf         func(string, ...any)
	t            timing
	now          func() time.Time // wall clock (WLAN schedules, events); nil = time.Now
	lldpOpen     lldp.Opener      // LLDP sockets; nil = AF_PACKET (Linux)
	noLLDP       bool             // run no LLDP agent at all
	spectrumPlan *wl.ScanPlan     // spectrum runner plan; nil = wl.DefaultScanPlan (tests shorten it)
	pmProber     pathmon.Prober   // path monitoring probes; nil = ICMP echo (pathmon.go)
	// logFollow streams the unit's log for remote syslog; nil = logread -f (syslogfwd.go)
	logFollow func(context.Context) (io.ReadCloser, error)
	// snmpListen opens the SNMP agent's socket; nil = UDP 0.0.0.0:161 (snmp.go)
	snmpListen func(context.Context) (net.PacketConn, error)
	// ftOpen opens the FT-SAE peer announcement sockets; nil = AF_PACKET (ftsae.go)
	ftOpen ftpeer.Opener
	// sntp asks an NTP server for the clock offset; nil = sntpOffset (clock.go)
	sntp func(ctx context.Context, server string, now func() time.Time) (time.Duration, error)
	// setClock steps the system clock; nil = settimeofday (clock.go)
	setClock func(time.Time) error
}

type agent struct {
	cfg *Config
	o   options
	t   timing

	profile   inform.Profile
	radioCaps map[string]apstate.RadioCaps

	x                              *device.Session
	sessDir, statePath, sysCfgPath string
	sa                             *device.SSHAdopt
	adopt                          chan device.AdoptRequest

	takeover atomic.Bool // current mode: false = observe
	shed     atomic.Bool // R4: memory is short, no scans and no steering
	events   *eventLog
	alive    aliveState                 // the alive record on flash (alive.go)
	acks     chan string                // cfgversions whose configuration is live (any goroutine -> loop)
	creds    atomic.Pointer[sshCreds]   // what ssh-adopt checks once adopted
	site     siteSSH                    // site SSH logins on sshd_port (sitessh.go)
	policy   atomic.Pointer[wifiPolicy] // the live Wi-Fi's steering settings (worker -> loop)
	cfgs     cfgTrack
	topo     *topology
	steer    steerState // loop goroutine only
	roam     roamState  // loop goroutine only (roaming.go)
	lldp     *lldp.Service
	res      atomic.Pointer[resources] // the last R4 reading (self-check)
	pm       *pathmonState             // path monitoring (pathmon.go)
	sl       *syslogState              // remote syslog (syslogfwd.go)
	snmp     *snmpState                // SNMP agent (snmp.go)
	ftp      *ftPeerState              // FT-SAE peer discovery (ftsae.go)
	ports    portState                 // LAN ports (ports.go)

	// loop goroutine only
	prev       *apstate.Snapshot
	ctr        *apstate.Counters // monotonic inform counters (counters.go)
	ctrSaved   time.Time
	ctrErr     string
	collectErr string
	// modelHeld: the model the controller holds for this unit when it is
	// not the config's (set at setup; adoptmodel.go)
	modelHeld  string
	infoKey    string
	info       apstate.CfgInfo
	infoPortal bool              // the saved system_cfg turns the guest portal on (redirector)
	cfgHash    [sha256.Size]byte // system_cfg last handed to provisioning
	rebootReq  bool

	// takeover only: sys from the start (the phase-1 fence), wifi from the
	// first reading
	sys    sysManager
	wifi   wifiApplier
	uplink string
	lan    decosys.LAN // loop goroutine: what sys was last told
	// lanRefused: loop goroutine: the gateway's/controller's address last
	// seen as br-lan's first address (not handed to sys; logged once)
	lanRefused string
	// loopReload: dropToObserve's Restore (worker) put the loop guard's
	// ports back; the loop goroutine reloads topo.removed from the record
	loopReload atomic.Bool
	// scanHold (worker -> scans): the TP-Link upgrade or Wi-Fi rebuild in
	// flight at the last tick ("" none); wifiBusy: an apply or rollback
	// runs. Either one stops the spectrum and neighbour scans (scanBlock).
	scanHold atomic.Value
	wifiBusy atomic.Bool

	scans  *scanner
	sta    staEvents     // station events for the controller (staevents.go); loop goroutine
	mcast  *mcastInspect // multicast inspection (mcinspect.go); loop goroutine only
	mdns   *mdnsState    // mDNS service bridge (mdnsbr.go); loop goroutine only
	wake   chan struct{}
	jobs   chan job
	bg     sync.WaitGroup
	worker workerState // Wi-Fi worker goroutine only
	rs     radsecState // RadSec proxy (radsec.go); Wi-Fi worker goroutine only

	// rateSeen: the limited clients (State.ClientRates) associated at the
	// last reading (ratelimit.go); loop goroutine
	rateSeen map[string]bool
	// rateNoted: the not-supported note for rate-update was logged
	rateNoted bool
	// selfLog hands the agent's own log lines to remote syslog (platform
	// jio-mtk, logfollow.go)
	selfLog logTap
	// ctlClock is the clock offset the last inform reply showed (clock.go)
	ctlClock atomic.Pointer[clockSample]
	// specNoted: per band, the last restore hold or error logged
	// (specsave.go); loop goroutine
	specNoted map[string]string
}

func newAgent(cfg *Config, o options) (*agent, error) {
	if o.root == "" {
		o.root = "/"
	}
	if o.runDir == "" {
		o.runDir = defaultRunDir
	}
	if o.logf == nil {
		o.logf = func(string, ...any) {}
	}
	if o.run == nil {
		o.run = execRunner{timeout: 30 * time.Second}
	}
	if cfg.jio() {
		// JioFiber JCOW414: MediaTek driver, Jio services kept down, no
		// firewall of the agent's own
		if o.col == nil {
			o.col = mtkwifi.NewCollector(mtkwifi.CollectorOptions{Root: o.root, Run: o.run, Model: "JCOW414",
				FreshScan: cfg.SiteSurvey})
		}
		if cfg.SiteSurvey {
			o.logf("site_survey: on: the controller's scan, spectrum-scan and quick-scan commands run a driver site survey (the radio leaves its channel for a few seconds); never periodic")
		}
		if o.newSys == nil {
			o.newSys = func(so decosys.Options) sysManager {
				return jiosys.New(jiosys.Options{Root: so.Root, Logf: so.Logf, KeepOnly: jiosys.DefaultKeepOnly})
			}
		}
		if o.newWifi == nil {
			o.newWifi = func(bo bcmwifi.Options) wifiApplier {
				return mtkwifi.New(mtkwifi.Options{Root: bo.Root, Run: bo.Run, StateDir: bo.StateDir, RunDir: bo.RunDir,
					Uplink: bo.Uplink, DryRun: bo.DryRun, WPA3: bo.WPA3, Logf: bo.Logf})
			}
		}
	}
	if cfg.SiteSurvey && !cfg.jio() {
		o.logf("site_survey: ignored: it is for platform %s (the Deco scans with wl)", PlatformJio)
	}
	if o.col == nil {
		o.col = wl.New(wl.Options{Root: o.root, Run: o.run})
	}
	if o.newSys == nil {
		o.newSys = func(so decosys.Options) sysManager { return decosys.New(so) }
	}
	if o.newWifi == nil {
		o.newWifi = func(bo bcmwifi.Options) wifiApplier { return bcmwifi.New(bo) }
	}
	o.t.fill()
	if o.post == nil {
		o.post = httpPoster(o.t.informTO)
	}
	if o.now == nil {
		o.now = time.Now
	}
	a := &agent{cfg: cfg, o: o, t: o.t, scans: newScanner(), wake: make(chan struct{}, 1),
		jobs: make(chan job, 32), adopt: make(chan device.AdoptRequest, 4), acks: make(chan string, 8)}
	a.events = &eventLog{path: a.dev(filepath.Join(o.base, eventsFile)), root: o.root, clock: o.now, logf: a.logf}
	a.topo = newTopology()
	// ports an earlier run took out of br-lan (loop guard; ramfs record)
	a.topo.removed = loadLoopGuard(a.loopFilePath())
	for p, why := range a.topo.removed {
		o.logf("loop guard: %s is out of br-lan since an earlier run (%s evidence)", p, why)
	}
	a.takeover.Store(cfg.Takeover && o.forceObserve == "")
	a.loadCounters()

	a.sessDir = a.dev(filepath.Join(o.base, sessionSub))
	if err := os.MkdirAll(a.sessDir, 0o700); err != nil {
		return nil, err
	}
	os.Chmod(a.sessDir, 0o700)
	a.statePath = filepath.Join(a.sessDir, "state.json")
	a.sysCfgPath = filepath.Join(a.sessDir, "system_cfg.txt")
	// the session directory is on flash (ubifs, mounted sync): keep few
	// system_cfg versions
	device.HistoryKeep = 5
	return a, nil
}

// dev maps a device path onto the filesystem root.
func (a *agent) dev(p string) string { return filepath.Join(a.o.root, p) }

func (a *agent) logf(f string, args ...any) {
	a.o.logf(f, args...)
	a.selfLog.send(time.Now(), f, args...) // remote syslog on platform jio-mtk (logfollow.go)
}

func (a *agent) mode() string {
	if a.takeover.Load() {
		return "takeover"
	}
	return "observe"
}

// run is the agent until ctx ends (SIGTERM): informs stop, the Wi-Fi
// worker finishes the job it is in, and the unit's Wi-Fi is left as it is
// (tc limits and the flow cache state included: flowcache.go).
//
// Order: phase 1 (takeover only: the inbound fence, nothing else), the
// boot gate (R1/R2: no inform, no Enforce, no apply until TP-Link's boot
// has finished; the fence is re-asserted meanwhile), the first reading,
// then informing and the worker (decosys.Enforce first, then bcmwifi).
func (a *agent) run(parent context.Context) error {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	a.checkReboot()
	a.markAlive("running", false, "")
	aliveDone := make(chan struct{})
	go func() { defer close(aliveDone); a.aliveLoop(ctx) }()
	defer func() { cancel(nil); <-aliveDone; a.markAlive("stopped", false, "") }()
	if a.o.forceObserve != "" && a.cfg.Takeover {
		a.event(fmt.Sprintf("OBSERVE MODE FORCED (%s): takeover is configured but nothing on the unit changes until %s is removed",
			a.o.forceObserve, filepath.Join(a.o.base, observeMarker)))
	}
	if a.takeover.Load() {
		a.phase1(ctx)
	}
	if err := a.waitGate(ctx); err != nil {
		return err
	}
	if !a.takeover.Load() {
		a.observeLoopGuardRestore(ctx)
		a.observeFlowCacheRestore(ctx)
	}
	s, err := a.firstReading(ctx)
	if err != nil {
		return err
	}
	if err := a.setup(ctx, s); err != nil {
		return err
	}
	defer a.x.Unhandled.Flush()
	if err := a.startSSH(); err != nil {
		return err
	}
	defer a.sa.Close()
	a.bg.Add(1)
	go func() { defer a.bg.Done(); a.resourceLoop(ctx, cancel) }()
	a.startLLDP(ctx, s)
	a.startPathmon(ctx)
	a.startFTPeers(ctx)
	a.startClock(ctx)
	if a.takeover.Load() {
		a.bg.Add(1)
		go func() { defer a.bg.Done(); a.workerLoop(ctx) }()
		if a.ports.mgr != nil {
			a.bg.Add(1)
			go func() { defer a.bg.Done(); a.portsWatchLoop(ctx) }() // ports.go
		}
		a.startHomeListen(ctx)
		a.startupJobs()
	} else if a.x.S.Adopted {
		a.provisionIfNew("startup")
	}
	a.loop(ctx)
	a.mdnsShutdown() // the vifs get their native mDNS back (mdnsbr.go)
	a.bg.Wait()
	a.logf("udeco-ap: stopped (Wi-Fi left as it is)")
	if c := context.Cause(ctx); errors.Is(c, errResources) {
		return c
	}
	return parent.Err()
}

// phase1 builds decosys and installs the inbound fence (R5) before the
// gate opens; nothing else changes in phase 1. The unit has not been read
// yet, so decosys knows no LAN: the fence drops TP-Link's management ports
// and fences sshd_port to console_ip, but adds no :22 rule (SSH :22 stays
// as TP-Link has it) until setup hands over the LAN (decosys.SetLAN).
func (a *agent) phase1(ctx context.Context) {
	a.sys = a.o.newSys(decosys.Options{Root: a.o.root, Run: a.o.run, ControllerIP: a.cfg.controllerIP(),
		ConsoleIP: a.cfg.ConsoleIP, SSHDPort: a.cfg.SSHDPort, MgmtSources: a.cfg.MgmtSources, Logf: a.logf,
		LoopGuardFile: a.loopGuardDevPath()})
	if err := a.sys.Ingress(ctx, true); err != nil {
		a.logf("phase 1: inbound fence: %v (re-tried at every gate check and tick)", err)
		return
	}
	if a.cfg.jio() {
		a.logf("phase 1: no inbound fence on platform %s (telnet and the web UI stay as they are)", a.cfg.Platform)
		return
	}
	a.logf("phase 1: inbound fence %s installed (TP-Link's :20001-20003/:80/:443 dropped, :%d only from %s)",
		decosys.IngressChain, a.cfg.SSHDPort, a.cfg.ConsoleIP)
}

// event logs a rare event and keeps it in the event ring on flash (R13).
func (a *agent) event(msg string) { a.events.add(msg) }

// firstReading collects until the unit can be read: nothing is informed
// before (a guessed radio set would stick in the controller for good).
func (a *agent) firstReading(ctx context.Context) (*apstate.Snapshot, error) {
	for {
		s, err := a.collect(ctx)
		if err == nil && s.MAC != "" {
			return s, nil
		}
		if err == nil {
			err = errors.New("no br-lan MAC")
		}
		if err.Error() != a.collectErr {
			a.logf("reading the unit: %v (retrying every %s; not informing yet)", err, a.t.retryWait)
			a.collectErr = err.Error()
		}
		t := time.NewTimer(a.t.retryWait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

func (a *agent) collect(ctx context.Context) (*apstate.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, a.t.collectTO)
	defer cancel()
	return a.o.col.Collect(ctx)
}

// setup builds the session (identity from the first reading) and, in
// takeover mode, the decosys and bcmwifi handles.
func (a *agent) setup(ctx context.Context, s *apstate.Snapshot) error {
	m, ok := models.Lookup(a.cfg.Model)
	if !ok {
		return fmt.Errorf("model %s not in the catalogue", a.cfg.Model)
	}
	var heAX map[string]bool
	if c, err := a.o.col.Caps(ctx); err == nil {
		heAX = map[string]bool{}
		for band, b := range c.Bands {
			heAX[band] = b.HE
		}
	} else {
		a.logf("hardware caps: %v (assuming 802.11ax on both radios)", err)
	}
	// the Wi-Fi handles first: whether bcmwifi can steer decides a
	// capability bit
	a.uplink = detectUplink(s)
	if a.cfg.jio() {
		a.uplink = jioports.Untagged(jioports.UplinkPhys) // wired WAN socket (topology.go)
	}
	a.topo.uplink = a.uplink
	a.topo.uplinkName.Store(a.uplink)
	if a.takeover.Load() {
		a.setLAN(s)
		// Caps: bcmwifi.Plan checks each channel and width against the
		// driver's own list (wl chanspecs) and clamps what it does not
		// allow, so no apply is made only to be rolled back. The collector
		// caches the caps; Invalidate after every Apply/Rollback re-reads
		// them (the country may have changed).
		a.wifi = a.o.newWifi(bcmwifi.Options{Root: a.o.root, Run: a.o.run,
			StateDir: filepath.Join(a.o.base, wifiStateSub), RunDir: a.o.runDir,
			Uplink: a.uplink, DryRun: !a.cfg.Apply, Logf: a.logf, Caps: a.o.col.Caps,
			MinRates: a.cfg.MinRates, WPA3: a.cfg.WPA3, FTSAE: a.cfg.ftSAE()})
		if a.uplink == "" {
			a.logf("uplink port: not found from the gateway's FDB entry (bcmwifi picks the only br-lan port with carrier)")
		}
		a.followRestarts()
		a.watchChanges() // routine ticks' changes in the alive record (alive.go)
	}
	st, found, err := device.Load(a.statePath)
	if err != nil {
		return fmt.Errorf("state %s: %w", a.statePath, err)
	}
	stChanged := a.checkAdoptedModel(&st) // the model UniFi holds (adoptmodel.go)
	portVLAN := a.portsSetup()            // LAN ports (jio-mtk as UHDIW: ports.go)
	_, canSteer := a.wifi.(steerer)
	_, canRoam := a.wifi.(roamer)
	ft, canFTSAE := a.wifi.(ftSAEServer)
	canFTSAE = canFTSAE && ft.ServesFTSAE()
	// The takeover features (RF_SCAN, minimum rates, PPSK, Lock to AP,
	// Roaming Assistant, RADIUS filter, multicast inspect, RadSec, mDNS
	// bridge, Hotspot 2.0) need the agent to own Wi-Fi: observe mode
	// claims none of them, and a drop to observe clears them (fields).
	own := a.takeover.Load()
	// hostapd/wl features (PPSK, RADIUS filter, multicast inspect, RadSec)
	// exist on the Deco only
	deco := own && !a.cfg.jio()
	// RF_SCAN: wl scans on the Deco; a collector that says whether it can
	// scan (jio-mtk: only with fresh site surveys enabled) decides itself
	rfScan := deco
	if sc, ok := a.o.col.(interface{ ScanSupported() bool }); ok {
		rfScan = own && sc.ScanSupported()
	}
	p, ok := models.DecoAgentProfileWith(m, heAX, models.DecoAgentFeatures{BandSteer: canSteer, RFScan: rfScan,
		MinRate: own && a.cfg.MinRates, PPSK: deco, LockAP: own, RoamAssist: own && canRoam,
		RadiusFilter: deco, MulticastInspect: deco, WPA3: own && a.cfg.WPA3, WPA3FT: own && a.cfg.WPA3 && canFTSAE,
		RadSec: deco, MdnsBridge: own && a.cfg.Apply && a.cfg.MdnsBridge, Hotspot2: own && a.cfg.Hotspot2,
		PortVLAN: own && portVLAN})
	if !ok {
		return fmt.Errorf("model %s has no agent capability words", a.cfg.Model)
	}
	if rfScan {
		// the last good spectrum tables from before the restart, restored
		// by the next informs (specsave.go; jio-mtk: with site_survey)
		a.loadSpectrum()
	}
	a.profile = p
	a.radioCaps = map[string]apstate.RadioCaps{}
	var radios []inform.Radio
	for i, band := range []string{"ng", "na"} {
		rp, ok := p.Radios[band]
		if !ok {
			continue
		}
		a.radioCaps[band] = apstate.RadioCaps{IEEEModes: rp.IEEEModes, RadioCaps: rp.RadioCaps,
			RadioCaps2: rp.RadioCaps2, HasDFS: rp.HasDFS, HasFCCDFS: rp.HasFCCDFS}
		radios = append(radios, inform.Radio{Name: fmt.Sprintf("wifi%d", i), Radio: band, Channel: "auto",
			MinTxpower: rp.MinTx, MaxTxpower: rp.MaxTx, NSS: rp.NSS, BuiltinAnt: true})
	}

	mac, err := net.ParseMAC(s.MAC)
	if err != nil || len(mac) != 6 {
		return fmt.Errorf("br-lan MAC %q: %v", s.MAC, err)
	}
	if !found {
		st = device.NewState(a.cfg.InformURL)
		st.Version = p.Version
	}
	a.x = &device.Session{
		S: st, Boot: time.Now().Add(-time.Duration(s.Uptime) * time.Second), StateDir: a.sessDir,
		SSHPort: a.cfg.SSHDPort, WifiCaps: int(p.WifiCaps), WifiCaps2: int(p.WifiCaps2),
		FWCaps: int(p.FWCaps), FW2Caps: int(p.FW2Caps), FW3Caps: int(p.FW3Caps),
		Dev: inform.Device{MAC: mac, IP: s.IP, Netmask: s.Netmask, Gateway: s.Gateway, Hostname: s.Hostname,
			Model: p.Model, ModelDisplay: p.Display, Radios: radios},
	}
	a.x.Unhandled, a.x.KnownSection = device.OpenLedger(filepath.Join(a.sessDir, "unhandled.json")), translate.Handled
	// radio names: ra0/rai0, or wifi0/wifi1 kept for an earlier adoption
	// (radionames.go)
	if chooseRadioNames(&a.x.S, found) {
		if err := a.x.S.Save(a.statePath); err != nil {
			return err
		}
	}
	a.renameRadios()
	a.logRadioNames()
	if stChanged {
		if err := a.x.S.Save(a.statePath); err != nil {
			return err
		}
	}
	a.logModelHeld()
	if a.x.S.HashID == "" {
		if a.x.S.HashID, err = device.NewHashID(); err != nil {
			return err
		}
		if err := a.x.S.Save(a.statePath); err != nil {
			return err
		}
	}
	a.x.RestoreFromMgmtCfg()
	// cfgversion is acknowledged only once its configuration is live
	// (cfgack.go), so a failed apply makes the controller provision again
	a.x.DeferCfgAck = true
	a.refreshCreds()
	a.logf("udeco-ap: %s mode, model %s %s, mac %s ip %s, uplink %q, apply=%v egress=%v, adopted=%v cfgversion=%s pending=%q (state %s), wifi_caps=%d fw_caps=%d wifi_caps2=%d fw3_caps=%d",
		a.mode(), p.Model, p.Version, s.MAC, s.IP, a.uplink, a.cfg.Apply, a.cfg.Egress, a.x.S.Adopted, a.x.S.CfgVersion,
		a.x.S.PendingCfgVersion, map[bool]string{true: "loaded", false: "new"}[found], p.WifiCaps, p.FWCaps, p.WifiCaps2, p.FW3Caps)
	if a.takeover.Load() && !a.cfg.Apply {
		a.logf("udeco-ap: apply=false: TP-Link services are stopped but Wi-Fi changes are only planned and logged")
	}
	a.prev = s
	return nil
}

// setLAN tells decosys the gateway, subnet and lease of a reading when they
// changed (loop goroutine, and setup before the loop starts). A reading
// without an address changes nothing: an empty lease would only narrow the
// address watch, and an empty subnet would drop the fence's :22 rule.
//
// Nor does a reading whose first br-lan address is the gateway's or the
// controller's own: that is TP-Link's lan default 192.168.0.1/22 coming
// back ahead of the lease (audit B5), never the unit's lease. Handed over as
// UnitIP, decosys's address watch (R8a) would keep that alias and delete
// the real lease. decosys keeps what it was told before, so the watch still
// removes the alias.
func (a *agent) setLAN(s *apstate.Snapshot) {
	l := decosys.LAN{GatewayIP: s.Gateway, LANCIDR: lanCIDR(s.IP, s.Netmask), UnitIP: s.IP}
	if a.sys == nil || l.LANCIDR == "" || l.GatewayIP == "" || l == a.lan {
		return
	}
	if l.UnitIP == l.GatewayIP || l.UnitIP == a.cfg.controllerIP() {
		if a.lanRefused != l.UnitIP {
			a.event(fmt.Sprintf("br-lan's first address %s is the gateway's or the controller's own (TP-Link's lan default, audit B5): not taken as the unit's lease", l.UnitIP))
			a.lanRefused = l.UnitIP
		}
		return
	}
	a.lanRefused = ""
	if a.lan.UnitIP != "" && a.lan.UnitIP != l.UnitIP {
		a.event(fmt.Sprintf("the unit's address changed from %s to %s (gateway %s)", a.lan.UnitIP, l.UnitIP, l.GatewayIP))
	}
	a.lan = l
	a.sys.SetLAN(l)
	a.siteLAN(l.LANCIDR)
}

// detectUplink is the wired port the gateway is behind (its br-lan FDB
// entry), the way apstate.Snapshot finds the uplink; "" when unknown.
func detectUplink(s *apstate.Snapshot) string {
	if s.UplinkName != "" {
		return s.UplinkName
	}
	if s.Gateway == "" {
		return ""
	}
	for mac, ip := range s.ARP {
		if ip != s.Gateway {
			continue
		}
		for _, e := range s.FDB {
			if !strings.EqualFold(e.MAC, mac) || e.Local {
				continue
			}
			for _, p := range s.Ports {
				if p.BridgePort == e.Port && p.BridgePort != 0 {
					return p.Name
				}
			}
		}
	}
	return ""
}

// lanCIDR is ip/netmask as a network, "" if either is missing.
func lanCIDR(ip, mask string) string {
	i, m := net.ParseIP(ip).To4(), net.ParseIP(mask).To4()
	if i == nil || m == nil {
		return ""
	}
	n := net.IPNet{IP: i.Mask(net.IPMask(m)), Mask: net.IPMask(m)}
	return n.String()
}

// startSSH opens the adoption responder: only console_ip may connect; the
// unit's own dropbear on port 22 is never touched.
func (a *agent) startSSH() error {
	host := a.o.sshListen
	if host == "" {
		host = "0.0.0.0"
	}
	a.sa = &device.SSHAdopt{
		Listen:    net.JoinHostPort(host, strconv.Itoa(a.cfg.SSHDPort)),
		AllowFrom: []string{a.cfg.ConsoleIP},
		HostKey:   filepath.Join(a.sessDir, "ssh_host_ed25519.pem"),
		Requests:  a.adopt,
		Auth:      a.sshAuth,
		Site:      a.siteSSHOptions(),
	}
	if err := a.sa.Start(); err != nil {
		return fmt.Errorf("ssh-adopt on %s: %w", a.sa.Listen, err)
	}
	a.siteApply() // site users' logins as the saved system_cfg has them (sitessh.go)
	a.logf("ssh-adopt listening on %s (only from %s; once adopted only with the site's device credential)", a.sa.Listen, a.cfg.ConsoleIP)
	return nil
}

// loop informs until ctx ends.
func (a *agent) loop(ctx context.Context) {
	defer func() { a.saveCounters(time.Now(), true) }()
	interval := a.t.interval
	errs := 0
	for {
		next, good := a.informOnce(ctx)
		// a band's EVT_AP_QuickScanEvent follows the inform that carried
		// its table at once (scan.go)
		evDue, evSent := a.scans.informed(good)
		for _, s := range evSent {
			a.logf("spectrum: EVT_AP_QuickScanEvent sent (%s)", s)
		}
		staSent, staMore := a.sta.informed(good)
		if staSent != nil {
			a.logf("client event: %v %v on %v", staSent["event_type"], staSent["mac"], staSent["vap"])
		}
		if a.sta.dropped > 0 {
			a.logf("client events: %d dropped (more than %d waiting)", a.sta.dropped, staQueueMax)
			a.sta.dropped = 0
		}
		for _, act := range next.Actions {
			a.action(ctx, act)
		}
		if next.Reset {
			a.logf("setdefault: removed from the controller; informing as a new device, the unit's Wi-Fi is left as it is")
			a.radioNamesAfterReset()
			a.modelAfterReset()
		}
		// adoption state changed (a reply adopted or reset the unit): the
		// SSH credential check follows it (R12)
		if c := a.creds.Load(); next.Reset || c == nil || c.adopted != a.x.S.Adopted {
			a.refreshCreds()
		}
		a.onReply(next)
		a.expireGuests(time.Now())
		if a.rebootReq {
			a.reboot(ctx)
		}
		if good {
			errs = 0
		} else {
			errs++
		}
		if next.Interval > 0 {
			interval = max(next.Interval, a.t.minWait)
		}
		wait := interval
		if next.Immediate {
			wait = a.t.immediateWait
		}
		if good && (evDue || staMore && a.x.S.Adopted) {
			wait = min(wait, a.t.immediateWait)
		}
		if errs > 0 {
			// like a real AP: keep informing, further and further apart
			wait = min(max(interval, 5*time.Second)*time.Duration(1<<min(errs-1, 4)), time.Minute)
		}
		// a port change waits for an answered inform (ports.go): no
		// backing off past portsRetry until it has one
		if d := a.portsRetry(); d > 0 {
			wait = min(wait, d)
		}
		if errs > 0 && (errs == 1 || errs%10 == 0) {
			a.logf("%d bad answer(s) in a row: next inform in %s", errs, wait)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case req := <-a.adopt:
			t.Stop()
			o := a.x.ApplyAdopt(req)
			for _, e := range o.Events {
				a.logf("%s", e)
			}
			if err := a.x.S.Save(a.statePath); err != nil {
				a.logf("saving state: %v", err)
			}
			a.refreshCreds()
			select { // let the console finish its SSH job first
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		case <-a.wake:
			t.Stop()
		case <-t.C:
		}
	}
}

// fields reads the unit and returns the inform fields (the last reading
// when this one fails).
func (a *agent) fields(ctx context.Context) map[string]any {
	s, err := a.collect(ctx)
	if err != nil {
		if err.Error() != a.collectErr {
			a.logf("reading the unit: %v (reporting the last reading)", err)
			a.collectErr = err.Error()
		}
		s = a.prev
	} else if a.collectErr != "" {
		a.logf("reading the unit works again")
		a.collectErr = ""
	}
	c := *s
	if c.IP != "" {
		a.x.Dev.IP, a.x.Dev.Netmask = c.IP, c.Netmask
	}
	if c.Gateway != "" {
		a.x.Dev.Gateway = c.Gateway
	}
	info := a.cfgInfo()
	if len(info.GuestVAP) > 0 {
		info.Authorized = a.guestAuthorized(&c, time.Now()) // a copy: a.info stays as read
	}
	a.ctr.Begin(c.Uptime)
	f := c.FieldsWith(a.prev, info, a.radioCaps, a.ctr)
	// Uptime runs from the session's boot time, which is the unit's boot
	// until the controller's upgrade or (observe-mode) restart is faked.
	if up := int64(time.Since(a.x.Boot).Seconds()); up >= 0 && up < c.Uptime {
		f["uptime"] = up
		if ss, ok := f["system-stats"].(map[string]any); ok {
			ss["uptime"] = strconv.FormatInt(up, 10)
		}
	}
	if c.Hostname != "" {
		f["hostname"] = c.Hostname
	}
	if a.takeover.Load() && err == nil {
		a.setLAN(&c)
	}
	if a.loopReload.Swap(false) {
		// what Restore could not put back stays in the record
		a.topo.removed = loadLoopGuard(a.loopFilePath())
	}
	a.observeReading(&c, f)
	a.monoIfTable(f) // after topology's if_table (counters.go)
	a.saveCounters(time.Now(), false)
	a.pathmonFields(f, &c)
	a.syslogFollow(ctx)
	if !a.takeover.Load() {
		// dropped to observe mode: TP-Link's hostapd serves Wi-Fi again and
		// the agent runs no scans, so nothing that needs Wi-Fi ownership
		// is claimed from the next inform on (RF_SCAN, minimum rates,
		// PPSK, Lock to AP, Roaming Assistant, RADIUS filter, multicast
		// inspect, Hotspot 2.0, RadSec, mDNS bridge)
		a.x.WifiCaps &^= models.DecoAgentTakeoverWifiCaps
		a.x.WifiCaps2 &^= models.DecoAgentTakeoverWifiCaps2
		a.x.FWCaps &^= models.DecoAgentTakeoverFWCaps
		a.x.FW2Caps &^= models.DecoAgentTakeoverFW2Caps
		a.x.FW3Caps &^= models.DecoAgentTakeoverFW3Caps
		for b, rc := range a.radioCaps { // SAE (wpa3) is served by bcmwifi only
			rc.RadioCaps2 &^= models.RadioCap2WPA3 | models.RadioCap2WPA3FT
			a.radioCaps[b] = rc
		}
	}
	if a.takeover.Load() {
		// saved tables, once plausible (specsave.go; nothing is loaded
		// without RF_SCAN: jio-mtk without site_survey)
		a.restoreSpectrum(ctx, a.o.now())
	}
	a.scans.merge(f, &c, info, time.Now())
	// a queued station event rides this inform; the changes this reading
	// shows are queued for the next ones (staevents.go)
	if a.x.S.Adopted {
		a.sta.attach(f)
	}
	a.sta.observe(f)
	a.rateJoins(f)
	a.mcastMerge(ctx, f, &c, info, time.Now())
	a.mdnsReconcile(ctx, &c, info)
	a.snmpFollow(ctx, f, &c)
	a.prev = &c
	return f
}

// cfgInfo is the saved system_cfg's VAP names and WLAN ids, re-read when
// the controller sent a new one.
func (a *agent) cfgInfo() apstate.CfgInfo {
	key := a.x.WantedCfgVersion() + "/" + strconv.Itoa(a.x.S.SystemCfgN)
	if key != a.infoKey {
		b, _ := os.ReadFile(a.sysCfgPath)
		a.info, a.infoKey = apstate.InfoFromCfg(string(b)), key
		a.infoPortal = translate.GuestPolicy(translate.ParseCfg(string(b))).Portal
	}
	info := a.info
	info.RadioNames = radioNameMap(a.x.S.RadioNames) // radionames.go
	return info
}

// guestAuthorized is CfgInfo.Authorized for a reading: the portal state of
// the guests (sta_table authorized, docs/internals.md). With the portal on,
// the guests the controller authorised (authorize-guest) and whose time has
// not run out; with no portal, every station (nothing holds a guest back).
func (a *agent) guestAuthorized(s *apstate.Snapshot, now time.Time) map[string]bool {
	m := map[string]bool{}
	if !a.infoPortal {
		for _, r := range s.Radios {
			for _, v := range r.VAPs {
				for _, st := range v.Stations {
					m[strings.ToLower(st.MAC)] = true
				}
			}
		}
		return m
	}
	for _, mac := range a.authorizedGuests(now) {
		m[strings.ToLower(mac)] = true
	}
	return m
}

// informOnce sends one inform and handles the answer (cmd/udeco/runner.go
// informOnce). ok=false counts as a bad answer.
func (a *agent) informOnce(ctx context.Context) (device.Outcome, bool) {
	x := a.x
	start := a.o.now() // a port change finished before this is confirmed by its reply (ports.go)
	a.drainAcks()
	f := a.fields(ctx)
	x.Extra = func() map[string]any { return f }
	js, err := x.Payload(time.Now())
	if err != nil {
		a.logf("payload: %v", err)
		return device.Outcome{}, false
	}
	pkt, err := inform.Encode(x.Dev.MAC, x.S.Key, x.Cipher(), js, nil)
	if err != nil {
		a.logf("encode: %v", err)
		return device.Outcome{}, false
	}
	sent := time.Now()
	status, body, err := a.o.post(ctx, x.S.InformURL, pkt)
	answered := time.Now()
	if err != nil {
		if ctx.Err() == nil {
			a.logf("POST: %v", err)
		}
		return device.Outcome{}, false
	}
	switch status {
	case 200:
	case 404:
		if !x.S.Adopted {
			return device.Outcome{}, true // pending: normal
		}
		a.logf("HTTP 404 while adopted (forgotten?)")
		return device.Outcome{}, false
	default:
		a.logf("HTTP %d (%d bytes)", status, len(body))
		return device.Outcome{}, false
	}
	if len(body) == 0 {
		return device.Outcome{}, true
	}
	// Only the key this inform was encrypted with: the controller answers
	// with it. No fallback to the public factory key once adopted, or
	// anyone who can answer the plain-HTTP inform could send a set-adopt,
	// system_cfg or setdefault the unit would obey. inform.Decode also
	// takes an unencrypted frame (no key needed at all): refuse that too.
	hdr, plain, err := inform.Decode(body, x.S.Key)
	if err == nil && hdr.Flags&(inform.FlagEncrypted|inform.FlagGCM) == 0 {
		err = errors.New("unencrypted reply refused")
	}
	if err != nil {
		a.logf("reply did not decode: %v", err)
		return device.Outcome{}, false
	}
	a.noteControllerTime(plain, sent, answered) // clock.go
	o, err := x.Handle(plain, time.Now())
	if err != nil {
		a.logf("%v", err)
		return o, false
	}
	a.portsInformed(start)
	for _, e := range o.Events {
		if !strings.HasPrefix(e, "noop ") || o.Immediate {
			a.logf("%s", e)
		}
	}
	if o.Changed {
		if err := x.S.Save(a.statePath); err != nil {
			a.logf("saving state: %v", err)
		}
	}
	return o, true
}

// provisionIfNew hands the saved system_cfg to provisioning when it differs
// from the one handed last: in takeover mode to the Wi-Fi worker, in
// observe mode only to the log.
func (a *agent) provisionIfNew(why string) {
	b, err := os.ReadFile(a.sysCfgPath)
	if err != nil || len(b) == 0 {
		return
	}
	h := sha256.Sum256(b)
	if h == a.cfgHash {
		return
	}
	a.cfgHash = h
	a.refreshCreds()
	pv := a.newProvision(why, b, h)
	if !a.takeover.Load() {
		a.logIntent(pv)
		a.logf("observe mode: the controller's Wi-Fi plan above is logged only")
		a.cfgDone(pv, true)
		return
	}
	a.cfgs.set(h, cfgPending)
	a.submit("provision "+pv.hash, func(ctx context.Context) { a.provision(ctx, pv) })
}

// reboot restarts the unit (takeover mode only; the controller's restart).
// A reboot always returns the unit to stock TP-Link until the agent takes
// over again.
func (a *agent) reboot(ctx context.Context) {
	a.rebootReq = false
	if err := a.x.S.Save(a.statePath); err != nil {
		a.logf("saving state: %v", err)
	}
	a.x.Unhandled.Flush()
	a.event("RESTART requested by the controller: rebooting the unit")
	if _, err := a.o.run.Run(ctx, "reboot"); err != nil {
		a.logf("reboot: %v", err)
	}
}

// wakeLoop asks the loop to inform now.
func (a *agent) wakeLoop() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}
