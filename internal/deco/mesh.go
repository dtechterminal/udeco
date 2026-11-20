// SPDX-License-Identifier: GPL-2.0-or-later

package deco

// Mesh is the single owner of the TMP session to the mesh master
// (docs/deco/design.md §3). It runs TDP prechecks before every login, polls the
// master on its own goroutine and caches a MeshState, rate-limits logins
// (each costs one TP-Link password attempt), latches off after an auth
// failure, and executes queued write commands off the inform path.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// RedialFloor is the minimum time between two SSH logins (design §3.1.3).
	RedialFloor = 60 * time.Second
	// RedialCeiling caps the exponential login backoff.
	RedialCeiling = 15 * time.Minute
	// stableAfter: a session that lived this long resets the login backoff.
	stableAfter = 10 * time.Minute
	// disableAfter: an opcode failing this many times in a row with an
	// error_code other than 1010 is treated as unsupported for the session.
	disableAfter = 3
	// dropAfter: this many consecutive non-application errors (timeouts,
	// protocol errors) on a live stream drop the session.
	dropAfter = 3
	// hostKeyFile holds the TOFU fingerprint of the master in StateDir.
	hostKeyFile = "master_host_key"
	// MinClientsEvery is the floor of the 0x4012 interval. 0x4012 is a slow
	// enrichment (names, client_type, last placement): live it took 62 s and
	// returned only stored settings, and while it runs nothing else is polled.
	MinClientsEvery = 10 * time.Minute
	// DefaultPoll is how often the device list, client speeds (0x4014) and
	// IoT clients (0x4040) are read when the config does not say
	// (MeshConfig.Poll; "poll" in cmd/udeco's config).
	DefaultPoll = 15 * time.Second
	// The other reads' intervals when MeshConfig leaves them zero:
	// Wi-Fi info (0x4009), port status (0x4327) and the block list (0x4018).
	defaultWirelessEvery = 60 * time.Second
	defaultPortsEvery    = 5 * time.Minute
	defaultBlocksEvery   = 60 * time.Second
	// defaultCommandTimeout is how long a queued command waits for a session.
	defaultCommandTimeout = 5 * time.Minute
)

// pollComponent gates a poll on a NEGOTIATE component, as the app does:
// 0x4012 on client (c.U2(), c.java:1232-1234; l0.java:1362-1368), 0x4014 on
// client_speed (c.S2(), c.java:1142-1144; l0.java:389-391), 0x4040 on
// iot_client (c.d6(), c.java:1630-1632; b2.java:2167-2169).
var pollComponent = map[uint16]string{
	OpGetClientList:      "client",
	OpGetClientSpeedList: "client_speed",
	OpGetIoTClientList:   "iot_client",
}

// slowPolls are the Gets whose run may block every other poll for up to
// their budget; Fresh does not count that time against other lists.
var slowPolls = map[uint16]bool{OpGetClientList: true}

// BYE back-offs (design §3.1.4).
var byeDelay = map[byte]time.Duration{
	3: 10 * time.Minute, // CLIENT_LIMIT: the phone app may hold the session (INFERRED)
	7: 10 * time.Minute, // USER_COUNT_EXCEED
	4: 3 * time.Minute,  // SYSTEM_REBOOT
	6: 3 * time.Minute,  // SYSTEM_UPGRADE
}

// byeAuthChanged latches logins off: the TP-Link credentials changed.
const byeAuthChanged = 8

var (
	// ErrLatched: logins are off until the process restarts.
	ErrLatched = errors.New("deco mesh: logins latched off until restart")
	// ErrNotConnected: a queued command expired before a session came up.
	ErrNotConnected = errors.New("deco mesh: no session before the command expired")
	// ErrOwnerMismatch: device_list does not agree with the configured master.
	ErrOwnerMismatch = errors.New("deco mesh: device_list master disagrees with config; apply refused")
	// ErrRateLimited: a Wi-Fi Set was sent less than WLANMinInterval ago.
	ErrRateLimited = errors.New("deco mesh: Wi-Fi apply rate-limited")
	// ErrStopped: the mesh is shutting down.
	ErrStopped = errors.New("deco mesh: stopped")
)

// RefusedError is a definite TDP precheck violation: logging in would be
// wrong (not our mesh, not the owner, unsupported transport). Retrying does
// not help, so the Mesh latches off.
type RefusedError struct{ Reason string }

func (e *RefusedError) Error() string { return "deco mesh: refusing to log in: " + e.Reason }

// MeshConfig configures a Mesh. Durations left zero take the defaults.
type MeshConfig struct {
	MasterIP  string   // configured master unit IP
	MasterMAC string   // configured master MAC (mesh.master)
	UnitIPs   []string // every configured unit IP, for the TDP precheck
	TPLinkID  string   // exact stored TP-Link ID; md5 must equal the TDP owner hash
	Password  Secret   // TP-Link ID password; never logged
	// HostKeySHA256 pins the master's SSH host key ("SHA256:..."). Empty means
	// trust on first use, remembered in StateDir.
	HostKeySHA256 string
	StateDir      string
	// Apply gates every write. False (the default) logs the plan only.
	Apply bool

	Poll           time.Duration // device list, client speeds (0x4014), IoT clients (0x4040); default DefaultPoll
	ClientsEvery   time.Duration // 0x4012 enrichment; default and floor MinClientsEvery; < 0 turns it off
	WirelessEvery  time.Duration // 0x4009; default defaultWirelessEvery, and after every Set
	PortsEvery     time.Duration // 0x4327; default defaultPortsEvery
	BlocksEvery    time.Duration // 0x4018; default defaultBlocksEvery
	RedialMin      time.Duration // login backoff start; never below RedialFloor
	RedialMax      time.Duration // login backoff cap; default RedialCeiling
	Heartbeat      time.Duration // TMP heartbeat; default DefaultHeartbeat
	RequestTimeout time.Duration // per request; default DefaultRequestTimeout (0x4012: at least its AppRequestTimeout)
	// OpTimeouts overrides the request budget of single opcodes.
	OpTimeouts      map[uint16]time.Duration
	CommandTimeout  time.Duration // queued command lifetime; default defaultCommandTimeout
	WLANMinInterval time.Duration // minimum gap between Wi-Fi Sets; default the constant WLANMinInterval

	// MaxLogins > 0 caps the SSH logins of this Mesh's lifetime (-print: 1).
	// Once reached, a lost session stays down.
	MaxLogins int
	// Only, if non-empty, limits polling to these Gets, in this order (one of
	// OpGetDeviceList, OpGetClientList, OpGetClientSpeedList,
	// OpGetIoTClientList, OpGetWireless, OpGetDeviceEthPort, OpGetBlockList
	// each). 0x4327 needs device_list ids, so OpGetDeviceList is put first
	// when only the ports are asked for.
	Only []uint16
	// Once (-print) runs each Get until it has succeeded or been turned off
	// once, never again: a poll that answered is not re-read in the same run.
	Once bool
	// Trace, if set, receives per-frame, per-packet and per-request lines
	// (Client Config.Trace). Never payloads, tokens or credentials.
	Trace func(format string, args ...any)

	// Logf receives log lines; default log.Printf. Lines never carry the
	// password, the TP-Link ID or Wi-Fi passphrases.
	Logf func(format string, args ...any)
	// Discover probes one IP over TDP; default DiscoverDeco unicast with a 3 s timeout.
	Discover func(ctx context.Context, ip string) (*DecoInfo, error)
}

// Polled is one cached poll result. Value is replaced, never mutated, so
// a snapshot may share it; treat it as read-only.
type Polled[T any] struct {
	Value    *T        `json:"value,omitempty"`
	At       time.Time `json:"at"` // last successful poll
	OK       bool      `json:"ok"` // the last attempt succeeded
	Err      string    `json:"err,omitempty"`
	Disabled bool      `json:"disabled,omitempty"` // unsupported for this session
}

// Fresh reports whether p may be reported as current at now: it has a value,
// the opcode is not disabled for the session, the value was read during the
// session that is up (not carried over from before a reconnect), and it is
// at most maxAge old (maxAge <= 0: no age limit). A failed poll keeps the
// last Value, so Value != nil alone says nothing about its age. Time the
// Mesh spends blocked in a slow Get (0x4012, up to its budget) that started
// after p was read does not count: nothing could have been polled then.
// That holds while the slow Get runs (Busy) and after it has returned
// (LastSlow), until p is read again: otherwise every list read before it
// would turn stale the moment it returns, before the next pass re-reads them.
func Fresh[T any](s *MeshState, p *Polled[T], now time.Time, maxAge time.Duration) bool {
	switch {
	case s == nil || p == nil || p.Value == nil || p.Disabled:
		return false
	case s.Connected && p.At.Before(s.ConnectedSince):
		return false
	case maxAge <= 0:
		return true
	}
	age := now.Sub(p.At)
	if b := s.Busy; b != nil && slowPolls[b.Op] && !b.Since.Before(p.At) {
		age -= min(max(now.Sub(b.Since), 0), AppRequestTimeout(b.Op))
	}
	if l := s.LastSlow; l != nil && slowPolls[l.Op] && !l.Since.Before(p.At) && !l.End.After(now) {
		age -= min(max(l.End.Sub(l.Since), 0), AppRequestTimeout(l.Op))
	}
	return age <= maxAge
}

// SlowPoll is the last slow Get (slowPolls) that returned: when it was
// sent and when it returned, whatever the outcome.
type SlowPoll struct {
	Op    uint16    `json:"op"`
	Since time.Time `json:"since"`
	End   time.Time `json:"end"`
}

// BusyPoll is the Get the Mesh is waiting for.
type BusyPoll struct {
	Op    uint16    `json:"op"`
	Since time.Time `json:"since"`
}

// MeshState is the cached view of the mesh. Pointers in it are immutable.
type MeshState struct {
	Connected      bool               `json:"connected"`
	ConnectedSince time.Time          `json:"connected_since,omitzero"`
	DownSince      time.Time          `json:"down_since,omitzero"` // zero while connected
	LastError      string             `json:"last_error,omitempty"`
	Latched        string             `json:"latched,omitempty"` // non-empty: no more logins
	Logins         int                `json:"logins"`            // SSH logins attempted
	NextLoginAt    time.Time          `json:"next_login_at,omitzero"`
	LastBye        *ByeError          `json:"last_bye,omitempty"`
	LastHeartbeat  time.Time          `json:"last_heartbeat,omitzero"`
	Master         *DecoInfo          `json:"master,omitempty"` // TDP reply of the master
	OperationMode  string             `json:"operation_mode,omitempty"`
	Negotiation    *NegotiationResult `json:"negotiation,omitempty"`
	NegotiationErr string             `json:"negotiation_err,omitempty"`
	// Units holds the last TDP reply of every configured unit that answered,
	// keyed by NormMAC (per-unit channels for collect).
	Units map[string]*DecoInfo `json:"units,omitempty"`

	// Busy is the Get in flight, nil between requests.
	Busy *BusyPoll `json:"busy,omitempty"`
	// LastSlow is the last slow Get (0x4012) of the session that returned.
	LastSlow *SlowPoll `json:"last_slow,omitempty"`

	Devices  Polled[DeviceListResult]      `json:"devices"`
	Clients  Polled[ClientListResult]      `json:"clients"`  // 0x4012: settings + (if any) live state; slow enrichment
	Speeds   Polled[ClientSpeedListResult] `json:"speeds"`   // 0x4014: online clients' speeds (presence)
	IoT      Polled[IoTClientListResult]   `json:"iot"`      // 0x4040: smart-home devices with inet_status
	Wireless Polled[WirelessInfo]          `json:"wireless"` // carries PSKs: MaskWireless before printing
	Ports    Polled[DeviceEthPortResult]   `json:"ports"`
	Blocks   Polled[ClientBlockListResult] `json:"blocks"`
}

// PollInfo is the status of one polled Get in a MeshState.
type PollInfo struct {
	Ran, OK, Disabled bool
	Err               string
}

func pollInfo[T any](p *Polled[T]) PollInfo {
	return PollInfo{Ran: !p.At.IsZero() || p.Err != "" || p.Disabled, OK: p.OK, Disabled: p.Disabled, Err: p.Err}
}

// Poll reports the status of op's slot; false if op is not a polled Get.
func (s *MeshState) Poll(op uint16) (PollInfo, bool) {
	switch op {
	case OpGetDeviceList:
		return pollInfo(&s.Devices), true
	case OpGetClientList:
		return pollInfo(&s.Clients), true
	case OpGetClientSpeedList:
		return pollInfo(&s.Speeds), true
	case OpGetIoTClientList:
		return pollInfo(&s.IoT), true
	case OpGetWireless:
		return pollInfo(&s.Wireless), true
	case OpGetDeviceEthPort:
		return pollInfo(&s.Ports), true
	case OpGetBlockList:
		return pollInfo(&s.Blocks), true
	}
	return PollInfo{}, false
}

// setOff marks op's slot as turned off for the session.
func (s *MeshState) setOff(op uint16, msg string) {
	off := func(ok *bool, err *string, dis *bool) { *ok, *err, *dis = false, msg, true }
	switch op {
	case OpGetDeviceList:
		off(&s.Devices.OK, &s.Devices.Err, &s.Devices.Disabled)
	case OpGetClientList:
		off(&s.Clients.OK, &s.Clients.Err, &s.Clients.Disabled)
	case OpGetClientSpeedList:
		off(&s.Speeds.OK, &s.Speeds.Err, &s.Speeds.Disabled)
	case OpGetIoTClientList:
		off(&s.IoT.OK, &s.IoT.Err, &s.IoT.Disabled)
	case OpGetWireless:
		off(&s.Wireless.OK, &s.Wireless.Err, &s.Wireless.Disabled)
	case OpGetDeviceEthPort:
		off(&s.Ports.OK, &s.Ports.Err, &s.Ports.Disabled)
	case OpGetBlockList:
		off(&s.Blocks.OK, &s.Blocks.Err, &s.Blocks.Disabled)
	}
}

// DownFor is how long the session has been down at now (0 while connected).
func (s *MeshState) DownFor(now time.Time) time.Duration {
	if s.Connected || s.DownSince.IsZero() {
		return 0
	}
	return now.Sub(s.DownSince)
}

// CommandKind selects a queued write.
type CommandKind int

const (
	CmdReboot      CommandKind = iota + 1 // 0x4016 for one unit
	CmdBlock                              // 0x4017 block-list add
	CmdUnblock                            // 0x4019 block-list remove
	CmdSetWireless                        // 0x4008 partial Set
)

func (k CommandKind) String() string {
	switch k {
	case CmdReboot:
		return "reboot"
	case CmdBlock:
		return "block"
	case CmdUnblock:
		return "unblock"
	case CmdSetWireless:
		return "wifi-set"
	}
	return fmt.Sprintf("cmd(%d)", int(k))
}

// Command is one write for the master. Results arrive on the channel
// returned by Submit.
type Command struct {
	Kind CommandKind
	// Reboot: the unit, by DeviceID or by MAC (resolved from device_list).
	DeviceID string
	MAC      string
	// Block / Unblock: client MACs in any format; the device's own spelling
	// from the client or block list is echoed back (open question 8).
	MACs []string
	// SetWireless: a partial 0x4008 body from BuildHostSet or BuildGuestSet.
	Wireless *WirelessInfo
	// SkipRateLimit exempts a SetWireless from the WLANMinInterval limit.
	// The WLAN applier sets it for the guest Set that follows the host Set
	// of one apply and for rollbacks (design §8.4.5); it rate-limits applies
	// itself.
	SkipRateLimit bool
}

// CommandResult reports one command. With apply off, DryRun is true and
// nothing was sent.
type CommandResult struct {
	Kind   CommandKind
	Opcode uint16
	DryRun bool
	Plan   string          // request params as JSON, passwords masked
	Raw    json.RawMessage // device result, kept raw (open question 14)
	Err    error
}

type pending struct {
	cmd      Command
	deadline time.Time
	done     chan CommandResult
}

type pollItem struct {
	op    uint16
	every func(*MeshConfig) time.Duration
	last  time.Time
	force bool
	done  bool // Once: succeeded or turned off; never polled again
}

// Mesh owns the one TMP session to the master. Create with NewMesh, run
// with Run, read with Snapshot, write with Submit.
type Mesh struct {
	cfg MeshConfig
	now func() time.Time

	// Owned by the Run goroutine.
	client    *Client
	failures  int // consecutive failed logins / short sessions
	lastLogin time.Time
	nextLogin time.Time
	upSince   time.Time
	errStreak int
	appFails  map[uint16]int
	disabled  map[uint16]bool
	lastWLAN  time.Time
	polls     []*pollItem

	mu         sync.Mutex
	stopped    bool
	seenHostFP string // TOFU fingerprint seen during the handshake
	state      MeshState
	queue      []*pending
	pollReq    map[uint16]bool // RequestPoll: re-read these opcodes next step
	wake       chan struct{}
}

// NewMesh validates cfg and fills defaults. It does no I/O.
func NewMesh(cfg MeshConfig) (*Mesh, error) {
	if cfg.MasterIP == "" || cfg.TPLinkID == "" || cfg.Password == "" {
		return nil, errors.New("deco mesh: master ip, tplink_id and password are required")
	}
	if NormMAC(cfg.MasterMAC) == "" {
		return nil, fmt.Errorf("deco mesh: bad master mac %q", cfg.MasterMAC)
	}
	if !contains(cfg.UnitIPs, cfg.MasterIP) {
		cfg.UnitIPs = append([]string{cfg.MasterIP}, cfg.UnitIPs...)
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&cfg.Poll, DefaultPoll)
	if cfg.ClientsEvery >= 0 && cfg.ClientsEvery < MinClientsEvery {
		cfg.ClientsEvery = MinClientsEvery
	}
	def(&cfg.WirelessEvery, defaultWirelessEvery)
	def(&cfg.PortsEvery, defaultPortsEvery)
	def(&cfg.BlocksEvery, defaultBlocksEvery)
	def(&cfg.RedialMax, RedialCeiling)
	def(&cfg.Heartbeat, DefaultHeartbeat)
	def(&cfg.RequestTimeout, DefaultRequestTimeout)
	def(&cfg.CommandTimeout, defaultCommandTimeout)
	def(&cfg.WLANMinInterval, WLANMinInterval)
	if cfg.RedialMin < RedialFloor {
		cfg.RedialMin = RedialFloor
	}
	if cfg.RedialMax < cfg.RedialMin {
		cfg.RedialMax = cfg.RedialMin
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.Discover == nil {
		cfg.Discover = func(ctx context.Context, ip string) (*DecoInfo, error) {
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			out, err := DiscoverDeco(ctx, ip, false)
			if err != nil {
				return nil, err
			}
			if len(out) == 0 {
				return nil, errors.New("tdp: no reply")
			}
			return &out[0], nil
		}
	}
	base := func(c *MeshConfig) time.Duration { return c.Poll }
	// Device list first: ports, writes and the client view need it. The
	// slow 0x4012 enrichment goes last, so the lists the inform path needs
	// are read before it can block the session.
	polls := []*pollItem{
		{op: OpGetDeviceList, every: base},
		{op: OpGetClientSpeedList, every: base},
		{op: OpGetIoTClientList, every: base},
		{op: OpGetWireless, every: func(c *MeshConfig) time.Duration { return c.WirelessEvery }},
		{op: OpGetDeviceEthPort, every: func(c *MeshConfig) time.Duration { return c.PortsEvery }},
		{op: OpGetBlockList, every: func(c *MeshConfig) time.Duration { return c.BlocksEvery }},
		{op: OpGetClientList, every: func(c *MeshConfig) time.Duration { return c.ClientsEvery }},
	}
	if len(cfg.Only) == 0 && cfg.ClientsEvery < 0 {
		polls = polls[:len(polls)-1]
	}
	if len(cfg.Only) > 0 {
		var err error
		if polls, err = selectPolls(polls, cfg.Only); err != nil {
			return nil, err
		}
	}
	m := &Mesh{
		cfg:   cfg,
		now:   time.Now,
		wake:  make(chan struct{}, 1),
		polls: polls,
	}
	m.state.DownSince = m.now()
	return m, nil
}

// selectPolls keeps the polls in only, in that order.
func selectPolls(all []*pollItem, only []uint16) ([]*pollItem, error) {
	by := map[uint16]*pollItem{}
	for _, p := range all {
		by[p.op] = p
	}
	var out []*pollItem
	seen := map[uint16]bool{}
	for _, op := range only {
		p := by[op]
		if p == nil {
			return nil, fmt.Errorf("deco mesh: 0x%04x is not a polled Get", op)
		}
		if seen[op] {
			return nil, fmt.Errorf("deco mesh: 0x%04x listed twice", op)
		}
		seen[op] = true
		out = append(out, p)
	}
	if seen[OpGetDeviceEthPort] && !seen[OpGetDeviceList] {
		out = append([]*pollItem{by[OpGetDeviceList]}, out...)
	}
	return out, nil
}

// PolledOps lists the Gets this Mesh polls, in order.
func (m *Mesh) PolledOps() []uint16 {
	out := make([]uint16, 0, len(m.polls))
	for _, p := range m.polls {
		out = append(out, p.op)
	}
	return out
}

// Snapshot returns a copy of the cached state. Safe from any goroutine.
func (m *Mesh) Snapshot() MeshState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Submit queues a write for the Mesh goroutine and returns at once. The
// channel receives exactly one result.
func (m *Mesh) Submit(cmd Command) <-chan CommandResult {
	p := &pending{cmd: cmd, done: make(chan CommandResult, 1)}
	m.mu.Lock()
	if m.state.Latched != "" || m.stopped {
		err := ErrLatched
		if m.stopped {
			err = ErrStopped
		}
		m.mu.Unlock()
		p.done <- CommandResult{Kind: cmd.Kind, Err: err}
		return p.done
	}
	p.deadline = m.now().Add(m.cfg.CommandTimeout)
	m.queue = append(m.queue, p)
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return p.done
}

// RequestPoll asks the Mesh goroutine to re-read op (one of the polled
// Gets) on its next step, ahead of its interval. Safe from any goroutine.
func (m *Mesh) RequestPoll(op uint16) {
	m.mu.Lock()
	if m.pollReq == nil {
		m.pollReq = map[uint16]bool{}
	}
	m.pollReq[op] = true
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Run drives the session until ctx ends, then frees the token, sends BYE
// and fails queued commands. It returns ctx.Err().
func (m *Mesh) Run(ctx context.Context) error {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	defer m.shutdown()
	for {
		m.step(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		case <-m.wake:
		}
	}
}

func (m *Mesh) shutdown() {
	if m.client != nil {
		_ = m.client.Close()
		m.client = nil
	}
	m.mu.Lock()
	m.stopped = true
	m.state.Connected = false
	m.mu.Unlock()
	m.failQueue(ErrStopped)
}

// step is one pass of the Mesh loop: session upkeep, due polls, queued
// commands. Tests drive it directly with a fake clock.
func (m *Mesh) step(ctx context.Context) {
	now := m.now()
	m.expireQueue(now)
	if m.latched() {
		m.failQueue(ErrLatched)
		return
	}
	if m.client != nil {
		if err := m.client.Err(); err != nil {
			m.lost(now, err)
		} else {
			m.update(func(s *MeshState) { s.LastHeartbeat = m.client.LastHeartbeatEcho() })
		}
	}
	m.runDryRuns()
	if m.client == nil {
		if m.latched() || now.Before(m.nextLogin) || !m.login(ctx, now) {
			return
		}
	}
	m.poll(ctx)
	if m.client != nil {
		m.runCommands(ctx)
		m.poll(ctx) // re-reads forced by a write (0x4009 after a Set, ...)
	}
}

// ---- session lifecycle ----

func (m *Mesh) latched() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.Latched != ""
}

func (m *Mesh) latch(reason string) {
	m.cfg.Logf("deco mesh: LATCHED OFF, no further logins until restart: %s", reason)
	m.update(func(s *MeshState) {
		s.Latched = reason
		s.NextLoginAt = time.Time{}
	})
	m.failQueue(ErrLatched)
}

// backoff is the login delay after n consecutive failures (n >= 1).
func (m *Mesh) backoff(n int) time.Duration {
	d := m.cfg.RedialMin
	for i := 1; i < n && d < m.cfg.RedialMax; i++ {
		d *= 2
	}
	return min(d, m.cfg.RedialMax)
}

// failed schedules the next login after a failure: backoff after from
// (the last login, or now when no login was tried), and at least extra
// after now. Since from is never before the last login, two logins are
// always at least RedialMin apart.
func (m *Mesh) failed(now, from time.Time, extra time.Duration, err error) {
	m.failures++
	next := from.Add(m.backoff(m.failures))
	if t := now.Add(extra); t.After(next) {
		next = t
	}
	if next.Before(now) {
		next = now
	}
	m.nextLogin = next
	m.update(func(s *MeshState) {
		s.NextLoginAt = next
		if err != nil {
			s.LastError = err.Error()
		}
	})
}

// Precheck runs TDP against every configured unit and enforces design
// §3.1.1: exactly one master, the configured one, owned by TPLinkID, on SSH
// (no TLS, no TPS banner). A *RefusedError is a definite violation; any
// other error means the master did not answer.
func (m *Mesh) Precheck(ctx context.Context) (*DecoInfo, error) {
	type res struct {
		ip   string
		info *DecoInfo
		err  error
	}
	ch := make(chan res, len(m.cfg.UnitIPs))
	for _, ip := range m.cfg.UnitIPs {
		go func() {
			info, err := m.cfg.Discover(ctx, ip)
			ch <- res{ip, info, err}
		}()
	}
	var master *DecoInfo
	var masters []string
	var masterErr error
	units := map[string]*DecoInfo{}
	for range m.cfg.UnitIPs {
		r := <-ch
		if r.ip == m.cfg.MasterIP {
			master, masterErr = r.info, r.err
		}
		if r.err == nil && r.info != nil && NormMAC(r.info.MAC) != "" {
			units[NormMAC(r.info.MAC)] = r.info
		}
		if r.err == nil && r.info != nil && r.info.IsMaster() {
			masters = append(masters, r.ip)
		}
	}
	if len(units) > 0 {
		m.update(func(s *MeshState) { s.Units = units })
	}
	if masterErr != nil || master == nil {
		if masterErr == nil {
			masterErr = errors.New("no reply")
		}
		return nil, fmt.Errorf("deco mesh: tdp %s: %w", m.cfg.MasterIP, masterErr)
	}
	refuse := func(f string, a ...any) (*DecoInfo, error) {
		return nil, &RefusedError{Reason: fmt.Sprintf(f, a...)}
	}
	switch {
	case len(masters) != 1:
		return refuse("%d units report role=master (%s), want exactly one", len(masters), strings.Join(masters, ","))
	case masters[0] != m.cfg.MasterIP:
		return refuse("the master is %s, not the configured %s", masters[0], m.cfg.MasterIP)
	case NormMAC(master.MAC) != NormMAC(m.cfg.MasterMAC):
		return refuse("master %s has mac %s, not the configured %s", m.cfg.MasterIP, NormMAC(master.MAC), NormMAC(m.cfg.MasterMAC))
	case master.MasterDeviceID != "" && master.DeviceID != master.MasterDeviceID:
		return refuse("master device_id differs from its master_device_id")
	case len(master.Owner) <= 1 || !master.OwnerMatches(m.cfg.TPLinkID):
		// Strict: the app treats an empty owner as a match; we never log in blind.
		return refuse("TDP owner hash does not match the configured tplink_id")
	case master.FactoryDefault:
		return refuse("master reports factory_default")
	case master.UsesTLS():
		return refuse("master uses the TLS (tpap) transport, not SSH")
	case master.TPSBanner():
		return refuse("master needs a TPS- SSH banner, unsupported")
	}
	return master, nil
}

// hostKeyCallback pins HostKeySHA256, else the TOFU fingerprint from
// StateDir, else accepts the key and remembers it for saveHostKey.
func (m *Mesh) hostKeyCallback() ssh.HostKeyCallback {
	pin := m.cfg.HostKeySHA256
	if pin == "" && m.cfg.StateDir != "" {
		if b, err := os.ReadFile(filepath.Join(m.cfg.StateDir, hostKeyFile)); err == nil {
			pin = strings.TrimSpace(string(b))
		}
	}
	m.mu.Lock()
	m.seenHostFP = ""
	m.mu.Unlock()
	if pin != "" {
		return PinnedHostKey(pin)
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		m.mu.Lock()
		m.seenHostFP = ssh.FingerprintSHA256(key)
		m.mu.Unlock()
		return nil
	}
}

// saveHostKey records a first-use fingerprint after a successful login.
func (m *Mesh) saveHostKey() {
	m.mu.Lock()
	fp := m.seenHostFP
	m.mu.Unlock()
	if fp == "" || m.cfg.StateDir == "" {
		return
	}
	if err := os.MkdirAll(m.cfg.StateDir, 0o700); err != nil {
		m.cfg.Logf("deco mesh: host key not saved: %v", err)
		return
	}
	p := filepath.Join(m.cfg.StateDir, hostKeyFile)
	if err := os.WriteFile(p, []byte(fp+"\n"), 0o600); err != nil {
		m.cfg.Logf("deco mesh: host key not saved: %v", err)
		return
	}
	m.cfg.Logf("deco mesh: trusting master host key %s on first use (%s)", fp, p)
}

// login runs the precheck and, if it passes, one SSH login. It reports
// whether a session is up.
func (m *Mesh) login(ctx context.Context, now time.Time) bool {
	if m.latched() { // never log in once latched, whatever the caller checked
		return false
	}
	if m.cfg.MaxLogins > 0 && m.Snapshot().Logins >= m.cfg.MaxLogins {
		return false
	}
	info, err := m.Precheck(ctx)
	if err != nil {
		var re *RefusedError
		if errors.As(err, &re) {
			m.latch(re.Error())
			return false
		}
		m.cfg.Logf("deco mesh: %v; no login", err)
		m.failed(now, now, 0, err) // no password spent, but keep the cadence
		return false
	}
	m.update(func(s *MeshState) { s.Master = info })
	cb := m.hostKeyCallback()
	m.lastLogin = now
	m.update(func(s *MeshState) { s.Logins++ })
	c, err := Connect(ctx, Config{
		Host:           m.cfg.MasterIP,
		Port:           info.SSHPort(),
		SSHUser:        info.SSHUsername(m.cfg.TPLinkID),
		CloudUserName:  m.cfg.TPLinkID,
		CloudPassword:  m.cfg.Password,
		Owner:          true,
		HostKey:        cb,
		Heartbeat:      m.cfg.Heartbeat,
		RequestTimeout: m.cfg.RequestTimeout,
		OpTimeouts:     m.cfg.OpTimeouts,
		Trace:          m.cfg.Trace,
		NoRedial:       true,
	})
	if err != nil {
		var ae *AuthError
		var he *HostKeyError
		var be *ByeError
		switch {
		case errors.As(err, &ae):
			m.latch("SSH login rejected (TP-Link lockout protection)")
		case errors.As(err, &he):
			m.latch(fmt.Sprintf("master host key %s is not the pinned one", he.Got))
		case errors.As(err, &be):
			m.onBye(now, be, err)
		default:
			m.cfg.Logf("deco mesh: login failed: %v", err)
			m.failed(now, m.lastLogin, 0, err)
		}
		return false
	}
	m.saveHostKey()
	m.client = c
	m.upSince = now
	m.errStreak = 0
	m.appFails, m.disabled = map[uint16]int{}, map[uint16]bool{}
	for _, p := range m.polls {
		p.force = true
	}
	mode, nerr := "", ""
	if c.Negotiation != nil {
		mode = string(c.Negotiation.OperationMode)
	}
	if c.NegotiationErr != nil {
		nerr = c.NegotiationErr.Error()
	}
	m.update(func(s *MeshState) {
		s.Connected, s.ConnectedSince, s.DownSince = true, now, time.Time{}
		s.NextLoginAt, s.LastError = time.Time{}, ""
		s.Negotiation, s.NegotiationErr, s.OperationMode = c.Negotiation, nerr, mode
		s.Busy, s.LastSlow = nil, nil
		for _, p := range []*bool{&s.Devices.Disabled, &s.Clients.Disabled, &s.Speeds.Disabled, &s.IoT.Disabled,
			&s.Wireless.Disabled, &s.Ports.Disabled, &s.Blocks.Disabled} {
			*p = false
		}
	})
	m.cfg.Logf("deco mesh: session up to %s (operation_mode=%q)", m.cfg.MasterIP, mode)
	if c.Negotiation != nil && !c.Negotiation.OperationMode.Is(OpModeAP) {
		m.cfg.Logf("deco mesh: WARNING operation_mode is %q, not AP: Deco clients are NATed and will not appear in UniFi's client table", mode)
	}
	return true
}

// lost tears down a dead session and schedules the next login.
func (m *Mesh) lost(now time.Time, cause error) {
	_ = m.client.Close()
	m.client = nil
	if now.Sub(m.upSince) >= stableAfter {
		m.failures = 0
	}
	m.update(func(s *MeshState) { s.Connected, s.DownSince = false, now })
	var be *ByeError
	if errors.As(cause, &be) {
		m.onBye(now, be, cause)
		return
	}
	m.cfg.Logf("deco mesh: session lost: %v", cause)
	m.failed(now, m.lastLogin, 0, cause)
}

func (m *Mesh) onBye(now time.Time, be *ByeError, err error) {
	b := *be
	m.update(func(s *MeshState) { s.LastBye = &b })
	m.cfg.Logf("deco mesh: %v", be)
	if be.Reason == byeAuthChanged {
		m.latch("device sent BYE AUTH_CHANGED")
		return
	}
	m.failed(now, m.lastLogin, byeDelay[be.Reason], err)
}

// dropSession closes a live session that keeps failing.
func (m *Mesh) dropSession(now time.Time, err error) {
	m.cfg.Logf("deco mesh: dropping session after %d consecutive errors", m.errStreak)
	m.lost(now, err)
}

// ---- polling ----

func (m *Mesh) update(f func(*MeshState)) {
	m.mu.Lock()
	f(&m.state)
	m.mu.Unlock()
}

func (m *Mesh) poll(ctx context.Context) {
	m.mu.Lock()
	for _, p := range m.polls {
		if m.pollReq[p.op] {
			p.force = true
		}
	}
	m.pollReq = nil
	m.mu.Unlock()
	for _, p := range m.polls {
		if m.client == nil || ctx.Err() != nil {
			return // no orphaned requests once the caller has given up
		}
		if m.cfg.Once && p.done {
			continue
		}
		now := m.now()
		if !p.force && now.Sub(p.last) < p.every(&m.cfg) {
			continue
		}
		p.force, p.last = false, now
		if m.disabled[p.op] {
			p.done = true
			continue
		}
		if comp := pollComponent[p.op]; comp != "" && !m.negotiated(comp) {
			m.disabled[p.op], p.done = true, true
			msg := fmt.Sprintf("component %q not in the NEGOTIATE component_list", comp)
			m.update(func(s *MeshState) { s.setOff(p.op, msg) })
			m.cfg.Logf("deco mesh: opcode 0x%04x not polled: %s", p.op, msg)
			continue
		}
		var err error
		switch p.op {
		case OpGetDeviceList:
			err = pollInto(m, ctx, p.op, nil, func(s *MeshState) *Polled[DeviceListResult] { return &s.Devices })
		case OpGetClientList:
			err = pollInto(m, ctx, p.op, nil, func(s *MeshState) *Polled[ClientListResult] { return &s.Clients })
		case OpGetClientSpeedList:
			err = pollInto(m, ctx, p.op, nil, func(s *MeshState) *Polled[ClientSpeedListResult] { return &s.Speeds })
		case OpGetIoTClientList:
			err = pollInto(m, ctx, p.op, nil, func(s *MeshState) *Polled[IoTClientListResult] { return &s.IoT })
		case OpGetWireless:
			err = pollInto(m, ctx, p.op, nil, func(s *MeshState) *Polled[WirelessInfo] { return &s.Wireless })
		case OpGetDeviceEthPort:
			ids := m.deviceIDs()
			if len(ids) == 0 {
				p.force = true // retry once device_list is known
				continue
			}
			err = pollInto(m, ctx, p.op, DeviceIDListParams{DeviceList: ids},
				func(s *MeshState) *Polled[DeviceEthPortResult] { return &s.Ports })
		case OpGetBlockList:
			err = pollInto(m, ctx, p.op, nil, func(s *MeshState) *Polled[ClientBlockListResult] { return &s.Blocks })
		}
		// The interval runs from the end of the request: a Get slower than
		// its interval (0x4012 took 62 s live) is not re-sent at once.
		p.last = m.now()
		if err == nil || m.disabled[p.op] {
			p.done = true
		}
		if err != nil && m.client != nil && !m.client.Alive() {
			m.lost(m.now(), m.client.Err())
			return
		}
	}
}

// negotiated reports whether the session's NEGOTIATE listed component. A
// NEGOTIATE that failed or listed no components gates nothing.
func (m *Mesh) negotiated(component string) bool {
	n := m.client.Negotiation
	return n == nil || len(n.ComponentList) == 0 || n.HasComponent(component)
}

// pollInto runs one Get and stores the outcome in the slot sel picks.
func pollInto[T any](m *Mesh, ctx context.Context, op uint16, params any, sel func(*MeshState) *Polled[T]) error {
	var v T
	since := m.now()
	m.update(func(s *MeshState) { s.Busy = &BusyPoll{Op: op, Since: since} })
	err := m.client.Get(ctx, op, params, &v)
	end := m.now()
	m.update(func(s *MeshState) {
		s.Busy = nil
		if slowPolls[op] {
			s.LastSlow = &SlowPoll{Op: op, Since: since, End: end}
		}
	})
	var ae *AppError
	var te *ResultTypeError
	switch {
	case err == nil, errors.As(err, &ae) && ae.NoData():
		m.errStreak, m.appFails[op] = 0, 0
		at := m.now()
		m.update(func(s *MeshState) { *sel(s) = Polled[T]{Value: &v, At: at, OK: true} })
		return nil
	case errors.As(err, &te) && op != OpGetWireless:
		// The device answered; one field has a type the schema lacks. Keep
		// the partial decode rather than lose the whole list. Wi-Fi is not
		// kept: Sets are built from it, and a zeroed field would be written.
		m.errStreak, m.appFails[op] = 0, 0
		at := m.now()
		var first bool
		m.update(func(s *MeshState) {
			p := sel(s)
			first = p.Err == ""
			*p = Polled[T]{Value: &v, At: at, OK: true, Err: err.Error()}
		})
		if first {
			m.cfg.Logf("deco mesh: opcode 0x%04x: partial decode kept: %v", op, err)
		}
		return nil
	case errors.As(err, &te):
		m.errStreak = 0 // a schema mismatch, not a dead link
		m.update(func(s *MeshState) {
			p := sel(s)
			p.OK, p.Err = false, err.Error()
		})
		return err
	case errors.As(err, &ae):
		m.errStreak = 0
		m.appFails[op]++
		off := m.appFails[op] >= disableAfter
		if off {
			m.disabled[op] = true
			m.cfg.Logf("deco mesh: opcode 0x%04x disabled for this session (error_code=%d)", op, ae.ErrorCode)
		}
		m.update(func(s *MeshState) {
			p := sel(s)
			p.OK, p.Err, p.Disabled = false, err.Error(), off
		})
		return err
	}
	if ctx.Err() != nil {
		// The caller's deadline or cancellation ended the request (shutdown,
		// the -print budget), not the request's own budget: says nothing
		// about the link, nor about a value an earlier poll read.
		m.update(func(s *MeshState) {
			if p := sel(s); !p.OK {
				p.Err = err.Error()
			}
		})
		return err
	}
	m.update(func(s *MeshState) {
		p := sel(s)
		p.OK, p.Err = false, err.Error()
	})
	if m.client.Alive() {
		m.errStreak++
		if m.errStreak >= dropAfter {
			m.dropSession(m.now(), err)
		}
	}
	return err
}

func (m *Mesh) deviceIDs() []DeviceID {
	s := m.Snapshot()
	if s.Devices.Value == nil {
		return nil
	}
	var ids []DeviceID
	for _, d := range s.Devices.Value.DeviceList {
		if d.DeviceID != "" {
			ids = append(ids, DeviceID{DeviceID: d.DeviceID})
		}
	}
	return ids
}

// ---- commands ----

func (m *Mesh) takeQueue(keep func(*pending) bool) []*pending {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out, rest []*pending
	for _, p := range m.queue {
		if keep(p) {
			rest = append(rest, p)
		} else {
			out = append(out, p)
		}
	}
	m.queue = rest
	return out
}

func (m *Mesh) failQueue(err error) {
	for _, p := range m.takeQueue(func(*pending) bool { return false }) {
		p.done <- CommandResult{Kind: p.cmd.Kind, Err: err}
	}
}

func (m *Mesh) expireQueue(now time.Time) {
	for _, p := range m.takeQueue(func(p *pending) bool { return now.Before(p.deadline) }) {
		p.done <- CommandResult{Kind: p.cmd.Kind, Err: ErrNotConnected}
	}
}

// runDryRuns answers every queued command from the cache when apply is off.
func (m *Mesh) runDryRuns() {
	if m.cfg.Apply {
		return
	}
	for _, p := range m.takeQueue(func(*pending) bool { return false }) {
		p.done <- m.dryRun(p.cmd)
	}
}

// dryRun is the apply=false answer to cmd: the plan, logged, never sent.
func (m *Mesh) dryRun(cmd Command) CommandResult {
	r, _ := m.plan(cmd)
	if r.Err == nil {
		r.DryRun = true
		m.cfg.Logf("deco mesh: apply=false, would send %s 0x%04x %s", r.Kind, r.Opcode, r.Plan)
	}
	return r
}

func (m *Mesh) runCommands(ctx context.Context) {
	for _, p := range m.takeQueue(func(*pending) bool { return false }) {
		if m.client == nil { // lost mid-batch: requeue
			m.mu.Lock()
			m.queue = append(m.queue, p)
			m.mu.Unlock()
			continue
		}
		p.done <- m.execute(ctx, p.cmd)
	}
}

// plan builds the opcode and params for cmd from the cache. r.Plan is the
// masked JSON for logs; params is what goes on the wire.
func (m *Mesh) plan(cmd Command) (r CommandResult, params any) {
	r.Kind = cmd.Kind
	s := m.Snapshot()
	switch cmd.Kind {
	case CmdReboot:
		r.Opcode = OpRebootDevices
		id := cmd.DeviceID
		if id == "" && s.Devices.Value != nil {
			for _, d := range s.Devices.Value.DeviceList {
				if NormMAC(d.MAC) != "" && NormMAC(d.MAC) == NormMAC(cmd.MAC) {
					id = d.DeviceID
				}
			}
		}
		if id == "" {
			r.Err = fmt.Errorf("deco mesh: reboot: unit %s not in device_list", cmd.MAC)
			return r, nil
		}
		params = DeviceIDListParams{DeviceList: []DeviceID{{DeviceID: id}}}
	case CmdBlock:
		r.Opcode = OpBlockClients
		var list []ClientBlockEntry
		for _, mac := range cmd.MACs {
			e := ClientBlockEntry{MAC: m.deviceMAC(s, mac), ClientType: "other"}
			if c := findClient(s, mac); c != nil {
				e = ClientBlockEntry{MAC: c.MAC, Name: c.Name, ClientType: c.ClientType}
			}
			list = append(list, e)
		}
		params = ClientBlockParams{ClientList: list}
	case CmdUnblock:
		r.Opcode = OpUnblockClients
		var list []string
		for _, mac := range cmd.MACs {
			list = append(list, m.blockedMAC(s, mac))
		}
		params = ClientUnblockParams{ClientList: list}
	case CmdSetWireless:
		r.Opcode = OpSetWireless
		if cmd.Wireless == nil {
			r.Err = errors.New("deco mesh: wifi-set without a body")
			return r, nil
		}
		params = cmd.Wireless
	default:
		r.Err = fmt.Errorf("deco mesh: unknown command %v", cmd.Kind)
		return r, nil
	}
	b, err := json.Marshal(params)
	if err != nil {
		r.Err = err
		return r, nil
	}
	r.Plan = string(RedactJSON(b))
	return r, params
}

func (m *Mesh) execute(ctx context.Context, cmd Command) CommandResult {
	// The write path itself is gated: a command submitted after runDryRuns
	// drained the queue (while login or poll ran) must not be sent either.
	if !m.cfg.Apply {
		return m.dryRun(cmd)
	}
	r, params := m.plan(cmd)
	if r.Err != nil {
		return r
	}
	s := m.Snapshot()
	if err := m.masterConsistent(&s); err != nil {
		m.cfg.Logf("deco mesh: %s refused: %v", r.Kind, err)
		r.Err = err
		return r
	}
	now := m.now()
	if cmd.Kind == CmdSetWireless && !cmd.SkipRateLimit && !m.lastWLAN.IsZero() && now.Sub(m.lastWLAN) < m.cfg.WLANMinInterval {
		r.Err = ErrRateLimited
		return r
	}
	if cmd.Kind == CmdSetWireless {
		m.lastWLAN = now
	}
	m.cfg.Logf("deco mesh: sending %s 0x%04x %s", r.Kind, r.Opcode, r.Plan)
	r.Raw, r.Err = m.client.Set(ctx, r.Opcode, params)
	if r.Err != nil {
		m.cfg.Logf("deco mesh: %s failed: %v", r.Kind, r.Err)
		if !m.client.Alive() {
			m.lost(m.now(), m.client.Err())
		}
		return r
	}
	for _, p := range m.polls {
		switch {
		case cmd.Kind == CmdSetWireless && p.op == OpGetWireless,
			cmd.Kind == CmdReboot && p.op == OpGetDeviceList,
			(cmd.Kind == CmdBlock || cmd.Kind == CmdUnblock) && p.op == OpGetBlockList:
			p.force = true
		}
	}
	return r
}

// masterConsistent is design §3.3 ConfigOwner: exactly one device_list
// entry is the master, and it is the configured unit. The check uses
// device_list data (device_id == master_device_id, role, MAC); the TDP
// cross-check compares md5hex of the device_list device_id with the TDP
// master_device_id, because TDP carries MD5 digests of the TMP ids (the app
// keys TDPGenericDevice.getDeviceIdMd5() and TmpGenericDevice.a() =
// dj.a.r(device_id) = md5hex the same way, GenericDevice.java:81-90,306-312).
func (m *Mesh) masterConsistent(s *MeshState) error {
	if s.Devices.Value == nil || s.Master == nil {
		return fmt.Errorf("%w (device_list not read yet)", ErrOwnerMismatch)
	}
	tdp := s.Master.MasterDeviceID
	if tdp == "" {
		tdp = s.Master.DeviceID
	}
	n, masters := 0, 0
	for _, d := range s.Devices.Value.DeviceList {
		if !d.IsMaster() {
			continue
		}
		masters++
		if d.DeviceID != "" &&
			(d.MasterDeviceID == "" || d.MasterDeviceID == d.DeviceID) &&
			NormMAC(d.MAC) == NormMAC(m.cfg.MasterMAC) &&
			tdpIDMatches(d.DeviceID, tdp) {
			n++
		}
	}
	if n != 1 || masters != 1 {
		return ErrOwnerMismatch
	}
	return nil
}

// tdpIDMatches reports whether the TDP id (an MD5 digest) names the TMP
// device_list id. An empty TDP id is no evidence either way. A TDP id equal
// to the raw TMP id is also accepted: the raw TMP id format is not yet
// captured live (docs/deco/open-questions.md), and the MAC check still holds.
func tdpIDMatches(tmpID, tdpID string) bool {
	if tdpID == "" {
		return true
	}
	return strings.EqualFold(DeviceIDDigest(tmpID), tdpID) || strings.EqualFold(tmpID, tdpID)
}

func findClient(s MeshState, mac string) *ClientBean {
	if s.Clients.Value == nil {
		return nil
	}
	for i, c := range s.Clients.Value.ClientList {
		if NormMAC(c.MAC) != "" && NormMAC(c.MAC) == NormMAC(mac) {
			return &s.Clients.Value.ClientList[i]
		}
	}
	return nil
}

// blockedMAC returns the device's spelling of mac from the block list.
func (m *Mesh) blockedMAC(s MeshState, mac string) string {
	if s.Blocks.Value != nil {
		for _, b := range s.Blocks.Value.ClientList {
			if NormMAC(b.MAC) != "" && NormMAC(b.MAC) == NormMAC(mac) {
				return b.MAC
			}
		}
	}
	return m.deviceMAC(s, mac)
}

// deviceMAC spells mac like the MACs the device returns (separator and
// case), since the wire format is unverified (open question 8).
func (m *Mesh) deviceMAC(s MeshState, mac string) string {
	sample := ""
	if s.Clients.Value != nil && len(s.Clients.Value.ClientList) > 0 {
		sample = s.Clients.Value.ClientList[0].MAC
	} else if s.Devices.Value != nil && len(s.Devices.Value.DeviceList) > 0 {
		sample = s.Devices.Value.DeviceList[0].MAC
	}
	return MACLike(sample, mac)
}

// ---- helpers ----

// NormMAC lowercases a MAC and uses colons; "" if it is not 6 hex bytes.
func NormMAC(s string) string {
	h := strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.ToLower(strings.TrimSpace(s)))
	if len(h) != 12 {
		return ""
	}
	for _, c := range h {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return ""
		}
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// MACLike formats mac with the separator and case of sample.
func MACLike(sample, mac string) string {
	n := NormMAC(mac)
	if n == "" {
		return mac
	}
	if strings.Contains(sample, "-") {
		n = strings.ReplaceAll(n, ":", "-")
	}
	if sample != strings.ToLower(sample) {
		n = strings.ToUpper(n)
	}
	return n
}

var redactKeys = map[string]bool{"password": true, "default_password": true}

// RedactJSON masks every password-like value in a JSON document. On a
// parse failure it returns a placeholder rather than the input.
func RedactJSON(b []byte) []byte {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return []byte(`"<unparseable>"`)
	}
	var walk func(any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case map[string]any:
			for k, x := range t {
				if redactKeys[k] {
					t[k] = "***"
				} else {
					t[k] = walk(x)
				}
			}
		case []any:
			for i, x := range t {
				t[i] = walk(x)
			}
		}
		return v
	}
	out, err := json.Marshal(walk(v))
	if err != nil {
		return []byte(`"<unparseable>"`)
	}
	return out
}

// MaskWireless returns a copy of w with every passphrase replaced by "***".
func MaskWireless(w *WirelessInfo) *WirelessInfo {
	if w == nil {
		return nil
	}
	mask := B64("***")
	band := func(b *WirelessBand) *WirelessBand {
		if b == nil {
			return nil
		}
		c := *b
		if c.Host != nil {
			h := *c.Host
			if h.Password != nil {
				h.Password = &mask
			}
			c.Host = &h
		}
		if c.Guest != nil {
			g := *c.Guest
			if g.Password != nil {
				g.Password = &mask
			}
			c.Guest = &g
		}
		if c.IoT != nil {
			i := *c.IoT
			if i.Password != nil {
				i.Password = &mask
			}
			c.IoT = &i
		}
		return &c
	}
	c := *w
	c.Band2G4, c.Band5G1, c.Band5G2 = band(w.Band2G4), band(w.Band5G1), band(w.Band5G2)
	c.Band60G, c.Band6G, c.Band6G2 = band(w.Band60G), band(w.Band6G), band(w.Band6G2)
	if w.ConfigSpec != nil && w.ConfigSpec.Password != nil {
		cs := *w.ConfigSpec
		cs.Password = &mask
		c.ConfigSpec = &cs
	}
	return &c
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
