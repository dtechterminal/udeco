// SPDX-License-Identifier: GPL-2.0-or-later

// Package device is the device side of the inform protocol: the state a
// UniFi AP keeps (key, cipher, cfgversion, adopted), the payload it sends,
// and what it does with each controller reply. It never applies firmware.
//
// Reply handling: docs/internals.md (open-unifi docs/PROTOCOL-mgmt.md
// §6, unifi-emu inform/session.go).
package device

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/inform"
)

// State is persisted (mode 600) so a restart keeps the adopted key.
type State struct {
	Key        string `json:"key"`        // current authkey (hex); secret
	GCM        bool   `json:"gcm"`        // encrypt informs with AES-GCM
	Adopted    bool   `json:"adopted"`    // holds a per-device key
	CfgVersion string `json:"cfgversion"` // echoed in every inform
	// PendingCfgVersion: with Session.DeferCfgAck, the cfgversion the
	// controller sent that is not yet acknowledged (its configuration is not
	// live yet); "" = none.
	PendingCfgVersion string           `json:"cfgversion_pending,omitempty"`
	InformURL         string           `json:"inform_url"`            // where to inform
	Version           string           `json:"version"`               // firmware version we report
	MgmtCfg           string           `json:"mgmt_cfg"`              // last mgmt_cfg (may hold authkey); secret
	LED               bool             `json:"led"`                   // mgmt_cfg led_enabled
	Locating          bool             `json:"locating"`              // UniFi "Locate" active
	Blocked           []string         `json:"blocked_sta,omitempty"` // blocked client MACs (controller's blocked_sta)
	Guests            map[string]int64 `json:"guests,omitempty"`      // portal-authorized guest MAC -> expiry (unix s)
	GuestToken        string           `json:"guest_token,omitempty"` // portal cookie key (32 hex), sent in informs; secret
	HashID            string           `json:"hash_id,omitempty"`     // device hash (16 hex), sent in informs; names us in encrypted syslog
	SystemCfgN        int              `json:"system_cfg_bytes"`
	// RadioNames: the radio_table naming this state reports ("mediatek":
	// ra0/rai0, "qualcomm": wifi0/wifi1; "" = not chosen yet). The
	// controller keeps every radio row it was ever sent, matched by name,
	// so the naming may only change when the controller forgets the device
	// (cmd/udeco-ap radionames.go).
	RadioNames string `json:"radio_names,omitempty"`
	// Model: the model code this state was adopted as ("" = not adopted, or
	// a state written before the field). The controller fixes a device's
	// model when it first sees it and never takes a new one from an
	// adopted device's informs, so reporting another model needs a Forget
	// and a new adoption (cmd/udeco-ap adoptmodel.go).
	Model string `json:"model,omitempty"`
	// ClientRates: per-client speed limits from the controller's
	// rate-update cmd (client MAC -> limits), kept until a rate-update
	// clears them.
	ClientRates map[string]ClientRate `json:"client_rates,omitempty"`
}

// ClientRate is one client's speed limit (cmd rate-update) in kbit/s; 0 =
// not limited that way. Set is when it was last set (unix s).
type ClientRate struct {
	DownKbps int   `json:"down,omitempty"`
	UpKbps   int   `json:"up,omitempty"`
	Set      int64 `json:"set,omitempty"`
}

// MaxClientRates bounds State.ClientRates: the controller never says when a
// forgotten client's limit is gone, so the oldest entry makes room.
const MaxClientRates = 512

func NewState(informURL string) State {
	return State{Key: inform.DefaultKeyHex, CfgVersion: "0", InformURL: informURL, Version: inform.U7PG2Version}
}

func Load(path string) (State, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, false, err
	}
	return s, true, nil
}

func (s State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// The files of a session's state directory (Session.StateDir), for the
// session, which writes the system_cfg ones, and for every daemon that
// reads or writes them by path.
const (
	StateFile           = "state.json"           // the State (State.Save, Load)
	SystemCfgFile       = "system_cfg.txt"       // the last system_cfg a setparam carried
	SystemCfgHistoryDir = "system_cfg.history"   // its HistoryKeep last versions
	UnhandledFile       = "unhandled.json"       // the Ledger (OpenLedger)
	SSHHostKeyFile      = "ssh_host_ed25519.pem" // the adoption SSH server's host key (SSHAdopt.HostKey)
)

// Session ties the state to the device description and a boot clock.
type Session struct {
	// GuestMu guards S.Guests (the inform loop and the :8882 portal handler).
	GuestMu  sync.Mutex
	S        State
	Dev      inform.Device
	Boot     time.Time
	StateDir string // where StateFile, SystemCfgFile and the others live (mode 700)
	SSHPort  int    // reported as sshd_port: where the console SSHes to adopt
	ledKnown bool
	// the last setparam and how often it was repeated unchanged
	lastParam  [sha256.Size]byte
	sameParams int
	// Unhandled, when set, records what the controller sent that nothing
	// here acted on. KnownSection tells which system_cfg sections the
	// translator handles (nil = none are recorded).
	Unhandled    *Ledger
	KnownSection func(section string) bool
	// Extra, when set, returns fields read from the real AP (radios, VAPs,
	// clients, system); they replace the static U7PG2 defaults.
	Extra func() map[string]any
	// WifiCaps is the UNIFI_WIFI_CAP bitmap we claim (0 = not sent). Claim
	// only what the AP really does: the controller trusts it.
	WifiCaps int
	// Optional further capability words (0 = not sent / default).
	WifiCaps2, FWCaps, FW2Caps, FW3Caps int
	// HWCaps: hardware bits (2 = LED bar colour, 16384 = LED brightness):
	// the controller offers LED colour/brightness only when they are set.
	HWCaps int
	// DeferCfgAck: a cfgversion the controller sends is reported only once
	// the AP calls AckCfgVersion (its configuration is live). Until then the
	// inform keeps the previous cfgversion, so the controller provisions
	// again. false = report it at once (an emulated AP that applies nothing).
	DeferCfgAck bool
}

// ClockSane is the earliest wall-clock time taken as set: a Deco has no
// RTC and reads 2025-09-12 until NTP (docs/deco/interference-audit.md X9,
// R7). Timestamped files (the system_cfg history) wait until it passes.
var ClockSane = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// AckCfgVersion makes cv the reported cfgversion (DeferCfgAck): the
// configuration it names is live. It reports whether the state changed
// (save it).
func (x *Session) AckCfgVersion(cv string) bool {
	if cv == "" {
		return false
	}
	changed := false
	if x.S.PendingCfgVersion == cv {
		x.S.PendingCfgVersion, changed = "", true
	}
	if x.S.CfgVersion != cv {
		x.S.CfgVersion, changed = cv, true
	}
	return changed
}

// WantedCfgVersion is the newest cfgversion the controller sent: the
// pending one when there is one, else the reported one.
func (x *Session) WantedCfgVersion() string {
	if x.S.PendingCfgVersion != "" {
		return x.S.PendingCfgVersion
	}
	return x.S.CfgVersion
}

func (x *Session) Cipher() inform.Cipher {
	if x.S.GCM {
		return inform.GCM
	}
	return inform.CBC
}

// Payload builds the next inform body.
func (x *Session) Payload(now time.Time) ([]byte, error) {
	d := x.Dev
	d.Uptime = int64(now.Sub(x.Boot).Seconds())
	d.Time = now.Unix()
	d.InformURL = x.S.InformURL
	m, err := inform.U7PG2Fields(d)
	if err != nil {
		return nil, err
	}
	if x.Extra != nil {
		for k, v := range x.Extra() {
			m[k] = v
		}
	}
	m["version"] = x.S.Version
	m["cfgversion"] = x.S.CfgVersion
	m["x_authkey"] = x.S.Key
	m["locating"] = x.S.Locating
	if x.S.HashID != "" {
		m["hash_id"] = x.S.HashID
	}
	if x.S.GuestToken != "" {
		m["guest_token"] = x.S.GuestToken
		m["guest_kicks"] = 0
	}
	// The fastest inform interval we support. 1 = "supports live updates"
	// (com.ubnt.data device: supportsLiveUpdates): the controller then asks
	// for 1 s informs while the device is watched in the panel, and the
	// panel draws its clients' live signal graph (docs/internals.md).
	m["inform_min_interval"] = 1
	if x.WifiCaps != 0 {
		m["wifi_caps"] = uint32(x.WifiCaps) // 32-bit word: on 32-bit ARM an int holding it is negative
	}
	if x.WifiCaps2 != 0 {
		m["wifi_caps2"] = uint32(x.WifiCaps2) // 32-bit word: on 32-bit ARM an int holding it is negative
	}
	if x.FWCaps != 0 {
		m["fw_caps"] = uint32(x.FWCaps) // 32-bit word: on 32-bit ARM an int holding it is negative
	}
	if x.HWCaps != 0 {
		m["hw_caps"] = uint32(x.HWCaps)
	}
	if x.FW2Caps != 0 {
		m["fw2_caps"] = uint32(x.FW2Caps) // 32-bit word: on 32-bit ARM an int holding it is negative
	}
	if x.FW3Caps != 0 {
		m["fw3_caps"] = uint32(x.FW3Caps) // 32-bit word: on 32-bit ARM an int holding it is negative
	}
	if x.SSHPort > 0 {
		m["sshd_port"] = x.SSHPort
	}
	if x.S.Adopted {
		m["default"] = false
		m["_default_key"] = false
		m["state"] = 4 // device-side "managed"; the controller does not read it
		m["x_aes_gcm"] = x.S.GCM
		m["bootrom_version"] = "unknown"
		// Canned values only stand in for what Extra (the real AP reading)
		// did not provide: they must never replace real figures
		// (docs/deco/agent-design.md §2, "Known code defect").
		if _, ok := m["sys_stats"]; !ok {
			m["sys_stats"] = map[string]any{
				"loadavg_1": "0.05", "loadavg_5": "0.04", "loadavg_15": "0.01",
				"mem_total": 129130496, "mem_used": 64565248, "mem_buffer": 4194304,
			}
		}
		if _, ok := m["radio_table_stats"]; !ok {
			m["radio_table_stats"] = radioStats(d.Radios)
		}
	}
	return json.Marshal(m)
}

func radioStats(rs []inform.Radio) []map[string]any {
	if rs == nil {
		rs = inform.DefaultU7PG2Radios()
	}
	var out []map[string]any
	for _, r := range rs {
		out = append(out, map[string]any{"name": r.Name, "radio": r.Radio, "channel": r.Channel,
			"tx_power": r.MaxTxpower, "num_sta": 0, "cu_total": 0, "cu_self_rx": 0, "cu_self_tx": 0})
	}
	return out
}

// Reply is a decoded controller reply.
type Reply struct {
	Type       string  `json:"_type"`
	Interval   int     `json:"interval"`
	Immediate  int     `json:"immediate"`
	Cmd        string  `json:"cmd"`
	Key        string  `json:"key"`
	URI        string  `json:"uri"`
	Version    string  `json:"version"`
	URL        string  `json:"url"`
	CfgVersion string  `json:"cfgversion"`
	MgmtCfg    string  `json:"mgmt_cfg"`
	SystemCfg  string  `json:"system_cfg"`
	BlockedSta *string `json:"blocked_sta"` // nil = not sent; "" = no blocked clients
	MAC        string  `json:"mac"`         // cmd kick-sta / block-sta / unblock-sta / (un)authorize-guest
	Minutes    int     `json:"minutes"`     // authorize-guest: duration, if sent
	End        int64   `json:"end"`         // authorize-guest: end time (unix s), if sent
	ScanBand   *IntArg `json:"scan-band"`   // cmd quick-scan: 0 = 2.4 GHz, 1 = 5 GHz, 2 = 6 GHz
	ScanBW     *IntArg `json:"scan-bw"`     // cmd quick-scan: channel width in MHz
	// cmd rate-update: the client's limits in kbit/s, -1 = none that way
	// (the _min ones, always 64, are read and not used)
	DLMax *IntArg `json:"dl_max"`
	ULMax *IntArg `json:"ul_max"`
	DLMin *IntArg `json:"dl_min"`
	ULMin *IntArg `json:"ul_min"`
}

// IntArg is a reply argument sent as a JSON number or as a numeric string.
type IntArg int

func (n *IntArg) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("not an integer: %s", b)
	}
	*n = IntArg(v)
	return nil
}

// QuickScanBands maps the quick-scan scan-band codes (mcad: "[quick-scan]
// band/bw: 1 80"; docs/reference/u6pro/study-actions-scans.md) to radios.
var QuickScanBands = map[int]string{0: "ng", 1: "na", 2: "6e"}

func init() {
	// read by the quick-scan cmd below (replyFields lives in unhandled.go)
	replyFields["scan-band"], replyFields["scan-bw"] = true, true
	for _, k := range []string{"dl_max", "ul_max", "dl_min", "ul_min"} {
		replyFields[k] = true // cmd rate-update
	}
}

// Outcome tells the loop what happened and what to do next.
type Outcome struct {
	Events     []string      // human log lines (no secrets)
	Interval   time.Duration // 0 = keep the current interval
	Immediate  bool          // inform again right away
	Changed    bool          // state changed: save it
	Reset      bool          // controller sent setdefault (device was removed)
	SystemCfg  bool          // a setparam carried a system_cfg (saved as SystemCfgFile)
	CfgVersion string        // the cfgversion the reply carried ("" = none)
	Actions    []string      // for a real AP: the Act* verbs with their arguments (action.go)
}

// Handle applies a decoded reply to the session.
func (x *Session) Handle(js []byte, now time.Time) (Outcome, error) {
	var r Reply
	if err := json.Unmarshal(js, &r); err != nil {
		return Outcome{}, fmt.Errorf("reply is not JSON: %w", err)
	}
	var o Outcome
	if r.Interval > 0 {
		o.Interval = time.Duration(r.Interval) * time.Second
	}
	if r.Type != "setparam" {
		x.sameParams = 0 // the controller moved on
	}
	switch r.Type {
	case "noop":
		o.Immediate = r.Immediate != 0
		o.Events = append(o.Events, fmt.Sprintf("noop interval=%d immediate=%d", r.Interval, r.Immediate))
	case "setparam":
		x.setparam(r, now, &o)
	case "upgrade":
		x.upgrade(r.Version, r.URL, now, &o)
	case "reboot":
		x.Boot = now
		o.Immediate = true
		o.Actions = append(o.Actions, ActReboot)
		o.Events = append(o.Events, "reboot requested")
	case "setdefault":
		x.setdefault(&o)
	case "cmd":
		x.cmd(r, js, now, &o)
	default:
		o.Events = append(o.Events, fmt.Sprintf("reply type %q: ignored", r.Type))
		x.note("reply", r.Type, redactReply(js), now, &o)
	}
	x.noteUnread(js, r.Type, now, &o)
	// The raw reply goes to the log: redactReply hides mgmt_cfg/system_cfg
	// (passphrases, RADIUS secrets, password hashes) and secret-named fields.
	if strings.Contains(r.Cmd, "guest") {
		o.Events = append(o.Events, "  raw reply: "+redactReply(js))
	}
	for _, e := range o.Events {
		if strings.Contains(e, "ignored") {
			o.Events = append(o.Events, "  raw reply: "+redactReply(js))
			break
		}
	}
	return o, nil
}

func (x *Session) setparam(r Reply, now time.Time, o *Outcome) {
	var cv, authkey, gcm, informURL string
	var keys []string
	for _, line := range strings.Split(r.MgmtCfg, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		keys = append(keys, k)
		if !mgmtKeys[k] {
			x.note("mgmt_cfg", k, redactValue(k, v), now, o)
		}
		switch k {
		case "cfgversion":
			cv = v
		case "authkey":
			authkey = v
		case "use_aes_gcm":
			gcm = v
		case "inform_url":
			informURL = v
		case "led_enabled":
			on := v == "true"
			if on != x.S.LED || !x.ledKnown {
				x.S.LED, x.ledKnown = on, true
				o.Changed = true
				o.Actions = append(o.Actions, Action(ActLED, onOff(on)))
			}
		}
	}
	if r.CfgVersion != "" {
		cv = r.CfgVersion // full provisioning carries it top-level too
	}
	ev := fmt.Sprintf("setparam: mgmt_cfg keys=%v", keys)
	if r.MgmtCfg != "" && r.MgmtCfg != x.S.MgmtCfg {
		x.S.MgmtCfg = r.MgmtCfg
		o.Changed = true
	}
	// "Override inform host" (or a migration): the controller names the
	// address to inform to and repeats the setparam until we report it.
	if informURL != "" && informURL != x.S.InformURL {
		if err := CheckInformURL(informURL); err == nil {
			ev += fmt.Sprintf(" inform_url %s -> %s", x.S.InformURL, informURL)
			x.S.InformURL = informURL
			o.Changed = true
		} else {
			ev += fmt.Sprintf(" (ignored inform_url %q: %v; keeping %s)", informURL, err, x.S.InformURL)
		}
	}
	o.CfgVersion = cv
	switch {
	case cv == "":
	case x.DeferCfgAck && cv == x.S.CfgVersion:
		if x.S.PendingCfgVersion != "" {
			// the controller is back at what is live
			x.S.PendingCfgVersion = ""
			o.Changed = true
		}
	case x.DeferCfgAck:
		if cv != x.S.PendingCfgVersion {
			ev += fmt.Sprintf(" cfgversion %s->%s pending (reported once live)", x.S.CfgVersion, cv)
			x.S.PendingCfgVersion = cv
			o.Changed = true
		}
	case cv != x.S.CfgVersion:
		ev += fmt.Sprintf(" cfgversion %s->%s", x.S.CfgVersion, cv)
		x.S.CfgVersion = cv
		o.Changed = true
	}
	// Take a new key only while still on the factory key (unifi-emu: the
	// classic stuck-adopt bug otherwise).
	if authkey != "" && authkey != inform.DefaultKeyHex {
		if x.S.Key == inform.DefaultKeyHex {
			x.S.Key = authkey
			x.setAdopted()
			o.Changed = true
			ev += " ADOPTED: new authkey stored"
		} else if authkey != x.S.Key {
			ev += " (ignored a different authkey: already hold a non-default key)"
		}
	}
	if gcm == "true" && !x.S.GCM {
		x.S.GCM = true
		o.Changed = true
		ev += " GCM on"
	}
	if r.SystemCfg != "" {
		x.S.SystemCfgN = len(r.SystemCfg)
		o.Changed = true
		o.SystemCfg = true
		path := filepath.Join(x.StateDir, SystemCfgFile)
		if err := os.WriteFile(path, []byte(r.SystemCfg), 0o600); err != nil {
			ev += " (saving system_cfg failed: " + err.Error() + ")"
		}
		// keep the last versions, to see what the controller changed; a
		// file named by an unset clock would sort wrong and be pruned first
		if now.Before(ClockSane) {
			ev += " (clock not set yet: no history copy)"
		} else {
			hist := filepath.Join(x.StateDir, SystemCfgHistoryDir)
			os.MkdirAll(hist, 0o700)
			os.WriteFile(filepath.Join(hist, now.Format("20060102-150405")+"-"+x.WantedCfgVersion()+".txt"), []byte(r.SystemCfg), 0o600)
			pruneHistory(hist, HistoryKeep)
		}
		ev += fmt.Sprintf(" system_cfg %d bytes saved (not applied), sections=%v", len(r.SystemCfg), sections(r.SystemCfg))
		if x.KnownSection != nil {
			for _, sec := range sections(r.SystemCfg) {
				if sec = strings.TrimSpace(sec); sec != "" && !strings.HasPrefix(sec, "#") && !x.KnownSection(sec) {
					x.note("system_cfg", sec, "", now, o)
				}
			}
		}
	}
	if r.BlockedSta != nil {
		ev += fmt.Sprintf(" blocked_sta=%d", len(strings.Fields(*r.BlockedSta)))
		x.setBlocked(ParseMACs(*r.BlockedSta), o)
	}
	o.Events = append(o.Events, ev)
	// A real device informs right after applying a setparam. If the
	// controller keeps sending the very same one (it wants something we do
	// not do), stop hurrying after the third and keep the normal interval.
	blocked := "-"
	if r.BlockedSta != nil {
		blocked = *r.BlockedSta
	}
	sum := sha256.Sum256([]byte(r.CfgVersion + "\x00" + r.MgmtCfg + "\x00" + r.SystemCfg + "\x00" + blocked))
	if sum == x.lastParam {
		x.sameParams++
	} else {
		x.lastParam, x.sameParams = sum, 0
	}
	o.Immediate = x.sameParams < 3
	if x.sameParams == 3 {
		o.Events = append(o.Events, "the controller repeats the same setparam: informing at the normal interval")
	}
}

// sections lists the top-level keys of system_cfg (e.g. "aaa", "radio",
// "wireless"), never their values: system_cfg carries the Wi-Fi passphrase.
func sections(cfg string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(cfg, "\n") {
		k, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		top, _, _ := strings.Cut(k, ".")
		if !seen[top] {
			seen[top] = true
			out = append(out, top)
		}
	}
	return out
}

func (x *Session) upgrade(version, url string, now time.Time, o *Outcome) {
	// Never download or apply anything. Report the target version and fake
	// a reboot so the controller does not loop on the upgrade.
	host := url
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	host, _, _ = strings.Cut(host, "/")
	o.Events = append(o.Events, fmt.Sprintf("UPGRADE requested to %q (from host %s): NOT applied, nothing downloaded; reporting the version and faking a reboot", version, host))
	if version != "" && version != x.S.Version {
		x.S.Version = version
		o.Changed = true
	}
	x.Boot = now
	o.Immediate = true
}

// setAdopted marks the state adopted, as the model reported now when it
// was not adopted before (a new key on an adopted state keeps its model,
// as the controller's record does).
func (x *Session) setAdopted() {
	if !x.S.Adopted {
		x.S.Model = x.Dev.Model
	}
	x.S.Adopted = true
}

func (x *Session) setdefault(o *Outcome) {
	x.S.Key = inform.DefaultKeyHex
	x.S.GCM = false
	x.S.Adopted = false
	x.S.Model = ""
	x.S.CfgVersion = "0"
	x.S.PendingCfgVersion = ""
	x.S.MgmtCfg = ""
	o.Changed = true
	o.Immediate = true
	o.Reset = true
	o.Events = append(o.Events, "setdefault: back to the factory key (the AP itself is not reset)")
}

func (x *Session) cmd(r Reply, js []byte, now time.Time, o *Outcome) {
	switch r.Cmd {
	case "set-adopt", "adopt":
		if r.Key != "" {
			x.S.Key = r.Key
			x.setAdopted()
		}
		uri := ""
		if r.URI != "" {
			if err := CheckInformURL(r.URI); err == nil {
				x.S.InformURL = r.URI
				uri = fmt.Sprintf(" uri=%q", r.URI)
			} else {
				uri = fmt.Sprintf(" (ignored uri %q: %v; keeping %s)", r.URI, err, x.S.InformURL)
			}
		}
		o.Changed = true
		o.Immediate = true
		o.Events = append(o.Events, fmt.Sprintf("cmd %s: key stored,%s", r.Cmd, uri))
	case "reboot", "restart":
		x.Boot = now
		o.Immediate = true
		o.Actions = append(o.Actions, ActReboot)
		o.Events = append(o.Events, "cmd "+r.Cmd+": reboot requested")
	case "locate", "set-locate", "locate-on":
		x.S.Locating = true
		o.Changed, o.Immediate = true, true
		o.Actions = append(o.Actions, Action(ActLocate, ArgOn))
		o.Events = append(o.Events, "cmd "+r.Cmd+": locate on")
	case "unset-locate", "locate-off", "stop-locate":
		x.S.Locating = false
		o.Changed, o.Immediate = true, true
		o.Actions = append(o.Actions, Action(ActLocate, ArgOff))
		o.Events = append(o.Events, "cmd "+r.Cmd+": locate off")
	case "setdefault":
		x.setdefault(o)
	case "upgrade":
		x.upgrade(r.Version, r.URL, now, o)
	case "kick-sta", "kick", "disassoc-sta":
		m := ParseMACs(r.MAC)
		if len(m) != 1 {
			o.Events = append(o.Events, fmt.Sprintf("cmd %s: bad mac %q: ignored", r.Cmd, r.MAC))
			break
		}
		o.Immediate = true
		o.Actions = append(o.Actions, Action(ActKick, m[0]))
		o.Events = append(o.Events, "cmd "+r.Cmd+": kick "+m[0])
	case "authorize-guest", "unauthorize-guest":
		m := ParseMACs(r.MAC)
		if len(m) != 1 {
			o.Events = append(o.Events, fmt.Sprintf("cmd %s: bad mac %q: ignored", r.Cmd, r.MAC))
			break
		}
		x.GuestMu.Lock()
		defer x.GuestMu.Unlock()
		if x.S.Guests == nil {
			x.S.Guests = map[string]int64{}
		}
		o.Changed, o.Immediate = true, true
		if r.Cmd == "unauthorize-guest" {
			delete(x.S.Guests, m[0])
			o.Actions = append(o.Actions, Action(ActGuestUnauth, m[0]))
			o.Events = append(o.Events, "cmd unauthorize-guest "+m[0])
			break
		}
		end := now.Add(8 * time.Hour).Unix() // the controller's default (expire 480 min)
		switch {
		case r.End > now.Unix():
			end = r.End
		case r.Minutes > 0:
			end = now.Add(time.Duration(r.Minutes) * time.Minute).Unix()
		}
		x.S.Guests[m[0]] = end
		o.Actions = append(o.Actions, Action(ActGuestAuth, m[0]))
		o.Events = append(o.Events, fmt.Sprintf("cmd authorize-guest %s until %s", m[0], time.Unix(end, 0).Format("15:04")))
	case "block-sta", "unblock-sta":
		m := ParseMACs(r.MAC)
		if len(m) != 1 {
			o.Events = append(o.Events, fmt.Sprintf("cmd %s: bad mac %q: ignored", r.Cmd, r.MAC))
			break
		}
		set := map[string]bool{}
		for _, b := range x.S.Blocked {
			set[b] = true
		}
		set[m[0]] = r.Cmd == "block-sta"
		var list []string
		for k, v := range set {
			if v {
				list = append(list, k)
			}
		}
		o.Events = append(o.Events, "cmd "+r.Cmd+" "+m[0])
		x.setBlocked(list, o)
	case "scan", "spectrum-scan":
		// neighbour scan / RF scan: the daemon scans the radios and reports
		// scan_table / spectrum_table (docs/internals.md)
		o.Immediate = true
		o.Actions = append(o.Actions, map[string]string{"scan": ActScan, "spectrum-scan": ActSpectrumScan}[r.Cmd])
		o.Events = append(o.Events, "cmd "+r.Cmd)
	case "quick-scan":
		// The controller's nightly channel optimisation: one band per cmd,
		// the next only after the AP reported the finished scan
		// (study-actions-scans.md). Action ActQuickScan with <band>:<bw>.
		if r.ScanBand == nil {
			o.Events = append(o.Events, "cmd quick-scan without scan-band: ignored")
			x.note("cmd", r.Cmd, redactReply(js), now, o)
			break
		}
		band, ok := QuickScanBands[int(*r.ScanBand)]
		if !ok {
			o.Events = append(o.Events, fmt.Sprintf("cmd quick-scan: unknown scan-band %d: ignored", *r.ScanBand))
			break
		}
		bw := 0
		if r.ScanBW != nil {
			bw = int(*r.ScanBW)
		}
		o.Immediate = true
		o.Actions = append(o.Actions, Action(ActQuickScan, band, strconv.Itoa(bw)))
		o.Events = append(o.Events, fmt.Sprintf("cmd quick-scan band=%s bw=%d", band, bw))
	case "rate-update":
		x.rateUpdate(r, js, now, o)
	default:
		o.Events = append(o.Events, fmt.Sprintf("cmd %q: ignored", r.Cmd))
		x.note("cmd", r.Cmd, redactReply(js), now, o)
	}
}

// rateUpdate records the controller's per-client speed limit (cmd
// rate-update: mac, dl_max, ul_max in kbit/s, -1 = no limit; sent when a
// client of a non-default user group shows up on the AP, and when its
// group or the group's limits change). Both -1 removes the client's entry.
// The ActRateUpdate action (with the MAC) asks the AP to apply the whole
// list.
func (x *Session) rateUpdate(r Reply, js []byte, now time.Time, o *Outcome) {
	m := ParseMACs(r.MAC)
	if len(m) != 1 {
		o.Events = append(o.Events, fmt.Sprintf("cmd rate-update: bad mac %q: ignored", r.MAC))
		return
	}
	if r.DLMax == nil && r.ULMax == nil {
		o.Events = append(o.Events, "cmd rate-update without dl_max/ul_max: ignored")
		x.note("cmd", r.Cmd, redactReply(js), now, o)
		return
	}
	lim := func(v *IntArg) int {
		if v == nil || *v <= 0 {
			return 0
		}
		return int(*v)
	}
	mac, down, up := m[0], lim(r.DLMax), lim(r.ULMax)
	old, had := x.S.ClientRates[mac]
	switch {
	case down == 0 && up == 0:
		if had {
			delete(x.S.ClientRates, mac)
			o.Changed = true
		}
	case !had || old.DownKbps != down || old.UpKbps != up:
		if x.S.ClientRates == nil {
			x.S.ClientRates = map[string]ClientRate{}
		}
		if !had && len(x.S.ClientRates) >= MaxClientRates {
			oldest := ""
			for k, v := range x.S.ClientRates {
				if oldest == "" || v.Set < x.S.ClientRates[oldest].Set || v.Set == x.S.ClientRates[oldest].Set && k < oldest {
					oldest = k
				}
			}
			delete(x.S.ClientRates, oldest)
			o.Events = append(o.Events, fmt.Sprintf("cmd rate-update: more than %d client limits, %s's dropped", MaxClientRates, oldest))
		}
		x.S.ClientRates[mac] = ClientRate{DownKbps: down, UpKbps: up, Set: now.Unix()}
		o.Changed = true
	}
	kb := func(n int) string {
		if n == 0 {
			return "none"
		}
		return strconv.Itoa(n) + "kbit"
	}
	o.Actions = append(o.Actions, Action(ActRateUpdate, mac))
	o.Events = append(o.Events, fmt.Sprintf("cmd rate-update %s down=%s up=%s", mac, kb(down), kb(up)))
}

// MaskHex hides 32-hex keys in a string (for logging raw replies).
func MaskHex(s string) string { return hex32.ReplaceAllString(s, "<masked>") }

// RestoreFromMgmtCfg re-reads settings carried by the last saved mgmt_cfg
// (LED) after a restart.
func (x *Session) RestoreFromMgmtCfg() {
	for _, line := range strings.Split(x.S.MgmtCfg, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "led_enabled="); ok {
			x.S.LED, x.ledKnown = v == "true", true
		}
	}
}

var macRe = regexp.MustCompile(`(?i)^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// ParseMACs reads a whitespace-separated MAC list (the blocked_sta wire
// format is newline-joined), lower-cased, sorted, without duplicates or
// malformed entries.
func ParseMACs(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range strings.Fields(s) {
		f = strings.ToLower(f)
		if macRe.MatchString(f) && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// setBlocked records the blocked-client list; a change asks the AP to
// enforce it (ActBlock).
func (x *Session) setBlocked(list []string, o *Outcome) {
	sort.Strings(list)
	if strings.Join(list, " ") == strings.Join(x.S.Blocked, " ") {
		return
	}
	now := map[string]bool{}
	for _, m := range list {
		now[m] = true
	}
	for _, m := range x.S.Blocked {
		if !now[m] {
			o.Actions = append(o.Actions, Action(ActUnblock, m))
		}
	}
	x.S.Blocked = list
	o.Changed = true
	o.Actions = append(o.Actions, ActBlock)
	o.Events = append(o.Events, fmt.Sprintf("blocked clients now %d", len(list)))
}

// HistoryKeep is how many system_cfg versions are kept (on an AP the state
// directory is on flash: it must not grow).
var HistoryKeep = 20

// pruneHistory keeps the newest n files in dir (names sort by time).
func pruneHistory(dir string, n int) {
	es, err := os.ReadDir(dir)
	if err != nil || len(es) <= n {
		return
	}
	var names []string
	for _, e := range es {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names[:max(0, len(names)-n)] {
		os.Remove(filepath.Join(dir, name))
	}
}
