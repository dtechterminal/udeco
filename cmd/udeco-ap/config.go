// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/decosys"
	"github.com/dtechterminal/udeco/internal/device"
	"github.com/dtechterminal/udeco/internal/inform"
	"github.com/dtechterminal/udeco/internal/jioports"
	"github.com/dtechterminal/udeco/internal/models"
	"github.com/dtechterminal/udeco/internal/rf"
	"github.com/dtechterminal/udeco/internal/unit"
)

// DefaultConfigPath is where persist_shell.sh starts the agent from.
const DefaultConfigPath = unit.DecoDir + "/" + unit.ConfigFile

// Config is /tp_data/udeco/udeco-ap.json (agent-design.md §3.5). Unknown
// keys are an error, so a typo never silently turns a safety switch off or on.
type Config struct {
	InformURL string `json:"inform_url"` // http://<controller>:8080/inform (IPv4 host)
	ConsoleIP string `json:"console_ip"` // the only address allowed to SSH-adopt on SSHDPort
	Model     string `json:"model"`      // models.DecoAgentModel on a Deco (the default); a models.JCOW414Models code on platform jio-mtk
	SSHDPort  int    `json:"sshd_port"`  // SSH-adopt responder (default decosys.DefaultSSHDPort); never 22 (the unit's real dropbear)
	Takeover  bool   `json:"takeover"`   // false = observe: inform only, nothing on the unit changes
	Apply     bool   `json:"apply"`      // takeover: apply the controller's Wi-Fi (false = plans logged only)
	Egress    bool   `json:"egress"`     // takeover: block the unit's own traffic beyond the LAN
	Log       string `json:"log"`        // logSyslog (the default) or logStderr
	// MgmtSources are the only sources (IPv4/IPv6 addresses or CIDRs)
	// allowed to SSH :22 once takeover installs the inbound fence (R5).
	// Empty (the default) accepts :22 from the whole LAN and never drops
	// it, so a fence cannot lock the user out.
	MgmtSources []string `json:"mgmt_sources,omitempty"`
	// MinRates (takeover only) applies the controller's minimum data rates
	// as each BSS's wl rateset (bcmwifi.Options.MinRates). Off by default
	// until `wl rateset` per BSS is verified on the X20 (minrate.go). On
	// platform jio-mtk it sets the 2.4 GHz radio's BasicRate (mtkwifi; the
	// 5 GHz driver forces its own basic rates, so a 5 GHz minimum is only
	// noted); off, the agent drops the minimums before the plan
	// (jioMinRates).
	MinRates bool `json:"min_rates,omitempty"`
	// WPA3 (takeover only) claims radio_caps2 WPA3 and lets bcmwifi serve
	// SAE (bcmwifi.Options.WPA3). Off by default until SAE is verified on
	// the X20: radio_caps2 is then 0, so the controller sends WPA2/WPA3
	// WLANs as WPA2 and no WPA3-only WLAN, and bcmwifi serves a WPA2/WPA3
	// SSID as WPA2 should one arrive (wpa3.go).
	WPA3 bool `json:"wpa3,omitempty"`
	// DriverCountry (e.g. "US") is the regulatory domain the radios run in
	// instead of the controller's site country. Stock TP-Link firmware runs
	// the X20 as US/0 whatever the region; this driver's IN/0 table allows
	// no 80 MHz chanspec at all ("Bad Channel" for 36/80..161/80, verified
	// on .205 2026-11-19), so the site country India caps 5 GHz at 40 MHz.
	// Empty uses the controller's country.
	DriverCountry string `json:"driver_country,omitempty"`
	// DriverCountryBands overrides the country of one radio ("ng" or
	// "na"), over driver_country for that band. IN/288 caps the X20's
	// 2.4 GHz at 14 dBm (US/0: 24) and 5 GHz 36-48 at 16.5 dBm (US/0:
	// 23.5), but only it has the DFS channels, at 23.5-25 dBm: {"ng": "US"}
	// gives full power on both bands with DFS on 5 GHz (read on .232
	// 2026-11-20). But IN/288 (and every real country here except US/0)
	// disables Wi-Fi 6 rates, and US/0 has no DFS. "#a", Broadcom's
	// all-channels table, has both but runs no radar detection; under it
	// the agent refuses channels 120-128 (weather radar). Takeover only.
	DriverCountryBands map[string]string `json:"driver_country_bands,omitempty"`
	// DriverDTIMBands overrides the DTIM period of one radio ("ng" or
	// "na") for every SSID it serves, over the controller's (UniFi sends
	// 1 on 2.4 GHz unless a WLAN sets its own). The JCOW414 runs one DTIM
	// per radio, the lowest its SSIDs ask (mtkwifi features.go), so a
	// WLAN shared with the Decos keeps it at 1 there; this key sets the
	// Garage alone. Its stock firmware ran 2 on 2.4 GHz. 1-255, takeover
	// only.
	DriverDTIMBands map[string]int `json:"driver_dtim_bands,omitempty"`
	// FTSAE is the kill switch for FT-SAE (802.11r for WPA3 clients) on top
	// of wpa3: absent or true serves it (bcmwifi.Options.FTSAE, the agents
	// learning each other's key holders: ftsae.go) and claims radio_caps2
	// WPA3 fast roaming; false keeps WPA3 clients on a full SAE at every
	// roam (FT-PSK for WPA2 clients is not affected). Only with wpa3.
	FTSAE *bool `json:"ft_sae,omitempty"`
	// DownlinkWatchdog is the kill switch for the Garage's downlink
	// watchdog (mtkwifi stuckps.go): absent or true disconnects a station
	// the driver holds dozing while ARP probes to it go unanswered, so it
	// re-associates at once instead of ~300 s later; false leaves such a
	// station to recover by itself. jio-mtk with takeover only.
	DownlinkWatchdog *bool `json:"downlink_watchdog,omitempty"`
	// MdnsBridge (takeover with apply only, both platforms) claims fw2_caps
	// mDNS service bridge and runs internal/mdnsbr (mdnsbr.go; on jio-mtk
	// over bdg2 and the br-v<vid> bridges, the ra/rai BSSes). Off by default
	// until AF_PACKET sends on the vifs are verified on the units: the
	// controller puts every "auto" WLAN in mDNS auto mode once the bit is
	// claimed, and an intercepted vif whose re-injection did not reach the
	// air would lose all mDNS (docs/deco/features/mdns-bridge.md).
	MdnsBridge bool `json:"mdns_bridge,omitempty"`
	// Hotspot2 (takeover only) claims fw_caps Hotspot 2.0, so the
	// controller sends hotspot2conf and bcmwifi renders it (hs20.go). Off
	// by default until the Interworking IE and GAS path through wl is
	// verified on the X20 (docs/deco/features/hotspot2.md).
	Hotspot2 bool `json:"hotspot2,omitempty"`
	// Platform is the unit the agent runs on: "" = a TP-Link Deco X20
	// (Broadcom, model UAL6); "jio-mtk" = a JioFiber JCOW414 used as a plain
	// AP (MediaTek, model U7LT or UHDIW; internal/mtkwifi, internal/jiosys).
	// As UHDIW (UAP-IW-HD) the unit's LAN ports 1-3 show in UniFi as the
	// in-wall AP's front ports 1-3 and its port 4 (the uplink) as the rear
	// port 5, and the controller's port VLANs are applied to ports 1-3
	// (internal/jioports, ports.go).
	Platform string `json:"platform,omitempty"`
	// PortsUnlocked (platform jio-mtk, model UHDIW) lists the LAN ports
	// (jioports.LANPorts, 1-3) whose VLANs the controller may change. Ports
	// 2 and 3 always may; port 1 (the tenant's router) only when listed
	// here, so its untagged LAN stays as it is whatever the controller
	// sends. Port 4 (jioports.UplinkPhys) is the uplink and is never
	// changed (beyond the VLAN devices on it).
	PortsUnlocked []int `json:"ports_unlocked,omitempty"`
	// PortsConfirmS (model UHDIW) is how long a port change waits for an
	// inform the controller answers before it is reverted. PortsLossS is
	// how long the controller may stay unreachable before every port the
	// agent may change goes back on the LAN. Seconds; the range each takes
	// and what 0 (absent) stands for: portsConfirmKey, portsLossKey. The
	// port monitor: ports.go.
	PortsConfirmS int `json:"ports_confirm_s,omitempty"`
	PortsLossS    int `json:"ports_loss_s,omitempty"`
	// SiteSurvey (platform jio-mtk) lets the controller's scan commands
	// run the MediaTek driver's site survey (`iwpriv <radio> set
	// SiteSurvey=1`, mtkwifi.CollectorOptions.FreshScan), which takes the
	// radio off its channel for a few seconds: `cmd scan` surveys both
	// bands, and `cmd spectrum-scan` and `cmd quick-scan`, which have no
	// spectrum runner on that unit, survey their band(s) and report
	// scan_table only (sitesurvey.go). RF_SCAN is claimed with it. Never
	// periodic, never during a radio restart or its settle time. Off by
	// default: the agent then claims no RF_SCAN and only the driver's
	// cached survey feeds the neighbour list. Needs takeover (observe mode
	// runs no scans); ignored, with a log line, on the Deco (wl scans).
	SiteSurvey bool `json:"site_survey,omitempty"`
	// TWT (takeover, Deco only) is 802.11ax Target Wake Time on both
	// radios: absent or true turns it on (`wl twt enab 1`), as a real U6
	// Pro sets twt_responder 3 on every VAP whatever the controller sends;
	// false keeps TP-Link's off (`twt enab 0`), for a client population
	// that handles TWT badly. bcmwifi.Options.NoTWT: the driver takes it
	// only while the radio is down, so it is set inside a radio restart
	// the agent makes anyway (a takeover, a channel, country or hostapd
	// change), never by a restart of its own; the hand-back restores
	// TP-Link's state (internal/bcmwifi/twt.go).
	TWT *bool `json:"twt,omitempty"`
	// RxDesense (takeover, Deco only) keeps TP-Link's glitch-based receiver
	// desense (bit 0x1 of the radios' interference mitigation mode, 361 on
	// the X20). Absent or false clears it, as a U6 Pro runs ani_enable 0
	// (bcmwifi.Options.KeepDesense, internal/bcmwifi/parity.go): the opt-out
	// is there because desense also protects against adjacent-channel
	// interference, and which way edge clients fare is not measured.
	RxDesense bool `json:"rx_desense,omitempty"`
	// UplinkSSIDDown (takeover, Deco only): absent or true takes every SSID
	// down while the uplink port has no carrier (5 s), as a U6 does, and
	// back up after 10 s of carrier; false leaves them up (uplink.go).
	UplinkSSIDDown *bool `json:"uplink_ssid_down,omitempty"`
	// UplinkGatewayDown (default off; needs uplink_ssid_down) also counts a
	// gateway that answers no ICMP echo for 60 s as a lost uplink.
	UplinkGatewayDown bool `json:"uplink_gateway_down,omitempty"`
	// StaSnoop (takeover, both platforms): absent or true sends the
	// controller the connection-timing events (success, failure, soft
	// failure, fixup) from hostapd's log and control sockets (Deco) or the
	// MediaTek drivers' station events (jio-mtk: mtkwifi Events steps) and a
	// read-only AF_PACKET tap per served BSS (ARP, DHCP, DNS; staconn.go);
	// false sends none.
	StaSnoop *bool `json:"sta_snoop,omitempty"`
	// AssocGARP (takeover, both platforms; on the Deco it needs sta_snoop
	// for the addresses): absent or true sends a gratuitous ARP for a
	// station that is authorized and whose address is known, on the wired
	// ports of its bridge, so the switches learn where it is at once
	// (garp.go). On jio-mtk it is the Garage's station GARP on the uplink
	// (garage.go garageStations, mtkwifi AnnounceStation); false turns it off.
	AssocGARP *bool `json:"assoc_garp,omitempty"`
	// UplinkLoss (platform jio-mtk, takeover with apply) is the U6's
	// uplink-loss behaviour: absent or true, after 15 s without carrier on
	// the uplink port the user and guest SSIDs go down and one management
	// SSID (UplinkLossSSID, else the first LAN SSID) stays up, so the GL
	// KVM side door can still join; every SSID comes back after 30 s of
	// carrier, never isolating again within 5 minutes of a restore. Each
	// change restarts the radios whose SSIDs change. false keeps every
	// SSID up whatever the uplink does (mtkwifi uplinkloss.go, garage.go).
	UplinkLoss *bool `json:"uplink_loss,omitempty"`
	// UplinkLossSSID is the SSID kept up while the uplink is down (an
	// SSID name the controller serves on this unit); "" = the first SSID
	// on the LAN (no VLAN, not a guest SSID). Not served: nothing is taken
	// down.
	UplinkLossSSID string `json:"uplink_loss_ssid,omitempty"`
	// BSSPinning (platform jio-mtk) keeps each WLAN on its own driver
	// profile slot (netdev and BSSID) while other WLANs come and go
	// (schedules, disabled WLANs), as a U6 has one VAP per WLAN; slot 0
	// always carries a WLAN, one without a schedule when there is one.
	// Off by default until the single-BSS down/up test passed on the unit
	// (mtkwifi slots.go, docs/deco/features/garage-parity.md).
	BSSPinning bool `json:"bss_pinning,omitempty"`
	// ProxyARP (platform jio-mtk) answers ARP requests for the stations
	// of the WLANs the controller set proxy ARP on (mtkwifi proxyarp.go);
	// false leaves the requests going out on the air. On by default.
	ProxyARP *bool `json:"proxy_arp,omitempty"`
	// ProxyARPDriver (platform jio-mtk, needs proxy_arp) has the MT7663
	// drop the 5 GHz requests itself (hs_flag=3, its 0x93b events to the
	// agent's responder) instead of the agent-side learning and ebtables
	// drop. Off by default: garage-final proxyarp says not to enable the
	// driver flag by default (unverified on the unit; with no responder
	// it black-holes inbound ARP to the BSS).
	ProxyARPDriver bool `json:"proxy_arp_driver,omitempty"`
	// DFS (platform jio-mtk) lets the 5 GHz radio serve the controller's
	// DFS channels 52-64 (the driver's region goes from 10 to 0 live, a
	// 65 s channel availability check, radar followed and reported as
	// EVT_AP_RadarDetected; mtkwifi dfs.go) and claims has_dfs. Off by
	// default until the region check of docs/deco/features/garage-parity.md
	// passed on the unit.
	DFS bool `json:"dfs,omitempty"`
	// RateLimits (platform jio-mtk) polices the controller's speed limits
	// (a client's user group by cmd rate-update, the WLANs' user groups)
	// per station with the agent's udeco_rl kernel module, loaded from
	// /flash2/udeco only while a limit is set and removed at the hand-back
	// (mtkwifi ratelimit.go, docs/deco/features/client-rate-limit.md).
	// Off by default until the test of garage-parity.md passed on the
	// unit: the limits are then noted as not applied.
	RateLimits bool `json:"rate_limits,omitempty"`
	// Enterprise (platform jio-mtk) serves the controller's WPA2/WPA3-
	// Enterprise WLANs through Jio's rtdot1xd, which the agent starts and
	// supervises per radio (mtkwifi dot1x.go; 2.4 GHz with the rebuilt
	// MT7603 module only). On by default; false never starts rtdot1xd and
	// leaves those WLANs off (noted), as before, and RadSec unclaimed.
	Enterprise *bool `json:"enterprise,omitempty"`
	// GarageFT (platform jio-mtk) serves the controller's 802.11r on the
	// Garage with the Decos' mobility domains and key holders (FT-PSK;
	// FT-SAE with wpa3 and ft_sae), the agent's 802.11k neighbour lists and
	// 802.11v requests (band steering, Roaming Assistant), and claims those
	// (mtkwifi ftplan.go, roam.go; docs/deco/features/garage-ft.md). Off by
	// default until the roaming test there passed on the unit: the FT AKMs
	// in the RSNE change every SSID's beacon (some old clients refuse them)
	// and turning it on restarts each radio once; off, the controller's FT
	// is noted as not served, as before.
	GarageFT bool `json:"garage_ft,omitempty"`
	// LoginLock (takeover with apply, both platforms): absent or true
	// drops new connections to the unit's root login ports (Deco :22;
	// Garage :23 and :22) while the controller's Device SSH Authentication
	// is off and the controller answers; anything else leaves them open
	// (loginlock.go, docs/deco/features/login-lock.md). false never locks.
	LoginLock *bool `json:"login_lock,omitempty"`
	// LoginLockFailOpenS is how long the controller may stay silent (no
	// reply that decodes with the device key) before the lock opens.
	// Seconds; range and default: loginLockFailOpenKey.
	LoginLockFailOpenS int `json:"login_lock_failopen_s,omitempty"`
	// InformEveryS is a minimum inform rate of the agent's own: the next
	// inform is at most this many seconds after the last answered one,
	// whatever longer interval the controller asks for (it paces unwatched
	// devices at about 30 s). Absent or 0: the controller's interval.
	// Seconds; range: informEveryKey.
	InformEveryS int `json:"inform_every_s,omitempty"`
}

// The values of the log key.
const (
	logSyslog = "syslog"
	logStderr = "stderr"
)

// secondsKey is a config key that holds a time in whole seconds: the range
// a set value must be in and the value an absent key (0) stands for. The
// range check, its error text and the key's accessor all read it, and the
// documents that give its numbers (README.md, docs/deco/agent-design.md,
// docs/deco/features/login-lock.md) are held to it (TestDocsSecondsKeys).
type secondsKey struct {
	name          string // the JSON key
	min, max, def int    // seconds
}

var (
	// ports_confirm_s. Under 60 s a healthy controller can miss the
	// window: an inform in flight and the next one each take up to
	// collectTO + informTO, 30 s.
	portsConfirmKey = secondsKey{name: "ports_confirm_s", min: 60, max: 900, def: 90}
	// ports_loss_s
	portsLossKey = secondsKey{name: "ports_loss_s", min: 60, max: 3600, def: 300}
	// login_lock_failopen_s, the login lock's silence window
	loginLockFailOpenKey = secondsKey{name: "login_lock_failopen_s", min: 60, max: 3600, def: 600}
	// inform_every_s, the agent's own minimum inform rate (0: off)
	informEveryKey = secondsKey{name: "inform_every_s", min: 5, max: 60, def: 0}
)

// check refuses a set value (v != 0) outside the key's range.
func (k secondsKey) check(v int) error {
	if v != 0 && (v < k.min || v > k.max) {
		return fmt.Errorf("config: %s %d: want %d-%d seconds (default %d)", k.name, v, k.min, k.max, k.def)
	}
	return nil
}

// of is the key's time for the value v: the default when the key is absent.
func (k secondsKey) of(v int) time.Duration {
	if v == 0 {
		v = k.def
	}
	return time.Duration(v) * time.Second
}

// keySet is a config key by its JSON name and whether the config sets it.
// A check on a group of keys takes its condition and the names in its
// message from one list of these (TestConfigKeyGroups holds each entry to
// the field with that JSON tag).
type keySet struct {
	name string
	set  bool
}

func anySet(ks []keySet) bool {
	return slices.ContainsFunc(ks, func(k keySet) bool { return k.set })
}

// keyNames lists the keys' names as a message does: "a", "a and b",
// "a, b and c".
func keyNames(ks []keySet) string {
	names := make([]string, len(ks))
	for i, k := range ks {
		names[i] = k.name
	}
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// decoOnlyKeys are the keys platform jio-mtk refuses. Not among them:
// wpa3 (SAE on the 5 GHz radio only: the MT7663 driver has it), min_rates
// (the 2.4 GHz radio's BasicRate, mtkwifi minRate), mdns_bridge
// (internal/mdnsbr on bdg2 and the br-v<vid> bridges), sta_snoop (the
// connection-timing events from the MediaTek drivers' own events and the
// same taps: staconn.go) and assoc_garp (the Garage's station GARP,
// garage.go). twt stays here: neither the MT7603 (802.11n) nor the MT7663
// (802.11ac) has Target Wake Time, an 802.11ax feature.
func (c *Config) decoOnlyKeys() []keySet {
	return []keySet{{"hotspot2", c.Hotspot2}, {"egress", c.Egress},
		{"twt", c.TWT != nil}, {"uplink_ssid_down", c.UplinkSSIDDown != nil},
		{"uplink_gateway_down", c.UplinkGatewayDown}, {"rx_desense", c.RxDesense}}
}

// jioOnlyKeys are the keys only platform jio-mtk takes
// (docs/deco/features/garage-parity.md lists them), the LAN ports' keys
// (portKeys) aside.
func (c *Config) jioOnlyKeys() []keySet {
	return []keySet{{"uplink_loss", c.UplinkLoss != nil}, {"uplink_loss_ssid", c.UplinkLossSSID != ""},
		{"bss_pinning", c.BSSPinning}, {"proxy_arp", c.ProxyARP != nil},
		{"proxy_arp_driver", c.ProxyARPDriver}, {"dfs", c.DFS}, {"rate_limits", c.RateLimits},
		{"enterprise", c.Enterprise != nil}, {"garage_ft", c.GarageFT}}
}

// The LAN ports' keys (platform jio-mtk as the model with LAN ports):
// ports_unlocked, the port monitor's two times, and all three.
func (c *Config) portsUnlockedKey() keySet {
	return keySet{"ports_unlocked", len(c.PortsUnlocked) > 0}
}

func (c *Config) portTimerKeys() []keySet {
	return []keySet{{portsConfirmKey.name, c.PortsConfirmS != 0}, {portsLossKey.name, c.PortsLossS != 0}}
}

func (c *Config) portKeys() []keySet {
	return append([]keySet{c.portsUnlockedKey()}, c.portTimerKeys()...)
}

// loginLock: the login lock runs (takeover with apply, unless login_lock
// is false).
func (c *Config) loginLock() bool {
	return c.Takeover && c.Apply && (c.LoginLock == nil || *c.LoginLock)
}

// informEvery is the agent's own longest wait between answered informs
// (0: the controller's interval alone).
func (c *Config) informEvery() time.Duration { return informEveryKey.of(c.InformEveryS) }

func (c *Config) loginLockFailOpen() time.Duration {
	return loginLockFailOpenKey.of(c.LoginLockFailOpenS)
}

// uplinkLoss: the SSIDs are isolated on uplink loss (platform jio-mtk)
// unless uplink_loss is false.
func (c *Config) uplinkLoss() bool { return c.jio() && (c.UplinkLoss == nil || *c.UplinkLoss) }

// proxyARP: the controller's proxy ARP is served (platform jio-mtk; on
// unless proxy_arp is false).
func (c *Config) proxyARP() bool { return c.jio() && (c.ProxyARP == nil || *c.ProxyARP) }

// enterprise: jio-mtk serves WPA2/WPA3-Enterprise (rtdot1xd).
func (c *Config) enterprise() bool { return c.jio() && (c.Enterprise == nil || *c.Enterprise) }

func (c *Config) portsConfirm() time.Duration { return portsConfirmKey.of(c.PortsConfirmS) }

func (c *Config) portsLoss() time.Duration { return portsLossKey.of(c.PortsLossS) }

// PlatformJio is the JioFiber JCOW414 (MediaTek) platform.
const PlatformJio = "jio-mtk"

func (c *Config) jio() bool { return c != nil && c.Platform == PlatformJio }

// hasLANPorts reports whether the configured model is reported with LAN
// ports: one with a rear uplink jack (models.RearUplinkPort, the rule the
// profile's switch bits follow). Of the models the agent takes that is the
// UAP-IW-HD, on platform jio-mtk.
func (c *Config) hasLANPorts() bool {
	m, ok := models.Lookup(c.Model)
	return ok && m.RearUplinkPort() > 0
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfig(b)
}

// defaultConfig is what parseConfig starts from: the value of every key
// with a default other than its zero value. deploy/deco-ap.sh writes the
// same three into a new unit's config (TestDeployDefaultConfig).
func defaultConfig() *Config {
	return &Config{Model: models.DecoAgentModel, SSHDPort: decosys.DefaultSSHDPort, Log: logSyslog}
}

func parseConfig(b []byte) (*Config, error) {
	c := defaultConfig()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("config: trailing data after the JSON object")
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	// plain HTTP to an IPv4 literal: the agent's HTTP client has no TLS
	// (post.go), and egress allows the controller by address (a name would
	// need DNS, which egress blocks outside the LAN). The same check guards
	// every later change of the URL (setparam, cmd set-adopt, SSH).
	if err := device.CheckInformURL(c.InformURL); err != nil {
		return fmt.Errorf("config: inform_url %q: %v (want http://<controller ipv4>:8080/inform)", c.InformURL, err)
	}
	if ip := net.ParseIP(c.ConsoleIP); ip == nil || ip.To4() == nil {
		return fmt.Errorf("config: console_ip %q: want an IPv4 address", c.ConsoleIP)
	}
	c.Model = strings.ToUpper(c.Model)
	switch c.Platform {
	case "":
		if c.Model != models.DecoAgentModel {
			return fmt.Errorf("config: model %q: only %s is supported (its capability words are chosen for this hardware)", c.Model, models.DecoAgentModel)
		}
	case PlatformJio:
		if !models.JCOW414Models[c.Model] {
			return fmt.Errorf("config: model %q: platform %s is reported as %s (UAP-AC-Lite) or %s (UAP-IW-HD, with its LAN ports): set \"model\": %q or %q",
				c.Model, c.Platform, models.ModelU7LT, models.ModelUHDIW, models.ModelU7LT, models.ModelUHDIW)
		}
		unlocked, timers := c.portsUnlockedKey(), c.portTimerKeys()
		if unlocked.set && !c.hasLANPorts() {
			return fmt.Errorf("config: %s needs model %s (the only model reported with LAN ports)", unlocked.name, models.ModelUHDIW)
		}
		if anySet(timers) && !c.hasLANPorts() {
			return fmt.Errorf("config: %s need model %s (the only model reported with LAN ports)", keyNames(timers), models.ModelUHDIW)
		}
		if err := portsConfirmKey.check(c.PortsConfirmS); err != nil {
			return err
		}
		if err := portsLossKey.check(c.PortsLossS); err != nil {
			return err
		}
		seen := map[int]bool{}
		for _, p := range c.PortsUnlocked {
			if lan := jioports.LANPorts; !slices.Contains(lan, p) || seen[p] {
				return fmt.Errorf("config: %s %v: want distinct LAN ports %d-%d (port %d is the uplink and is never changed)",
					unlocked.name, c.PortsUnlocked, lan[0], lan[len(lan)-1], jioports.UplinkPhys)
			}
			seen[p] = true
		}
		for _, k := range c.decoOnlyKeys() {
			if k.set {
				return fmt.Errorf("config: %s is not supported on platform %s", k.name, c.Platform)
			}
		}
	default:
		return fmt.Errorf("config: platform %q: want \"\" (Deco) or %q", c.Platform, PlatformJio)
	}
	if ks := c.jioOnlyKeys(); anySet(ks) && !c.jio() {
		return errors.New("config: " + keyNames(ks) + " are for platform " + PlatformJio + " only")
	}
	if c.ProxyARPDriver && !c.proxyARP() {
		return errors.New("config: proxy_arp_driver needs proxy_arp")
	}
	if ks := c.portKeys(); anySet(ks) && !c.jio() {
		return errors.New("config: " + keyNames(ks) + " are for platform " + PlatformJio + " only")
	}
	if c.SSHDPort < 1 || c.SSHDPort > 65535 || c.SSHDPort == 22 {
		return fmt.Errorf("config: sshd_port %d: want 1-65535 and never 22 (the unit's own dropbear)", c.SSHDPort)
	}
	if c.Apply && !c.Takeover {
		return errors.New("config: apply needs takeover (observe mode never changes the unit)")
	}
	if c.Egress && !c.Takeover {
		return errors.New("config: egress needs takeover (observe mode never changes the unit)")
	}
	if c.MinRates && !c.Takeover {
		return errors.New("config: min_rates needs takeover (observe mode never changes the unit)")
	}
	if c.FTSAE != nil && *c.FTSAE && !c.WPA3 {
		return errors.New("config: ft_sae needs wpa3 (FT-SAE is 802.11r for SAE clients)")
	}
	if c.WPA3 && !c.Takeover {
		return errors.New("config: wpa3 needs takeover (observe mode serves no Wi-Fi of its own)")
	}
	if c.MdnsBridge && (!c.Takeover || !c.Apply) {
		return errors.New("config: mdns_bridge needs takeover and apply (the bridge sends frames on the agent's own vifs)")
	}
	if c.Hotspot2 && !c.Takeover {
		return errors.New("config: hotspot2 needs takeover (observe mode serves no Wi-Fi of its own)")
	}
	if c.TWT != nil && !c.Takeover {
		return errors.New("config: twt needs takeover (observe mode never changes the unit)")
	}
	if len(c.DriverCountryBands) > 0 && !c.Takeover {
		return errors.New("config: driver_country_bands needs takeover (observe mode never changes the unit)")
	}
	if err := validDriverCountryBands(c.DriverCountryBands); err != nil {
		return err
	}
	if len(c.DriverDTIMBands) > 0 && !c.Takeover {
		return errors.New("config: driver_dtim_bands needs takeover (observe mode never changes the unit)")
	}
	if err := validDriverDTIMBands(c.DriverDTIMBands); err != nil {
		return err
	}
	if c.RxDesense && !c.Takeover {
		return errors.New("config: rx_desense needs takeover (observe mode never changes the unit)")
	}
	if (c.UplinkSSIDDown != nil || c.UplinkGatewayDown) && !c.Takeover {
		return errors.New("config: uplink_ssid_down and uplink_gateway_down need takeover (observe mode never changes the unit)")
	}
	if (c.StaSnoop != nil || c.AssocGARP != nil) && !c.Takeover {
		return errors.New("config: sta_snoop and assoc_garp need takeover (the BSSes are the agent's only then)")
	}
	// the Garage's GARP takes the addresses from the unit's ARP table and
	// the proxy ARP responder, not only from the taps
	if c.AssocGARP != nil && *c.AssocGARP && !c.staSnoopOn() && !c.jio() {
		return errors.New("config: assoc_garp needs sta_snoop (the stations' addresses come from it)")
	}
	if c.UplinkGatewayDown && !c.uplinkSSIDDown() {
		return errors.New("config: uplink_gateway_down needs uplink_ssid_down")
	}
	if c.LoginLock != nil && *c.LoginLock && (!c.Takeover || !c.Apply) {
		return errors.New("config: login_lock needs takeover and apply (observe mode never changes the unit)")
	}
	if err := loginLockFailOpenKey.check(c.LoginLockFailOpenS); err != nil {
		return err
	}
	if err := informEveryKey.check(c.InformEveryS); err != nil {
		return err
	}
	if c.LoginLockFailOpenS != 0 && !c.loginLock() {
		return errors.New("config: " + loginLockFailOpenKey.name + " needs the login lock (takeover and apply, login_lock not false)")
	}
	if c.SiteSurvey && !c.Takeover {
		return errors.New("config: site_survey needs takeover (observe mode runs no scans and claims no RF scan)")
	}
	for _, m := range c.MgmtSources {
		if net.ParseIP(m) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(m); err != nil {
			return fmt.Errorf("config: mgmt_sources %q: want an IP address or a CIDR", m)
		}
	}
	switch c.Log {
	case logSyslog, logStderr:
	default:
		return fmt.Errorf("config: log %q: want %s or %s", c.Log, logSyslog, logStderr)
	}
	return nil
}

// controllerIP is the inform URL's host (validated as IPv4).
// ftSAE: FT-SAE is served, with wpa3, unless ft_sae is false.
//
// Default on with wpa3 because the failure modes are bounded: the
// controller sends WPA3 fast roaming only for a WLAN where the user turned
// it on; a station roaming to a unit that does not list its first AP (not
// learnt yet, or not running the agent) is refused at once by hostapd
// ("unknown R0KH", no pull wait) and does a full SAE, which is what it
// would do without FT-SAE; and the per-band mobility domain keeps stations
// from trying FT between the two radios of one unit, which hostapd 2.9
// cannot serve. ft_sae false is for a client population that handles a
// refused FT authentication badly.
func (c *Config) ftSAE() bool { return c.WPA3 && (c.FTSAE == nil || *c.FTSAE) }

// downlinkWatchdog: the downlink watchdog runs unless the key is false.
func (c *Config) downlinkWatchdog() bool { return c.DownlinkWatchdog == nil || *c.DownlinkWatchdog }

// twt: TWT is on unless the twt key is false.
func (c *Config) twt() bool { return c.TWT == nil || *c.TWT }

func (c *Config) controllerIP() string { return inform.URLHost(c.InformURL) }

// validDriverDTIMBands: keys the radios' bands (rf.Bands: "ng", "na"),
// periods 1-255.
func validDriverDTIMBands(m map[string]int) error {
	for b, v := range m {
		if bands := rf.Bands(); !slices.Contains(bands, b) {
			return fmt.Errorf("config: driver_dtim_bands: band %q is not %s", b, strings.Join(bands, " or "))
		}
		if v < 1 || v > 255 {
			return fmt.Errorf("config: driver_dtim_bands: %s period %d is not 1-255", b, v)
		}
	}
	return nil
}

// validDriverCountryBands: keys the radios' bands (rf.Bands: "ng", "na"),
// values driver countries (bcmwifi.ValidCountry: a two-letter code, or
// "#a", Broadcom's all-channels table with no radar detection and Wi-Fi 6
// on 52-144).
func validDriverCountryBands(m map[string]string) error {
	for b, c := range m {
		if bands := rf.Bands(); !slices.Contains(bands, b) {
			return fmt.Errorf("config: driver_country_bands: band %q is not %s", b, strings.Join(bands, " or "))
		}
		if !bcmwifi.ValidCountry(c) {
			return fmt.Errorf("config: driver_country_bands: %s country %q is not a two-letter code", b, strings.TrimSpace(c))
		}
	}
	return nil
}
