// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/models"
)

// DefaultConfigPath is where persist_shell.sh starts the agent from.
const DefaultConfigPath = "/tp_data/udeco/udeco-ap.json"

// Config is /tp_data/udeco/udeco-ap.json (agent-design.md §3.5). Unknown
// keys are an error, so a typo never silently turns a safety switch off or on.
type Config struct {
	InformURL string `json:"inform_url"` // http://<controller>:8080/inform (IPv4 host)
	ConsoleIP string `json:"console_ip"` // the only address allowed to SSH-adopt on SSHDPort
	Model     string `json:"model"`      // UAL6 (the only model with deliberate capability words)
	SSHDPort  int    `json:"sshd_port"`  // SSH-adopt responder; never 22 (the unit's real dropbear)
	Takeover  bool   `json:"takeover"`   // false = observe: inform only, nothing on the unit changes
	Apply     bool   `json:"apply"`      // takeover: apply the controller's Wi-Fi (false = plans logged only)
	Egress    bool   `json:"egress"`     // takeover: block the unit's own traffic beyond the LAN
	Log       string `json:"log"`        // "syslog" (default) or "stderr"
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
	// FTSAE is the kill switch for FT-SAE (802.11r for WPA3 clients) on top
	// of wpa3: absent or true serves it (bcmwifi.Options.FTSAE, the agents
	// learning each other's key holders: ftsae.go) and claims radio_caps2
	// WPA3 fast roaming; false keeps WPA3 clients on a full SAE at every
	// roam (FT-PSK for WPA2 clients is not affected). Only with wpa3.
	FTSAE *bool `json:"ft_sae,omitempty"`
	// MdnsBridge (takeover with apply only) claims fw2_caps mDNS service
	// bridge and runs internal/mdnsbr (mdnsbr.go). Off by default until
	// AF_PACKET sends on the wl vifs are verified on the X20: the
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
	// (1-3) whose VLANs the controller may change. Ports 2 and 3 always
	// may; port 1 (the tenant's router) only when listed here, so its
	// untagged LAN stays as it is whatever the controller sends. Port 4 is
	// the uplink and is never changed (beyond the VLAN devices on it).
	PortsUnlocked []int `json:"ports_unlocked,omitempty"`
	// PortsConfirmS (model UHDIW) is how long a port change waits for an
	// inform the controller answers before it is reverted (60-900 s; 0 =
	// 90; under 60 s a healthy controller can miss it: an inform in flight
	// and the next one each take up to collectTO + informTO, 30 s). PortsLossS is how long the controller may stay unreachable
	// before every port the agent may change goes back on the LAN
	// (60-3600 s; 0 = 300). The port monitor: ports.go.
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
}

// uplinkLoss: the SSIDs are isolated on uplink loss (platform jio-mtk)
// unless uplink_loss is false.
func (c *Config) uplinkLoss() bool { return c.jio() && (c.UplinkLoss == nil || *c.UplinkLoss) }

func (c *Config) portsConfirm() time.Duration {
	if c.PortsConfirmS == 0 {
		return defaultPortsConfirm
	}
	return time.Duration(c.PortsConfirmS) * time.Second
}

func (c *Config) portsLoss() time.Duration {
	if c.PortsLossS == 0 {
		return defaultPortsLoss
	}
	return time.Duration(c.PortsLossS) * time.Second
}

// PlatformJio is the JioFiber JCOW414 (MediaTek) platform.
const PlatformJio = "jio-mtk"

func (c *Config) jio() bool { return c != nil && c.Platform == PlatformJio }

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfig(b)
}

func parseConfig(b []byte) (*Config, error) {
	c := &Config{Model: "UAL6", SSHDPort: 2222, Log: "syslog"}
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
		if c.Model != "UAL6" {
			return fmt.Errorf("config: model %q: only UAL6 is supported (its capability words are chosen for this hardware)", c.Model)
		}
	case PlatformJio:
		if !models.JCOW414Models[c.Model] {
			return fmt.Errorf("config: model %q: platform %s is reported as U7LT (UAP-AC-Lite) or UHDIW (UAP-IW-HD, with its LAN ports): set \"model\": \"U7LT\" or \"UHDIW\"", c.Model, c.Platform)
		}
		if len(c.PortsUnlocked) > 0 && c.Model != "UHDIW" {
			return fmt.Errorf("config: ports_unlocked needs model UHDIW (the only model reported with LAN ports)")
		}
		if (c.PortsConfirmS != 0 || c.PortsLossS != 0) && c.Model != "UHDIW" {
			return fmt.Errorf("config: ports_confirm_s and ports_loss_s need model UHDIW (the only model reported with LAN ports)")
		}
		if c.PortsConfirmS != 0 && (c.PortsConfirmS < 60 || c.PortsConfirmS > 900) {
			return fmt.Errorf("config: ports_confirm_s %d: want 60-900 seconds (default 90)", c.PortsConfirmS)
		}
		if c.PortsLossS != 0 && (c.PortsLossS < 60 || c.PortsLossS > 3600) {
			return fmt.Errorf("config: ports_loss_s %d: want 60-3600 seconds (default 300)", c.PortsLossS)
		}
		seen := map[int]bool{}
		for _, p := range c.PortsUnlocked {
			if p < 1 || p > 3 || seen[p] {
				return fmt.Errorf("config: ports_unlocked %v: want distinct LAN ports 1-3 (port 4 is the uplink and is never changed)", c.PortsUnlocked)
			}
			seen[p] = true
		}
		// wpa3: SAE on the 5 GHz radio only (the MT7663 driver has it);
		// min_rates: the 2.4 GHz radio's BasicRate (mtkwifi minRate)
		for name, on := range map[string]bool{"mdns_bridge": c.MdnsBridge,
			"hotspot2": c.Hotspot2, "egress": c.Egress, "twt": c.TWT != nil} {
			if on {
				return fmt.Errorf("config: %s is not supported on platform %s", name, c.Platform)
			}
		}
	default:
		return fmt.Errorf("config: platform %q: want \"\" (Deco) or %q", c.Platform, PlatformJio)
	}
	if (c.UplinkLoss != nil || c.UplinkLossSSID != "" || c.BSSPinning) && !c.jio() {
		return errors.New("config: uplink_loss, uplink_loss_ssid and bss_pinning are for platform " + PlatformJio + " only")
	}
	if (len(c.PortsUnlocked) > 0 || c.PortsConfirmS != 0 || c.PortsLossS != 0) && !c.jio() {
		return errors.New("config: ports_unlocked, ports_confirm_s and ports_loss_s are for platform " + PlatformJio + " only")
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
	case "syslog", "stderr":
	default:
		return fmt.Errorf("config: log %q: want syslog or stderr", c.Log)
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

// twt: TWT is on unless the twt key is false.
func (c *Config) twt() bool { return c.TWT == nil || *c.TWT }

func (c *Config) controllerIP() string {
	u, _ := url.Parse(c.InformURL)
	return u.Hostname()
}
