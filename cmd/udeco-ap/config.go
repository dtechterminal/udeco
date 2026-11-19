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

	"github.com/antoniocosta/unifi-openwrt/internal/device"
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
	// until `wl rateset` per BSS is verified on the X20 (minrate.go).
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
	// AP (MediaTek, model U7LT; internal/mtkwifi, internal/jiosys).
	Platform string `json:"platform,omitempty"`
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
		if c.Model != "U7LT" {
			return fmt.Errorf("config: model %q: platform %s is reported as U7LT (UAP-AC-Lite): set \"model\": \"U7LT\"", c.Model, c.Platform)
		}
		// wpa3: SAE on the 5 GHz radio only (the MT7663 driver has it)
		for name, on := range map[string]bool{"min_rates": c.MinRates, "mdns_bridge": c.MdnsBridge,
			"hotspot2": c.Hotspot2, "egress": c.Egress} {
			if on {
				return fmt.Errorf("config: %s is not supported on platform %s", name, c.Platform)
			}
		}
	default:
		return fmt.Errorf("config: platform %q: want \"\" (Deco) or %q", c.Platform, PlatformJio)
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

func (c *Config) controllerIP() string {
	u, _ := url.Parse(c.InformURL)
	return u.Hostname()
}
