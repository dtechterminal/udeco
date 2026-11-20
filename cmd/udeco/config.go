// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Configuration: JSON at defaultConfigPath (docs/deco/README.md, Setup). The
// TP-Link password is never in the JSON: it comes from TPLINK_PASSWORD,
// TPLINK_PASSWORD_FILE, password_file or an env file (credentials.env) and
// is held only as a deco.Secret.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dtechterminal/udeco/internal/deco"
	"github.com/dtechterminal/udeco/internal/models"
)

// Duration is a time.Duration written as a Go duration string ("15s").
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"15s\": %w", err)
	}
	if s == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	if v < 0 {
		return fmt.Errorf("negative duration %q", s)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// UnitConfig is one Deco presented as a UniFi AP.
type UnitConfig struct {
	Name     string `json:"name"`
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	SSHDPort int    `json:"sshd_port"` // SSH adoption listener; default 22201 + index
}

// MeshSection names the master and optionally pins its SSH host key.
type MeshSection struct {
	// Master is the master unit, by IP or MAC; default the first unit.
	Master        string `json:"master"`
	HostKeySHA256 string `json:"host_key_sha256,omitempty"`
}

// Config is the config file (-config, default defaultConfigPath).
type Config struct {
	InformURL string `json:"inform_url"`
	ConsoleIP string `json:"console_ip,omitempty"` // allowed to SSH-adopt; default the inform host
	DaemonIP  string `json:"daemon_ip,omitempty"`  // reported IP; default the local address toward the inform host
	Netmask   string `json:"netmask,omitempty"`
	Gateway   string `json:"gateway,omitempty"`

	TPLinkID        string `json:"tplink_id,omitempty"` // or TPLINK_EMAIL in the environment / env file
	PasswordFile    string `json:"password_file,omitempty"`
	CredentialsFile string `json:"credentials_file,omitempty"` // env file; default <state_dir>/credentials.env

	Mesh  MeshSection  `json:"mesh"`
	Units []UnitConfig `json:"units"`

	Model    string `json:"model,omitempty"` // UniFi model; default U7PG2
	Profile  string `json:"profile,omitempty"`
	WifiCaps int    `json:"wifi_caps,omitempty"`

	Apply         bool   `json:"apply"`
	ReportIP      string `json:"report_ip,omitempty"` // reportDaemon (default) | reportDeco
	OnRemove      string `json:"on_remove,omitempty"` // onRemoveStop (default) | onRemovePending
	KickEmulation bool   `json:"kick_emulation,omitempty"`
	HideWired     bool   `json:"hide_wired,omitempty"`

	Poll           Duration `json:"poll,omitempty"`            // device list, client speeds, IoT clients; default deco.DefaultPoll, at least minPoll
	ClientsEvery   Duration `json:"clients_every,omitempty"`   // 0x4012 (see below); default and minimum deco.MinClientsEvery
	NoClientList   bool     `json:"no_client_list,omitempty"`  // never read 0x4012
	InformInterval Duration `json:"inform_interval,omitempty"` // inform at least this often; 0 = the controller's
	StateDir       string   `json:"state_dir,omitempty"`       // default the config file's directory

	masterIdx int
}

const (
	defaultModel    = models.DefaultModel // the measured UAP-AC-Pro
	defaultSSHDPort = 22201
	minPoll         = 5 * time.Second
)

// Where the TP-Link credentials come from besides the config's own keys:
// environment variables, each of which the env file may set as well, and
// the env file's name in the state directory. deploy/unraid.sh and
// docs/deco/README.md name them too (TestUnraidScriptCredentials,
// TestCredentialNames).
const (
	envTPLinkEmail           = "TPLINK_EMAIL"
	envTPLinkPassword        = "TPLINK_PASSWORD"
	envTPLinkPasswordFile    = "TPLINK_PASSWORD_FILE"
	envTPLinkPasswordFileAlt = "UDECO_TPLINK_PASSWORD_FILE" // the environment only, not the env file
	credentialsFileName      = "credentials.env"
)

// The values of report_ip: the address a unit is reported with.
const (
	reportDaemon = "daemon" // the daemon's, always
	reportDeco   = "deco"   // the Deco's own once adopted
)

// The values of on_remove: what a unit's runner does once the controller
// forgets the unit.
const (
	onRemoveStop    = "stop"    // stops
	onRemovePending = "pending" // goes on informing, as a unit to adopt
)

// loadConfig reads and validates path. It never reads secrets.
func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := parseConfig(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.StateDir == "" {
		c.StateDir = filepath.Dir(path)
	}
	return c, nil
}

func parseConfig(b []byte) (*Config, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, err
	}
	for _, k := range []string{"password", "tplink_password"} {
		if _, ok := probe[k]; ok {
			return nil, fmt.Errorf("%q is not read from the config: use %s, password_file or %s", k, envTPLinkPasswordFile, credentialsFileName)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	return &c, c.validate()
}

// clientsEvery is MeshConfig.ClientsEvery: < 0 turns 0x4012 off. 0x4012
// only adds names, client types and the last known access Deco/band; it is
// slow (62 s live), blocks the session while it runs, and is never on the
// inform path.
func (c *Config) clientsEvery() time.Duration {
	if c.NoClientList {
		return -1
	}
	return time.Duration(c.ClientsEvery)
}

func (c *Config) validate() error {
	if c.ClientsEvery != 0 && time.Duration(c.ClientsEvery) < deco.MinClientsEvery {
		return fmt.Errorf("clients_every %s is below the %s minimum (0x4012 is slow and blocks the session)",
			time.Duration(c.ClientsEvery), deco.MinClientsEvery)
	}
	u, err := startInformURL(c.InformURL)
	if err != nil {
		return err
	}
	if c.ConsoleIP == "" {
		c.ConsoleIP = u.Hostname()
	}
	if c.Gateway == "" {
		c.Gateway = u.Hostname()
	}
	if c.Netmask == "" {
		c.Netmask = "255.255.255.0"
	}
	for name, ip := range map[string]string{"console_ip": c.ConsoleIP, "daemon_ip": c.DaemonIP, "gateway": c.Gateway, "netmask": c.Netmask} {
		if ip != "" && net.ParseIP(ip).To4() == nil {
			return fmt.Errorf("%s %q is not an IPv4 address", name, ip)
		}
	}
	if c.Model == "" {
		c.Model = c.Profile
	}
	if c.Model == "" {
		c.Model = defaultModel
	}
	if _, ok := models.Lookup(c.Model); !ok {
		return fmt.Errorf("unknown UniFi model %q", c.Model)
	}
	switch c.ReportIP {
	case "":
		c.ReportIP = reportDaemon
	case reportDaemon, reportDeco:
	default:
		return fmt.Errorf("report_ip %q: want %s or %s", c.ReportIP, reportDaemon, reportDeco)
	}
	switch c.OnRemove {
	case "":
		c.OnRemove = onRemoveStop
	case onRemoveStop, onRemovePending:
	default:
		return fmt.Errorf("on_remove %q: want %s or %s", c.OnRemove, onRemoveStop, onRemovePending)
	}
	if c.Poll == 0 {
		c.Poll = Duration(deco.DefaultPoll)
	}
	if time.Duration(c.Poll) < minPoll {
		return fmt.Errorf("poll %s is below %s", time.Duration(c.Poll), minPoll)
	}
	if len(c.Units) == 0 {
		return errors.New("no units")
	}
	seenMAC, seenIP, seenPort, seenName := map[string]bool{}, map[string]bool{}, map[int]bool{}, map[string]bool{}
	for i := range c.Units {
		un := &c.Units[i]
		mac := deco.NormMAC(un.MAC)
		hw, _ := net.ParseMAC(mac)
		if mac == "" || len(hw) != 6 || hw[0]&0x01 != 0 {
			return fmt.Errorf("unit %d: bad mac %q", i, un.MAC)
		}
		un.MAC = mac
		if net.ParseIP(un.IP).To4() == nil {
			return fmt.Errorf("unit %s: bad ip %q", mac, un.IP)
		}
		if un.Name == "" {
			un.Name = "deco-" + un.IP[strings.LastIndex(un.IP, ".")+1:]
		}
		if un.SSHDPort == 0 {
			un.SSHDPort = defaultSSHDPort + i
		}
		if un.SSHDPort < 1 || un.SSHDPort > 65535 {
			return fmt.Errorf("unit %s: bad sshd_port %d", un.Name, un.SSHDPort)
		}
		for what, dup := range map[string]bool{"mac": seenMAC[mac], "ip": seenIP[un.IP], "sshd_port": seenPort[un.SSHDPort], "name": seenName[un.Name]} {
			if dup {
				return fmt.Errorf("unit %s: duplicate %s", un.Name, what)
			}
		}
		seenMAC[mac], seenIP[un.IP], seenPort[un.SSHDPort], seenName[un.Name] = true, true, true, true
	}
	c.masterIdx = -1
	if c.Mesh.Master == "" {
		c.masterIdx = 0
	}
	for i, un := range c.Units {
		if un.IP == c.Mesh.Master || (deco.NormMAC(c.Mesh.Master) != "" && un.MAC == deco.NormMAC(c.Mesh.Master)) {
			c.masterIdx = i
		}
	}
	if c.masterIdx < 0 {
		return fmt.Errorf("mesh.master %q is not one of the units (by ip or mac)", c.Mesh.Master)
	}
	if h := c.Mesh.HostKeySHA256; h != "" && !strings.HasPrefix(h, "SHA256:") {
		return fmt.Errorf("mesh.host_key_sha256 must start with SHA256:")
	}
	return nil
}

// master is the configured master unit.
func (c *Config) master() UnitConfig { return c.Units[c.masterIdx] }

func (c *Config) unitIPs() []string {
	var out []string
	for _, u := range c.Units {
		out = append(out, u.IP)
	}
	return out
}

func (c *Config) unitMACs() []string {
	var out []string
	for _, u := range c.Units {
		out = append(out, u.MAC)
	}
	return out
}

// Secrets are the TP-Link credentials. String and GoString never show them.
type Secrets struct {
	TPLinkID string
	Password deco.Secret
}

func (s Secrets) String() string   { return "{tplink_id:[redacted] password:[redacted]}" }
func (s Secrets) GoString() string { return s.String() }

// env abstracts the process environment for tests.
type env func(string) string

// loadSecrets finds the TP-Link ID and password (in this order):
//
//	tplink_id: config tplink_id, $TPLINK_EMAIL, env file TPLINK_EMAIL
//	password:  $TPLINK_PASSWORD, $TPLINK_PASSWORD_FILE (or $UDECO_TPLINK_PASSWORD_FILE),
//	           config password_file, env file TPLINK_PASSWORD_FILE, env file TPLINK_PASSWORD
//
// The env file is credentials_file, default <state_dir>/credentials.env; a
// missing file is fine. Errors and warnings name files, never values. The
// names are the env* constants and credentialsFileName.
func loadSecrets(c *Config, getenv env, warn func(string, ...any)) (Secrets, error) {
	path := c.CredentialsFile
	if path == "" {
		path = filepath.Join(c.StateDir, credentialsFileName)
	}
	file, err := readEnvFile(path, warn)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Secrets{}, err
	}
	if err != nil && c.CredentialsFile != "" {
		return Secrets{}, fmt.Errorf("credentials_file %s: not found", path)
	}
	var s Secrets
	s.TPLinkID = firstNonEmpty(c.TPLinkID, getenv(envTPLinkEmail), file[envTPLinkEmail])
	if c.TPLinkID != "" && file[envTPLinkEmail] != "" && file[envTPLinkEmail] != c.TPLinkID {
		warn("tplink_id in the config differs from %s in %s; using the config's", envTPLinkEmail, path)
	}
	switch {
	case getenv(envTPLinkPassword) != "":
		s.Password = deco.Secret(getenv(envTPLinkPassword))
	default:
		for _, f := range []string{getenv(envTPLinkPasswordFile), getenv(envTPLinkPasswordFileAlt), c.PasswordFile, file[envTPLinkPasswordFile]} {
			if f == "" {
				continue
			}
			pw, err := readSecretFile(f, warn)
			if err != nil {
				return Secrets{}, err
			}
			s.Password = deco.Secret(pw)
			break
		}
		if s.Password == "" && file[envTPLinkPassword] != "" {
			s.Password = deco.Secret(file[envTPLinkPassword])
		}
	}
	if s.TPLinkID == "" {
		return s, errors.New("no TP-Link ID: set tplink_id, " + envTPLinkEmail + " or " + envTPLinkEmail + " in " + credentialsFileName)
	}
	return s, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// readSecretFile reads a one-line secret; only a trailing newline is cut.
func readSecretFile(path string, warn func(string, ...any)) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("password file %s: %w", path, errors.Unwrap(err))
	}
	if fi.Mode().Perm()&0o077 != 0 {
		warn("password file %s is readable by group/others (mode %o); chmod 600 it", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("password file %s: unreadable", path)
	}
	pw := strings.TrimRight(string(b), "\r\n")
	if pw == "" {
		return "", fmt.Errorf("password file %s is empty", path)
	}
	return pw, nil
}

// readEnvFile parses KEY=VALUE lines (# comments, optional "export ",
// optional single or double quotes around the value).
func readEnvFile(path string, warn func(string, ...any)) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Mode().Perm()&0o077 != 0 {
		warn("env file %s is readable by group/others (mode %o); chmod 600 it", path, fi.Mode().Perm())
	}
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("env file %s line %d: not KEY=VALUE", path, n)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("env file %s: %w", path, err)
	}
	return out, nil
}

// startInformURL is the rule for the config's inform_url: http or https
// to an IP-literal host. It is wider than device.CheckInformURL, the rule
// for every later change of the URL (a setparam, a set-adopt, an SSH
// set-inform), which takes http to an IPv4 literal only, without user
// info and with a port in range: an https or IPv6 start URL passes here
// and could not be set again later. TestStartInformURL lists where the
// two differ. Which rule the config should have is the owner's call.
func startInformURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || net.ParseIP(u.Hostname()) == nil {
		return nil, fmt.Errorf("inform_url %q: want http:// or https:// to an IP-literal host, like http://192.168.1.1:8080/inform", s)
	}
	return u, nil
}
