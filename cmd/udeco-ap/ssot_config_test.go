// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
	"github.com/antoniocosta/unifi-openwrt/internal/jioports"
	"github.com/antoniocosta/unifi-openwrt/internal/models"
	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
	"github.com/antoniocosta/unifi-openwrt/internal/rf"
)

// Tests that hold the agent's config (config.go) to itself and to what
// repeats it: the texts of its checks, the deploy script and the documents.

// cfgBase is the two keys every config needs, without the braces.
const cfgBase = `"inform_url":"http://192.168.0.1:8080/inform","console_ip":"192.168.0.1"`

// configTags are Config's JSON keys, in the struct's order.
func configTags(t *testing.T) []string {
	t.Helper()
	var tags []string
	ty := reflect.TypeOf(Config{})
	for i := 0; i < ty.NumField(); i++ {
		tag, _, _ := strings.Cut(ty.Field(i).Tag.Get("json"), ",")
		if tag == "" || tag == "-" {
			t.Fatalf("Config.%s has no JSON key", ty.Field(i).Name)
		}
		tags = append(tags, tag)
	}
	return tags
}

// configField is c's field with the JSON key key.
func configField(t *testing.T, c *Config, key string) reflect.Value {
	t.Helper()
	i := slices.Index(configTags(t), key)
	if i < 0 {
		t.Fatalf("Config has no JSON key %q", key)
	}
	return reflect.ValueOf(c).Elem().Field(i)
}

// flat is text with every run of spaces and line breaks as one space, so a
// phrase is found across a document's line breaks.
func flat(s string) string { return strings.Join(strings.Fields(s), " ") }

// docSection is the part of the Markdown document at rel under heading (a
// whole line), up to the next heading of the same or a higher level.
func docSection(t *testing.T, rel, heading string) string {
	t.Helper()
	doc := repotest.Read(t, rel)
	i := strings.Index(doc, "\n"+heading+"\n")
	if i < 0 {
		t.Fatalf("%s has no heading %q", rel, heading)
	}
	body := doc[i+len(heading)+2:]
	level := len(heading) - len(strings.TrimLeft(heading, "#"))
	for l := 1; l <= level; l++ {
		if j := strings.Index(body, "\n"+strings.Repeat("#", l)+" "); j >= 0 {
			body = body[:j]
		}
	}
	return body
}

// The texts of validate's errors, written down from the code as it was
// before the checks took their numbers and key names from one place each
// (secondsKey, keySet, jioports, rf.Bands, bcmwifi.ValidCountry, the log
// constants). "" = the config passes.
func TestConfigErrorTexts(t *testing.T) {
	base := cfgBase
	jio := base + `,"platform":"jio-mtk","model":"UHDIW"`
	lt := base + `,"platform":"jio-mtk","model":"U7LT"`
	for _, c := range []struct{ js, want string }{
		{jio + `,"ports_confirm_s":59`, `config: ports_confirm_s 59: want 60-900 seconds (default 90)`},
		{jio + `,"ports_confirm_s":901`, `config: ports_confirm_s 901: want 60-900 seconds (default 90)`},
		{jio + `,"ports_confirm_s":-1`, `config: ports_confirm_s -1: want 60-900 seconds (default 90)`},
		{jio + `,"ports_confirm_s":60`, ``},
		{jio + `,"ports_confirm_s":900`, ``},
		{jio + `,"ports_loss_s":59`, `config: ports_loss_s 59: want 60-3600 seconds (default 300)`},
		{jio + `,"ports_loss_s":3601`, `config: ports_loss_s 3601: want 60-3600 seconds (default 300)`},
		{jio + `,"ports_loss_s":60`, ``},
		{jio + `,"ports_loss_s":3600`, ``},
		{base + `,"takeover":true,"apply":true,"login_lock_failopen_s":59`, `config: login_lock_failopen_s 59: want 60-3600 seconds (default 600)`},
		{base + `,"takeover":true,"apply":true,"login_lock_failopen_s":3601`, `config: login_lock_failopen_s 3601: want 60-3600 seconds (default 600)`},
		{base + `,"takeover":true,"apply":true,"login_lock_failopen_s":-5`, `config: login_lock_failopen_s -5: want 60-3600 seconds (default 600)`},
		{base + `,"takeover":true,"apply":true,"login_lock_failopen_s":60`, ``},
		{base + `,"takeover":true,"apply":true,"login_lock_failopen_s":3600`, ``},
		{base + `,"takeover":true,"apply":true,"login_lock":false,"login_lock_failopen_s":300`, `config: login_lock_failopen_s needs the login lock (takeover and apply, login_lock not false)`},
		{base + `,"login_lock_failopen_s":300`, `config: login_lock_failopen_s needs the login lock (takeover and apply, login_lock not false)`},
		{base + `,"login_lock_failopen_s":30`, `config: login_lock_failopen_s 30: want 60-3600 seconds (default 600)`},
		{jio + `,"ports_unlocked":[0]`, `config: ports_unlocked [0]: want distinct LAN ports 1-3 (port 4 is the uplink and is never changed)`},
		{jio + `,"ports_unlocked":[4]`, `config: ports_unlocked [4]: want distinct LAN ports 1-3 (port 4 is the uplink and is never changed)`},
		{jio + `,"ports_unlocked":[1,1]`, `config: ports_unlocked [1 1]: want distinct LAN ports 1-3 (port 4 is the uplink and is never changed)`},
		{jio + `,"ports_unlocked":[1,2,3,4]`, `config: ports_unlocked [1 2 3 4]: want distinct LAN ports 1-3 (port 4 is the uplink and is never changed)`},
		{jio + `,"ports_unlocked":[3,2,1]`, ``},
		{jio + `,"ports_unlocked":[-1]`, `config: ports_unlocked [-1]: want distinct LAN ports 1-3 (port 4 is the uplink and is never changed)`},
		{jio + `,"ports_unlocked":[5]`, `config: ports_unlocked [5]: want distinct LAN ports 1-3 (port 4 is the uplink and is never changed)`},
		{base + `,"uplink_loss":true`, `config: uplink_loss, uplink_loss_ssid, bss_pinning, proxy_arp, proxy_arp_driver and dfs are for platform jio-mtk only`},
		{base + `,"uplink_loss":false`, `config: uplink_loss, uplink_loss_ssid, bss_pinning, proxy_arp, proxy_arp_driver and dfs are for platform jio-mtk only`},
		{base + `,"uplink_loss_ssid":"x"`, `config: uplink_loss, uplink_loss_ssid, bss_pinning, proxy_arp, proxy_arp_driver and dfs are for platform jio-mtk only`},
		{base + `,"bss_pinning":true`, `config: uplink_loss, uplink_loss_ssid, bss_pinning, proxy_arp, proxy_arp_driver and dfs are for platform jio-mtk only`},
		{base + `,"proxy_arp":false`, `config: uplink_loss, uplink_loss_ssid, bss_pinning, proxy_arp, proxy_arp_driver and dfs are for platform jio-mtk only`},
		{base + `,"proxy_arp":true`, `config: uplink_loss, uplink_loss_ssid, bss_pinning, proxy_arp, proxy_arp_driver and dfs are for platform jio-mtk only`},
		{base + `,"proxy_arp_driver":true`, `config: uplink_loss, uplink_loss_ssid, bss_pinning, proxy_arp, proxy_arp_driver and dfs are for platform jio-mtk only`},
		{base + `,"dfs":true`, `config: uplink_loss, uplink_loss_ssid, bss_pinning, proxy_arp, proxy_arp_driver and dfs are for platform jio-mtk only`},
		{base + `,"ports_unlocked":[1]`, `config: ports_unlocked, ports_confirm_s and ports_loss_s are for platform jio-mtk only`},
		{base + `,"ports_confirm_s":90`, `config: ports_unlocked, ports_confirm_s and ports_loss_s are for platform jio-mtk only`},
		{base + `,"ports_loss_s":300`, `config: ports_unlocked, ports_confirm_s and ports_loss_s are for platform jio-mtk only`},
		{lt + `,"ports_unlocked":[1]`, `config: ports_unlocked needs model UHDIW (the only model reported with LAN ports)`},
		{lt + `,"ports_confirm_s":90`, `config: ports_confirm_s and ports_loss_s need model UHDIW (the only model reported with LAN ports)`},
		{lt + `,"ports_loss_s":300`, `config: ports_confirm_s and ports_loss_s need model UHDIW (the only model reported with LAN ports)`},
		{lt + `,"proxy_arp":false,"proxy_arp_driver":true`, `config: proxy_arp_driver needs proxy_arp`},
		{lt + `,"takeover":true,"apply":true,"mdns_bridge":true`, `config: mdns_bridge is not supported on platform jio-mtk`},
		{lt + `,"takeover":true,"hotspot2":true`, `config: hotspot2 is not supported on platform jio-mtk`},
		{lt + `,"takeover":true,"egress":true`, `config: egress is not supported on platform jio-mtk`},
		{lt + `,"takeover":true,"twt":true`, `config: twt is not supported on platform jio-mtk`},
		{lt + `,"takeover":true,"uplink_ssid_down":false`, `config: uplink_ssid_down is not supported on platform jio-mtk`},
		{lt + `,"takeover":true,"uplink_gateway_down":true`, `config: uplink_gateway_down is not supported on platform jio-mtk`},
		{lt + `,"takeover":true,"sta_snoop":false`, `config: sta_snoop is not supported on platform jio-mtk`},
		{lt + `,"takeover":true,"assoc_garp":false`, `config: assoc_garp is not supported on platform jio-mtk`},
		{lt + `,"takeover":true,"rx_desense":true`, `config: rx_desense is not supported on platform jio-mtk`},
		{base + `,"uplink_ssid_down":true`, `config: uplink_ssid_down and uplink_gateway_down need takeover (observe mode never changes the unit)`},
		{base + `,"uplink_gateway_down":true`, `config: uplink_ssid_down and uplink_gateway_down need takeover (observe mode never changes the unit)`},
		{base + `,"sta_snoop":true`, `config: sta_snoop and assoc_garp need takeover (the BSSes are the agent's only then)`},
		{base + `,"assoc_garp":false`, `config: sta_snoop and assoc_garp need takeover (the BSSes are the agent's only then)`},
		{base + `,"takeover":true,"driver_country_bands":{"6e":"US"}`, `config: driver_country_bands: band "6e" is not ng or na`},
		{base + `,"takeover":true,"driver_country_bands":{"ng":"USA"}`, `config: driver_country_bands: ng country "USA" is not a two-letter code`},
		{base + `,"takeover":true,"driver_country_bands":{"ng":"U1"}`, `config: driver_country_bands: ng country "U1" is not a two-letter code`},
		{base + `,"takeover":true,"driver_country_bands":{"na":"#A"}`, `config: driver_country_bands: na country "#A" is not a two-letter code`},
		{base + `,"takeover":true,"driver_country_bands":{"na":"#a"}`, ``},
		{base + `,"takeover":true,"driver_country_bands":{"na":" #a "}`, ``},
		{base + `,"takeover":true,"driver_country_bands":{"na":" us "}`, ``},
		{base + `,"takeover":true,"driver_country_bands":{"na":""}`, `config: driver_country_bands: na country "" is not a two-letter code`},
		{base + `,"takeover":true,"driver_country_bands":{"NG":"US"}`, `config: driver_country_bands: band "NG" is not ng or na`},
		{base + `,"takeover":true,"driver_country_bands":{"na":"#b"}`, `config: driver_country_bands: na country "#b" is not a two-letter code`},
		{base + `,"takeover":true,"driver_country_bands":{"na":"U S"}`, `config: driver_country_bands: na country "U S" is not a two-letter code`},
		{base + `,"driver_country_bands":{"na":"US"}`, `config: driver_country_bands needs takeover (observe mode never changes the unit)`},
		{base + `,"log":"file"`, `config: log "file": want syslog or stderr`},
		{base + `,"log":""`, `config: log "": want syslog or stderr`},
		{base + `,"log":"stderr"`, ``},
		{base + `,"log":"syslog"`, ``},
		{base + `,"log":"SYSLOG"`, `config: log "SYSLOG": want syslog or stderr`},
		{base + `,"platform":"x"`, `config: platform "x": want "" (Deco) or "jio-mtk"`},
		{base + `,"sshd_port":22`, `config: sshd_port 22: want 1-65535 and never 22 (the unit's own dropbear)`},
		{lt + `,"takeover":true,"apply":true,"login_lock_failopen_s":59`, `config: login_lock_failopen_s 59: want 60-3600 seconds (default 600)`},
	} {
		_, err := parseConfig([]byte("{" + c.js + "}"))
		switch {
		case c.want == "" && err != nil:
			t.Errorf("{%s}: refused: %v", c.js, err)
		case c.want != "" && (err == nil || err.Error() != c.want):
			t.Errorf("{%s}:\n got  %v\n want %s", c.js, err, c.want)
		}
	}
	// several Deco-only keys on platform jio-mtk: the first of the list is
	// the one named (it was any one of them while the list was a map)
	_, err := parseConfig([]byte("{" + lt + `,"takeover":true,"rx_desense":true,"twt":true,"hotspot2":true}`))
	if want := "config: hotspot2 is not supported on platform jio-mtk"; err == nil || err.Error() != want {
		t.Errorf("three Deco-only keys: %v, want %s", err, want)
	}
}

// The three keys that hold a time in seconds: each accessor, check and
// message reads the key's secondsKey, and the key is an int of Config.
func TestSecondsKeys(t *testing.T) {
	for _, c := range []struct {
		k   secondsKey
		get func(*Config) time.Duration
	}{
		{portsConfirmKey, (*Config).portsConfirm},
		{portsLossKey, (*Config).portsLoss},
		{loginLockFailOpenKey, (*Config).loginLockFailOpen},
	} {
		k := c.k
		if k.min <= 0 || k.def < k.min || k.def > k.max {
			t.Errorf("%s: range %d-%d, default %d: a set value must not read as absent (0), and the default must be one the check takes", k.name, k.min, k.max, k.def)
		}
		cfg := &Config{}
		f := configField(t, cfg, k.name)
		if f.Kind() != reflect.Int {
			t.Fatalf("%s is a %s in Config", k.name, f.Kind())
		}
		if got := c.get(cfg); got != time.Duration(k.def)*time.Second {
			t.Errorf("%s absent: %s, want the default %d s", k.name, got, k.def)
		}
		for _, v := range []int{k.min, k.max} {
			f.SetInt(int64(v))
			if got := c.get(cfg); got != time.Duration(v)*time.Second || k.check(v) != nil {
				t.Errorf("%s %d: %s, check %v", k.name, v, got, k.check(v))
			}
		}
		for _, v := range []int{k.min - 1, k.max + 1, -1} {
			want := fmt.Sprintf("config: %s %d: want %d-%d seconds (default %d)", k.name, v, k.min, k.max, k.def)
			if err := k.check(v); err == nil || err.Error() != want {
				t.Errorf("%s %d: %v, want %s", k.name, v, err, want)
			}
		}
		if err := k.check(0); err != nil {
			t.Errorf("%s absent: %v", k.name, err)
		}
	}
}

// The documents state the seconds keys' numbers as the code has them.
func TestDocsSecondsKeys(t *testing.T) {
	pc, pl, ll := portsConfirmKey, portsLossKey, loginLockFailOpenKey
	if ll.def%60 != 0 {
		t.Fatalf("%s default %d s is not whole minutes: the documents give it in minutes", ll.name, ll.def)
	}
	readme := flat(repotest.Read(t, "README.md"))
	for _, p := range []string{
		fmt.Sprintf("`%s`, %d, opens them after that much silence", ll.name, ll.def),
		fmt.Sprintf("%d min without a controller reply", ll.def/60),
		fmt.Sprintf("open after %d min of silence", ll.def/60),
		fmt.Sprintf("`%s` (default %d s, %d-%d)", pc.name, pc.def, pc.min, pc.max),
		fmt.Sprintf("`%s` (default %d s, %d-%d)", pl.name, pl.def, pl.min, pl.max),
	} {
		if !strings.Contains(readme, p) {
			t.Errorf("README.md does not have %q", p)
		}
	}
	lock := flat(repotest.Read(t, "docs/deco/features/login-lock.md"))
	for _, p := range []string{
		fmt.Sprintf("`%s` old (%d s)", ll.name, ll.def),
		fmt.Sprintf("| `%s` | %d | How long the controller may be silent before the lock opens (%d-%d).", ll.name, ll.def, ll.min, ll.max),
	} {
		if !strings.Contains(lock, p) {
			t.Errorf("docs/deco/features/login-lock.md does not have %q", p)
		}
	}
	keys := docSection(t, "docs/deco/agent-design.md", "### 3.5 cmd/udeco-ap")
	for _, k := range []secondsKey{pc, pl, ll} {
		if p := fmt.Sprintf("`%s` (seconds, %d-%d, default %d;", k.name, k.min, k.max, k.def); !strings.Contains(keys, p) {
			t.Errorf("docs/deco/agent-design.md 3.5 does not have %q", p)
		}
	}
}

// The lists validate's group checks read (keySet): each name is a JSON
// key of Config, and the entry is set exactly when the field with that key
// is: an empty config sets none, and a config with one key sets that entry
// and no other of its list.
func TestConfigKeyGroups(t *testing.T) {
	tags := configTags(t)
	for name, group := range map[string]func(*Config) []keySet{
		"decoOnlyKeys":     (*Config).decoOnlyKeys,
		"jioOnlyKeys":      (*Config).jioOnlyKeys,
		"portTimerKeys":    (*Config).portTimerKeys,
		"portKeys":         (*Config).portKeys,
		"portsUnlockedKey": func(c *Config) []keySet { return []keySet{c.portsUnlockedKey()} },
	} {
		empty := group(&Config{})
		if len(empty) == 0 {
			t.Errorf("%s is empty", name)
		}
		for i, k := range empty {
			if !slices.Contains(tags, k.name) {
				t.Errorf("%s names %q, which is not a JSON key of Config", name, k.name)
				continue
			}
			if k.set {
				t.Errorf("%s: %s is set in an empty config", name, k.name)
			}
			c := &Config{}
			switch f := configField(t, c, k.name); f.Kind() {
			case reflect.Pointer: // a key that is there counts, whatever its value: false too
				f.Set(reflect.New(f.Type().Elem()))
			default:
				fillValue(t, f)
			}
			for j, got := range group(c) {
				if got.set != (i == j) {
					t.Errorf("%s: with only %s in the config, %s set = %v", name, k.name, got.name, got.set)
				}
			}
		}
	}
	// a list with nothing in it sets no key
	if (&Config{PortsUnlocked: []int{}}).portsUnlockedKey().set {
		t.Error("an empty ports_unlocked counts as set")
	}
	if got := keyNames(nil) + "|" + keyNames([]keySet{{name: "a"}}) + "|" + keyNames([]keySet{{name: "a"}, {name: "b"}}) + "|" +
		keyNames([]keySet{{name: "a"}, {name: "b"}, {name: "c"}}); got != "|a|a and b|a, b and c" {
		t.Errorf("keyNames: %q", got)
	}
	// no key is refused on both platforms
	for _, d := range (&Config{}).decoOnlyKeys() {
		for _, j := range append((&Config{}).jioOnlyKeys(), (&Config{}).portKeys()...) {
			if d.name == j.name {
				t.Errorf("%s is in the Deco-only and the jio-only keys", d.name)
			}
		}
	}
}

// deploy/deco-ap.sh shows the keys of a unit's existing config by name:
// each name it greps for is a key of Config.
func TestDeployScriptConfigKeys(t *testing.T) {
	m := regexp.MustCompile(`grep -E '"\(([a-z0-9_|]+)\)"' \$CFG`).FindStringSubmatch(repotest.Read(t, "deploy/deco-ap.sh"))
	if m == nil {
		t.Fatal("deploy/deco-ap.sh no longer greps the config for its keys this way")
	}
	tags := configTags(t)
	keys := strings.Split(m[1], "|")
	if len(keys) < 2 {
		t.Fatalf("keys read from the script: %q", keys)
	}
	for _, k := range keys {
		if !slices.Contains(tags, k) {
			t.Errorf("deploy/deco-ap.sh greps the config for %q, which is not a key of Config", k)
		}
	}
}

// deploy/deco-ap.sh writes the default config on a unit that has none, with
// its own --inform-url and --console-ip defaults. It must pass the agent's
// strict parser (unknown keys are an error), be observe mode, and be the
// config the agent reads from those two keys alone: the script writes
// "model", "sshd_port" and "log" out, so a default changed in defaultConfig
// fails here until the script writes the new value.
func TestDeployDefaultConfig(t *testing.T) {
	script := repotest.Read(t, "deploy/deco-ap.sh")
	m := regexp.MustCompile(`(?s)<<'JSON'\n(.*?)\nJSON\n`).FindStringSubmatch(script)
	if m == nil {
		t.Fatal("no default config in deploy/deco-ap.sh")
	}
	defaults := scriptVars(t, decoDeploy, "inform_url", "console_ip")
	informURL, consoleIP := defaults["inform_url"], defaults["console_ip"]
	js := strings.NewReplacer("$inform_url", informURL, "$console_ip", consoleIP).Replace(m[1])
	if strings.Contains(js, "$") {
		t.Fatalf("unexpanded variable in %s", js)
	}
	c, err := parseConfig([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if c.Takeover || c.Apply || c.Egress {
		t.Errorf("default config not observe mode: %+v", c)
	}
	two, _ := json.Marshal(map[string]string{"inform_url": informURL, "console_ip": consoleIP})
	want, err := parseConfig(two)
	if err != nil {
		t.Fatalf("the script's default --inform-url and --console-ip: %v", err)
	}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("the config deploy/deco-ap.sh writes is not the agent's defaults:\n script   %+v\n defaults %+v", c, want)
	}
	// the three keys with a default are written out, not left to the agent
	var written map[string]any
	if err := json.Unmarshal([]byte(js), &written); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"model", "sshd_port", "log"} {
		if _, ok := written[k]; !ok {
			t.Errorf("deploy/deco-ap.sh no longer writes %q into a new config", k)
		}
	}
}

// The documents that list keys by platform have the lists validate reads.
func TestDocsPlatformKeys(t *testing.T) {
	names := func(ks []keySet) string {
		var n []string
		for _, k := range ks {
			n = append(n, "`"+k.name+"`")
		}
		return strings.Join(n, ", ")
	}
	c := &Config{}
	if p := "(all `platform: " + PlatformJio + "` only; an error elsewhere): " + names(c.jioOnlyKeys()) + "."; !strings.Contains(flat(repotest.Read(t, "docs/deco/features/garage-parity.md")), p) {
		t.Errorf("docs/deco/features/garage-parity.md does not have %q", p)
	}
	keys := docSection(t, "docs/deco/agent-design.md", "### 3.5 cmd/udeco-ap")
	if p := "Refused on " + PlatformJio + ": " + names(c.decoOnlyKeys()) + ")"; !strings.Contains(keys, p) {
		t.Errorf("docs/deco/agent-design.md 3.5 does not have %q", p)
	}
	if p := "`" + PlatformJio + "`: a JioFiber JCOW414 used as a plain AP, reported as `model` " + models.ModelU7LT + " or " + models.ModelUHDIW; !strings.Contains(keys, p) {
		t.Errorf("docs/deco/agent-design.md 3.5 does not have %q", p)
	}
	lan := jioports.LANPorts
	if p := fmt.Sprintf("`ports_unlocked` (list of LAN ports %d-%d;", lan[0], lan[len(lan)-1]); !strings.Contains(keys, p) {
		t.Errorf("docs/deco/agent-design.md 3.5 does not have %q", p)
	}
	if p := fmt.Sprintf("never to port %d, the uplink", jioports.UplinkPhys); !strings.Contains(keys, p) {
		t.Errorf("docs/deco/agent-design.md 3.5 does not have %q", p)
	}
}

// docs/deco/agent-design.md section 3.5 is the readers' list of the
// config's keys and the README names each too: a key added to Config is
// added to both. The README's example config is one the agent takes, and
// the defaults both documents state are the code's.
func TestDocsConfigKeys(t *testing.T) {
	keys := docSection(t, "docs/deco/agent-design.md", "### 3.5 cmd/udeco-ap")
	readme := repotest.Read(t, "README.md")
	for _, k := range configTags(t) {
		if !strings.Contains(keys, "`"+k+"`") {
			t.Errorf("docs/deco/agent-design.md 3.5 does not name the config key `%s`", k)
		}
		if !strings.Contains(readme, "`"+k+"`") && !strings.Contains(readme, `"`+k+`"`) {
			t.Errorf("README.md does not name the config key %s", k)
		}
	}
	d := defaultConfig()
	for _, p := range []string{
		fmt.Sprintf("`model` (%s), `sshd_port` (%d)", d.Model, d.SSHDPort),
		"`log` (`" + logSyslog + "` or `" + logStderr + "`)",
		fmt.Sprintf("SSH on `:%d`, only from `console_ip`", d.SSHDPort),
	} {
		if !strings.Contains(keys, p) {
			t.Errorf("docs/deco/agent-design.md 3.5 does not have %q", p)
		}
	}
	if p := "`log` is `" + d.Log + "` (the default) or `" + logStderr + "`."; !strings.Contains(flat(readme), p) {
		t.Errorf("README.md does not have %q", p)
	}
	if d.Log != logSyslog {
		t.Errorf("the default log is %q: the documents say %s", d.Log, logSyslog)
	}

	// the example under "Configure"
	i := strings.Index(readme, "**Configure.**")
	if i < 0 {
		t.Fatal("README.md has no Configure step")
	}
	js, ok := repotest.Fenced(readme[i:], "json", 0)
	if !ok {
		t.Fatal("README.md has no json block under Configure")
	}
	c, err := parseConfig([]byte(js))
	if err != nil {
		t.Fatalf("the README's example config: %v\n%s", err, js)
	}
	var written map[string]any
	if err := json.Unmarshal([]byte(js), &written); err != nil {
		t.Fatal(err)
	}
	// where the example writes a key that has a default, it writes the default
	if _, ok := written["model"]; ok && c.Model != d.Model {
		t.Errorf("the README's example has model %s, the default is %s", c.Model, d.Model)
	}
	if _, ok := written["sshd_port"]; ok && c.SSHDPort != d.SSHDPort {
		t.Errorf("the README's example has sshd_port %d, the default is %d", c.SSHDPort, d.SSHDPort)
	}

	// a key a design planned and nobody built stays marked as such
	const planned = "observe_scans"
	if slices.Contains(configTags(t), planned) {
		t.Fatalf("%s is a config key now: take the \"never built\" notes out of docs/deco/spectrum-design.md", planned)
	}
	if _, err := parseConfig([]byte("{" + cfgBase + `,"` + planned + `":true}`)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("%s: %v, want it refused as an unknown key", planned, err)
	}
	n := 0
	for _, line := range strings.Split(repotest.Read(t, "docs/deco/spectrum-design.md"), "\n") {
		if strings.Contains(line, planned) {
			n++
			if !strings.Contains(strings.ToLower(line), "never built") {
				t.Errorf("docs/deco/spectrum-design.md names %s without saying it was never built: %.120s", planned, line)
			}
		}
	}
	if n == 0 {
		t.Errorf("docs/deco/spectrum-design.md no longer names %s: drop this check", planned)
	}
}

// docs/deco/agent-design.md section 3.6 lists the keys that are an error
// in observe mode. The lists are the keys validate refuses that way: each
// key alone in a config without takeover, its error read.
func TestDocsTakeoverKeys(t *testing.T) {
	doc := flat(docSection(t, "docs/deco/agent-design.md", "### 3.6 cmd/udeco-ap as built (decisions, 2026-11-18)"))
	list := func(re string) []string {
		m := regexp.MustCompile(re).FindStringSubmatch(doc)
		if m == nil {
			t.Fatalf("docs/deco/agent-design.md 3.6 has no sentence like %s", re)
		}
		var keys []string
		for _, k := range regexp.MustCompile("`([a-z0-9_]+)`").FindAllStringSubmatch(m[1], -1) {
			keys = append(keys, k[1])
		}
		slices.Sort(keys)
		return keys
	}
	const item = "((?:`[a-z0-9_]+`(?:, | and )?)+)"
	docTakeover := list("Keys that are an error in observe mode: " + item + " require `takeover`;")
	docBoth := list("; " + item + " require `takeover` and `apply`")

	var takeover, both []string
	for _, k := range configTags(t) {
		if strings.Contains(cfgBase, `"`+k+`"`) || k == "takeover" {
			continue
		}
		var v string
		switch f := configField(t, &Config{}, k); f.Kind() {
		case reflect.Bool, reflect.Pointer:
			v = "true"
		case reflect.Int:
			v = "300"
		case reflect.String:
			v = `"x"`
		case reflect.Map:
			v = `{"ng":"US"}`
		case reflect.Slice:
			v = "[1]"
			if f.Type().Elem().Kind() == reflect.String {
				v = `["192.168.0.2"]`
			}
		default:
			t.Fatalf("no value for the %s key %s", f.Kind(), k)
		}
		_, err := parseConfig([]byte("{" + cfgBase + `,"` + k + `":` + v + "}"))
		if err == nil {
			continue
		}
		switch msg := err.Error(); {
		case strings.Contains(msg, " needs takeover and apply ("), strings.Contains(msg, " need takeover and apply ("):
			both = append(both, k)
		case strings.Contains(msg, " needs takeover ("), strings.Contains(msg, " need takeover ("):
			takeover = append(takeover, k)
		}
	}
	slices.Sort(takeover)
	slices.Sort(both)
	if !slices.Equal(takeover, docTakeover) {
		t.Errorf("keys that need takeover:\n validate %q\n document %q", takeover, docTakeover)
	}
	if !slices.Equal(both, docBoth) {
		t.Errorf("keys that need takeover and apply:\n validate %q\n document %q", both, docBoth)
	}
	// the same paragraph names the models a config may give
	if p := fmt.Sprintf("`model` must be %s (on platform %s: %s or %s)", models.DecoAgentModel, PlatformJio, models.ModelU7LT, models.ModelUHDIW); !strings.Contains(doc, p) {
		t.Errorf("docs/deco/agent-design.md 3.6 does not have %q", p)
	}
	if len(models.JCOW414Models) != 2 || !models.JCOW414Models[models.ModelU7LT] || !models.JCOW414Models[models.ModelUHDIW] {
		t.Errorf("the models of platform %s are %v now: the documents name %s and %s", PlatformJio, models.JCOW414Models, models.ModelU7LT, models.ModelUHDIW)
	}
}

// The values validate takes from other packages are theirs: the LAN ports
// ports_unlocked may name, the bands of driver_country_bands, and the
// defaults a config file may leave out.
func TestConfigTakesOthersFacts(t *testing.T) {
	jio := cfgBase + `,"platform":"jio-mtk","model":"UHDIW"`
	for p := -1; p <= jioports.NumPorts+1; p++ {
		_, err := parseConfig([]byte(fmt.Sprintf(`{%s,"ports_unlocked":[%d]}`, jio, p)))
		if want := slices.Contains(jioports.LANPorts, p); (err == nil) != want {
			t.Errorf("ports_unlocked [%d]: %v, a LAN port: %v", p, err, want)
		}
	}
	if slices.Contains(jioports.LANPorts, jioports.UplinkPhys) {
		t.Error("the uplink is one of jioports.LANPorts")
	}
	for _, b := range []string{rf.Band2G, rf.Band5G, rf.Band6G, "2g", ""} {
		_, err := parseConfig([]byte(fmt.Sprintf(`{%s,"takeover":true,"driver_country_bands":{%q:"US"}}`, cfgBase, b)))
		if want := slices.Contains(rf.Bands(), b); (err == nil) != want {
			t.Errorf("driver_country_bands band %q: %v, one of rf.Bands(): %v", b, err, want)
		}
	}
	c, err := parseConfig([]byte("{" + cfgBase + "}"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, &Config{InformURL: "http://192.168.0.1:8080/inform", ConsoleIP: "192.168.0.1",
		Model: models.DecoAgentModel, SSHDPort: decosys.DefaultSSHDPort, Log: logSyslog}) {
		t.Errorf("a config with the two needed keys: %+v", c)
	}
}

// The agent's PATH is the firmware's binary directories as decosys
// searches them, a site login's session gets the same on both platforms,
// and the Garage's adds its own two in front.
func TestAgentPATH(t *testing.T) {
	if want := strings.Join(decosys.BinDirs, ":"); agentPATH != want || jioPATH != "/userfs/bin:/pfrm2.0/bin:"+want {
		t.Errorf("agentPATH %q, jioPATH %q, decosys.BinDirs %q", agentPATH, jioPATH, decosys.BinDirs)
	}
	for _, c := range []*Config{{Takeover: true}, {Takeover: true, Platform: PlatformJio}} {
		a := &agent{cfg: c}
		if o := a.siteSSHOptions(); o == nil || o.Path != agentPATH {
			t.Errorf("platform %q: site sessions' options %+v, want PATH %s", c.Platform, o, agentPATH)
		}
	}
	if (&agent{cfg: &Config{}}).siteSSHOptions() != nil {
		t.Error("site logins in observe mode")
	}
	if p := "PATH is set to `" + agentPATH + "` at start"; !strings.Contains(flat(repotest.Read(t, "docs/deco/agent-design.md")), p) {
		t.Errorf("docs/deco/agent-design.md does not have %q", p)
	}
}
