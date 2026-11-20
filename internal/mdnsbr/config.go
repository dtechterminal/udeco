// SPDX-License-Identifier: GPL-2.0-or-later

// Package mdnsbr is the Deco agent's mDNS service bridge: the controller's
// fw2_caps 0x10000000 (supportsMdnsSdBridge) feature, driven by a WLAN's
// mdns_proxy_mode (auto/custom) and mdns_proxy_custom settings
// (docs/deco/features/mdns-bridge.md).
//
// What the controller sends (Network 10.6.109/11.1.50,
// com.ubnt.service.config.ubntconf.jfhrAUVHPMhBVsMer, only to a device that
// claims the bit):
//
//	mdns_sd.status=enabled
//	mdns_sd.ap_mode=enabled                      any applied custom entry has isolation_enabled
//	mdns_sd.proxy.P.status=enabled               custom mode, one per (WLAN, custom entry)
//	mdns_sd.proxy.P.dst.1.devname=<WLAN bridge>  br0 (untagged) or br0.<vid>
//	mdns_sd.proxy.P.src.M.devname=<bridge>       the entry's networks' bridges, minus dst
//	mdns_sd.filter.F.vlan=<vid>                  1 = untagged
//	mdns_sd.filter.F.policy=allow|deny
//	mdns_sd.filter.F.dst.D.devname=<VAP>         the WLAN's VAP devnames (ra0, rai1, ...)
//	mdns_sd.filter.F.service.S.name=<type>       exceptions to the policy (_airplay._tcp.local)
//
// auto mode: one filter per WLAN for its own VLAN, policy deny with the
// controller's 25 predefined service groups as the exceptions. custom mode:
// per entry, a proxy (when another VLAN is named) and one filter per named
// VLAN (services_mode all = allow, specific = deny but the chosen services,
// none = deny); the WLAN's own VLAN always gets a filter too. On a U6 Pro the
// proxy is /usr/sbin/mdns-repeater and the filter a kernel module
// (/proc/ui_multicast/mdns_filter/vaps/<vap>/vlans/<vlan>/{policy,services}).
package mdnsbr

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Proxy is one mdns_sd.proxy.P section: mDNS services in the Src bridges are
// offered to the clients of the Dst bridge (controller devnames).
type Proxy struct {
	Dst  string
	Srcs []string
}

// Filter is one mdns_sd.filter.F section: what mDNS from VLAN may reach the
// VAPs. Services are the exceptions to the policy: Allow with services =
// everything but them; deny with services = only them.
type Filter struct {
	VLAN     int // 1 = untagged
	Allow    bool
	VAPs     []string
	Services []string // normalised service types (lower case, no ".local")
}

// Config is the mdns_sd section.
type Config struct {
	Enabled bool
	APMode  bool // mdns_sd.ap_mode: only this AP's wireless clients take part
	Proxies []Proxy
	Filters []Filter
}

// Limits on what is taken from system_cfg.
const (
	maxSections = 64  // proxies, and filters
	maxMembers  = 32  // src bridges of a proxy, VAPs of a filter
	maxServices = 256 // services of a filter
	maxSvcLen   = 255
)

// devRE is this package's one rule for an interface name, in the
// controller's config and on the unit: 1 to 15 characters of
// [A-Za-z0-9._-], the first a letter or a digit. internal/apstate's
// IfNameChars is the same characters without the rule for the first;
// cmd/udeco-ap's TestInterfaceNameRules holds the two to each other.
var devRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`)

func on(v string) bool {
	switch strings.TrimSpace(v) {
	case "enabled", "true", "1", "on":
		return true
	}
	return false
}

// indices returns the sorted N of prefix.N.* keys.
func indices(cfg map[string]string, prefix string) []int {
	seen := map[int]bool{}
	for k := range cfg {
		rest, ok := strings.CutPrefix(k, prefix)
		if !ok {
			continue
		}
		n, _, _ := strings.Cut(rest, ".")
		if i, err := strconv.Atoi(n); err == nil && i >= 0 && strconv.Itoa(i) == n {
			seen[i] = true
		}
	}
	out := make([]int, 0, len(seen))
	for i := range seen {
		out = append(out, i)
	}
	sort.Ints(out)
	return out
}

// devnames reads prefix.N.devname for every N, validated.
func devnames(cfg map[string]string, prefix, what string, note func(string, ...any)) []string {
	var out []string
	seen := map[string]bool{}
	for _, i := range indices(cfg, prefix) {
		d := strings.TrimSpace(cfg[fmt.Sprintf("%s%d.devname", prefix, i)])
		switch {
		case d == "":
			continue
		case !devRE.MatchString(d):
			note("%s %q is not an interface name: ignored", what, d)
			continue
		case seen[d]:
			continue
		case len(out) == maxMembers:
			note("%s: more than %d: the rest ignored", what, maxMembers)
			return out
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// ParseConfig reads the mdns_sd section of a parsed system_cfg. Anything it
// cannot use is left out with a note; a section it cannot read whole is
// dropped, never half-applied.
func ParseConfig(cfg map[string]string) (Config, []string) {
	var c Config
	var notes []string
	note := func(f string, a ...any) { notes = append(notes, "mdns_sd: "+fmt.Sprintf(f, a...)) }
	c.Enabled = on(cfg["mdns_sd.status"])
	if !c.Enabled {
		return Config{}, nil
	}
	c.APMode = on(cfg["mdns_sd.ap_mode"])
	for n, i := range indices(cfg, "mdns_sd.proxy.") {
		p := fmt.Sprintf("mdns_sd.proxy.%d.", i)
		if n == maxSections {
			note("more than %d proxies: the rest ignored", maxSections)
			break
		}
		if !on(cfg[p+"status"]) {
			continue
		}
		dst := devnames(cfg, p+"dst.", fmt.Sprintf("proxy %d destination", i), note)
		srcs := devnames(cfg, p+"src.", fmt.Sprintf("proxy %d source", i), note)
		if len(dst) != 1 || len(srcs) == 0 {
			note("proxy %d: needs one destination and a source bridge (has %d, %d): ignored", i, len(dst), len(srcs))
			continue
		}
		var keep []string
		for _, s := range srcs {
			if s != dst[0] {
				keep = append(keep, s)
			}
		}
		if len(keep) > 0 {
			c.Proxies = append(c.Proxies, Proxy{Dst: dst[0], Srcs: keep})
		}
	}
	for n, i := range indices(cfg, "mdns_sd.filter.") {
		p := fmt.Sprintf("mdns_sd.filter.%d.", i)
		if n == maxSections {
			note("more than %d filters: the rest ignored", maxSections)
			break
		}
		v, err := strconv.Atoi(strings.TrimSpace(cfg[p+"vlan"]))
		if err != nil || v < 0 || v > 4094 {
			note("filter %d: VLAN %q not usable: ignored", i, cfg[p+"vlan"])
			continue
		}
		if v == 0 {
			v = 1
		}
		f := Filter{VLAN: v}
		switch pol := strings.TrimSpace(cfg[p+"policy"]); pol {
		case "allow":
			f.Allow = true
		case "deny":
		default:
			// fail closed: an unknown policy lets nothing through
			note("filter %d: policy %q not known: treated as deny (no mDNS from VLAN %d)", i, pol, v)
		}
		f.VAPs = devnames(cfg, p+"dst.", fmt.Sprintf("filter %d VAP", i), note)
		if len(f.VAPs) == 0 {
			continue
		}
		seen := map[string]bool{}
		for _, j := range indices(cfg, p+"service.") {
			s := cfg[fmt.Sprintf("%sservice.%d.name", p, j)]
			ns := NormService(s)
			if ns == "" {
				if strings.TrimSpace(s) != "" {
					note("filter %d: service %q not usable: ignored", i, s)
				}
				continue
			}
			if seen[ns] {
				continue
			}
			if len(f.Services) == maxServices {
				note("filter %d: more than %d services: the rest ignored", i, maxServices)
				break
			}
			seen[ns] = true
			f.Services = append(f.Services, ns)
		}
		c.Filters = append(c.Filters, f)
	}
	return c, notes
}

// NormService normalises a service type from the controller
// ("_airplay._tcp.local", "_matterc._udp", "_Foo._TCP.local.") to the form
// names are matched in: lower case, no trailing dot, no ".local". It
// returns "" for something that is not a service type (every label must be
// non-empty and the first must start with '_').
func NormService(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimSuffix(s, ".local")
	if s == "" || len(s) > maxSvcLen || !strings.HasPrefix(s, "_") {
		return ""
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 {
			return ""
		}
		for _, r := range l {
			if r < 0x21 || r > 0x7e {
				return ""
			}
		}
	}
	return s
}

// BridgeVLAN is the VLAN a controller bridge devname carries: br0 is
// untagged (1), br0.<vid> is <vid>. ok is false for anything else.
func BridgeVLAN(dev string) (vlan int, ok bool) {
	if !devRE.MatchString(dev) || !strings.HasPrefix(dev, "br") {
		return 0, false
	}
	base, id, dotted := strings.Cut(dev, ".")
	if !dotted {
		return 1, base != ""
	}
	v, err := strconv.Atoi(id)
	if err != nil || v < 1 || v > 4094 || strconv.Itoa(v) != id || strings.Contains(id, ".") {
		return 0, false
	}
	if v == 1 {
		return 1, true
	}
	return v, true
}
