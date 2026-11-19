// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// CheckInformURL accepts only what an inform URL may be on a device:
// http:// (the inform is encrypted end to end and the agents' HTTP
// clients have no TLS) to an IPv4 literal host (inform_ip is derived from
// it, and egress allows the controller by address, so a name would need
// DNS), with an optional numeric port and no user info.
//
// Every place the URL can change goes through it: the start config, a
// setparam's mgmt_cfg inform_url, cmd set-adopt's uri and an SSH
// set-adopt/set-inform. A rejected URL leaves the old one in place.
func CheckInformURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return errors.New("not a URL")
	}
	if u.Scheme != "http" {
		return errors.New("the scheme must be http")
	}
	if u.Opaque != "" || u.User != nil {
		return errors.New("want http://<ipv4>[:port]/path")
	}
	h := u.Hostname()
	if h == "" {
		return errors.New("no host")
	}
	// "[::ffff:192.168.0.1]" parses to an address with a To4 form: an IPv6
	// literal all the same, so refuse anything with a colon in the host
	if ip := net.ParseIP(h); ip == nil || ip.To4() == nil || strings.Contains(h, ":") {
		return errors.New("the host must be an IPv4 address")
	}
	if strings.HasSuffix(u.Host, ":") {
		return errors.New("empty port")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return errors.New("bad port")
		}
	}
	return nil
}
