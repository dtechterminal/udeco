// SPDX-License-Identifier: GPL-2.0-or-later

package inform

import (
	"net"
	"net/url"
)

// The inform POST, as every client here sends it and reads its answer:
// the AP agent's own HTTP client (cmd/udeco-ap/post.go) and the net/http
// one of the other daemons (internal/informhttp).
const (
	// ContentType is the Content-Type of an inform POST.
	ContentType = "application/x-binary"
	// MaxReply is the most a client reads of an inform answer, in bytes.
	MaxReply = 4 << 20
	// UserAgent is what UniFi APs send. Only the AP agent sends it; the
	// net/http clients keep Go's own.
	UserAgent = "AirControl Agent v1.0"
)

// URLHost is the host of an inform URL as net/url reads it: without the
// port, without the brackets of an IPv6 literal and without user info;
// "" when rawURL does not parse or names no host. device.CheckInformURL
// reads the host the same way before it judges it.
//
// informIP (u7pg2.go) and upstream uow's localIPToward cut the URL by hand
// instead and give other answers for some URLs no device accepts
// (TestURLHostAndHostOf, upstream's uow TestInformHostCut).
func URLHost(rawURL string) string {
	h, _ := urlHost(rawURL)
	return h
}

func urlHost(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

// LocalIPToward is the local IPv4 address the kernel would use to reach
// the inform URL's host (no packet is sent: UDP connect only).
func LocalIPToward(rawURL string) (string, error) {
	h, err := urlHost(rawURL)
	if err != nil {
		return "", err
	}
	c, err := net.Dial("udp4", net.JoinHostPort(h, "9"))
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String(), nil
}
