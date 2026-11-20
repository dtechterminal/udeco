// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

// IfNameChars reports whether s is 1 to 15 characters of [A-Za-z0-9._-]:
// what the interface names of the supported units are made of (wl1.2,
// eth0.4.1, br-lan, rai0, phy0-ap0), and nothing a shell could read as
// anything else. It is the one character rule behind the validators of
// internal/wl, internal/bcmwifi and upstream's openwrt package.
//
// A name that starts with '-' passes: a caller that puts the name where a
// command would take an option refuses that itself (wl's ifaceOK does).
// internal/mdnsbr does not import this package and has its own stricter
// rule (the first character a letter or a digit); cmd/udeco-ap's tests
// hold the two to each other.
func IfNameChars(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
