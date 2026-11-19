// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import "testing"

func TestUsers(t *testing.T) {
	c := ParseCfg(`users.status=enabled
users.1.name=Ab3xY
users.1.password=$6$salt$abcDEF./123
users.1.status=enabled
users.2.name=nobody
users.2.password=$6$x$y
users.2.shell=/bin/false
users.2.status=enabled
users.3.name=bad:name
users.3.password=$6$x$y
users.3.status=enabled
users.4.name=evil
users.4.password=$6$x$y:0:0
users.4.status=enabled
users.5.name=7kq2mzpa
users.5.password=$6$salt$abcDEF./123
users.5.status=enabled
users.6.name=12345678
users.6.password=$6$x$y
users.6.status=enabled
users.7.name=-oops
users.7.password=$6$x$y
users.7.status=enabled
users.8.name=has space
users.8.password=$6$x$y
users.8.status=enabled
`)
	u, notes := Users(c)
	// a controller-generated login may start with a digit; all digits,
	// a leading '-' or whitespace are refused
	if len(u) != 2 || u[0].Name != "Ab3xY" || u[0].Hash != "$6$salt$abcDEF./123" || u[1].Name != "7kq2mzpa" {
		t.Fatalf("users %+v", u)
	}
	if len(notes) != 6 {
		t.Fatalf("notes %v", notes)
	}
}
