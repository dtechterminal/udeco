// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/decosys"
)

// Tests that hold a value of this package to the package that owns it,
// where this one cannot import that one outside its tests.

// A site session's PATH, when SiteOptions names none, is the Deco
// firmware's binary directories in decosys's search order. cmd/udeco-ap
// passes that list itself (its agentPATH); this is the default any other
// caller gets, and a given PATH is kept.
func TestSiteDefaultPATH(t *testing.T) {
	if got, want := (&SiteOptions{}).path(), strings.Join(decosys.BinDirs, ":"); got != want {
		t.Errorf("SiteOptions{}.path() = %q, decosys.BinDirs joined %q", got, want)
	}
	if got := (&SiteOptions{Path: "/x/bin"}).path(); got != "/x/bin" {
		t.Errorf("a given Path became %q", got)
	}
}
