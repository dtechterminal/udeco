// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import "github.com/dtechterminal/udeco/internal/pathmon"

// Path monitoring (system_cfg pathmon.*) is run by the Deco agent itself
// (cmd/udeco-ap/pathmon.go with internal/pathmon), in observe and takeover
// mode alike: it only sends ICMP echoes. The section is therefore handled;
// only what pathmon.FromCfg skips or clamps is noted. (The controller sends
// the section only to a device claiming fw3_caps 0x40, which only the Deco
// agent does, so marking it handled changes nothing for upstream's uow or
// cmd/udeco.)
func init() { handled["pathmon"] = true }

// pathmonNotes adds pathmon.FromCfg's notes (skipped targets, clamped
// values) to the intent notes.
func pathmonNotes(cfg Cfg, nb *noteList) {
	_, notes := pathmon.FromCfg(cfg)
	for _, n := range notes {
		nb.addf("%s", n)
	}
}
