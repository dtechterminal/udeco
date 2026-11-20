// SPDX-License-Identifier: GPL-2.0-or-later

// Package atomicfile replaces a file through a temporary file beside it
// and a rename, so a reader (or a restart after a power cut) finds the old
// content or the new, never half of one. It is the one copy of that
// sequence for the state files of the agents and daemons; it imports
// nothing from this module.
//
// Three writers keep their own sequence, each for what Write does not do:
// internal/bcmwifi's writeFileAtomic (a random temporary name, the
// directory made, the mode set on the open file), internal/decosys'
// writeRaw (the temporary file in the state directory, not beside the
// target) and cmd/udeco-ap's replaceKeepMode (the target's mode put on the
// temporary file before the rename). TestRenameSites lists them.
package atomicfile

import "os"

// Write replaces path with data: it writes tmpPath (os.WriteFile, so perm
// is used only when tmpPath does not exist yet, less the umask) and
// renames it to path. tmpPath must be on path's filesystem; every caller
// passes the name it has always used there ("<path>.tmp", "<path>.udeco",
// "<path>.new"), so no file on a unit's flash is named differently.
//
// When the write or the rename fails, tmpPath is removed, path is what it
// was and the error is the one that failed. Write makes no directory,
// syncs nothing and changes no mode: a caller that needs one of those does
// it around the call.
func Write(path, tmpPath string, data []byte, perm os.FileMode) error {
	err := os.WriteFile(tmpPath, data, perm)
	if err == nil {
		err = os.Rename(tmpPath, path)
	}
	if err != nil {
		os.Remove(tmpPath)
	}
	return err
}
