// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux

package device

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// ptyUnlock unlocks the pty master and returns its slave's path (glibc's
// unlockpt + ptsname: TIOCSPTLCK, TIOCGPTN).
func ptyUnlock(fd int) (string, error) {
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		return "", os.NewSyscallError("TIOCSPTLCK", err)
	}
	n, err := unix.IoctlGetUint32(fd, unix.TIOCGPTN)
	if err != nil {
		return "", os.NewSyscallError("TIOCGPTN", err)
	}
	return "/dev/pts/" + strconv.FormatUint(uint64(n), 10), nil
}
