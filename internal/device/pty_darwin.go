// SPDX-License-Identifier: GPL-2.0-or-later

//go:build darwin

package device

import (
	"bytes"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ptyUnlock grants and unlocks the pty master and returns its slave's path
// (libc's grantpt + unlockpt + ptsname: TIOCPTYGRANT, TIOCPTYUNLK,
// TIOCPTYGNAME). Darwin is only a test platform for this code.
func ptyUnlock(fd int) (string, error) {
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
		return "", os.NewSyscallError("TIOCPTYGRANT", err)
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
		return "", os.NewSyscallError("TIOCPTYUNLK", err)
	}
	var name [128]byte
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&name[0]))); e != 0 {
		return "", os.NewSyscallError("TIOCPTYGNAME", e)
	}
	n := bytes.IndexByte(name[:], 0)
	if n < 0 {
		n = len(name)
	}
	return string(name[:n]), nil
}
