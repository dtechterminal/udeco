// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux || darwin

package device

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openPTY opens a pseudo-terminal pair. The master is non-blocking and in
// the runtime poller (os.OpenFile on a character device), so Close
// unblocks a pending Read; the slave goes to the child.
func openPTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	var name string
	var ierr error
	// Control, not Fd: Fd would put the master back into blocking mode
	if cerr := rawControl(master, func(fd int) { name, ierr = ptyUnlock(fd) }); cerr != nil || ierr != nil {
		master.Close()
		if cerr != nil {
			return nil, nil, cerr
		}
		return nil, nil, ierr
	}
	slave, err = os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

// setWinsize sets the terminal size on the pty master (TIOCSWINSZ); the
// kernel sends the foreground process group SIGWINCH.
func setWinsize(master *os.File, cols, rows uint32) error {
	ws := &unix.Winsize{Col: clampDim(cols), Row: clampDim(rows)}
	var ierr error
	if err := rawControl(master, func(fd int) { ierr = unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, ws) }); err != nil {
		return err
	}
	return ierr
}

func rawControl(f *os.File, fn func(fd int)) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Control(func(fd uintptr) { fn(int(fd)) })
}

// clampDim caps a client's terminal dimension at 4096 (0, unknown, is
// passed as is).
func clampDim(v uint32) uint16 {
	return uint16(min(v, 4096))
}
