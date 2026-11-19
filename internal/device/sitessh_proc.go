// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux || darwin

package device

// Site shells and commands (sitessh.go): a login shell or "sh -c" in its
// own session, on a PTY when the client asked for one (controlling
// terminal, TERM, window size, SIGWINCH) or on pipes otherwise (stdout,
// stderr, stdin with EOF). A hang-up (the client went, the user was
// removed, the idle timeout) sends SIGHUP to the process group and
// SIGKILL if it is still there 3 s later.

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// killGraceSite is how long a hung-up process group has before SIGKILL.
const killGraceSite = 3 * time.Second

type siteProc struct {
	cmd     *exec.Cmd
	master  *os.File // nil without a PTY
	outDone chan struct{}
	mu      sync.Mutex
	exited  bool
	hung    bool
}

var sshSignals = map[string]syscall.Signal{"HUP": syscall.SIGHUP, "INT": syscall.SIGINT, "QUIT": syscall.SIGQUIT,
	"KILL": syscall.SIGKILL, "TERM": syscall.SIGTERM, "USR1": syscall.SIGUSR1, "USR2": syscall.SIGUSR2,
	"ALRM": syscall.SIGALRM, "PIPE": syscall.SIGPIPE, "ABRT": syscall.SIGABRT}

var sshSignalNames = map[syscall.Signal]string{syscall.SIGHUP: "HUP", syscall.SIGINT: "INT", syscall.SIGQUIT: "QUIT",
	syscall.SIGKILL: "KILL", syscall.SIGTERM: "TERM", syscall.SIGUSR1: "USR1", syscall.SIGUSR2: "USR2",
	syscall.SIGALRM: "ALRM", syscall.SIGPIPE: "PIPE", syscall.SIGABRT: "ABRT", syscall.SIGSEGV: "SEGV",
	syscall.SIGFPE: "FPE", syscall.SIGILL: "ILL", syscall.SIGBUS: "BUS"}

// startSiteProc starts spec with its I/O on rw (stdin and stdout) and
// stderr (pipes only; a PTY merges them).
func startSiteProc(spec procSpec, rw io.ReadWriter, stderr io.Writer) (*siteProc, error) {
	c := &exec.Cmd{Path: spec.shell}
	base := filepath.Base(spec.shell)
	if spec.command == "" {
		c.Args = []string{"-" + base} // a login shell, as dropbear starts it
	} else {
		c.Args = []string{base, "-c", spec.command}
	}
	c.Dir = spec.home
	if fi, err := os.Stat(spec.home); err != nil || !fi.IsDir() {
		c.Dir = "/"
	}
	p := &siteProc{cmd: c, outDone: make(chan struct{})}
	if spec.pty == nil {
		c.Env = spec.environ("")
		c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		c.Stdout, c.Stderr = rw, stderr
		// the output copies end at most 1 s after the shell exits, even
		// when a background child keeps the pipes open
		c.WaitDelay = time.Second
		in, err := c.StdinPipe()
		if err != nil {
			return nil, err
		}
		if err := c.Start(); err != nil {
			return nil, err
		}
		close(p.outDone)
		go func() {
			io.Copy(in, rw) // ends at the client's EOF (or when the process went)
			in.Close()
		}()
		return p, nil
	}
	master, slave, err := openPTY()
	if err != nil {
		return nil, err
	}
	if spec.pty.Cols > 0 || spec.pty.Rows > 0 {
		setWinsize(master, spec.pty.Cols, spec.pty.Rows)
	}
	c.Env = spec.environ(slave.Name())
	c.Stdin, c.Stdout, c.Stderr = slave, slave, slave
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	err = c.Start()
	slave.Close() // the child has its own copies
	if err != nil {
		master.Close()
		return nil, err
	}
	p.master = master
	go func() {
		io.Copy(rw, master) // ends with EIO once every slave copy is closed
		close(p.outDone)
	}()
	go io.Copy(master, rw)
	return p, nil
}

// wait waits for the process and the rest of its output.
func (p *siteProc) wait() exitState {
	p.cmd.Wait()
	p.mu.Lock()
	p.exited = true
	p.mu.Unlock()
	if p.master != nil {
		select {
		case <-p.outDone:
		case <-time.After(time.Second): // a background job keeps the terminal
		}
		p.master.Close()
		<-p.outDone
	}
	st := exitState{code: 255}
	if ps := p.cmd.ProcessState; ps != nil {
		if ws, ok := ps.Sys().(syscall.WaitStatus); ok {
			switch {
			case ws.Signaled():
				if name, ok := sshSignalNames[ws.Signal()]; ok {
					st.signal, st.core = name, ws.CoreDump()
				} else {
					st.code = 128 + int(ws.Signal())
				}
			case ws.Exited():
				st.code = ws.ExitStatus()
			}
		}
	}
	return st
}

// hangup ends the session's processes: SIGHUP to the group (and, with a
// PTY, the terminal's hang-up), SIGKILL after killGraceSite. Only while the
// shell has not been reaped, so a recycled PID is never signalled.
func (p *siteProc) hangup() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.exited || p.hung {
		return
	}
	p.hung = true
	pid := p.cmd.Process.Pid
	syscall.Kill(-pid, syscall.SIGHUP)
	syscall.Kill(-pid, syscall.SIGCONT)
	if p.master != nil {
		p.master.Close()
	}
	time.AfterFunc(killGraceSite, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if !p.exited {
			syscall.Kill(-pid, syscall.SIGKILL)
		}
	})
}

// signal delivers an SSH "signal" request to the process group.
func (p *siteProc) signal(name string) bool {
	sig, ok := sshSignals[name]
	if !ok {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.exited {
		return false
	}
	return syscall.Kill(-p.cmd.Process.Pid, sig) == nil
}

// resize applies a window-change (PTY only).
func (p *siteProc) resize(cols, rows uint32) {
	if p.master != nil {
		setWinsize(p.master, cols, rows)
	}
}
