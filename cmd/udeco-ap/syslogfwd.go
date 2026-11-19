// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Remote syslog (system_cfg syslog.remote.*), plain or UniFi-encrypted
// (fw_caps 0x1000000, supportSyslogEncryption). The U6 Pro streams its log
// with `logread -f -u -r <ip> <port> -h <host> -E <key>`; the Deco's logread
// has no -E, so the agent follows `logread -f` itself and sends each line as
// one UDP datagram: plain RFC 3164 text, or sealed for the controller's
// listener on :5514 (device.SealSyslog: AES-256-GCM with the device's
// syslog key, tagged with its hash_id). Nothing on the unit changes (logd's
// own remote target is left alone), so it runs in observe and takeover mode
// alike. docs/deco/features/pathmon.md (with path monitoring).

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// syslogTarget is one forwarding setup; a change of any field restarts it.
type syslogTarget struct {
	addr      string // host:port
	encrypted bool
	key       string // syslog.remote.key (a secret: never logged)
	level     int    // syslog.level: send severities below it (0 = all)
	hashID    string // the inform's hash_id (encrypted only)
	host, tag string // hostname and "MODEL,mac12,version:" of the lines
}

func (t syslogTarget) String() string {
	if t.addr == "" {
		return "off"
	}
	kind := "plain"
	if t.encrypted {
		kind = "UniFi-encrypted"
	}
	lvl := "all levels"
	if t.level > 0 {
		lvl = fmt.Sprintf("severity < %d", t.level)
	}
	return fmt.Sprintf("%s to %s (%s)", kind, t.addr, lvl)
}

// syslogState is the forwarder (loop goroutine fields).
type syslogState struct {
	key      string // the system_cfg (adopted/cfgversion/N) last read
	cur      syslogTarget
	stop     context.CancelFunc
	jioNoted bool // the platform-has-no-logread note was logged
}

// syslogFollow starts, changes or stops the forwarding when the saved
// system_cfg (or the identity its lines carry) changed. Loop goroutine; ctx
// is the agent's run context.
func (a *agent) syslogFollow(ctx context.Context) {
	if a.sl == nil {
		a.sl = &syslogState{}
	}
	sl := a.sl
	key := strconv.FormatBool(a.x.S.Adopted) + "/" + a.x.WantedCfgVersion() + "/" + strconv.Itoa(a.x.S.SystemCfgN) +
		"/" + a.x.S.Version + "/" + a.x.S.HashID + "/" + a.x.Dev.Hostname
	if key == sl.key {
		return
	}
	sl.key = key
	var want syslogTarget
	if a.x.S.Adopted && a.cfg.jio() && !sl.jioNoted {
		// the JCOW414's syslogd keeps no shared buffer (-n -m 0): logread
		// cannot follow it, so nothing is forwarded
		sl.jioNoted = true
		a.logf("remote syslog: not forwarded on platform %s (its syslogd has no buffer logread can follow)", a.cfg.Platform)
	}
	if a.x.S.Adopted && !a.cfg.jio() {
		b, _ := os.ReadFile(a.sysCfgPath)
		in, _ := translate.IntentFromCfg(string(b))
		if s := in.Syslog; s != nil {
			want = syslogTarget{addr: net.JoinHostPort(s.Host, strconv.Itoa(s.Port)), encrypted: s.Encrypted, key: s.Key, level: s.Level,
				host: a.x.Dev.Hostname, tag: fmt.Sprintf("%s,%s,%s:", a.x.Dev.Model, strings.ReplaceAll(strings.ToLower(a.x.Dev.MAC.String()), ":", ""), a.x.S.Version)}
			if want.host == "" {
				want.host = "U6-Lite"
			}
			if s.Encrypted {
				want.hashID = a.x.S.HashID
			}
		}
	}
	if want == sl.cur {
		return
	}
	if sl.stop != nil {
		sl.stop()
		sl.stop = nil
	}
	sl.cur = want
	a.logf("remote syslog: %s", want)
	if want.addr == "" {
		return
	}
	fctx, cancel := context.WithCancel(ctx)
	sl.stop = cancel
	a.bg.Add(1)
	go func() { defer a.bg.Done(); a.forwardSyslog(fctx, want) }()
}

// logFollow streams the unit's log (logread -f; one line per message).
func (a *agent) logFollow(ctx context.Context) (io.ReadCloser, error) {
	if a.o.logFollow != nil {
		return a.o.logFollow(ctx)
	}
	// -l 1: only the newest buffered line, so a restart does not resend the
	// whole ring buffer
	cmd := exec.CommandContext(ctx, "logread", "-f", "-l", "1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &cmdStream{ReadCloser: out, cmd: cmd}, nil
}

// cmdStream is a child's stdout; Close kills and reaps the child once.
// forwardSyslogOnce closes it both from its ctx hook and on return, and a
// second concurrent exec.Cmd.Wait blocks forever: on 2026-11-19 that kept
// r8 from exiting on SIGTERM once remote syslog was on.
type cmdStream struct {
	io.ReadCloser
	cmd  *exec.Cmd
	once sync.Once
	err  error
}

func (c *cmdStream) Close() error {
	c.once.Do(func() {
		c.ReadCloser.Close()
		c.cmd.Process.Kill()
		c.err = c.cmd.Wait()
	})
	return c.err
}

// syslogRetry: the wait before logread or the socket is tried again.
const syslogRetry = 10 * time.Second

// forwardSyslog sends the log to t until ctx ends; logread exiting (logd
// restarted) or a socket error starts it again after syslogRetry.
func (a *agent) forwardSyslog(ctx context.Context, t syslogTarget) {
	lastErr := ""
	for ctx.Err() == nil {
		err := a.forwardSyslogOnce(ctx, t)
		if ctx.Err() != nil {
			return
		}
		if err != nil && err.Error() != lastErr {
			lastErr = err.Error()
			a.logf("remote syslog: %v (retrying every %s; further identical errors not logged)", err, syslogRetry)
		}
		select {
		case <-ctx.Done():
		case <-time.After(syslogRetry):
		}
	}
}

func (a *agent) forwardSyslogOnce(ctx context.Context, t syslogTarget) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", t.addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	rc, err := a.logFollow(ctx)
	if err != nil {
		return fmt.Errorf("logread: %w", err)
	}
	defer rc.Close()
	stop := context.AfterFunc(ctx, func() { rc.Close() })
	defer stop()
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 8192), 8192)
	tokens, last := 100.0, time.Now()
	failed := false
	for sc.Scan() {
		line, sev, ok := uafSyslog(sc.Text(), t.host, t.tag)
		if !ok || t.level > 0 && sev >= t.level {
			continue
		}
		now := time.Now()
		tokens = min(100, tokens+now.Sub(last).Seconds()*50) // 50 lines/s, bursts of 100
		last = now
		if tokens < 1 {
			continue
		}
		tokens--
		b := []byte(line)
		if t.encrypted {
			if b, err = device.SealSyslog(t.key, t.hashID, b); err != nil {
				return err // a bad key or hash_id: nothing can be sent
			}
		}
		if _, err := conn.Write(b); err != nil && !failed {
			failed = true
			a.logf("remote syslog: send to %s: %v (further send errors not logged)", t.addr, err)
		}
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("logread: %w", err)
	}
	return fmt.Errorf("logread ended")
}

// uafSyslog turns a logread line ("Thu Nov 19 03:13:11 2026 daemon.err
// prog[1]: msg") into a UniFi AP style syslog line ("<27>Nov 19 03:13:11
// host U6-Lite...: prog[1]: msg") and its severity (0-7). ok is false for
// an empty line. A line logread did not format is sent as user.info with
// the current time.
func uafSyslog(line, host, tag string) (string, int, bool) {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return "", 0, false
	}
	f := strings.Fields(line)
	if len(f) >= 7 {
		if fac, lvl, ok := strings.Cut(f[5], "."); ok {
			fv, fok := syslogFacilities[fac]
			lv, lok := syslogSeverities[lvl]
			if fok && lok {
				rest := line
				for i := 0; i < 6; i++ { // drop the six leading fields, keep the message's own spacing
					rest = strings.TrimLeft(rest, " ")
					rest = rest[strings.IndexByte(rest, ' ')+1:]
				}
				return fmt.Sprintf("<%d>%s %2s %s %s %s %s", fv*8+lv, f[1], f[2], f[3], host, tag, strings.TrimLeft(rest, " ")), lv, true
			}
		}
	}
	return fmt.Sprintf("<14>%s %s %s %s", time.Now().Format(time.Stamp), host, tag, line), 6, true
}

var syslogFacilities = map[string]int{"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
	"lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11, "local0": 16, "local1": 17,
	"local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23}

var syslogSeverities = map[string]int{"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warn": 4, "warning": 4,
	"notice": 5, "info": 6, "debug": 7}
