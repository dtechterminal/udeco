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
//
// Platform jio-mtk has no logread: its BusyBox syslogd writes only the file
// /var/log/messages, which the agent follows instead, merging in its own
// log lines (logfollow.go).

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
	"github.com/antoniocosta/unifi-openwrt/internal/snmpagent"
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
	key  string // the system_cfg (adopted/cfgversion/N) last read
	cur  syslogTarget
	stop context.CancelFunc
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
	if a.x.S.Adopted {
		b, _ := os.ReadFile(a.sysCfgPath)
		in, _ := translate.IntentFromCfg(string(b))
		if s := in.Syslog; s != nil {
			want = syslogTarget{addr: net.JoinHostPort(s.Host, strconv.Itoa(s.Port)), encrypted: s.Encrypted, key: s.Key, level: s.Level,
				host: a.x.Dev.Hostname, tag: device.SyslogTag(a.x.Dev.Model, a.x.Dev.MAC, a.x.S.Version)}
			if want.host == "" {
				want.host = snmpagent.DefaultDescr
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

// logFollow streams the unit's log (logread -f; one line per message). On
// platform jio-mtk it follows syslogd's file instead (logfollow.go), with
// the agent's own lines merged in unless they already go to syslog.
func (a *agent) logFollow(ctx context.Context) (io.ReadCloser, error) {
	if a.o.logFollow != nil {
		return a.o.logFollow(ctx)
	}
	if a.cfg.jio() {
		var own <-chan string
		if a.cfg.Log != "syslog" {
			own = a.selfLog.attach()
		}
		rc := followFile(ctx, a.dev(jioLogPath), a.t.logPoll, own)
		return &tapStream{ReadCloser: rc, done: func() { a.selfLog.detach(own) }}, nil
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

// tapStream detaches the agent's own lines from the log tap on Close.
type tapStream struct {
	io.ReadCloser
	once sync.Once
	done func()
}

func (t *tapStream) Close() error {
	t.once.Do(t.done)
	return t.ReadCloser.Close()
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
	sc.Buffer(make([]byte, device.SyslogLineMax), device.SyslogLineMax)
	limit := device.NewSyslogLimiter(time.Now()) // device.SyslogRate lines/s, bursts of device.SyslogBurst
	failed := false
	for sc.Scan() {
		line, sev, ok := uafSyslog(sc.Text(), t.host, t.tag)
		if !ok || t.level > 0 && sev >= t.level {
			continue
		}
		if !limit.Allow(time.Now()) {
			continue
		}
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
// prog[1]: msg") or a BusyBox syslogd file line ("Nov 19 03:13:11 RIL
// daemon.err prog[1]: msg", platform jio-mtk) into a UniFi AP style syslog
// line ("<27>Nov 19 03:13:11 host U6-Lite...: prog[1]: msg") and its
// severity (0-7). ok is false for an empty line. A line in neither format
// is sent as user.info with the current time.
func uafSyslog(line, host, tag string) (string, int, bool) {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return "", 0, false
	}
	f := strings.Fields(line)
	// logread: weekday month day time year fac.lvl; the file: month day
	// time host fac.lvl
	for _, l := range []struct{ n, month, pri int }{{6, 1, 5}, {5, 0, 4}} {
		if len(f) <= l.n {
			continue
		}
		if _, ok := syslogMonths[f[l.month]]; !ok {
			continue
		}
		if fac, lvl, ok := strings.Cut(f[l.pri], "."); ok {
			fv, fok := device.SyslogFacility(fac)
			lv, lok := device.SyslogSeverity(lvl)
			if fok && lok {
				rest := line
				for i := 0; i < l.n; i++ { // drop the leading fields, keep the message's own spacing
					rest = strings.TrimLeft(rest, " ")
					rest = rest[strings.IndexByte(rest, ' ')+1:]
				}
				return fmt.Sprintf("<%d>%s %2s %s %s %s %s", fv*8+lv, f[l.month], f[l.month+1], f[l.month+2], host, tag,
					strings.TrimLeft(rest, " ")), lv, true
			}
		}
	}
	return fmt.Sprintf("<14>%s %s %s %s", time.Now().Format(time.Stamp), host, tag, line), 6, true
}

var syslogMonths = map[string]bool{"Jan": true, "Feb": true, "Mar": true, "Apr": true, "May": true, "Jun": true,
	"Jul": true, "Aug": true, "Sep": true, "Oct": true, "Nov": true, "Dec": true}
