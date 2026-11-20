// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"
)

// UniFi encrypted remote syslog (UniFi Network 10.6.109, RemoteLoggerServer on
// UDP 5514; docs/internals.md). One datagram per message:
//
//	0  4  magic AB CD DC BA
//	4  1  0x01
//	5  4  00 00 00 01
//	9  8  device hash_id (the 16 hex chars the AP reports in its inform)
//	17 12 GCM nonce (random)
//	29 n  AES-256-GCM(key = hex(syslog.remote.key), AAD = bytes 0..28) || tag
//
// The plaintext is a syslog line; the controller writes it to
// logs/remote/<ip>_<mac>.log.

const syslogHeader = 29

// MaxSyslogDatagram is the controller's receive buffer.
const MaxSyslogDatagram = 4096

// NewHashID returns a random device hash_id in the controller's format
// (16 hex, not all zero).
func NewHashID() (string, error) {
	b := make([]byte, 8)
	for {
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		if s := hex.EncodeToString(b); s != "0000000000000000" {
			return s, nil
		}
	}
}

// SealSyslog builds one encrypted syslog datagram.
func SealSyslog(keyHex, hashID string, msg []byte) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return nil, errors.New("syslog key: want 64 hex characters")
	}
	id, err := hex.DecodeString(strings.ToLower(hashID))
	if err != nil || len(id) != 8 {
		return nil, errors.New("hash_id: want 16 hex characters")
	}
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	if max := MaxSyslogDatagram - syslogHeader - gcm.Overhead(); len(msg) > max {
		msg = msg[:max]
	}
	hdr := make([]byte, syslogHeader, syslogHeader+len(msg)+gcm.Overhead())
	copy(hdr, []byte{0xAB, 0xCD, 0xDC, 0xBA, 0x01, 0, 0, 0, 1})
	copy(hdr[9:17], id)
	if _, err := rand.Read(hdr[17:29]); err != nil {
		return nil, err
	}
	return gcm.Seal(hdr, hdr[17:29], msg, hdr[:syslogHeader]), nil
}

// OpenSyslog is the controller's side (for tests).
func OpenSyslog(keyHex string, d []byte) (hashID string, msg []byte, err error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 || len(d) < syslogHeader {
		return "", nil, errors.New("bad key or datagram")
	}
	if string(d[:9]) != string([]byte{0xAB, 0xCD, 0xDC, 0xBA, 0x01, 0, 0, 0, 1}) {
		return "", nil, errors.New("not an encrypted syslog datagram")
	}
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	msg, err = gcm.Open(nil, d[17:29], d[syslogHeader:], d[:syslogHeader])
	return hex.EncodeToString(d[9:17]), msg, err
}

// The syslog line a UniFi AP sends, for the two forwarders (cmd/uow's and
// cmd/udeco-ap's). Each has its own reader of the unit's log lines; the
// tag, the priority tables and the send limit are the same.

// SyslogTag is the tag of a UniFi AP's syslog lines: "MODEL,mac12,version:",
// the MAC as 12 lower-case hex digits.
func SyslogTag(model string, mac net.HardwareAddr, version string) string {
	return model + "," + strings.ReplaceAll(strings.ToLower(mac.String()), ":", "") + "," + version + ":"
}

// SyslogFacility is the code of a facility as logread and BusyBox syslogd
// name it ("daemon" in "daemon.err"); ok is false for a name it does not
// know. A line's priority is facility*8 + severity.
func SyslogFacility(name string) (code int, ok bool) {
	code, ok = syslogFacilities[name]
	return code, ok
}

// SyslogSeverity is the code (0 to 7) of a severity as logread and BusyBox
// syslogd name it ("err" in "daemon.err").
func SyslogSeverity(name string) (code int, ok bool) {
	code, ok = syslogSeverities[name]
	return code, ok
}

var syslogFacilities = map[string]int{"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
	"lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11, "local0": 16, "local1": 17,
	"local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23}

var syslogSeverities = map[string]int{"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warn": 4, "warning": 4,
	"notice": 5, "info": 6, "debug": 7}

const (
	// SyslogRate is how many lines a second a forwarder sends at most,
	// over time; SyslogBurst is how many it may send at once.
	SyslogRate  = 50
	SyslogBurst = 100
	// SyslogLineMax is the longest log line a forwarder reads, in bytes.
	SyslogLineMax = 8192
)

// SyslogLimiter is a forwarder's send limit: a token bucket of SyslogBurst
// lines that fills at SyslogRate a second. A line it does not allow is
// dropped, not queued. Not for concurrent use.
type SyslogLimiter struct {
	tokens float64
	last   time.Time
}

// NewSyslogLimiter returns a full bucket.
func NewSyslogLimiter(now time.Time) *SyslogLimiter {
	return &SyslogLimiter{tokens: SyslogBurst, last: now}
}

// Allow reports whether a line may be sent at now, and counts it.
func (l *SyslogLimiter) Allow(now time.Time) bool {
	l.tokens = min(SyslogBurst, l.tokens+now.Sub(l.last).Seconds()*SyslogRate)
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
