// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/inform"
)

// Once adopted, the inform reply is the controller's only authenticated
// channel: it must be encrypted with the device key the request was sent
// with. Informs are plain HTTP, so anyone on the LAN who can answer them
// (ARP-spoofing the controller's address) knows the public factory key; a
// reply encrypted with it must be refused, or a forged
// `cmd set-adopt` re-keys the unit and points it at another controller.
func TestAdoptedRefusesFactoryKeyReply(t *testing.T) {
	t.Run("factory key", func(t *testing.T) {
		testForgedReadopt(t, func(mac net.HardwareAddr, js string) ([]byte, error) {
			return inform.Encode(mac, inform.DefaultKeyHex, inform.CBC, []byte(js), nil)
		})
	})
	// inform.Decode takes a frame without the encryption flags as plain
	// zlib JSON: no key at all is needed to forge one
	t.Run("unencrypted", func(t *testing.T) { testForgedReadopt(t, unencryptedFrame) })
}

// unencryptedFrame is a TNBU frame carrying zlib JSON with no encryption.
func unencryptedFrame(mac net.HardwareAddr, js string) ([]byte, error) {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write([]byte(js))
	zw.Close()
	h := make([]byte, inform.HeaderLen)
	binary.BigEndian.PutUint32(h[0:4], inform.Magic)
	copy(h[8:14], mac)
	binary.BigEndian.PutUint16(h[14:16], inform.FlagZlib)
	binary.BigEndian.PutUint32(h[32:36], inform.DataVersion)
	binary.BigEndian.PutUint32(h[36:40], uint32(z.Len()))
	return append(h, z.Bytes()...), nil
}

func testForgedReadopt(t *testing.T, forge func(mac net.HardwareAddr, js string) ([]byte, error)) {
	const (
		attackerKey = "fedcba9876543210fedcba9876543210"
		attackerURL = "http://10.99.99.99:8080/inform"
	)
	var (
		mu     sync.Mutex
		key    = inform.DefaultKeyHex
		forged int
		after  int // device-key informs seen after the first forged reply
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		mu.Lock()
		defer mu.Unlock()
		hdr, _, err := inform.Decode(body, key)
		if err != nil {
			http.Error(w, "undecodable", http.StatusBadRequest)
			return
		}
		var pkt []byte
		if key == inform.DefaultKeyHex {
			// the real controller adopts on the factory key
			pkt, err = inform.Encode(hdr.MAC, key, inform.CBC, []byte(adoptReply), nil)
		} else {
			if forged > 0 {
				after++
			}
			// the attacker: a forged re-adoption without the device key
			forged++
			pkt, err = forge(hdr.MAC, `{"_type":"cmd","cmd":"set-adopt","key":"`+attackerKey+`","uri":"`+attackerURL+`"}`)
		}
		if err != nil {
			t.Errorf("encode: %v", err)
			return
		}
		if key == inform.DefaultKeyHex {
			key = testKey
		}
		w.Write(pkt)
	}))
	t.Cleanup(srv.Close)

	h := newHarness(t, func(c *Config, o *options) { c.InformURL = srv.URL + "/inform" })
	h.start()
	eventually(t, "a forged reply", func() bool { mu.Lock(); defer mu.Unlock(); return forged > 0 })
	// with the fix the unit keeps informing here on its own key; without
	// it, it has moved to the attacker's URL and nothing more arrives
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := after
		mu.Unlock()
		if n >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.stop()

	if h.a.x.S.Key != testKey {
		t.Errorf("device key replaced by a forged reply: %q", h.a.x.S.Key)
	}
	if h.a.x.S.InformURL != srv.URL+"/inform" {
		t.Errorf("inform URL redirected by a forged reply: %q", h.a.x.S.InformURL)
	}
}
