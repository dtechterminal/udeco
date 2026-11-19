// SPDX-License-Identifier: GPL-2.0-or-later

package deco

// Regression tests for the live 0x4012 stall (2026-11-18): the client list
// is a large, slow reply that the app gives 75 s; requests must not be sent
// on a context that already expired; a caller's deadline is not a link
// error; the frame reader never blocks on a reply nobody waits for.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const stallToken = "SECRET-TOKEN-77"

// bigClientList is a 0x4012 reply of about 40 KB: n clients with base64
// names, as the X20 sends them.
func bigClientList(n int) []byte {
	var b strings.Builder
	b.WriteString(`{"error_code":0,"result":{"client_list":[`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"mac":"AA-BB-CC-DD-%02X-%02X","ip":"192.168.0.%d","name":"%s","client_type":"phone","online":true,`+
			`"interface":"main","connection_type":"band5","wire_type":"wireless","access_host":"1","up_speed":0,"down_speed":0,`+
			`"linked_device_info":{"device_id":"dev205","connection_type":["band5"],"signal_strength":{"band5":-52}}}`,
			i/256, i%256, i%250+2, b64(fmt.Sprintf("client-name-%03d-xxxxxxxxxxxxxxxx", i)))
	}
	b.WriteString(`]}}`)
	return []byte(b.String())
}

func TestAppRequestTimeout(t *testing.T) {
	if got := AppRequestTimeout(OpGetClientList); got != 75*time.Second {
		t.Fatalf("0x4012 budget %s, want 75s (l0.java:930 60L + i0.java:581 15s)", got)
	}
	for _, op := range []uint16{OpGetDeviceList, OpGetClientSpeedList, OpGetWireless, OpGetBlockList, OpGetDeviceEthPort} {
		if got := AppRequestTimeout(op); got != 45*time.Second {
			t.Fatalf("0x%04x budget %s, want 45s", op, got)
		}
	}
	c := &Client{cfg: Config{RequestTimeout: 45 * time.Second}}
	if c.timeoutFor(OpGetClientList) != 75*time.Second || c.timeoutFor(OpGetClientSpeedList) != 45*time.Second {
		t.Fatal("Client budgets")
	}
	c.cfg.OpTimeouts = map[uint16]time.Duration{OpGetClientList: time.Second}
	if c.timeoutFor(OpGetClientList) != time.Second {
		t.Fatal("OpTimeouts override")
	}
}

// A ~40 KB client list (112 clients) that takes longer than the default budget arrives
// in five 8156-byte chunks, both ways the device may answer the PUSH
// (transaction/a.java:143-156,177-192,223-234), within the 0x4012 budget.
// The trace shows every frame and packet header but no payload, token or
// password.
func TestClientListSlowMultiChunk(t *testing.T) {
	const n = 112
	big := bigClientList(n)
	if len(big) < 36000 || len(big) > 5*V2ChunkSize {
		t.Fatalf("reply is %d bytes, want ~40 KB in 5 chunks", len(big))
	}
	for _, pushAck := range []bool{false, true} {
		t.Run(fmt.Sprintf("pushAck=%v", pushAck), func(t *testing.T) {
			var mu sync.Mutex
			slow := map[uint16]time.Duration{OpGetClientList: 400 * time.Millisecond}
			h := func(op uint16, req []byte) []byte {
				mu.Lock()
				d := slow[op]
				mu.Unlock()
				time.Sleep(d)
				switch op {
				case OpcodeTokenAlloc:
					return []byte(stallToken)
				case OpcodeTokenVerify, OpcodeTokenFree:
					return nil
				case OpNegotiation:
					return []byte(`{"error_code":0,"result":{"operation_mode":"AP","component_list":[{"id":"client","ver_code":2}]}}`)
				case OpGetClientList:
					return big
				case OpGetClientSpeedList:
					return []byte(`{"error_code":0,"result":{"client_list_speed":[]}}`)
				case OpGetDeviceList:
					return []byte(`{"error_code":0,"result":{"device_list":[]}}`)
				}
				return []byte(`{"error_code":-40210}`)
			}
			srv := newSSHDeco(t, "user", testPassword, h)
			srv.pushAck = pushAck
			var tr syncBuf
			ctx := context.Background()
			c, err := Connect(ctx, Config{Host: "127.0.0.1", Port: srv.port(), SSHUser: "user", CloudPassword: testPassword,
				Owner: true, Heartbeat: 20 * time.Millisecond, RequestTimeout: 200 * time.Millisecond, Trace: tr.logf})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()

			var cl ClientListResult
			start := time.Now()
			if err := c.Get(ctx, OpGetClientList, nil, &cl); err != nil {
				t.Fatalf("0x4012 slower than the default budget must still arrive: %v", err)
			}
			if el := time.Since(start); el < 400*time.Millisecond {
				t.Fatalf("handler delay not exercised (%s)", el)
			}
			if len(cl.ClientList) != n || string(cl.ClientList[n-1].Name) != fmt.Sprintf("client-name-%03d-xxxxxxxxxxxxxxxx", n-1) {
				t.Fatalf("client list: %d clients", len(cl.ClientList))
			}
			want := []uint32{8156, 16312, 24468, 32624}
			if pushAck {
				want = append([]uint32{0}, want...)
			}
			if got := srv.session().pullStarts(OpGetClientList); !slices.Equal(got, want) {
				t.Fatalf("PULL starts %v, want %v", got, want)
			}

			// Any other opcode keeps the default budget: a 400 ms 0x4014
			// misses its 200 ms. The late reply is dropped by the reader
			// (counted), and the stream still carries the next request.
			mu.Lock()
			slow[OpGetClientSpeedList] = 400 * time.Millisecond
			mu.Unlock()
			var sp ClientSpeedListResult
			if err := c.Get(ctx, OpGetClientSpeedList, nil, &sp); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("0x4014 with the default budget: %v", err)
			}
			mu.Lock()
			slow[OpGetClientSpeedList] = 0
			mu.Unlock()
			waitUntil(t, "late 0x4014 reply", func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.fc.Unmatched() >= 1 })
			var dl DeviceListResult
			if err := c.Get(ctx, OpGetDeviceList, nil, &dl); err != nil {
				t.Fatalf("stream unusable after a late reply: %v", err)
			}

			logs := tr.String()
			if testing.Verbose() {
				t.Log(logs)
			}
			for _, want := range []string{"trace: tmp +", "tx DATA serial=", "rx DATA serial=", "[v2 PULL_ACK opcode=0x4012",
				"biz tx PUSH opcode=0x4012", "biz rx PULL_ACK opcode=0x4012", "total=" + fmt.Sprint(len(big)), "chunk=8156",
				"crc ok", "req 0x4012 start (budget 1m15s)", "req 0x4012 done in", "req 0x4014 start (budget 200ms)",
				"NO-WAITER(dropped)", "no reply after"} {
				if !strings.Contains(logs, want) {
					t.Errorf("trace lacks %q", want)
				}
			}
			for _, secret := range []string{stallToken, testPassword, b64("client-name-001-xxxxxxxxxxxxxxxx"), "AA-BB-CC"} {
				if strings.Contains(logs, secret) {
					t.Errorf("trace leaks %q", secret)
				}
			}
		})
	}
}

func waitUntil(t *testing.T, what string, f func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A request whose context already ended is never written: the device would
// otherwise run it ahead of the next real request (live serials 5 and 6).
func TestNothingSentOnExpiredContext(t *testing.T) {
	s, fc, d := newPair(t, true, jsonHandler("t", 0))
	defer fc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.Call(ctx, 0, nil); err != nil {
		t.Fatal(err)
	}
	dead, stop := context.WithCancel(ctx)
	stop()
	if _, err := s.Call(dead, OpGetClientSpeedList, mustReq(nil)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if _, err := s.Call(ctx, OpGetDeviceList, mustReq(nil)); err != nil {
		t.Fatal(err)
	}
	if got, want := d.received(), []string{"PUSH 0x0001", "PUSH 0x400f"}; !slices.Equal(got, want) {
		t.Fatalf("device received %v, want %v", got, want)
	}
}

// Repeated reply frames for one serial are dropped, as the app's
// PublishSubject does; they never block the reader (h0.java:219-225), and
// every one is counted. The first copy claims the waiter: a copy arriving
// after the caller took the first one from its buffer, but before
// RoundTrip removed the waiter, used to slip into the emptied buffer
// uncounted (about 1 reply in 80 under -race). Many calls make that
// regression show up on almost every run.
func TestDuplicateRepliesDoNotStallReader(t *testing.T) {
	s, fc, d := newPair(t, true, jsonHandler("t", 0))
	defer fc.Close()
	d.mu.Lock()
	d.copies = 3
	d.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	const calls = 300
	for i := range calls {
		if _, err := s.Call(ctx, OpGetDeviceList, mustReq(nil)); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	want := int64(2 * (calls + 1)) // every call + the token alloc, two extra copies each
	for end := time.Now().Add(5 * time.Second); fc.Unmatched() < want && time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
	}
	if n := fc.Unmatched(); n != want {
		t.Fatalf("%d duplicate frames counted, want %d", n, want)
	}
}

// The caller's deadline (the -print budget, shutdown) ending a poll is not a
// link error: the session stays up, the error streak stays 0, no further
// polls go out on the expired context, and the cancelled retry does not
// overwrite the value and ok flag an earlier poll stored.
func TestMeshParentDeadlineIsNotALinkError(t *testing.T) {
	r := newRig(t, nil)
	r.step()
	before := r.m.Snapshot()
	if !before.Connected || !before.Speeds.OK {
		t.Fatal("not up")
	}
	iot, wireless := r.emu.count(OpGetIoTClientList), r.emu.count(OpGetWireless)
	r.emu.setHook(func(op uint16) {
		if op == OpGetClientSpeedList {
			time.Sleep(600 * time.Millisecond)
		}
	})
	r.clock.Add(15 * time.Second)
	r.m.RequestPoll(OpGetWireless)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	r.m.step(ctx)
	cancel()
	r.emu.setHook(nil)
	s := r.m.Snapshot()
	if r.m.client == nil || !r.m.client.Alive() || !s.Connected || r.m.errStreak != 0 {
		t.Fatalf("parent deadline counted as a link error: streak=%d %+v", r.m.errStreak, s)
	}
	if !s.Speeds.OK || s.Speeds.Err != "" || !s.Speeds.At.Equal(before.Speeds.At) || s.Busy != nil {
		t.Fatalf("cancelled retry overwrote the speeds slot: %+v busy %+v", s.Speeds, s.Busy)
	}
	if r.emu.count(OpGetIoTClientList) != iot || r.emu.count(OpGetWireless) != wireless {
		t.Fatal("polls were sent after the caller's deadline")
	}
	// The late 0x4014 reply is dropped; the next pass works on the same login.
	r.clock.Add(15 * time.Second)
	r.step()
	if s := r.m.Snapshot(); !s.Speeds.OK || !s.Speeds.At.Equal(r.clock.Now()) || !s.IoT.OK || s.Logins != 1 {
		t.Fatalf("after the late reply: %+v", s)
	}
}

// A poll that never succeeded and is cancelled records why.
func TestMeshCancelledFirstPollRecordsError(t *testing.T) {
	r := newRig(t, func(c *MeshConfig) { c.Only = []uint16{OpGetClientList} })
	r.emu.setHook(func(op uint16) {
		if op == OpGetClientList {
			time.Sleep(600 * time.Millisecond)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	r.m.step(ctx)
	cancel()
	r.emu.setHook(nil)
	if s := r.m.Snapshot(); s.Clients.OK || s.Clients.Err == "" || s.Busy != nil {
		t.Fatalf("clients: %+v busy %+v", s.Clients, s.Busy)
	}
}

// MaxLogins caps the Mesh's logins: a lost session stays down.
func TestMeshMaxLogins(t *testing.T) {
	r := newRig(t, func(c *MeshConfig) { c.MaxLogins = 1 })
	r.step()
	r.srv.bye(0)
	r.waitDead()
	r.step()
	for range 3 {
		r.clock.Add(20 * time.Minute)
		r.step()
	}
	if _, _, logins := r.srv.counts(); logins != 1 {
		t.Fatalf("%d logins with MaxLogins=1", logins)
	}
	if s := r.m.Snapshot(); s.Connected || s.Logins != 1 {
		t.Fatalf("%+v", s)
	}
}

// Only polls the listed Gets in the given order; ports pull in the device list.
func TestMeshOnly(t *testing.T) {
	var mu sync.Mutex
	var seen []uint16
	r := newRig(t, func(c *MeshConfig) { c.Only = []uint16{OpGetClientSpeedList, OpGetClientList} })
	r.emu.setHook(func(op uint16) {
		if op >= 0x4002 { // not the token or NEGOTIATE
			mu.Lock()
			seen = append(seen, op)
			mu.Unlock()
		}
	})
	r.step()
	mu.Lock()
	got := slices.Clone(seen)
	mu.Unlock()
	if want := []uint16{OpGetClientSpeedList, OpGetClientList}; !slices.Equal(got, want) {
		t.Fatalf("polled %x, want %x", got, want)
	}
	m, err := NewMesh(MeshConfig{MasterIP: "127.0.0.1", MasterMAC: "b0:a7:b9:3e:16:94", TPLinkID: "x", Password: "y",
		Only: []uint16{OpGetDeviceEthPort}})
	if err != nil || !slices.Equal(m.PolledOps(), []uint16{OpGetDeviceList, OpGetDeviceEthPort}) {
		t.Fatalf("ports only: %v %x", err, m.PolledOps())
	}
	for _, bad := range [][]uint16{{OpNegotiation}, {OpGetClientList, OpGetClientList}} {
		if _, err := NewMesh(MeshConfig{MasterIP: "127.0.0.1", MasterMAC: "b0:a7:b9:3e:16:94", TPLinkID: "x", Password: "y", Only: bad}); err == nil {
			t.Fatalf("Only %x accepted", bad)
		}
	}
}
