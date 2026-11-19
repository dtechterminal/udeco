// SPDX-License-Identifier: GPL-2.0-or-later

package main

// In-process stand-ins for the two network peers, so the daemon runs end
// to end without touching a real Deco or controller:
//   - decoEmu: a three-unit Deco X20 mesh master behind a real x/crypto/ssh
//     server on 127.0.0.1 (password auth, the 127.0.0.1:20002 channel, TMP
//     v1 frames and business V2), plus a TDP stand-in for discovery;
//   - fakeCtl: a UniFi controller's /inform endpoint that decrypts with the
//     default key, adopts with setparam mgmt_cfg authkey, and from then on
//     only accepts informs encrypted with the new key.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/antoniocosta/unifi-openwrt/internal/deco"
	"github.com/antoniocosta/unifi-openwrt/internal/inform"
)

const (
	testTPLinkID = "Owner@Example.com"
	testPassword = "hunter2-tplink-pw"
	testPSK      = "s3cret-Wifi-PSK"
	testUniFiPSK = "unifi-psk-0987"
	clientMAC    = "aa:bb:cc:dd:ee:01"
	// masterRawID is the master's TMP device_list id; TDP carries md5hex of
	// every device_list id (deco.DeviceIDDigest).
	masterRawID = "8022B0A7B93E16940A1B2C3D4E5F60718293A4B5"
)

func hexOf(b []byte) string   { return hex.EncodeToString(b) }
func md5hex(s string) string  { h := md5.Sum([]byte(s)); return hexOf(h[:]) }
func sha1hex(s string) string { h := sha1.Sum([]byte(s)); return hexOf(h[:]) }
func b64(s string) string     { return base64.StdEncoding.EncodeToString([]byte(s)) }

// testUnits: the master must be 127.0.0.1 (the Mesh dials the master IP);
// the satellites are never dialed.
var testUnits = []UnitConfig{
	{Name: "deco-241", IP: "127.0.0.1", MAC: "b0:a7:b9:3e:16:94"},
	{Name: "deco-205", IP: "127.0.0.2", MAC: "b0:a7:b9:3e:17:00"},
	{Name: "deco-232", IP: "127.0.0.3", MAC: "b0:a7:b9:3e:15:fc"},
}

// decoEmu is the mesh master: SSH server, business replies, counters.
type decoEmu struct {
	t      *testing.T
	ln     net.Listener
	signer ssh.Signer

	mu      sync.Mutex
	owner   string // TDP owner hash
	replies map[uint16]string
	calls   map[uint16]int
	conns   int
	pwTries int
	logins  int
	silent  map[uint16]bool // opcodes the device never answers
	byes    int             // TMP BYE frames received
}

func (e *decoEmu) setSilent(op uint16) { e.mu.Lock(); e.silent[op] = true; e.mu.Unlock() }

func (e *decoEmu) isSilent(op uint16) bool { e.mu.Lock(); defer e.mu.Unlock(); return e.silent[op] }

func (e *decoEmu) byeCount() int { e.mu.Lock(); defer e.mu.Unlock(); return e.byes }

func newDecoEmu(t *testing.T) *decoEmu {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader) // the X20 offers ecdsa-sha2-nistp521
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &decoEmu{t: t, ln: ln, signer: signer, owner: md5hex(testTPLinkID),
		replies: map[uint16]string{}, calls: map[uint16]int{}, silent: map[uint16]bool{}}
	e.ok(deco.OpNegotiation, `{"operation_mode":"AP","component_list":[{"id":"block_list","ver_code":1},{"id":"wireless","ver_code":2},`+
		`{"id":"client","ver_code":2},{"id":"client_mesh","ver_code":2},{"id":"client_link","ver_code":1},{"id":"client_speed","ver_code":1},`+
		`{"id":"iot_client","ver_code":1},{"id":"client_device","ver_code":1},{"id":"device","ver_code":5}]}`)
	e.ok(deco.OpGetDeviceList, `{"device_list":[`+
		`{"device_id":"`+masterRawID+`","mac":"B0-A7-B9-3E-16-94","ip":"192.168.0.241","role":"master","master_device_id":"`+masterRawID+`","runtime":5000,"device_model":"X20","software_ver":"1.2.3"},`+
		`{"device_id":"dev205","mac":"B0-A7-B9-3E-17-00","ip":"192.168.0.205","role":"slave","inet_status":"online","nickname":"`+b64("Bedroom")+`","custom_nickname":"`+b64("Bedroom")+`"},`+
		`{"device_id":"dev232","mac":"B0-A7-B9-3E-15-FC","ip":"192.168.0.232","role":"slave"}]}`)
	e.ok(deco.OpGetClientList, `{"client_list":[{"mac":"AA-BB-CC-DD-EE-01","ip":"192.168.0.50","name":"`+b64("phone")+
		`","client_type":"phone","online":true,"interface":"main","linked_device_info":{"device_id":"dev205","connection_type":["band5"],"signal_strength":{"band5":-52},"tx_rate_list":{"band5":866},"rx_rate_list":{"band5":433}}}]}`)
	e.ok(deco.OpGetClientSpeedList, `{"client_list_speed":[{"mac":"AA-BB-CC-DD-EE-01","up_speed":12,"down_speed":340}]}`)
	e.ok(deco.OpGetIoTClientList, `{"iot_client_list":[],"iot_count_per_cate_max":64,"scan_status":"idle","scan_wait_time":0}`)
	host := `{"enable":true,"ssid":"` + b64("Home") + `","password":"` + b64(testPSK) + `","encryption_mode":"wpa2","enable_wpa3":false}`
	e.ok(deco.OpGetWireless, `{"band2_4":{"host":`+host+`,"radio":{"channel":"8","enable":true}},"band5_1":{"host":`+host+`}}`)
	e.ok(deco.OpGetDeviceEthPort, `{"device_list":[{"device_id":"`+masterRawID+`","port_info":[{"port":1,"port_speed":1000,"ports_status_info":[{"status":"well","type":"lan"}]}]}]}`)
	e.ok(deco.OpGetBlockList, `{"client_list":[],"max_count":64}`)
	for _, op := range []uint16{deco.OpRebootDevices, deco.OpBlockClients, deco.OpUnblockClients, deco.OpSetWireless} {
		e.ok(op, `null`)
	}
	go e.accept()
	t.Cleanup(func() { _ = ln.Close() })
	return e
}

func (e *decoEmu) ok(op uint16, result string) {
	e.mu.Lock()
	e.replies[op] = `{"error_code":0,"result":` + result + `}`
	e.mu.Unlock()
}

func (e *decoEmu) count(op uint16) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls[op]
}

func (e *decoEmu) counts() (conns, pwTries, logins int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.conns, e.pwTries, e.logins
}

func (e *decoEmu) setOwner(h string) { e.mu.Lock(); e.owner = h; e.mu.Unlock() }

// discover answers TDP for the three test units.
func (e *decoEmu) discover(_ context.Context, ip string) (*deco.DecoInfo, error) {
	e.mu.Lock()
	owner := e.owner
	e.mu.Unlock()
	port := e.ln.Addr().(*net.TCPAddr).Port
	for i, u := range testUnits {
		if u.IP != ip {
			continue
		}
		role, id := "slave", md5hex([]string{masterRawID, "dev205", "dev232"}[i])
		if i == 0 {
			role = "master"
		}
		return &deco.DecoInfo{IP: ip, MAC: strings.ToUpper(strings.ReplaceAll(u.MAC, ":", "-")), DeviceID: id,
			MasterDeviceID: md5hex(masterRawID), Role: role, Owner: owner, NeedAccountDigest: true,
			TMPPorts: []int{port}, DeviceModel: "X20", Channel2G: "6", Channel5G: "44"}, nil
	}
	return nil, errors.New("tdp: no reply")
}

func (e *decoEmu) handle(op uint16, req []byte) []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls[op]++
	switch op {
	case deco.OpcodeTokenAlloc:
		return []byte("tok")
	case deco.OpcodeTokenVerify, deco.OpcodeTokenFree:
		return nil
	}
	if r, ok := e.replies[op]; ok {
		return []byte(r)
	}
	return []byte(`{"error_code":-40210,"msg":"unsupported"}`)
}

func (e *decoEmu) accept() {
	for {
		c, err := e.ln.Accept()
		if err != nil {
			return
		}
		go e.serveConn(c)
	}
}

func (e *decoEmu) serveConn(c net.Conn) {
	e.mu.Lock()
	e.conns++
	e.mu.Unlock()
	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-dropbear",
		PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			e.mu.Lock()
			e.pwTries++
			e.mu.Unlock()
			if m.User() == sha1hex(testTPLinkID) && string(pw) == testPassword {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	cfg.AddHostKey(e.signer)
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		_ = c.Close()
		return
	}
	e.mu.Lock()
	e.logins++
	e.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		var fwd struct {
			Host     string
			Port     uint32
			OrigHost string
			OrigPort uint32
		}
		if nc.ChannelType() != "direct-tcpip" || ssh.Unmarshal(nc.ExtraData(), &fwd) != nil ||
			fwd.Host != deco.TMPForwardHost || fwd.Port != deco.TMPForwardPort {
			_ = nc.Reject(ssh.ConnectionFailed, "only 127.0.0.1:20002")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(creqs)
		go func() {
			serveTMP(ch, e.handle, e.isSilent, func() { e.mu.Lock(); e.byes++; e.mu.Unlock() })
			_ = sc.Close() // the device drops SSH when the TMP stream ends
		}()
	}
}

// serveTMP is the device side of TMP v1 + business V2 (direct PULL_ACK replies).
// A request for a silent opcode gets no reply at all; onBye runs when the
// client sends BYE.
func serveTMP(conn io.ReadWriteCloser, handler func(uint16, []byte) []byte, silent func(uint16) bool, onBye func()) {
	defer conn.Close()
	var wmu sync.Mutex
	write := func(b []byte) { wmu.Lock(); _, _ = conn.Write(b); wmu.Unlock() }
	reqs, resps := map[uint16][]byte{}, map[uint16][]byte{}
	chunk := func(h deco.V2Header, start uint32) []byte {
		resp := resps[h.TransID]
		crc := crc32.ChecksumIEEE(resp)
		if len(resp) == 0 {
			crc = 0
		}
		end := min(int(start)+deco.V2ChunkSize, len(resp))
		var body []byte
		if int(start) < len(resp) {
			body = resp[start:end]
		}
		return deco.EncodeV2(deco.V2Header{Type: 1, Version: 2, Opcode: h.Opcode, Operation: deco.OpPullAck,
			TransID: h.TransID, CRC32: crc, Total: uint32(len(resp)), Start: start}, body)
	}
	for {
		fr, err := deco.ReadFrame(conn)
		if err != nil {
			return
		}
		switch fr.Type {
		case deco.TMPTypeHeartbeat:
			write(deco.ShortFrame(deco.TMPTypeHeartbeat))
			continue
		case deco.TMPTypeBye:
			onBye()
			return
		case deco.TMPTypeData:
		default:
			continue
		}
		h, body, err := deco.DecodeV2(fr.Payload)
		if err != nil {
			return
		}
		var reply []byte
		switch h.Operation {
		case deco.OpPush:
			reqs[h.TransID] = append(reqs[h.TransID], body...)
			if h.Start/deco.V2ChunkSize != h.Total/deco.V2ChunkSize {
				reply = deco.EncodeV2(deco.V2Header{Type: 1, Version: 2, Opcode: h.Opcode, Operation: deco.OpPushAck, TransID: h.TransID}, nil)
				break
			}
			resps[h.TransID] = handler(h.Opcode, reqs[h.TransID])
			if silent(h.Opcode) {
				continue
			}
			reply = chunk(h, 0)
		case deco.OpPull:
			reply = chunk(h, h.Start)
		}
		write(deco.EncodeDataFrame(fr.Serial, reply))
	}
}

// fakeCtl is a UniFi controller's inform endpoint.
type fakeCtl struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	devs      map[string]*ctlDev
	systemCfg string
	blocked   string
	extra     map[string][]string // mac -> replies queued after provisioning
}

type ctlDev struct {
	key      string
	authkey  string
	adopted  bool
	stage    int
	informs  []map[string]any // decoded payloads, in order
	newKey   int              // informs decoded with the adopted key
	staleKey int              // informs after adoption still on the default key
	gcm      int              // informs encrypted with AES-GCM
}

func newFakeCtl(t *testing.T) *fakeCtl {
	c := &fakeCtl{t: t, devs: map[string]*ctlDev{}, extra: map[string][]string{}}
	c.srv = httptest.NewServer(http.HandlerFunc(c.inform))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *fakeCtl) url() string { return c.srv.URL + "/inform" }

func (c *fakeCtl) inform(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	hdr, _, err := inform.ParseHeader(body)
	if err != nil || req.URL.Path != "/inform" {
		http.Error(w, "bad packet", http.StatusBadRequest)
		return
	}
	mac := hdr.MAC.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.devs[mac]
	if d == nil {
		d = &ctlDev{key: inform.DefaultKeyHex, authkey: md5hex("authkey:" + mac)}
		c.devs[mac] = d
	}
	h2, plain, err := inform.Decode(body, d.key)
	if err != nil {
		if _, _, e2 := inform.Decode(body, inform.DefaultKeyHex); d.adopted && e2 == nil {
			d.staleKey++
		}
		http.Error(w, "undecodable", http.StatusBadRequest)
		return
	}
	if h2.Flags&inform.FlagGCM != 0 {
		d.gcm++
	}
	if d.adopted {
		d.newKey++
	}
	var m map[string]any
	if err := json.Unmarshal(plain, &m); err != nil {
		http.Error(w, "not json", http.StatusBadRequest)
		return
	}
	d.informs = append(d.informs, m)
	replyKey := d.key
	var reply string
	switch {
	case d.stage == 0: // adopt
		reply = `{"_type":"setparam","mgmt_cfg":"capability=notif\ncfgversion=0000000000000001\nauthkey=` + d.authkey + `\nuse_aes_gcm=true\nled_enabled=true\n"}`
		d.key, d.adopted, d.stage = d.authkey, true, 1
	case d.stage == 1: // provision
		js, _ := json.Marshal(map[string]any{"_type": "setparam", "cfgversion": "00000000000000c1",
			"mgmt_cfg": "cfgversion=00000000000000c1\nauthkey=" + d.authkey + "\n", "system_cfg": c.systemCfg, "blocked_sta": c.blocked})
		reply, d.stage = string(js), 2
	case len(c.extra[mac]) > 0:
		reply, c.extra[mac] = c.extra[mac][0], c.extra[mac][1:]
	default:
		reply = `{"_type":"noop","interval":1}`
	}
	pkt, err := inform.Encode(hdr.MAC, replyKey, inform.CBC, []byte(reply), nil)
	if err != nil {
		c.t.Errorf("controller encode: %v", err)
		return
	}
	w.Header().Set("Content-Type", "application/x-binary")
	_, _ = w.Write(pkt)
}

// dev returns a copy of what the controller knows about mac.
func (c *fakeCtl) dev(mac string) ctlDev {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d := c.devs[mac]; d != nil {
		cp := *d
		cp.informs = append([]map[string]any(nil), d.informs...)
		return cp
	}
	return ctlDev{}
}

func (c *fakeCtl) queue(mac string, replies ...string) {
	c.mu.Lock()
	c.extra[mac] = append(c.extra[mac], replies...)
	c.mu.Unlock()
}
