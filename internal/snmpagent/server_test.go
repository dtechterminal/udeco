// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	testMAC    = []byte{0x50, 0x91, 0xe3, 0x00, 0x02, 0x05}
	testEngine = EngineIDFromMAC(testMAC)
	lo         = netip.MustParseAddr("127.0.0.1")
	lanHost    = netip.MustParseAddr("192.168.0.10")
	wanHost    = netip.MustParseAddr("10.9.9.9")
)

// writeTree creates files under root (path -> content; a trailing "/"
// makes a directory).
func writeTree(tb testing.TB, root string, files map[string]string) {
	tb.Helper()
	for p, c := range files {
		full := filepath.Join(root, p)
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				tb.Fatal(err)
			}
			continue
		}
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			tb.Fatal(err)
		}
	}
}

const procNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:    1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0
  eth1: 4294967000  5000    1    2    0     0          0       300 900000    4000    3    4    0     0       0          0
br-lan:  777000    7000    0    0    0     0          0        70   88000     800    0    0    0     0       0          0
   wl12:   5000      50    0    0    0     0          0         0    6000      60    0    0    0     0       0          0
`

func fixtureRoot(tb testing.TB) string {
	root := tb.TempDir()
	writeTree(tb, root, map[string]string{
		"proc/net/dev":             procNetDev,
		"proc/loadavg":             "0.25 0.50 9.10 1/80 1234\n",
		"proc/meminfo":             "MemTotal:         252152 kB\nMemFree:           16212 kB\nMemAvailable:      98000 kB\nBuffers:            6392 kB\nCached:            40000 kB\nShmem:               100 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n",
		"sys/class/net/lo/ifindex": "1\n", "sys/class/net/lo/type": "772\n", "sys/class/net/lo/flags": "0x49\n",
		"sys/class/net/lo/operstate": "unknown\n", "sys/class/net/lo/mtu": "65536\n", "sys/class/net/lo/address": "00:00:00:00:00:00\n",
		"sys/class/net/eth1/ifindex": "4\n", "sys/class/net/eth1/type": "1\n", "sys/class/net/eth1/flags": "0x1003\n",
		"sys/class/net/eth1/operstate": "up\n", "sys/class/net/eth1/mtu": "1500\n", "sys/class/net/eth1/speed": "1000\n",
		"sys/class/net/eth1/address": "50:91:e3:00:02:06\n", "sys/class/net/eth1/device/": "",
		"sys/class/net/br-lan/ifindex": "15\n", "sys/class/net/br-lan/type": "1\n", "sys/class/net/br-lan/flags": "0x1043\n",
		"sys/class/net/br-lan/operstate": "unknown\n", "sys/class/net/br-lan/mtu": "1500\n", "sys/class/net/br-lan/address": "50:91:e3:00:02:05\n",
		"sys/class/net/br-lan/bridge/": "",
		"sys/class/net/wl12/ifindex":   "30\n", "sys/class/net/wl12/type": "1\n", "sys/class/net/wl12/flags": "0x1002\n",
		"sys/class/net/wl12/operstate": "down\n", "sys/class/net/wl12/mtu": "1500\n", "sys/class/net/wl12/address": "52:91:e3:00:02:07\n",
	})
	return root
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func testServerClock(tb testing.TB, cfg *Config) (*Server, *fakeClock) {
	clk := &fakeClock{t: time.Date(2026, 11, 19, 4, 0, 0, 0, time.UTC)}
	s := New(Options{Root: fixtureRoot(tb), EngineID: testEngine, Boots: 3, Now: clk.now})
	s.SetConfig(cfg)
	s.SetAllow(LANAllow(netip.MustParsePrefix("192.168.0.0/24")))
	s.burst, s.tokens = 1e9, 1e9 // TestRateLimit puts the limit back
	return s, clk
}

func testServer(tb testing.TB, cfg *Config) *Server {
	s, _ := testServerClock(tb, cfg)
	return s
}

func v2Request(ver int64, comm string, p PDU) []byte {
	return seq(tagSequence, encInt(ver), encOctets([]byte(comm)), p.encode())
}

func get(names ...string) PDU {
	p := PDU{Type: pduGet, RequestID: 42}
	for _, n := range names {
		p.VarBinds = append(p.VarBinds, VarBind{Name: mustOID(n), Value: nullValue})
	}
	return p
}

// parseV2 reads a v1/v2c reply.
func parseV2(tb testing.TB, b []byte) (string, PDU) {
	tb.Helper()
	if b == nil {
		tb.Fatal("no reply")
	}
	body, _, err := expect(b, tagSequence)
	if err != nil {
		tb.Fatal(err)
	}
	_, body, _ = readInt(body)
	comm, body, _ := expect(body, tagOctetString)
	p, err := parsePDU(body)
	if err != nil {
		tb.Fatal(err)
	}
	return string(comm), p
}

func vbString(v Value) string { return string(v.Bytes) }

var v2cfg = &Config{V1V2c: true, Community: "s3cret", Location: "hall", Contact: "ops"}

func TestV2cGet(t *testing.T) {
	s := testServer(t, v2cfg)
	s.SetView(&View{Hostname: "deco-205", Model: "U6-Lite", Version: "6.7.54.15663", IP: "192.168.0.205"})
	comm, p := parseV2(t, s.Handle(v2Request(1, "s3cret", get("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.6.0",
		"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.9.0", "1.3.6.1.2.1.1.1", "1.3.6.1.4.1.41112.1.6.3.3.0")), lanHost))
	if comm != "s3cret" || p.Type != pduResponse || p.RequestID != 42 || p.ErrorStatus != 0 {
		t.Fatalf("%s %+v", comm, p)
	}
	want := []string{"U6-Lite 6.7.54.15663", "deco-205", "hall", "ops"}
	for i, w := range want {
		if got := vbString(p.VarBinds[i].Value); got != w {
			t.Errorf("varbind %d = %q, want %q", i, got, w)
		}
	}
	if p.VarBinds[4].Value.OID.String() != "1.3.6.1.4.1.8072.3.2.10" {
		t.Errorf("sysObjectID %v", p.VarBinds[4].Value.OID)
	}
	if p.VarBinds[5].Value.Tag != tagNoSuchObject || p.VarBinds[6].Value.Tag != tagNoSuchInstance {
		t.Errorf("missing objects: %+v %+v", p.VarBinds[5].Value, p.VarBinds[6].Value)
	}
	if vbString(p.VarBinds[7].Value) != "U6-Lite" {
		t.Errorf("unifiApSystemModel %+v", p.VarBinds[7].Value)
	}
	_, p = parseV2(t, s.Handle(v2Request(1, "s3cret", get("1.3.6.1.99.1.0")), lanHost))
	if p.VarBinds[0].Value.Tag != tagNoSuchObject {
		t.Errorf("unknown subtree: %+v", p.VarBinds[0].Value)
	}
}

func TestDropsUnlessAllowed(t *testing.T) {
	s := testServer(t, v2cfg)
	req := v2Request(1, "s3cret", get("1.3.6.1.2.1.1.1.0"))
	if s.Handle(req, wanHost) != nil {
		t.Error("answered a source outside the LAN")
	}
	if s.Handle(v2Request(1, "S3cret", get("1.3.6.1.2.1.1.1.0")), lanHost) != nil {
		t.Error("answered a wrong community")
	}
	if s.Handle(req, lo) == nil || s.Handle(req, lanHost) == nil {
		t.Error("loopback and LAN must be answered")
	}
	s.SetAllow(nil)
	if s.Handle(req, lanHost) != nil {
		t.Error("nil allow must answer loopback only")
	}
	s.SetConfig(nil)
	if s.Handle(req, lo) != nil {
		t.Error("answered with SNMP off")
	}
	s.SetConfig(&Config{V3: true, User: "mon", Password: "password1"})
	if s.Handle(req, lo) != nil {
		t.Error("answered v2c with only v3 on")
	}
	if got := s.snapshotStats().badCommunity; got != 3 {
		t.Errorf("snmpInBadCommunityNames = %d", got)
	}
}

func TestSetIsRefused(t *testing.T) {
	s := testServer(t, v2cfg)
	set := PDU{Type: pduSet, RequestID: 9, VarBinds: []VarBind{{Name: mustOID("1.3.6.1.2.1.1.6.0"), Value: OctetString("x")}}}
	_, p := parseV2(t, s.Handle(v2Request(1, "s3cret", set), lanHost))
	if p.ErrorStatus != errNoAccess || p.ErrorIndex != 1 {
		t.Errorf("v2c set: %+v", p)
	}
	_, p = parseV2(t, s.Handle(v2Request(0, "s3cret", set), lanHost))
	if p.ErrorStatus != errNoSuchName {
		t.Errorf("v1 set: %+v", p)
	}
	_, p = parseV2(t, s.Handle(v2Request(1, "s3cret", get("1.3.6.1.2.1.1.6.0")), lanHost))
	if vbString(p.VarBinds[0].Value) != "hall" {
		t.Error("the set changed something")
	}
}

// walk GetNexts from 1.3.6.1 to the end and returns every varbind.
func walk(t *testing.T, s *Server, ver int64) []VarBind {
	var out []VarBind
	o := mustOID("1.3.6.1")
	for i := 0; i < 5000; i++ {
		_, p := parseV2(t, s.Handle(v2Request(ver, "s3cret", PDU{Type: pduGetNext, RequestID: int32(i), VarBinds: []VarBind{{Name: o, Value: nullValue}}}), lo))
		if ver == 0 && p.ErrorStatus == errNoSuchName {
			return out
		}
		vb := p.VarBinds[0]
		if vb.Value.Tag == tagEndOfMibView {
			return out
		}
		if vb.Name.Compare(o) <= 0 {
			t.Fatalf("walk went backwards: %s after %s", vb.Name, o)
		}
		out = append(out, vb)
		o = vb.Name
	}
	t.Fatal("walk did not end")
	return nil
}

func TestWalk(t *testing.T) {
	s := testServer(t, v2cfg)
	s.SetView(FromFields(informFields()))
	all := walk(t, s, 1)
	byName := map[string]Value{}
	for _, vb := range all {
		byName[vb.Name.String()] = vb.Value
	}
	checks := map[string]string{
		"1.3.6.1.2.1.2.2.1.2.4":            "eth1",
		"1.3.6.1.2.1.31.1.1.1.1.15":        "br-lan",
		"1.3.6.1.4.1.41112.1.6.1.2.1.6.1":  "Home",
		"1.3.6.1.4.1.41112.1.6.1.2.1.7.2":  "rai1",
		"1.3.6.1.4.1.41112.1.6.1.2.1.23.2": "guest",
		"1.3.6.1.4.1.41112.1.6.1.1.1.2.2":  "rai0",
		"1.3.6.1.4.1.41112.1.6.2.1.1.5.1":  "eth0",
		"1.3.6.1.4.1.2021.10.1.3.3":        "9.10",
		"1.3.6.1.4.1.2021.10.1.101.3":      "15 min Load Average too high (= 9.10)",
	}
	for o, w := range checks {
		if got := vbString(byName[o]); got != w {
			t.Errorf("%s = %q, want %q", o, got, w)
		}
	}
	ints := map[string]int64{
		"1.3.6.1.2.1.2.1.0":               4,  // ifNumber
		"1.3.6.1.2.1.2.2.1.3.1":           24, // lo softwareLoopback
		"1.3.6.1.2.1.2.2.1.3.4":           6,  // eth1 ethernetCsmacd
		"1.3.6.1.2.1.2.2.1.3.15":          209,
		"1.3.6.1.2.1.2.2.1.3.30":          71,
		"1.3.6.1.2.1.2.2.1.8.15":          1, // operstate unknown + RUNNING
		"1.3.6.1.2.1.2.2.1.8.30":          2,
		"1.3.6.1.2.1.2.2.1.7.30":          2,
		"1.3.6.1.4.1.41112.1.6.1.2.1.8.1": 3,
		"1.3.6.1.4.1.41112.1.6.1.1.1.6.2": 37,
		"1.3.6.1.4.1.2021.4.5.0":          252152,
		"1.3.6.1.4.1.2021.4.6.0":          98000,
	}
	for o, w := range ints {
		if got := byName[o].Int; got != w || byName[o].Tag != tagInteger {
			t.Errorf("%s = %+v, want %d", o, byName[o], w)
		}
	}
	if v := byName["1.3.6.1.2.1.2.2.1.5.4"]; v.Uint != 1_000_000_000 || v.Tag != tagGauge32 {
		t.Errorf("ifSpeed %+v", v)
	}
	if v := byName["1.3.6.1.2.1.31.1.1.1.6.4"]; v.Uint != 4294967000 || v.Tag != tagCounter64 {
		t.Errorf("ifHCInOctets %+v", v)
	}
	if v := byName["1.3.6.1.4.1.41112.1.6.1.2.1.2.1"]; !bytes.Equal(v.Bytes, []byte{0x52, 0x91, 0xe3, 0, 2, 0x08}) {
		t.Errorf("unifiVapBssId % x", v.Bytes)
	}
	if v := byName["1.3.6.1.4.1.41112.1.6.1.1.1.4.2"]; v.Uint != 200+20 {
		t.Errorf("unifiRadioRxPackets %+v", v)
	}
	if v := byName["1.3.6.1.4.1.41112.1.6.3.1.0"]; !bytes.Equal(v.Bytes, []byte{192, 168, 0, 205}) {
		t.Errorf("unifiApSystemIp %+v", v)
	}
	if v := byName["1.3.6.1.6.3.10.2.1.1.0"]; !bytes.Equal(v.Bytes, testEngine) {
		t.Errorf("snmpEngineID % x", v.Bytes)
	}

	// SNMPv1 walks skip Counter64 objects
	for _, vb := range walk(t, s, 0) {
		if vb.Value.Tag == tagCounter64 {
			t.Fatalf("v1 walk returned Counter64 %s", vb.Name)
		}
	}
}

func TestGetBulk(t *testing.T) {
	s := testServer(t, v2cfg)
	req := PDU{Type: pduGetBulk, RequestID: 5, ErrorStatus: 1, ErrorIndex: 3, VarBinds: []VarBind{
		{Name: mustOID("1.3.6.1.2.1.1.5"), Value: nullValue},      // non-repeater: sysName.0
		{Name: mustOID("1.3.6.1.2.1.2.2.1.2"), Value: nullValue},  // ifDescr
		{Name: mustOID("1.3.6.1.2.1.2.2.1.10"), Value: nullValue}, // ifInOctets
	}}
	_, p := parseV2(t, s.Handle(v2Request(1, "s3cret", req), lanHost))
	if len(p.VarBinds) != 1+2*3 {
		t.Fatalf("%d varbinds", len(p.VarBinds))
	}
	if p.VarBinds[0].Name.String() != "1.3.6.1.2.1.1.5.0" || vbString(p.VarBinds[1].Value) != "lo" ||
		p.VarBinds[2].Name.String() != "1.3.6.1.2.1.2.2.1.10.1" || vbString(p.VarBinds[3].Value) != "eth1" {
		t.Errorf("%+v", p.VarBinds)
	}
	// a huge max-repetitions is cut to what fits in one message
	req = PDU{Type: pduGetBulk, RequestID: 6, ErrorIndex: 1 << 30, VarBinds: []VarBind{{Name: mustOID("1.3.6.1"), Value: nullValue}}}
	out := s.Handle(v2Request(1, "s3cret", req), lanHost)
	_, p = parseV2(t, out)
	if len(out) > maxMsgSize || len(p.VarBinds) == 0 || len(p.VarBinds) > maxRepetitions {
		t.Errorf("bulk reply %d bytes, %d varbinds", len(out), len(p.VarBinds))
	}
	// GetBulk is not SNMPv1
	if s.Handle(v2Request(0, "s3cret", req), lanHost) != nil {
		t.Error("v1 GetBulk answered")
	}
}

func TestCounterWidening(t *testing.T) {
	root := fixtureRoot(t)
	h := newHost(root)
	first := h.interfaces()
	if first[1].Name != "eth1" || first[1].RxBytes != 4294967000 {
		t.Fatalf("%+v", first[1])
	}
	// eth1 rx_bytes wraps past 2^32
	writeTree(t, root, map[string]string{"proc/net/dev": strings.Replace(procNetDev, "4294967000", "1000", 1)})
	got := h.interfaces()
	if got[1].RxBytes != 1<<32+1000 {
		t.Errorf("widened rx_bytes = %d", got[1].RxBytes)
	}
	if got[0].RxBytes != 1000 {
		t.Errorf("lo changed: %d", got[0].RxBytes)
	}
}

func TestEngineBoots(t *testing.T) {
	p := BootsFile(t.TempDir())
	for want := int64(1); want <= 3; want++ {
		n, err := NextEngineBoots(p)
		if err != nil || n != want {
			t.Fatalf("boots %d %v, want %d", n, err, want)
		}
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v %v", fi.Mode(), err)
	}
	os.WriteFile(p, []byte("junk"), 0o600)
	if _, err := NextEngineBoots(p); err == nil {
		t.Error("junk boots file accepted")
	}
	os.WriteFile(p, []byte("2147483646"), 0o600)
	if _, err := NextEngineBoots(p); err == nil {
		t.Error("boots at the maximum must stop v3")
	}
}

func TestPrefixFromIPMask(t *testing.T) {
	if p := PrefixFromIPMask("192.168.0.205", "255.255.255.0"); p.String() != "192.168.0.0/24" {
		t.Errorf("%v", p)
	}
	for _, bad := range [][2]string{{"", "255.255.255.0"}, {"192.168.0.205", ""}, {"192.168.0.205", "255.0.255.0"}, {"192.168.0.205", "0.0.0.0"}} {
		if p := PrefixFromIPMask(bad[0], bad[1]); p.IsValid() {
			t.Errorf("%v accepted: %v", bad, p)
		}
	}
	if LANAllow(netip.Prefix{})(lanHost) {
		t.Error("an invalid prefix must allow nothing")
	}
}

// informFields is a small inform shaped like apstate.Snapshot.Fields' output.
func informFields() map[string]any {
	return map[string]any{
		"hostname": "deco-205", "ip": "192.168.0.205", "uplink": "eth0", "uptime": int64(3600),
		"model_display": "U6-Lite", "version": "6.7.54.15663",
		"radio_table_stats": []map[string]any{
			{"name": "ra0", "radio": "ng", "cu_total": 20, "cu_self_rx": 5, "cu_self_tx": 3, "cu_interf": 12},
			{"name": "rai0", "radio": "na", "cu_total": 37, "cu_self_rx": 7, "cu_self_tx": 9, "cu_interf": 21},
		},
		"vap_table": []map[string]any{
			{"name": "rai0", "radio_name": "rai0", "radio": "na", "essid": "Home", "bssid": "52:91:e3:00:02:08", "channel": 36,
				"tx_power": 20, "num_sta": 3, "up": true, "is_guest": false, "rx_packets": int64(200), "tx_packets": int64(300), "ccq": 1000},
			{"name": "rai1", "radio_name": "rai0", "radio": "na", "essid": "Guests", "bssid": "52:91:e3:00:02:09", "channel": 36,
				"num_sta": 0, "up": true, "is_guest": true, "rx_packets": 20, "tx_packets": uint64(30)},
		},
		"if_table": []map[string]any{{"name": "eth0", "mac": "50:91:e3:00:02:05", "ip": "192.168.0.205", "up": true, "speed": 1000,
			"full_duplex": true, "rx_bytes": int64(1 << 33), "tx_bytes": int64(5)}},
	}
}

// ---- SNMPv3: a minimal manager side ----

type v3client struct {
	engine      []byte
	boots, time int64
	user        string
	keys        *userKeys
	ap          authProto
	pp          privProto // -1: authNoPriv
	flags       byte
}

func discovery(msgID int64) []byte {
	c := &v3client{flags: flagReportable}
	return c.message(msgID, get())
}

// message builds a request; flags pick the level (the client's keys sign
// and encrypt when the flags ask for it).
func (c *v3client) message(msgID int64, p PDU) []byte {
	scoped := seq(tagSequence, encOctets(c.engine), encOctets(nil), p.encode())
	var authP, privP []byte
	data := scoped
	if c.flags&flagAuth != 0 {
		authP = make([]byte, c.ap.digestLen())
	}
	if c.flags&flagPriv != 0 {
		privP = make([]byte, 8)
		binary.BigEndian.PutUint64(privP, uint64(msgID)*7919)
		ct, _ := encrypt(c.pp, c.keys.privKey(c.ap), uint32(c.boots), uint32(c.time), privP, scoped)
		data = encOctets(ct)
	}
	privEnc := encOctets(privP)
	spSeq := seq(tagSequence, encOctets(c.engine), encInt(c.boots), encInt(c.time), encOctets([]byte(c.user)), encOctets(authP), privEnc)
	glob := seq(tagSequence, encInt(msgID), encInt(65507), encOctets([]byte{c.flags}), encInt(3))
	msg := seq(tagSequence, encInt(3), glob, encOctets(spSeq), data)
	if c.flags&flagAuth != 0 {
		off := len(msg) - len(data) - len(privEnc) - len(authP)
		copy(msg[off:], c.keys.mac(c.ap, msg))
	}
	return msg
}

// reply reads a v3 reply: its flags, USM parameters and PDU (decrypted and
// its digest checked with the client's keys).
func (c *v3client) reply(t *testing.T, b []byte) (byte, secParams, PDU) {
	t.Helper()
	if b == nil {
		t.Fatal("no reply")
	}
	b = append(make([]byte, 0, len(b)), b...)
	body, _, err := expect(b, tagSequence)
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ = readInt(body)
	glob, body, _ := expect(body, tagSequence)
	_, g, _ := readInt(glob)
	_, g, _ = readInt(g)
	fl, _, _ := expect(g, tagOctetString)
	raw, body, _ := expect(body, tagOctetString)
	sp, err := parseSecParams(raw)
	if err != nil {
		t.Fatal(err)
	}
	if fl[0]&flagAuth != 0 {
		z := append([]byte(nil), b...)
		off := cap(b) - cap(sp.auth)
		clear(z[off : off+len(sp.auth)])
		if !bytes.Equal(c.keys.mac(c.ap, z), sp.auth) {
			t.Fatal("reply digest does not verify")
		}
	}
	data := body
	if fl[0]&flagPriv != 0 {
		ct, _, err := expect(body, tagOctetString)
		if err != nil {
			t.Fatal(err)
		}
		if data, err = decrypt(c.pp, c.keys.privKey(c.ap), uint32(sp.boots), uint32(sp.time), sp.priv, ct); err != nil {
			t.Fatal(err)
		}
	}
	_, _, p, err := parseScoped(data, fl[0]&flagPriv != 0)
	if err != nil {
		t.Fatal(err)
	}
	return fl[0], sp, p
}

func reportOf(p PDU) string {
	if p.Type != pduReport || len(p.VarBinds) != 1 {
		return ""
	}
	return p.VarBinds[0].Name.String()
}

func TestV3(t *testing.T) {
	cfg := &Config{V3: true, User: "monitor", Password: "Pass-w0rd!"}
	s, clk := testServerClock(t, cfg)
	s.SetView(&View{Hostname: "deco-205", Model: "U6-Lite", Version: "6.7.54.15663"})

	// discovery: unknownEngineIDs report carrying the engine ID, boots, time
	clk.t = clk.t.Add(100 * time.Second)
	fl, sp, p := (&v3client{}).reply(t, s.Handle(discovery(1), lanHost))
	if fl != 0 || reportOf(p) != "1.3.6.1.6.3.15.1.1.4.0" || !bytes.Equal(sp.engineID, testEngine) || sp.boots != 3 || sp.time != 100 {
		t.Fatalf("discovery: flags %x %s %+v", fl, reportOf(p), sp)
	}

	keys := newUserKeys("monitor", "Pass-w0rd!", testEngine)
	for _, combo := range []struct {
		ap authProto
		pp privProto
	}{{authMD5, privDES}, {authSHA1, privAES128}, {authSHA256, privAES128}, {authSHA512, privDES}} {
		c := &v3client{engine: testEngine, boots: 3, time: 101, user: "monitor", keys: keys, ap: combo.ap, pp: combo.pp, flags: flagAuth | flagPriv | flagReportable}
		fl, _, p := c.reply(t, s.Handle(c.message(2, get("1.3.6.1.2.1.1.5.0")), lanHost))
		if fl != flagAuth|flagPriv || p.Type != pduResponse || p.RequestID != 42 || vbString(p.VarBinds[0].Value) != "deco-205" {
			t.Errorf("%s/%s: flags %x %+v", combo.ap, combo.pp, fl, p)
		}
	}

	base := v3client{engine: testEngine, boots: 3, time: 101, user: "monitor", keys: keys, ap: authSHA1, pp: privAES128, flags: flagAuth | flagPriv | flagReportable}
	cases := []struct {
		name   string
		mod    func(c *v3client)
		report string
		authed bool
	}{
		{"wrong password", func(c *v3client) { c.keys = newUserKeys("monitor", "Pass-w0rd?", testEngine) }, "1.3.6.1.6.3.15.1.1.5.0", false},
		{"unknown user", func(c *v3client) { c.user = "intruder" }, "1.3.6.1.6.3.15.1.1.3.0", false},
		{"authNoPriv", func(c *v3client) { c.flags = flagAuth | flagReportable }, "1.3.6.1.6.3.15.1.1.1.0", false},
		{"noAuthNoPriv", func(c *v3client) { c.flags = flagReportable }, "1.3.6.1.6.3.15.1.1.1.0", false},
		{"old boots", func(c *v3client) { c.boots = 2 }, "1.3.6.1.6.3.15.1.1.2.0", true},
		{"time ahead", func(c *v3client) { c.time = 100 + 151 }, "1.3.6.1.6.3.15.1.1.2.0", true},
		{"other engine", func(c *v3client) { c.engine = []byte{0x80, 0, 0, 0, 1} }, "1.3.6.1.6.3.15.1.1.4.0", false},
	}
	for _, tc := range cases {
		c := base
		tc.mod(&c)
		fl, sp, p := c.reply(t, s.Handle(c.message(3, get("1.3.6.1.2.1.1.5.0")), lanHost))
		if reportOf(p) != tc.report || (fl&flagAuth != 0) != tc.authed || fl&flagPriv != 0 {
			t.Errorf("%s: flags %x report %s", tc.name, fl, reportOf(p))
		}
		if tc.report == "1.3.6.1.6.3.15.1.1.2.0" && (sp.boots != 3 || sp.time != 100) {
			t.Errorf("%s: report time %d/%d", tc.name, sp.boots, sp.time)
		}
	}
	// a tampered ciphertext under a valid digest cannot exist; a tampered
	// message fails the digest
	c := base
	msg := c.message(4, get("1.3.6.1.2.1.1.5.0"))
	msg[len(msg)-1] ^= 1
	if _, _, p := c.reply(t, s.Handle(msg, lanHost)); reportOf(p) != "1.3.6.1.6.3.15.1.1.5.0" {
		t.Errorf("tampered message: %s", reportOf(p))
	}
	// not reportable: no report
	c.flags = flagAuth | flagPriv
	c.user = "intruder"
	if s.Handle(c.message(5, get("1.3.6.1.2.1.1.5.0")), lanHost) != nil {
		t.Error("report sent for a non-reportable message")
	}
	// v3 from outside the LAN: nothing
	if s.Handle(discovery(6), wanHost) != nil {
		t.Error("v3 answered outside the LAN")
	}
	// the user's keys follow a password change
	s.SetConfig(&Config{V3: true, User: "monitor", Password: "another-pass"})
	c = base
	if _, _, p := c.reply(t, s.Handle(c.message(7, get("1.3.6.1.2.1.1.5.0")), lanHost)); reportOf(p) != "1.3.6.1.6.3.15.1.1.5.0" {
		t.Errorf("old password still works: %s", reportOf(p))
	}
}

func TestV3OffWithoutEngine(t *testing.T) {
	s := New(Options{Root: fixtureRoot(t)})
	s.SetConfig(&Config{V3: true, User: "monitor", Password: "Pass-w0rd!"})
	if s.Handle(discovery(1), lo) != nil {
		t.Error("v3 served without engine boots")
	}
}

func TestRateLimit(t *testing.T) {
	s, clk := testServerClock(t, v2cfg)
	s.burst, s.tokens = rateBurst, rateBurst
	req := v2Request(1, "s3cret", get("1.3.6.1.2.1.1.5.0"))
	n := 0
	for i := 0; i < 1000; i++ {
		if s.Handle(req, lanHost) != nil {
			n++
		}
	}
	if n != rateBurst {
		t.Errorf("%d answered in a burst, want %d", n, rateBurst)
	}
	clk.t = clk.t.Add(time.Second)
	if s.Handle(req, lanHost) == nil {
		t.Error("the bucket did not refill")
	}
}
