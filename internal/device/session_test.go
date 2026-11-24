// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"encoding/json"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/inform"
)

const newKey = "a066a066a066a066a066a066a066a066"

func newSession(t *testing.T) *Session {
	return &Session{
		S: NewState("http://192.168.1.1:8080/inform"),
		Dev: inform.Device{MAC: net.HardwareAddr{2, 0x6f, 0x77, 0x72, 0x74, 1}, IP: "192.168.1.50",
			Netmask: "255.255.255.0", Gateway: "192.168.1.1", Hostname: "t"},
		Boot:     time.Now(),
		StateDir: t.TempDir(),
	}
}

func handle(t *testing.T, x *Session, reply string) Outcome {
	t.Helper()
	o, err := x.Handle([]byte(reply), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// The adoption sequence seen on a real U7PG2 (open-unifi live log):
// setparam{mgmt_cfg with authkey, use_aes_gcm} -> device switches key + GCM.
func TestAdoptionViaMgmtCfg(t *testing.T) {
	x := newSession(t)
	o := handle(t, x, `{"_type":"setparam","mgmt_cfg":"capability=notif,notif-assoc-stat\nselfrun_guest_mode=pass\ncfgversion=1111222233334444\nled_enabled=true\nstun_url=stun://192.168.1.1:3478/\nmgmt_url=https://192.168.1.1:8443/manage/site/default\nauthkey=`+newKey+`\nuse_aes_gcm=true\nreport_crash=true\n","server_time_in_utc":"1"}`)
	if !x.S.Adopted || x.S.Key != newKey || !x.S.GCM || x.S.CfgVersion != "1111222233334444" {
		t.Fatalf("state after adoption: %+v", x.S)
	}
	if !o.Immediate || !o.Changed {
		t.Errorf("outcome %+v", o)
	}
	js, _ := x.Payload(time.Now())
	var m map[string]any
	json.Unmarshal(js, &m)
	if m["default"] != false || m["state"] != 4.0 || m["cfgversion"] != "1111222233334444" || m["x_aes_gcm"] != true {
		t.Errorf("adopted payload: default=%v state=%v cfgversion=%v gcm=%v", m["default"], m["state"], m["cfgversion"], m["x_aes_gcm"])
	}
	if x.Cipher() != inform.GCM {
		t.Error("cipher not GCM after use_aes_gcm=true")
	}
}

// A later mgmt_cfg must not replace an adopted key (stuck-adopt bug).
func TestAuthkeyOnlyFromDefault(t *testing.T) {
	x := newSession(t)
	handle(t, x, `{"_type":"setparam","mgmt_cfg":"authkey=`+newKey+`\n"}`)
	handle(t, x, `{"_type":"setparam","mgmt_cfg":"authkey=ffffffffffffffffffffffffffffffff\n"}`)
	if x.S.Key != newKey {
		t.Fatalf("key replaced: %s", x.S.Key)
	}
}

func TestFullProvisioningSavesButDoesNotLogSystemCfg(t *testing.T) {
	x := newSession(t)
	handle(t, x, `{"_type":"setparam","mgmt_cfg":"authkey=`+newKey+`\n"}`)
	o := handle(t, x, `{"_type":"setparam","cfgversion":"abcdabcdabcdabcd","system_cfg":"aaa.1.ssid=HomeWiFi\naaa.1.wpa_psk=SECRETSECRET\nradio.1.phyname=wifi0\n","blocked_sta":"","mgmt_cfg":"cfgversion=abcdabcdabcdabcd\n"}`)
	if x.S.CfgVersion != "abcdabcdabcdabcd" {
		t.Errorf("cfgversion %s", x.S.CfgVersion)
	}
	for _, e := range o.Events {
		if strings.Contains(e, "SECRET") || strings.Contains(e, "HomeWiFi") {
			t.Errorf("event leaks system_cfg values: %s", e)
		}
	}
}

func TestUpgradeIsNeverApplied(t *testing.T) {
	x := newSession(t)
	before := x.Boot
	time.Sleep(time.Millisecond)
	o := handle(t, x, `{"_type":"upgrade","version":"6.8.9.99999","url":"http://192.168.1.1:8080/dl/firmware/x.bin","sha256sum":"00"}`)
	if x.S.Version != "6.8.9.99999" || !x.Boot.After(before) || !o.Immediate {
		t.Fatalf("upgrade handling: version=%s boot moved=%v", x.S.Version, x.Boot.After(before))
	}
}

func TestSetdefaultAndCmds(t *testing.T) {
	x := newSession(t)
	handle(t, x, `{"_type":"setparam","mgmt_cfg":"authkey=`+newKey+`\nuse_aes_gcm=true\n"}`)
	handle(t, x, `{"_type":"cmd","cmd":"setdefault"}`)
	if x.S.Adopted || x.S.Key != inform.DefaultKeyHex || x.S.GCM || x.S.CfgVersion != "0" {
		t.Fatalf("after setdefault: %+v", x.S)
	}
	handle(t, x, `{"_type":"cmd","cmd":"set-adopt","key":"`+newKey+`","uri":"http://192.168.1.1:8080/inform"}`)
	if !x.S.Adopted || x.S.Key != newKey {
		t.Fatalf("after set-adopt: %+v", x.S)
	}
	handle(t, x, `{"_type":"setdefault"}`)
	if x.S.Adopted {
		t.Fatal("top-level setdefault ignored")
	}
}

func TestStateRoundTrip(t *testing.T) {
	x := newSession(t)
	p := x.StateDir + "/state.json"
	x.S.Key = newKey
	if err := x.S.Save(p); err != nil {
		t.Fatal(err)
	}
	s, ok, err := Load(p)
	if err != nil || !ok || s.Key != newKey {
		t.Fatalf("load: %+v %v %v", s, ok, err)
	}
}

func TestApplyAdoptAndSSHPort(t *testing.T) {
	x := newSession(t)
	x.SSHPort = 2222
	x.ApplyAdopt(AdoptRequest{URL: "http://192.168.1.1:8080/inform", Key: newKey})
	if !x.S.Adopted || x.S.Key != newKey {
		t.Fatalf("%+v", x.S)
	}
	js, _ := x.Payload(time.Now())
	var m map[string]any
	json.Unmarshal(js, &m)
	if m["sshd_port"] != 2222.0 {
		t.Errorf("sshd_port %v", m["sshd_port"])
	}
}

func TestSetAdoptParse(t *testing.T) {
	s := &SSHAdopt{Requests: make(chan AdoptRequest, 1)}
	s.command("/usr/bin/syswrapper.sh set-adopt http://192.168.1.1:8080/inform " + newKey)
	r := <-s.Requests
	if r.URL != "http://192.168.1.1:8080/inform" || r.Key != newKey {
		t.Fatalf("%+v", r)
	}
}

// "Override inform host": the controller repeats the setparam until the
// device reports the new address.
func TestInformURLFromMgmtCfg(t *testing.T) {
	x := newSession(t)
	handle(t, x, `{"_type":"setparam","mgmt_cfg":"authkey=`+newKey+`\ncfgversion=1\n"}`)
	o := handle(t, x, `{"_type":"setparam","mgmt_cfg":"cfgversion=1\ninform_url=http://192.168.1.9:8080/inform\n"}`)
	if x.S.InformURL != "http://192.168.1.9:8080/inform" || !o.Changed || !o.Immediate {
		t.Fatalf("inform_url %q changed=%v immediate=%v", x.S.InformURL, o.Changed, o.Immediate)
	}
	js, err := x.Payload(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(js, &m)
	if m["inform_url"] != x.S.InformURL || m["inform_ip"] != "192.168.1.9" {
		t.Errorf("reported inform_url %v inform_ip %v", m["inform_url"], m["inform_ip"])
	}
	for _, bad := range []string{"ftp://192.168.1.9/x", "192.168.1.9:8080", "http://"} {
		handle(t, x, `{"_type":"setparam","mgmt_cfg":"cfgversion=1\ninform_url=`+bad+`\n"}`)
		if x.S.InformURL != "http://192.168.1.9:8080/inform" {
			t.Errorf("malformed inform_url %q taken", bad)
		}
	}
}

// A setparam the controller keeps repeating unchanged must not keep the
// device informing twice a second for ever.
func TestRepeatedSetparamStopsHurrying(t *testing.T) {
	x := newSession(t)
	same := `{"_type":"setparam","mgmt_cfg":"cfgversion=7\nsomething_new=1\n"}`
	var got []bool
	for i := 0; i < 6; i++ {
		got = append(got, handle(t, x, same).Immediate)
	}
	if want := []bool{true, true, true, false, false, false}; !slices.Equal(got, want) {
		t.Errorf("immediate %v, want %v", got, want)
	}
	if !handle(t, x, `{"_type":"setparam","mgmt_cfg":"cfgversion=8\n"}`).Immediate {
		t.Error("a new setparam must be answered right away")
	}
}

// Once adopted, the payload must keep the real sys_stats and
// radio_table_stats that Extra read from the AP (agent-design.md §2: they
// used to be replaced by canned U7PG2 constants). The canned values only
// fill in when Extra has none.
func TestAdoptedPayloadKeepsExtraStats(t *testing.T) {
	x := newSession(t)
	handle(t, x, `{"_type":"setparam","mgmt_cfg":"authkey=`+newKey+`\n"}`)
	if !x.S.Adopted {
		t.Fatal("not adopted")
	}
	x.Extra = func() map[string]any {
		return map[string]any{
			"sys_stats": map[string]any{"loadavg_1": "1.23", "mem_total": 264241152},
			"radio_table_stats": []map[string]any{
				{"name": "wifi0", "radio": "ng", "channel": 6, "num_sta": 7, "cu_total": 42},
			},
		}
	}
	var m map[string]any
	js, err := x.Payload(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(js, &m); err != nil {
		t.Fatal(err)
	}
	ss := m["sys_stats"].(map[string]any)
	if ss["loadavg_1"] != "1.23" || ss["mem_total"] != 264241152.0 {
		t.Errorf("sys_stats replaced: %v", ss)
	}
	rs := m["radio_table_stats"].([]any)
	if len(rs) != 1 || rs[0].(map[string]any)["num_sta"] != 7.0 || rs[0].(map[string]any)["cu_total"] != 42.0 {
		t.Errorf("radio_table_stats replaced: %v", rs)
	}

	// without Extra the canned stand-ins are still sent
	x.Extra = nil
	js, _ = x.Payload(time.Now())
	m = nil
	json.Unmarshal(js, &m)
	if ss, ok := m["sys_stats"].(map[string]any); !ok || ss["mem_total"] != 129130496.0 {
		t.Errorf("canned sys_stats missing: %v", m["sys_stats"])
	}
	if rs, ok := m["radio_table_stats"].([]any); !ok || len(rs) != 2 {
		t.Errorf("canned radio_table_stats missing: %v", m["radio_table_stats"])
	}
}

// Radio AI's nightly neighbour scan: cmd scan_band with band "ng"/"na"
// (the controller's 03:00 run, 2026-11-25), one band per cmd. The band
// field is read, not noted as unhandled.
func TestScanBandCmd(t *testing.T) {
	x := newSession(t)
	x.Unhandled = OpenLedger(x.StateDir + "/unhandled.json")
	for _, c := range []struct{ reply, want string }{
		{`{"_type":"cmd","cmd":"scan_band","band":"ng","datetime":1795555802478}`, "scan-band:ng"},
		{`{"_type":"cmd","cmd":"scan_band","band":"na"}`, "scan-band:na"},
	} {
		o := handle(t, x, c.reply)
		if !slices.Equal(o.Actions, []string{c.want}) || !o.Immediate {
			t.Errorf("%s: actions %v immediate %v, want %s", c.reply, o.Actions, o.Immediate, c.want)
		}
	}
	for _, bad := range []string{
		`{"_type":"cmd","cmd":"scan_band"}`,
		`{"_type":"cmd","cmd":"scan_band","band":"5g"}`,
	} {
		if o := handle(t, x, bad); len(o.Actions) != 0 {
			t.Errorf("%s: actions %v", bad, o.Actions)
		}
	}
	for _, u := range x.Unhandled.Entries() {
		if u.Kind == "field" && u.Name == "cmd.band" {
			t.Errorf("band noted as unhandled: %+v", u)
		}
	}
}

// The nightly channel optimisation sends cmd quick-scan with scan-band and
// scan-bw (numbers, or numeric strings).
func TestQuickScanCmd(t *testing.T) {
	x := newSession(t)
	x.Unhandled = OpenLedger(x.StateDir + "/unhandled.json")
	for _, c := range []struct{ reply, want string }{
		{`{"_type":"cmd","cmd":"quick-scan","scan-band":1,"scan-bw":80}`, "quick-scan:na:80"},
		{`{"_type":"cmd","cmd":"quick-scan","scan-band":"0","scan-bw":"20"}`, "quick-scan:ng:20"},
		{`{"_type":"cmd","cmd":"quick-scan","scan-band":1}`, "quick-scan:na:0"},
	} {
		o := handle(t, x, c.reply)
		if !slices.Equal(o.Actions, []string{c.want}) || !o.Immediate {
			t.Errorf("%s: actions %v immediate %v, want %s", c.reply, o.Actions, o.Immediate, c.want)
		}
	}
	for _, bad := range []string{
		`{"_type":"cmd","cmd":"quick-scan"}`,
		`{"_type":"cmd","cmd":"quick-scan","scan-band":7,"scan-bw":20}`,
	} {
		if o := handle(t, x, bad); len(o.Actions) != 0 {
			t.Errorf("%s: actions %v", bad, o.Actions)
		}
	}
	for _, u := range x.Unhandled.Entries() {
		if u.Kind == "field" && strings.Contains(u.Name, "scan-") {
			t.Errorf("scan-band/scan-bw recorded as unread: %+v", u)
		}
	}
}

// The capability words are 32-bit unsigned (a bit 31 word held in a 32-bit
// ARM int is negative); a zero word is left out, which the controller reads
// as 0 (payload getInt default), so clearing the last bit of fw3_caps or
// wifi_caps2 also clears it on the controller.
func TestCapabilityWordsSerialised(t *testing.T) {
	x := newSession(t)
	x.WifiCaps, x.WifiCaps2, x.FWCaps, x.FW3Caps = 0x1120000, 0x20, 0x21401403, 0xc0
	x.FW2Caps = -0x80000000 // bit 31 in a 32-bit int
	m := map[string]any{}
	js, err := x.Payload(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(js, &m)
	for k, want := range map[string]float64{"wifi_caps": 0x1120000, "wifi_caps2": 0x20, "fw_caps": 0x21401403,
		"fw2_caps": 0x80000000, "fw3_caps": 0xc0} {
		if m[k] != want {
			t.Errorf("%s = %v, want %v", k, m[k], want)
		}
	}
	x.WifiCaps2, x.FW3Caps, x.FW2Caps = 0, 0, 0
	m = map[string]any{}
	js, _ = x.Payload(time.Now())
	json.Unmarshal(js, &m)
	for _, k := range []string{"wifi_caps2", "fw2_caps", "fw3_caps"} {
		if _, ok := m[k]; ok {
			t.Errorf("zero %s sent: %v", k, m[k])
		}
	}
}

// The state keeps the model it was adopted as (the controller never takes
// a new model from an adopted device): every adoption path records the
// reported model, a re-key keeps it, setdefault clears it.
func TestAdoptedModel(t *testing.T) {
	x := newSession(t)
	x.Dev.Model = "UHDIW"
	handle(t, x, `{"_type":"setparam","mgmt_cfg":"authkey=`+newKey+`\n"}`)
	if x.S.Model != "UHDIW" {
		t.Fatalf("setparam adoption: model %q", x.S.Model)
	}
	x.Dev.Model = "U7LT" // a config change on an adopted unit
	handle(t, x, `{"_type":"cmd","cmd":"set-adopt","key":"ffffffffffffffffffffffffffffffff"}`)
	x.ApplyAdopt(AdoptRequest{Key: newKey})
	if x.S.Model != "UHDIW" {
		t.Fatalf("re-key changed the adopted model: %q", x.S.Model)
	}
	handle(t, x, `{"_type":"setdefault"}`)
	if x.S.Model != "" {
		t.Fatalf("setdefault kept model %q", x.S.Model)
	}
	handle(t, x, `{"_type":"cmd","cmd":"set-adopt","key":"`+newKey+`"}`)
	if x.S.Model != "U7LT" {
		t.Fatalf("set-adopt adoption: model %q", x.S.Model)
	}
	handle(t, x, `{"_type":"cmd","cmd":"setdefault"}`)
	x.ApplyAdopt(AdoptRequest{Key: newKey})
	if x.S.Model != "U7LT" || !x.S.Adopted {
		t.Fatalf("ssh adoption: %+v", x.S)
	}
}
