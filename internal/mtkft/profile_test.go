// SPDX-License-Identifier: GPL-2.0-or-later

package mtkft

import (
	"testing"

	"github.com/dtechterminal/udeco/internal/ftpeer"
)

// hostapd's mobility_domain=d530 puts MDIE octets d5 30 on the air; the
// driver's "<hex>:H" stores the integer little-endian, so it is 30d5:H.
func TestMDIDValue(t *testing.T) {
	if got := MDIDValue(0xd530); got != "30d5:H" {
		t.Errorf("MDIDValue(0xd530) = %q", got)
	}
	if got := MDIDValue(0x0001); got != "0100:H" {
		t.Errorf("MDIDValue(1) = %q", got)
	}
}

func TestR0KHID(t *testing.T) {
	id := R0KHID(mustMAC(t, "A8:42:A1:00:00:01"))
	if len(id) != R0KHIDLen || id != "a842a1000001-mt7663-r0kh" {
		t.Errorf("%q (%d)", id, len(id))
	}
	if !ftpeer.ValidR0KHID(id) {
		t.Errorf("%q is not a valid announced R0KH-ID", id)
	}
	if a, err := SetR0KHID(id); err != nil || a != "ftr0khid="+id {
		t.Errorf("%q %v", a, err)
	}
	if _, err := SetR0KHID(""); err == nil {
		t.Error("empty R0KH-ID accepted")
	}
}

func TestProfileKeys(t *testing.T) {
	bss := mustMAC(t, "a8:42:a1:00:00:01")
	kv, err := ProfileKeys([]BSSFT{{On: true, MDID: 0xd530, R0KHID: R0KHID(bss)}, {}, {}, {}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"FtSupport": "1;0;0;0", "FtRic": "0;0;0;0", "FtOtd": "0;0;0;0",
		"FtMdId1": "30d5:H", "FtR0khId1": "a842a1000001-mt7663-r0kh",
	}
	if len(kv) != len(want) {
		t.Errorf("keys %v", kv)
	}
	for k, v := range want {
		if kv[k] != v {
			t.Errorf("%s=%q, want %q", k, kv[k], v)
		}
	}
	if _, err := ProfileKeys([]BSSFT{{On: true, MDID: 1, R0KHID: "a842a1000001"}}); err == nil {
		t.Error("12-character R0KH-ID accepted in the profile (the driver would send 24 octets)")
	}
}
