// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// RFC 3414 A.3.1 and A.3.2: password "maplesyrup", engine ID 00..02.
func TestKeyLocalisationRFC3414(t *testing.T) {
	engine, _ := hex.DecodeString("000000000000000000000002")
	for _, c := range []struct {
		p       authProto
		ku, kul string
	}{
		{authMD5, "9faf3283884e92834ebc9847d8edd963", "526f5eed9fcce26f8964c2930787d82b"},
		{authSHA1, "9fb5cc0381497b3793528939ff788d5d79145211", "6695febc9288e36282235fc7151f128497b38f3f"},
	} {
		h := c.p.hash()
		ku := passwordToKey(h, []byte("maplesyrup"))
		if hex.EncodeToString(ku) != c.ku {
			t.Errorf("%s Ku = %x", c.p, ku)
		}
		if kul := localizeKey(h, ku, engine); hex.EncodeToString(kul) != c.kul {
			t.Errorf("%s Kul = %x", c.p, kul)
		}
	}
}

func TestPrivacyRoundTrip(t *testing.T) {
	u := newUserKeys("mon", "password1", EngineIDFromMAC([]byte{1, 2, 3, 4, 5, 6}))
	salt := []byte{0, 0, 0, 1, 0, 0, 0, 2}
	pt := []byte("a scoped PDU of an odd length")
	for _, pp := range []privProto{privDES, privAES128} {
		ct, err := encrypt(pp, u.privKey(authSHA1), 1, 99, salt, pt)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(ct, []byte("scoped")) {
			t.Fatalf("%s: plaintext in ciphertext", pp)
		}
		got, err := decrypt(pp, u.privKey(authSHA1), 1, 99, salt, ct)
		if err != nil || !bytes.HasPrefix(got, pt) {
			t.Errorf("%s: %q %v", pp, got, err)
		}
		if pp == privAES128 && len(ct) != len(pt) || pp == privDES && len(ct)%8 != 0 {
			t.Errorf("%s: ciphertext length %d", pp, len(ct))
		}
	}
	if _, err := decrypt(privDES, u.privKey(authMD5), 1, 1, salt, []byte{1, 2, 3}); err == nil {
		t.Error("DES ciphertext not a multiple of 8 accepted")
	}
	if _, err := decrypt(privAES128, u.privKey(authMD5), 1, 1, salt[:4], []byte{1, 2, 3}); err == nil {
		t.Error("short salt accepted")
	}
}

func TestVerifyPicksProtocol(t *testing.T) {
	u := newUserKeys("mon", "password1", []byte{0x80, 0, 0, 1, 4})
	msg := []byte("message with a zeroed digest")
	for p := authProto(0); p < numAuth; p++ {
		got, ok := u.verify(msg, u.mac(p, msg))
		if !ok || got != p {
			t.Errorf("%s: verified as %s %v", p, got, ok)
		}
	}
	other := newUserKeys("mon", "password2", []byte{0x80, 0, 0, 1, 4})
	if _, ok := u.verify(msg, other.mac(authSHA1, msg)); ok {
		t.Error("another password's digest verified")
	}
}
