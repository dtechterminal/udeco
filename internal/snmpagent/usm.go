// SPDX-License-Identifier: GPL-2.0-or-later

package snmpagent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"sync"
)

// User-based Security Model (RFC 3414): key localisation, HMAC
// authentication and DES/AES privacy.
//
// The UniFi controller sends one SNMPv3 user (name and password) and no
// protocols. A UAP's ubntconf writes it as net-snmp's
// `createUser "<name>" <proto> "<password>" <encrypt> "<password>"` plus
// `rouser <name> authpriv`, with proto and encrypt from snmp.user.N.proto /
// .encrypt, which the controller never sends; the strings that follow those
// key names in ubntbox are "md5" and "des", the defaults. So a UAP serves
// MD5 + DES, authPriv only. This agent accepts that pair and, for the same
// user and password, the stronger HMAC-SHA family (RFC 3414, RFC 7860) and
// AES-128 (RFC 3826): the protocol is the one the request's digest and
// ciphertext verify under, and the reply uses the same.

type authProto int

const (
	authMD5 authProto = iota
	authSHA1
	authSHA224
	authSHA256
	authSHA384
	authSHA512
	numAuth
)

var authNames = [numAuth]string{"MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}

func (p authProto) String() string { return authNames[p] }

func (p authProto) hash() func() hash.Hash {
	switch p {
	case authMD5:
		return md5.New
	case authSHA1:
		return sha1.New
	case authSHA224:
		return sha256.New224
	case authSHA256:
		return sha256.New
	case authSHA384:
		return sha512.New384
	}
	return sha512.New
}

// digestLen is the msgAuthenticationParameters length (HMAC-96 for MD5 and
// SHA-1; RFC 7860 for SHA-2).
func (p authProto) digestLen() int {
	switch p {
	case authMD5, authSHA1:
		return 12
	case authSHA224:
		return 16
	case authSHA256:
		return 24
	case authSHA384:
		return 32
	}
	return 48
}

type privProto int

const (
	privDES privProto = iota
	privAES128
)

func (p privProto) String() string {
	if p == privDES {
		return "DES"
	}
	return "AES"
}

// passwordToKey is RFC 3414 A.2: the hash of the password repeated to 1 MB.
func passwordToKey(h func() hash.Hash, password []byte) []byte {
	d := h()
	const total = 1 << 20
	buf := make([]byte, 64)
	pos := 0
	for n := 0; n < total; n += len(buf) {
		for i := range buf {
			buf[i] = password[pos]
			pos = (pos + 1) % len(password)
		}
		d.Write(buf)
	}
	return d.Sum(nil)
}

// localizeKey is RFC 3414 2.6: H(Ku || engineID || Ku).
func localizeKey(h func() hash.Hash, ku, engineID []byte) []byte {
	d := h()
	d.Write(ku)
	d.Write(engineID)
	d.Write(ku)
	return d.Sum(nil)
}

// userKeys are one user's localised keys, one per auth protocol (the
// privacy key is derived with the auth protocol's hash, RFC 3414 2.6). Each
// is derived the first time a request needs it (1 MB of hashing: tens of ms
// for SHA-512 on the unit's ARMv7), in the server goroutine, so a settings
// change never holds up the inform loop.
type userKeys struct {
	name     string
	password []byte
	engineID []byte

	mu   sync.Mutex
	auth [numAuth][]byte
}

func newUserKeys(name, password string, engineID []byte) *userKeys {
	return &userKeys{name: name, password: []byte(password), engineID: engineID}
}

func (u *userKeys) key(p authProto) []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.auth[p] == nil {
		h := p.hash()
		u.auth[p] = localizeKey(h, passwordToKey(h, u.password), u.engineID)
	}
	return u.auth[p]
}

// mac is the truncated HMAC of msg (with its digest field zeroed).
func (u *userKeys) mac(p authProto, msg []byte) []byte {
	m := hmac.New(p.hash(), u.key(p))
	m.Write(msg)
	return m.Sum(nil)[:p.digestLen()]
}

// verify finds the auth protocol under which digest authenticates msg
// (whose digest bytes are already zeroed). Every candidate of the digest's
// length is computed, so the time taken does not depend on which matched.
func (u *userKeys) verify(msg, digest []byte) (authProto, bool) {
	found, ok := authProto(0), false
	for p := authProto(0); p < numAuth; p++ {
		if p.digestLen() != len(digest) {
			continue
		}
		if subtle.ConstantTimeCompare(u.mac(p, msg), digest) == 1 && !ok {
			found, ok = p, true
		}
	}
	return found, ok
}

// privKey is the first 16 bytes of the localised key: DES key + pre-IV
// (RFC 3414 8.1.1.1) or the AES-128 key (RFC 3826 3.1.2.1).
func (u *userKeys) privKey(p authProto) []byte { return u.key(p)[:16] }

var errDecrypt = errors.New("decryption error")

// desIV is the pre-IV XOR the salt (RFC 3414 8.1.1.1).
func desIV(key, salt []byte) []byte {
	iv := make([]byte, 8)
	for i := range iv {
		iv[i] = key[8+i] ^ salt[i]
	}
	return iv
}

// aesIV is boots || time || salt (RFC 3826 3.1.2.1).
func aesIV(boots, etime uint32, salt []byte) []byte {
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:], boots)
	binary.BigEndian.PutUint32(iv[4:], etime)
	copy(iv[8:], salt)
	return iv
}

func decrypt(p privProto, key []byte, boots, etime uint32, salt, ct []byte) ([]byte, error) {
	if len(salt) != 8 {
		return nil, errDecrypt
	}
	out := make([]byte, len(ct))
	switch p {
	case privDES:
		if len(ct) == 0 || len(ct)%8 != 0 {
			return nil, errDecrypt
		}
		b, err := des.NewCipher(key[:8])
		if err != nil {
			return nil, err
		}
		cipher.NewCBCDecrypter(b, desIV(key, salt)).CryptBlocks(out, ct)
	case privAES128:
		b, err := aes.NewCipher(key[:16])
		if err != nil {
			return nil, err
		}
		cipher.NewCFBDecrypter(b, aesIV(boots, etime, salt)).XORKeyStream(out, ct)
	}
	return out, nil
}

func encrypt(p privProto, key []byte, boots, etime uint32, salt, pt []byte) ([]byte, error) {
	switch p {
	case privDES:
		if pad := len(pt) % 8; pad != 0 {
			pt = append(append([]byte(nil), pt...), make([]byte, 8-pad)...)
		}
		b, err := des.NewCipher(key[:8])
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(pt))
		cipher.NewCBCEncrypter(b, desIV(key, salt)).CryptBlocks(out, pt)
		return out, nil
	default:
		b, err := aes.NewCipher(key[:16])
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(pt))
		cipher.NewCFBEncrypter(b, aesIV(boots, etime, salt)).XORKeyStream(out, pt)
		return out, nil
	}
}
