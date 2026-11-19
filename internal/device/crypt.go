// SPDX-License-Identifier: GPL-2.0-or-later

package device

// crypt(3) password hashes, verification only: the agent checks an SSH
// password against the site's device credential (docs/deco/agent-design.md
// §3.6, R12 and "Site SSH logins"). Three schemes:
//
//   - "$6$" SHA-512 crypt and "$5$" SHA-256 crypt (Ulrich Drepper's "Unix
//     crypt using SHA-256 and SHA-512", the schemes glibc's crypt(3) uses;
//     the controller's users.N.password is "$6$");
//   - "$1$" MD5 crypt (Poul-Henning Kamp's FreeBSD scheme, also in glibc),
//     only because the controller's mgmt settings carry an x_ssh_md5passwd.
//
// Locked ("!..." / "*..."), empty and unknown hashes never match.

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"hash"
	"strconv"
	"strings"
)

const (
	sha512CryptDefaultRounds = 5000
	sha512CryptMinRounds     = 1000
	// The scheme allows 999999999 rounds; a hash the controller sends uses
	// the default. More than this is refused rather than computed (one
	// verification must not stall the SSH responder).
	sha512CryptMaxRounds = 500000
	cryptB64             = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	// longest password verified: a crypt costs time linear in it
	cryptMaxPassword = 1024
)

// VerifyCrypt reports whether password matches hash, a crypt(3) hash:
// SHA-512 ("$6$[rounds=N$]salt$digest"), SHA-256 ("$5$...") or MD5
// ("$1$salt$digest"). Any other scheme, a malformed or locked hash, an empty
// password or one longer than 1024 bytes is a mismatch. The comparison is
// constant-time.
func VerifyCrypt(hash, password string) bool {
	if password == "" || len(password) > cryptMaxPassword {
		return false
	}
	var want string
	switch {
	case strings.HasPrefix(hash, "$6$"), strings.HasPrefix(hash, "$5$"):
		var ok bool
		if want, ok = shaCryptFor(hash, password); !ok {
			return false
		}
	case strings.HasPrefix(hash, "$1$"):
		salt, _, ok := strings.Cut(hash[3:], "$")
		if !ok {
			return false
		}
		want = md5Crypt([]byte(password), []byte(salt))
	default:
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(hash)) == 1
}

// CryptUsable reports whether hash is a scheme VerifyCrypt checks, with a
// salt and a digest: not empty, not locked ("!", "*"), not another scheme.
// It runs no crypt.
func CryptUsable(hash string) bool {
	var rest string
	switch {
	case strings.HasPrefix(hash, "$6$"), strings.HasPrefix(hash, "$5$"), strings.HasPrefix(hash, "$1$"):
		rest = hash[3:]
	default:
		return false
	}
	if r, ok := strings.CutPrefix(rest, "rounds="); ok && hash[1] != '1' {
		if _, tail, ok := strings.Cut(r, "$"); ok {
			rest = tail
		}
	}
	salt, digest, ok := strings.Cut(rest, "$")
	return ok && digest != "" && !strings.ContainsAny(salt+digest, "$:\n\t ")
}

// shaCryptFor computes the "$5$"/"$6$" string for password with hash's
// salt and rounds; false for a malformed hash or too many rounds.
func shaCryptFor(hash, password string) (string, bool) {
	sha512 := hash[1] == '6'
	rest := hash[3:]
	rounds, custom := sha512CryptDefaultRounds, false
	if r, ok := strings.CutPrefix(rest, "rounds="); ok {
		n, tail, ok := strings.Cut(r, "$")
		if !ok {
			return "", false
		}
		v, err := strconv.Atoi(n)
		if err != nil || v < 1 {
			return "", false
		}
		rounds, custom, rest = min(max(v, sha512CryptMinRounds), 999999999), true, tail
		if rounds > sha512CryptMaxRounds {
			return "", false
		}
	}
	salt, _, ok := strings.Cut(rest, "$")
	if !ok {
		return "", false
	}
	if sha512 {
		return sha512Crypt([]byte(password), []byte(salt), rounds, custom), true
	}
	return sha256Crypt([]byte(password), []byte(salt), rounds, custom), true
}

// sha512Crypt computes the full "$6$..." string for key and salt (the salt
// is cut to 16 bytes, as the scheme says).
func sha512Crypt(key, salt []byte, rounds int, custom bool) string {
	c, salt := shaCryptDigest(sha512.New, key, salt, rounds)
	out := shaCryptPrefix("$6$", salt, rounds, custom)
	order := [21][3]int{{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26}, {6, 27, 48},
		{28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13},
		{56, 14, 35}, {15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19}, {62, 20, 41}}
	for _, o := range order {
		b64From24(out, c[o[0]], c[o[1]], c[o[2]], 4)
	}
	b64From24(out, 0, 0, c[63], 2)
	return out.String()
}

// sha256Crypt computes the full "$5$..." string for key and salt.
func sha256Crypt(key, salt []byte, rounds int, custom bool) string {
	c, salt := shaCryptDigest(sha256.New, key, salt, rounds)
	out := shaCryptPrefix("$5$", salt, rounds, custom)
	order := [10][3]int{{0, 10, 20}, {21, 1, 11}, {12, 22, 2}, {3, 13, 23}, {24, 4, 14},
		{15, 25, 5}, {6, 16, 26}, {27, 7, 17}, {18, 28, 8}, {9, 19, 29}}
	for _, o := range order {
		b64From24(out, c[o[0]], c[o[1]], c[o[2]], 4)
	}
	b64From24(out, 0, c[31], c[30], 3)
	return out.String()
}

func shaCryptPrefix(id string, salt []byte, rounds int, custom bool) *strings.Builder {
	out := &strings.Builder{}
	out.WriteString(id)
	if custom {
		out.WriteString("rounds=" + strconv.Itoa(rounds) + "$")
	}
	out.Write(salt)
	out.WriteByte('$')
	return out
}

// shaCryptDigest is the SHA-crypt digest (steps 1-21 of the
// specification) with newHash (SHA-256 or SHA-512), and the salt as used
// (cut to 16 bytes).
func shaCryptDigest(newHash func() hash.Hash, key, salt []byte, rounds int) ([]byte, []byte) {
	if len(salt) > 16 {
		salt = salt[:16]
	}
	h := newHash()
	size := h.Size()
	h.Write(key)
	h.Write(salt)
	h.Write(key)
	b := h.Sum(nil)

	h.Reset()
	h.Write(key)
	h.Write(salt)
	n := len(key)
	for ; n > size; n -= size {
		h.Write(b)
	}
	h.Write(b[:n])
	for n = len(key); n > 0; n >>= 1 {
		if n&1 != 0 {
			h.Write(b)
		} else {
			h.Write(key)
		}
	}
	a := h.Sum(nil)

	h.Reset()
	for range len(key) {
		h.Write(key)
	}
	p := repeatTo(h.Sum(nil), len(key))

	h.Reset()
	for range 16 + int(a[0]) {
		h.Write(salt)
	}
	s := repeatTo(h.Sum(nil), len(salt))

	c := a
	for i := range rounds {
		h.Reset()
		if i&1 != 0 {
			h.Write(p)
		} else {
			h.Write(c)
		}
		if i%3 != 0 {
			h.Write(s)
		}
		if i%7 != 0 {
			h.Write(p)
		}
		if i&1 != 0 {
			h.Write(c)
		} else {
			h.Write(p)
		}
		c = h.Sum(c[:0])
	}
	return c, salt
}

// md5Crypt computes the full "$1$..." string for key and salt (the salt is
// cut to 8 bytes, as the scheme says).
func md5Crypt(key, salt []byte) string {
	if len(salt) > 8 {
		salt = salt[:8]
	}
	h := md5.New()
	h.Write(key)
	h.Write(salt)
	h.Write(key)
	fin := h.Sum(nil)

	h.Reset()
	h.Write(key)
	h.Write([]byte("$1$"))
	h.Write(salt)
	for n := len(key); n > 0; n -= 16 {
		h.Write(fin[:min(n, 16)])
	}
	for n := len(key); n > 0; n >>= 1 {
		if n&1 != 0 {
			h.Write([]byte{0})
		} else {
			h.Write(key[:1])
		}
	}
	fin = h.Sum(nil)

	for i := range 1000 {
		h.Reset()
		if i&1 != 0 {
			h.Write(key)
		} else {
			h.Write(fin)
		}
		if i%3 != 0 {
			h.Write(salt)
		}
		if i%7 != 0 {
			h.Write(key)
		}
		if i&1 != 0 {
			h.Write(fin)
		} else {
			h.Write(key)
		}
		fin = h.Sum(fin[:0])
	}

	out := &strings.Builder{}
	out.WriteString("$1$")
	out.Write(salt)
	out.WriteByte('$')
	for _, o := range [5][3]int{{0, 6, 12}, {1, 7, 13}, {2, 8, 14}, {3, 9, 15}, {4, 10, 5}} {
		b64From24(out, fin[o[0]], fin[o[1]], fin[o[2]], 4)
	}
	b64From24(out, 0, 0, fin[11], 2)
	return out.String()
}

// repeatTo is d repeated to n bytes.
func repeatTo(d []byte, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, d[:min(len(d), n-len(out))]...)
	}
	return out
}

func b64From24(out *strings.Builder, b2, b1, b0 byte, n int) {
	w := uint(b2)<<16 | uint(b1)<<8 | uint(b0)
	for range n {
		out.WriteByte(cryptB64[w&0x3f])
		w >>= 6
	}
}
