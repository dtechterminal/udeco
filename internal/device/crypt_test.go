// SPDX-License-Identifier: GPL-2.0-or-later

package device

import (
	"strings"
	"testing"
)

// Known answers for SHA-256 crypt (the SHA-crypt specification's and
// glibc's crypt/sha256c-test.c vectors), the SHA-512 vectors with custom
// rounds (glibc crypt/sha512c-test.c), and MD5 crypt (glibc
// crypt/md5c-test.c). The default-rounds ones were re-checked with
// `openssl passwd -5|-1 -salt <salt> <password>` (OpenSSL 4.1.0).
func TestVerifyCryptKnownAnswers(t *testing.T) {
	for _, c := range []struct{ hash, pw string }{
		{"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5", "Hello world!"},
		{"$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA", "Hello world!"},
		{"$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5", "This is just a test"},
		{"$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1", "a very much longer text to encrypt.  This one even stretches over morethan one line."},
		{"$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/", "we have a short salt string but not a short password"},
		{"$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD", "a short string"},
		// rounds=10 is raised to the minimum, 1000
		{"$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC", "the minimum number is still observed"},
		// a key longer than the 32-byte digest (150 x 'x'), openssl
		{"$5$ab$Ifx1CNrs.eVxY/TKa5OcWT4b6VE4ZcX1gh8lPIflzV7", strings.Repeat("x", 150)},
		{"$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1", "a very much longer text to encrypt.  This one even stretches over morethan one line."},
		{"$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0", "we have a short salt string but not a short password"},
		{"$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1", "a short string"},
		{"$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.", "the minimum number is still observed"},
		{"$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1", "Hello world!"},
		// a key longer than the 16-byte digest (70 x 'x'), openssl
		{"$1$abcdefgh$qZQJZIj/wBFysso0hpBg61", strings.Repeat("x", 70)},
	} {
		if !VerifyCrypt(c.hash, c.pw) {
			t.Errorf("%s: right password refused", c.hash[:16])
		}
		if VerifyCrypt(c.hash, c.pw+"!") || VerifyCrypt(c.hash, c.pw[:len(c.pw)-1]) || VerifyCrypt(c.hash, "") {
			t.Errorf("%s: wrong password accepted", c.hash[:16])
		}
		if !CryptUsable(c.hash) {
			t.Errorf("%s: not usable", c.hash[:16])
		}
	}
}

func TestCryptUnusable(t *testing.T) {
	for _, h := range []string{"", "!", "*", "!$6$saltstring$abc", "*$6$x$y", "x", "$2y$10$abc", "$6$", "$6$salt", "$6$salt$",
		"$5$rounds=1000$", "$1$", "$1$salt$", "$6$sa:lt$digest", "$y$j9T$salt$digest"} {
		if CryptUsable(h) {
			t.Errorf("%q usable", h)
		}
		if VerifyCrypt(h, "anything") {
			t.Errorf("%q verified", h)
		}
	}
	// a password longer than 1024 bytes is never hashed
	long := strings.Repeat("y", cryptMaxPassword+1)
	if VerifyCrypt("$5$ab$Ifx1CNrs.eVxY/TKa5OcWT4b6VE4ZcX1gh8lPIflzV7", long) {
		t.Error("over-long password verified")
	}
}
